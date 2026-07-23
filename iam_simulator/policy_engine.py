"""Engine de avaliação de políticas IAM.

Segue a lógica real do AWS IAM:
1. Coleta todas as políticas aplicáveis ao principal
2. Avalia cada política (Allow/Deny)
3. Explicit Deny sempre vence
4. Implicit Deney = sem política allow → negado
"""

import re
from fnmatch import fnmatch
from typing import Any

from .models import PolicyDocument, User, Group, Role, Policy


def _arn_match(pattern: str, arn: str) -> bool:
    """Verifica se um ARN combina com um padrão (suporta wildcards)."""
    if pattern == "*":
        return True
    if pattern == arn:
        return True
    return fnmatch(arn, pattern)


def _action_match(pattern: str, action: str) -> bool:
    """Verifica se uma ação combina com um padrão (suporta wildcards)."""
    if pattern == "*":
        return True
    if pattern == action:
        return True
    # Suporta wildcards: s3:Get*, s3:*, etc.
    return fnmatch(action, pattern)


def _evaluate_condition(condition: dict[str, Any], context: dict[str, str]) -> bool:
    """Avalia uma condição. Retorna True se a condição é satisfeita."""
    if not condition:
        return True

    for condition_op, condition_blocks in condition.items():
        if isinstance(condition_blocks, dict):
            condition_blocks = [condition_blocks]
        for block in condition_blocks:
            for key, expected_values in block.items():
                actual_value = context.get(key, "")
                if isinstance(expected_values, str):
                    expected_values = [expected_values]
                if condition_op == "StringEquals":
                    if actual_value not in expected_values:
                        return False
                elif condition_op == "StringNotEquals":
                    if actual_value in expected_values:
                        return False
                elif condition_op == "StringLike":
                    matched = False
                    for ev in expected_values:
                        if fnmatch(actual_value, ev):
                            matched = True
                            break
                    if not matched:
                        return False
                elif condition_op == "StringNotLike":
                    for ev in expected_values:
                        if fnmatch(actual_value, ev):
                            return False
                elif condition_op == "StringEqualsIgnoreCase":
                    if actual_value.lower() not in [v.lower() for v in expected_values]:
                        return False
                elif condition_op == "StringStartsWith":
                    matched = False
                    for ev in expected_values:
                        if actual_value.startswith(ev):
                            matched = True
                            break
                    if not matched:
                        return False
                elif condition_op == "StringEndsWith":
                    matched = False
                    for ev in expected_values:
                        if actual_value.endswith(ev):
                            matched = True
                            break
                    if not matched:
                        return False
                elif condition_op == "StringContains":
                    matched = False
                    for ev in expected_values:
                        if ev in actual_value:
                            matched = True
                            break
                    if not matched:
                        return False
                elif condition_op == "NumericEquals":
                    try:
                        if float(actual_value) not in [float(v) for v in expected_values]:
                            return False
                    except ValueError:
                        return False
                elif condition_op == "NumericNotEquals":
                    try:
                        if float(actual_value) in [float(v) for v in expected_values]:
                            return False
                    except ValueError:
                        return False
                elif condition_op == "NumericLessThan":
                    try:
                        if float(actual_value) >= float(expected_values[0]):
                            return False
                    except (ValueError, IndexError):
                        return False
                elif condition_op == "NumericLessThanEquals":
                    try:
                        if float(actual_value) > float(expected_values[0]):
                            return False
                    except (ValueError, IndexError):
                        return False
                elif condition_op == "NumericGreaterThan":
                    try:
                        if float(actual_value) <= float(expected_values[0]):
                            return False
                    except (ValueError, IndexError):
                        return False
                elif condition_op == "NumericGreaterThanEquals":
                    try:
                        if float(actual_value) < float(expected_values[0]):
                            return False
                    except (ValueError, IndexError):
                        return False
                elif condition_op == "Bool":
                    actual_lower = actual_value.lower()
                    if actual_lower not in [v.lower() for v in expected_values]:
                        return False
                elif condition_op == "ArnLike":
                    matched = False
                    for ev in expected_values:
                        if fnmatch(actual_value, ev):
                            matched = True
                            break
                    if not matched:
                        return False
                elif condition_op == "ArnEquals":
                    if actual_value not in expected_values:
                        return False
                elif condition_op == "ArnNotLike":
                    for ev in expected_values:
                        if fnmatch(actual_value, ev):
                            return False
                elif condition_op == "ArnNotEquals":
                    if actual_value in expected_values:
                        return False
                elif condition_op == "IpAddress":
                    matched = False
                    for ev in expected_values:
                        if fnmatch(actual_value, ev):
                            matched = True
                            break
                    if not matched:
                        return False
                elif condition_op == "NotIpAddress":
                    for ev in expected_values:
                        if fnmatch(actual_value, ev):
                            return False
                elif condition_op == "Null":
                    check_not_exists = expected_values[0].lower() == "true" if expected_values else False
                    value_exists = key in context
                    if check_not_exists and value_exists:
                        return False
                    if not check_not_exists and not value_exists:
                        return False
                elif condition_op == "ForAllValues":
                    actual_set = set(actual_value.split(",")) if actual_value else set()
                    expected_set = set(expected_values)
                    if not actual_set.issubset(expected_set):
                        return False
                elif condition_op == "ForAnyValue":
                    actual_set = set(actual_value.split(",")) if actual_value else set()
                    expected_set = set(expected_values)
                    if not actual_set.intersection(expected_set):
                        return False
    return True


def _eval_statements(statements: list[PolicyDocument], action: str,
                     resource: str, context: dict[str, str]) -> str | None:
    """Avalia uma lista de statements. Retorna 'Allow', 'Deney', ou None."""
    result = None
    for stmt in statements:
        # Verifica condição
        if not _evaluate_condition(stmt.Condition or {}, context):
            continue

        action_matches = any(_action_match(p, action) for p in stmt.Action)
        resource_matches = any(_arn_match(p, resource) for p in stmt.Resource)

        if action_matches and resource_matches:
            if stmt.Effect == "Deny":
                return "Deny"
            if stmt.Effect == "Allow":
                result = "Allow"
    return result


def _collect_policies_from_user(user: User, groups: dict[str, Group],
                                 policies: dict[str, Policy]) -> list[Policy]:
    """Coleta todas as políticas aplicáveis a um usuário."""
    collected = []

    # Políticas inline do usuário
    for inline in user.InlinePolicies:
        doc = inline.get("PolicyDocument", {})
        collected.append(Policy(
            PolicyName=inline.get("PolicyName", "inline"),
            PolicyDocument=doc,
        ))

    # Políticas gerenciadas anexadas diretamente
    for pname in user.AttachedPolicies:
        if pname in policies:
            collected.append(policies[pname])

    # Políticas dos grupos que o usuário pertence
    for gname in user.Groups:
        if gname in groups:
            group = groups[gname]
            for inline in group.InlinePolicies:
                doc = inline.get("PolicyDocument", {})
                collected.append(Policy(
                    PolicyName=inline.get("PolicyName", "inline"),
                    PolicyDocument=doc,
                ))
            for pname in group.AttachedPolicies:
                if pname in policies:
                    collected.append(policies[pname])

    return collected


def _collect_policies_from_role(role: Role, policies: dict[str, Policy]) -> list[Policy]:
    """Coleta todas as políticas aplicáveis a uma role."""
    collected = []

    for inline in role.InlinePolicies:
        doc = inline.get("PolicyDocument", {})
        collected.append(Policy(
            PolicyName=inline.get("PolicyName", "inline"),
            PolicyDocument=doc,
        ))

    for pname in role.AttachedPolicies:
        if pname in policies:
            collected.append(policies[pname])

    return collected


def evaluate_access(action: str, resource: str,
                    user: User | None = None,
                    role: Role | None = None,
                    groups: dict[str, Group] | None = None,
                    policies: dict[str, Policy] | None = None,
                    context: dict[str, str] | None = None) -> dict[str, Any]:
    """
    Avalia se um principal tem acesso a um recurso com uma ação.

    Retorna:
        {
            "allowed": bool,
            "reason": "Allow" | "Deny" | "ImplicitDeny",
            "matched_policies": list[str],
            "denied_by": str | None,
        }
    """
    groups = groups or {}
    policies = policies or {}
    context = context or {}

    collected_policies: list[Policy] = []

    if user:
        collected_policies = _collect_policies_from_user(user, groups, policies)
        principal_arn = user.Arn
        principal_name = user.UserName
    elif role:
        collected_policies = _collect_policies_from_role(role, policies)
        principal_arn = role.Arn
        principal_name = role.RoleName
    else:
        return {
            "allowed": False,
            "reason": "ImplicitDeny",
            "matched_policies": [],
            "denied_by": None,
            "principal_arn": "unknown",
            "principal_name": "unknown",
        }

    matched = []
    denied_by = None

    for policy in collected_policies:
        stmts = policy.statements()
        result = _eval_statements(stmts, action, resource, context)
        if result == "Deny":
            denied_by = policy.PolicyName
            matched.append(policy.PolicyName)
            break
        if result == "Allow":
            matched.append(policy.PolicyName)

    if denied_by:
        return {
            "allowed": False,
            "reason": "Deny",
            "matched_policies": matched,
            "denied_by": denied_by,
            "principal_arn": principal_arn,
            "principal_name": principal_name,
        }

    if matched:
        return {
            "allowed": True,
            "reason": "Allow",
            "matched_policies": matched,
            "denied_by": None,
            "principal_arn": principal_arn,
            "principal_name": principal_name,
        }

    return {
        "allowed": False,
        "reason": "ImplicitDeny",
        "matched_policies": [],
        "denied_by": None,
        "principal_arn": principal_arn,
        "principal_name": principal_name,
    }


def evaluate_trust_policy(role: Role, principal_arn: str, principal_type: str = "User") -> dict[str, Any]:
    """
    Avalia se um principal pode assumir uma role (trust policy).

    Retorna:
        {
            "allowed": bool,
            "reason": "Allow" | "Deny" | "ImplicitDeny",
        }
    """
    trust_doc = role.AssumeRolePolicyDocument
    if not trust_doc:
        return {"allowed": False, "reason": "ImplicitDeny"}

    stmts = trust_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for stmt in stmts:
        if stmt.get("Effect") != "Allow":
            continue

        principal = stmt.get("Principal", {})
        if isinstance(principal, str) and principal == "*":
            return {"allowed": True, "reason": "Allow"}

        if isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            service_principals = principal.get("Service", [])
            if isinstance(service_principals, str):
                service_principals = [service_principals]

            if principal_arn in aws_principals or "*" in aws_principals:
                return {"allowed": True, "reason": "Allow"}

            if principal_type == "Service":
                if principal_arn in service_principals or "*" in service_principals:
                    return {"allowed": True, "reason": "Allow"}

    return {"allowed": False, "reason": "ImplicitDeny"}
