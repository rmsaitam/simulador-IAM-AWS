"""CLI principal do simulador IAM AWS."""

import json
import sys
from pathlib import Path

import click

from .exceptions import (
    IAMSimulatorError,
    EntityAlreadyExistsError,
    EntityNotFoundError,
    AccessDeniedError,
)
from .models import User, Group, Policy, Role, validate_entity_name
from .storage import load_data, persist_all, load_users, load_groups, load_policies, load_roles
from .policy_engine import evaluate_access
from .services import get_service_from_arn, get_actions_for_service, list_services, validate_action, SERVICE_ACTIONS

DATA_FILE = None  # Usa o padrão


def _parse_tags(tags_str: str) -> list[dict]:
    """Parse 'key1=val1,key2=val2' into [{'Key': 'key1', 'Value': 'val1'}, ...]."""
    if not tags_str:
        return []
    tags = []
    for pair in tags_str.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            tags.append({"Key": k.strip(), "Value": v.strip()})
    return tags


def _validate_name(name: str):
    """Valida nome de entidade IAM."""
    if not validate_entity_name(name):
        raise click.ClickException(
            f"Invalid entity name '{name}'. Must be max 64 characters "
            f"and contain only [a-zA-Z0-9+=,.@_-]"
        )


class IAMContext:
    """Contexto compartilhado entre os comandos CLI."""
    def __init__(self):
        self.data = load_data()
        self.users = load_users(self.data)
        self.groups = load_groups(self.data)
        self.policies = load_policies(self.data)
        self.roles = load_roles(self.data)

    def save(self):
        persist_all(self.users, self.groups, self.policies, self.roles)


pass_context = click.make_pass_decorator(IAMContext, ensure=True)


class IAMGroup(click.Group):
    """Grupo CLI com tratamento de exceções do simulador."""
    def invoke(self, ctx):
        try:
            super().invoke(ctx)
        except IAMSimulatorError as e:
            raise click.ClickException(str(e))


# ─── CLI Principal ────────────────────────────────────────────────

@click.group(cls=IAMGroup)
@click.version_option(version="1.0.0", prog_name="iam-simulator")
def cli():
    """Simulador IAM AWS - CLI para simular políticas e acesso a recursos AWS."""
    pass


# ─── USUÁRIOS ─────────────────────────────────────────────────────

@cli.group()
def user():
    """Gerenciar usuários IAM."""
    pass


@user.command("create")
@click.argument("name")
@click.option("--groups", "-g", default="", help="Grupos separados por vírgula")
@click.option("--policies", "-p", default="", help="Políticas separadas por vírgula")
@click.option("--tags", "-t", default="", help="Tags no formato key1=val1,key2=val2")
@pass_context
def user_create(ctx: IAMContext, name: str, groups: str, policies: str, tags: str):
    """Criar um novo usuário IAM."""
    _validate_name(name)
    if name in ctx.users:
        raise EntityAlreadyExistsError("User", name)

    group_list = [g.strip() for g in groups.split(",") if g.strip()]
    policy_list = [p.strip() for p in policies.split(",") if p.strip()]

    for gname in group_list:
        if gname not in ctx.groups:
            raise EntityNotFoundError("Group", gname)
    for pname in policy_list:
        if pname not in ctx.policies:
            raise EntityNotFoundError("Policy", pname)

    tag_list = _parse_tags(tags)
    user_obj = User(UserName=name, Groups=group_list, AttachedPolicies=policy_list, Tags=tag_list)

    for gname in group_list:
        ctx.groups[gname].Members.append(name)

    ctx.users[name] = user_obj
    ctx.save()
    click.echo(f"User '{name}' created successfully.")
    if group_list:
        click.echo(f"  Groups: {', '.join(group_list)}")
    if policy_list:
        click.echo(f"  Policies: {', '.join(policy_list)}")
    if tag_list:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in tag_list)}")


@user.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Mostrar detalhes")
@click.option("--filter", "-F", "filter_str", default="", help="Filtrar por nome, grupo ou política")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def user_list(ctx: IAMContext, verbose: bool, filter_str: str, json_output: bool):
    """Listar todos os usuários."""
    users = dict(sorted(ctx.users.items()))

    if filter_str:
        users = {n: u for n, u in users.items()
                 if filter_str in n
                 or filter_str in u.Groups
                 or filter_str in u.AttachedPolicies
                 or any(filter_str in t.get("Key", "") or filter_str in t.get("Value", "") for t in u.Tags)}

    if json_output:
        click.echo(json.dumps({n: u.to_dict() for n, u in users.items()}, indent=2))
        return

    if not users:
        click.echo("No users found.")
        return

    for name, u in users.items():
        if verbose:
            click.echo(f"  {u.UserName}")
            click.echo(f"    ARN: {u.Arn}")
            click.echo(f"    Groups: {', '.join(u.Groups) if u.Groups else 'none'}")
            click.echo(f"    Policies: {', '.join(u.AttachedPolicies) if u.AttachedPolicies else 'none'}")
            if u.Tags:
                click.echo(f"    Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in u.Tags)}")
        else:
            click.echo(f"  {u.UserName}")


@user.command("delete")
@click.argument("name")
@pass_context
def user_delete(ctx: IAMContext, name: str):
    """Deletar um usuário IAM."""
    if name not in ctx.users:
        raise EntityNotFoundError("User", name)

    user_obj = ctx.users[name]
    for gname in user_obj.Groups:
        if gname in ctx.groups:
            ctx.groups[gname].Members = [
                m for m in ctx.groups[gname].Members if m != name
            ]
    for pname in user_obj.AttachedPolicies:
        if pname in ctx.policies:
            ctx.policies[pname].AttachmentCount = max(
                0, ctx.policies[pname].AttachmentCount - 1
            )
    del ctx.users[name]
    ctx.save()
    click.echo(f"User '{name}' deleted successfully.")


@user.command("get")
@click.argument("name")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def user_get(ctx: IAMContext, name: str, json_output: bool):
    """Obter detalhes de um usuário."""
    if name not in ctx.users:
        raise EntityNotFoundError("User", name)

    u = ctx.users[name]
    if json_output:
        click.echo(json.dumps(u.to_dict(), indent=2))
        return

    click.echo(f"User: {u.UserName}")
    click.echo(f"  ARN: {u.Arn}")
    click.echo(f"  UserId: {u.UserId}")
    click.echo(f"  CreateDate: {u.CreateDate}")
    click.echo(f"  Groups: {', '.join(u.Groups) if u.Groups else 'none'}")
    click.echo(f"  AttachedPolicies: {', '.join(u.AttachedPolicies) if u.AttachedPolicies else 'none'}")
    if u.Tags:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in u.Tags)}")
    if u.InlinePolicies:
        click.echo(f"  InlinePolicies:")
        for ip in u.InlinePolicies:
            click.echo(f"    - {ip.get('PolicyName', 'unnamed')}")


@user.command("attach-policy")
@click.argument("user_name")
@click.argument("policy_name")
@pass_context
def user_attach_policy(ctx: IAMContext, user_name: str, policy_name: str):
    """Anexar uma política a um usuário."""
    if user_name not in ctx.users:
        raise EntityNotFoundError("User", user_name)
    if policy_name not in ctx.policies:
        raise EntityNotFoundError("Policy", policy_name)
    if policy_name in ctx.users[user_name].AttachedPolicies:
        click.echo(f"Policy '{policy_name}' already attached to user '{user_name}'.")
        return

    ctx.users[user_name].AttachedPolicies.append(policy_name)
    ctx.policies[policy_name].AttachmentCount += 1
    ctx.save()
    click.echo(f"Policy '{policy_name}' attached to user '{user_name}'.")


@user.command("detach-policy")
@click.argument("user_name")
@click.argument("policy_name")
@pass_context
def user_detach_policy(ctx: IAMContext, user_name: str, policy_name: str):
    """Remover uma política de um usuário."""
    if user_name not in ctx.users:
        raise EntityNotFoundError("User", user_name)
    if policy_name not in ctx.users[user_name].AttachedPolicies:
        click.echo(f"Policy '{policy_name}' is not attached to user '{user_name}'.")
        return

    ctx.users[user_name].AttachedPolicies.remove(policy_name)
    if policy_name in ctx.policies:
        ctx.policies[policy_name].AttachmentCount = max(
            0, ctx.policies[policy_name].AttachmentCount - 1
        )
    ctx.save()
    click.echo(f"Policy '{policy_name}' detached from user '{user_name}'.")


@user.command("add-group")
@click.argument("user_name")
@click.argument("group_name")
@pass_context
def user_add_group(ctx: IAMContext, user_name: str, group_name: str):
    """Adicionar um usuário a um grupo."""
    if user_name not in ctx.users:
        raise EntityNotFoundError("User", user_name)
    if group_name not in ctx.groups:
        raise EntityNotFoundError("Group", group_name)
    if group_name in ctx.users[user_name].Groups:
        click.echo(f"User '{user_name}' is already in group '{group_name}'.")
        return

    ctx.users[user_name].Groups.append(group_name)
    ctx.groups[group_name].Members.append(user_name)
    ctx.save()
    click.echo(f"User '{user_name}' added to group '{group_name}'.")


@user.command("remove-group")
@click.argument("user_name")
@click.argument("group_name")
@pass_context
def user_remove_group(ctx: IAMContext, user_name: str, group_name: str):
    """Remover um usuário de um grupo."""
    if user_name not in ctx.users:
        raise EntityNotFoundError("User", user_name)
    if group_name not in ctx.users[user_name].Groups:
        click.echo(f"User '{user_name}' is not in group '{group_name}'.")
        return

    ctx.users[user_name].Groups.remove(group_name)
    ctx.groups[group_name].Members = [
        m for m in ctx.groups[group_name].Members if m != user_name
    ]
    ctx.save()
    click.echo(f"User '{user_name}' removed from group '{group_name}'.")


# ─── GRUPOS ───────────────────────────────────────────────────────

@cli.group()
def group():
    """Gerenciar grupos IAM."""
    pass


@group.command("create")
@click.argument("name")
@click.option("--policies", "-p", default="", help="Políticas separadas por vírgula")
@click.option("--tags", "-t", default="", help="Tags no formato key1=val1,key2=val2")
@pass_context
def group_create(ctx: IAMContext, name: str, policies: str, tags: str):
    """Criar um novo grupo IAM."""
    _validate_name(name)
    if name in ctx.groups:
        raise EntityAlreadyExistsError("Group", name)

    policy_list = [p.strip() for p in policies.split(",") if p.strip()]
    for pname in policy_list:
        if pname not in ctx.policies:
            raise EntityNotFoundError("Policy", pname)

    tag_list = _parse_tags(tags)
    group_obj = Group(GroupName=name, AttachedPolicies=policy_list, Tags=tag_list)
    for pname in policy_list:
        ctx.policies[pname].AttachmentCount += 1

    ctx.groups[name] = group_obj
    ctx.save()
    click.echo(f"Group '{name}' created successfully.")
    if policy_list:
        click.echo(f"  Policies: {', '.join(policy_list)}")
    if tag_list:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in tag_list)}")


@group.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Mostrar detalhes")
@click.option("--filter", "-F", "filter_str", default="", help="Filtrar por nome, membro ou política")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def group_list(ctx: IAMContext, verbose: bool, filter_str: str, json_output: bool):
    """Listar todos os grupos."""
    groups = dict(sorted(ctx.groups.items()))

    if filter_str:
        groups = {n: g for n, g in groups.items()
                  if filter_str in n
                  or filter_str in g.Members
                  or filter_str in g.AttachedPolicies
                  or any(filter_str in t.get("Key", "") or filter_str in t.get("Value", "") for t in g.Tags)}

    if json_output:
        click.echo(json.dumps({n: g.to_dict() for n, g in groups.items()}, indent=2))
        return

    if not groups:
        click.echo("No groups found.")
        return

    for name, g in groups.items():
        if verbose:
            click.echo(f"  {g.GroupName}")
            click.echo(f"    ARN: {g.Arn}")
            click.echo(f"    Members: {', '.join(g.Members) if g.Members else 'none'}")
            click.echo(f"    Policies: {', '.join(g.AttachedPolicies) if g.AttachedPolicies else 'none'}")
            if g.Tags:
                click.echo(f"    Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in g.Tags)}")
        else:
            click.echo(f"  {g.GroupName}")


@group.command("delete")
@click.argument("name")
@pass_context
def group_delete(ctx: IAMContext, name: str):
    """Deletar um grupo IAM."""
    if name not in ctx.groups:
        raise EntityNotFoundError("Group", name)

    group_obj = ctx.groups[name]
    for mname in group_obj.Members:
        if mname in ctx.users:
            ctx.users[mname].Groups = [
                g for g in ctx.users[mname].Groups if g != name
            ]

    for pname in group_obj.AttachedPolicies:
        if pname in ctx.policies:
            ctx.policies[pname].AttachmentCount = max(
                0, ctx.policies[pname].AttachmentCount - 1
            )

    del ctx.groups[name]
    ctx.save()
    click.echo(f"Group '{name}' deleted successfully.")


@group.command("get")
@click.argument("name")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def group_get(ctx: IAMContext, name: str, json_output: bool):
    """Obter detalhes de um grupo."""
    if name not in ctx.groups:
        raise EntityNotFoundError("Group", name)

    g = ctx.groups[name]
    if json_output:
        click.echo(json.dumps(g.to_dict(), indent=2))
        return

    click.echo(f"Group: {g.GroupName}")
    click.echo(f"  ARN: {g.Arn}")
    click.echo(f"  GroupId: {g.GroupId}")
    click.echo(f"  CreateDate: {g.CreateDate}")
    click.echo(f"  Members: {', '.join(g.Members) if g.Members else 'none'}")
    click.echo(f"  AttachedPolicies: {', '.join(g.AttachedPolicies) if g.AttachedPolicies else 'none'}")
    if g.Tags:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in g.Tags)}")


@group.command("attach-policy")
@click.argument("group_name")
@click.argument("policy_name")
@pass_context
def group_attach_policy(ctx: IAMContext, group_name: str, policy_name: str):
    """Anexar uma política a um grupo."""
    if group_name not in ctx.groups:
        raise EntityNotFoundError("Group", group_name)
    if policy_name not in ctx.policies:
        raise EntityNotFoundError("Policy", policy_name)
    if policy_name in ctx.groups[group_name].AttachedPolicies:
        click.echo(f"Policy '{policy_name}' already attached to group '{group_name}'.")
        return

    ctx.groups[group_name].AttachedPolicies.append(policy_name)
    ctx.policies[policy_name].AttachmentCount += 1
    ctx.save()
    click.echo(f"Policy '{policy_name}' attached to group '{group_name}'.")


@group.command("detach-policy")
@click.argument("group_name")
@click.argument("policy_name")
@pass_context
def group_detach_policy(ctx: IAMContext, group_name: str, policy_name: str):
    """Remover uma política de um grupo."""
    if group_name not in ctx.groups:
        raise EntityNotFoundError("Group", group_name)
    if policy_name not in ctx.groups[group_name].AttachedPolicies:
        click.echo(f"Policy '{policy_name}' is not attached to group '{group_name}'.")
        return

    ctx.groups[group_name].AttachedPolicies.remove(policy_name)
    if policy_name in ctx.policies:
        ctx.policies[policy_name].AttachmentCount = max(
            0, ctx.policies[policy_name].AttachmentCount - 1
        )
    ctx.save()
    click.echo(f"Policy '{policy_name}' detached from group '{group_name}'.")


# ─── POLÍTICAS ────────────────────────────────────────────────────

@cli.group()
def policy():
    """Gerenciar políticas IAM."""
    pass


@policy.command("create")
@click.argument("name")
@click.option("--document", "-d", required=True, help="JSON do documento da política (inline ou caminho de arquivo)")
@click.option("--file", "-f", "from_file", is_flag=True, help="Indica que --document é um caminho de arquivo")
@click.option("--tags", "-t", default="", help="Tags no formato key1=val1,key2=val2")
@pass_context
def policy_create(ctx: IAMContext, name: str, document: str, from_file: bool, tags: str):
    """Criar uma nova política IAM."""
    _validate_name(name)
    if name in ctx.policies:
        raise EntityAlreadyExistsError("Policy", name)

    if from_file:
        doc_path = Path(document)
        if not doc_path.exists():
            click.echo(f"Error: File '{document}' not found.", err=True)
            sys.exit(1)
        with open(doc_path) as f:
            doc = json.load(f)
    else:
        try:
            doc = json.loads(document)
        except json.JSONDecodeError as e:
            click.echo(f"Error: Invalid JSON: {e}", err=True)
            sys.exit(1)

    if "Version" not in doc:
        doc["Version"] = "2012-10-17"
    if "Statement" not in doc:
        click.echo("Error: Policy must contain a 'Statement' field.", err=True)
        sys.exit(1)

    tag_list = _parse_tags(tags)
    policy_obj = Policy(PolicyName=name, PolicyDocument=doc, Tags=tag_list)
    ctx.policies[name] = policy_obj
    ctx.save()
    click.echo(f"Policy '{name}' created successfully.")
    click.echo(f"  ARN: {policy_obj.Arn}")
    if tag_list:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in tag_list)}")


@policy.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Mostrar detalhes")
@click.option("--filter", "-F", "filter_str", default="", help="Filtrar por nome ou attachment")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def policy_list(ctx: IAMContext, verbose: bool, filter_str: str, json_output: bool):
    """Listar todas as políticas."""
    policies = dict(sorted(ctx.policies.items()))

    if filter_str:
        policies = {n: p for n, p in policies.items()
                    if filter_str in n
                    or (filter_str == "attached" and p.AttachmentCount > 0)
                    or (filter_str == "unattached" and p.AttachmentCount == 0)
                    or any(filter_str in t.get("Key", "") or filter_str in t.get("Value", "") for t in p.Tags)}

    if json_output:
        click.echo(json.dumps({n: p.to_dict() for n, p in policies.items()}, indent=2))
        return

    if not policies:
        click.echo("No policies found.")
        return

    for name, p in policies.items():
        if verbose:
            click.echo(f"  {p.PolicyName}")
            click.echo(f"    ARN: {p.Arn}")
            click.echo(f"    Attachments: {p.AttachmentCount}")
            if p.Tags:
                click.echo(f"    Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in p.Tags)}")
        else:
            click.echo(f"  {p.PolicyName}")


@policy.command("delete")
@click.argument("name")
@pass_context
def policy_delete(ctx: IAMContext, name: str):
    """Deletar uma política IAM."""
    if name not in ctx.policies:
        raise EntityNotFoundError("Policy", name)

    for user_obj in ctx.users.values():
        if name in user_obj.AttachedPolicies:
            user_obj.AttachedPolicies.remove(name)
    for group_obj in ctx.groups.values():
        if name in group_obj.AttachedPolicies:
            group_obj.AttachedPolicies.remove(name)
    for role_obj in ctx.roles.values():
        if name in role_obj.AttachedPolicies:
            role_obj.AttachedPolicies.remove(name)

    del ctx.policies[name]
    ctx.save()
    click.echo(f"Policy '{name}' deleted successfully.")


@policy.command("get")
@click.argument("name")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def policy_get(ctx: IAMContext, name: str, json_output: bool):
    """Obter detalhes e documento de uma política."""
    if name not in ctx.policies:
        raise EntityNotFoundError("Policy", name)

    p = ctx.policies[name]
    if json_output:
        click.echo(json.dumps(p.to_dict(), indent=2))
        return

    click.echo(f"Policy: {p.PolicyName}")
    click.echo(f"  ARN: {p.Arn}")
    click.echo(f"  CreateDate: {p.CreateDate}")
    click.echo(f"  Attachments: {p.AttachmentCount}")
    if p.Tags:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in p.Tags)}")
    click.echo(f"  Document:")
    click.echo(json.dumps(p.PolicyDocument, indent=4))


# ─── ROLES ────────────────────────────────────────────────────────

@cli.group()
def role():
    """Gerenciar roles IAM."""
    pass


@role.command("create")
@click.argument("name")
@click.option("--trust-policy", "-t", default="", help="Trust policy JSON (inline ou arquivo)")
@click.option("--policies", "-p", default="", help="Políticas separadas por vírgula")
@click.option("--file", "-f", "from_file", is_flag=True, help="Indica que --trust-policy é um caminho de arquivo")
@click.option("--tags", "-T", default="", help="Tags no formato key1=val1,key2=val2")
@pass_context
def role_create(ctx: IAMContext, name: str, trust_policy: str, policies: str, from_file: bool, tags: str):
    """Criar uma nova role IAM."""
    _validate_name(name)
    if name in ctx.roles:
        raise EntityAlreadyExistsError("Role", name)

    if trust_policy:
        if from_file:
            tp_path = Path(trust_policy)
            if not tp_path.exists():
                click.echo(f"Error: File '{trust_policy}' not found.", err=True)
                sys.exit(1)
            with open(tp_path) as f:
                tp_doc = json.load(f)
        else:
            try:
                tp_doc = json.loads(trust_policy)
            except json.JSONDecodeError as e:
                click.echo(f"Error: Invalid JSON: {e}", err=True)
                sys.exit(1)
    else:
        tp_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

    policy_list = [p.strip() for p in policies.split(",") if p.strip()]
    for pname in policy_list:
        if pname not in ctx.policies:
            raise EntityNotFoundError("Policy", pname)

    tag_list = _parse_tags(tags)
    role_obj = Role(
        RoleName=name,
        AssumeRolePolicyDocument=tp_doc,
        AttachedPolicies=policy_list,
        Tags=tag_list,
    )
    for pname in policy_list:
        ctx.policies[pname].AttachmentCount += 1

    ctx.roles[name] = role_obj
    ctx.save()
    click.echo(f"Role '{name}' created successfully.")
    click.echo(f"  ARN: {role_obj.Arn}")
    if tag_list:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in tag_list)}")


@role.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Mostrar detalhes")
@click.option("--filter", "-F", "filter_str", default="", help="Filtrar por nome ou política")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def role_list(ctx: IAMContext, verbose: bool, filter_str: str, json_output: bool):
    """Listar todas as roles."""
    roles = dict(sorted(ctx.roles.items()))

    if filter_str:
        roles = {n: r for n, r in roles.items()
                 if filter_str in n
                 or filter_str in r.AttachedPolicies
                 or any(filter_str in t.get("Key", "") or filter_str in t.get("Value", "") for t in r.Tags)}

    if json_output:
        click.echo(json.dumps({n: r.to_dict() for n, r in roles.items()}, indent=2))
        return

    if not roles:
        click.echo("No roles found.")
        return

    for name, r in roles.items():
        if verbose:
            click.echo(f"  {r.RoleName}")
            click.echo(f"    ARN: {r.Arn}")
            click.echo(f"    Policies: {', '.join(r.AttachedPolicies) if r.AttachedPolicies else 'none'}")
            if r.Tags:
                click.echo(f"    Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in r.Tags)}")
        else:
            click.echo(f"  {r.RoleName}")


@role.command("delete")
@click.argument("name")
@pass_context
def role_delete(ctx: IAMContext, name: str):
    """Deletar uma role IAM."""
    if name not in ctx.roles:
        raise EntityNotFoundError("Role", name)

    role_obj = ctx.roles[name]
    for pname in role_obj.AttachedPolicies:
        if pname in ctx.policies:
            ctx.policies[pname].AttachmentCount = max(
                0, ctx.policies[pname].AttachmentCount - 1
            )
    del ctx.roles[name]
    ctx.save()
    click.echo(f"Role '{name}' deleted successfully.")


@role.command("get")
@click.argument("name")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def role_get(ctx: IAMContext, name: str, json_output: bool):
    """Obter detalhes de uma role."""
    if name not in ctx.roles:
        raise EntityNotFoundError("Role", name)

    r = ctx.roles[name]
    if json_output:
        click.echo(json.dumps(r.to_dict(), indent=2))
        return

    click.echo(f"Role: {r.RoleName}")
    click.echo(f"  ARN: {r.Arn}")
    click.echo(f"  RoleId: {r.RoleId}")
    click.echo(f"  CreateDate: {r.CreateDate}")
    click.echo(f"  AttachedPolicies: {', '.join(r.AttachedPolicies) if r.AttachedPolicies else 'none'}")
    if r.Tags:
        click.echo(f"  Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in r.Tags)}")
    click.echo(f"  AssumeRolePolicyDocument:")
    click.echo(json.dumps(r.AssumeRolePolicyDocument, indent=4))


@role.command("attach-policy")
@click.argument("role_name")
@click.argument("policy_name")
@pass_context
def role_attach_policy(ctx: IAMContext, role_name: str, policy_name: str):
    """Anexar uma política a uma role."""
    if role_name not in ctx.roles:
        raise EntityNotFoundError("Role", role_name)
    if policy_name not in ctx.policies:
        raise EntityNotFoundError("Policy", policy_name)
    if policy_name in ctx.roles[role_name].AttachedPolicies:
        click.echo(f"Policy '{policy_name}' already attached to role '{role_name}'.")
        return

    ctx.roles[role_name].AttachedPolicies.append(policy_name)
    ctx.policies[policy_name].AttachmentCount += 1
    ctx.save()
    click.echo(f"Policy '{policy_name}' attached to role '{role_name}'.")


@role.command("detach-policy")
@click.argument("role_name")
@click.argument("policy_name")
@pass_context
def role_detach_policy(ctx: IAMContext, role_name: str, policy_name: str):
    """Remover uma política de uma role."""
    if role_name not in ctx.roles:
        raise EntityNotFoundError("Role", role_name)
    if policy_name not in ctx.roles[role_name].AttachedPolicies:
        click.echo(f"Policy '{policy_name}' is not attached to role '{role_name}'.")
        return

    ctx.roles[role_name].AttachedPolicies.remove(policy_name)
    if policy_name in ctx.policies:
        ctx.policies[policy_name].AttachmentCount = max(
            0, ctx.policies[policy_name].AttachmentCount - 1
        )
    ctx.save()
    click.echo(f"Policy '{policy_name}' detached from role '{role_name}'.")


# ─── SIMULAÇÃO DE ACESSO ──────────────────────────────────────────

@cli.command("sim-access")
@click.option("--user", "-u", default=None, help="Usuário a ser testado")
@click.option("--role", "-r", default=None, help="Role a ser testada")
@click.option("--group", "-g", default=None, help="Grupo a ser testado")
@click.option("--action", "-a", required=True, help="Ação a ser testada (ex: s3:GetObject)")
@click.option("--resource", "-R", required=True, help="ARN do recurso (ex: arn:aws:s3:::bucket/*)")
@click.option("--context", "-c", default="", help="Contexto key=value separado por vírgula")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def sim_access(ctx: IAMContext, user: str | None, role: str | None, group: str | None,
               action: str, resource: str, context: str, json_output: bool):
    """Simular acesso a um recurso AWS.

    Exemplo:
      iam sim-access --user bob --action s3:GetObject --resource arn:aws:s3:::meu-bucket/*
    """
    selected = sum(1 for x in [user, role, group] if x)
    if selected == 0:
        click.echo("Error: You must specify --user, --role, or --group.", err=True)
        sys.exit(1)
    if selected > 1:
        click.echo("Error: You can only specify one of --user, --role, or --group.", err=True)
        sys.exit(1)

    ctx_map = {}
    if context:
        for pair in context.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                ctx_map[k.strip()] = v.strip()

    if group:
        if group not in ctx.groups:
            raise EntityNotFoundError("Group", group)
        temp_user = User(UserName=f"__temp_{group}", Groups=[group])
        result = evaluate_access(
            action=action,
            resource=resource,
            user=temp_user,
            groups=ctx.groups,
            policies=ctx.policies,
            context=ctx_map,
        )
        principal = group
        principal_type = "group"
    else:
        result = evaluate_access(
            action=action,
            resource=resource,
            user=ctx.users.get(user) if user else None,
            role=ctx.roles.get(role) if role else None,
            groups=ctx.groups,
            policies=ctx.policies,
            context=ctx_map,
        )
        principal = user or role
        principal_type = "user" if user else "role"

    if result["allowed"]:
        if json_output:
            click.echo(json.dumps({
                "status": "Access Granted",
                "principal": principal,
                "principal_type": principal_type,
                "action": action,
                "resource": resource,
                "matched_policies": result["matched_policies"],
            }, indent=2))
        else:
            click.secho("\n  Access Granted", fg="green", bold=True)
            click.echo(f"  User: {result['principal_name']} successfully accessed {action} on {resource}")
            click.echo(f"  Matched policies: {', '.join(result['matched_policies'])}\n")
    else:
        reason = result["reason"]
        if json_output:
            click.echo(json.dumps({
                "status": "Access Denied",
                "error_code": "AccessDeniedException",
                "message": f"User: {result['principal_arn']} is not authorized to perform: {action} on resource: {resource}",
                "principal": principal,
                "principal_type": principal_type,
                "reason": reason,
                "denied_by": result["denied_by"],
                "matched_policies": result["matched_policies"],
            }, indent=2))
        else:
            click.secho("\n  An error occurred (AccessDeniedException) when calling the "
                        f"{action.split(':')[1] if ':' in action else action} operation:",
                        fg="red", bold=True)
            click.echo(f"  User: {result['principal_arn']} is not authorized to perform: "
                       f"{action} on resource: {resource}")
            if reason == "Deny" and result["denied_by"]:
                click.echo(f"  Explicit deny by policy: {result['denied_by']}")
            elif reason == "ImplicitDeny":
                click.echo(f"  No matching allow policy found (implicit deny)")
            click.echo("")


# ─── UTILITÁRIOS ──────────────────────────────────────────────────

@cli.command("stats")
@pass_context
def stats(ctx: IAMContext):
    """Mostrar estatísticas do IAM simulado."""
    click.echo("IAM Simulator Stats:")
    click.echo(f"  Users:      {len(ctx.users)}")
    click.echo(f"  Groups:     {len(ctx.groups)}")
    click.echo(f"  Policies:   {len(ctx.policies)}")
    click.echo(f"  Roles:      {len(ctx.roles)}")


@cli.command("export")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "table"]), default="json")
@click.option("--output", "-o", default=None, help="Arquivo de saída (default: stdout)")
@pass_context
def export_cmd(ctx: IAMContext, fmt: str, output: str | None):
    """Exportar dados IAM."""
    data = {
        "users": {n: u.to_dict() for n, u in ctx.users.items()},
        "groups": {n: g.to_dict() for n, g in ctx.groups.items()},
        "policies": {n: p.to_dict() for n, p in ctx.policies.items()},
        "roles": {n: r.to_dict() for n, r in ctx.roles.items()},
    }

    if fmt == "json":
        content = json.dumps(data, indent=2)
    else:
        lines = []
        lines.append(f"{'Type':<10} {'Name':<25} {'ARN'}")
        lines.append("-" * 80)
        for n, u in sorted(ctx.users.items()):
            lines.append(f"{'User':<10} {u.UserName:<25} {u.Arn}")
        for n, g in sorted(ctx.groups.items()):
            lines.append(f"{'Group':<10} {g.GroupName:<25} {g.Arn}")
        for n, p in sorted(ctx.policies.items()):
            lines.append(f"{'Policy':<10} {p.PolicyName:<25} {p.Arn}")
        for n, r in sorted(ctx.roles.items()):
            lines.append(f"{'Role':<10} {r.RoleName:<25} {r.Arn}")
        content = "\n".join(lines)

    if output:
        Path(output).write_text(content)
        click.echo(f"Exported to {output}")
    else:
        click.echo(content)


@cli.command("import")
@click.option("--file", "-f", "filepath", required=True, help="Arquivo JSON para importar")
@click.option("--merge", "-m", is_flag=True, help="Mesclar com dados existentes (senão sobrescreve)")
@pass_context
def import_cmd(ctx: IAMContext, filepath: str, merge: bool):
    """Importar dados IAM de um arquivo JSON."""
    import os as _os
    if not _os.path.exists(filepath):
        click.echo(f"Error: File '{filepath}' not found.", err=True)
        sys.exit(1)

    with open(filepath) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            click.echo(f"Error: Invalid JSON: {e}", err=True)
            sys.exit(1)

    if not merge:
        ctx.users.clear()
        ctx.groups.clear()
        ctx.policies.clear()
        ctx.roles.clear()

    for name, udata in data.get("users", {}).items():
        if merge and name in ctx.users:
            continue
        ctx.users[name] = User.from_dict(udata)

    for name, gdata in data.get("groups", {}).items():
        if merge and name in ctx.groups:
            continue
        ctx.groups[name] = Group.from_dict(gdata)

    for name, pdata in data.get("policies", {}).items():
        if merge and name in ctx.policies:
            continue
        ctx.policies[name] = Policy.from_dict(pdata)

    for name, rdata in data.get("roles", {}).items():
        if merge and name in ctx.roles:
            continue
        ctx.roles[name] = Role.from_dict(rdata)

    ctx.save()
    click.echo(f"Imported successfully from {filepath}")
    click.echo(f"  Users: {len(ctx.users)}")
    click.echo(f"  Groups: {len(ctx.groups)}")
    click.echo(f"  Policies: {len(ctx.policies)}")
    click.echo(f"  Roles: {len(ctx.roles)}")


@cli.command("seed")
@pass_context
def seed(ctx: IAMContext):
    """Criar dados de exemplo (seed)."""
    # Políticas
    policies_data = {
        "AdministratorAccess": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
        },
        "S3ReadOnlyAccess": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                    "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"],
                }
            ],
        },
        "S3FullAccess": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]}],
        },
        "LambdaInvokeFunction": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["lambda:InvokeFunction", "lambda:InvokeAsync"],
                    "Resource": ["arn:aws:lambda:*:*:function:*"],
                }
            ],
        },
        "EC2ReadOnlyAccess": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:Describe*"],
                    "Resource": ["*"],
                }
            ],
        },
        "EC2FullAccess": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ec2:*"], "Resource": ["*"]}],
        },
        "DynamoDBReadOnlyAccess": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:DescribeTable", "dynamodb:ListTables"],
                    "Resource": ["arn:aws:dynamodb:*:*:table/*"],
                }
            ],
        },
        "DynamoDBFullAccess": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["dynamodb:*"], "Resource": ["arn:aws:dynamodb:*:*:table/*"]}],
        },
        "ReadOnlyAccess": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject", "s3:ListBucket",
                        "ec2:Describe*",
                        "lambda:GetFunction", "lambda:ListFunctions",
                        "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:DescribeTable",
                        "rds:DescribeDBInstances", "rds:DescribeDBClusters",
                        "sns:ListTopics", "sns:GetTopicAttributes",
                        "sqs:ListQueues", "sqs:GetQueueAttributes",
                    ],
                    "Resource": ["*"],
                }
            ],
        },
        "DenyS3Delete": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
                    "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"],
                }
            ],
        },
    }

    for pname, pdoc in policies_data.items():
        if pname not in ctx.policies:
            ctx.policies[pname] = Policy(PolicyName=pname, PolicyDocument=pdoc)

    # Grupos
    groups_data = {
        "Admins": {"policies": ["AdministratorAccess"]},
        "Developers": {"policies": ["S3FullAccess", "EC2FullAccess", "LambdaInvokeFunction", "DynamoDBFullAccess"]},
        "Analysts": {"policies": ["ReadOnlyAccess", "S3ReadOnlyAccess"]},
        "DevOps": {"policies": ["EC2FullAccess", "S3FullAccess", "DynamoDBFullAccess"]},
    }

    for gname, gdata in groups_data.items():
        if gname not in ctx.groups:
            ctx.groups[gname] = Group(GroupName=gname, AttachedPolicies=gdata["policies"])

    # Usuários
    users_data = {
        "admin": {"groups": ["Admins"], "policies": []},
        "dev-alice": {"groups": ["Developers"], "policies": []},
        "dev-bob": {"groups": ["Developers"], "policies": ["DenyS3Delete"]},
        "analyst-carol": {"groups": ["Analysts"], "policies": []},
        "devops-dave": {"groups": ["DevOps"], "policies": ["DynamoDBReadOnlyAccess"]},
    }

    for uname, udata in users_data.items():
        if uname not in ctx.users:
            ctx.users[uname] = User(
                UserName=uname,
                Groups=udata["groups"],
                AttachedPolicies=udata["policies"],
            )

    # Roles
    roles_data = {
        "EC2InstanceRole": {
            "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
            "policies": ["S3ReadOnlyAccess", "DynamoDBReadOnlyAccess"],
        },
        "LambdaExecutionRole": {
            "trust": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
            "policies": ["DynamoDBFullAccess"],
        },
    }

    for rname, rdata in roles_data.items():
        if rname not in ctx.roles:
            ctx.roles[rname] = Role(
                RoleName=rname,
                AssumeRolePolicyDocument=rdata["trust"],
                AttachedPolicies=rdata["policies"],
            )

    ctx.save()
    click.echo("Seed data created successfully!")
    click.echo(f"  Policies: {len(policies_data)}")
    click.echo(f"  Groups: {len(groups_data)}")
    click.echo(f"  Users: {len(users_data)}")
    click.echo(f"  Roles: {len(roles_data)}")


@cli.command("report")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def report(ctx: IAMContext, json_output: bool):
    """Gerar relatório de segurança do IAM."""
    report_data = {
        "users": [],
        "groups": [],
        "policies": [],
        "roles": [],
    }

    for name, u in sorted(ctx.users.items()):
        user_report = {
            "name": u.UserName,
            "arn": u.Arn,
            "groups": u.Groups,
            "attached_policies": u.AttachedPolicies,
            "inline_policies": [ip.get("PolicyName", "unnamed") for ip in u.InlinePolicies],
            "tags": u.Tags,
        }
        report_data["users"].append(user_report)

    for name, g in sorted(ctx.groups.items()):
        group_report = {
            "name": g.GroupName,
            "arn": g.Arn,
            "members": g.Members,
            "attached_policies": g.AttachedPolicies,
            "inline_policies": [ip.get("PolicyName", "unnamed") for ip in g.InlinePolicies],
            "tags": g.Tags,
        }
        report_data["groups"].append(group_report)

    for name, p in sorted(ctx.policies.items()):
        policy_report = {
            "name": p.PolicyName,
            "arn": p.Arn,
            "attachment_count": p.AttachmentCount,
            "tags": p.Tags,
        }
        report_data["policies"].append(policy_report)

    for name, r in sorted(ctx.roles.items()):
        role_report = {
            "name": r.RoleName,
            "arn": r.Arn,
            "attached_policies": r.AttachedPolicies,
            "inline_policies": [ip.get("PolicyName", "unnamed") for ip in r.InlinePolicies],
            "trust_policy": r.AssumeRolePolicyDocument,
            "tags": r.Tags,
        }
        report_data["roles"].append(role_report)

    if json_output:
        click.echo(json.dumps(report_data, indent=2))
    else:
        click.secho("\n=== IAM Security Report ===\n", bold=True)
        click.echo(f"Users: {len(report_data['users'])}")
        click.echo(f"Groups: {len(report_data['groups'])}")
        click.echo(f"Policies: {len(report_data['policies'])}")
        click.echo(f"Roles: {len(report_data['roles'])}")

        click.secho("\n--- Users ---", bold=True)
        for u in report_data["users"]:
            click.echo(f"  {u['name']}")
            click.echo(f"    Groups: {', '.join(u['groups']) if u['groups'] else 'none'}")
            click.echo(f"    Policies: {', '.join(u['attached_policies']) if u['attached_policies'] else 'none'}")
            if u['tags']:
                click.echo(f"    Tags: {', '.join(f'{t['Key']}={t['Value']}' for t in u['tags'])}")

        click.secho("\n--- Groups ---", bold=True)
        for g in report_data["groups"]:
            click.echo(f"  {g['name']}")
            click.echo(f"    Members: {', '.join(g['members']) if g['members'] else 'none'}")
            click.echo(f"    Policies: {', '.join(g['attached_policies']) if g['attached_policies'] else 'none'}")

        click.secho("\n--- Policies ---", bold=True)
        for p in report_data["policies"]:
            click.echo(f"  {p['name']} (attachments: {p['attachment_count']})")

        click.secho("\n--- Roles ---", bold=True)
        for r in report_data["roles"]:
            click.echo(f"  {r['name']}")
            click.echo(f"    Policies: {', '.join(r['attached_policies']) if r['attached_policies'] else 'none'}")
        click.echo("")


@cli.command("services")
def services_cmd():
    """Listar serviços AWS simulados e suas ações."""
    for svc in list_services():
        click.echo(f"\n  {svc.upper()}:")
        for action in get_actions_for_service(svc):
            click.echo(f"    - {action}")


@cli.command("validate")
@click.option("--document", "-d", required=True, help="JSON do documento da política (inline ou caminho)")
@click.option("--file", "-f", "from_file", is_flag=True, help="Indica que --document é um caminho de arquivo")
def validate_policy(document: str, from_file: bool):
    """Validar um documento de política IAM."""
    if from_file:
        doc_path = Path(document)
        if not doc_path.exists():
            click.echo(f"Error: File '{document}' not found.", err=True)
            sys.exit(1)
        with open(doc_path) as f:
            doc = json.load(f)
    else:
        try:
            doc = json.loads(document)
        except json.JSONDecodeError as e:
            click.echo(f"Error: Invalid JSON: {e}", err=True)
            sys.exit(1)

    errors = []

    if "Version" not in doc:
        errors.append("Missing 'Version' field")
    elif doc["Version"] != "2012-10-17":
        errors.append(f"Invalid Version: '{doc['Version']}' (expected '2012-10-17')")

    if "Statement" not in doc:
        errors.append("Missing 'Statement' field")
    else:
        stmts = doc["Statement"]
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            errors.append("'Statement' must be a list or dict")
        else:
            for i, stmt in enumerate(stmts):
                prefix = f"Statement[{i}]"
                if "Effect" not in stmt:
                    errors.append(f"{prefix}: missing 'Effect'")
                elif stmt["Effect"] not in ("Allow", "Deny"):
                    errors.append(f"{prefix}: invalid Effect '{stmt['Effect']}' (must be 'Allow' or 'Deny')")
                if "Action" not in stmt:
                    errors.append(f"{prefix}: missing 'Action'")
                else:
                    actions = stmt["Action"]
                    if isinstance(actions, str):
                        actions = [actions]
                    for a in actions:
                        if ":" not in a and a != "*":
                            errors.append(f"{prefix}: invalid Action format '{a}' (expected 'service:Action')")
                if "Resource" not in stmt:
                    errors.append(f"{prefix}: missing 'Resource'")
                else:
                    resources = stmt["Resource"]
                    if isinstance(resources, str):
                        resources = [resources]
                    for r in resources:
                        if r != "*" and not r.startswith("arn:"):
                            errors.append(f"{prefix}: invalid Resource ARN '{r}'")

    if errors:
        click.secho(f"\nValidation failed with {len(errors)} error(s):", fg="red", bold=True)
        for err in errors:
            click.echo(f"  - {err}")
        sys.exit(1)
    else:
        click.secho("Policy document is valid.", fg="green", bold=True)


@cli.command("what-can")
@click.option("--user", "-u", default=None, help="Usuário a ser consultado")
@click.option("--role", "-r", default=None, help="Role a ser consultada")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def what_can(ctx: IAMContext, user: str | None, role: str | None, json_output: bool):
    """Listar todas as permissões efetivas de um usuário ou role."""
    if not user and not role:
        click.echo("Error: You must specify --user or --role.", err=True)
        sys.exit(1)
    if user and role:
        click.echo("Error: You cannot specify both --user and --role.", err=True)
        sys.exit(1)

    if user:
        if user not in ctx.users:
            raise EntityNotFoundError("User", user)
        principal_name = user
        principal_type = "user"
    else:
        if role not in ctx.roles:
            raise EntityNotFoundError("Role", role)
        principal_name = role
        principal_type = "role"

    all_actions = set()
    for svc, actions in SERVICE_ACTIONS.items():
        for action in actions:
            all_actions.add(action)

    allowed = []
    denied = []

    for action in sorted(all_actions):
        for svc_resource in ["*"]:
            resource = f"arn:aws:{action.split(':')[0]}:*:*:*"
            result = evaluate_access(
                action=action,
                resource=resource,
                user=ctx.users.get(user) if user else None,
                role=ctx.roles.get(role) if role else None,
                groups=ctx.groups,
                policies=ctx.policies,
            )
            if result["allowed"]:
                allowed.append({"action": action, "policies": result["matched_policies"]})
            elif result["reason"] == "Deny":
                denied.append({"action": action, "denied_by": result["denied_by"]})

    if json_output:
        click.echo(json.dumps({
            "principal": principal_name,
            "principal_type": principal_type,
            "allowed_count": len(allowed),
            "denied_count": len(denied),
            "allowed": allowed,
            "denied": denied,
        }, indent=2))
    else:
        click.echo(f"\nPermissions for {principal_type}: {principal_name}")
        click.echo(f"  Allowed: {len(allowed)} actions")
        click.echo(f"  Denied:  {len(denied)} actions")
        if allowed:
            click.echo("\n  Allowed actions:")
            for item in allowed:
                click.echo(f"    {item['action']}  ({', '.join(item['policies'])})")
        if denied:
            click.echo("\n  Denied actions:")
            for item in denied:
                click.echo(f"    {item['action']}  (denied by: {item['denied_by']})")
        click.echo("")


@cli.command("who-can")
@click.option("--action", "-a", required=True, help="Ação a ser verificada (ex: s3:DeleteObject)")
@click.option("--resource", "-R", required=True, help="ARN do recurso")
@click.option("--json-output", "-j", is_flag=True, help="Saída em formato JSON")
@pass_context
def who_can(ctx: IAMContext, action: str, resource: str, json_output: bool):
    """Listar quem tem acesso a uma ação em um recurso."""
    results = []

    for name, user_obj in ctx.users.items():
        result = evaluate_access(
            action=action,
            resource=resource,
            user=user_obj,
            groups=ctx.groups,
            policies=ctx.policies,
        )
        results.append({
            "name": name,
            "type": "user",
            "allowed": result["allowed"],
            "reason": result["reason"],
            "matched_policies": result["matched_policies"],
            "denied_by": result["denied_by"],
        })

    for name, role_obj in ctx.roles.items():
        result = evaluate_access(
            action=action,
            resource=resource,
            role=role_obj,
            groups=ctx.groups,
            policies=ctx.policies,
        )
        results.append({
            "name": name,
            "type": "role",
            "allowed": result["allowed"],
            "reason": result["reason"],
            "matched_policies": result["matched_policies"],
            "denied_by": result["denied_by"],
        })

    allowed = [r for r in results if r["allowed"]]
    denied = [r for r in results if r["reason"] == "Deny"]

    if json_output:
        click.echo(json.dumps({
            "action": action,
            "resource": resource,
            "allowed": allowed,
            "denied": denied,
        }, indent=2))
    else:
        click.echo(f"\nWho can: {action} on {resource}")
        if allowed:
            click.secho(f"\n  Allowed ({len(allowed)}):", fg="green")
            for r in allowed:
                policies = ', '.join(r['matched_policies'])
                click.echo(f"    {r['type']}: {r['name']}  ({policies})")
        if denied:
            click.secho(f"\n  Denied ({len(denied)}):", fg="red")
            for r in denied:
                click.echo(f"    {r['type']}: {r['name']}  (denied by: {r['denied_by']})")
        if not allowed and not denied:
            click.echo("\n  No principals found.")
        click.echo("")


# ─── HANDLER DE ERROS ─────────────────────────────────────────────

def main():
    try:
        cli()
    except IAMSimulatorError as e:
        raise click.ClickException(str(e))
    except KeyboardInterrupt:
        click.echo("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
