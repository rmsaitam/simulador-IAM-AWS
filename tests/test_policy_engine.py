"""Testes unitários para o engine de avaliação de políticas IAM."""

import pytest
from iam_simulator.models import User, Group, Policy, Role, PolicyDocument
from iam_simulator.policy_engine import (
    evaluate_access,
    _arn_match,
    _action_match,
    _eval_statements,
    _collect_policies_from_user,
)


# ─── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def s3_read_policy():
    return Policy(
        PolicyName="S3ReadOnlyAccess",
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
                }
            ],
        },
    )


@pytest.fixture
def admin_policy():
    return Policy(
        PolicyName="AdministratorAccess",
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
        },
    )


@pytest.fixture
def deny_s3_delete_policy():
    return Policy(
        PolicyName="DenyS3Delete",
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["s3:DeleteObject"],
                    "Resource": ["arn:aws:s3:::*/*"],
                }
            ],
        },
    )


@pytest.fixture
def user_ro(s3_read_policy):
    return User(
        UserName="readonly-user",
        Groups=[],
        AttachedPolicies=["S3ReadOnlyAccess"],
    )


@pytest.fixture
def user_admin(admin_policy):
    return User(
        UserName="admin-user",
        Groups=[],
        AttachedPolicies=["AdministratorAccess"],
    )


@pytest.fixture
def user_with_deny(s3_read_policy, deny_s3_delete_policy):
    return User(
        UserName="deny-user",
        Groups=[],
        AttachedPolicies=["S3ReadOnlyAccess", "DenyS3Delete"],
    )


@pytest.fixture
def user_in_group(s3_read_policy):
    return User(
        UserName="group-user",
        Groups=["Developers"],
        AttachedPolicies=[],
    )


@pytest.fixture
def group_developers(s3_read_policy):
    return Group(
        GroupName="Developers",
        Members=["group-user"],
        AttachedPolicies=["S3ReadOnlyAccess"],
    )


# ─── ARN Matching ──────────────────────────────────────────────────

class TestArnMatch:
    def test_exact_match(self):
        assert _arn_match("arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket")

    def test_wildcard_all(self):
        assert _arn_match("*", "arn:aws:s3:::my-bucket")

    def test_wildcard_bucket(self):
        assert _arn_match("arn:aws:s3:::*", "arn:aws:s3:::my-bucket")

    def test_wildcard_objects(self):
        assert _arn_match("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/file.txt")

    def test_no_match(self):
        assert not _arn_match("arn:aws:s3:::other-bucket", "arn:aws:s3:::my-bucket")

    def test_partial_wildcard(self):
        assert _arn_match("arn:aws:s3:::my-*", "arn:aws:s3:::my-bucket")


# ─── Action Matching ──────────────────────────────────────────────

class TestActionMatch:
    def test_exact_match(self):
        assert _action_match("s3:GetObject", "s3:GetObject")

    def test_wildcard_all(self):
        assert _action_match("*", "s3:GetObject")

    def test_wildcard_prefix(self):
        assert _action_match("s3:Get*", "s3:GetObject")

    def test_no_match(self):
        assert not _action_match("s3:PutObject", "s3:GetObject")


# ─── Policy Evaluation ────────────────────────────────────────────

class TestPolicyEvaluation:
    def test_allow_access(self, user_ro, s3_read_policy, group_developers):
        policies = {"S3ReadOnlyAccess": s3_read_policy}
        result = evaluate_access(
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            user=user_ro,
            groups={},
            policies=policies,
        )
        assert result["allowed"] is True
        assert result["reason"] == "Allow"

    def test_implicit_deny(self, user_ro, s3_read_policy):
        policies = {"S3ReadOnlyAccess": s3_read_policy}
        result = evaluate_access(
            action="s3:PutObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            user=user_ro,
            groups={},
            policies=policies,
        )
        assert result["allowed"] is False
        assert result["reason"] == "ImplicitDeny"

    def test_explicit_deny(self, user_with_deny, s3_read_policy, deny_s3_delete_policy):
        policies = {
            "S3ReadOnlyAccess": s3_read_policy,
            "DenyS3Delete": deny_s3_delete_policy,
        }
        result = evaluate_access(
            action="s3:DeleteObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            user=user_with_deny,
            groups={},
            policies=policies,
        )
        assert result["allowed"] is False
        assert result["reason"] == "Deny"
        assert result["denied_by"] == "DenyS3Delete"

    def test_group_policy(self, user_in_group, group_developers, s3_read_policy):
        policies = {"S3ReadOnlyAccess": s3_read_policy}
        groups = {"Developers": group_developers}
        result = evaluate_access(
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            user=user_in_group,
            groups=groups,
            policies=policies,
        )
        assert result["allowed"] is True

    def test_no_policies(self):
        user = User(UserName="empty-user")
        result = evaluate_access(
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            user=user,
        )
        assert result["allowed"] is False
        assert result["reason"] == "ImplicitDeny"

    def test_role_access(self, s3_read_policy):
        role = Role(
            RoleName="TestRole",
            AttachedPolicies=["S3ReadOnlyAccess"],
        )
        policies = {"S3ReadOnlyAccess": s3_read_policy}
        result = evaluate_access(
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            role=role,
            policies=policies,
        )
        assert result["allowed"] is True

    def test_admin_policy_allows_all(self, user_admin, admin_policy):
        policies = {"AdministratorAccess": admin_policy}
        result = evaluate_access(
            action="ec2:RunInstances",
            resource="arn:aws:ec2:*:*:instance/*",
            user=user_admin,
            policies=policies,
        )
        assert result["allowed"] is True

    def test_condition_evaluation(self):
        policy = Policy(
            PolicyName="ConditionalPolicy",
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::my-bucket/*"],
                        "Condition": {
                            "StringEquals": {
                                "aws:RequestedRegion": "us-east-1"
                            }
                        },
                    }
                ],
            },
        )
        user = User(UserName="cond-user", AttachedPolicies=["ConditionalPolicy"])

        result = evaluate_access(
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            user=user,
            policies={"ConditionalPolicy": policy},
            context={"aws:RequestedRegion": "us-east-1"},
        )
        assert result["allowed"] is True

        result = evaluate_access(
            action="s3:GetObject",
            resource="arn:aws:s3:::my-bucket/file.txt",
            user=user,
            policies={"ConditionalPolicy": policy},
            context={"aws:RequestedRegion": "eu-west-1"},
        )
        assert result["allowed"] is False
