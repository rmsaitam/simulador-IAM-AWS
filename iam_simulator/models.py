"""Modelos de dados para o simulador IAM AWS."""

from dataclasses import dataclass, field
from typing import Any
import time
import uuid


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class PolicyDocument:
    """Representa um statement de política IAM."""
    Effect: str  # Allow | Deny
    Action: list[str]
    Resource: list[str]
    Condition: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "Effect": self.Effect,
            "Action": self.Action,
            "Resource": self.Resource,
        }
        if self.Condition:
            d["Condition"] = self.Condition
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyDocument":
        action = data.get("Action", [])
        if isinstance(action, str):
            action = [action]
        resource = data.get("Resource", [])
        if isinstance(resource, str):
            resource = [resource]
        return cls(
            Effect=data["Effect"],
            Action=action,
            Resource=resource,
            Condition=data.get("Condition"),
        )


@dataclass
class Policy:
    """Política IAM gerenciada."""
    PolicyName: str
    PolicyDocument: dict  # Documento completo com Version e Statement
    Arn: str = ""
    CreateDate: str = ""
    AttachmentCount: int = 0

    def __post_init__(self):
        if not self.Arn:
            self.Arn = f"arn:aws:iam::123456789012:policy/{self.PolicyName}"
        if not self.CreateDate:
            self.CreateDate = _timestamp()

    def statements(self) -> list[PolicyDocument]:
        stmts = self.PolicyDocument.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        return [PolicyDocument.from_dict(s) for s in stmts]

    def to_dict(self) -> dict:
        return {
            "PolicyName": self.PolicyName,
            "PolicyDocument": self.PolicyDocument,
            "Arn": self.Arn,
            "CreateDate": self.CreateDate,
            "AttachmentCount": self.AttachmentCount,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        return cls(**data)


@dataclass
class User:
    """Usuário IAM."""
    UserName: str
    UserId: str = ""
    Arn: str = ""
    CreateDate: str = ""
    Groups: list[str] = field(default_factory=list)
    AttachedPolicies: list[str] = field(default_factory=list)
    InlinePolicies: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.UserId:
            self.UserId = f"AIDA{uuid.uuid4().hex[:16].upper()}"
        if not self.Arn:
            self.Arn = f"arn:aws:iam::123456789012:user/{self.UserName}"
        if not self.CreateDate:
            self.CreateDate = _timestamp()

    def to_dict(self) -> dict:
        return {
            "UserName": self.UserName,
            "UserId": self.UserId,
            "Arn": self.Arn,
            "CreateDate": self.CreateDate,
            "Groups": self.Groups,
            "AttachedPolicies": self.AttachedPolicies,
            "InlinePolicies": self.InlinePolicies,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        return cls(**data)


@dataclass
class Group:
    """Grupo IAM."""
    GroupName: str
    GroupId: str = ""
    Arn: str = ""
    CreateDate: str = ""
    Members: list[str] = field(default_factory=list)
    AttachedPolicies: list[str] = field(default_factory=list)
    InlinePolicies: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.GroupId:
            self.GroupId = f"AGPA{uuid.uuid4().hex[:16].upper()}"
        if not self.Arn:
            self.Arn = f"arn:aws:iam::123456789012:group/{self.GroupName}"
        if not self.CreateDate:
            self.CreateDate = _timestamp()

    def to_dict(self) -> dict:
        return {
            "GroupName": self.GroupName,
            "GroupId": self.GroupId,
            "Arn": self.Arn,
            "CreateDate": self.CreateDate,
            "Members": self.Members,
            "AttachedPolicies": self.AttachedPolicies,
            "InlinePolicies": self.InlinePolicies,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Group":
        return cls(**data)


@dataclass
class Role:
    """Role IAM."""
    RoleName: str
    RoleId: str = ""
    Arn: str = ""
    CreateDate: str = ""
    AssumeRolePolicyDocument: dict = field(default_factory=dict)
    AttachedPolicies: list[str] = field(default_factory=list)
    InlinePolicies: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.RoleId:
            self.RoleId = f"AROA{uuid.uuid4().hex[:16].upper()}"
        if not self.Arn:
            self.Arn = f"arn:aws:iam::123456789012:role/{self.RoleName}"
        if not self.CreateDate:
            self.CreateDate = _timestamp()
        if not self.AssumeRolePolicyDocument:
            self.AssumeRolePolicyDocument = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }

    def to_dict(self) -> dict:
        return {
            "RoleName": self.RoleName,
            "RoleId": self.RoleId,
            "Arn": self.Arn,
            "CreateDate": self.CreateDate,
            "AssumeRolePolicyDocument": self.AssumeRolePolicyDocument,
            "AttachedPolicies": self.AttachedPolicies,
            "InlinePolicies": self.InlinePolicies,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Role":
        return cls(**data)
