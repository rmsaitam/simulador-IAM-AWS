"""Persistência de dados em JSON para o simulador IAM AWS."""

import json
import os
from pathlib import Path
from typing import Any

from .models import User, Group, Policy, Role

DEFAULT_DATA_DIR = Path(__file__).parent.parent / "data"
DEFAULT_DATA_FILE = DEFAULT_DATA_DIR / "iam_data.json"


def _ensure_data_dir():
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_data(filepath: Path | None = None) -> dict[str, Any]:
    fp = filepath or DEFAULT_DATA_FILE
    if not fp.exists():
        return {
            "users": {},
            "groups": {},
            "policies": {},
            "roles": {},
        }
    with open(fp, "r") as f:
        return json.load(f)


def save_data(data: dict[str, Any], filepath: Path | None = None):
    fp = filepath or DEFAULT_DATA_FILE
    _ensure_data_dir()
    with open(fp, "w") as f:
        json.dump(data, f, indent=2, default=str)


def load_users(data: dict) -> dict[str, User]:
    return {name: User.from_dict(u) for name, u in data.get("users", {}).items()}


def load_groups(data: dict) -> dict[str, Group]:
    return {name: Group.from_dict(g) for name, g in data.get("groups", {}).items()}


def load_policies(data: dict) -> dict[str, Policy]:
    return {name: Policy.from_dict(p) for name, p in data.get("policies", {}).items()}


def load_roles(data: dict) -> dict[str, Role]:
    return {name: Role.from_dict(r) for name, r in data.get("roles", {}).items()}


def persist_all(users: dict[str, User], groups: dict[str, Group],
                policies: dict[str, Policy], roles: dict[str, Role],
                filepath: Path | None = None):
    data = {
        "users": {name: u.to_dict() for name, u in users.items()},
        "groups": {name: g.to_dict() for name, g in groups.items()},
        "policies": {name: p.to_dict() for name, p in policies.items()},
        "roles": {name: r.to_dict() for name, r in roles.items()},
    }
    save_data(data, filepath)
