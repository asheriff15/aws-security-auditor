"""Helpers for reading IAM / resource policy documents."""
from __future__ import annotations

import json


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(document) -> list[dict]:
    if isinstance(document, str):
        document = json.loads(document)
    return _as_list((document or {}).get("Statement"))


def is_full_admin(stmt: dict) -> bool:
    """True for Allow / Action "*" / Resource "*" — i.e. full administrator access."""
    if stmt.get("Effect") != "Allow":
        return False
    actions = _as_list(stmt.get("Action"))
    resources = _as_list(stmt.get("Resource"))
    return "*" in actions and "*" in resources


def is_public_principal(stmt: dict) -> bool:
    """True when an Allow statement grants access to everyone with no Condition limiting it."""
    if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
        return False
    principal = stmt.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in _as_list(principal.get("AWS"))
    return False
