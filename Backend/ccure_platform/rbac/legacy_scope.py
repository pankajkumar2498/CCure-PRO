"""
ccure_platform/rbac/legacy_scope.py — the legacy scope rules, kept as the rollback path.

RBAC-5 expresses "where may this account act" through the scope model
(``rbac/scope.py``). These two functions are the rules it replaced, still used while a
scope path is switched off or the new model cannot answer. They are the only place a
role name decides scope, and they go with the legacy model (RBAC-8).
"""

from __future__ import annotations


def legacy_acts_across_organisations(user) -> bool:
    """Acting outside one's own organisation was the superadmin role."""
    role = getattr(user, "role", None)
    return bool(role) and (getattr(role, "name", "") or "").lower() == "superadmin"


def legacy_assignment_allowed(actor, target_role) -> bool:
    """Only a superadmin could hand out the superadmin role."""
    if (getattr(target_role, "name", "") or "").lower() != "superadmin":
        return True
    return legacy_acts_across_organisations(actor)
