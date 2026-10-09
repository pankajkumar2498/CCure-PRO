"""
ccure_platform/rbac/authorization_view.py — what the signed-in user may do, for the UI.

The frontend does not reconstruct permissions from a role: it is told the account's
**effective permission keys** for the organisation it is acting in, split by scope, and
asks ``can(key)``. This builds that answer from the RBAC engine alone (RBAC-8: there is no
other model). It is **advisory** — a UI hides what a person cannot do — and the backend
still enforces every request; a forged copy of this payload in a browser grants nothing.

Contract (``/auth/me`` → ``authorization``), stable and free of database structure:

``contract``          1
``home_org_id``       the account's own organisation
``active_org_id``     the organisation this answer is for — validated by the backend
                      (``scope.resolve_active_organisation``), never the client's word
``permissions``       ``{"platform": [key…], "organization": [key…]}`` — effective in the
                      active organisation, by the permission's scope kind. An account with
                      no RBAC assignment has none: the lists are empty
``can_switch_organisation``  the platform-scope switch grant (cross-organisation reach)
``assignments``       ``[{display_name, scope_type}]`` — **display only**

No role id, role key, row id, table name or legacy atom is exposed, and no role name is an
input.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, resolver
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from sqlalchemy.orm import Session

CONTRACT_VERSION = 1


def _split(keys, catalogue) -> dict[str, list[str]]:
    out = {"platform": [], "organization": []}
    for key in sorted(keys):
        perm = catalogue.get(key)
        kind = perm.scope_kind if perm else "organization"
        out["platform" if kind == "platform" else "organization"].append(key)
    return out


def _display_assignments(db: Session, user_id: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    rows = (
        db.query(
            RbacRole.display_name,
            RbacUserRole.scope_type,
            RbacUserRole.expires_at,
        )
        .join(RbacRole, RbacRole.id == RbacUserRole.role_id)
        .filter(
            RbacUserRole.user_id == user_id,
            RbacUserRole.revoked_at.is_(None),
            RbacRole.state.in_(("active", "retiring")),
        )
        .order_by(RbacRole.display_name)
        .all()
    )
    return [
        {"display_name": name, "scope_type": scope}
        for name, scope, expires in rows
        if expires is None or expires > now
    ]


def build_authorization(db: Session, user, active_org_id: str | None = None) -> dict:
    """The authorization payload for ``user`` acting in ``active_org_id`` (already
    validated by the caller; None means the account's own organisation)."""
    catalogue = resolver.load_catalogue(db)
    principal = resolver.principal_for_user(user)
    home = str(user.org_id) if getattr(user, "org_id", None) else None
    active = str(active_org_id) if active_org_id else home
    grants = resolver.resolve_grants(db, principal) if catalogue else ()
    keys = (
        engine.held_keys(principal, grants, catalogue, active)
        if grants
        else frozenset()
    )
    switch = (
        engine.decide(principal, grants, catalogue, c.ORG_SWITCH_KEY).allowed
        if grants
        else False
    )
    return {
        "contract": CONTRACT_VERSION,
        "home_org_id": home,
        "active_org_id": active,
        "permissions": _split(keys, catalogue or {}),
        "can_switch_organisation": bool(switch),
        "assignments": _display_assignments(db, principal.principal_id),
    }
