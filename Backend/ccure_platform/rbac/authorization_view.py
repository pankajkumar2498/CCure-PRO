"""
ccure_platform/rbac/authorization_view.py — what the signed-in user may do, for the UI.

RBAC-6. The frontend does not reconstruct permissions from a role: it is told the
account's **effective permission keys** for the organisation it is acting in, split by
scope, and asks ``can(key)``. This builds that answer. It is **advisory** — a UI hides
what a person cannot do — and the backend still enforces every request; a forged copy of
this payload in a browser grants nothing.

Contract (``/auth/me`` → ``authorization``), stable and free of database structure:

``contract``          1
``source``            ``platform`` — the RBAC engine's answer (the account holds an RBAC
                      assignment); ``legacy_mapped`` — the account has none yet, so the
                      legacy role's permissions expressed as the same keys through the
                      golden mapping. A UI cannot tell them apart by behaviour.
``home_org_id``       the account's own organisation
``active_org_id``     the organisation this answer is for — validated by the backend
                      (``scope.resolve_active_organisation``), never the client's word
``permissions``       ``{"platform": [key…], "organization": [key…]}`` — effective in the
                      active organisation, by the permission's scope kind
``can_switch_organisation``  the platform-scope switch grant (cross-organisation reach)
``assignments``       ``[{display_name, scope_type}]`` — **display only**
``atoms``             ``{"resource:action": [key…]}`` — the legacy vocabulary the
                      platform-administration screens still speak (RBAC-7), served so the
                      UI copies nothing

No role id, role key, row id or table name is exposed, and no role name is an input.
"""

from __future__ import annotations

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, legacy_map, resolver
from ccure_platform.rbac.legacy_scope import legacy_acts_across_organisations
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from sqlalchemy.orm import Session

CONTRACT_VERSION = 1


def _atoms(golden) -> dict[str, list[str]]:
    return {a["atom"]: list(a["new_keys"]) for a in golden["atoms"] if a["new_keys"]}


def _split(keys, catalogue) -> dict[str, list[str]]:
    out = {"platform": [], "organization": []}
    for key in sorted(keys):
        perm = catalogue.get(key)
        kind = perm.scope_kind if perm else "organization"
        out["platform" if kind == "platform" else "organization"].append(key)
    return out


def _display_assignments(db: Session, user_id: str) -> list[dict]:
    from datetime import datetime, timezone

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


def _legacy_mapped(user, golden, catalogue, home_org, active_org):
    """The legacy role's permissions as keys. A superadmin held everything; any other
    role held its atoms, each expressed as the keys the golden mapping names."""
    reach = legacy_acts_across_organisations(user)
    all_keys = {p["key"] for p in golden["permissions"]}
    if reach:
        keys = set(all_keys)
    else:
        atoms = _atoms(golden)
        keys = set()
        role = getattr(user, "role", None)
        for rp in getattr(role, "permissions", None) or []:
            keys.update(
                atoms.get(f"{rp.permission.resource}:{rp.permission.action}", ())
            )
        # a legacy account never held platform-wide capability without the superadmin
        # role; nothing else is inferred
    keys &= set(catalogue) if catalogue else all_keys
    return keys, reach


def build_authorization(db: Session, user, active_org_id: str | None = None) -> dict:
    """The authorization payload for ``user`` acting in ``active_org_id`` (already
    validated by the caller; None means the account's own organisation)."""
    golden = legacy_map.load_golden()
    catalogue = resolver.load_catalogue(db)
    principal = resolver.principal_for_user(user)
    home = str(user.org_id) if getattr(user, "org_id", None) else None
    active = str(active_org_id) if active_org_id else home
    assignments = resolver.assignment_summary(db, principal) if catalogue else ()

    if catalogue and assignments:
        grants = resolver.resolve_grants(db, principal)
        keys = engine.held_keys(principal, grants, catalogue, active)
        switch = engine.decide(principal, grants, catalogue, c.ORG_SWITCH_KEY).allowed
        source = "platform"
        shown = _display_assignments(db, principal.principal_id)
    else:
        keys, switch = _legacy_mapped(user, golden, catalogue, home, active)
        source = "legacy_mapped"
        shown = []
    return {
        "contract": CONTRACT_VERSION,
        "source": source,
        "home_org_id": home,
        "active_org_id": active,
        "permissions": _split(keys, catalogue or {}),
        "can_switch_organisation": bool(switch),
        "assignments": shown,
        "atoms": _atoms(golden),
    }
