"""
The one way a CCure module reaches identity, organisations and roles.

Step 8.3 of the modular-platform programme
(``docs/architecture/PHASE8_PLATFORM_IDENTITY.md``). Module code — Audit today,
Policy Pro, Rank and IR next — asks these functions instead of querying
``users``, ``organizations``, ``roles`` or ``role_permissions`` itself. A later
authentication service (plan §3.9) replaces what is behind them, not their
callers.

What is here is what the modules were measured to need, and nothing more
(``scripts/architecture/identity_boundary.PLATFORM_API_SURFACE`` is the
ceiling, and a test fails on anything outside it):

* **Request identity** — ``current_user``, ``current_user_flexible``,
  ``require_permission``, ``require_role``: the FastAPI dependencies routes
  already use, re-exported unchanged. They still hand a route the ORM ``User``,
  because every route reads its attributes; views for those are a later
  decision, not a side effect of this step.
* **RBAC** — ``user_has_permission``: the single implementation behind
  ``require_permission``, for checks a dependency cannot express.
* **Accounts** — ``user`` / ``UserView``, ``user_display_names``,
  ``active_members_with_roles``.
* **Tenancy** — ``organisation`` / ``OrganisationView``.
* **Organisation plan** (step 8.4) — ``scan_limits``, ``scan_scope``,
  ``remediation_sla_setting`` / ``store_remediation_sla_setting``. Each is one
  removable plan feature (``ccure_platform/plan/``) with exactly one consumer in
  each module; ``tests/repo/test_plan_feature_containment.py`` holds that.

Two rules every function keeps:

* **The caller's session is used**, so a read sees exactly what the direct
  query it replaces saw — the same transaction, the same autoflush.
* **Only plain values leave.** A view is a frozen dataclass of strings and
  booleans; no ORM row crosses the boundary from these functions.

``OrganisationView`` carries no plan field. Plan features are separate
functions with separate views so that each can be removed without touching the
others or the organisation's identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Union

from ccure_platform.identity.dependencies import get_current_user as current_user
from ccure_platform.plan.remediation_sla import (
    RemediationSlaSettingView,
    remediation_sla_setting,
    store_remediation_sla_setting,
)
from ccure_platform.plan.scan_limits import ScanLimits, ScanLimitsView, scan_limits
from ccure_platform.plan.scan_scope import ScanScopeView, scan_scope
from ccure_platform.identity.dependencies import (
    get_current_user_flexible as current_user_flexible,
)
from ccure_platform.rbac.dependencies import require_permission, require_role
from ccure_platform.rbac.dependencies import (
    user_has_permission as _role_holds_permission,
)
from db.models import Organization, Role, User
from sqlalchemy.orm import Session

__all__ = (
    "current_user",
    "current_user_flexible",
    "require_permission",
    "require_role",
    "user_has_permission",
    "UserView",
    "user",
    "user_display_names",
    "active_members_with_roles",
    "OrganisationView",
    "organisation",
    # organisation plan — one removable feature per group
    "ScanLimits",
    "ScanLimitsView",
    "scan_limits",
    "ScanScopeView",
    "scan_scope",
    "RemediationSlaSettingView",
    "remediation_sla_setting",
    "store_remediation_sla_setting",
)


# ── views ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class UserView:
    """An account, as a module may see it."""

    id: str
    org_id: str
    username: str
    email: str
    #: The account's own "in-app alerts" preference. Absent means on; only an
    #: explicit ``False`` turns it off.
    in_app_alerts: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class OrganisationView:
    """
    An organisation's identity — never its Audit configuration.

    Quotas, scan scope and the remediation SLA policy are Audit's and are not
    here; see the module docstring.
    """

    id: str
    name: str
    slug: str


def _user_view(row: User) -> UserView:
    preferences = row.preferences if isinstance(row.preferences, dict) else {}
    return UserView(
        id=str(row.id),
        org_id=row.org_id,
        username=row.username,
        email=row.email,
        in_app_alerts=preferences.get("in_app_alerts", True) is not False,
    )


# ── accounts ──────────────────────────────────────────────────────────────────


def user(db: Session, user_id: str | None) -> UserView | None:
    """
    The account with this id, or None.

    Deleted, inactive and unapproved accounts are returned as they are: the
    callers this replaces resolved a scan's owner or an audit actor by id, and
    an owner who has since been disabled is still that scan's owner.
    """
    if not user_id:
        return None
    row = db.query(User).filter(User.id == str(user_id)).first()
    return _user_view(row) if row is not None else None


def user_display_names(db: Session, user_ids: Iterable[str]) -> dict[str, str]:
    """
    ``{user id: the name the account is shown by}`` for the ids that exist.

    The name is the email address — the one identifier every account has, and
    what exports have always printed for an owner. An id with no account is
    absent from the result, never mapped to an empty string, so a caller can
    tell "unknown owner" from "owner with no name".
    """
    wanted = {str(u) for u in user_ids if u}
    if not wanted:
        return {}
    rows = db.query(User.id, User.email).filter(User.id.in_(wanted)).all()
    return {str(uid): str(email or "") for uid, email in rows}


def active_members_with_roles(
    db: Session, org_id: str, role_names: Iterable[str]
) -> list[UserView]:
    """
    The active, undeleted accounts in ``org_id`` holding any of ``role_names``.

    Role names are matched exactly, as stored. No matching role gives an empty
    list without querying accounts.
    """
    names = list(role_names)
    role_ids = [r.id for r in db.query(Role).filter(Role.name.in_(names)).all()]
    if not role_ids:
        return []
    rows = (
        db.query(User)
        .filter(
            User.org_id == org_id,
            User.role_id.in_(role_ids),
            User.is_active == True,  # noqa: E712  (SQL comparison)
            User.is_deleted == False,  # noqa: E712
        )
        .all()
    )
    return [_user_view(row) for row in rows]


# ── RBAC ──────────────────────────────────────────────────────────────────────


def user_has_permission(
    db: Session, account: Union[User, str, None], resource: str, action: str
) -> bool:
    """
    Whether the account's role holds the ``resource:action`` permission atom.

    ``account`` is the ``User`` a route already holds (from ``current_user``)
    or an account id. Superadmin holds everything; an account with no role, or
    no account, holds nothing. This is ``require_permission``'s own rule, so a
    check made here can never disagree with a route guard.
    """
    if account is None:
        return False
    if isinstance(account, str):
        account = db.query(User).filter(User.id == account).first()
        if account is None:
            return False
    return _role_holds_permission(db, account, resource, action)


# ── tenancy ───────────────────────────────────────────────────────────────────


def organisation(db: Session, org_id: str | None) -> OrganisationView | None:
    """
    The organisation with this id, or None.

    Callers decide what a missing organisation means; most fall back to the id
    itself where they needed the slug, as they did before.
    """
    if not org_id:
        return None
    row = db.query(Organization).filter(Organization.id == str(org_id)).first()
    if row is None:
        return None
    return OrganisationView(
        id=str(row.id),
        name=row.name,
        slug=row.slug,
    )
