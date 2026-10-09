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

* **Request identity** — ``current_user``, ``current_user_flexible``: the FastAPI
  dependencies routes already use, re-exported unchanged. They hand a route the ORM
  ``User``. ``CurrentUser`` (step 8.5) is the name a route annotates that parameter with.
* **Authorization (RBAC-8, final)** — ``require_authorized(key)`` and
  ``has_permission(db, account, key, org_id=)``: the Platform RBAC engine is the **only**
  authorization decision point. A route names the permission key it enforces
  (``module.resource.action``); there is no legacy atom, role name or ``users.role_id``
  input and no fallback. Scope — ``resolve_active_organisation``,
  ``acts_across_organisations``, ``resource_organisation_allowed`` — keeps *where* apart
  from *what*. ``PermissionDecl`` declares a module's permissions as data;
  ``authorize`` / ``can`` / ``effective_permissions`` / ``require`` are the lower-level
  engine API.
* **Accounts** — ``user`` / ``UserView``, ``user_display_names``,
  ``users_holding_permission``.
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
from ccure_platform.accounts import (
    UserView,
    users_holding_permission,
    user,
    user_display_names,
)
from ccure_platform.audit_log.taxonomy import register_event_severities
from ccure_platform.audit_log.writer import log_audit_event
from ccure_platform.notifications.service import (
    NotificationCategory,
    NotificationType,
    create_notification,
    fan_out_notification,
    register_notification_categories,
)
from ccure_platform.offboarding import register_user_purge_hook
from ccure_platform.preferences import register_product_preferences
from ccure_platform.rbac import resolver as _rbac_resolver
from ccure_platform.rbac.contract import (
    AuthorizationDecision,
    EffectivePermissionSet,
    PermissionDecl,
    Principal,
    ScopeContext,
)
from ccure_platform.rbac.scope import (
    acts_across_organisations,
    resolve_active_organisation,
    resource_organisation_allowed,
)
from ccure_platform.rbac.dependencies import has_permission, require_authorized
from db.base import get_db
from db.models import Organization, User
from fastapi import Depends, HTTPException
from fastapi import status as _http_status
from sqlalchemy.orm import Session

#: The account a request is authenticated as — what ``current_user``,
#: ``current_user_flexible`` and ``require_authorized`` hand a
#: route. Today it *is* the identity model, and the alias says so rather than
#: pretending otherwise; naming it here is what lets a later phase (a narrower
#: view, or a separate authentication service, plan §3.9) change one line
#: instead of every route. It is a type for annotations, not a way to query
#: ``users``: the identity-boundary ratchet counts a query through it.
CurrentUser = User

__all__ = (
    "CurrentUser",
    "current_user",
    "current_user_flexible",
    # RBAC-4: permission-key guards that replaced role-name checks
    "require_authorized",
    "has_permission",
    # RBAC-5: where a principal may act (scope), kept apart from what it may do
    "resolve_active_organisation",
    "acts_across_organisations",
    "resource_organisation_allowed",
    # RBAC capability (RBAC-1): declared and consumable, used by no live route
    "PermissionDecl",
    "ScopeContext",
    "Principal",
    "AuthorizationDecision",
    "EffectivePermissionSet",
    "authorize",
    "can",
    "effective_permissions",
    "require",
    "UserView",
    "user",
    "user_display_names",
    "users_holding_permission",
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
    # in-app notifications: every module raises them through the platform
    "NotificationCategory",
    "NotificationType",
    "create_notification",
    "fan_out_notification",
    "register_notification_categories",
    # the platform's audit log: the one write path every module records through
    "log_audit_event",
    "register_event_severities",
    # offboarding contract — a module detaches its own data from a purged user
    "register_user_purge_hook",
    # preferences — a product registers the schema of its own preference block
    "register_product_preferences",
)


# ── views ─────────────────────────────────────────────────────────────────────


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


# ── RBAC ──────────────────────────────────────────────────────────────────────


# ── Authorization (RBAC-8: the only model) ────────────────────────────────────
#
# ``require_authorized(key)`` and ``has_permission(db, account, key)`` (above) answer from
# the RBAC engine alone. These take the account a route holds (or a ``Principal``), never
# a role, and decide from permissions and scope.


def _principal(who: Union[User, Principal]) -> Principal:
    return who if isinstance(who, Principal) else _rbac_resolver.principal_for_user(who)


def authorize(
    db: Session,
    who: Union[User, Principal],
    permission_key: str,
    *,
    scope: ScopeContext | None = None,
) -> AuthorizationDecision:
    """ALLOW or DENY ``who`` the permission, with the reason. Never raises for a
    denial."""
    return _rbac_resolver.authorize(db, _principal(who), permission_key, scope)


def can(
    db: Session,
    who: Union[User, Principal],
    permission_key: str,
    *,
    scope: ScopeContext | None = None,
) -> bool:
    """Whether ``who`` holds the permission here. ``authorize(...).allowed``."""
    return authorize(db, who, permission_key, scope=scope).allowed


def effective_permissions(
    db: Session, who: Union[User, Principal], *, org_id: str | None = None
) -> EffectivePermissionSet:
    """The permission keys ``who`` holds in ``org_id`` (their own organisation
    when omitted)."""
    return _rbac_resolver.effective_permissions(db, _principal(who), org_id)


def require(permission_key: str, *, scope: ScopeContext | None = None):
    """
    A FastAPI dependency that answers 403 unless the signed-in account holds
    ``permission_key``, and hands the route the account. The new counterpart of
    ``require_authorized`` (which also hands the route the account).
    """

    def _guard(
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ) -> User:
        decision = authorize(db, user, permission_key, scope=scope)
        if not decision.allowed:
            raise HTTPException(
                status_code=_http_status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Missing permission: {permission_key}.",
            )
        return user

    return _guard


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
