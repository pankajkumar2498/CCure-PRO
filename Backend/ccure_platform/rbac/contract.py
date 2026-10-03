"""
ccure_platform/rbac/contract.py — what RBAC speaks, and nothing else.

RBAC is an independent platform capability (RBAC-0, frozen): it is
module-agnostic and exposes stable contracts that Audit, Policy Pro, Rank and IR
consume. This file is that contract — frozen dataclasses of plain values, the
vocabularies, and the grammars. **Standard library only**: it imports no
SQLAlchemy, no FastAPI and no product code, so a module (or a future separate
service) can hold these types without holding RBAC.

Three rules the rest of the package keeps, and this file is where they start:

* **A role is ``id`` + ``key`` + ``display_name``, and none of the three is an
  authorization input.** ``id`` is the database identity every foreign key and
  historical reference uses; ``key`` is an immutable technical handle for
  seeding, migration and tooling; ``display_name`` is a mutable label. The
  decision function (``engine.decide``) is handed a principal, the grants that
  principal holds, and a scope — ``Grant`` carries no role field — so it cannot
  branch on which role granted what.
* **A permission key is ``<namespace>.<resource>.<action>``** and the namespace
  names the declaring module. RBAC validates that and nothing module-specific.
* **Superadmin is permissions plus scope.** There is no wildcard and no
  request-time "if superadmin then allow": a role that holds everything holds
  materialised grants (``auto_grant_new_permissions`` is read by catalogue sync,
  never by the engine).

The role keys that appear below (``SYSTEM_ROLE_SEEDS``)
are **seed data**. They are the one place the five original role
names may be written, and the repository ratchet
(``tests/repo/test_rbac_role_identity.py``) allows them nowhere else.

RBAC-8 (final): this contract and the engine over it are the only authorization model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

# ── vocabularies ──────────────────────────────────────────────────────────────

#: Where a permission applies. ``platform`` is a platform-level resource
#: (organisations, email-domain rules, platform role governance); ``organization``
#: is anything inside one organisation.
SCOPE_KINDS = ("platform", "organization")

#: ``privileged`` permissions have their denials audited.
SENSITIVITIES = ("normal", "privileged")

#: ``deprecated`` is still honoured where granted; ``retired`` is never granted.
PERMISSION_STATUSES = ("active", "deprecated", "retired")

ROLE_KINDS = ("system", "custom")
#: Where a role may be assigned. A system role is a global definition that is
#: *assigned* per organisation; a platform-scope role is assigned platform-wide.
ASSIGNABLE_SCOPES = ("platform", "organization")
#: ``code`` roles get their permissions from catalogue sync and are immutable to
#: administrators; ``admin`` roles are configured through RBAC governance.
ROLE_MANAGERS = ("code", "admin")
ROLE_STATES = ("active", "retiring", "retired")

#: ``role_state → states it may move to``. Reactivation (``retired → active``)
#: is allowed by the model; whether it is *safe* is a governance question.
ROLE_TRANSITIONS: Mapping[str, tuple[str, ...]] = {
    "active": ("retiring",),
    "retiring": ("retired", "active"),
    "retired": ("active",),
}

REVOKE_REASONS = ("migrated", "role_retired", "expired", "manual")
REVISION_KINDS = (
    "created",
    "renamed",
    "described",
    "permissions_changed",
    "state_changed",
    "retired",
    "reactivated",
    "synced",
)
DEFAULT_ROLE_PURPOSES = ("self_registration",)

# ── grammars ──────────────────────────────────────────────────────────────────

_SEGMENT = r"[a-z][a-z0-9_]*"
#: ``<namespace>.<resource>.<action>`` — three segments, never a wildcard.
PERMISSION_KEY = re.compile(rf"^({_SEGMENT})\.({_SEGMENT})\.({_SEGMENT})$")
PERMISSION_KEY_MAX = 120
NAMESPACE = re.compile(rf"^{_SEGMENT}$")
DESCRIPTION_MAX = 500

#: Code-managed system roles: ``platform.<slug>``.
SYSTEM_ROLE_KEY = re.compile(rf"^platform\.{_SEGMENT}$")
#: Administrator-created platform-scope roles: ``custom.platform.<slug>``.
PLATFORM_CUSTOM_ROLE_KEY = re.compile(rf"^custom\.platform\.{_SEGMENT}$")
#: Organisation custom roles: ``custom.<org_id>.<slug>``. The organisation a role
#: belongs to is its ``org_id`` column, never this segment.
ORG_CUSTOM_ROLE_KEY = re.compile(rf"^custom\.org_[a-z0-9_-]+\.{_SEGMENT}$")
ROLE_KEY_MAX = 200
DISPLAY_NAME_MAX = 100


def role_key_kind(key: str) -> str | None:
    """``system``, ``platform_custom``, ``org_custom`` — or None for a key that
    is none of them. A grammar check only; it never decides authorization."""
    if not isinstance(key, str) or len(key) > ROLE_KEY_MAX:
        return None
    if SYSTEM_ROLE_KEY.match(key):
        return "system"
    if PLATFORM_CUSTOM_ROLE_KEY.match(key):
        return "platform_custom"
    if ORG_CUSTOM_ROLE_KEY.match(key):
        return "org_custom"
    return None


# ── governance keys ───────────────────────────────────────────────────────────
#
# Permission keys RBAC's own governance and invariants refer to. They are RBAC's
# vocabulary (the catalogue declares them in RBAC-2), not a product's.

ASSIGN_ROLE_KEY = "platform.user.assign_role"
ASSIGN_PLATFORM_ROLE_KEY = "platform.role.assign_platform"
CREATE_ROLE_KEY = "platform.role.create"
CREATE_PLATFORM_ROLE_KEY = "platform.role.create_platform"
UPDATE_ROLE_KEY = "platform.role.update"
RETIRE_ROLE_KEY = "platform.role.retire"
RETIRE_SYSTEM_ROLE_KEY = "platform.role.retire_system"
#: Entering an organisation other than the principal's own.
ORG_SWITCH_KEY = "platform.organization.switch"
CREATE_ORGANIZATION_KEY = "platform.organization.create"

#: The frozen continuity keys (RBAC-0 §9): the system must always hold an
#: active, verified human who has each of them at platform scope.
CONTINUITY_KEYS = frozenset(
    {
        ASSIGN_PLATFORM_ROLE_KEY,
        CREATE_PLATFORM_ROLE_KEY,
        ASSIGN_ROLE_KEY,
        CREATE_ORGANIZATION_KEY,
    }
)

# ── seed and migration data ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class SystemRoleSeed:
    key: str
    display_name: str
    description: str
    assignable_scope: str
    #: Catalogue sync grants every active permission to a role with this set.
    #: A materialisation, not a bypass: the engine reads the grants.
    auto_grant_new_permissions: bool = False


#: The stable identities of the two system roles provisioning refers to (seed data; a
#: role is its key, never its display name).
PLATFORM_ADMIN_ROLE_KEY = "platform.superadmin"
ORGANISATION_ADMIN_ROLE_KEY = "platform.org_admin"

SYSTEM_ROLE_SEEDS: tuple[SystemRoleSeed, ...] = (
    SystemRoleSeed(
        key="platform.superadmin",
        display_name="Superadmin",
        description="Platform-wide administration; holds every active permission.",
        assignable_scope="platform",
        auto_grant_new_permissions=True,
    ),
    SystemRoleSeed(
        key="platform.org_admin",
        display_name="Org Admin",
        description="Full administration of one organisation.",
        assignable_scope="organization",
    ),
    SystemRoleSeed(
        key="platform.analyst",
        display_name="Analyst",
        description="Operates the products and works their results within one organisation.",
        assignable_scope="organization",
    ),
    SystemRoleSeed(
        key="platform.viewer",
        display_name="Viewer",
        description="Read-only access within one organisation.",
        assignable_scope="organization",
    ),
    SystemRoleSeed(
        key="platform.scanner",
        display_name="Scanner",
        description="API-only account that launches and reads automated work within one organisation.",
        assignable_scope="organization",
    ),
)

#: What each default-role purpose is configured to on a fresh install, so
#: today's behaviour (self-registered accounts are viewers) is preserved.
DEFAULT_ROLE_SEEDS: Mapping[str, str] = {"self_registration": "platform.viewer"}


# ── decision reasons ──────────────────────────────────────────────────────────

ALLOWED = "allowed"
PRINCIPAL_INACTIVE = "principal_inactive"
UNKNOWN_PERMISSION = "unknown_permission"
RETIRED_PERMISSION = "retired_permission"
MISSING_PERMISSION = "missing_permission"
#: The principal holds the permission, but not for the organisation asked about.
CROSS_ORG = "cross_org"
NO_TARGET_ORG = "no_target_org"
#: A platform-scope grant reaches another organisation only with an explicit
#: switch (``ORG_SWITCH_KEY``).
ORG_SWITCH_REQUIRED = "org_switch_required"
#: The permission is platform-scope and only an organisation grant was found.
PLATFORM_SCOPE_REQUIRED = "platform_scope_required"

DENY_REASONS = (
    PRINCIPAL_INACTIVE,
    UNKNOWN_PERMISSION,
    RETIRED_PERMISSION,
    MISSING_PERMISSION,
    CROSS_ORG,
    NO_TARGET_ORG,
    ORG_SWITCH_REQUIRED,
    PLATFORM_SCOPE_REQUIRED,
)

PRINCIPAL_KINDS = ("human", "service")

# ── declarations ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class PermissionDecl:
    """
    One permission a product (or the platform) declares, as data.

    ``default_grants`` names the **code-managed system roles** that hold the
    permission by default. It is seed-time data the catalogue sync applies; the
    engine never reads it, and a role named here that is retired is skipped.
    """

    key: str
    description: str
    scope_kind: str
    sensitivity: str = "normal"
    #: ``False`` (✗ in the design) — may not appear in an organisation-scope
    #: role, system or custom. Platform-scope permissions are never delegable.
    delegable_to_org_roles: bool = True
    #: One of ``CONTINUITY_KEYS``: the system must always have a holder.
    continuity: bool = False
    default_grants: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.default_grants, tuple):
            object.__setattr__(self, "default_grants", tuple(self.default_grants))


@dataclass(frozen=True, slots=True, kw_only=True)
class ModuleDeclarations:
    """
    What one source declares: its key, the permission namespace it owns, and its
    permissions. Built by the composition root from a module's manifest; RBAC
    receives it and never learns where it came from.
    """

    module_key: str
    namespace: str
    permissions: tuple[PermissionDecl, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.permissions, tuple):
            object.__setattr__(self, "permissions", tuple(self.permissions))


# ── stored views (plain values; no ORM object crosses the boundary) ───────────


@dataclass(frozen=True, slots=True, kw_only=True)
class Permission:
    key: str
    module: str
    resource: str
    action: str
    description: str
    scope_kind: str
    sensitivity: str
    delegable_to_org_roles: bool
    continuity: bool
    status: str
    replaced_by: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Role:
    id: str
    key: str
    display_name: str
    kind: str
    assignable_scope: str
    org_id: str | None
    managed_by: str
    state: str
    auto_grant_new_permissions: bool
    replaced_by_role_id: str | None
    revision: int


@dataclass(frozen=True, slots=True, kw_only=True)
class RoleAssignment:
    id: str
    user_id: str
    role_id: str
    scope_type: str
    scope_org_id: str | None
    expires_at: object | None = None
    revoked_at: object | None = None


# ── what the engine is handed ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True)
class Principal:
    """Who is asking. ``active`` is the caller's verdict on the account state
    (authentication has already vetted it); RBAC adds no account rules."""

    kind: str
    principal_id: str
    home_org_id: str | None = None
    active: bool = True


@dataclass(frozen=True, slots=True, kw_only=True)
class Grant:
    """
    One permission a principal holds and where it applies. **No role field**:
    the engine must not be able to learn which role a grant came from, let alone
    what that role is called. ``assignment_scope`` is where the *assignment* that
    carries it applies — platform-wide, or one organisation.
    """

    permission_key: str
    assignment_scope: str
    scope_org_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ScopeContext:
    """
    Where the request acts. ``requested_org_id`` is an organisation the caller
    explicitly names (an organisation switch); ``resource_org_id`` is the
    organisation the resource being touched belongs to. Both None means the
    principal's own organisation.
    """

    requested_org_id: str | None = None
    resource_org_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    permission_key: str
    principal_id: str
    principal_kind: str
    target_org_id: str | None = None
    #: The permission is deprecated: honoured, but its holder should move off it.
    deprecated: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class EffectivePermissionSet:
    """The permission keys a principal holds for one organisation (or, with
    ``org_id`` None, at platform scope). Role identity is not part of it."""

    principal_id: str
    org_id: str | None
    permissions: frozenset[str]
