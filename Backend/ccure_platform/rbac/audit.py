"""
ccure_platform/rbac/audit.py — RBAC's audit events and who they belong to.

RBAC governs who may do what, so every change to that — a role created, renamed,
retired, a permission granted, a role assigned — is a security event and is
recorded through the platform's audit service, never a table of RBAC's own. This
file holds the vocabulary (event names and severities), a draft type that carries
its **attribution**, and one emitter.

**Attribution (RBAC-2).** ``audit_logs`` is tenant-bound: ``org_id`` is NOT NULL
and half the key, the table is hash-partitioned on it and the tamper-evidence
chain is per organisation. That is right for what a tenant did and wrong for an
event no organisation owns. Borrowing an arbitrary organisation, or inventing a
pseudo-tenant, would write a false statement into a trail. So **the draft says who
owns it, and the emitter never guesses**:

=====================================  ==========================================  ==================
event                                  owner                                       sink
=====================================  ==========================================  ==================
a role of one organisation changed     that organisation (the role's ``org_id``)   ``audit_logs``
an organisation-scope assignment       the assignment's organisation               ``audit_logs``
a platform-scope assignment            the **member** whose access changed: the    ``audit_logs``
                                       target user's own organisation
a system or platform-scope role        no organisation                             platform ledger
catalogue sync, permission lifecycle   no organisation                             platform ledger
default role re-pointed                no organisation (a platform setting)        platform ledger
a denied privileged request            the principal's organisation                ``audit_logs``
=====================================  ==========================================  ==================

An organisation-less event records the actor's own organisation as *information*
(``actor_org_id``), never as its owner.

**Registration is lazy.** Severities are registered with the audit-log taxonomy
the first time something is emitted, not when this module is imported, so
importing RBAC changes nothing about the live taxonomy. RBAC-2 is dark: no live
path emits these yet.

**Every event snapshots the role's identity at the moment it happened** — id,
key and the display name *then* — because the display name is mutable. An audit
record that said only "Viewer" would be unreadable after a rename.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

INFO, LOW, MEDIUM, HIGH, CRITICAL = "info", "low", "medium", "high", "critical"

#: ``{action: severity}`` — every RBAC event (RBAC-0 §9 and the role-lifecycle
#: correction).
EVENT_SEVERITIES: dict[str, str] = {
    # roles
    "rbac.role.created": MEDIUM,
    "rbac.role.updated": LOW,
    "rbac.role.renamed": LOW,
    "rbac.role.permissions_changed": HIGH,
    "rbac.role.retiring": MEDIUM,
    "rbac.role.retired": HIGH,
    "rbac.role.reactivated": HIGH,
    "rbac.role.retirement_refused": LOW,
    # assignments
    "rbac.role.assigned": MEDIUM,
    "rbac.role.revoked": MEDIUM,
    "rbac.role.expired": LOW,
    "rbac.role.reassigned": HIGH,
    "rbac.role.revoked_without_replacement": HIGH,
    "rbac.platform_role.assigned": CRITICAL,
    "rbac.platform_role.revoked": CRITICAL,
    # governance refusals and security-sensitive authorization
    "rbac.escalation.refused": HIGH,
    "rbac.authz.denied_privileged": MEDIUM,
    "rbac.org_switch.entered": MEDIUM,
    "rbac.continuity.violated": CRITICAL,
    # configuration
    "rbac.default_role.changed": HIGH,
    # catalogue
    "rbac.catalogue.permission_registered": LOW,
    "rbac.catalogue.permission_updated": LOW,
    "rbac.catalogue.permission_deprecated": MEDIUM,
    "rbac.catalogue.permission_retired": HIGH,
    "rbac.catalogue.sync_failed": CRITICAL,
    "rbac.system_role.synced": MEDIUM,
    "rbac.system_role.sync_skipped_retired": LOW,
    "rbac.legacy_map.synced": LOW,
}

_registered = False


def register_severities() -> None:
    """Register RBAC's event severities with the audit log. Idempotent."""
    global _registered
    if _registered:
        return
    from ccure_platform.audit_log.taxonomy import register_event_severities

    register_event_severities("rbac", EVENT_SEVERITIES)
    _registered = True


@dataclass(frozen=True, slots=True, kw_only=True)
class RoleSnapshot:
    """A role as it was when an event happened. ``org_id`` is the role's own
    organisation (None for a system or platform-scope role)."""

    role_id: str
    role_key: str
    display_name: str
    org_id: str | None = None

    def as_changes(self) -> dict[str, str]:
        return {
            "role_id": self.role_id,
            "role_key": self.role_key,
            "role_display_name_at_event": self.display_name,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class EventDraft:
    """
    One audit event, built by RBAC code and written by ``emit``.

    ``org_id`` is the **owner**: the organisation whose trail the event belongs to,
    or None for an event no organisation owns. It is set explicitly by whoever
    builds the draft — there is no default and nothing is inferred.
    """

    action: str
    resource_type: str
    resource_id: str | None = None
    changes: dict[str, Any] = field(default_factory=dict)
    org_id: str | None = None

    def __post_init__(self) -> None:
        if self.action not in EVENT_SEVERITIES:
            raise ValueError(f"{self.action!r} is not an RBAC audit event")

    @property
    def owned(self) -> bool:
        return self.org_id is not None


def role_event(action: str, role: RoleSnapshot, **changes: Any) -> EventDraft:
    """A draft about one role. Owned by the role's organisation, or by nobody for
    a system or platform-scope role."""
    return EventDraft(
        action=action,
        resource_type="rbac_role",
        resource_id=role.role_id,
        changes={**role.as_changes(), **changes},
        org_id=role.org_id,
    )


def assignment_event(
    action: str,
    role: RoleSnapshot,
    *,
    user_id: str,
    user_org_id: str | None,
    scope_type: str,
    scope_org_id: str | None = None,
    **changes: Any,
) -> EventDraft:
    """
    A draft about a role being given to or taken from a user.

    Owned by the organisation the assignment is *in* (an organisation-scope
    assignment), or — for a platform-scope assignment, which is in no organisation
    — by the **member's own organisation**: that is the tenant whose person's
    access changed, and it is a real organisation, not an invented one.
    """
    if scope_type == "organization":
        owner = scope_org_id
    elif scope_type == "platform":
        owner = user_org_id
    else:
        raise ValueError(f"unknown assignment scope {scope_type!r}")
    return EventDraft(
        action=action,
        resource_type="rbac_user_role",
        resource_id=user_id,
        changes={
            **role.as_changes(),
            "user_id": user_id,
            "scope_type": scope_type,
            "scope_org_id": scope_org_id,
            **changes,
        },
        org_id=owner,
    )


@dataclass(frozen=True, slots=True)
class EmitResult:
    organization: int = 0
    platform: int = 0

    @property
    def total(self) -> int:
        return self.organization + self.platform


def emit(
    db,
    drafts: list[EventDraft] | tuple[EventDraft, ...],
    *,
    actor=None,
    system_actor: str | None = None,
    request=None,
) -> EmitResult:
    """
    Write ``drafts`` into the caller's transaction, each to the sink its owner
    dictates, and say how many went where.

    An owned draft goes to ``audit_logs`` in its organisation; an unowned one goes
    to the platform ledger. Exactly one of ``actor`` (a signed-in account) or
    ``system_actor`` (a label for an event with no human behind it) is required —
    an event nobody can attribute is a visible error, not a silent skip. Nothing is
    committed here.
    """
    if not drafts:
        return EmitResult()
    if (actor is None) == (system_actor is None):
        raise ValueError(
            "an RBAC audit event needs exactly one of actor or system_actor"
        )
    from ccure_platform.audit_log.writer import log_audit_event, log_platform_event

    register_severities()
    organization = platform = 0
    for draft in drafts:
        if draft.owned:
            log_audit_event(
                db,
                actor,
                draft.action,
                resource_type=draft.resource_type,
                resource_id=draft.resource_id,
                changes=draft.changes or None,
                request=request,
                org_id=draft.org_id,
                system_actor=system_actor,
            )
            organization += 1
        else:
            log_platform_event(
                db,
                draft.action,
                actor=actor,
                system_actor=system_actor,
                resource_type=draft.resource_type,
                resource_id=draft.resource_id,
                changes=draft.changes or None,
                request=request,
            )
            platform += 1
    return EmitResult(organization=organization, platform=platform)
