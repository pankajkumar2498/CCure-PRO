"""
ccure_platform/rbac/audit.py — RBAC's audit events.

RBAC governs who may do what, so every change to that — a role created, renamed,
retired, a permission granted, a role assigned — is a security event and is
recorded through the platform's audit log, never a table of RBAC's own.

This file holds the vocabulary (event names and severities), a small draft type,
and one emitter that writes drafts through ``log_audit_event`` on the caller's
session and in the caller's transaction.

**Registration is lazy.** Severities are registered with the audit-log taxonomy
the first time something is emitted, not when this module is imported, so
importing RBAC changes nothing about the live taxonomy. RBAC-1 is dark: no live
path emits these yet.

**Every event snapshots the role's identity at the moment it happened** — id,
key and the display name *then* — because the display name is mutable. An audit
record that said only "Viewer" would be unreadable after a rename.

**Which organisation platform-wide events belong to** is an open question the
audit log forces (``audit_logs.org_id`` is NOT NULL and part of the key, and a
catalogue sync has no organisation). RBAC-1 does not guess: ``emit`` needs an
explicit ``org_id`` (or an actor, whose organisation is used) and refuses
otherwise, and catalogue sync only writes events when it is given one. RBAC-2
settles the attribution.
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
    """A role as it was when an event happened."""

    role_id: str
    role_key: str
    display_name: str

    def as_changes(self) -> dict[str, str]:
        return {
            "role_id": self.role_id,
            "role_key": self.role_key,
            "role_display_name_at_event": self.display_name,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class EventDraft:
    """One audit event, built by RBAC code and written by ``emit``."""

    action: str
    resource_type: str
    resource_id: str | None = None
    changes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.action not in EVENT_SEVERITIES:
            raise ValueError(f"{self.action!r} is not an RBAC audit event")


def role_event(action: str, role: RoleSnapshot, **changes: Any) -> EventDraft:
    """A draft about one role, carrying its identity snapshot."""
    return EventDraft(
        action=action,
        resource_type="rbac_role",
        resource_id=role.role_id,
        changes={**role.as_changes(), **changes},
    )


def emit(
    db,
    drafts: list[EventDraft] | tuple[EventDraft, ...],
    *,
    actor=None,
    org_id: str | None = None,
    system_actor: str | None = None,
) -> int:
    """
    Write ``drafts`` into the caller's transaction and return how many.

    Either ``actor`` (a signed-in account; its organisation is used unless
    ``org_id`` overrides it) or ``system_actor`` + ``org_id`` for an event with
    no human behind it. Neither is refused: an event nobody can attribute is a
    visible error here, not a silent skip.
    """
    if not drafts:
        return 0
    if actor is None and not (system_actor and org_id):
        raise ValueError(
            "an RBAC audit event needs an actor, or a system_actor and an org_id"
        )
    from ccure_platform.audit_log.writer import log_audit_event

    register_severities()
    for draft in drafts:
        log_audit_event(
            db,
            actor,
            draft.action,
            resource_type=draft.resource_type,
            resource_id=draft.resource_id,
            changes=draft.changes or None,
            org_id=org_id,
            system_actor=system_actor,
        )
    return len(drafts)
