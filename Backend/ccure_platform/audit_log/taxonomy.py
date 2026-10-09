"""
core/audit_taxonomy.py
─────────────────────────────────────────────────────────────────────────────
Severity classification for audit events, and the redaction rules that keep
credentials out of the audit trail.

Severity is keyed on the **exact action string**, never on a suffix pattern.
Pattern matching (`*.deleted` → HIGH) reads the verb and ignores the resource,
which is where the risk actually lives: `finding_resolved` is routine, while
`user.role_changed` is not, and both would match a naive rule the same way.

Unmapped actions resolve to `MEDIUM`, not `INFO`. Every writer in this
codebase records a state change, so an action nobody classified is more likely
to be an unreviewed new event than a harmless one — the default must not
under-report it.
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "core.audit_taxonomy")


import logging
import re
from typing import Any

# ─── Severity levels ─────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

INFO = "info"
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"

SEVERITY_LEVELS = (INFO, LOW, MEDIUM, HIGH, CRITICAL)

#: Ordering for comparisons and for "at least this severe" filtering.
SEVERITY_RANK = {level: rank for rank, level in enumerate(SEVERITY_LEVELS)}

#: Applied to any action absent from the table below. See module docstring.
DEFAULT_SEVERITY = MEDIUM


# ─── Action → severity ───────────────────────────────────────────────────────
#
# The **platform's** events: sign-in and accounts (``user.*``, ``auth.*``),
# tenancy (``organization.*``) and the platform's administration and audit log
# (``admin.*``, ``audit.*``). A product's own events are that product's: Audit's
# (scans, findings, credentials, schedules, remediation, compliance, reports) are
# registered by ``ccure_audit/audit_events.py``. Together they cover every action
# string emitted by this codebase; the inventory test in tests/audit/ fails on an
# action nobody classifies. The values are the ones the single table always held.

SEVERITY_BY_ACTION: dict[str, str] = {
    # ── Authentication ──────────────────────────────────────────────────────
    "user.login": INFO,
    "user.logout": INFO,
    "user.login_failed": MEDIUM,
    "user.locked": HIGH,
    "user.mfa_challenge_issued": INFO,
    "user.mfa_failed": HIGH,
    "user.mfa_recovery_used": HIGH,
    "user.mfa_enabled": MEDIUM,
    # Disabling MFA weakens an account's strongest control, and is a standard
    # step in an account takeover — it outranks enabling it.
    "user.mfa_disabled": HIGH,
    "user.mfa_reset_by_admin": HIGH,
    "user.verification_token_issued": INFO,
    "user.email_verified": LOW,
    # ── Credentials / recovery ──────────────────────────────────────────────
    "user.forgot_password_requested": LOW,
    "user.password_reset_completed": HIGH,
    "user.password_reset": HIGH,
    "user.password_changed": MEDIUM,
    "user.password_change_failed": MEDIUM,
    # ── Sessions ────────────────────────────────────────────────────────────
    "user.session_revoked": LOW,
    "user.sessions_revoked_bulk": MEDIUM,
    # ── User management ─────────────────────────────────────────────────────
    "user.created": MEDIUM,
    "user.updated": MEDIUM,
    "user.profile_updated": LOW,
    "user.preferences_updated": INFO,
    "user.approved": HIGH,
    "user.status_changed": HIGH,
    "user.deleted": HIGH,
    "user.restored": HIGH,
    # A purge is the one user operation with no undo.
    "user.purged": CRITICAL,
    # Role and tenancy changes decide what the account can reach, so they
    # outrank ordinary profile edits regardless of which direction they move.
    "user.role_changed": HIGH,
    "user.organization_changed": HIGH,
    # ── Organizations ───────────────────────────────────────────────────────
    "organization.created": HIGH,
    "organization.updated": MEDIUM,
    "organization.activated": HIGH,
    "organization.deactivated": HIGH,
    "organization.deleted": CRITICAL,
    # Archival is the end of a tenancy: every member loses access and every
    # session is revoked. It is reversible, which is exactly why it is not
    # CRITICAL the way the old hard delete was — but it is the most
    # consequential thing a superadmin can do to another tenant.
    "organization.archived": CRITICAL,
    "organization.restored": HIGH,
    "organization.scan_scope_changed": HIGH,
    # ── Platform administration ─────────────────────────────────────────────
    "admin.email_domain_allowlisted": MEDIUM,
    "admin.email_domain_rule_created": MEDIUM,
    "admin.email_domain_rule_updated": MEDIUM,
    "admin.email_domain_rule_deleted": MEDIUM,
    "auth.email_domain_blocked": MEDIUM,
    "auth.email_domain_flagged": LOW,
    # Emitted by POST /auth/service-token (Phase 9.5) and, until now, unclassified:
    # it took the unmapped default, which is MEDIUM, so naming MEDIUM here records
    # what the rows already say and changes no stored severity. A service
    # credential being exchanged for a token is an authentication event.
    "service.token_issued": MEDIUM,
    # ── Audit trail itself ──────────────────────────────────────────────────
    # Taking a copy of the audit trail off the platform is a security event in
    # its own right; purging it is the most sensitive operation in the module.
    "audit.log_exported": HIGH,
    "audit.retention_purge_executed": CRITICAL,
}


# ─── Product event definitions ───────────────────────────────────────────────
#
# A module registers its events' severities (``register_event_severities``). The
# module that does so is named in its manifest (``audit_event_modules``) and is
# imported **by this module, by name, the first time a severity is resolved** —
# so every process that can write an audit event has the definitions, whichever
# of them is the API, a Celery worker, the web worker or a script. A caller never
# has to remember to import a module for its events to be classified.
#
# A severity is computed here and then stored on the row, so a process that
# classified an event wrongly would write the wrong value permanently. Two rules
# follow: a declared definitions module that cannot be imported raises
# (``AuditDefinitionsUnavailable``) instead of letting its events take the
# default; and an action nobody classified is logged, once, not silently defaulted.

_registered: dict[str, str] = {}
_sources: dict[str, str] = {}
_loaded = False
_warned: set[str] = set()


class AuditDefinitionsUnavailable(RuntimeError):
    """A module's audit-event definitions are declared but cannot be loaded."""


def register_event_severities(source: str, severities: dict[str, str]) -> None:
    """
    Register a module's ``{action: severity}``. Registering the same mapping again
    is a no-op; an action the platform or another module already defines, with a
    different severity, or an unknown severity level, is refused.
    """
    for action, level in severities.items():
        if level not in SEVERITY_RANK:
            raise ValueError(f"{source}: {action!r} has unknown severity {level!r}")
        if action in SEVERITY_BY_ACTION and SEVERITY_BY_ACTION[action] != level:
            raise ValueError(f"{source}: {action!r} is a platform event")
        known = _registered.get(action)
        if known is not None and known != level:
            raise ValueError(
                f"{source}: {action!r} is already {known!r} (from {_sources[action]})"
            )
    for action, level in severities.items():
        _registered[action] = level
        _sources.setdefault(action, source)


def ensure_definitions_loaded() -> None:
    """Import every enabled module's declared definitions module, once."""
    global _loaded
    if _loaded:
        return
    import importlib

    from ccure_platform.modules import registry

    _loaded = True  # set first: a definitions module imports this package
    try:
        for name in registry.audit_event_modules():
            try:
                importlib.import_module(name)
            except Exception as exc:  # noqa: BLE001 - re-raised, typed
                raise AuditDefinitionsUnavailable(
                    f"audit-event definitions {name!r} are declared in a module "
                    f"manifest but cannot be loaded: {exc!r}. Refusing to classify "
                    "events without them."
                ) from exc
    except BaseException:
        _loaded = False
        raise


def all_severities() -> dict[str, str]:
    """The platform's table and every registered module's, merged."""
    ensure_definitions_loaded()
    return {**SEVERITY_BY_ACTION, **_registered}


def severity_for(action: str | None) -> str:
    """Resolve an action string to its severity, defaulting conservatively."""
    if not action:
        return DEFAULT_SEVERITY
    ensure_definitions_loaded()
    level = SEVERITY_BY_ACTION.get(action) or _registered.get(action)
    if level is not None:
        return level
    if action not in _warned:
        _warned.add(action)
        logger.warning(
            "Audit action %r is classified by no module; recorded as %s",
            action,
            DEFAULT_SEVERITY,
        )
    return DEFAULT_SEVERITY


# ─── Redaction ───────────────────────────────────────────────────────────────
#
# Two layers, because neither alone is sufficient.
#
#   * The explicit set names the fields this schema actually has. It is exact,
#     needs no pattern to be right, and cannot be defeated by an unusual name.
#   * The pattern catches what a future call site might introduce — an
#     `api_key`, a `refresh_token`, an `encryption_key` that nobody thought to
#     list. It is deliberately broad.
#
# Redaction happens on the way *in*, so a secret is never written to the table
# at all. Masking it only on display would leave the value in the database,
# in backups, and in anything reading the column directly.

REDACTED = "[REDACTED]"

#: Exact field names known to this schema that must never carry a value.
SENSITIVE_FIELDS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "new_password",
        "old_password",
        "current_password",
        "totp_secret",
        "mfa_secret",
        "mfa_backup_codes",
        "backup_codes",
        "recovery_codes",
        "token",
        "token_hash",
        "access_token",
        "refresh_token",
        "reset_token",
        "mfa_token",
        "api_key",
        "secret_key",
        "private_key",
        "encryption_key",
        "client_secret",
        "session_token",
        "credential",
        "credentials",
    }
)

#: Substring patterns for names the explicit set does not anticipate. Matched
#: against the key with separators and case removed, so `API-Key`, `api key`
#: and `apiKey` all normalise to the same thing.
_SENSITIVE_PATTERN = re.compile(
    r"password|passwd|secret|token|apikey|privatekey|encryptionkey|"
    r"credential|totp|backupcode|recoverycode|sessionkey|authorization",
    re.IGNORECASE,
)

#: Keys that match the pattern above but carry no secret and are worth keeping.
#: Without this, `session_id` (which the session-revocation events record so a
#: reviewer can tell which device was signed out) would be redacted into
#: uselessness, and the failed-login counter would vanish.
#:
#: `authorization_confirmed` matches `authorization` (aimed at an
#: `Authorization` header) but is a boolean: the caller's statement that they
#: are authorised to attack the target of a web scan. Redacting it erased the
#: one fact `web_scan.created` exists to record.
_SENSITIVE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "session_id",
        "credential_id",
        "token_id",
        "api_key_id",
        "secret_id",
        "authorization_confirmed",
    }
)


def _normalise_key(key: Any) -> str:
    """Strip case and separators so `MFA-Backup Codes` == `mfa_backup_codes`."""
    return re.sub(r"[\s_\-.]+", "", str(key)).lower()


def is_sensitive_key(key: Any) -> bool:
    """True if a field of this name must never carry a value into the trail."""
    raw = str(key).lower()
    normalised = _normalise_key(key)

    if normalised in {_normalise_key(k) for k in _SENSITIVE_ALLOWLIST}:
        return False
    if raw in SENSITIVE_FIELDS or normalised in {
        _normalise_key(k) for k in SENSITIVE_FIELDS
    }:
        return True
    return bool(_SENSITIVE_PATTERN.search(normalised))


def redact_changes(changes: Any, _depth: int = 0) -> Any:
    """
    Return `changes` with every sensitive value replaced by ``[REDACTED]``.

    Walks nested dicts and lists, so the ``{"old": ..., "new": ...}`` shape the
    update endpoints use is covered at any depth. A redacted key keeps its
    *name* — that a password changed is exactly what the trail should record;
    what it changed to is exactly what it must not.

    Depth is bounded: `changes` is caller-supplied and reaches a JSONB column,
    and a structure deep enough to exhaust the stack here would take the
    request down with it.
    """
    if _depth > 12:
        return REDACTED

    if isinstance(changes, dict):
        redacted: dict[Any, Any] = {}
        for key, value in changes.items():
            if is_sensitive_key(key):
                # A marker the call sites already write ("modified", "cleared")
                # says what happened without revealing anything, so it is kept.
                redacted[key] = (
                    value
                    if isinstance(value, str) and value in {"modified", "cleared"}
                    else REDACTED
                )
            else:
                redacted[key] = redact_changes(value, _depth + 1)
        return redacted

    if isinstance(changes, (list, tuple)):
        return [redact_changes(item, _depth + 1) for item in changes]

    return changes
