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


import re
from typing import Any

# ─── Severity levels ─────────────────────────────────────────────────────────

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
# Covers every action string emitted by this codebase as of the audit review.
# Adding a new audited action means adding it here; the inventory test in
# tests/audit/ fails on an action a router emits that this table does not name.

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
    # ── Scanning ────────────────────────────────────────────────────────────
    "scan.created": LOW,
    "scan.completed": INFO,
    "scan.failed": MEDIUM,
    "scan.cancelled": LOW,
    # ── Web application scanning ────────────────────────────────────────────
    # Launching a web scan sends sqlmap, ffuf and nuclei at a URL the caller
    # names — active attack traffic from this host against somebody's
    # application — so it outranks launching a network scan. The entry also
    # records the authorisation confirmation the caller gave, which is the
    # only durable evidence it was given.
    "web_scan.created": MEDIUM,
    "web_scan.cancelled": LOW,
    # Triage outcomes, one per status, weighted like their network-finding
    # counterparts: accepting a risk is the decision an auditor looks for;
    # marking one false positive removes it from every count built on it.
    "web_finding.open": INFO,
    "web_finding.reopened": LOW,
    "web_finding.confirmed": LOW,
    "web_finding.fixed": LOW,
    "web_finding.false_positive": MEDIUM,
    "web_finding.accepted_risk": HIGH,
    # ── Scan scheduling (Phase 1) ───────────────────────────────────────────
    # Creating or editing a schedule decides what this platform will point at
    # a network unattended, repeatedly, from now on — so it outranks starting
    # one scan by hand ("scan.created": LOW). Deleting one is the same weight
    # as creating: an assurance scan that silently stops running is a
    # compliance gap nobody is told about.
    "scan_schedule.created": MEDIUM,
    "scan_schedule.updated": MEDIUM,
    "scan_schedule.deleted": MEDIUM,
    # Enable/disable is the switch that decides whether the above happens at
    # all, and is the most likely thing to be changed quietly.
    "scan_schedule.enabled": MEDIUM,
    "scan_schedule.disabled": MEDIUM,
    # A person pressing Run Now is one scan, deliberately taken, and is
    # rated like the manual scan it produces.
    "scan_schedule.run_now": LOW,
    # The scheduler switching a schedule off after repeated failures. HIGH
    # because nobody asked for it and the effect is that assurance scanning
    # silently stops — exactly the state a reviewer needs to find.
    "scan_schedule.auto_disabled": HIGH,
    # ── Credentials (Phase 2) ───────────────────────────────────────────────
    # Storing a credential gives this platform a way into a host, so it
    # outranks ordinary configuration changes. Deletion matches: a scheduled
    # assurance scan whose credential vanished stops producing findings, and
    # nothing else announces that.
    "credential.created": HIGH,
    "credential.updated": HIGH,
    "credential.deleted": HIGH,
    # A validation is one deliberate authentication attempt against one named
    # host. LOW on its own; the value is the trail — repeated failures against
    # many hosts is credential spraying wearing an administrator's session.
    "credential.validated": LOW,
    # ── Assets ──────────────────────────────────────────────────────────────
    "asset_updated": LOW,
    "amt_inventory_imported": MEDIUM,
    # ── Findings ────────────────────────────────────────────────────────────
    # Accepting or ignoring a finding is a decision to live with a risk, and
    # is the finding action an auditor comes looking for.
    "finding_open": INFO,
    "finding_resolved": LOW,
    "finding_false_positive": MEDIUM,
    "finding_accepted": HIGH,
    "finding_ignored": HIGH,
    # ── Remediation (GAP-14) ────────────────────────────────────────────────
    # Ownership and workflow are routine bookkeeping. Accepting a risk is not:
    # it is a decision to live with a finding, and it is the remediation action
    # an auditor comes looking for — the same reading `finding_accepted` above
    # already gets. Withdrawing one is HIGH for the mirror reason: it is the
    # record of a decision being reversed.
    "remediation.assigned": INFO,
    "remediation.unassigned": LOW,
    "remediation.state_changed": LOW,
    "remediation.note_added": INFO,
    "remediation.risk_accepted": HIGH,
    "remediation.acceptance_withdrawn": HIGH,
    # Changing the SLA changes when every future finding is reported overdue,
    # across the whole organisation, from one settings edit.
    "remediation.sla_policy_updated": HIGH,
    # ── Compliance ──────────────────────────────────────────────────────────
    "install_framework": MEDIUM,
    "uninstall_framework": HIGH,
    "compliance.rule_updated": HIGH,
    "create_policy": MEDIUM,
    "trigger_scan": LOW,
    "attest_control": HIGH,
    "upload_evidence": LOW,
    "delete_evidence": HIGH,
    "create_schedule": LOW,
    "update_schedule": LOW,
    "delete_schedule": MEDIUM,
    "create_credential": HIGH,
    "delete_credential": MEDIUM,
    "export_soa": MEDIUM,
    "export_report": MEDIUM,
    # Remediation: requesting is routine, approving executes something on a
    # host, and bypassing the maker-checker queue removes the second pair of
    # eyes that the queue exists to provide.
    "request_remediation": LOW,
    "approve_remediation": HIGH,
    "reject_remediation": MEDIUM,
    "cancel_remediation": LOW,
    "request_rollback": LOW,
    "approve_rollback": HIGH,
    "emergency_bypass_remediation": CRITICAL,
    "emergency_bypass_rollback": CRITICAL,
    "request_waiver": MEDIUM,
    "approve_waiver": HIGH,
    # ── Reports ─────────────────────────────────────────────────────────────
    "report.downloaded": LOW,
    # ── Audit trail itself ──────────────────────────────────────────────────
    # Taking a copy of the audit trail off the platform is a security event in
    # its own right; purging it is the most sensitive operation in the module.
    "audit.log_exported": HIGH,
    "audit.retention_purge_executed": CRITICAL,
}


def severity_for(action: str | None) -> str:
    """Resolve an action string to its severity, defaulting conservatively."""
    if not action:
        return DEFAULT_SEVERITY
    return SEVERITY_BY_ACTION.get(action, DEFAULT_SEVERITY)


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
