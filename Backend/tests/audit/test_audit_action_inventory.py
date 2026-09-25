"""
tests/audit/test_audit_action_inventory.py
─────────────────────────────────────────────────────────────────────────────
Static guards over how `log_audit_event` is called across the codebase.

Two defects motivate this file, both found by reading rather than by any test:

  * `routers/compliance.py` passed the *status* as the sixth positional
    argument, which is `changes`. Twenty-five call sites were affected, and
    two of them — `blocked_malware` and `scanner_unavailable` — recorded a
    refused malware upload as `status="success"`.
  * `export_report` was emitted by a router but absent from the severity
    table, so it silently took the unmapped default.

Both are invisible at runtime: the row is written, it just says the wrong
thing. A static walk over the call sites is the only thing that catches them.
"""

import ast
import re

from core.audit_taxonomy import SEVERITY_BY_ACTION
from testpaths import BACKEND_ROOT

#: Directories that legitimately call log_audit_event.
_SOURCE_DIRS = ("routers", "auth", "scans", "core")

#: Positional index of each parameter in log_audit_event's signature.
#: (db, user, action, resource_type, resource_id, changes, request, status)
_CHANGES_POSITION = 5

#: Values that are plainly a status rather than a change set. If one of these
#: turns up in the `changes` position it is the compliance.py defect again.
_STATUS_LIKE = {
    "success",
    "failure",
    "failed",
    "denied",
    "error",
    "blocked",
    "blocked_malware",
    "scanner_unavailable",
}


def _call_sites():
    """Yield (path, ast.Call) for every log_audit_event(...) in the backend."""
    for sub in _SOURCE_DIRS:
        root = BACKEND_ROOT / sub
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "log_audit_event"
                ):
                    yield path, node


def test_status_is_never_passed_in_the_changes_position():
    """
    The exact defect from `routers/compliance.py`.

    `log_audit_event(db, user, "upload_evidence", "evidence", cid,
    "blocked_malware")` puts the status into `changes` and leaves `status` at
    its "success" default — so a refused malware upload was recorded as a
    successful one. Keyword form (`status=...`) is the fix and the only form
    this allows.
    """
    offenders = []
    for path, call in _call_sites():
        if len(call.args) <= _CHANGES_POSITION:
            continue
        arg = call.args[_CHANGES_POSITION]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if arg.value in _STATUS_LIKE:
                offenders.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{arg.lineno} "
                    f"passes {arg.value!r} positionally as `changes`; "
                    f"use status={arg.value!r} instead"
                )
    assert not offenders, "status passed as changes:\n  - " + "\n  - ".join(offenders)


def test_changes_position_is_never_a_bare_string():
    """
    `changes` reaches a JSONB column and every reader treats it as a mapping.
    A bare string there is either a mis-passed status (above) or a note that
    belongs in a keyed field — `emergency_bypass_remediation` passed a
    human-readable sentence and is now `changes={"reason": ..., "asset_id": ...}`.
    """
    offenders = []
    for path, call in _call_sites():
        if len(call.args) <= _CHANGES_POSITION:
            continue
        arg = call.args[_CHANGES_POSITION]
        if isinstance(arg, (ast.Constant, ast.JoinedStr)):
            value = getattr(arg, "value", "<f-string>")
            if isinstance(value, str) or isinstance(arg, ast.JoinedStr):
                offenders.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{arg.lineno} "
                    f"passes a string as `changes`"
                )
    assert not offenders, "string passed as changes:\n  - " + "\n  - ".join(offenders)


def _literal_actions():
    """Every action string passed to log_audit_event as a plain literal."""
    actions = set()
    for path, call in _call_sites():
        node = None
        if len(call.args) > 2:
            node = call.args[2]
        for kw in call.keywords:
            if kw.arg == "action":
                node = kw.value
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            actions.add(node.value)
    return actions


def test_every_literal_action_is_classified():
    """
    An action absent from the table silently takes the unmapped default, which
    is how `export_report` shipped unclassified. f-string actions
    (`scan.{status}`, `finding_{status}`) cannot be resolved statically and are
    covered by the enumerated-variant test below instead.
    """
    unmapped = sorted(_literal_actions() - set(SEVERITY_BY_ACTION))
    assert not unmapped, (
        "actions emitted by a router but absent from SEVERITY_BY_ACTION:\n  - "
        + "\n  - ".join(unmapped)
    )


def test_dynamic_action_variants_are_classified():
    """
    Four call sites build the action from a variable: `scan.{status}`,
    `finding_{body.status}`, the `approve_remediation`/`approve_rollback`
    label, and the web-finding triage lookup `_TRIAGE_AUDIT_ACTIONS`. Their possible values cannot be read statically, so they are pinned
    here — a new scan state or finding state must be classified too.
    """
    expected = {
        "scan.created",
        "scan.completed",
        "scan.failed",
        "scan.cancelled",
        "finding_open",
        "finding_resolved",
        "finding_false_positive",
        "finding_accepted",
        "finding_ignored",
        "approve_remediation",
        "approve_rollback",
        # routers/web_scans.py `_TRIAGE_AUDIT_ACTIONS`, one per triage status
        "web_finding.open",
        "web_finding.confirmed",
        "web_finding.false_positive",
        "web_finding.accepted_risk",
        "web_finding.fixed",
        "web_finding.reopened",
    }
    missing = sorted(expected - set(SEVERITY_BY_ACTION))
    assert not missing, f"dynamic action variants not classified: {missing}"


def test_every_status_value_fits_the_column():
    """
    `audit_logs.status` is VARCHAR(20). `scanner_unavailable` is 19 characters,
    so the fix above sits one character inside the limit — a longer status
    added later would raise DataError at write time, inside an exception
    handler, on a path that is already failing.
    """
    from db.models import AuditLog

    limit = AuditLog.__table__.c.status.type.length
    too_long = sorted(s for s in _STATUS_LIKE if len(s) > limit)
    assert not too_long, f"status values exceeding VARCHAR({limit}): {too_long}"
