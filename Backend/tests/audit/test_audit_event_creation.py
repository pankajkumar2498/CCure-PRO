"""
tests/audit/test_audit_event_creation.py
─────────────────────────────────────────────────────────────────────────────
Phase 1 of the audit-log hardening: severity classification, request/
correlation id capture, and redaction of anything credential-shaped.

The redaction tests matter more than they look. The existing call sites are
already careful — they write ``"modified"`` rather than a password hash — so a
test that only exercises those proves nothing about a call site added next
month. These drive `log_audit_event` with values a careless caller would pass
and assert the secret never reaches the column.
"""

from core.audit import log_audit_event
from core.audit_taxonomy import (
    DEFAULT_SEVERITY,
    REDACTED,
    SEVERITY_BY_ACTION,
    SEVERITY_LEVELS,
    is_sensitive_key,
    redact_changes,
    severity_for,
)
from db.models import AuditLog


# ─── Severity ────────────────────────────────────────────────────────────────


def test_every_mapped_severity_is_a_known_level():
    """A typo in the table would otherwise produce a severity nothing filters on."""
    unknown = {
        action: level
        for action, level in SEVERITY_BY_ACTION.items()
        if level not in SEVERITY_LEVELS
    }
    assert (
        not unknown
    ), f"actions mapped to a severity outside {SEVERITY_LEVELS}: {unknown}"


def test_unmapped_action_defaults_conservatively():
    """
    An action nobody classified is more likely a new unreviewed event than a
    harmless one, so the default must not be the lowest severity.
    """
    assert severity_for("something.nobody.mapped") == DEFAULT_SEVERITY
    assert DEFAULT_SEVERITY != "info"


def test_security_critical_actions_outrank_routine_ones():
    """
    The specific classifications the design calls out. These are the ones a
    reviewer filters on, so a silent reclassification should fail here.
    """
    assert severity_for("user.login") == "info"
    assert severity_for("user.login_failed") == "medium"
    assert severity_for("user.role_changed") == "high"
    assert severity_for("user.mfa_disabled") == "high"
    assert severity_for("organization.deleted") == "critical"
    assert severity_for("user.purged") == "critical"


def test_severity_is_not_derived_from_the_verb_alone():
    """
    Guards the design decision to key on the exact action rather than a suffix
    pattern: two actions ending in the same verb legitimately differ.
    """
    assert severity_for("user.deleted") == "high"
    assert severity_for("finding_resolved") == "low"
    assert severity_for("scan.created") != severity_for("organization.created")


def test_audit_event_gets_severity_from_its_action(db_session, test_user):
    log_audit_event(
        db_session, test_user, "user.role_changed", "user", str(test_user.id)
    )
    db_session.commit()

    row = (
        db_session.query(AuditLog).filter(AuditLog.action == "user.role_changed").one()
    )
    assert row.severity == "high"


def test_explicit_severity_overrides_the_table(db_session, test_user):
    """A call site with more context than the action string may say so."""
    log_audit_event(
        db_session,
        test_user,
        "user.login",
        "user",
        str(test_user.id),
        severity="critical",
    )
    db_session.commit()

    row = db_session.query(AuditLog).filter(AuditLog.action == "user.login").one()
    assert row.severity == "critical"


# ─── Request / correlation id ────────────────────────────────────────────────


def test_request_id_is_captured_from_the_middleware(client, auth_headers, db_session):
    """
    The whole point of the correlation id is that the value on the audit row
    equals the X-Request-ID the caller saw, so the two can be joined.
    """
    supplied = "req-correlation-probe-0001"
    response = client.get(
        "/auth/me", headers={**auth_headers, "X-Request-ID": supplied}
    )
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == supplied

    # The login that produced auth_headers ran through the same middleware, so
    # there is at least one audited request to check.
    login_rows = (
        db_session.query(AuditLog).filter(AuditLog.action == "user.login").all()
    )
    assert login_rows, "login should have produced an audit row"
    assert all(
        r.request_id for r in login_rows
    ), "an audited request must carry the correlation id of the request that caused it"


def test_request_id_is_null_without_a_request(db_session, test_user):
    """Celery tasks and other non-request writers legitimately have none."""
    log_audit_event(db_session, test_user, "scan.completed", "scan", "scan_x")
    db_session.commit()

    row = db_session.query(AuditLog).filter(AuditLog.action == "scan.completed").one()
    assert row.request_id is None


# ─── Redaction ───────────────────────────────────────────────────────────────


def test_obvious_secret_names_are_recognised():
    for key in (
        "password",
        "password_hash",
        "totp_secret",
        "mfa_backup_codes",
        "api_key",
        "refresh_token",
        "private_key",
    ):
        assert is_sensitive_key(key), f"{key!r} should be treated as sensitive"


def test_recognition_survives_unusual_spelling():
    """
    A future call site will not necessarily use this schema's exact field
    names. Case, separators and camelCase must not defeat the check.
    """
    for key in ("API-Key", "apiKey", "API KEY", "New_Password", "TOTP.Secret"):
        assert is_sensitive_key(key), f"{key!r} should be treated as sensitive"


def test_identifiers_that_merely_look_sensitive_are_kept():
    """
    Over-redaction has a cost: the session-revocation events record which
    session was ended, and redacting that makes the event unusable for the
    reviewer deciding whether the right device was signed out.
    """
    for key in ("session_id", "credential_id", "token_id"):
        assert not is_sensitive_key(key), f"{key!r} should not be redacted"


def test_secret_values_never_reach_the_column(db_session, test_user):
    log_audit_event(
        db_session,
        test_user,
        "user.updated",
        "user",
        str(test_user.id),
        changes={
            "full_name": {"old": "Old Name", "new": "New Name"},
            "password": "hunter2-actual-secret",
            "api_key": "sk-live-should-never-be-stored",
        },
    )
    db_session.commit()

    row = db_session.query(AuditLog).filter(AuditLog.action == "user.updated").one()
    serialised = str(row.changes)

    assert "hunter2-actual-secret" not in serialised
    assert "sk-live-should-never-be-stored" not in serialised
    assert row.changes["password"] == REDACTED
    assert row.changes["api_key"] == REDACTED
    # The non-sensitive diff must survive intact — redaction that ate the
    # useful content would make the trail worthless.
    assert row.changes["full_name"] == {"old": "Old Name", "new": "New Name"}


def test_redaction_reaches_nested_old_new_pairs():
    """The shape every update endpoint uses, at depth."""
    out = redact_changes(
        {
            "account": {
                "password": {"old": "old-secret", "new": "new-secret"},
                "username": {"old": "a", "new": "b"},
            }
        }
    )
    assert "old-secret" not in str(out)
    assert "new-secret" not in str(out)
    assert out["account"]["username"] == {"old": "a", "new": "b"}


def test_a_sensitive_container_redacts_its_whole_subtree():
    """
    When the *container* is named for a secret, everything under it goes —
    the safe reading of `{"credentials": {...}}` is that the whole structure
    is credential material, not that only the keys we recognise inside it are.
    """
    out = redact_changes(
        {"credentials": {"username": "svc-account", "password": "s3cret"}}
    )
    assert out["credentials"] == REDACTED
    assert "svc-account" not in str(out)
    assert "s3cret" not in str(out)


def test_redaction_reaches_inside_lists():
    out = redact_changes({"entries": [{"token": "leak-me"}, {"name": "keep-me"}]})
    assert "leak-me" not in str(out)
    assert out["entries"][1]["name"] == "keep-me"


def test_existing_marker_values_are_preserved():
    """
    The call sites already write "modified"/"cleared" instead of a value.
    Replacing those with [REDACTED] would lose the distinction between
    "the password was changed" and "the MFA secret was wiped".
    """
    out = redact_changes(
        {
            "password_hash": "modified",
            "totp_secret": "cleared",
            "mfa_backup_codes": "cleared",
        }
    )
    assert out["password_hash"] == "modified"
    assert out["totp_secret"] == "cleared"
    assert out["mfa_backup_codes"] == "cleared"


def test_redaction_is_depth_bounded():
    """`changes` is caller-supplied; a deep structure must not blow the stack."""
    deep = current = {}
    for _ in range(200):
        current["nested"] = {}
        current = current["nested"]
    current["password"] = "secret"

    out = redact_changes(deep)
    assert "secret" not in str(out)


def test_redaction_passes_through_none():
    """Most call sites pass no changes at all."""
    assert redact_changes(None) is None
