"""
tests/audit/test_audit_helper_contract.py
─────────────────────────────────────────────────────────────────────────────
Phase 4, decision C4: `log_audit_event` must not swallow failures.

The old behaviour was `except Exception: logger.error(...)` around
`db.flush()`, and it was worse than it looked. The audit event was lost *and*
the session was left in a failed state, so the caller's `db.commit()` raised
anyway — the operator got a 500 and no audit record. The silence bought
nothing.

What must hold now:

* a failed audit write propagates;
* the session is left in a state where the business transaction cannot
  commit, so no change persists without its audit event;
* the failure is logged with enough to identify the lost event;
* a caller that audits an outcome it is about to fail on — `_audit_refusal` —
  still delivers its own intended HTTP status rather than a database error.
"""

import logging

import pytest
from db.models import AuditLog
from sqlalchemy.exc import SQLAlchemyError

pytestmark = pytest.mark.usefixtures("db_session")


def _boom(*_a, **_k):
    raise RuntimeError("simulated audit storage failure")


def test_a_failed_audit_write_propagates(db_session, test_user, monkeypatch):
    """The headline change: it raises instead of returning quietly."""
    from core import audit as audit_module

    monkeypatch.setattr(audit_module.Session, "flush", _boom, raising=False)

    with pytest.raises(RuntimeError, match="simulated audit storage failure"):
        audit_module.log_audit_event(
            db_session, test_user, "user.login", "user", str(test_user.id)
        )
    db_session.rollback()


def test_the_failure_is_logged_with_enough_to_identify_the_lost_event(
    db_session, test_user, monkeypatch, caplog
):
    """
    The exception reaches the caller's error handling, which reports a 500
    without ever naming the audit event as the cause. The log line is the only
    place the lost event is identified, so it has to carry the action, the
    resource and the correlation id.
    """
    from core import audit as audit_module

    monkeypatch.setattr(audit_module.Session, "flush", _boom, raising=False)

    with caplog.at_level(logging.ERROR, logger="core.audit"):
        with pytest.raises(RuntimeError):
            audit_module.log_audit_event(
                db_session, test_user, "user.role_changed", "user", "usr_target"
            )
    db_session.rollback()

    assert caplog.records, "a failed audit write must leave a log record"
    message = caplog.records[-1].getMessage()
    assert "user.role_changed" in message
    assert "usr_target" in message
    assert "RuntimeError" in message


def _unwritable_audit_row(monkeypatch):
    """
    Make the audit INSERT fail the way it would in production — at the
    database, not in Python.

    The distinction turned out to matter. A plain Python exception raised from
    a patched `flush` does **not** put the SQLAlchemy session into a failed
    state, so a caller could still commit afterwards. A genuine database error
    does. Since the realistic failures here are database ones — a constraint,
    the append-only trigger, a chain-head lock timeout — the test has to
    produce one of those to be measuring the real contract.
    """
    from core import audit as audit_module

    real = audit_module.AuditLog

    def broken(**kwargs):
        # An organisation id that cannot satisfy the foreign key: the flush
        # fails inside PostgreSQL, exactly as a real storage failure would.
        kwargs["org_id"] = "org_does_not_exist_anywhere"
        return real(**kwargs)

    monkeypatch.setattr(audit_module, "AuditLog", broken)


def test_the_business_change_cannot_commit_without_its_audit_event(
    db_session, test_user, monkeypatch
):
    """
    The contract that matters. A business mutation followed by a failing audit
    write must not be committable — otherwise the operation succeeds with no
    record of it, which is the one outcome this product must not produce.
    """
    from core import audit as audit_module

    original_name = test_user.full_name
    test_user.full_name = "Changed Before The Audit Write"
    db_session.flush()

    _unwritable_audit_row(monkeypatch)
    with pytest.raises(SQLAlchemyError):
        audit_module.log_audit_event(
            db_session, test_user, "user.profile_updated", "user", str(test_user.id)
        )

    monkeypatch.undo()
    # The session now requires a rollback. Committing over the top of a failed
    # flush is exactly what must not silently work.
    with pytest.raises(SQLAlchemyError):
        db_session.commit()

    db_session.rollback()
    db_session.expire_all()
    assert db_session.get(type(test_user), test_user.id).full_name == original_name


def test_an_uncaught_audit_failure_discards_the_request(
    client, db_session, auth_headers, test_user, monkeypatch
):
    """
    End to end, through a real endpoint, read back through an **independent
    session**.

    The independent read is the point. The `client` fixture overrides `get_db`
    with the test's own session, so anything still pending in that session
    looks committed — which is how an earlier generation of these tests passed
    while proving nothing. Only a separate connection distinguishes
    "committed" from "merely flushed".

    `TestClient` is built with `raise_server_exceptions=True`, so an unhandled
    exception surfaces here rather than as a 500 response. That *is* the
    observation being made: the request did not complete, so `get_db` closed a
    session with uncommitted work and the change was discarded. Against a real
    deployment the same path returns 500.
    """
    from db.base import SessionLocal
    from db.models import User as UserModel

    user_id = test_user.id
    original = test_user.full_name

    _unwritable_audit_row(monkeypatch)

    with pytest.raises(SQLAlchemyError):
        client.put(
            "/user/profile",
            headers=auth_headers,
            json={"full_name": "Should Never Persist"},
        )

    monkeypatch.undo()
    db_session.rollback()

    verify = SessionLocal()
    try:
        persisted = verify.get(UserModel, user_id)
        assert (
            persisted is None or persisted.full_name != "Should Never Persist"
        ), "the business change committed without its audit event"
        assert (
            verify.query(AuditLog)
            .filter(AuditLog.action == "user.profile_updated")
            .filter(AuditLog.actor_user_id == user_id)
            .count()
            == 0
        ), "an audit row persisted despite the write having failed"
    finally:
        verify.close()

    assert original is not None


def test_a_successful_audit_write_still_leaves_the_commit_to_the_caller(
    db_session, test_user
):
    """
    The helper flushes but does not commit — unchanged, and load-bearing: the
    audit row and the business change share one transaction precisely because
    the caller owns the commit.
    """
    from core.audit import log_audit_event

    before = db_session.query(AuditLog).count()
    log_audit_event(db_session, test_user, "user.login", "user", str(test_user.id))

    # Visible inside the transaction...
    assert db_session.query(AuditLog).count() == before + 1
    db_session.rollback()
    # ...and gone once it is rolled back, because nothing committed it here.
    assert db_session.query(AuditLog).count() == before


def test_audit_refusal_preserves_the_original_http_exception(
    client, db_session, monkeypatch
):
    """
    `_audit_refusal` audits an outcome whose handler is about to raise. It uses
    a separate session and swallows deliberately, so that a database problem
    while recording the refusal cannot replace the 400 or 503 the caller
    intended with a 500 about audit storage.

    Under C4 `log_audit_event` raises, which makes that swallow load-bearing
    rather than incidental — this asserts it still holds.
    """
    from routers import compliance_common as compliance_module

    monkeypatch.setattr(compliance_module, "log_audit_event", _boom)

    intended = compliance_module.HTTPException(
        status_code=503, detail="scanner unavailable"
    )

    def handler():
        compliance_module._audit_refusal(
            user=None,
            action="upload_evidence",
            resource_type="evidence",
            resource_id="ctrl-1",
            status="scanner_unavailable",
        )
        raise intended

    with pytest.raises(compliance_module.HTTPException) as caught:
        handler()

    assert (
        caught.value.status_code == 503
    ), "the refusal's own audit failure must not replace the intended status"
    assert caught.value.detail == "scanner unavailable"
