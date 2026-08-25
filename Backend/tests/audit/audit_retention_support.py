"""
tests/audit/audit_retention_support.py
─────────────────────────────────────────────────────────────────────────────
Shared helpers for the phase-6a retention suites.

Imported by bare name for the same reason ``audit_chain_support`` is: the group
directories under ``tests/`` carry no ``__init__.py``, because as packages
``tests/audit`` and friends collide with Backend's own top-level packages.

**Every retention suite skips when the bootstrap has not been run**, and a skip
is reported as NOT VERIFIED, never as a pass. The privileged half lives in
``scripts/audit/bootstrap_chain_retention.sql`` and can only be installed by a
database administrator as a superuser; the application role holds neither
SUPERUSER nor CREATEROLE, which is the entire point of the design.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from db.base import gen_uuid
from db.models import AuditLog
from sqlalchemy import text

SKIP_REASON = (
    "phase 6a audit retention is not installed in this database. A DBA must "
    "run, as a superuser: psql -v ON_ERROR_STOP=1 -f "
    "Backend/scripts/audit/bootstrap_chain_retention.sql — then rerun. "
    "NOT VERIFIED, not passing."
)


def retention_installed(conn) -> bool:
    from core.audit_retention import retention_installed as _installed

    return _installed(conn)["installed"]


def require_retention(conn) -> None:
    if not retention_installed(conn):
        pytest.skip(SKIP_REASON)


def make_legacy_event(session, org_id: str, *, age_days: float, action="user.login"):
    """
    One pre-chain row, made the way real pre-chain history was made: **with the
    chain trigger disabled**.

    The earlier version of this helper inserted the row normally and then
    stripped its hash. That looked equivalent and is not, and the difference is
    the whole point of these suites: a normal insert makes the chain trigger
    hash the row *and advance the head to it*. Removing the hash afterwards
    leaves the head — and the next event's ``prev_hash`` — pointing at a value
    no row carries any more. It broke the chain in the fixture, before the
    purge under test had run, and ``verify_chain`` duly reported
    ``walked 1 of 3 chained rows``.

    A test that corrupts the chain while setting up cannot say anything about
    whether a purge preserves it.

    Disabling the trigger is what genuinely pre-chain rows experienced: they
    were written before it existed. The head is never advanced, no hash is
    computed, no ``prev_hash`` link is created, and no legitimately chained row
    is touched. It matches ``test_audit_chain_legacy_boundary.org_with_legacy``,
    which had it right all along.

    ``age_days`` is what makes a row eligible: the purge floor is 90 days and
    is not overridable, so a test that wants a deletion has to age its data
    rather than lower the guard.
    """
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    event_id = gen_uuid()

    # `DISABLE TRIGGER` takes ACCESS EXCLUSIVE and is transactional, so no other
    # session ever observes a window in which audit_logs is unchained. Restored
    # on the success path; on failure the caller's ROLLBACK restores it, which
    # is the same discipline `suspended_immutability` documents — a statement
    # issued in a `finally` after an error would itself fail with "current
    # transaction is aborted" and turn a clear error into a confusing one.
    session.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_chain"))
    session.execute(
        text(
            "INSERT INTO audit_logs (id, org_id, action, resource_type, "
            "                        resource_id, status, severity, ip_address, "
            "                        created_at) "
            "VALUES (:i, :o, :a, 'user', 'legacy', 'success', 'info', "
            "        '10.180.6.14'::inet, :c)"
        ),
        {"i": event_id, "o": org_id, "a": action, "c": created},
    )
    session.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_chain"))
    session.commit()

    row = session.get(AuditLog, {"id": event_id, "org_id": org_id})
    assert row is not None and row.record_hash is None, (
        "a legacy fixture row must carry no hash; the chain trigger was not "
        "disabled for its insert"
    )
    return row


def seed_legacy(session, org_id: str, count: int, *, age_days: float = 400):
    """`count` aged pre-chain rows, plus the head row retention needs.

    The head's ``legacy_event_count`` is deliberately **not** adjusted to match.
    It is seeded once, from a COUNT, when the chain is bootstrapped; rows
    injected afterwards are invisible to it, and the only function that can
    move it decrements and is executable by ``audit_maintenance`` alone — which
    is correct and must not be worked around to make a fixture tidy.

    So on a test organisation the head sits *below* the row count, and
    ``verify_chain`` reports that as a **note**, not a break: rows written with
    the chain trigger disabled are how pre-chain history exists at all. What the
    product actually guarantees, and what the suites therefore assert, is that a
    purge decrements the head by exactly the number of rows it removed — a
    delta, not an absolute.
    """
    ensure_head(session, org_id)
    return [make_legacy_event(session, org_id, age_days=age_days) for _ in range(count)]


def ensure_head(session, org_id: str) -> None:
    """Guarantee a chain-head row exists — the purge locks it and refuses without."""
    exists = session.execute(
        text("SELECT 1 FROM audit_chain.audit_chain_heads WHERE org_id = :o"),
        {"o": org_id},
    ).scalar()
    if exists:
        return
    # Written by writing a real event: the head is created by the chain
    # trigger, and the application role cannot INSERT into it directly.
    from core.audit import log_audit_event
    from db.models import User

    actor = session.query(User).filter(User.org_id == org_id).first()
    if actor is not None:
        log_audit_event(session, actor, "user.login", "user", str(actor.id))
        session.commit()


def head_row(session, org_id: str):
    return session.execute(
        text(
            "SELECT event_count, legacy_event_count, genesis_event_id, "
            "       last_event_id, last_record_hash "
            "  FROM audit_chain.audit_chain_heads WHERE org_id = :o"
        ),
        {"o": org_id},
    ).fetchone()


def counts(session, org_id: str) -> dict:
    row = session.execute(
        text(
            "SELECT count(*) FILTER (WHERE record_hash IS NULL), "
            "       count(*) FILTER (WHERE record_hash IS NOT NULL) "
            "  FROM audit_logs WHERE org_id = :o"
        ),
        {"o": org_id},
    ).fetchone()
    return {"legacy": row[0], "chained": row[1]}


def anchors_for(session, org_id: str) -> list:
    return session.execute(
        text(
            "SELECT id, kind, deleted_count, cutoff, range_from, range_to, "
            "       last_deleted_event_id, last_deleted_record_hash, "
            "       first_surviving_event_id, head_legacy_count_after, "
            "       head_tip_after, head_genesis_after, backup_reference, "
            "       operator_identity, operator_db_user "
            "  FROM audit_retention.retention_anchors "
            " WHERE org_id = :o ORDER BY id"
        ),
        {"o": org_id},
    ).fetchall()


def purge_events(session, org_id: str) -> list:
    return (
        session.query(AuditLog)
        .filter(
            AuditLog.org_id == org_id,
            AuditLog.action == "audit.retention_purge_executed",
        )
        .order_by(AuditLog.created_at)
        .all()
    )


def expect_refused(session, sql: str, params: dict | None = None) -> str:
    """
    Assert the database refuses `sql`, **without ever committing it**.

    The same discipline `audit_chain_support.expect_refused` establishes, and
    for the same reason: the natural ``with pytest.raises(...): execute();
    commit()`` shape commits the statement whenever it turns out to be
    permitted, which is precisely the case the test exists to detect. Every
    caller here is attempting a deliberate deletion.
    """
    allowed = False
    try:
        session.execute(text(sql), params or {})
        allowed = True
        message = "ALLOWED — the database permitted this statement"
    except Exception as exc:  # noqa: BLE001 - the message is the evidence
        message = str(exc)
    finally:
        session.rollback()

    assert not allowed, f"{sql!r} was permitted; the database must refuse it"
    return message
