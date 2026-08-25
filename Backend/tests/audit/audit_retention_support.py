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
from db.audit_hardening import suspended_immutability
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
    One pre-chain row: written normally, then stripped of its hash.

    This is the shape real legacy history has, and the only way to produce it —
    the chain trigger hashes every insert unconditionally and discards whatever
    the client supplied in those columns, so a legacy row cannot be inserted
    directly. Stripping afterwards needs the append-only trigger suspended,
    which is why this helper exists rather than each suite doing it by hand.

    ``age_days`` is what makes a row eligible: the purge floor is 90 days and
    is not overridable, so a test that wants a deletion has to age its data
    rather than lower the guard.
    """
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    row = AuditLog(
        id=gen_uuid(),
        org_id=org_id,
        action=action,
        resource_type="user",
        resource_id="legacy",
        status="success",
        severity="info",
        ip_address="10.180.6.14",
        created_at=created,
    )
    session.add(row)
    session.commit()

    with suspended_immutability(session):
        session.execute(
            text(
                "UPDATE audit_logs SET record_hash = NULL, prev_hash = NULL "
                " WHERE id = :i AND org_id = :o"
            ),
            {"i": row.id, "o": org_id},
        )
    session.commit()
    return row


def seed_legacy(session, org_id: str, count: int, *, age_days: float = 400):
    """`count` aged pre-chain rows, plus the head row retention needs."""
    ensure_head(session, org_id)
    rows = [make_legacy_event(session, org_id, age_days=age_days) for _ in range(count)]
    # The head's legacy counter is seeded once at chain bootstrap; rows created
    # afterwards are invisible to it. Align it so the decrement the purge
    # performs can be asserted against a known starting point.
    set_head_legacy_count(session, org_id, count)
    return rows


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


def set_head_legacy_count(session, org_id: str, value: int) -> None:
    """Set the head's legacy counter through the sanctioned function only.

    The application role holds SELECT on `audit_chain_heads` and nothing more,
    so this goes through `audit_chain_note_legacy_purge_v1` — which only ever
    *decrements*. To raise the counter the helper first reads it; a test that
    needs a higher value must therefore have created the rows first.
    """
    current = session.execute(
        text(
            "SELECT legacy_event_count FROM audit_chain.audit_chain_heads "
            " WHERE org_id = :o"
        ),
        {"o": org_id},
    ).scalar()
    if current is None or current <= value:
        return
    session.execute(
        text("SELECT audit_chain.audit_chain_note_legacy_purge_v1(:o, :n)"),
        {"o": org_id, "n": current - value},
    )
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
