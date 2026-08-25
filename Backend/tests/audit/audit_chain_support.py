"""
tests/audit/audit_chain_support.py
─────────────────────────────────────────────────────────────────────────────
Shared helpers for the chain suites.

Imported by bare name (`import audit_chain_support`) rather than as a package
member: the group directories under `tests/` deliberately carry no
`__init__.py`, because as packages `tests/audit` and friends collide with
Backend's own top-level packages. pytest puts each test file's directory on
`sys.path`, so a bare import resolves — the same arrangement
`test_compliance_iso27001` already relies on.

**Every chain suite skips when the bootstrap has not been run**, and a skip is
reported as NOT VERIFIED, never as a pass. The privileged half of phase 4 lives
in `scripts/audit/bootstrap_chain.sql` and can only be installed by a database
administrator as `postgres`; the application role holds neither SUPERUSER nor
CREATEROLE, which is the entire point of the design.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

SKIP_REASON = (
    "audit chain is not installed in this database. A DBA must run, as "
    "postgres: psql -v ON_ERROR_STOP=1 -f Backend/scripts/audit/"
    "bootstrap_chain.sql  — then rerun. NOT VERIFIED, not passing."
)


def expect_refused(session, sql: str, params: dict | None = None) -> str:
    """
    Assert the database refuses `sql`, **without ever committing it**.

    Shared because getting this wrong is expensive and easy. The natural
    formulation —

        with pytest.raises(Exception):
            session.execute(text(sql))
            session.commit()

    — commits the statement whenever it turns out to be *permitted*, which is
    precisely the case the test exists to detect. Every caller here is
    attempting a deliberate tamper or a destructive DDL, so that shape means a
    regression is **executed** rather than merely reported.

    It has already cost one: `test_app_role_cannot_drop_the_canonical_functions`
    genuinely dropped `_audit_field_v1` from the test database and committed the
    drop, which broke twenty-four unrelated tests, because on that database the
    application role owns schema `public` and a schema owner may drop objects it
    does not own.

    The rollback is unconditional and happens before any assertion.
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


def chain_installed(conn) -> bool:
    """True only when both halves are present: the head table and the trigger."""
    has_table = bool(
        conn.execute(text("SELECT to_regclass('public.audit_chain_heads')")).scalar()
    )
    has_trigger = bool(
        conn.execute(
            text("SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_chain' LIMIT 1")
        ).scalar()
    )
    return has_table and has_trigger


def require_chain(conn) -> None:
    if not chain_installed(conn):
        pytest.skip(SKIP_REASON)


def write_event(session, user, action="user.login", **kwargs):
    """Write one audit event through the application's own write path."""
    from core.audit import log_audit_event

    log_audit_event(session, user, action, "user", str(user.id), **kwargs)
    session.commit()


def newest_event(session, org_id):
    from db.models import AuditLog

    return (
        session.query(AuditLog)
        .filter(AuditLog.org_id == org_id)
        .order_by(AuditLog.created_at.desc())
        .first()
    )


def head_row(conn, org_id):
    return conn.execute(
        text(
            "SELECT event_count, last_event_id, last_record_hash, genesis_event_id, "
            "       chain_started_at, legacy_event_count "
            "  FROM audit_chain_heads WHERE org_id = :o"
        ),
        {"o": org_id},
    ).fetchone()


def recompute(conn, event_id, org_id) -> str | None:
    """
    Recompute a row's hash **through the same SQL function the trigger uses**.

    Deliberately not a Python reimplementation: two implementations of a
    canonical form drift, and drift is indistinguishable from tampering.
    """
    return conn.execute(
        text(
            "SELECT audit_record_hash_v1(a.prev_hash, a) FROM audit_logs a "
            " WHERE a.id = :i AND a.org_id = :o"
        ),
        {"i": event_id, "o": org_id},
    ).scalar()


def verify_org(conn, org_id) -> dict:
    """
    Walk one organisation's chain and report on it.

    Ordering follows `prev_hash` links from genesis, **never `created_at`**:
    that column is set client-side in Python, so it can legitimately be out of
    order relative to insertion, and a verifier that sorted by it would
    manufacture false breaks.
    """
    rows = conn.execute(
        text(
            "SELECT id, prev_hash, record_hash FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL"
        ),
        {"o": org_id},
    ).fetchall()

    legacy = conn.execute(
        text(
            "SELECT count(*) FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NULL"
        ),
        {"o": org_id},
    ).scalar()

    by_prev: dict[str | None, list] = {}
    for row in rows:
        by_prev.setdefault(row.prev_hash, []).append(row)

    genesis = by_prev.get(None, [])
    result = {
        "chained": len(rows),
        "legacy": legacy,
        "genesis_count": len(genesis),
        "forks": {p: len(v) for p, v in by_prev.items() if len(v) > 1},
        "broken": [],
        "walked": 0,
    }
    if len(genesis) != 1:
        return result

    current = genesis[0]
    seen = set()
    while current is not None:
        if current.id in seen:
            result["broken"].append(f"cycle at {current.id}")
            break
        seen.add(current.id)
        result["walked"] += 1
        expected = recompute(conn, current.id, org_id)
        if expected != current.record_hash:
            result["broken"].append(f"hash mismatch at {current.id}")
        nxt = by_prev.get(current.record_hash, [])
        current = nxt[0] if nxt else None

    if result["walked"] != len(rows):
        result["broken"].append(
            f"walked {result['walked']} of {len(rows)} chained rows"
        )
    return result
