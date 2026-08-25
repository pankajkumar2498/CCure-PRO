"""
tests/audit/test_audit_second_session_deadlock.py
─────────────────────────────────────────────────────────────────────────────
Phase 4, risk C2: opening a second database session to write an audit event,
while the request's own transaction is still open, is **prohibited**.

Why it is a trap rather than a style preference. The chain trigger takes a
`FOR UPDATE` lock on the organisation's row in `audit_chain_heads` and holds it
until commit. A second session writing an event for the same organisation
blocks on a lock the first session holds — and the first session cannot release
it, because it is waiting for the second to return. The request hangs until
something times it out.

`routers/compliance._audit_refusal` uses exactly this second-session pattern.
It is safe today, and the reason is narrow: its two call sites raise
immediately and are mutually exclusive with the success path's audit write, so
the request transaction never holds the head lock at the moment the second
session runs. That is a property of those call sites, not of the pattern — the
next handler to reuse it would not be so lucky.

`lock_timeout = '3s'` on the trigger function is what converts an indefinite
hang into a loud, diagnosable failure. These tests prove the timeout is real
and that the safe path stays safe.
"""

import pytest
from audit_chain_support import require_chain
from db.base import SessionLocal, gen_uuid
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)


@pytest.fixture
def org(db_session):
    from db.models import Organization

    organisation = Organization(
        name="Deadlock Probe Ltd", slug=f"deadlock-{gen_uuid()[:8]}"
    )
    db_session.add(organisation)
    db_session.commit()
    return organisation


def _insert(session, org_id):
    session.execute(
        text(
            "INSERT INTO audit_logs (id, org_id, action, status, severity, created_at) "
            "VALUES (:i, :o, 'user.login', 'success', 'info', now())"
        ),
        {"i": gen_uuid(), "o": org_id},
    )


def test_a_second_session_blocked_on_the_head_lock_fails_fast(db_session, org):
    """
    The prohibited pattern, made to happen deliberately.

    Session one writes an event and does **not** commit, so it holds the head
    lock. Session two — standing in for a stray `SessionLocal()` inside the
    same request — tries to write another event for the same organisation.

    It must fail within the pinned `lock_timeout` rather than wait forever. The
    error is the diagnosis: a lock timeout naming the chain write is something
    an operator can act on, whereas a hung worker is not.
    """
    holder = SessionLocal()
    blocked = SessionLocal()
    try:
        _insert(holder, org.id)  # takes and holds the head lock

        with pytest.raises(Exception) as caught:
            _insert(blocked, org.id)
            blocked.commit()

        message = str(caught.value)
        assert (
            "lock timeout" in message.lower() or "canceling statement" in message
        ), f"expected a lock timeout, got: {message[:200]}"
    finally:
        blocked.rollback()
        blocked.close()
        holder.rollback()
        holder.close()


def test_the_timeout_is_bounded_not_indefinite(db_session, org):
    """
    Measured rather than assumed. Without `lock_timeout` this call never
    returns, and the test would hang the suite instead of failing it.
    """
    from time import perf_counter

    holder = SessionLocal()
    blocked = SessionLocal()
    try:
        _insert(holder, org.id)

        started = perf_counter()
        with pytest.raises(Exception):
            _insert(blocked, org.id)
        elapsed = perf_counter() - started

        assert elapsed < 20, (
            f"blocked chain write took {elapsed:.1f}s — the pinned lock_timeout "
            f"does not appear to be in force"
        )
    finally:
        blocked.rollback()
        blocked.close()
        holder.rollback()
        holder.close()


def test_a_second_session_for_a_different_organisation_is_not_blocked(db_session, org):
    """
    The lock is per organisation. If a second session for a *different* tenant
    blocked, the design would be serialising the whole system rather than one
    chain — and the prohibition would have to be far broader than it is.
    """
    from db.models import Organization

    other = Organization(name="Other Probe Ltd", slug=f"other-{gen_uuid()[:8]}")
    db_session.add(other)
    db_session.commit()

    holder = SessionLocal()
    independent = SessionLocal()
    try:
        _insert(holder, org.id)  # holds org's head lock, uncommitted

        _insert(independent, other.id)
        independent.commit()  # must not block

        count = db_session.execute(
            text("SELECT count(*) FROM audit_logs WHERE org_id = :o"),
            {"o": other.id},
        ).scalar()
        assert count == 1
    finally:
        independent.rollback()
        independent.close()
        holder.rollback()
        holder.close()


def test_sequential_sessions_are_fine(db_session, org):
    """
    The prohibition is on a second session *while the first still holds the
    lock*. Once the first commits, the lock is released and a separate session
    chains normally — which is why `_audit_refusal` works: it runs on a path
    where the request transaction holds nothing.
    """
    first = SessionLocal()
    try:
        _insert(first, org.id)
        first.commit()
    finally:
        first.close()

    second = SessionLocal()
    try:
        _insert(second, org.id)
        second.commit()
    finally:
        second.close()

    rows = db_session.execute(
        text(
            "SELECT prev_hash, record_hash FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL"
        ),
        {"o": org.id},
    ).fetchall()
    assert len(rows) == 2
    genesis = [r for r in rows if r.prev_hash is None]
    assert len(genesis) == 1
    assert {r.prev_hash for r in rows if r.prev_hash} == {genesis[0].record_hash}


def test_the_prohibition_is_documented_where_the_pattern_lives(db_session):
    """
    A rule nobody can find is not a rule. `core/audit.py` is the module anyone
    adding an audit call will read first.
    """
    import core.audit as audit_module

    doc = (audit_module.__doc__ or "").lower()
    assert (
        "second" in doc and "sessionlocal" in doc
    ), "core/audit.py must document the second-session prohibition"
