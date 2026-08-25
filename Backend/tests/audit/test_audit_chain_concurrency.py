"""
tests/audit/test_audit_chain_concurrency.py
─────────────────────────────────────────────────────────────────────────────
Phase 4: the chain must not fork under concurrent writers.

The failure this exists to prevent, from the design review:

    A: read HASH100          B: read HASH100
    A: write HASH101         B: write HASH102     <- fork

Two events then both claim the same predecessor, and the trail has two
histories with no way to say which is real. An earlier draft of this design
derived the tip with `ORDER BY created_at DESC LIMIT 1` under an advisory lock;
this one locks the organisation's row in `audit_chain_heads` with `FOR UPDATE`,
so serialisation is ordinary MVCC row locking rather than every writer
remembering to take the right advisory key.

**Zero duplicate `prev_hash` values is the assertion that would have failed
under the first draft**, and it is the one that matters most here.

Every test uses real, separate database connections through a thread pool. A
single session cannot exhibit this class of bug at all.
"""

from concurrent.futures import ThreadPoolExecutor
from time import perf_counter

import pytest
from audit_chain_support import (
    heads,
    require_chain,
    verify_org,
)
from db.base import SessionLocal, gen_uuid
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")

WRITERS = 40


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)


def _insert_one(org_id: str) -> str | None:
    """
    One audit event on its own connection, committed independently.

    Raw SQL rather than `log_audit_event`, so the test measures the chain
    trigger under contention rather than the ORM's flush behaviour.
    """
    session = SessionLocal()
    try:
        event_id = gen_uuid()
        session.execute(
            text(
                "INSERT INTO audit_logs "
                "  (id, org_id, action, resource_type, status, severity, created_at) "
                "VALUES (:i, :o, 'user.login', 'user', 'success', 'info', now())"
            ),
            {"i": event_id, "o": org_id},
        )
        session.commit()
        return event_id
    except Exception:
        session.rollback()
        return None
    finally:
        session.close()


def _run_concurrently(org_ids: list[str]) -> float:
    start = perf_counter()
    with ThreadPoolExecutor(max_workers=len(org_ids)) as pool:
        list(pool.map(_insert_one, org_ids))
    return perf_counter() - start


@pytest.fixture
def fresh_org(db_session):
    """An organisation with no audit history and no chain head row."""
    from db.models import Organization

    org = Organization(name="Chain Race Ltd", slug=f"chain-race-{gen_uuid()[:8]}")
    db_session.add(org)
    db_session.commit()
    yield org


def test_concurrent_writers_for_one_org_do_not_fork_the_chain(db_session, fresh_org):
    """
    The headline test. Forty writers, forty separate connections, one
    organisation.
    """
    _run_concurrently([fresh_org.id] * WRITERS)
    db_session.commit()

    rows = db_session.execute(
        text(
            "SELECT prev_hash, record_hash FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL"
        ),
        {"o": fresh_org.id},
    ).fetchall()

    assert len(rows) == WRITERS, f"expected {WRITERS} chained rows, got {len(rows)}"

    genesis = [r for r in rows if r.prev_hash is None]
    assert len(genesis) == 1, f"expected exactly one chain start, got {len(genesis)}"

    prevs = [r.prev_hash for r in rows if r.prev_hash is not None]
    assert len(prevs) == len(set(prevs)), (
        "duplicate prev_hash values: the chain forked — two events claim the "
        "same predecessor"
    )

    hashes = {r.record_hash for r in rows}
    assert len(hashes) == WRITERS, "duplicate record_hash values"
    assert set(prevs).issubset(hashes), "a prev_hash points at no known event"


def test_the_chain_verifies_end_to_end_after_the_race(db_session, fresh_org):
    _run_concurrently([fresh_org.id] * WRITERS)
    db_session.commit()

    report = verify_org(db_session, fresh_org.id)
    assert report["genesis_count"] == 1
    assert report["forks"] == {}
    assert report["broken"] == []
    assert report["walked"] == WRITERS, (
        f"walked {report['walked']} of {report['chained']} rows — the chain is "
        f"not a single unbroken sequence"
    )


def test_the_head_tracks_every_insert_under_contention(db_session, fresh_org):
    """
    A lost update here would leave `event_count` short while the rows all
    exist — the head silently disagreeing with reality, which is exactly what
    the head-versus-recomputed-tip cross-check is meant to catch.
    """
    _run_concurrently([fresh_org.id] * WRITERS)
    db_session.commit()

    head = db_session.execute(
        text(
            "SELECT event_count, last_event_id, last_record_hash, genesis_event_id "
            f"  FROM {heads(db_session)} WHERE org_id = :o"
        ),
        {"o": fresh_org.id},
    ).fetchone()

    assert head is not None
    assert (
        head.event_count == WRITERS
    ), f"head counted {head.event_count} of {WRITERS} inserts — updates were lost"

    # The true tip is the one row nothing links to.
    rows = db_session.execute(
        text(
            "SELECT id, prev_hash, record_hash FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL"
        ),
        {"o": fresh_org.id},
    ).fetchall()
    linked = {r.prev_hash for r in rows}
    tip = [r for r in rows if r.record_hash not in linked]
    assert len(tip) == 1
    assert head.last_event_id == tip[0].id
    assert head.last_record_hash == tip[0].record_hash

    genesis = [r for r in rows if r.prev_hash is None][0]
    assert head.genesis_event_id == genesis.id


def test_the_first_event_race_produces_one_chain_not_two(db_session, fresh_org):
    """
    The initialisation path, exercised directly: an organisation with **no**
    head row, hit by concurrent first events. Both find nothing, so the race
    has to be resolved in the database — `ON CONFLICT DO NOTHING` followed by a
    **locked re-read**. Without the re-read both transactions proceed with
    `prev_hash = NULL` and start two separate chains.
    """
    head_before = db_session.execute(
        text(f"SELECT count(*) FROM {heads(db_session)} WHERE org_id = :o"),
        {"o": fresh_org.id},
    ).scalar()
    assert head_before == 0, "fixture must start with no chain head"

    _run_concurrently([fresh_org.id] * WRITERS)
    db_session.commit()

    # Not named `heads`: that shadows the imported schema-resolver helper, and
    # the shadow is created before the f-string on the same line evaluates it.
    head_count = db_session.execute(
        text(f"SELECT count(*) FROM {heads(db_session)} WHERE org_id = :o"),
        {"o": fresh_org.id},
    ).scalar()
    assert head_count == 1

    genesis = db_session.execute(
        text(
            "SELECT count(*) FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NOT NULL AND prev_hash IS NULL"
        ),
        {"o": fresh_org.id},
    ).scalar()
    assert genesis == 1, f"{genesis} chain starts — the initialisation race forked"


def test_separate_organisations_do_not_serialise_against_each_other(db_session):
    """
    The head lock is per organisation, which is what preserves cross-tenant
    throughput — a global chain would serialise every audit write in the
    system, defeating the reason `audit_logs` is hash-partitioned by `org_id`.

    Asserted on correctness (each chain independent and intact) and, loosely,
    on wall clock. The timing assertion is deliberately generous: this runs on
    a shared development machine and a tight bound would be flaky. It is here
    to catch a global lock, not to benchmark.
    """
    from db.models import Organization

    orgs = []
    for i in range(3):
        org = Organization(name=f"Parallel {i} Ltd", slug=f"parallel-{gen_uuid()[:8]}")
        db_session.add(org)
        orgs.append(org)
    db_session.commit()

    single = _run_concurrently([orgs[0].id] * WRITERS)
    db_session.commit()

    mixed = [o.id for o in orgs[1:] for _ in range(WRITERS)]
    multi = _run_concurrently(mixed)
    db_session.commit()

    for org in orgs:
        report = verify_org(db_session, org.id)
        assert report["genesis_count"] == 1, f"{org.slug}: {report}"
        assert report["forks"] == {}, f"{org.slug}: {report}"
        assert report["broken"] == [], f"{org.slug}: {report}"
        assert report["walked"] == WRITERS, f"{org.slug}: {report}"

    assert multi < single * 6, (
        f"two organisations took {multi:.2f}s against {single:.2f}s for one — "
        f"writers appear to be serialising across organisations"
    )
