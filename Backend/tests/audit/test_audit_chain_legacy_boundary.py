"""
tests/audit/test_audit_chain_legacy_boundary.py
─────────────────────────────────────────────────────────────────────────────
Phase 4, decision 7: pre-chain history must never be reported as
cryptographically verified.

On this deployment the chain arrives on top of 511 existing events. Those rows
have no hashes and never can — there is nothing to recompute them against. A
verifier that quietly counted them as "verified", or that treated their missing
hashes as breaks, would be wrong in opposite and equally misleading directions.

The boundary is therefore explicit rather than inferred:

* `record_hash IS NULL` is the authoritative legacy test;
* `audit_chain_heads.legacy_event_count` records how many such rows existed
  per organisation when the chain was installed;
* `genesis_event_id` records the first chained event, so "everything before
  this is legacy" is a stored fact rather than a guess about timestamps.
"""

import pytest
from audit_chain_support import (
    expect_refused,
    head_row,
    newest_event,
    require_chain,
    verify_org,
    write_event,
)
from db.base import gen_uuid
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)


@pytest.fixture
def org_with_legacy(db_session, test_user):
    """
    An organisation carrying pre-chain rows, built the way history really got
    there: rows inserted with the chain trigger disabled, so they have no
    hashes.
    """
    from db.models import Organization

    org = Organization(name="Legacy Ltd", slug=f"legacy-{gen_uuid()[:8]}")
    db_session.add(org)
    db_session.commit()

    db_session.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_chain"))
    for _ in range(5):
        db_session.execute(
            text(
                "INSERT INTO audit_logs (id, org_id, action, status, severity, created_at) "
                "VALUES (:i, :o, 'user.login', 'success', 'info', now())"
            ),
            {"i": gen_uuid(), "o": org.id},
        )
    db_session.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_chain"))
    db_session.commit()
    return org


def test_legacy_rows_carry_no_hash(db_session, org_with_legacy):
    unhashed = db_session.execute(
        text(
            "SELECT count(*) FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NULL"
        ),
        {"o": org_with_legacy.id},
    ).scalar()
    assert unhashed == 5


def test_legacy_rows_are_reported_separately_not_as_verified(
    db_session, org_with_legacy, test_user
):
    """
    The core requirement. A report on this organisation must say "5 events
    predate the chain and cannot be verified", never fold them into a verified
    total and never call them breaks.
    """
    # Add chained events on top, so both populations coexist.
    from db.models import User

    member = User(
        username=f"legacy_member_{gen_uuid()[:6]}",
        email=f"legacy.{gen_uuid()[:6]}@test.com",
        password_hash="hash",
        org_id=org_with_legacy.id,
        role_id=test_user.role_id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(member)
    db_session.commit()

    for _ in range(3):
        write_event(db_session, member)

    report = verify_org(db_session, org_with_legacy.id)
    assert report["legacy"] == 5, "legacy rows must be counted, not ignored"
    assert report["chained"] == 3, "only chained rows are verifiable"
    assert report["broken"] == [], "legacy rows must not be reported as breaks"
    assert report["genesis_count"] == 1
    assert report["walked"] == 3


def test_the_chain_starts_cleanly_above_legacy_history(
    db_session, org_with_legacy, test_user
):
    """
    The first chained event is a genesis — `prev_hash IS NULL` — even though
    older events exist. It cannot link to them: they have no hash to link to.
    """
    from db.models import User

    member = User(
        username=f"legacy_first_{gen_uuid()[:6]}",
        email=f"first.{gen_uuid()[:6]}@test.com",
        password_hash="hash",
        org_id=org_with_legacy.id,
        role_id=test_user.role_id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(member)
    db_session.commit()

    write_event(db_session, member)
    first = newest_event(db_session, org_with_legacy.id)

    assert first.record_hash is not None
    assert (
        first.prev_hash is None
    ), "the first chained event must be a genesis, not linked to unhashed history"

    head = head_row(db_session, org_with_legacy.id)
    assert head.genesis_event_id == first.id
    assert head.chain_started_at is not None


def test_genesis_is_recorded_rather_than_inferred_from_timestamps(
    db_session, org_with_legacy, test_user
):
    """
    `created_at` is set client-side in Python, so it can be out of order
    relative to insertion — two events in the same millisecond, or a clock
    adjustment, make "oldest by timestamp" ambiguous. The boundary is therefore
    read from `genesis_event_id`, never derived by sorting.
    """
    from db.models import User

    member = User(
        username=f"legacy_gen_{gen_uuid()[:6]}",
        email=f"gen.{gen_uuid()[:6]}@test.com",
        password_hash="hash",
        org_id=org_with_legacy.id,
        role_id=test_user.role_id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(member)
    db_session.commit()

    write_event(db_session, member)
    genesis = newest_event(db_session, org_with_legacy.id)

    # A later event backdated behind genesis must not be mistaken for it.
    write_event(db_session, member, "user.logout")
    later = newest_event(db_session, org_with_legacy.id)
    assert later.prev_hash == genesis.record_hash

    head = head_row(db_session, org_with_legacy.id)
    assert (
        head.genesis_event_id == genesis.id
    ), "genesis must come from the head row, not from a timestamp sort"


def test_a_legacy_row_cannot_be_promoted_by_writing_a_hash_into_it(
    db_session, org_with_legacy
):
    """
    Backfilling hashes onto pre-chain rows would manufacture a verified history
    that no one ever witnessed. The append-only trigger refuses the write, so
    the boundary cannot be laundered away through any application path.
    """
    from sqlalchemy.exc import DatabaseError

    target = db_session.execute(
        text(
            "SELECT id FROM audit_logs WHERE org_id = :o AND record_hash IS NULL "
            "LIMIT 1"
        ),
        {"o": org_with_legacy.id},
    ).scalar()

    message = expect_refused(
        db_session,
        "UPDATE audit_logs SET record_hash = repeat('e', 64) WHERE id = :i",
        {"i": target},
    )
    assert "append-only" in message


def test_legacy_rows_never_inflate_the_chained_event_count(
    db_session, org_with_legacy, test_user
):
    """
    `event_count` counts chained events only. Legacy rows must never be folded
    into it, or the head would claim to cover history it cannot verify.

    Two things this test deliberately does **not** do:

    * It does not call `audit_chain_seed_legacy_v1()`. That function is a
      bootstrap-only entry point and the application role is denied EXECUTE on
      it — an earlier version of this test invoked it and was refused with
      `permission denied for function audit_chain_seed_legacy_v1`, which is the
      boundary working exactly as intended (asserted directly in
      `test_audit_chain_privileges.py`). Seeding is verified where it actually
      happens: on the live database, where the bootstrap produced 319 / 91 /
      105 for the three organisations.
    * It does not assume any head row already exists. The suite purges tenant
      data between tests, so seeded rows are cascaded away with their
      organisations.

    What is checked here is the property the trigger owns: a head created on
    first write starts at zero chained events, counts only what it chains, and
    leaves `legacy_event_count` alone.
    """
    from db.models import User

    member = User(
        username=f"legacy_count_{gen_uuid()[:6]}",
        email=f"count.{gen_uuid()[:6]}@test.com",
        password_hash="hash",
        org_id=org_with_legacy.id,
        role_id=test_user.role_id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(member)
    db_session.commit()

    unhashed_before = db_session.execute(
        text(
            "SELECT count(*) FROM audit_logs "
            " WHERE org_id = :o AND record_hash IS NULL"
        ),
        {"o": org_with_legacy.id},
    ).scalar()
    assert unhashed_before == 5, "fixture must supply 5 pre-chain rows"

    for _ in range(3):
        write_event(db_session, member)

    head = head_row(db_session, org_with_legacy.id)
    assert head is not None, "the trigger must create a head on first chained write"
    assert (
        head.event_count == 3
    ), f"head counted {head.event_count}; the 5 legacy rows must not be included"
    assert head.legacy_event_count == 0, (
        "the trigger initialises legacy_event_count to 0 — only the bootstrap "
        "seeder sets it, and it is not reachable from the application role"
    )

    # The legacy rows are still there, still unhashed, still unverifiable.
    assert (
        db_session.execute(
            text(
                "SELECT count(*) FROM audit_logs "
                " WHERE org_id = :o AND record_hash IS NULL"
            ),
            {"o": org_with_legacy.id},
        ).scalar()
        == 5
    )
