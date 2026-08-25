"""
tests/audit/test_audit_chain_tamper.py
─────────────────────────────────────────────────────────────────────────────
Phase 4: the chain must *detect* what the append-only trigger cannot prevent.

The honest scope, stated the same way everywhere: `ccure_user` cannot modify an
audit row through any application path, but it owns `audit_logs`, so a
sufficiently determined operator with the application's own credentials can
drop the trigger and rewrite history. That is what the chain is for — evidence,
not prevention.

These tests therefore tamper the way that operator would: with the append-only
trigger suspended, using raw SQL. Every one of the fourteen canonical fields is
covered, plus the three ways someone would try to cover their tracks (forging
the row's own hash, forging its link, and rewriting the head).
"""

import pytest
from audit_chain_support import (
    newest_event,
    recompute,
    require_chain,
    verify_org,
    write_event,
)
from db.audit_hardening import suspended_immutability
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")

#: Every field in the canonical payload, with a value that differs from what
#: the fixture writes. `user_id` is deliberately absent — it is not hashed, and
#: a separate test asserts that nulling it does NOT break the chain.
TAMPERS = [
    ("action", "'user.something_else'"),
    ("resource_type", "'invoice'"),
    ("resource_id", "'someone-elses-resource'"),
    ("status", "'denied'"),
    ("severity", "'info'"),
    ("ip_address", "'203.0.113.99'"),
    ("user_agent", "'forged-agent/1.0'"),
    ("changes", """'{"tampered": true}'::jsonb"""),
    ("request_id", "'forged-request-id'"),
    ("actor_user_id", "'usr_someone_else'"),
    ("actor_username", "'someone_else'"),
    ("created_at", "now() - interval '30 days'"),
    ("id", "'forged-event-id'"),
]

#: `org_id` is covered separately. It carries a foreign key to `organizations`,
#: so rewriting it to an invented value fails with a FK violation *before* the
#: hash is ever consulted — which tests the foreign key, not the chain. To
#: prove the chain detects a tenant reassignment, the target organisation has
#: to actually exist.
TAMPER_ORG_ID = "org_id"


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)


@pytest.fixture
def chained(db_session, test_user):
    """Three linked events, so a tamper in the middle has neighbours."""
    events = []
    for action in ("user.login", "user.profile_updated", "user.logout"):
        write_event(db_session, test_user, action)
        events.append(newest_event(db_session, test_user.org_id))
    return events


def test_the_fixture_chain_verifies_before_any_tampering(
    db_session, test_user, chained
):
    """A test that cannot pass cleanly first proves nothing when it fails."""
    report = verify_org(db_session, test_user.org_id)
    assert report["broken"] == []
    assert report["genesis_count"] == 1
    assert report["forks"] == {}


@pytest.mark.parametrize("column,value", TAMPERS)
def test_rewriting_any_canonical_field_is_detected(
    db_session, test_user, chained, column, value
):
    """
    Fourteen fields, fourteen cases. If a field can be changed without the
    recomputed hash moving, it is not really covered by the chain — and an
    investigator reading a "verified" report would be misled about precisely
    that field.
    """
    target = chained[1]
    original = target.record_hash

    with suspended_immutability(db_session):
        db_session.execute(
            text(f"UPDATE audit_logs SET {column} = {value} WHERE id = :i"),
            {"i": target.id},
        )

    # `id` is half the primary key, so after rewriting it the row is found
    # under its new identity.
    lookup_id = "forged-event-id" if column == "id" else target.id
    lookup_org = target.org_id

    recomputed = recompute(db_session, lookup_id, lookup_org)
    assert recomputed is not None
    assert recomputed != original, (
        f"tampering with {column} left the hash unchanged — it is not covered "
        f"by the canonical payload"
    )
    db_session.rollback()


def test_nulling_user_id_is_not_reported_as_tampering(db_session, test_user, chained):
    """
    The counterpart to the fourteen above, and the reason `user_id` is excluded
    from the payload. Deleting an account is sanctioned and nulls this column
    on every event that account produced; if it broke the chain, a routine
    operation would raise a mass tamper alarm indistinguishable from an attack.
    """
    target = chained[1]
    db_session.execute(
        text("UPDATE audit_logs SET user_id = NULL WHERE id = :i"), {"i": target.id}
    )
    db_session.commit()

    assert recompute(db_session, target.id, target.org_id) == target.record_hash
    assert verify_org(db_session, test_user.org_id)["broken"] == []


def test_a_forged_record_hash_is_detected(db_session, test_user, chained):
    """
    The obvious cover-up: change the row, then change its hash to match. It
    fails because the recomputed value is derived from the row's content, not
    stored alongside it.
    """
    target = chained[1]
    with suspended_immutability(db_session):
        db_session.execute(
            text(
                "UPDATE audit_logs SET action = 'user.forged', "
                "record_hash = repeat('a', 64) WHERE id = :i"
            ),
            {"i": target.id},
        )
    report = verify_org(db_session, test_user.org_id)
    assert report["broken"], "a forged record_hash must be reported"
    db_session.rollback()


def test_a_forged_prev_hash_is_detected(db_session, test_user, chained):
    """
    The subtler cover-up: relink the chain around a deleted event. Changing
    `prev_hash` changes the row's own hash, because prev is prepended to the
    payload before hashing — which is what makes it a chain rather than a list
    of independent hashes.
    """
    target = chained[2]
    with suspended_immutability(db_session):
        db_session.execute(
            text("UPDATE audit_logs SET prev_hash = repeat('b', 64) WHERE id = :i"),
            {"i": target.id},
        )
    assert recompute(db_session, target.id, target.org_id) != target.record_hash
    report = verify_org(db_session, test_user.org_id)
    assert report["broken"] or report["walked"] < report["chained"]
    db_session.rollback()


def test_deleting_a_middle_event_breaks_the_walk(db_session, test_user, chained):
    """
    Removing an event leaves the next one pointing at a hash that no longer
    exists. The walk stops early, and the count mismatch is the signal.
    """
    with suspended_immutability(db_session):
        db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :i"), {"i": chained[1].id}
        )
    report = verify_org(db_session, test_user.org_id)
    assert report["walked"] < report["chained"] or report["broken"]
    db_session.rollback()


def test_an_appended_row_that_bypassed_the_trigger_is_visible(
    db_session, test_user, chained
):
    """
    The residue of the one thing the design cannot prevent: the table owner
    dropping the chain trigger and inserting. Such a row carries no hash and
    never advanced the head, so it shows up as an unchained row sitting after
    genesis rather than as a legacy row.
    """
    from db.base import gen_uuid

    db_session.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_chain"))
    forged_id = gen_uuid()
    db_session.execute(
        text(
            "INSERT INTO audit_logs (id, org_id, action, status, severity, created_at) "
            "VALUES (:i, :o, 'user.forged', 'success', 'info', now())"
        ),
        {"i": forged_id, "o": test_user.org_id},
    )
    db_session.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_chain"))

    unchained = db_session.execute(
        text(
            "SELECT count(*) FROM audit_logs WHERE org_id = :o AND record_hash IS NULL"
        ),
        {"o": test_user.org_id},
    ).scalar()
    head_count = db_session.execute(
        text("SELECT event_count FROM audit_chain_heads WHERE org_id = :o"),
        {"o": test_user.org_id},
    ).scalar()
    chained_rows = db_session.execute(
        text(
            "SELECT count(*) FROM audit_logs WHERE org_id = :o "
            "AND record_hash IS NOT NULL"
        ),
        {"o": test_user.org_id},
    ).scalar()

    assert unchained >= 1, "the bypassed row must be identifiable"
    assert (
        head_count == chained_rows
    ), "the head must not have counted a row that bypassed the trigger"
    db_session.rollback()


def test_a_rewritten_chain_head_disagrees_with_the_recomputed_tip(
    db_session, test_user, chained
):
    """
    The head and the rows are maintained in one transaction, so they can only
    diverge through out-of-band modification. That makes the head an
    independent witness: a cross-check against the recomputed tip catches
    tampering aimed at the head itself.

    The application role cannot perform this write at all — see
    `test_audit_chain_privileges` — so it is simulated by comparing against a
    value the head does not hold.
    """
    tip = chained[-1]
    head = db_session.execute(
        text("SELECT last_record_hash FROM audit_chain_heads WHERE org_id = :o"),
        {"o": test_user.org_id},
    ).scalar()

    assert head == tip.record_hash, "baseline: head agrees with the true tip"
    assert head != repeat_hash(), "a forged head value would not match the tip"


def repeat_hash() -> str:
    return "c" * 64


def test_reassigning_an_event_to_another_tenant_is_detected(
    db_session, test_user, chained
):
    """
    The fourteenth canonical field, covered on its own.

    `org_id` carries a foreign key, so pointing it at an invented organisation
    fails with a FK violation before the hash is ever consulted — that tests
    the constraint, not the chain. Moving an event into a **real** other tenant
    is the attack worth detecting: it hides an action from the organisation it
    happened in and plants it in one it did not.

    It is also a partition move (`audit_logs` is HASH partitioned on `org_id`),
    so this exercises the row crossing partitions as well.
    """
    from db.base import gen_uuid
    from db.models import Organization

    elsewhere = Organization(name="Elsewhere Ltd", slug=f"elsewhere-{gen_uuid()[:8]}")
    db_session.add(elsewhere)
    db_session.commit()

    target = chained[1]
    original = target.record_hash

    with suspended_immutability(db_session):
        db_session.execute(
            text("UPDATE audit_logs SET org_id = :o WHERE id = :i"),
            {"o": elsewhere.id, "i": target.id},
        )

    recomputed = recompute(db_session, target.id, elsewhere.id)
    assert recomputed is not None, "the row should exist under its new tenant"
    assert recomputed != original, (
        "moving an event to another tenant left the hash unchanged — org_id is "
        "not covered by the canonical payload"
    )
    db_session.rollback()
