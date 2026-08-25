"""
tests/audit/test_audit_retention_legacy.py
─────────────────────────────────────────────────────────────────────────────
Phase 6a: the purge does what it says, and the chain is unaffected.

The central claim being tested is that removing pre-chain rows is
**cryptographically free**, and that it is free *structurally* rather than by
luck: ``prev_hash`` references a ``record_hash`` value, legacy rows have no
``record_hash``, so nothing can ever link to one. The chain's genesis is a
chained row and stays exactly where it was.

The other half is accounting. An anchor records what was removed, and it is
written **before** the deletion in the same transaction, so an anchor without
its deletion is impossible and a deletion without its anchor is impossible.
What an anchor does *not* do is preserve the deleted events — for pre-chain
rows there was never any continuity to preserve, and there is no copy of the
content anywhere.
"""

import pytest
from audit_chain_support import require_chain, verify_org, write_event
from audit_retention_support import (
    anchors_for,
    counts,
    head_row,
    purge_events,
    require_retention,
    seed_legacy,
)
from config import AppConfig
from core.audit_retention import run_retention
from sqlalchemy import text


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)
    require_retention(db_session)


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 0)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 1000)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MAX_ROWS_PER_RUN", 50000)


@pytest.fixture
def mixed(db_session, test_user):
    """Aged legacy rows, recent legacy rows, and a live chain above both."""
    org = test_user.org_id
    old = seed_legacy(db_session, org, 6, age_days=400)
    recent = [row for row in seed_legacy(db_session, org, 2, age_days=10)]
    write_event(db_session, test_user, "user.login")
    write_event(db_session, test_user, "user.profile_updated")
    return {"old": old, "recent": recent, "org": org}


# ─── Only the right rows go ──────────────────────────────────────────────────


def test_only_rows_older_than_the_cutoff_are_removed(db_session, mixed, enabled):
    org = mixed["org"]
    run_retention(db_session, dry_run=False)

    remaining = {
        row[0]
        for row in db_session.execute(
            text("SELECT id FROM audit_logs WHERE org_id = :o"), {"o": org}
        )
    }
    for row in mixed["old"]:
        assert row.id not in remaining, "an aged legacy row survived"
    for row in mixed["recent"]:
        assert row.id in remaining, "a legacy row inside the window was removed"


def test_chained_rows_survive_a_legacy_purge(db_session, mixed, enabled):
    org = mixed["org"]
    before = counts(db_session, org)
    run_retention(db_session, dry_run=False)
    after = counts(db_session, org)

    assert after["chained"] == before["chained"]
    assert after["legacy"] == before["legacy"] - len(mixed["old"])


def test_only_rows_with_no_record_hash_are_eligible(db_session, mixed, enabled):
    """
    Backdating a chained row does not make it eligible. Age is one condition;
    the absence of a hash is the other, and it is the one that matters.
    """
    org = mixed["org"]
    chained_ids = {
        row[0]
        for row in db_session.execute(
            text(
                "SELECT id FROM audit_logs WHERE org_id=:o AND record_hash IS NOT NULL"
            ),
            {"o": org},
        )
    }
    run_retention(db_session, dry_run=False)
    still_there = {
        row[0]
        for row in db_session.execute(
            text("SELECT id FROM audit_logs WHERE org_id = :o"), {"o": org}
        )
    }
    assert chained_ids <= still_there


# ─── Chain integrity, before and after ───────────────────────────────────────


def test_the_chain_verifies_before_the_purge(db_session, mixed):
    """A test that cannot pass cleanly first proves nothing when it fails."""
    report = verify_org(db_session, mixed["org"])
    assert report["broken"] == []
    assert report["genesis_count"] == 1


def test_the_chain_still_verifies_after_the_purge(db_session, mixed, enabled):
    before = verify_org(db_session, mixed["org"])
    run_retention(db_session, dry_run=False)
    after = verify_org(db_session, mixed["org"])

    assert after["broken"] == []
    assert after["genesis_count"] == 1
    assert after["forks"] == {}
    # The chained half must be byte-for-byte the same walk.
    assert after["chained"] == before["chained"]
    assert after["walked"] == before["walked"]


def test_the_genesis_and_tip_are_untouched(db_session, mixed, enabled):
    org = mixed["org"]
    before = head_row(db_session, org)
    run_retention(db_session, dry_run=False)
    after = head_row(db_session, org)

    assert after.genesis_event_id == before.genesis_event_id
    assert after.last_event_id == before.last_event_id
    assert after.last_record_hash == before.last_record_hash
    assert after.event_count == before.event_count


def test_a_legitimate_purge_is_not_reported_as_a_tamper_break(
    db_session, mixed, enabled
):
    """
    The property the whole design exists to preserve. Sanctioned retention must
    look different from somebody quietly removing history — and it does,
    because the purge decrements the head in the same transaction as the
    deletion, so the two stay in agreement.
    """
    from scripts.audit.verify_chain import verify_org as script_verify_org

    run_retention(db_session, dry_run=False)
    report = script_verify_org(db_session, mixed["org"])
    assert report["breaks"] == [], report["breaks"]


def test_an_unaccounted_deletion_is_reported_as_a_break(db_session, mixed, enabled):
    """
    The mirror of the test above, and the one that proves the accounting
    *distinguishes* sanctioned retention from tampering rather than *excusing*
    both. Without it, "a purge is not reported as a break" would be satisfied
    by a verifier that never reports anything.

    The deletion is performed the way a determined operator holding the
    application's own credentials would: suspend the append-only trigger, delete
    directly, put it back. That is the documented honest-scope limit of this
    design — `ccure_user` owns `audit_logs` — and it is exactly the case the
    accounting exists to make visible. The chain head is not decremented,
    because nothing tells it, so the head ends up ahead of reality.
    """
    from db.audit_hardening import suspended_immutability
    from scripts.audit.verify_chain import verify_org as script_verify_org

    org = mixed["org"]
    run_retention(db_session, dry_run=False)
    assert script_verify_org(db_session, org)["breaks"] == [], "clean before"

    victim = db_session.execute(
        text(
            "SELECT id FROM audit_logs WHERE org_id = :o AND record_hash IS NULL "
            " LIMIT 1"
        ),
        {"o": org},
    ).scalar()
    assert victim, "the fixture must leave a legacy row to remove out of band"

    with suspended_immutability(db_session):
        db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :i AND org_id = :o"),
            {"i": victim, "o": org},
        )
    db_session.commit()

    report = script_verify_org(db_session, org)
    assert report["breaks"], "an out-of-band deletion was not detected"
    assert any("outside the purge path" in issue for issue in report["breaks"])


# ─── Accounting ──────────────────────────────────────────────────────────────


def test_legacy_event_count_matches_the_remaining_legacy_rows(
    db_session, mixed, enabled
):
    org = mixed["org"]
    run_retention(db_session, dry_run=False)

    head = head_row(db_session, org)
    assert head.legacy_event_count == counts(db_session, org)["legacy"]


def test_an_anchor_is_written_for_the_purge(db_session, mixed, enabled):
    org = mixed["org"]
    run_retention(db_session, dry_run=False)

    anchors = anchors_for(db_session, org)
    assert len(anchors) == 1
    anchor = anchors[0]
    assert anchor.kind == "legacy"
    assert anchor.deleted_count == len(mixed["old"])


def test_the_anchor_records_every_required_fact(db_session, mixed, enabled):
    org = mixed["org"]
    run_retention(db_session, dry_run=False)
    anchor = anchors_for(db_session, org)[0]
    head = head_row(db_session, org)

    assert anchor.deleted_count == len(mixed["old"])
    assert anchor.cutoff is not None
    assert anchor.range_from is not None and anchor.range_to is not None
    assert anchor.range_from <= anchor.range_to
    assert anchor.last_deleted_event_id in {row.id for row in mixed["old"]}
    assert anchor.first_surviving_event_id is not None
    assert anchor.head_legacy_count_after == head.legacy_event_count
    assert anchor.head_tip_after == head.last_event_id
    assert anchor.head_genesis_after == head.genesis_event_id
    assert anchor.operator_db_user
    assert anchor.operator_identity


def test_a_legacy_anchor_carries_no_hash_because_there_is_none(
    db_session, mixed, enabled
):
    """
    Stated as a test so it cannot quietly become untrue. A legacy anchor is an
    accounting record; it is not continuity evidence, and reading a hash out of
    one must not become possible by accident in phase 6b.
    """
    run_retention(db_session, dry_run=False)
    anchor = anchors_for(db_session, mixed["org"])[0]
    assert anchor.last_deleted_record_hash is None


def test_the_purge_audit_event_is_committed(db_session, mixed, enabled):
    """
    Read from an independent session. The event and the deletion share one
    transaction; an event that is written but never committed is the phase-4.1
    failure mode, and it is invisible from the session that wrote it.
    """
    from db.base import SessionLocal

    org = mixed["org"]
    run_retention(db_session, dry_run=False)

    independent = SessionLocal()
    try:
        events = (
            independent.execute(
                text(
                    "SELECT id, status, severity, actor_username, changes "
                    "  FROM audit_logs WHERE org_id = :o "
                    "   AND action = 'audit.retention_purge_executed'"
                ),
                {"o": org},
            )
            .mappings()
            .all()
        )
    finally:
        independent.close()

    assert len(events) == 1
    event = events[0]
    assert event["severity"] == "critical"
    assert event["actor_username"] == "system:retention"
    assert event["changes"]["kind"] == "legacy"
    assert event["changes"]["deleted_count"] == len(mixed["old"])
    assert event["changes"]["anchor_id"] is not None


def test_the_purge_event_is_itself_chained(db_session, mixed, enabled):
    """
    The record of a deletion has to be at least as trustworthy as the records
    it describes. It is written through the ordinary audit path, so the chain
    trigger hashes it like anything else.
    """
    run_retention(db_session, dry_run=False)
    event = purge_events(db_session, mixed["org"])[0]
    assert event.record_hash is not None
    assert len(event.record_hash) == 64


# ─── Batching ────────────────────────────────────────────────────────────────


def test_batching_removes_every_qualifying_row_exactly_once(
    db_session, test_user, enabled, monkeypatch
):
    org = test_user.org_id
    rows = seed_legacy(db_session, org, 11, age_days=400)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 3)

    report = run_retention(db_session, dry_run=False)

    assert report["deleted_total"] == 11
    assert counts(db_session, org)["legacy"] == 0
    # One anchor per batch: four batches for eleven rows at three per batch.
    anchors = anchors_for(db_session, org)
    assert sum(a.deleted_count for a in anchors) == 11
    assert len(anchors) == 4

    survivors = {
        row[0]
        for row in db_session.execute(
            text("SELECT id FROM audit_logs WHERE org_id = :o"), {"o": org}
        )
    }
    assert not ({row.id for row in rows} & survivors)


def test_each_batch_produces_its_own_audit_event(
    db_session, test_user, enabled, monkeypatch
):
    """
    One event per committed batch, not one per run. A batch is the unit that
    either happened or did not, so it is the unit that gets recorded.
    """
    org = test_user.org_id
    seed_legacy(db_session, org, 7, age_days=400)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 3)

    run_retention(db_session, dry_run=False)

    events = purge_events(db_session, org)
    assert len(events) == 3
    assert sum(e.changes["deleted_count"] for e in events) == 7


def test_nothing_is_deleted_when_no_row_qualifies(db_session, test_user, enabled):
    org = test_user.org_id
    seed_legacy(db_session, org, 4, age_days=5)
    before = counts(db_session, org)

    report = run_retention(db_session, dry_run=False)

    assert report["deleted_total"] == 0
    assert counts(db_session, org) == before
    assert anchors_for(db_session, org) == []


# ─── Tenant isolation ────────────────────────────────────────────────────────


def test_a_purge_touches_only_its_own_organisation(
    db_session, test_user, test_org, enabled
):
    from db.base import gen_uuid
    from db.models import Organization

    other = Organization(
        id=f"org_ret_{gen_uuid()[:8]}",
        name="Retention Other",
        slug=f"retention-other-{gen_uuid()[:8]}",
        max_assets=1,
        max_users=1,
        is_active=True,
    )
    db_session.add(other)
    db_session.commit()

    seed_legacy(db_session, test_user.org_id, 3, age_days=400)
    # The other tenant gets aged rows too, but no chain head — so it is not
    # eligible and must be left entirely alone.
    from audit_retention_support import make_legacy_event

    foreign = [make_legacy_event(db_session, other.id, age_days=400) for _ in range(3)]

    run_retention(db_session, dry_run=False)

    survivors = {
        row[0]
        for row in db_session.execute(
            text("SELECT id FROM audit_logs WHERE org_id = :o"), {"o": other.id}
        )
    }
    assert {row.id for row in foreign} <= survivors
