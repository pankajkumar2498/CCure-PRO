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
    all_ids,
    anchors_for,
    chained_ids,
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
    # Plain ids, never mapped instances: the purge deletes these rows, and a
    # mapped object raises ObjectDeletedError the moment an attribute is read
    # afterwards — failing the test while asserting the deletion it asked for.
    old = seed_legacy(db_session, org, 6, age_days=400)
    recent = seed_legacy(db_session, org, 2, age_days=10)
    write_event(db_session, test_user, "user.login")
    write_event(db_session, test_user, "user.profile_updated")
    return {
        "old": old,
        "recent": recent,
        "org": org,
        # Captured before any purge runs, so "every chained row survived" is a
        # claim about the rows that existed then, not about a count.
        "chained_before": chained_ids(db_session, org),
    }


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
    for event_id in mixed["old"]:
        assert event_id not in remaining, "an aged legacy row survived"
    for event_id in mixed["recent"]:
        assert event_id in remaining, "a legacy row inside the window was removed"


def test_chained_rows_survive_a_legacy_purge(db_session, mixed, enabled):
    """
    **Survival is set inclusion, not an unchanged count.**

    A purge appends its own `audit.retention_purge_executed`, which is written
    through the ordinary audit path and is therefore chained like anything
    else. So the chained *count* legitimately rises by one per committed batch.
    Asserting the count was unchanged tested the wrong thing and would have
    failed on correct behaviour — what matters is that no row that was chained
    before the purge is missing after it.
    """
    org = mixed["org"]
    before = counts(db_session, org)

    run_retention(db_session, dry_run=False)

    after = counts(db_session, org)
    survivors = chained_ids(db_session, org)

    assert (
        mixed["chained_before"] <= survivors
    ), "a pre-existing chained row was removed"
    assert after["legacy"] == before["legacy"] - len(mixed["old"])
    # One new chained row: the purge's own event, from the single batch.
    assert after["chained"] == before["chained"] + 1


def test_only_rows_with_no_record_hash_are_eligible(db_session, mixed, enabled):
    """
    Backdating a chained row does not make it eligible. Age is one condition;
    the absence of a hash is the other, and it is the one that matters.
    """
    org = mixed["org"]
    hashed_before = chained_ids(db_session, org)
    run_retention(db_session, dry_run=False)
    assert hashed_before <= all_ids(db_session, org)


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

    assert after["broken"] == [], "the purge introduced a chain break"
    assert after["genesis_count"] == 1
    assert after["forks"] == {}
    # Every chained row is still reachable from genesis — including the purge's
    # own event, which is why the walk grows by one rather than staying equal.
    assert after["walked"] == after["chained"]
    assert after["chained"] == before["chained"] + 1
    assert mixed["chained_before"] <= chained_ids(db_session, mixed["org"])


def test_genesis_is_unchanged_and_the_tip_advances_to_the_purge_event(
    db_session, mixed, enabled
):
    """
    Genesis must not move; the tip must, and to a specific row.

    `genesis_event_id` is `COALESCE(genesis_event_id, NEW.id)` — set once and
    never again — so a purge moving it would mean the head had been rebuilt,
    which nothing here may do. The **tip** is different: the purge appends its
    own `audit.retention_purge_executed`, so the head advances to that event
    exactly as it would for any other write. Asserting the tip was unchanged
    was asserting that the purge failed to record itself.

    Pinning *which* row becomes the tip is the point — "the tip changed" alone
    would also be satisfied by something having quietly rewritten it.
    """
    org = mixed["org"]
    before = head_row(db_session, org)

    run_retention(db_session, dry_run=False)

    after = head_row(db_session, org)
    purge_event = purge_events(db_session, org)[-1]

    assert after.genesis_event_id == before.genesis_event_id, "genesis moved"
    assert after.last_event_id == purge_event.id
    assert after.last_record_hash == purge_event.record_hash
    assert after.event_count == before.event_count + 1


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
    The mirror of the test above: the accounting must *distinguish* sanctioned
    retention from tampering, not *excuse* both. Without this, "a purge is not
    reported as a break" would be satisfied by a verifier that never reports
    anything at all.

    **Scope, and why this test can skip.** The detection compares
    `audit_chain_heads.legacy_event_count` against the surviving pre-chain rows
    and reports a break only when the head is *ahead* — rows vanished without
    the counter moving, which is what an out-of-band deletion looks like.

    That comparison is meaningful only where the counter is authoritative: it
    is seeded once, from a `COUNT`, by `audit_chain_seed_legacy_v1` at chain
    bootstrap, and afterwards only ever decremented by the purge. On a real
    installation it therefore tracks reality, and this detection works. On a
    test organisation the rows are injected after that seeding, so the counter
    reads 0 while rows exist, and the head can never be ahead of anything.

    Raising it from a test is not available and must not be made available:
    `audit_chain_seed_legacy_v1` is granted to nobody, and
    `audit_chain_note_legacy_purge_v1` only decrements and is executable by
    `audit_maintenance` alone. Both are correct. So this test uses an
    organisation whose counter is genuinely authoritative if one exists, and
    **skips as NOT VERIFIED** rather than pretending otherwise.
    """
    from db.audit_hardening import suspended_immutability
    from scripts.audit.verify_chain import verify_org as script_verify_org

    org = mixed["org"]
    run_retention(db_session, dry_run=False)
    assert script_verify_org(db_session, org)["breaks"] == [], "clean before"

    # An organisation where the counter tracks the rows, and there is a
    # pre-chain row left to remove.
    candidate = db_session.execute(
        text(
            "SELECT h.org_id FROM audit_chain.audit_chain_heads h "
            "  JOIN (SELECT org_id, count(*) AS n FROM audit_logs "
            "         WHERE record_hash IS NULL GROUP BY org_id) a "
            "    ON a.org_id = h.org_id "
            " WHERE h.legacy_event_count = a.n AND a.n > 0 LIMIT 1"
        )
    ).scalar()

    if candidate is None:
        pytest.skip(
            "no organisation in this database has an authoritative "
            "legacy_event_count with pre-chain rows remaining. The counter is "
            "seeded from a COUNT by audit_chain_seed_legacy_v1 at chain "
            "bootstrap and can only be decremented afterwards, so a test "
            "organisation cannot reach that state and must not be given a "
            "privilege that would let it. Out-of-band-deletion detection is "
            "NOT VERIFIED here, not passing."
        )

    before = script_verify_org(db_session, candidate)
    assert before["breaks"] == [], "the candidate organisation is not clean"

    victim = db_session.execute(
        text(
            "SELECT id FROM audit_logs WHERE org_id = :o AND record_hash IS NULL "
            " LIMIT 1"
        ),
        {"o": candidate},
    ).scalar()

    # Removed the way a determined operator holding the application's own
    # credentials would — `ccure_user` owns `audit_logs`, the documented
    # honest-scope limit of this design. The head is not decremented, because
    # nothing tells it, so it ends up ahead of the surviving rows.
    with suspended_immutability(db_session):
        db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :i AND org_id = :o"),
            {"i": victim, "o": candidate},
        )
    db_session.commit()

    report = script_verify_org(db_session, candidate)
    assert report["breaks"], "an out-of-band deletion was not detected"
    assert any("outside the purge path" in issue for issue in report["breaks"])


def test_the_note_direction_is_not_reported_as_a_break(db_session, mixed, enabled):
    """
    The other half of the directional rule, and the half that *is* reachable
    here: a head **behind** the row count means rows were inserted with the
    chain trigger disabled — how pre-chain history exists at all, and what
    every legacy fixture produces. Reporting that as tampering would cry wolf
    on the ordinary case, so it is a note.
    """
    from scripts.audit.verify_chain import verify_org as script_verify_org

    org = mixed["org"]
    head = head_row(db_session, org)
    legacy_rows = counts(db_session, org)["legacy"]
    assert head.legacy_event_count < legacy_rows, (
        "this test needs the head behind the row count, which is what an "
        "injected legacy fixture produces"
    )

    report = script_verify_org(db_session, org)
    assert report["breaks"] == []
    assert any("unhashed row(s) beyond the count" in note for note in report["notes"])


# ─── Accounting ──────────────────────────────────────────────────────────────


def test_the_head_legacy_counter_falls_by_exactly_what_was_deleted(
    db_session, mixed, enabled
):
    """
    A **delta**, not an absolute, and the distinction is not a convenience.

    `legacy_event_count` is seeded once from a COUNT when the chain is
    bootstrapped. On a real installation it therefore equals the surviving
    pre-chain rows, and `verify_chain` treats a shortfall as a break. On a test
    organisation the rows are injected afterwards and the head cannot see them —
    the only function that moves it decrements, and is executable by
    `audit_maintenance` alone. Adjusting it from a fixture would mean handing
    the application role a privilege the design deliberately withholds.

    What the product guarantees either way is this: a purge decrements the head
    by exactly the number of rows it removed, in the same transaction. That is
    what makes an out-of-band deletion detectable, and it is what is asserted.
    """
    org = mixed["org"]
    before = head_row(db_session, org).legacy_event_count
    rows_before = counts(db_session, org)["legacy"]

    report = run_retention(db_session, dry_run=False)

    after = head_row(db_session, org).legacy_event_count
    rows_after = counts(db_session, org)["legacy"]

    assert report["deleted_total"] == len(mixed["old"])
    assert rows_before - rows_after == report["deleted_total"]
    # GREATEST(...,0) floors the counter, so the fall can be smaller than the
    # deletion only when the counter was already below it — never larger.
    assert before - after == min(before, report["deleted_total"])


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
    assert anchor.last_deleted_event_id in set(mixed["old"])
    assert anchor.first_surviving_event_id is not None
    assert anchor.head_legacy_count_after == head.legacy_event_count

    # `head_tip_after` is the tip **as the deletion left it** — captured when
    # the purge locked the head, which is necessarily before the purge writes
    # its own `audit.retention_purge_executed`. That event's id cannot exist
    # yet, and the anchor is written inside a SECURITY DEFINER function that
    # returns before it is created; `ccure_user` holds no UPDATE on the anchor
    # table and must not, so the row cannot be amended afterwards either.
    #
    # So the correct assertion is that the purge did not move the tip — legacy
    # rows are never the tip — and that the live head has since advanced to the
    # purge's own event.
    purge_event = purge_events(db_session, org)[-1]
    assert anchor.head_tip_after != purge_event.id
    assert head.last_event_id == purge_event.id
    assert anchor.head_genesis_after == head.genesis_event_id
    assert anchor.operator_db_user
    assert anchor.operator_identity


def test_the_anchor_names_the_purge_event_that_describes_it(db_session, mixed, enabled):
    """
    Phase 6b: `audit_event_id` resolves to the event, and to the right one.

    It used to be NULL, and could not be anything else: the anchor is written
    inside a SECURITY DEFINER function that returns *before* the audit event
    exists, and nothing may amend the anchor afterwards — `ccure_user` holds no
    UPDATE on that table and must not. The id is now chosen before the purge
    runs and handed to both, so the anchor and the event it names are one
    atomic fact rather than two things hoped to agree.
    """
    org = mixed["org"]
    run_retention(db_session, dry_run=False)

    anchor = anchors_for(db_session, org)[0]
    assert anchor.audit_event_id is not None, "the anchor did not name its event"

    event = (
        db_session.execute(
            text(
                "SELECT id, action, org_id, changes FROM audit_logs "
                " WHERE id = :i AND org_id = :o"
            ),
            {"i": anchor.audit_event_id, "o": org},
        )
        .mappings()
        .fetchone()
    )

    assert event is not None, "the anchor names an event that does not exist"
    assert event["action"] == "audit.retention_purge_executed"
    assert (
        event["changes"]["anchor_id"] == anchor.id
    ), "the event and the anchor do not point at each other"
    assert event["changes"]["deleted_count"] == anchor.deleted_count


def test_each_batch_anchor_names_its_own_distinct_event(
    db_session, test_user, enabled, monkeypatch
):
    """
    One anchor and one event per committed batch, paired one to one.

    A single id reused across batches would make the linkage worse than
    useless: every anchor would resolve to an event describing a different
    deletion.
    """
    org = test_user.org_id
    seed_legacy(db_session, org, 7, age_days=400)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 3)

    run_retention(db_session, dry_run=False)

    anchors = anchors_for(db_session, org)
    events = purge_events(db_session, org)
    assert len(anchors) == 3 and len(events) == 3

    ids = [a.audit_event_id for a in anchors]
    assert all(ids), "an anchor was left without an event id"
    assert len(set(ids)) == 3, "an event id was reused across batches"
    assert set(ids) == {e.id for e in events}

    for a in anchors:
        event = next(e for e in events if e.id == a.audit_event_id)
        assert event.changes["anchor_id"] == a.id
        assert event.changes["deleted_count"] == a.deleted_count


def test_a_failed_audit_write_rolls_back_the_anchor_and_the_deletion(
    db_session, test_user, enabled, monkeypatch
):
    """
    The linkage must not have created a way for an anchor to outlive its event.

    The audit write happens after the purge function returns, so if it fails
    the anchor is already in the transaction — and must go with it. Failure is
    injected there deliberately.
    """
    import core.audit_retention as retention

    org = test_user.org_id
    rows = seed_legacy(db_session, org, 4, age_days=400)

    def explode(*args, **kwargs):
        raise RuntimeError("injected: audit write fails after the anchor exists")

    monkeypatch.setattr(retention, "log_audit_event", explode, raising=False)
    monkeypatch.setattr("core.audit.log_audit_event", explode)

    with pytest.raises(RuntimeError):
        run_retention(db_session, dry_run=False)

    db_session.rollback()
    assert counts(db_session, org)["legacy"] == len(rows), "rows were lost"
    assert anchors_for(db_session, org) == [], "an anchor outlived its event"


def test_an_anchor_written_before_phase_6b_is_still_valid(
    db_session, test_user, enabled
):
    """
    `audit_event_id` stays nullable and carries no foreign key.

    Anchors written before this change have NULL there and must keep reading
    cleanly — the column is a soft reference by design. An FK to `audit_logs`
    was rejected precisely because audit rows *are* removable (an organisation
    deletion cascades, and a future chained purge would too), so the constraint
    would either block that removal or null the link, tying the anchor's
    survival to the trail it describes.
    """
    org = test_user.org_id
    seed_legacy(db_session, org, 2, age_days=400)
    run_retention(db_session, dry_run=False)

    anchor = anchors_for(db_session, org)[0]
    column = db_session.execute(
        text(
            "SELECT is_nullable FROM information_schema.columns "
            " WHERE table_schema='audit_retention' "
            "   AND table_name='retention_anchors' "
            "   AND column_name='audit_event_id'"
        )
    ).scalar()
    assert column == "YES", "audit_event_id must remain nullable"

    fks = db_session.execute(
        text(
            "SELECT count(*) FROM pg_constraint c "
            "  JOIN pg_class t ON t.oid = c.conrelid "
            " WHERE c.contype = 'f' AND t.relname = 'retention_anchors'"
        )
    ).scalar()
    assert fks == 0, "retention_anchors must carry no foreign key"

    # And the current anchor still resolves, proving the soft reference works
    # without one.
    assert anchor.audit_event_id is not None


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
    assert not (set(rows) & survivors)


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
    """
    A second tenant's rows must survive, and — because this one has pre-chain
    rows but **no chain head** — it must be skipped and reported rather than
    taking the whole run down with it.

    The purge locks the organisation's chain head, and that lock is what stops
    a purge interleaving with an insert. With no head there is nothing to lock,
    so the purge cannot run for that tenant and must not. What it must also not
    do is abort: retention is a nightly job across every tenant, and one tenant
    in an unexpected state stopping everyone else's backlog from draining is
    the wrong failure mode. It fails closed for the one and continues.

    A correctly bootstrapped database cannot reach this state —
    `audit_chain_seed_legacy_v1` creates a head for every organisation holding
    unhashed rows — so reaching it means something worth an operator seeing.
    """
    from audit_retention_support import make_legacy_event
    from db.base import gen_uuid
    from db.models import Organization

    other = Organization(
        id=f"org_ret_{gen_uuid()[:8]}",
        name="Retention Other",
        slug=f"retention-other-{gen_uuid()[:8]}",
        is_active=True,
    )
    db_session.add(other)
    db_session.commit()

    mine = seed_legacy(db_session, test_user.org_id, 3, age_days=400)
    foreign = [make_legacy_event(db_session, other.id, age_days=400) for _ in range(3)]

    report = run_retention(db_session, dry_run=False)

    # The eligible tenant was purged...
    assert report["deleted_total"] == len(mine)
    assert test_user.org_id in report["purged"]

    # ...and the headless one was skipped, reported, and left completely alone.
    assert other.id in report["no_head_orgs"]
    assert other.id not in report["purged"]
    assert set(foreign) <= all_ids(db_session, other.id)
    assert counts(db_session, other.id)["legacy"] == 3
    assert anchors_for(db_session, other.id) == []
