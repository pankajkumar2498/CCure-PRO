"""
tests/audit/test_audit_retention_chained.py
─────────────────────────────────────────────────────────────────────────────
Phase 6c: removing rows that carry cryptographic evidence.

Phase 6a removed pre-chain rows, and that was cryptographically free — nothing
could link to them, so nothing could be broken. This is a different act. Every
row removed here was hashed and linked, and deleting one severs a link that
cannot be restored. The anchor is what makes the severance explicable rather
than indistinguishable from somebody quietly removing history.

Four properties carry the phase, and each has tests that fail loudly if it
regresses:

* **A contiguous prefix from genesis, never the middle.** A middle deletion
  orphans a link no anchor can explain.
* **A mandatory, verified archive.** A purge authorised by an export that
  verified nothing is a purge authorised by nothing.
* **The tip is undeletable**, enforced by the trigger per row, so it holds even
  if the purge function's own predicate is wrong.
* **Continuity is provable afterwards.** The surviving chain's first
  `prev_hash` equals the anchor's `last_deleted_record_hash`, and
  `verify_chain.py` reports 0 breaks.

What these tests deliberately do **not** claim: that the anchor preserves the
deleted events. It does not. The archive holds them, off-platform, in a file
this system does not have and cannot verify.
"""

import pytest
from audit_chain_support import require_chain, verify_org, write_event
from audit_retention_support import (
    anchors_for,
    chained_ids,
    counts,
    head_row,
    purge_events,
    require_retention,
)
from config import AppConfig
from core.audit_retention import (
    ArchiveUnacceptable,
    RetentionRefused,
    chained_retention_installed,
    describe_archive,
    resolve_cutoff,
    run_chained_retention,
)
from sqlalchemy import text

SKIP_6C = (
    "phase 6c chained retention is not installed in this database. A DBA must "
    "run, as a superuser: psql -v ON_ERROR_STOP=1 -f "
    "Backend/scripts/audit/bootstrap_chain_retention_chained.sql — then rerun. "
    "NOT VERIFIED, not passing."
)


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)
    require_retention(db_session)
    if not chained_retention_installed(db_session):
        pytest.skip(SKIP_6C)


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 0)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 1000)


def _age(db, org_id, event_id, days):
    """Backdate one chained row without disturbing its hash.

    `created_at` is inside the canonical payload, so changing it would break
    the row's own hash — which is why this is done with the append-only trigger
    suspended and the chain re-verified afterwards by the caller. Tests that
    need aged chained rows have no other way: the chain hashes at insert time
    and the purge floor is 90 days.
    """
    from db.audit_hardening import suspended_immutability

    with suspended_immutability(db):
        db.execute(
            text(
                "UPDATE audit_logs SET created_at = now() - make_interval(days => :d) "
                " WHERE id = :i AND org_id = :o"
            ),
            {"d": days, "i": event_id, "o": org_id},
        )
    db.commit()


@pytest.fixture
def aged_chain(db_session, test_user, enabled):
    """Six chained events, the first four backdated past the cutoff.

    Backdating rewrites `created_at`, which is hashed — so these rows no longer
    reproduce their own hashes. That is fine and deliberate for the tests that
    only exercise selection, refusal and accounting; the continuity tests below
    assert against the anchor and the head rather than against recomputation.
    """
    org = test_user.org_id
    ids = []
    for action in (
        "user.login",
        "user.profile_updated",
        "user.logout",
        "user.login",
        "user.profile_updated",
        "user.logout",
    ):
        write_event(db_session, test_user, action)
        ids.append(
            db_session.execute(
                text(
                    "SELECT id FROM audit_logs WHERE org_id = :o "
                    "   AND record_hash IS NOT NULL "
                    " ORDER BY created_at DESC LIMIT 1"
                ),
                {"o": org},
            ).scalar()
        )
    for event_id in ids[:4]:
        _age(db_session, org, event_id, 400)
    return {"org": org, "ids": ids, "old": ids[:4], "recent": ids[4:]}


@pytest.fixture
def archive(db_session, test_user):
    """A qualifying export event: verified, zero failures, covering everything."""
    from core.audit import log_audit_event
    from datetime import datetime, timedelta, timezone

    log_audit_event(
        db_session,
        test_user,
        "audit.log_exported",
        resource_type="audit_log",
        changes={
            "format": "csv",
            "row_count": 500,
            "verification_mode": "performed",
            "verified": 500,
            "not_verified": 0,
            "legacy_unverifiable": 0,
            "integrity_failures": 0,
            "snapshot_upper_bound": (
                datetime.now(timezone.utc) + timedelta(days=1)
            ).isoformat(),
        },
    )
    db_session.commit()
    return db_session.execute(
        text(
            "SELECT id FROM audit_logs WHERE org_id = :o "
            "   AND action = 'audit.log_exported' "
            " ORDER BY created_at DESC LIMIT 1"
        ),
        {"o": test_user.org_id},
    ).scalar()


SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ─── The archive is mandatory, and must be a good one ────────────────────────


def test_a_chained_purge_refuses_without_an_archive(db_session, aged_chain, enabled):
    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_chained_v1("
                "  :o, :c, 10, 90, NULL, NULL, 'test', NULL, 'test')"
            ),
            {"o": aged_chain["org"], "c": resolve_cutoff()},
        )
    assert "requires an archive" in str(raised.value)
    db_session.rollback()


def test_an_unverified_export_cannot_authorise_a_purge(
    db_session, test_user, aged_chain, enabled
):
    """
    The load-bearing rule. An export produced with verify=false recomputed
    nothing, so it is evidence of nothing — and authorising an irreversible
    deletion with it would launder exactly the gap the export exists to close.
    """
    from core.audit import log_audit_event
    from datetime import datetime, timedelta, timezone

    log_audit_event(
        db_session,
        test_user,
        "audit.log_exported",
        resource_type="audit_log",
        changes={
            "verification_mode": "not_requested",
            "integrity_failures": 0,
            "row_count": 10,
            "snapshot_upper_bound": (
                datetime.now(timezone.utc) + timedelta(days=1)
            ).isoformat(),
        },
    )
    db_session.commit()
    bad = db_session.execute(
        text(
            "SELECT id FROM audit_logs WHERE org_id=:o "
            "   AND action='audit.log_exported' ORDER BY created_at DESC LIMIT 1"
        ),
        {"o": test_user.org_id},
    ).scalar()

    assert describe_archive(db_session, bad)["acceptable"] is False

    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_chained_v1("
                "  :o, :c, 10, 90, :a, :s, 'test', NULL, 'test')"
            ),
            {"o": aged_chain["org"], "c": resolve_cutoff(), "a": bad, "s": SHA},
        )
    assert "not verified" in str(raised.value).lower()
    db_session.rollback()


def test_an_export_with_integrity_failures_cannot_authorise_a_purge(
    db_session, test_user, aged_chain, enabled
):
    from core.audit import log_audit_event
    from datetime import datetime, timedelta, timezone

    log_audit_event(
        db_session,
        test_user,
        "audit.log_exported",
        resource_type="audit_log",
        changes={
            "verification_mode": "performed",
            "integrity_failures": 3,
            "row_count": 10,
            "snapshot_upper_bound": (
                datetime.now(timezone.utc) + timedelta(days=1)
            ).isoformat(),
        },
    )
    db_session.commit()
    bad = db_session.execute(
        text(
            "SELECT id FROM audit_logs WHERE org_id=:o "
            "   AND action='audit.log_exported' ORDER BY created_at DESC LIMIT 1"
        ),
        {"o": test_user.org_id},
    ).scalar()

    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_chained_v1("
                "  :o, :c, 10, 90, :a, :s, 'test', NULL, 'test')"
            ),
            {"o": aged_chain["org"], "c": resolve_cutoff(), "a": bad, "s": SHA},
        )
    assert "integrity failure" in str(raised.value).lower()
    db_session.rollback()


def test_a_non_export_event_cannot_authorise_a_purge(
    db_session, aged_chain, archive, enabled
):
    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_chained_v1("
                "  :o, :c, 10, 90, :a, :s, 'test', NULL, 'test')"
            ),
            {
                "o": aged_chain["org"],
                "c": resolve_cutoff(),
                "a": aged_chain["ids"][0],
                "s": SHA,
            },
        )
    assert "not an audit.log_exported" in str(raised.value)
    db_session.rollback()


def test_an_export_that_does_not_reach_the_cutoff_is_refused(
    db_session, test_user, aged_chain, enabled
):
    """Cover, not exact match — but it must at least cover."""
    from core.audit import log_audit_event
    from datetime import datetime, timedelta, timezone

    log_audit_event(
        db_session,
        test_user,
        "audit.log_exported",
        resource_type="audit_log",
        changes={
            "verification_mode": "performed",
            "integrity_failures": 0,
            "row_count": 10,
            "snapshot_upper_bound": (
                datetime.now(timezone.utc) - timedelta(days=900)
            ).isoformat(),
        },
    )
    db_session.commit()
    short = db_session.execute(
        text(
            "SELECT id FROM audit_logs WHERE org_id=:o "
            "   AND action='audit.log_exported' ORDER BY created_at DESC LIMIT 1"
        ),
        {"o": test_user.org_id},
    ).scalar()

    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_chained_v1("
                "  :o, :c, 10, 90, :a, :s, 'test', NULL, 'test')"
            ),
            {"o": aged_chain["org"], "c": resolve_cutoff(), "a": short, "s": SHA},
        )
    assert "does not reach the cutoff" in str(raised.value)
    db_session.rollback()


def test_the_orchestration_refuses_an_unacceptable_archive(
    db_session, aged_chain, enabled
):
    with pytest.raises(ArchiveUnacceptable):
        run_chained_retention(
            db_session, aged_chain["org"], "no-such-event", SHA, dry_run=False
        )


# ─── The tip is undeletable ──────────────────────────────────────────────────


def test_the_trigger_refuses_to_delete_the_chain_tip(db_session, aged_chain, enabled):
    """
    D1(b). The database-level guard that replaced phase 6a's `record_hash`
    clause, asserted from the installed trigger source and from its behaviour.
    """
    source = db_session.execute(
        text(
            "SELECT prosrc FROM pg_proc p JOIN pg_namespace n "
            "  ON n.oid = p.pronamespace "
            " WHERE p.proname='audit_logs_reject_mutation' AND n.nspname='public'"
        )
    ).scalar()
    assert "audit_chain_is_tip_v1" in source
    assert "refusing to delete the current chain tip" in source


def test_a_purge_never_removes_the_tip(db_session, aged_chain, archive, enabled):
    """
    Every chained row is backdated, so age alone would take the whole chain.
    The tip must still survive — the function refuses to leave no chain, and
    the trigger refuses the tip per row.
    """
    org = aged_chain["org"]
    for event_id in aged_chain["ids"]:
        _age(db_session, org, event_id, 400)

    tip = head_row(db_session, org).last_event_id
    run_chained_retention(db_session, org, archive, SHA, dry_run=False)

    assert (
        db_session.execute(
            text("SELECT 1 FROM audit_logs WHERE id = :i AND org_id = :o"),
            {"i": tip, "o": org},
        ).scalar()
        == 1
    ), "the chain tip was removed"


# ─── Dry run writes nothing ──────────────────────────────────────────────────


def test_dry_run_is_the_default_and_writes_nothing(
    db_session, aged_chain, archive, enabled
):
    org = aged_chain["org"]
    before = counts(db_session, org)
    anchors_before = len(anchors_for(db_session, org))

    report = run_chained_retention(db_session, org, archive, SHA)

    assert report["dry_run"] is True
    assert report["would_delete_total"] >= 4
    assert counts(db_session, org) == before
    assert len(anchors_for(db_session, org)) == anchors_before


# ─── The purge itself ────────────────────────────────────────────────────────


def test_only_rows_older_than_the_cutoff_are_removed(
    db_session, aged_chain, archive, enabled
):
    org = aged_chain["org"]
    run_chained_retention(db_session, org, archive, SHA, dry_run=False)

    surviving = chained_ids(db_session, org)
    for event_id in aged_chain["old"]:
        assert event_id not in surviving, "an aged chained row survived"
    for event_id in aged_chain["recent"]:
        assert event_id in surviving, "a chained row inside the window was removed"


def test_the_anchor_records_the_continuity_hash_and_the_archive(
    db_session, aged_chain, archive, enabled
):
    org = aged_chain["org"]
    run_chained_retention(db_session, org, archive, SHA, dry_run=False)

    anchor = [a for a in anchors_for(db_session, org) if a.kind == "chained"][0]

    assert anchor.deleted_count == len(aged_chain["old"])
    assert anchor.last_deleted_record_hash is not None, (
        "a chained anchor must carry continuity evidence; only a legacy anchor "
        "may leave this NULL"
    )
    assert anchor.first_surviving_event_id in aged_chain["recent"]

    artefact = db_session.execute(
        text(
            "SELECT archive_artifact FROM audit_retention.retention_anchors "
            " WHERE id = :i"
        ),
        {"i": anchor.id},
    ).scalar()
    assert artefact["export_event_id"] == archive
    assert artefact["sha256"] == SHA


def test_the_surviving_chain_links_to_the_anchor(
    db_session, aged_chain, archive, enabled
):
    """
    The property the whole phase turns on: after the purge the oldest surviving
    row's `prev_hash` equals the hash of the newest row removed, and the anchor
    is what records that value.
    """
    org = aged_chain["org"]
    run_chained_retention(db_session, org, archive, SHA, dry_run=False)

    anchor = [a for a in anchors_for(db_session, org) if a.kind == "chained"][0]
    survivor = (
        db_session.execute(
            text(
                "SELECT id, prev_hash FROM audit_logs " " WHERE id = :i AND org_id = :o"
            ),
            {"i": anchor.first_surviving_event_id, "o": org},
        )
        .mappings()
        .fetchone()
    )

    assert survivor["prev_hash"] == anchor.last_deleted_record_hash


def test_genesis_is_repointed_and_the_count_decremented(
    db_session, aged_chain, archive, enabled
):
    org = aged_chain["org"]
    before = head_row(db_session, org)
    report = run_chained_retention(db_session, org, archive, SHA, dry_run=False)
    after = head_row(db_session, org)

    assert after.genesis_event_id != before.genesis_event_id, "genesis was not moved"
    assert after.genesis_event_id in aged_chain["recent"]
    # The tip must not move except by the purge's own audit event.
    assert after.last_event_id == purge_events(db_session, org)[-1].id
    assert after.event_count < before.event_count
    assert report["deleted_total"] == len(aged_chain["old"])


def test_the_purge_event_is_committed_and_names_its_anchor(
    db_session, aged_chain, archive, enabled
):
    from db.base import SessionLocal

    org = aged_chain["org"]
    run_chained_retention(db_session, org, archive, SHA, dry_run=False)

    independent = SessionLocal()
    try:
        event = (
            independent.execute(
                text(
                    "SELECT id, severity, changes FROM audit_logs "
                    " WHERE org_id = :o AND action='audit.retention_purge_executed' "
                    " ORDER BY created_at DESC LIMIT 1"
                ),
                {"o": org},
            )
            .mappings()
            .fetchone()
        )
    finally:
        independent.close()

    assert event is not None, "the purge event was never committed"
    assert event["severity"] == "critical"
    assert event["changes"]["kind"] == "chained"
    assert event["changes"]["archive_event_id"] == archive
    assert event["changes"]["archive_sha256"] == SHA

    anchor = [a for a in anchors_for(db_session, org) if a.kind == "chained"][0]
    assert anchor.audit_event_id == event["id"]


# ─── Chain verification across the boundary ──────────────────────────────────


def test_verify_chain_reports_no_break_after_a_chained_purge(
    db_session, aged_chain, archive, enabled
):
    """
    A sanctioned purge must not look like tampering. The oldest surviving row
    has a non-NULL `prev_hash` pointing at a row that no longer exists — which
    is exactly the shape of an unauthorised deletion — and the anchor is the
    only thing that tells them apart.
    """
    from scripts.audit.verify_chain import verify_org as script_verify

    org = aged_chain["org"]
    run_chained_retention(db_session, org, archive, SHA, dry_run=False)

    report = script_verify(db_session, org)
    assert report["breaks"] == [], report["breaks"]
    assert report["anchored_genesis"] is not None
    assert any("purge boundary" in note for note in report["notes"])


def test_an_unanchored_chained_deletion_is_still_a_break(
    db_session, aged_chain, archive, enabled
):
    """
    The mirror, and the test that proves the anchor *distinguishes* rather than
    *excuses*. Removed the way an operator holding the application's own
    credentials would — the documented honest-scope limit — with no anchor
    written, so nothing explains the gap.
    """
    from db.audit_hardening import suspended_immutability
    from scripts.audit.verify_chain import verify_org as script_verify

    org = aged_chain["org"]
    assert script_verify(db_session, org)["breaks"] == [], "clean before"

    genesis = head_row(db_session, org).genesis_event_id
    with suspended_immutability(db_session):
        db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :i AND org_id = :o"),
            {"i": genesis, "o": org},
        )
    db_session.commit()

    report = script_verify(db_session, org)
    assert report["breaks"], "an unanchored chained deletion was not detected"
    assert any("matches no retention anchor" in b for b in report["breaks"])


# ─── The legacy path is unaffected ───────────────────────────────────────────


def test_the_legacy_path_still_works_alongside(db_session, test_user, enabled):
    """Phase 6c must not have changed how pre-chain rows are removed."""
    from audit_retention_support import seed_legacy
    from core.audit_retention import run_retention

    org = test_user.org_id
    rows = seed_legacy(db_session, org, 3, age_days=400)
    report = run_retention(db_session, dry_run=False)

    assert report["deleted_total"] == len(rows)
    legacy_anchors = [a for a in anchors_for(db_session, org) if a.kind == "legacy"]
    assert legacy_anchors
    assert legacy_anchors[-1].last_deleted_record_hash is None


def test_ccure_user_still_cannot_delete_a_chained_row(db_session, aged_chain):
    """The application role gained nothing from this phase."""
    from audit_retention_support import expect_refused

    message = expect_refused(
        db_session,
        "DELETE FROM audit_logs WHERE id = :i AND org_id = :o",
        {"i": aged_chain["ids"][0], "o": aged_chain["org"]},
    )
    assert "append-only" in message
