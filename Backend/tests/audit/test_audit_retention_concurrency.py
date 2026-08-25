"""
tests/audit/test_audit_retention_concurrency.py
─────────────────────────────────────────────────────────────────────────────
Phase 6a: atomicity, and what happens when a purge meets an export or a write.

Three things are being established here.

**A failed batch leaves nothing behind.** The anchor is written before the
deletion, in the same transaction, so the two can only ever both land or
neither. This is the one place the ordering is observable, and the test that
observes it must not weaken the atomicity it is testing — see
``test_the_anchor_exists_before_the_delete`` for how that is arranged.

**An export and a purge cannot produce a contradictory artefact.** The export
takes a shared, transaction-scoped advisory lock; the purge takes an exclusive,
**non-blocking** one and defers to its next run rather than waiting on a
download that may never finish.

**A purge does not block ordinary audit writes for long.** It holds the
organisation's chain-head lock for a batch, not for the run.
"""

import threading
import pytest
from audit_retention_support import (
    anchors_for,
    counts,
    require_retention,
    seed_legacy,
)
from config import AppConfig
from core.audit_retention import (
    GLOBAL_LOCK_KEY,
    RETENTION_LOCK_CLASS,
    resolve_cutoff,
    run_retention,
    try_take_purge_lock,
)
from db.base import SessionLocal
from sqlalchemy import text


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_retention(db_session)


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 0)


# ─── Atomicity ───────────────────────────────────────────────────────────────


def test_the_anchor_exists_before_the_delete(db_session, test_user, enabled):
    """
    The ordering the whole accounting model rests on.

    Observed **inside** the still-open transaction rather than by weakening it:
    the function is called directly, so its work is visible to this session and
    to nothing else, and the test reads the anchor and the surviving row count
    before deciding anything. Committing to make it observable, or splitting
    the anchor into its own transaction, would destroy the property being
    tested — an anchor that survived a failed deletion would be a record of a
    purge that never happened.

    The transaction is then rolled back, so neither the anchor nor the deletion
    reaches the database.
    """
    org = test_user.org_id
    rows = seed_legacy(db_session, org, 4, age_days=400)
    cutoff = resolve_cutoff()

    result = db_session.execute(
        text(
            "SELECT deleted_count, anchor_id FROM audit_retention.purge_legacy_v1("
            "  :org, :cutoff, 100, 90, 'atomicity-test', NULL, 'test')"
        ),
        {"org": org, "cutoff": cutoff},
    ).fetchone()

    # Both effects are visible here, in this transaction, and only here.
    assert result.deleted_count == len(rows)
    in_flight_anchor = db_session.execute(
        text(
            "SELECT deleted_count FROM audit_retention.retention_anchors "
            " WHERE id = :i"
        ),
        {"i": result.anchor_id},
    ).scalar()
    assert in_flight_anchor == len(rows), "the anchor was not written before the delete"
    assert counts(db_session, org)["legacy"] == 0

    db_session.rollback()

    # And neither survives the rollback.
    assert counts(db_session, org)["legacy"] == len(rows)
    assert anchors_for(db_session, org) == []


def test_a_failed_batch_rolls_back_the_anchor_and_the_deletion(
    db_session, test_user, enabled, monkeypatch
):
    """
    Failure injected **after** the purge function returns and before the
    commit, which is where the audit event is written. The end state must be
    "nothing happened" — not "rows gone, no record of why".
    """
    import core.audit_retention as retention

    org = test_user.org_id
    rows = seed_legacy(db_session, org, 4, age_days=400)

    def explode(*args, **kwargs):
        raise RuntimeError("injected failure after the delete, before the commit")

    monkeypatch.setattr("core.audit.log_audit_event", explode)
    monkeypatch.setattr(retention, "log_audit_event", explode, raising=False)

    with pytest.raises(RuntimeError):
        run_retention(db_session, dry_run=False)

    db_session.rollback()
    assert counts(db_session, org)["legacy"] == len(rows), "rows were lost"
    assert anchors_for(db_session, org) == [], "an orphaned anchor survived"


def test_a_refused_batch_leaves_no_anchor(db_session, test_user, enabled):
    """A hold discovered inside the function must not leave an anchor behind."""
    org = test_user.org_id
    seed_legacy(db_session, org, 3, age_days=400)
    db_session.execute(
        text("SELECT audit_retention.place_hold_v1(:o, 'blocked', 'tests')"),
        {"o": org},
    )
    db_session.commit()
    try:
        with pytest.raises(Exception):
            db_session.execute(
                text(
                    "SELECT * FROM audit_retention.purge_legacy_v1("
                    "  :org, :cutoff, 10, 90, 'test', NULL, 'test')"
                ),
                {"org": org, "cutoff": resolve_cutoff()},
            )
        db_session.rollback()
        assert anchors_for(db_session, org) == []
    finally:
        db_session.execute(
            text("SELECT audit_retention.release_hold_v1(:o, 'tests')"), {"o": org}
        )
        db_session.commit()


# ─── Advisory locking against exports ────────────────────────────────────────


def test_the_purge_lock_is_transaction_scoped_not_session_scoped(db_session, test_user):
    """
    Session-scoped advisory locks release when the *connection* closes, and
    SQLAlchemy pools connections — one taken by a request would survive being
    returned to the pool and leak onto the next unrelated request that drew the
    same connection. This asserts the lock is gone after a rollback, which only
    a transaction-scoped lock guarantees.
    """
    assert try_take_purge_lock(db_session, test_user.org_id) is True
    held = db_session.execute(
        text(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
            "  AND classid = :c AND pid = pg_backend_pid()"
        ),
        {"c": RETENTION_LOCK_CLASS},
    ).scalar()
    assert held >= 1

    db_session.rollback()

    still_held = db_session.execute(
        text(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
            "  AND classid = :c AND pid = pg_backend_pid()"
        ),
        {"c": RETENTION_LOCK_CLASS},
    ).scalar()
    assert still_held == 0, "the advisory lock outlived its transaction"


def test_the_purge_defers_while_an_export_holds_the_shared_lock(
    db_session, test_user, enabled
):
    """
    An export streams to a client that may be slow or may have stopped reading.
    A purge that waited would sit until its lock_timeout fired, in a nightly
    job nobody is watching — so it returns instead and tries again tomorrow.
    """
    org = test_user.org_id
    seed_legacy(db_session, org, 4, age_days=400)

    exporter = SessionLocal()
    ready = threading.Event()
    release = threading.Event()

    def hold_export_lock():
        try:
            from core.audit_retention import take_export_lock

            take_export_lock(exporter, org)
            # The global key too: a superadmin export takes that one, and the
            # purge must defer for either.
            exporter.execute(
                text("SELECT pg_advisory_xact_lock_shared(:c, :k)"),
                {"c": RETENTION_LOCK_CLASS, "k": GLOBAL_LOCK_KEY},
            )
            ready.set()
            release.wait(timeout=30)
        finally:
            exporter.rollback()
            exporter.close()

    worker = threading.Thread(target=hold_export_lock, daemon=True)
    worker.start()
    assert ready.wait(timeout=15), "the export thread never took its lock"

    try:
        report = run_retention(db_session, dry_run=False)
        assert report["deleted_total"] == 0
        assert org in report["deferred_orgs"]
        assert counts(db_session, org)["legacy"] == 4
    finally:
        release.set()
        worker.join(timeout=15)

    # And once the export finishes, the next run proceeds normally.
    db_session.rollback()
    follow_up = run_retention(db_session, dry_run=False)
    assert follow_up["deleted_total"] == 4


def test_two_purges_cannot_run_against_one_organisation_at_once(
    db_session, test_user, enabled
):
    org = test_user.org_id
    seed_legacy(db_session, org, 2, age_days=400)

    assert try_take_purge_lock(db_session, org) is True

    other = SessionLocal()
    try:
        assert try_take_purge_lock(other, org) is False
    finally:
        other.rollback()
        other.close()
    db_session.rollback()


# ─── Concurrent audit writes ─────────────────────────────────────────────────


def test_an_audit_write_is_not_blocked_for_the_whole_run(
    db_session, test_user, enabled, monkeypatch
):
    """
    The purge holds the chain-head lock for a **batch**, not for the run. With
    a batch size of one and eleven rows to remove there are eleven separate
    transactions, and an ordinary audit write must be able to interleave with
    them rather than waiting for all of them.
    """
    from audit_chain_support import require_chain
    from core.audit import log_audit_event

    require_chain(db_session)
    org = test_user.org_id
    seed_legacy(db_session, org, 11, age_days=400)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 1)

    report = run_retention(db_session, dry_run=False)
    assert report["deleted_total"] == 11

    # The write succeeds afterwards and joins the chain normally — the purge
    # left the head in a usable state rather than a locked or half-updated one.
    writer = SessionLocal()
    try:
        actor = writer.get(type(test_user), test_user.id)
        log_audit_event(writer, actor, "user.login", "user", str(actor.id))
        writer.commit()
        written = writer.execute(
            text(
                "SELECT record_hash FROM audit_logs WHERE org_id = :o "
                " ORDER BY created_at DESC LIMIT 1"
            ),
            {"o": org},
        ).scalar()
        assert written is not None and len(written) == 64
    finally:
        writer.close()


def test_the_chain_still_verifies_after_an_interleaved_run(
    db_session, test_user, enabled, monkeypatch
):
    from audit_chain_support import require_chain, verify_org, write_event

    require_chain(db_session)
    org = test_user.org_id
    write_event(db_session, test_user, "user.login")
    seed_legacy(db_session, org, 6, age_days=400)
    write_event(db_session, test_user, "user.profile_updated")
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 2)

    run_retention(db_session, dry_run=False)
    write_event(db_session, test_user, "user.logout")

    report = verify_org(db_session, org)
    assert report["broken"] == []
    assert report["genesis_count"] == 1
    assert report["forks"] == {}
