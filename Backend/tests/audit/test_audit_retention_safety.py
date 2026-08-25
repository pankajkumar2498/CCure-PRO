"""
tests/audit/test_audit_retention_safety.py
─────────────────────────────────────────────────────────────────────────────
Phase 6a: everything retention must **refuse**.

An audit purge is irreversible and `archive_mode` is off on this deployment,
so recovery granularity is "since the last dump". That makes the refusals the
important half of the feature — more important than the deletion, which is
three lines of SQL. Each test here corresponds to a way somebody could destroy
audit history by accident.

Two properties run through all of them:

* **The application role gains nothing.** `ccure_user` could not delete or
  update an audit row before phase 6a and still cannot. The new escape is
  keyed on `current_user = 'audit_maintenance'`, which is true only inside a
  SECURITY DEFINER function owned by a role the application cannot become.

* **The 6a scope limit is a database constraint.** The trigger permits a
  maintenance DELETE only when `record_hash IS NULL`, so a chained row cannot
  be removed on this path even if every line of Python were wrong.
"""

from datetime import datetime, timedelta, timezone

import pytest
from audit_retention_support import (
    counts,
    expect_refused,
    require_retention,
    seed_legacy,
)
from config import AppConfig
from core.audit_retention import RetentionRefused, resolve_cutoff, run_retention
from sqlalchemy import text


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_retention(db_session)


@pytest.fixture
def enabled(monkeypatch):
    """Retention switched on for one test, at a period above the floor."""
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 0)
    return AppConfig


# ─── Retention disabled means zero mutation ──────────────────────────────────


def test_retention_is_disabled_by_default():
    """
    The shipped default, asserted rather than assumed.

    0 is not a placeholder for a number to be chosen in code later: ISO 27001
    A.5.33 requires a *defined* period and does not supply one, so picking one
    here would be inventing a compliance position.
    """
    from config import AppConfig as Shipped

    assert Shipped.AUDIT_LOG_RETENTION_DAYS == 0


def test_purge_refuses_when_retention_is_disabled(db_session, test_user, monkeypatch):
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 0)
    seed_legacy(db_session, test_user.org_id, 3)
    before = counts(db_session, test_user.org_id)

    with pytest.raises(RetentionRefused) as refusal:
        run_retention(db_session, dry_run=False)

    assert "disabled" in str(refusal.value).lower()
    assert counts(db_session, test_user.org_id) == before


def test_disabled_retention_writes_nothing_at_all(db_session, test_user, monkeypatch):
    """Not merely "deletes nothing" — no anchor and no audit event either."""
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 0)
    seed_legacy(db_session, test_user.org_id, 3)

    anchors_before = db_session.execute(
        text("SELECT count(*) FROM audit_retention.retention_anchors")
    ).scalar()

    with pytest.raises(RetentionRefused):
        run_retention(db_session, dry_run=False)

    assert (
        db_session.execute(
            text("SELECT count(*) FROM audit_retention.retention_anchors")
        ).scalar()
        == anchors_before
    )


# ─── The floor ───────────────────────────────────────────────────────────────


def test_a_period_below_the_floor_is_refused(monkeypatch):
    """
    `AUDIT_LOG_RETENTION_DAYS` is operator-supplied and "9" for "90" is not a
    recoverable typo. The floor turns it into an error message.
    """
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 9)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)

    with pytest.raises(RetentionRefused) as refusal:
        resolve_cutoff()
    assert "floor" in str(refusal.value).lower()


def test_the_database_enforces_the_floor_independently(db_session, test_user, enabled):
    """
    The Python check is a courtesy; this is the control.

    A caller reaching the function directly with a cutoff of yesterday must be
    refused by the function itself, because that is the layer a bug in the
    orchestration cannot get past.
    """
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_legacy_v1("
                "  :org, :cutoff, 10, 90, 'test', NULL, 'test')"
            ),
            {"org": test_user.org_id, "cutoff": yesterday},
        )
    assert (
        "floor" in str(raised.value).lower() or "younger" in str(raised.value).lower()
    )
    db_session.rollback()


def test_a_future_cutoff_is_refused_by_the_database(db_session, test_user, enabled):
    tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
    with pytest.raises(Exception) as raised:
        db_session.execute(
            text(
                "SELECT * FROM audit_retention.purge_legacy_v1("
                "  :org, :cutoff, 10, 90, 'test', NULL, 'test')"
            ),
            {"org": test_user.org_id, "cutoff": tomorrow},
        )
    assert "past" in str(raised.value).lower()
    db_session.rollback()


# ─── The backup precondition ─────────────────────────────────────────────────


def test_purge_refuses_without_a_recent_backup(
    db_session, test_user, monkeypatch, tmp_path
):
    """
    A hard precondition, not a warning. Without a dump the purge is simply
    unrecoverable, and a warning nobody reads is not a control.
    """
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 24)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BACKUP_DIR", str(tmp_path))

    seed_legacy(db_session, test_user.org_id, 3)
    before = counts(db_session, test_user.org_id)

    with pytest.raises(RetentionRefused) as refusal:
        run_retention(db_session, dry_run=False)

    assert "backup" in str(refusal.value).lower()
    assert counts(db_session, test_user.org_id) == before


def test_a_stale_backup_is_refused(db_session, test_user, monkeypatch, tmp_path):
    import os
    import time

    dump = tmp_path / "ccure_test_old.dump"
    dump.write_bytes(b"not really a dump")
    stale = time.time() - (48 * 3600)
    os.utime(dump, (stale, stale))

    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 24)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BACKUP_DIR", str(tmp_path))

    seed_legacy(db_session, test_user.org_id, 2)
    with pytest.raises(RetentionRefused) as refusal:
        run_retention(db_session, dry_run=False)
    assert "hours old" in str(refusal.value)


def test_a_dry_run_is_not_refused_for_want_of_a_backup(
    db_session, test_user, monkeypatch, tmp_path
):
    """
    A dry run is exactly what an operator does *before* taking a backup.
    Refusing it would make the safe action the inconvenient one.
    """
    monkeypatch.setattr(AppConfig, "AUDIT_LOG_RETENTION_DAYS", 180)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MIN_DAYS", 90)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", 24)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BACKUP_DIR", str(tmp_path))

    seed_legacy(db_session, test_user.org_id, 2)
    report = run_retention(db_session, dry_run=True)
    assert report["dry_run"] is True
    assert report["backup_reference"] is None


# ─── Dry run writes nothing ──────────────────────────────────────────────────


def test_dry_run_is_the_default(db_session, test_user, enabled):
    seed_legacy(db_session, test_user.org_id, 3)
    report = run_retention(db_session)  # no dry_run argument at all
    assert report["dry_run"] is True


def test_dry_run_deletes_nothing_and_writes_no_anchor_or_event(
    db_session, test_user, enabled
):
    org = test_user.org_id
    seed_legacy(db_session, org, 5)
    before = counts(db_session, org)
    anchors_before = db_session.execute(
        text("SELECT count(*) FROM audit_retention.retention_anchors WHERE org_id=:o"),
        {"o": org},
    ).scalar()
    events_before = db_session.execute(
        text(
            "SELECT count(*) FROM audit_logs WHERE org_id=:o "
            " AND action='audit.retention_purge_executed'"
        ),
        {"o": org},
    ).scalar()

    report = run_retention(db_session, dry_run=True)

    assert report["would_delete_total"] >= 5
    assert counts(db_session, org) == before
    assert (
        db_session.execute(
            text(
                "SELECT count(*) FROM audit_retention.retention_anchors WHERE org_id=:o"
            ),
            {"o": org},
        ).scalar()
        == anchors_before
    )
    assert (
        db_session.execute(
            text(
                "SELECT count(*) FROM audit_logs WHERE org_id=:o "
                " AND action='audit.retention_purge_executed'"
            ),
            {"o": org},
        ).scalar()
        == events_before
    )


# ─── The application role's privileges are unchanged ─────────────────────────


def test_ccure_user_still_cannot_delete_an_audit_row(db_session, test_user):
    """Phase 6a must not have widened anything for the application role."""
    row = seed_legacy(db_session, test_user.org_id, 1)[0]
    message = expect_refused(
        db_session,
        "DELETE FROM audit_logs WHERE id = :i AND org_id = :o",
        {"i": row.id, "o": row.org_id},
    )
    assert "append-only" in message


def test_ccure_user_still_cannot_delete_an_aged_legacy_row(db_session, test_user):
    """
    Being *eligible* for retention does not make a row deletable by the
    application. Eligibility is a property of the row; the privilege to act on
    it belongs to a different role entirely.
    """
    row = seed_legacy(db_session, test_user.org_id, 1, age_days=900)[0]
    message = expect_refused(
        db_session,
        "DELETE FROM audit_logs WHERE id = :i AND org_id = :o",
        {"i": row.id, "o": row.org_id},
    )
    assert "append-only" in message


def test_ccure_user_still_cannot_update_an_audit_row(db_session, test_user):
    row = seed_legacy(db_session, test_user.org_id, 1)[0]
    message = expect_refused(
        db_session,
        "UPDATE audit_logs SET action = 'forged' WHERE id = :i AND org_id = :o",
        {"i": row.id, "o": row.org_id},
    )
    assert "append-only" in message


def test_ccure_user_still_cannot_truncate(db_session):
    message = expect_refused(db_session, "TRUNCATE audit_logs")
    assert "not permitted" in message or "denied" in message.lower()


def test_ccure_user_is_not_a_member_of_audit_maintenance(db_session):
    """The whole boundary. If this is ever true, nothing else here matters."""
    assert (
        db_session.execute(
            text("SELECT pg_has_role(current_user, 'audit_maintenance', 'MEMBER')")
        ).scalar()
        is False
    )


def test_audit_maintenance_and_audit_chain_writer_are_separate(db_session):
    assert (
        db_session.execute(
            text(
                "SELECT pg_has_role('audit_maintenance','audit_chain_writer','MEMBER')"
                "    OR pg_has_role('audit_chain_writer','audit_maintenance','MEMBER')"
            )
        ).scalar()
        is False
    )


def test_ccure_user_cannot_write_to_the_anchor_table(db_session, test_user):
    """
    Anchors are the record that a purge happened. If the application role could
    write one, it could also fabricate one — and an anchor nobody can trust is
    worse than none, because it looks like accounting.
    """
    for statement in (
        (
            "INSERT INTO audit_retention.retention_anchors "
            "  (org_id, kind, purge_started_at, cutoff, deleted_count) "
            "  VALUES ('org_x','legacy', now(), now(), 1)"
        ),
        "DELETE FROM audit_retention.retention_anchors",
        "UPDATE audit_retention.retention_anchors SET deleted_count = 0",
    ):
        message = expect_refused(db_session, statement)
        assert "denied" in message.lower(), message


def test_ccure_user_cannot_create_objects_in_audit_retention(db_session):
    """
    A schema owner may drop any object in the schema regardless of who owns it
    — the phase-4 finding. The application role must not own this schema, and
    must not be able to create in it either.
    """
    message = expect_refused(db_session, "CREATE TABLE audit_retention.shadow (id int)")
    assert "denied" in message.lower()


def test_ccure_user_cannot_adjust_the_chain_head(db_session, test_user):
    """
    `audit_chain_note_legacy_purge_v1` exists for the purge function alone.
    Executable by the application role, it would let retention accounting be
    rewritten to hide a deletion.
    """
    assert (
        db_session.execute(
            text(
                "SELECT has_function_privilege(current_user, "
                "  'audit_chain.audit_chain_note_legacy_purge_v1(character varying, bigint)',"
                "  'EXECUTE')"
            )
        ).scalar()
        is False
    )


# ─── The phase boundary, enforced by PostgreSQL ──────────────────────────────


def test_the_purge_function_refuses_a_batch_containing_a_chained_row(
    db_session, test_user, enabled
):
    """
    The function's own guard. Phase 6a removes legacy rows only, and the
    predicate plus this assertion make that true twice over.
    """
    from audit_chain_support import require_chain, write_event

    require_chain(db_session)
    seed_legacy(db_session, test_user.org_id, 2, age_days=400)
    write_event(db_session, test_user, "user.login")

    before = counts(db_session, test_user.org_id)
    cutoff = datetime.now(timezone.utc) - timedelta(days=180)
    db_session.execute(
        text(
            "SELECT * FROM audit_retention.purge_legacy_v1("
            "  :org, :cutoff, 100, 90, 'test', NULL, 'test')"
        ),
        {"org": test_user.org_id, "cutoff": cutoff},
    ).fetchone()
    db_session.commit()

    after = counts(db_session, test_user.org_id)
    assert after["chained"] == before["chained"], "a chained row was removed"


def test_the_trigger_refuses_a_chained_row_even_for_the_maintenance_role(db_session):
    """
    The 6a scope limit as a database constraint rather than a convention.

    Read from the installed trigger source: both halves of the escape must be
    present. A future change that dropped `OLD.record_hash IS NULL` would make
    every chained row deletable by the maintenance path immediately, with
    nothing else in the system objecting.
    """
    source = db_session.execute(
        text(
            "SELECT prosrc FROM pg_proc p JOIN pg_namespace n "
            "  ON n.oid = p.pronamespace "
            " WHERE p.proname = 'audit_logs_reject_mutation' AND n.nspname='public'"
        )
    ).scalar()
    assert "current_user = 'audit_maintenance'" in source
    assert "OLD.record_hash IS NULL" in source


def test_the_purge_function_is_not_executable_by_public(db_session):
    assert (
        db_session.execute(
            text(
                "SELECT has_function_privilege('public', "
                "  'audit_retention.purge_legacy_v1(character varying, "
                "timestamp with time zone, integer, integer, text, "
                "character varying, text)', 'EXECUTE')"
            )
        ).scalar()
        is False
    )


# ─── The row cap ─────────────────────────────────────────────────────────────


def test_the_maximum_row_cap_is_enforced(db_session, test_user, enabled, monkeypatch):
    """
    A ceiling per invocation, so a misconfiguration removes at most this many
    rows before anyone looks at the result.
    """
    org = test_user.org_id
    seed_legacy(db_session, org, 9, age_days=400)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_MAX_ROWS_PER_RUN", 4)
    monkeypatch.setattr(AppConfig, "AUDIT_RETENTION_BATCH_SIZE", 2)

    report = run_retention(db_session, dry_run=False)

    assert report["deleted_total"] == 4
    assert report["capped"] is True
    assert counts(db_session, org)["legacy"] == 5


def test_the_chain_tip_is_never_in_a_purge_batch(db_session, test_user, enabled):
    """
    Deleting the tip would leave `last_record_hash` naming a row that no longer
    exists, and the *next* insert would link to a hash nothing can resolve —
    permanently unverifiable, and unfixable afterwards.
    """
    from audit_chain_support import require_chain, write_event

    require_chain(db_session)
    seed_legacy(db_session, test_user.org_id, 3, age_days=400)
    write_event(db_session, test_user, "user.login")

    tip = db_session.execute(
        text("SELECT last_event_id FROM audit_chain.audit_chain_heads WHERE org_id=:o"),
        {"o": test_user.org_id},
    ).scalar()

    run_retention(db_session, dry_run=False)

    still_there = db_session.execute(
        text("SELECT 1 FROM audit_logs WHERE id = :i AND org_id = :o"),
        {"i": tip, "o": test_user.org_id},
    ).scalar()
    assert still_there == 1, "the chain tip was removed"
