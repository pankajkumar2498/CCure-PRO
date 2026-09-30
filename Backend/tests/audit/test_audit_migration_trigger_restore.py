"""
tests/audit/test_audit_migration_trigger_restore.py
─────────────────────────────────────────────────────────────────────────────
Phase 4, risk M1: the actor-snapshot backfill is an `UPDATE` on `audit_logs`,
which the phase-3 append-only trigger refuses outright. The migration therefore
drops that trigger, backfills, and puts it back — inside one transaction.

The danger in that manoeuvre is obvious: a failure part-way through must not
leave the audit table permanently mutable. These tests assert the three states
that matter — before, after, and after a failure — and that no other session
can observe the gap.
"""

import pytest
from audit_chain_support import expect_refused
from db.audit_hardening import suspended_immutability
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

pytestmark = pytest.mark.usefixtures("db_session")


def _trigger_present(conn) -> bool:
    return bool(
        conn.execute(
            text(
                "SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_immutable' "
                "AND NOT tgisinternal LIMIT 1"
            )
        ).scalar()
    )


def _trigger_copies(conn) -> int:
    """Parent plus one clone per partition."""
    return conn.execute(
        text(
            "SELECT count(*) FROM pg_trigger "
            "WHERE tgname = 'audit_logs_immutable' AND NOT tgisinternal"
        )
    ).scalar()


@pytest.fixture(autouse=True)
def require_hardening(db_session):
    if not _trigger_present(db_session):
        pytest.skip(
            "audit_logs append-only enforcement is not installed in this "
            "database (migration f5a6b7c8d9e0). Run `alembic upgrade heads`."
        )


def test_the_trigger_is_present_before_and_after_the_migration(db_session):
    """
    The migration has already run against this database, so 'after' is now.
    The parent carries the trigger and every partition carries a clone — a
    parent-only trigger would leave `DELETE FROM audit_logs_p3` unguarded.
    """
    assert _trigger_present(db_session)
    partitions = db_session.execute(
        text(
            "SELECT count(*) FROM pg_inherits WHERE inhparent = 'audit_logs'::regclass"
        )
    ).scalar()
    assert _trigger_copies(db_session) == partitions + 1


def test_suspension_actually_lifts_the_trigger(db_session):
    """
    If it did not, the backfill would fail and the migration would be broken in
    the opposite direction. Asserted behaviourally, not just structurally: an
    `UPDATE` that is normally refused must succeed inside the block.
    """
    with suspended_immutability(db_session):
        assert not _trigger_present(db_session)
        # Normally refused. Touch nothing real — a WHERE that matches no row
        # still proves the statement was permitted rather than rejected.
        db_session.execute(
            text("UPDATE audit_logs SET action = action WHERE id = '__nonexistent__'")
        )
    assert _trigger_present(db_session)
    db_session.rollback()


def test_the_trigger_is_restored_on_the_success_path(db_session):
    with suspended_immutability(db_session):
        pass
    assert _trigger_present(db_session)
    partitions = db_session.execute(
        text(
            "SELECT count(*) FROM pg_inherits WHERE inhparent = 'audit_logs'::regclass"
        )
    ).scalar()
    assert (
        _trigger_copies(db_session) == partitions + 1
    ), "the restored trigger must be cloned to every partition again"
    db_session.rollback()


def test_a_failure_inside_the_block_leaves_the_trigger_installed(db_session):
    """
    The failure path, and the reason the context manager does not use
    `finally`. After an error the transaction is aborted, so re-creating the
    trigger there would itself fail with "current transaction is aborted" and
    would replace a clear error with a confusing one.

    Restoration comes from the ROLLBACK instead: the `DROP TRIGGER` is undone
    with everything else, so the two possible end states are "backfilled,
    trigger present" and "nothing changed, trigger present" — never "trigger
    missing".
    """
    with pytest.raises(RuntimeError, match="simulated backfill failure"):
        with suspended_immutability(db_session):
            raise RuntimeError("simulated backfill failure")

    db_session.rollback()
    assert _trigger_present(
        db_session
    ), "a failed maintenance block must not leave audit_logs mutable"


def test_enforcement_still_works_after_a_suspend_and_restore_cycle(
    db_session, test_user
):
    """
    Structural presence is not the same as working enforcement — a trigger can
    exist and point at the wrong function. This is the behavioural check.

    A row has to exist first. A row-level trigger fires per row, so an `UPDATE`
    matching nothing changes nothing, raises nothing, and would pass this test
    while proving nothing at all — the same trap the phase-3 partition test
    fell into.
    """
    from core.audit import log_audit_event

    log_audit_event(db_session, test_user, "user.login", "user", str(test_user.id))
    db_session.commit()

    with suspended_immutability(db_session):
        pass

    message = expect_refused(db_session, "UPDATE audit_logs SET action = 'tampered'")
    assert "append-only" in message


def test_a_database_error_inside_the_block_also_restores_the_trigger(db_session):
    """The realistic failure is a database error, not a Python one."""
    with pytest.raises(DatabaseError):
        with suspended_immutability(db_session):
            db_session.execute(text("SELECT * FROM a_table_that_does_not_exist"))

    db_session.rollback()
    assert _trigger_present(db_session)
