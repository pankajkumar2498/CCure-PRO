"""
tests/audit/test_audit_immutability.py
─────────────────────────────────────────────────────────────────────────────
Phase 3: the UI calls the audit trail an "immutable trail of system activities
and user actions". These tests are what makes that sentence true rather than
decorative.

Everything here talks to the database directly, deliberately. The API-layer
half — that no route exposes a write verb — is covered in
`test_audit_api_authorization.py`. This file assumes an attacker who already
has the application's database credentials, which is the situation the phrase
"enforced at the database level" is actually claiming to survive.

Scope, stated honestly: a superuser or the owning role can drop a trigger. What
these assert is that the application's role, using ordinary SQL, cannot alter
history — and that the one mutation the schema genuinely requires (the
`user_id` foreign key nulling itself when an account is deleted) still works,
because breaking account deletion to protect the audit log would be a poor
trade nobody asked for.
"""

import pytest
from db.base import gen_uuid
from db.models import AuditLog
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

pytestmark = pytest.mark.usefixtures("db_session")


def _hardening_installed(db_session) -> bool:
    return bool(
        db_session.execute(
            text("SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_immutable'")
        ).scalar()
    )


@pytest.fixture(autouse=True)
def require_hardening(db_session):
    """
    Skip rather than fail if the migration has not been applied to this
    database — the suite runs against disposable databases that may have been
    built by `create_all` at an older revision. A skip that says why is more
    useful than eleven failures that all mean "run alembic".
    """
    if not _hardening_installed(db_session):
        pytest.skip(
            "audit_logs append-only enforcement is not installed in this "
            "database (migration f5a6b7c8d9e0). Run `alembic upgrade heads`."
        )


@pytest.fixture
def event(db_session, test_user):
    row = AuditLog(
        id=gen_uuid(),
        org_id=test_user.org_id,
        user_id=test_user.id,
        action="user.login",
        resource_type="user",
        resource_id=str(test_user.id),
        status="success",
        severity="info",
        ip_address="10.180.6.14",
        request_id="req-immutability-probe",
    )
    db_session.add(row)
    db_session.commit()
    return row


def _expect_refused(db_session, sql, params=None):
    """
    Run `sql` and assert the database refused it — **without ever committing**.

    The rollback is unconditional and happens before the assertion. An earlier
    version committed inside `pytest.raises`, so a statement that turned out to
    be permitted was made durable before the test failed. Every statement here
    is a deliberate tamper attempt against the audit trail, so that shape meant
    a regression in the trigger would be *executed* rather than merely
    reported. It cost a dropped function in the sibling privileges suite before
    it was caught.
    """
    allowed = False
    try:
        db_session.execute(text(sql), params or {})
        allowed = True
        message = "ALLOWED — the database permitted this statement"
    except DatabaseError as exc:
        message = str(exc)
    finally:
        db_session.rollback()

    assert not allowed, f"{sql!r} was permitted; audit_logs must refuse it"
    return message


# ─── UPDATE ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "column,value",
    [
        ("action", "'something.else'"),
        ("status", "'success'"),
        ("severity", "'info'"),
        ("created_at", "now()"),
        ("ip_address", "'203.0.113.1'"),
        ("resource_id", "'someone-elses-resource'"),
        ("changes", "'{}'::jsonb"),
        ("request_id", "'forged'"),
        ("org_id", "'org_somewhere_else'"),
    ],
)
def test_no_field_of_an_audit_event_can_be_rewritten(db_session, event, column, value):
    """
    Every field the spec names as load-bearing: who, what, when, from where,
    what changed, whether it succeeded. Backdating `created_at` and forging
    `ip_address` are the two that matter most to an investigation.
    """
    message = _expect_refused(
        db_session,
        f"UPDATE audit_logs SET {column} = {value} WHERE id = :id",
        {"id": event.id},
    )
    assert "append-only" in message


def test_an_event_cannot_be_reattributed_to_a_different_user(
    db_session, event, test_user
):
    """
    The subtlest tamper available, and the reason the trigger does not simply
    allow any change to `user_id`: pointing an action at someone who did not
    perform it. The foreign key's own SET NULL is permitted; this is not.
    """
    message = _expect_refused(
        db_session,
        "UPDATE audit_logs SET user_id = 'usr_someone_else' WHERE id = :id",
        {"id": event.id},
    )
    assert "append-only" in message


def test_mass_update_across_the_table_is_refused(db_session, event):
    """A tamper does not have to name a row."""
    message = _expect_refused(db_session, "UPDATE audit_logs SET severity = 'info'")
    assert "append-only" in message


# ─── DELETE ──────────────────────────────────────────────────────────────────


def test_a_single_event_cannot_be_deleted(db_session, event):
    _expect_refused(
        db_session, "DELETE FROM audit_logs WHERE id = :id", {"id": event.id}
    )
    assert db_session.get(AuditLog, (event.id, event.org_id)) is not None


def test_a_whole_tenants_history_cannot_be_deleted(db_session, event):
    _expect_refused(
        db_session,
        "DELETE FROM audit_logs WHERE org_id = :o",
        {"o": event.org_id},
    )


def test_deleting_through_a_partition_directly_is_also_refused(db_session, event):
    """
    The parent table is not the only door. Enforcement has to reach every
    partition, or `DELETE FROM audit_logs_p3` walks around it.

    The statement is aimed at the partition that actually holds the seeded
    event. A row-level trigger fires per row, so `DELETE FROM <empty partition>`
    removes nothing, raises nothing, and would pass this test while proving
    nothing at all.
    """
    partition = db_session.execute(
        text("SELECT tableoid::regclass::text FROM audit_logs WHERE id = :id"),
        {"id": event.id},
    ).scalar()
    assert (
        partition and partition != "audit_logs"
    ), f"expected a leaf partition, got {partition!r}"

    message = _expect_refused(db_session, f"DELETE FROM {partition}")
    assert "append-only" in message
    assert db_session.get(AuditLog, (event.id, event.org_id)) is not None


# ─── TRUNCATE ────────────────────────────────────────────────────────────────


def test_truncate_is_refused_on_the_parent(db_session, event):
    """
    A row-level trigger never fires for TRUNCATE. Without a statement-level
    trigger this is the one statement that empties the entire trail while every
    other control looks correct.
    """
    _expect_refused(db_session, "TRUNCATE audit_logs")


def test_truncate_is_refused_on_every_partition(db_session, event):
    """
    Statement triggers are *not* cloned to partitions the way row triggers are,
    so each leaf carries its own. This is what catches a partition created
    later without one.
    """
    partitions = [
        r[0]
        for r in db_session.execute(
            text(
                "SELECT c.relname FROM pg_inherits i JOIN pg_class c "
                "ON c.oid = i.inhrelid "
                "WHERE i.inhparent = 'audit_logs'::regclass"
            )
        )
    ]
    for part in partitions:
        _expect_refused(db_session, f"TRUNCATE {part}")


def test_every_partition_carries_a_truncate_trigger(db_session):
    """
    Asserted structurally as well as behaviourally: a partition added by a
    future `create_partitions` run without a trigger is a hole that only opens
    when someone truncates it.
    """
    missing = db_session.execute(
        text(
            """
            SELECT c.relname
              FROM pg_inherits i
              JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = 'audit_logs'::regclass
               AND NOT EXISTS (
                   SELECT 1 FROM pg_trigger t
                    WHERE t.tgrelid = c.oid
                      AND NOT t.tgisinternal
                      AND t.tgname LIKE '%_no_truncate'
               )
            """
        )
    ).fetchall()
    assert not missing, f"partitions without a TRUNCATE trigger: {missing}"


# ─── What must still work ────────────────────────────────────────────────────


def test_inserting_a_new_event_still_works(db_session, test_user):
    """Append-only means append still works. This is the whole point."""
    row = AuditLog(
        id=gen_uuid(),
        org_id=test_user.org_id,
        user_id=test_user.id,
        action="user.logout",
        status="success",
        severity="info",
    )
    db_session.add(row)
    db_session.commit()
    assert db_session.get(AuditLog, (row.id, row.org_id)) is not None


def test_deleting_a_user_still_works_and_preserves_their_events(
    db_session, event, test_user
):
    """
    The one mutation the schema requires. `audit_logs.user_id` is
    ON DELETE SET NULL, and PostgreSQL performs that referential action with
    the privileges of the role issuing the DELETE — not the table owner.
    Revoking UPDATE to protect the trail was measured to break account deletion
    outright, which is why UPDATE is still granted and the trigger allows
    exactly this one shape.

    What must survive: the event itself, and every field except the actor
    pointer.
    """
    from db.models import User

    user = db_session.get(User, test_user.id)
    db_session.delete(user)
    db_session.commit()

    db_session.expire_all()
    survivor = db_session.get(AuditLog, (event.id, event.org_id))
    assert survivor is not None, "deleting a user must not delete their history"
    assert survivor.user_id is None, "the foreign key should have nulled the actor"
    assert survivor.action == "user.login"
    assert survivor.severity == "info"
    assert survivor.status == "success"
    assert survivor.request_id == "req-immutability-probe"
    assert str(survivor.ip_address) == "10.180.6.14"


# ─── The indexes this phase added ────────────────────────────────────────────


def test_the_measured_indexes_exist_and_are_valid(db_session):
    """
    An index built with the ON ONLY + ATTACH procedure is **invalid** — and
    silently ignored by the planner — until every partition has attached. A
    partially-attached index looks present in `pg_indexes` and does nothing.
    """
    for name in ("ix_audit_logs_user_created", "ix_audit_logs_request_id"):
        valid = db_session.execute(
            text(
                "SELECT indisvalid FROM pg_index "
                "WHERE indexrelid = CAST(:n AS regclass)"
            ),
            {"n": name},
        ).scalar()
        assert valid is True, f"{name} is missing or invalid (planner ignores it)"


def test_each_partition_has_its_own_attached_index(db_session):
    """The parent index is a container; the per-partition indexes do the work."""
    for name in ("ix_audit_logs_user_created", "ix_audit_logs_request_id"):
        attached = db_session.execute(
            text(
                "SELECT count(*) FROM pg_inherits "
                "WHERE inhparent = CAST(:n AS regclass)"
            ),
            {"n": name},
        ).scalar()
        partitions = db_session.execute(
            text(
                "SELECT count(*) FROM pg_inherits "
                "WHERE inhparent = 'audit_logs'::regclass"
            )
        ).scalar()
        assert attached == partitions, (
            f"{name}: {attached} partition indexes attached, "
            f"but audit_logs has {partitions} partitions"
        )
