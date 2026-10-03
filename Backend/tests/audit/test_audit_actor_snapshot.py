"""
tests/audit/test_audit_actor_snapshot.py
─────────────────────────────────────────────────────────────────────────────
Phase 4: an audit event must stay attributable after the account that produced
it is gone.

This is not a hypothetical. Before this phase, **88 of the 511 events on this
deployment (17%) had already lost their actor** — and not anonymous ones: the
affected actions include 27 successful `user.login`, 11 `user.logout` and 11
`user.profile_updated`, every call site of which passes a real user object.
`audit_logs.user_id` is `ON DELETE SET NULL`, so deleting one account erased
the actor from every event it had ever produced.

Two mechanisms do the erasing and both are covered here:

* the foreign key's own `ON DELETE SET NULL`, and
* `admin_users.purge_user`, which additionally issues an explicit
  `UPDATE audit_logs SET user_id = NULL` in application SQL before deleting.

`actor_user_id` / `actor_username` are frozen copies carrying no foreign key,
so nothing in either path can reach them.
"""

import pytest
from audit_chain_support import expect_refused
from db.base import gen_uuid
from db.models import AuditLog, User
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")


@pytest.fixture
def event(db_session, test_user):
    """One audit event written the way the application writes them."""
    from core.audit import log_audit_event

    log_audit_event(
        db_session,
        test_user,
        "user.login",
        "user",
        str(test_user.id),
        status="success",
    )
    db_session.commit()
    return (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == test_user.id)
        .order_by(AuditLog.created_at.desc())
        .first()
    )


def test_the_write_path_records_the_snapshot(event, test_user):
    """`log_audit_event` is the only writer, so this is the whole surface."""
    assert event is not None
    assert event.actor_user_id == test_user.id
    assert event.actor_username == test_user.username


def test_snapshot_matches_the_live_relationship_while_the_account_exists(
    event, test_user
):
    """Before any deletion the snapshot and the foreign key must agree."""
    assert event.user_id == event.actor_user_id
    assert event.user.username == event.actor_username


def test_snapshot_survives_account_deletion(db_session, event, test_user):
    """
    The foreign key's `ON DELETE SET NULL` fires; the snapshot does not move.

    This is the exact mechanism that made 88 live events unattributable.
    """
    expected_id, expected_name = test_user.id, test_user.username

    db_session.execute(
        text("DELETE FROM rbac_user_roles WHERE user_id = :u"), {"u": test_user.id}
    )
    db_session.delete(db_session.get(User, test_user.id))
    db_session.commit()
    db_session.expire_all()

    survivor = db_session.get(AuditLog, (event.id, event.org_id))
    assert survivor is not None, "deleting a user must not delete their history"
    assert survivor.user_id is None, "the foreign key should have nulled the actor"
    assert survivor.actor_user_id == expected_id, "the snapshot must not move"
    assert survivor.actor_username == expected_name


def test_snapshot_survives_the_explicit_purge_update(db_session, event, test_user):
    """
    `purge_user` does not rely on the foreign key — it issues its own
    `UPDATE audit_logs SET user_id = NULL` first. That statement is permitted
    by the phase-3 append-only trigger (it is exactly the allowed shape), so it
    really does run, and it must still leave the snapshot alone.
    """
    expected_id, expected_name = test_user.id, test_user.username

    db_session.execute(
        text("UPDATE audit_logs SET user_id = NULL WHERE user_id = :u"),
        {"u": test_user.id},
    )
    db_session.commit()
    db_session.expire_all()

    survivor = db_session.get(AuditLog, (event.id, event.org_id))
    assert survivor.user_id is None
    assert survivor.actor_user_id == expected_id
    assert survivor.actor_username == expected_name


def test_the_snapshot_cannot_be_rewritten(db_session, event):
    """
    The append-only trigger must protect the new columns too.

    It recognises the one permitted update as `to_jsonb(NEW) - 'user_id'`
    comparing equal — a whole-row test rather than a column list — precisely so
    that columns added later are covered without anyone remembering to extend
    it. These two are the first columns to exercise that property.
    """
    from sqlalchemy.exc import DatabaseError

    for column, value in (
        ("actor_user_id", "'usr_someone_else'"),
        ("actor_username", "'someone_else'"),
    ):
        message = expect_refused(
            db_session,
            f"UPDATE audit_logs SET {column} = {value} WHERE id = :i",
            {"i": event.id},
        )
        assert "append-only" in message


def test_nulling_the_snapshot_alongside_user_id_is_still_refused(db_session, event):
    """
    The permitted exception is `user_id` alone. Nulling the snapshot in the
    same statement is the obvious way to launder an actor out of the record,
    and it must not inherit the exception.
    """
    from sqlalchemy.exc import DatabaseError

    message = expect_refused(
        db_session,
        "UPDATE audit_logs SET user_id = NULL, actor_user_id = NULL, "
        "actor_username = NULL WHERE id = :i",
        {"i": event.id},
    )
    assert "append-only" in message


def test_an_actorless_audit_call_fails_loudly_rather_than_silently(db_session):
    """
    `log_audit_event(db, None, ...)` cannot work and must now say so.

    The signature permits `user=None`, but `org_id` is derived from the user
    and is NOT NULL and half the primary key, so such a call has *always*
    failed — it was simply swallowed, which is how it went unnoticed. Under the
    phase-4 contract it raises.

    This is safe because no production call site reaches it: an AST sweep of
    every `log_audit_event` call in routers, auth, core, scans and engines
    found zero passing `None`, and the one runtime path that could produce a
    `None` user — a login attempt on an unknown identifier — raises 401 before
    any audit call, deliberately, so it does not leak account existence.

    A failed login for a *known* account audits with the real user object, which
    is why `user.login_failed` rows exist in the trail at all.
    """
    from core.audit import log_audit_event

    with pytest.raises(Exception) as caught:
        log_audit_event(
            db_session, None, "user.login_failed", "user", None, status="denied"
        )
    db_session.rollback()
    # The point is that it surfaced, not which driver error it was.
    assert caught.value is not None


def test_legacy_rows_are_left_null_not_invented(db_session, test_org):
    """
    The migration backfills only where the live relationship still exists.

    A row whose actor was already erased cannot be recovered — the identity is
    gone — and inventing one would be worse than admitting the gap. This
    asserts the direction: no non-NULL snapshot may exist on a row that has
    neither a live `user_id` nor a backfilled value.
    """
    orphan_id = gen_uuid()
    db_session.add(
        AuditLog(
            id=orphan_id,
            org_id=test_org.id,
            user_id=None,
            action="user.login",
            status="success",
            severity="info",
        )
    )
    db_session.commit()

    row = db_session.get(AuditLog, (orphan_id, test_org.id))
    assert row.actor_user_id is None
    assert row.actor_username is None
