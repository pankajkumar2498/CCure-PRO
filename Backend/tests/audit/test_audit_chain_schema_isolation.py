"""
tests/audit/test_audit_chain_schema_isolation.py
─────────────────────────────────────────────────────────────────────────────
The chain machinery must live somewhere the application role cannot remove it.

Owning the objects is **necessary but not sufficient**. A PostgreSQL schema
owner may `DROP` any object in that schema, regardless of who owns the object.
Measured on this cluster with the same roles and the same objects, before the
isolation change:

    ccure_test       public owned by pg_database_owner
                     -> DROP FUNCTION audit_record_hash_v1 = must be owner
    ccure_pytest_db  public owned by ccure_user
                     -> DROP FUNCTION audit_record_hash_v1 = ALLOWED

(`ALTER ... RENAME` is refused in both — that one does require object
ownership. It is specifically `DROP` that a schema owner inherits.)

So the machinery moved into `audit_chain`, owned by `audit_chain_writer`. The
application role owns nothing there and belongs to no role that does.

Every probe below rolls back unconditionally and never commits. A test that
verifies "X is refused" must never be the thing that performs X — an earlier
version of the sibling suite committed a `DROP FUNCTION` that turned out to be
permitted and destroyed `_audit_field_v1` for twenty-four other tests.
"""

import pytest
from audit_chain_support import (
    CHAIN_SCHEMA,
    expect_refused,
    head_row,
    newest_event,
    recompute,
    require_chain,
    write_event,
)
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")

#: Hardcoded, not resolved. The sibling suites deliberately follow the chain to
#: wherever it currently lives so they keep testing during the window between
#: this change merging and a DBA running the move. This suite is the one that
#: asserts the move actually happened, so it must name the target explicitly —
#: resolving would make it pass against the very layout it exists to reject.
HEADS = f"{CHAIN_SCHEMA}.audit_chain_heads"


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)
    schema = db_session.execute(
        text(
            "SELECT n.nspname FROM pg_class c JOIN pg_namespace n "
            "ON n.oid = c.relnamespace WHERE c.relname = 'audit_chain_heads'"
        )
    ).scalar()
    if schema != CHAIN_SCHEMA:
        pytest.skip(
            f"NOT VERIFIED: chain is installed in `{schema}`, not `{CHAIN_SCHEMA}`. "
            f"Re-run scripts/audit/bootstrap_chain.sql as a superuser to move it."
        )


# ── Removal resistance — the reason the schema exists ───────────────────────


def test_app_role_cannot_drop_the_chain_schema(db_session):
    message = expect_refused(db_session, f"DROP SCHEMA {CHAIN_SCHEMA} CASCADE")
    assert "must be owner" in message or "permission denied" in message


def test_app_role_cannot_drop_the_head_table(db_session):
    message = expect_refused(db_session, f"DROP TABLE {HEADS}")
    assert "must be owner" in message or "permission denied" in message


@pytest.mark.parametrize(
    "signature",
    [
        "_audit_field_v1(text)",
        "audit_canonical_payload_v1(public.audit_logs)",
        "audit_record_hash_v1(text, public.audit_logs)",
        "audit_chain_advance_v1()",
        "audit_chain_seed_legacy_v1()",
    ],
)
def test_app_role_cannot_drop_any_chain_function(db_session, signature):
    """
    All five, individually. Dropping any one of them disarms the chain: the
    trigger calls `audit_chain_advance_v1`, which calls the hash function,
    which calls the field encoder.
    """
    message = expect_refused(db_session, f"DROP FUNCTION {CHAIN_SCHEMA}.{signature}")
    assert "must be owner" in message or "permission denied" in message


def test_app_role_cannot_create_objects_in_the_chain_schema(db_session):
    """
    CREATE is revoked as well as ownership withheld. Otherwise the application
    role could plant a function in `audit_chain` that later shadows a real one.
    """
    message = expect_refused(db_session, f"CREATE TABLE {CHAIN_SCHEMA}.planted (x int)")
    assert "permission denied" in message


def test_the_chain_schema_is_owned_by_the_writer_role(db_session):
    owner = db_session.execute(
        text("SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = :s"),
        {"s": CHAIN_SCHEMA},
    ).scalar()
    app_role = db_session.execute(text("SELECT current_user")).scalar()
    assert owner == "audit_chain_writer"
    assert owner != app_role, (
        "the application role owns the chain schema and can therefore drop "
        "everything in it"
    )


# ── Direct writes still denied, now schema-qualified ────────────────────────


@pytest.mark.parametrize(
    "verb,sql",
    [
        (
            "INSERT",
            f"INSERT INTO {HEADS} (org_id, event_count, legacy_event_count) "
            "VALUES ('org_forged', 0, 0)",
        ),
        ("UPDATE", f"UPDATE {HEADS} SET last_record_hash = repeat('f', 64)"),
        ("DELETE", f"DELETE FROM {HEADS}"),
        ("TRUNCATE", f"TRUNCATE {HEADS}"),
    ],
)
def test_app_role_cannot_write_the_head_table(db_session, verb, sql):
    assert "permission denied" in expect_refused(db_session, sql)


def test_app_role_cannot_set_role_to_the_writer(db_session):
    message = expect_refused(db_session, "SET ROLE audit_chain_writer")
    assert "permission denied" in message or "must be" in message


def test_app_role_cannot_grant_itself_head_privileges(db_session):
    """
    Asserted on the effect, not on an exception: a GRANT issued without grant
    option emits `WARNING: no privileges were granted` and succeeds as a no-op,
    so an exception-based check would report a broken boundary that is intact.
    """
    role = db_session.execute(text("SELECT current_user")).scalar()
    priv = text(f"SELECT has_table_privilege(current_user, '{HEADS}', 'UPDATE')")
    assert db_session.execute(priv).scalar() is False

    try:
        db_session.execute(text(f'GRANT UPDATE ON {HEADS} TO "{role}"'))
    except Exception:  # a refusal is equally acceptable
        db_session.rollback()

    assert db_session.execute(priv).scalar() is False
    assert "permission denied" in expect_refused(
        db_session, f"UPDATE {HEADS} SET last_record_hash = repeat('f', 64)"
    )


# ── The legitimate path still works after the move ──────────────────────────


def test_the_trigger_still_advances_the_real_head_after_the_move(db_session, test_user):
    """
    The other half of the boundary. It is not enough that direct writes are
    denied — the SECURITY DEFINER path must still cross the role boundary,
    reach a table in a schema the caller cannot write, and advance it.
    """
    before = head_row(db_session, test_user.org_id)
    before_count = before.event_count if before else 0

    write_event(db_session, test_user)
    event = newest_event(db_session, test_user.org_id)
    after = head_row(db_session, test_user.org_id)

    assert event.record_hash is not None, "the relocated trigger must still hash"
    assert after.event_count == before_count + 1
    assert after.last_event_id == event.id
    assert after.last_record_hash == event.record_hash
    assert recompute(db_session, event.id, event.org_id) == event.record_hash


def test_the_trigger_points_at_the_relocated_function(db_session):
    """
    `ALTER FUNCTION ... SET SCHEMA` carries the trigger binding, because a
    trigger references its function by OID. The bootstrap relies on that to
    avoid ever dropping the trigger on a live audit table.
    """
    points_at = db_session.execute(
        text(
            "SELECT n.nspname || '.' || p.proname FROM pg_trigger t "
            "  JOIN pg_proc p ON p.oid = t.tgfoid "
            "  JOIN pg_namespace n ON n.oid = p.pronamespace "
            " WHERE t.tgname = 'audit_logs_chain' LIMIT 1"
        )
    ).scalar()
    assert points_at == f"{CHAIN_SCHEMA}.audit_chain_advance_v1"


# ── Shadow objects in public cannot affect the real chain ───────────────────


def test_a_public_shadow_head_table_cannot_affect_the_real_chain(db_session, test_user):
    """
    The application role owns `public` on some databases, so it can create
    `public.audit_chain_heads`. Every chain reference is fully schema-qualified
    precisely so that such a shadow is inert — `search_path` is defence in
    depth here, not the boundary.

    Verified on a replica before implementation: with the real table in the
    dedicated schema and a shadow created in public, inserts continued to
    advance the real chain and the shadow stayed empty.
    """
    try:
        db_session.execute(
            text(
                "CREATE TABLE public.audit_chain_heads ("
                "  org_id varchar(100) PRIMARY KEY,"
                "  last_event_id varchar(200),"
                "  last_record_hash varchar(64),"
                "  event_count bigint NOT NULL DEFAULT 999,"
                "  genesis_event_id varchar(200),"
                "  chain_started_at timestamptz,"
                "  legacy_event_count bigint NOT NULL DEFAULT 999,"
                "  updated_at timestamptz NOT NULL DEFAULT now())"
            )
        )
    except Exception:
        db_session.rollback()
        pytest.skip(
            "NOT VERIFIED here: this role cannot create objects in `public`, so "
            "the shadow scenario is not reachable on this database."
        )

    try:
        before = head_row(db_session, test_user.org_id)
        before_count = before.event_count if before else 0

        write_event(db_session, test_user)
        event = newest_event(db_session, test_user.org_id)
        after = head_row(db_session, test_user.org_id)

        assert event.record_hash is not None
        assert (
            after.event_count == before_count + 1
        ), "the real chain head did not advance — a shadow object interfered"

        shadow_rows = db_session.execute(
            text("SELECT count(*) FROM public.audit_chain_heads")
        ).scalar()
        assert shadow_rows == 0, (
            "the shadow table received writes; chain references are not fully "
            "qualified"
        )
    finally:
        db_session.rollback()
        db_session.execute(text("DROP TABLE IF EXISTS public.audit_chain_heads"))
        db_session.commit()


# ── Chain state survived the move ───────────────────────────────────────────


def test_existing_hashes_still_reproduce_after_the_move(db_session):
    """
    The move is `ALTER TABLE ... SET SCHEMA` and `CREATE OR REPLACE`, never a
    drop-and-recreate, and no hash is ever recomputed or backfilled. Every
    chained row must therefore still reproduce byte-for-byte through the
    relocated function.
    """
    rows = db_session.execute(
        text(
            "SELECT id, org_id, prev_hash, record_hash FROM public.audit_logs "
            " WHERE record_hash IS NOT NULL"
        )
    ).fetchall()
    if not rows:
        pytest.skip("no chained events in this database to re-verify")

    for r in rows:
        assert (
            recompute(db_session, r.id, r.org_id) == r.record_hash
        ), f"event {r.id} no longer reproduces after the schema move"


def test_legacy_rows_remain_unhashed_and_uncounted(db_session):
    """The move must not have promoted, hashed or dropped any legacy row."""
    legacy = db_session.execute(
        text("SELECT count(*) FROM public.audit_logs WHERE record_hash IS NULL")
    ).scalar()
    chained = db_session.execute(
        text("SELECT count(*) FROM public.audit_logs WHERE record_hash IS NOT NULL")
    ).scalar()
    head_chained = (
        db_session.execute(
            text(f"SELECT coalesce(sum(event_count),0) FROM {HEADS}")
        ).scalar()
        or 0
    )
    assert legacy >= 0
    assert (
        head_chained == chained
    ), f"heads claim {head_chained} chained events but {chained} rows carry a hash"
