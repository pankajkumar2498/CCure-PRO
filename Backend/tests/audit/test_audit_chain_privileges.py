"""
tests/audit/test_audit_chain_privileges.py
─────────────────────────────────────────────────────────────────────────────
Phase 4, decision 1: privilege-escalation regression tests for
`audit_chain_heads`.

Phase 3's append-only enforcement had a known soft spot, recorded honestly at
the time: `ccure_user` owns `audit_logs`, and an owner can re-`GRANT` to
itself, so a `REVOKE` was never a boundary. The chain head closes that for the
one table where it matters, by putting ownership somewhere the application role
cannot reach:

* `audit_chain_heads` and all five functions are owned by `audit_chain_writer`;
* the application role is granted **no membership** in that role, which closes
  the `SET ROLE` escape more firmly than `WITH SET FALSE` would;
* writes happen only inside a `SECURITY DEFINER` function with a pinned
  `search_path`.

These tests are what makes that a fact rather than an intention. They run as
the application role — the attacker being modelled is application code, or SQL
injection reaching a second statement, not a database superuser.
"""

import pytest
from audit_chain_support import require_chain
from sqlalchemy import text

pytestmark = pytest.mark.usefixtures("db_session")

APP_CALLABLE = (
    ("_audit_field_v1", "text"),
    ("audit_canonical_payload_v1", "public.audit_logs"),
    ("audit_record_hash_v1", "text, public.audit_logs"),
    ("audit_chain_advance_v1", ""),
)
DEFINER_FUNCS = (("audit_chain_advance_v1", ""), ("audit_chain_seed_legacy_v1", ""))
ALL_FUNCS = APP_CALLABLE + (("audit_chain_seed_legacy_v1", ""),)


@pytest.fixture(autouse=True)
def require_bootstrap(db_session):
    require_chain(db_session)


def _denied(db_session, sql: str) -> str:
    """
    Assert the database refuses `sql`, **without ever committing it**.

    The commit is the whole point of this rewrite. An earlier version ran
    `execute(...)` followed by `commit()` inside `pytest.raises`, so a statement
    that turned out to be *permitted* was committed before the assertion failed.
    That is catastrophic for a probe whose entire purpose is to attempt
    destructive DDL: `test_app_role_cannot_drop_the_canonical_functions`
    genuinely dropped `_audit_field_v1` from the test database and committed it,
    which then broke twenty-four unrelated tests because every hash computation
    depends on that function.

    A test that verifies "X is refused" must never be the thing that performs X.
    The rollback happens unconditionally, before any assertion is made.
    """
    allowed = False
    try:
        db_session.execute(text(sql))
        allowed = True
        message = "ALLOWED — the database permitted this statement"
    except Exception as exc:  # noqa: BLE001 - the message is the evidence
        message = str(exc)
    finally:
        # Unconditional, and before the assertion below. Nothing this helper
        # attempts is ever made durable.
        db_session.rollback()

    assert not allowed, f"{sql!r} was permitted; expected the database to refuse it"
    return message


# ── Direct writes to the head table ─────────────────────────────────────────


def test_app_role_cannot_insert_a_chain_head(db_session):
    message = _denied(
        db_session,
        "INSERT INTO audit_chain_heads (org_id, event_count, legacy_event_count) "
        "VALUES ('org_forged', 0, 0)",
    )
    assert "permission denied" in message


def test_app_role_cannot_update_a_chain_head(db_session):
    """
    The most valuable tamper available: rewriting the tip so a forged event
    appears to link correctly.
    """
    message = _denied(
        db_session,
        "UPDATE audit_chain_heads SET last_record_hash = repeat('f', 64)",
    )
    assert "permission denied" in message


def test_app_role_cannot_delete_a_chain_head(db_session):
    """Deleting the head would let the next insert start a fresh chain."""
    message = _denied(db_session, "DELETE FROM audit_chain_heads")
    assert "permission denied" in message


def test_app_role_cannot_truncate_the_head_table(db_session):
    message = _denied(db_session, "TRUNCATE audit_chain_heads")
    assert "permission denied" in message


def test_app_role_retains_select(db_session):
    """Read access is legitimate: the verifier and the API report chain state."""
    assert (
        db_session.execute(
            text(
                "SELECT has_table_privilege(current_user,'audit_chain_heads','SELECT')"
            )
        ).scalar()
        is True
    )


# ── The escalation paths ────────────────────────────────────────────────────


def test_app_role_cannot_grant_itself_write_access(db_session):
    """
    The phase-3 weakness, closed. `ccure_user` owns `audit_logs` and could
    always re-grant itself privileges there; it does not own
    `audit_chain_heads` and cannot.

    Asserted on the **effect**, not on an exception. PostgreSQL does not raise
    when a role without grant option issues a GRANT — it emits
    `WARNING: no privileges were granted` and the statement succeeds as a
    no-op. Measured here: `has_table_privilege` is False before and after, and
    the write is still refused. An exception-based assertion would report a
    broken boundary that is actually intact.
    """
    role = db_session.execute(text("SELECT current_user")).scalar()
    priv = text("SELECT has_table_privilege(current_user,'audit_chain_heads','UPDATE')")

    assert db_session.execute(priv).scalar() is False

    try:
        db_session.execute(text(f'GRANT UPDATE ON audit_chain_heads TO "{role}"'))
    except Exception:  # a refusal is an equally acceptable outcome
        db_session.rollback()

    assert (
        db_session.execute(priv).scalar() is False
    ), "the app role acquired UPDATE on the chain head table"
    message = _denied(
        db_session, "UPDATE audit_chain_heads SET last_record_hash = repeat('f', 64)"
    )
    assert "permission denied" in message


def test_app_role_is_not_a_member_of_the_writer_role(db_session):
    """Membership would make every other control here decorative."""
    assert (
        db_session.execute(
            text("SELECT pg_has_role(current_user, 'audit_chain_writer', 'MEMBER')")
        ).scalar()
        is False
    )


def test_app_role_cannot_set_role_to_the_writer(db_session):
    message = _denied(db_session, "SET ROLE audit_chain_writer")
    assert "permission denied" in message or "must be" in message


def test_app_role_cannot_take_ownership_of_the_head_table(db_session):
    role = db_session.execute(text("SELECT current_user")).scalar()
    message = _denied(db_session, f'ALTER TABLE audit_chain_heads OWNER TO "{role}"')
    assert "must be" in message or "permission denied" in message


def test_app_role_cannot_redefine_the_canonical_algorithm(db_session):
    """
    If it could, it could make any forged row verify. The functions are owned
    by `audit_chain_writer`, and `CREATE OR REPLACE` requires ownership.
    """
    message = _denied(
        db_session,
        "CREATE OR REPLACE FUNCTION public._audit_field_v1(v text) RETURNS text "
        "LANGUAGE sql IMMUTABLE AS $$ SELECT 'x' $$",
    )
    assert "must be owner" in message or "permission denied" in message


def test_app_role_cannot_drop_the_canonical_functions(db_session):
    """
    Ownership of the functions is not sufficient on its own — **a schema owner
    may DROP any object in that schema, including objects owned by someone
    else.** So this property holds only where the application role does not own
    the schema the chain objects live in.

    Measured on this cluster, same roles, same script:

        ccure_test       public owned by pg_database_owner
                         -> DROP FUNCTION ... = must be owner   (protected)
        ccure_pytest_db  public owned by ccure_user
                         -> DROP FUNCTION ... = ALLOWED         (not protected)

    Where the precondition does not hold this **skips and is reported as NOT
    VERIFIED**, rather than failing forever or — as an earlier version did —
    actually performing the drop. It is a property of the deployment, not a
    defect in the chain: hashes are still computed and verified, and tampering
    with existing rows is still detected. What is absent is protection against
    the application role removing the machinery outright.
    """
    schema_owner = db_session.execute(
        text("SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname='public'")
    ).scalar()
    app_role = db_session.execute(text("SELECT current_user")).scalar()

    if schema_owner == app_role:
        pytest.skip(
            f"NOT VERIFIED on this database: schema public is owned by the "
            f"application role ({app_role}), and a schema owner can drop objects "
            f"it does not own. Verified on ccure_test, where public is owned by "
            f"pg_database_owner. See scripts/audit/bootstrap_chain.sql, which "
            f"warns about exactly this at install time."
        )

    message = _denied(db_session, "DROP FUNCTION public._audit_field_v1(text)")
    assert "must be owner" in message or "permission denied" in message


# ── Object configuration ────────────────────────────────────────────────────


def test_the_head_table_is_owned_by_the_writer_role(db_session):
    owner = db_session.execute(
        text(
            "SELECT pg_get_userbyid(relowner) FROM pg_class "
            "WHERE oid = 'public.audit_chain_heads'::regclass"
        )
    ).scalar()
    assert owner == "audit_chain_writer"


@pytest.mark.parametrize("fname,args", ALL_FUNCS)
def test_every_chain_function_is_owned_by_the_writer_role(db_session, fname, args):
    owner = db_session.execute(
        text(
            "SELECT pg_get_userbyid(proowner) FROM pg_proc "
            "WHERE oid = CAST(:s AS regprocedure)"
        ),
        {"s": f"public.{fname}({args})"},
    ).scalar()
    assert owner == "audit_chain_writer"


@pytest.mark.parametrize("fname,args", ALL_FUNCS)
def test_every_chain_function_pins_its_search_path(db_session, fname, args):
    """
    The standard `SECURITY DEFINER` hijack is shadowing a table or operator
    name via `search_path`. Pinned on the pure functions too, so a caller
    cannot change what `_audit_field_v1` resolves to mid-verification.
    """
    cfg = (
        db_session.execute(
            text(
                "SELECT array_to_string(proconfig, ',') FROM pg_proc "
                "WHERE oid = CAST(:s AS regprocedure)"
            ),
            {"s": f"public.{fname}({args})"},
        ).scalar()
        or ""
    )
    assert "search_path=pg_catalog, public" in cfg.replace('"', "")


@pytest.mark.parametrize("fname,args", DEFINER_FUNCS)
def test_the_writing_functions_are_security_definer(db_session, fname, args):
    assert (
        db_session.execute(
            text("SELECT prosecdef FROM pg_proc WHERE oid = CAST(:s AS regprocedure)"),
            {"s": f"public.{fname}({args})"},
        ).scalar()
        is True
    )


@pytest.mark.parametrize(
    "fname,args",
    (("_audit_field_v1", "text"), ("audit_record_hash_v1", "text, public.audit_logs")),
)
def test_the_pure_functions_are_not_security_definer(db_session, fname, args):
    """
    They need no privileges, so granting them the owner's would be an
    unnecessary escalation surface.
    """
    assert (
        db_session.execute(
            text("SELECT prosecdef FROM pg_proc WHERE oid = CAST(:s AS regprocedure)"),
            {"s": f"public.{fname}({args})"},
        ).scalar()
        is False
    )


def test_the_chain_trigger_function_pins_a_lock_timeout(db_session):
    """
    Without it, a second session writing an audit event for an organisation
    whose head is locked by the request's own transaction waits forever. The
    pattern is prohibited in `core/audit.py`; this is what makes a violation
    fail loudly instead of hanging.
    """
    cfg = db_session.execute(
        text(
            "SELECT array_to_string(proconfig, ',') FROM pg_proc "
            "WHERE oid = 'public.audit_chain_advance_v1()'::regprocedure"
        )
    ).scalar()
    assert "lock_timeout=3s" in (cfg or "")


@pytest.mark.parametrize("fname,args", ALL_FUNCS)
def test_public_cannot_execute_any_chain_function(db_session, fname, args):
    """
    PostgreSQL grants EXECUTE to PUBLIC on every new function by default, so
    the bootstrap's REVOKEs are required rather than defensive.
    """
    assert (
        db_session.execute(
            text("SELECT has_function_privilege('public', :s, 'EXECUTE')"),
            {"s": f"public.{fname}({args})"},
        ).scalar()
        is False
    )


@pytest.mark.parametrize("fname,args", APP_CALLABLE)
def test_the_app_role_can_execute_what_it_legitimately_needs(db_session, fname, args):
    assert (
        db_session.execute(
            text("SELECT has_function_privilege(current_user, :s, 'EXECUTE')"),
            {"s": f"public.{fname}({args})"},
        ).scalar()
        is True
    )


def test_the_app_role_cannot_execute_the_legacy_seeder(db_session):
    """A bootstrap-only entry point. It writes head rows, so it stays out of
    reach of application code."""
    assert (
        db_session.execute(
            text(
                "SELECT has_function_privilege(current_user, "
                "'public.audit_chain_seed_legacy_v1()', 'EXECUTE')"
            )
        ).scalar()
        is False
    )


# ── The legitimate path still works ─────────────────────────────────────────


def test_the_trigger_writes_the_head_the_app_role_cannot(db_session, test_user):
    """
    The other half of the boundary. It is not enough that direct writes are
    denied — the `SECURITY DEFINER` path must still cross the role boundary and
    advance the head, or the chain simply would not work.
    """
    from audit_chain_support import head_row, newest_event, write_event

    before = head_row(db_session, test_user.org_id)
    before_count = before.event_count if before else 0

    write_event(db_session, test_user)

    event = newest_event(db_session, test_user.org_id)
    after = head_row(db_session, test_user.org_id)

    assert event.record_hash is not None, "the trigger must have hashed the row"
    assert after.event_count == before_count + 1
    assert after.last_event_id == event.id
    assert after.last_record_hash == event.record_hash
