"""DBA-only historical fixtures, confined to the suite's vetted scratch database.

AUDIT_HISTORY_DBA_URL is a separate disposable-DB credential. It never changes
the application role's grants. No fixture edits a hash or fabricates a counter.
"""

from contextlib import contextmanager
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from testpaths import SCRIPTS_DIR


def validate_historical_target(application_url, dba_url):
    from conftest import _is_test_database

    target = make_url(dba_url)
    app = make_url(application_url)
    assert target.drivername in ("postgresql", "postgresql+psycopg2")
    assert not target.query, "historical DBA URL cannot override connection parameters"
    assert _is_test_database(
        str(target)
    ), "historical bootstrap requires a scratch name"
    assert (target.host, target.port, target.database) == (
        app.host,
        app.port,
        app.database,
    ), "historical bootstrap must target the already-vetted test database"
    assert (
        target.username != app.username
    ), "DBA and application credentials must differ"
    return target


@contextmanager
def historical_dba(session):
    raw = os.getenv("AUDIT_HISTORY_DBA_URL")
    if not raw:
        pytest.skip(
            "NOT VERIFIED: historical fixtures need AUDIT_HISTORY_DBA_URL for the "
            "same disposable database; never supply production credentials."
        )
    target = validate_historical_target(session.get_bind().url, raw)
    assert session.execute(
        text("SELECT to_regclass('public._pytest_scratch_marker')")
    ).scalar(), "historical bootstrap requires the scratch sentinel"
    app_role = session.execute(text("SELECT current_user")).scalar()
    app_identity = session.execute(
        text("SELECT current_database(), inet_server_addr()::text, inet_server_port()")
    ).one()
    assert not session.execute(
        text(
            "SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname=current_user"
        )
    ).scalar(), "historical verification must run as the restricted application role"
    assert not session.execute(
        text("SELECT pg_has_role(current_user, 'audit_chain_writer', 'MEMBER')")
    ).scalar(), "application role must not belong to the chain writer"
    assert not session.execute(
        text(
            "SELECT has_function_privilege(current_user, 'audit_chain.audit_chain_seed_legacy_v1()', 'EXECUTE')"
        )
    ).scalar(), "application role must not gain the privileged legacy seed"
    # Release application read/DDL locks before the independent DBA transaction.
    session.rollback()
    engine = create_engine(target)
    try:
        with engine.begin() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT current_database(), inet_server_addr()::text, inet_server_port()"
                    )
                ).one()
                == app_identity
            ), "DBA connection resolved to a different server"
            assert (
                conn.execute(text("SELECT current_database()")).scalar()
                == target.database
            )
            assert conn.execute(
                text("SELECT to_regclass('public._pytest_scratch_marker')")
            ).scalar(), "DBA target has no scratch sentinel"
            assert (
                conn.execute(
                    text(
                        "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.audit_logs'::regclass"
                    )
                ).scalar()
                == app_role
            ), "historical bootstrap cannot alter application ownership"
            yield conn
    finally:
        engine.dispose()


def relocate_and_bootstrap(conn):
    """Model the old public layout, then run the exact supported bootstrap SQL.

    The relocation and script share one transaction. No other connection sees
    the temporary layout, and any bootstrap guard failure restores the old state.
    """
    conn.execute(text("LOCK TABLE public.audit_logs IN ACCESS EXCLUSIVE MODE"))
    for signature in (
        "_audit_field_v1(text)",
        "audit_canonical_payload_v1(public.audit_logs)",
        "audit_record_hash_v1(text, public.audit_logs)",
        "audit_chain_advance_v1()",
        "audit_chain_seed_legacy_v1()",
    ):
        conn.execute(text(f"ALTER FUNCTION audit_chain.{signature} SET SCHEMA public"))
    conn.execute(text("ALTER TABLE audit_chain.audit_chain_heads SET SCHEMA public"))
    script = (SCRIPTS_DIR / "audit/bootstrap_chain.sql").read_text()
    # psycopg raises and aborts on the first SQL error, equivalent to this psql
    # client directive. Keep every SQL statement, including all security guards.
    script = script.replace("\\set ON_ERROR_STOP on\n", "")
    assert not any(line.startswith("\\") for line in script.splitlines())
    conn.execution_options(no_parameters=True).exec_driver_sql(script)


@pytest.fixture(name="authoritative_legacy")
def authoritative_legacy_fixture(db_session, test_user):
    from audit_chain_support import write_event
    from audit_retention_support import head_row, make_legacy_event

    org = test_user.org_id
    assert (
        head_row(db_session, org) is None
    ), "historical fixture needs a pre-chain tenant"
    old = [make_legacy_event(db_session, org, age_days=400) for _ in range(6)]
    recent = [make_legacy_event(db_session, org, age_days=10) for _ in range(2)]
    with historical_dba(db_session) as conn:
        # Same authoritative COUNT used by the real DBA bootstrap, INSERT only
        # for a tenant without a head. Never UPDATE a counter to a guessed value.
        conn.execute(text("SELECT audit_chain.audit_chain_seed_legacy_v1()"))
    head = head_row(db_session, org)
    assert head.legacy_event_count == len(old) + len(recent)
    assert head.event_count == 0 and head.genesis_event_id is None
    write_event(db_session, test_user)
    return {"org": org, "old": old, "recent": recent}
