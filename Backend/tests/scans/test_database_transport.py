"""
tests/scans/test_database_transport.py
─────────────────────────────────────────────────────────────────────────────
The database transport — read-only enforcement, result semantics, and the four
error types. Phase 7 (GAP-10).

Nothing here needs a live database. The transport's job is to preserve
distinctions, and every distinction it preserves can be exercised against a
constructed exception or a constructed result. What *does* need a live database
— that the SQL in the rules is valid for each engine, and that a hardened
instance produces no findings — was done against disposable containers and is
recorded in the tracker, not asserted here.

Why the classification tests matter more than they look
───────────────────────────────────────────────────────
A refused password, an unprivileged account, nothing listening and a driver
that is not installed send whoever reads the scan to four different places.
Every one of these tests exists because collapsing two of them produces a
scanner that is confidently wrong about *why* it could not assess something —
and the phase found exactly that twice: a failed statement on a healthy session
reported as an unreachable database, and PostgreSQL's pg_hba refusal reported
as a connection failure.
"""

import pytest

from engines.credentialed.database_executor import (
    DEFAULT_PORTS,
    SUPPORTED_ENGINES,
    DatabaseAuthenticationError,
    DatabaseConfigurationError,
    DatabaseConnectionError,
    DatabaseError,
    DatabasePermissionError,
    DatabaseSession,
    QueryResult,
    assert_read_only,
    available_engines,
    normalize_engine,
)


def _session(engine="postgresql"):
    return DatabaseSession(
        engine=engine, host="10.0.0.1", username="scanner", password="pw"
    )


# ── Engine naming ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "spelling,expected",
    [
        ("postgresql", "postgresql"),
        ("PostgreSQL", "postgresql"),
        ("postgres", "postgresql"),
        ("mysql", "mysql"),
        ("MariaDB", "mysql"),
        ("mssql", "mssql"),
        ("SQL Server", "mssql"),
        ("sql-server", "mssql"),
        ("oracle", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_engine_spellings_fold_onto_one_name(spelling, expected):
    assert normalize_engine(spelling) == expected


def test_every_supported_engine_has_a_default_port():
    assert set(SUPPORTED_ENGINES) <= set(DEFAULT_PORTS)


def test_unknown_engine_is_a_configuration_error_not_a_connection_error():
    """
    "We cannot make the attempt" and "we made it and nothing answered" send a
    reader to different places. An engine nothing implements is the first.
    """
    with pytest.raises(DatabaseConfigurationError):
        DatabaseSession(engine="db2", host="h", username="u")


def test_available_engines_reports_every_supported_engine():
    reported = available_engines()
    assert set(reported) == set(SUPPORTED_ENGINES)
    assert all(isinstance(v, bool) for v in reported.values())


# ── Read-only enforcement ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT 1",
        "select setting from pg_settings where name = 'ssl'",
        "SHOW VARIABLES LIKE 'local_infile'",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "VALUES (1)",
        "SELECT 1;",
        # A literal containing a write keyword is data, not a statement.
        "SELECT name FROM t WHERE name = 'delete'",
        "SELECT name FROM t WHERE name = 'drop table users'",
        # A comment containing one is likewise not a statement.
        "SELECT 1 -- ; DROP TABLE users",
        "SELECT 1 /* update everything */",
        # Column names that merely contain a keyword must not trip the guard,
        # or half the PostgreSQL catalogue becomes unreadable.
        "SELECT rolcreatedb, rolcreaterole FROM pg_roles",
        "SELECT * FROM information_schema.table_privileges",
    ],
)
def test_read_only_statements_are_allowed(statement):
    # A plain call, not a comparison: the guard signals refusal by raising, so
    # `assert_read_only(...) is None` would be a pointless expression that
    # passes whether or not the guard did anything.
    assert_read_only(statement)


@pytest.mark.parametrize(
    "statement",
    [
        "DROP TABLE users",
        "UPDATE pg_authid SET rolsuper = true",
        "DELETE FROM mysql.user",
        "INSERT INTO t VALUES (1)",
        "ALTER LOGIN sa ENABLE",
        "CREATE USER attacker",
        "GRANT ALL ON *.* TO 'x'@'%'",
        "TRUNCATE TABLE audit_logs",
        "EXEC xp_cmdshell 'whoami'",
        "CALL some_procedure()",
        "COMMIT",
        "SELECT * INTO other FROM t",
        # Two statements: the classic way a read becomes a write.
        "SELECT 1; DROP TABLE users",
        "SHOW ssl; DELETE FROM t",
        "",
        "   ",
    ],
)
def test_write_statements_are_refused(statement):
    with pytest.raises(DatabaseConfigurationError):
        assert_read_only(statement)


def test_refusal_names_the_reason():
    """
    The message reaches a rule author through the collector's UNAVAILABLE
    detail, so it has to say which rule of the guard was broken.
    """
    with pytest.raises(DatabaseConfigurationError) as exc:
        assert_read_only("DROP TABLE t")
    assert "drop" in str(exc.value).lower()

    with pytest.raises(DatabaseConfigurationError) as exc:
        assert_read_only("SELECT 1; SELECT 2")
    assert "more than one" in str(exc.value).lower()


def test_query_refuses_a_write_without_a_session():
    """
    A statement that fails the guard is refused before any connection is used,
    and comes back as a transport error rather than raising — one bad rule must
    not abort the audit of every other check.
    """
    session = _session()
    result = session.query("DROP TABLE users")
    assert result.ok is False
    assert result.transport_error


# ── QueryResult semantics ────────────────────────────────────────────────────


def test_empty_result_is_not_a_failure():
    """
    The single most dangerous confusion in this module: a compliant instance
    answers "which accounts have an empty password" with no rows at all, and a
    refused query answers identically. Only ``ok`` tells them apart.
    """
    clean = QueryResult(statement="SELECT 1", rows=[], ok=True)
    refused = QueryResult(statement="SELECT 1", rows=[], error="permission denied")

    assert clean.ok is True
    assert clean.row_count == 0
    assert refused.ok is False
    assert refused.row_count == 0
    assert clean.rows == refused.rows


def test_scalar_returns_none_for_no_row():
    assert QueryResult(statement="s", rows=[], ok=True).scalar() is None
    assert QueryResult(statement="s", rows=[("on",)], ok=True).scalar() == "on"


def test_rendered_rows_is_capped_and_says_so():
    rows = [(f"account{i}",) for i in range(60)]
    rendered = QueryResult(statement="s", rows=rows, ok=True).rendered_rows(limit=10)
    assert len(rendered) == 11
    assert "50 more" in rendered[-1]


def test_failure_detail_distinguishes_transport_from_statement():
    transport = QueryResult(statement="s", transport_error="socket closed")
    statement = QueryResult(statement="s", error="relation does not exist")
    assert "could not be executed" in transport.failure_detail()
    assert "statement failed" in statement.failure_detail()


# ── Error classification ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "message",
    [
        'password authentication failed for user "scanner"',
        "Access denied for user 'root'@'10.0.0.9' (using password: YES)",
        "Login failed for user 'sa'.",
        # PostgreSQL's refusal when no pg_hba line matches. The instance
        # answered and declined; classifying it as a connection error sent a
        # reader to the firewall for a server that was listening.
        'no pg_hba.conf entry for host "10.0.0.9", user "scanner"',
    ],
)
def test_credential_refusals_classify_as_authentication(message):
    assert isinstance(
        _session()._classify(Exception(message)), DatabaseAuthenticationError
    )


@pytest.mark.parametrize(
    "message",
    [
        "permission denied for table pg_authid",
        "must be superuser to read this setting",
        "SELECT command denied to user 'scan'@'%' for table 'user'",
        "The server principal is not able to access the database",
    ],
)
def test_privilege_refusals_classify_as_permission(message):
    assert isinstance(_session()._classify(Exception(message)), DatabasePermissionError)


@pytest.mark.parametrize(
    "message",
    [
        "could not connect to server: Connection refused",
        "connection timed out",
        "Can't connect to MySQL server on '10.0.0.1'",
        "No route to host",
    ],
)
def test_unreachable_classifies_as_connection(message):
    assert isinstance(_session()._classify(Exception(message)), DatabaseConnectionError)


def test_tls_problems_classify_as_configuration():
    classified = _session()._classify(Exception("SSL error: certificate verify failed"))
    assert isinstance(classified, DatabaseConfigurationError)


def test_unrecognised_failure_depends_on_whether_a_session_exists():
    """
    The asymmetry that a real target exposed.

    On connect, an unrecognised failure stopped us reaching the instance, so a
    connection error is honest. On an *open* session it is the server rejecting
    one statement — a catalogue view this version does not have — and says
    nothing about reachability. Reporting that as a connection error claims a
    database is unreachable while holding a connection to it.
    """
    session = _session()
    unknown = Exception('relation "pg_catalog.no_such_view" does not exist')

    on_connect = session._classify(unknown, context="connect")
    on_query = session._classify(unknown, context="query")

    assert isinstance(on_connect, DatabaseConnectionError)
    assert isinstance(on_query, DatabaseError)
    assert not isinstance(on_query, DatabaseConnectionError)


def test_a_classified_error_is_never_reclassified():
    original = DatabasePermissionError("permission denied")
    assert _session()._classify(original) is original


# ── Product naming (engine targeting) ────────────────────────────────────────


@pytest.mark.parametrize(
    "engine,banner,expected_contains",
    [
        # MySQL answers SELECT version() with a bare number, so the engine name
        # has to be supplied. Without this every MySQL rule was NOT_APPLICABLE
        # and the whole rule set silently never ran.
        ("mysql", "8.0.46", "mysql"),
        ("postgresql", "PostgreSQL 16.15 on x86_64", "postgresql"),
        ("mssql", "Microsoft SQL Server 2022 (RTM)", "microsoft sql server"),
        # MariaDB must not be labelled MySQL: its version series is its own, and
        # a "MySQL 8.0 or later" rule would read 10.11 as ancient.
        ("mysql", "10.11.6-MariaDB", "mariadb"),
    ],
)
def test_product_name_always_identifies_the_engine(engine, banner, expected_contains):
    session = _session(engine)
    session._server_banner = banner
    assert expected_contains in session.product_name.lower()


def test_mariadb_is_not_reported_as_mysql():
    session = _session("mysql")
    session._server_banner = "10.11.6-MariaDB-1:10.11.6+maria~ubu2204"
    assert "mysql" not in session.product_name.lower()


def test_product_name_does_not_duplicate_an_engine_the_banner_already_names():
    session = _session("postgresql")
    session._server_banner = "PostgreSQL 16.15 on x86_64"
    assert session.product_name.lower().count("postgresql") == 1


# ── libpq environment isolation ──────────────────────────────────────────────


def test_postgresql_connection_clears_the_inherited_root_certificate(monkeypatch):
    """
    ``Backend/.env`` sets PGSSLROOTCERT to this deployment's private CA for the
    *application* database, and loading config puts it in the environment.
    libpq applies it to any connection that does not set it — so every
    PostgreSQL *target* was verified against our own CA and failed with
    "certificate verify failed", which reads as a fault on the target.

    Passing ``sslmode`` explicitly is not enough and that is what made it hard
    to find: the mode was correctly overridden, only the trust anchor was not.
    """
    captured = {}

    class _FakeConn:
        def set_session(self, **kwargs):
            captured["set_session"] = kwargs

    def _fake_connect(**kwargs):
        captured.update(kwargs)
        return _FakeConn()

    fake_psycopg2 = type("m", (), {"connect": staticmethod(_fake_connect)})
    fake_psycopg2.extensions = type("e", (), {})
    monkeypatch.setitem(__import__("sys").modules, "psycopg2", fake_psycopg2)
    monkeypatch.setitem(
        __import__("sys").modules, "psycopg2.extensions", fake_psycopg2.extensions
    )
    monkeypatch.setenv("PGSSLROOTCERT", "D:/PostgreSQL/18/data/root.crt")

    session = _session("postgresql")
    session._connect_postgresql()

    assert captured["sslrootcert"] == ""
    assert captured["sslmode"] == "prefer"
    assert captured["set_session"] == {"readonly": True, "autocommit": True}


def test_postgresql_verification_uses_the_credentials_own_ca(monkeypatch):
    captured = {}

    class _FakeConn:
        def set_session(self, **kwargs):
            pass

    def _fake_connect(**kwargs):
        captured.update(kwargs)
        return _FakeConn()

    fake_psycopg2 = type("m", (), {"connect": staticmethod(_fake_connect)})
    fake_psycopg2.extensions = type("e", (), {})
    monkeypatch.setitem(__import__("sys").modules, "psycopg2", fake_psycopg2)
    monkeypatch.setitem(
        __import__("sys").modules, "psycopg2.extensions", fake_psycopg2.extensions
    )

    session = DatabaseSession(
        engine="postgresql",
        host="10.0.0.1",
        username="u",
        password="p",
        verify_cert=True,
        ca_cert="/etc/ccure/customer-ca.pem",
    )
    session._connect_postgresql()

    assert captured["sslmode"] == "verify-full"
    assert captured["sslrootcert"] == "/etc/ccure/customer-ca.pem"


# ── Session state ────────────────────────────────────────────────────────────


def test_query_without_a_session_is_a_transport_error_not_an_exception():
    result = _session().query("SELECT 1")
    assert result.ok is False
    assert "no authenticated session" in result.transport_error


def test_tls_in_use_is_none_before_anything_established_it():
    """
    None is not False. "We could not tell whether this session is encrypted"
    and "this session is plaintext" are different facts and only one of them
    is a finding.
    """
    assert _session().tls_in_use is None
