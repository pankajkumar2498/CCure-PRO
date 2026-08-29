"""
core/config_audit/builtin/database_postgresql.py
─────────────────────────────────────────────────────────────────────────────
PostgreSQL configuration and privilege checks. Phase 7 (GAP-10).

Every statement here was run against a live PostgreSQL 16 instance before the
rule was written, and several rules exist in the shape they do *because* of
what that showed. Three that would otherwise have shipped looking correct:

* **``public`` holding CONNECT on ``postgres`` and ``template0`` is the stock
  default** on every PostgreSQL installation. A rule reporting it would raise a
  finding on every instance this product ever scans. Not promoted.
* **``trust`` on ``local`` and on ``127.0.0.1`` is the postgres image default**
  and is how ``docker exec psql`` works at all. The rule is scoped to
  non-loopback addresses, where ``trust`` really does mean "any client that can
  reach the port is a superuser".
* **Three separate rules initially read ``pg_hba_file_rules``** with
  overlapping predicates, so one permissive line produced three findings and
  made the remediation look three times larger than it was. They are now
  orthogonal: one asks whether plaintext is accepted, one asks what the server
  binds to, and the third was dropped.

The credential this needs, and what happens without it
──────────────────────────────────────────────────────
``pg_authid`` and ``pg_hba_file_rules`` are superuser-only. With an
unprivileged credential those reads return "permission denied", which the
collector reports as UNAVAILABLE and the engine reports as ERROR — never as a
pass, and never as "no offending accounts". Measured on a real instance: the
superuser-only reads degrade to ERROR while ``pg_settings`` and ``pg_roles``
still answer, so a low-privilege scan produces a partial audit that says which
parts it could not perform. That is the correct behaviour and it is what
``requires_credentials`` plus the four collection states buy.

Version boundary
────────────────
``db.conf.version_supported`` compares against PostgreSQL 14, which is the
oldest release still receiving fixes under the PostgreSQL Global Development
Group's five-year policy **as at 29 August 2026** (13 reached end of life on
13 November 2025). That date is stated in the rule so a reader can tell how
stale the boundary is; it is a published fact with a shelf life, not a
judgement.
"""

from __future__ import annotations

import re
from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["POSTGRESQL_CHECKS", "postgresql_checks"]

_PG = ("postgresql",)
_DOC = "https://www.postgresql.org/docs/current/runtime-config-logging.html"
_HBA_DOC = "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"
_SSL_DOC = "https://www.postgresql.org/docs/current/ssl-tcp.html"
_ROLE_DOC = "https://www.postgresql.org/docs/current/predefined-roles.html"


#: Read a single server setting. ``pg_settings`` is readable by any role, which
#: is why the settings-based rules survive an unprivileged credential while the
#: catalogue-based ones do not.
def _setting(name: str) -> str:
    # The setting name is interpolated rather than bound because these are
    # module-level literals composed once at import, not runtime input — but
    # the identifier is validated anyway. This helper is exactly the shape that
    # becomes an injection point the first time somebody makes rules editable,
    # and a guard that costs one line now is cheaper than finding out later.
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
        raise ValueError(f"not a PostgreSQL setting identifier: {name!r}")
    # Interpolation is safe here because of the line above: the name has been
    # proven to be a bare identifier before it reaches the statement.
    return f"SELECT setting FROM pg_settings WHERE name = '{name}'"  # nosec B608


POSTGRESQL_CHECKS: List[ConfigCheck] = [
    # ── Authentication & accounts ────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.postgresql.empty_password",
        title="No PostgreSQL login role has an empty password",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT rolname FROM pg_authid "
                "WHERE rolcanlogin AND rolpassword IS NULL"
            ),
        },
        expect=Expectation("is_empty", description="no login role without a password"),
        # A search that returned nothing is a real result, unlike a missing
        # registry value — so absence is a pass, not a deferral. Same reasoning
        # as the Phase 5 privilege probes.
        absent=AbsencePolicy.PASS,
        description=(
            "Login roles whose password is unset. Such a role authenticates "
            "against any pg_hba rule that does not itself demand a password."
        ),
        rationale=(
            "A login role with no password is usable by anyone who can reach "
            "the port under a 'trust' rule, and cannot be used at all under a "
            "password rule — so it is either an open door or a broken account, "
            "and both warrant attention."
        ),
        remediation=(
            "ALTER ROLE <name> WITH PASSWORD '<value>'; for a role that should "
            "not log in, ALTER ROLE <name> WITH NOLOGIN."
        ),
        references=(_HBA_DOC,),
        tags=("database", "postgresql", "authentication"),
        metadata={"gap10_area": "db.auth.empty_password", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.password_encryption",
        title="PostgreSQL stores passwords with SCRAM rather than MD5",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "sql": _setting("password_encryption"),
        },
        expect=Expectation("equals", "scram-sha-256", description="scram-sha-256"),
        # The setting exists in every supported release, so its absence means
        # the read did not return what it should have — not a platform default.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=("The algorithm new and changed passwords are stored under."),
        rationale=(
            "MD5 password verifiers are unsalted against the username only and "
            "are replayable: the stored hash is password-equivalent, so a read "
            "of pg_authid is enough to authenticate as the role."
        ),
        remediation=(
            "Set password_encryption = 'scram-sha-256', reload, then reset "
            "each role's password so the stored verifier is re-derived — "
            "changing the setting alone does not re-encode existing passwords."
        ),
        references=("https://www.postgresql.org/docs/current/auth-password.html",),
        tags=("database", "postgresql", "authentication"),
        metadata={
            "gap10_area": "db.auth.weak_auth_method",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.md5_roles",
        title="No PostgreSQL role still holds an MD5 password verifier",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT rolname FROM pg_authid "
                "WHERE rolcanlogin AND rolpassword LIKE 'md5%'"
            ),
        },
        expect=Expectation("is_empty", description="no role on an MD5 verifier"),
        absent=AbsencePolicy.PASS,
        description=(
            "Roles whose stored verifier is still MD5 after the server was "
            "switched to SCRAM."
        ),
        rationale=(
            "Changing password_encryption does not re-encode existing "
            "passwords. A server reporting scram-sha-256 can still hold MD5 "
            "verifiers for every role created before the change, which is why "
            "this is checked separately from the setting."
        ),
        remediation=(
            "Reset the password for each listed role so the verifier is "
            "re-derived under SCRAM."
        ),
        references=("https://www.postgresql.org/docs/current/auth-password.html",),
        tags=("database", "postgresql", "authentication"),
        metadata={
            "gap10_area": "db.auth.weak_auth_method",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.trust_authentication",
        title="PostgreSQL does not accept unauthenticated remote connections",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT type || ' ' || COALESCE(address, '') || ' ' || "
                "auth_method FROM pg_hba_file_rules "
                "WHERE auth_method IN ('trust', 'password') "
                "AND type <> 'local' "
                "AND COALESCE(address, '') NOT IN "
                "('127.0.0.1', '::1', 'samehost', 'localhost')"
            ),
        },
        expect=Expectation(
            "is_empty", description="no remote trust or cleartext-password rule"
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "pg_hba.conf rules that accept a remote client with no password "
            "('trust') or with a password sent in the clear ('password')."
        ),
        rationale=(
            "A remote 'trust' rule makes every client that can reach the port "
            "a superuser without presenting anything. 'password' authenticates "
            "but transmits the secret unprotected unless the connection is "
            "already encrypted."
        ),
        remediation=(
            "Replace remote 'trust' and 'password' rules in pg_hba.conf with "
            "'scram-sha-256', restrict the address range, and reload the "
            "server."
        ),
        references=(_HBA_DOC,),
        tags=("database", "postgresql", "authentication"),
        metadata={
            "gap10_area": "db.auth.superuser_remote",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.log_connections",
        title="PostgreSQL records authentication attempts",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("log_connections")},
        expect=Expectation("is_true", description="on"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Whether each connection attempt is written to the log.",
        rationale=(
            "Without it there is no record of who authenticated, from where, "
            "or of a failed attempt — so neither a brute-force attempt nor the "
            "successful login that followed it leaves a trace."
        ),
        remediation="Set log_connections = on and reload the server.",
        references=(_DOC,),
        tags=("database", "postgresql", "audit"),
        metadata={"gap10_area": "db.auth.login_auditing", "db_engine": "postgresql"},
    ),
    # ── Privileges, roles & grants ───────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.postgresql.superuser_roles",
        title="PostgreSQL superuser is limited to the bootstrap role",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT rolname FROM pg_roles "
                "WHERE rolsuper AND rolcanlogin AND rolname <> 'postgres'"
            ),
        },
        expect=Expectation(
            "is_empty", description="no login superuser besides postgres"
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "Roles that can log in and hold the superuser attribute, other "
            "than the bootstrap role the cluster was initialised with."
        ),
        rationale=(
            "A superuser bypasses every permission check, can read and write "
            "any file the server account can reach, and can execute code on "
            "the host through an untrusted procedural language. Each one is a "
            "full compromise of the instance and, usually, of its host."
        ),
        remediation=(
            "ALTER ROLE <name> NOSUPERUSER and grant the specific predefined "
            "role the account actually needs (pg_read_all_data, "
            "pg_monitor, pg_signal_backend)."
        ),
        references=(_ROLE_DOC,),
        tags=("database", "postgresql", "privilege"),
        metadata={"gap10_area": "db.priv.superusers", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.filesystem_roles",
        title="No PostgreSQL role holds server filesystem or program privileges",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT m.rolname || ' in ' || r.rolname "
                "FROM pg_auth_members am "
                "JOIN pg_roles r ON r.oid = am.roleid "
                "JOIN pg_roles m ON m.oid = am.member "
                "WHERE r.rolname IN ('pg_read_server_files', "
                "'pg_write_server_files', 'pg_execute_server_program')"
            ),
        },
        expect=Expectation("is_empty", description="no member of the filesystem roles"),
        absent=AbsencePolicy.PASS,
        description=(
            "Membership of pg_read_server_files, pg_write_server_files and "
            "pg_execute_server_program."
        ),
        rationale=(
            "These grant a non-superuser the ability to read any file the "
            "server account can read, write files it can write, and — for "
            "pg_execute_server_program — run commands on the host as the "
            "postgres operating-system user. Each is a route from a database "
            "login to the host."
        ),
        remediation=(
            "REVOKE the predefined role from the listed members and use "
            "COPY ... FROM STDIN through the client instead of server-side "
            "file access."
        ),
        references=(_ROLE_DOC,),
        tags=("database", "postgresql", "privilege"),
        metadata={
            "gap10_area": "db.priv.filesystem_access",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.untrusted_languages",
        title="PostgreSQL has no untrusted procedural language installed",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT lanname FROM pg_language " "WHERE lanispl AND NOT lanpltrusted"
            ),
        },
        expect=Expectation("is_empty", description="no untrusted procedural language"),
        absent=AbsencePolicy.PASS,
        description=(
            "Untrusted procedural languages (plpythonu, plperlu, plsh and "
            "similar) installed in the current database."
        ),
        rationale=(
            "An untrusted language runs without the sandbox a trusted one "
            "imposes, so a function written in it executes arbitrary code as "
            "the operating-system account the server runs under."
        ),
        remediation=(
            "DROP EXTENSION for any untrusted language that is not required. "
            "Where one is required, restrict CREATE FUNCTION on it and treat "
            "every function written in it as server-side code."
        ),
        references=("https://www.postgresql.org/docs/current/xplang.html",),
        tags=("database", "postgresql", "privilege"),
        metadata={
            "gap10_area": "db.priv.dangerous_features",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.public_schema_create",
        title="PUBLIC cannot create objects in a PostgreSQL schema",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT nspname FROM pg_namespace "
                "WHERE has_schema_privilege('public', nspname, 'CREATE') "
                "AND nspname NOT LIKE 'pg\\_%' "
                "AND nspname <> 'information_schema'"
            ),
        },
        expect=Expectation("is_empty", description="no schema where PUBLIC may create"),
        absent=AbsencePolicy.PASS,
        description=("Schemas in which the PUBLIC pseudo-role may create objects."),
        rationale=(
            "Any role that can connect can then create functions and tables in "
            "such a schema. Where that schema is early on search_path, an "
            "attacker-created function can shadow a built-in and be executed "
            "by another user — the classic search_path hijack."
        ),
        remediation=(
            "REVOKE CREATE ON SCHEMA <name> FROM PUBLIC and grant it to the "
            "roles that genuinely need it. PostgreSQL 15 and later do this for "
            "the public schema by default."
        ),
        references=("https://www.postgresql.org/docs/current/ddl-schemas.html",),
        tags=("database", "postgresql", "privilege"),
        metadata={"gap10_area": "db.priv.schema_create", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.public_table_grants",
        title="PUBLIC holds no privileges on user tables in PostgreSQL",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT table_schema || '.' || table_name || ' ' || "
                "privilege_type FROM information_schema.table_privileges "
                "WHERE grantee = 'PUBLIC' AND table_schema NOT IN "
                "('pg_catalog', 'information_schema')"
            ),
        },
        expect=Expectation("is_empty", description="no PUBLIC grant on user data"),
        absent=AbsencePolicy.PASS,
        description=(
            "Privileges granted to PUBLIC on tables outside the system " "catalogues."
        ),
        rationale=(
            "PUBLIC is every current and future role. A grant to it cannot be "
            "reasoned about from the role list, and it survives the creation "
            "of accounts nobody has thought about yet."
        ),
        remediation=(
            "REVOKE the listed privileges FROM PUBLIC and grant them to named " "roles."
        ),
        references=("https://www.postgresql.org/docs/current/sql-grant.html",),
        tags=("database", "postgresql", "privilege"),
        metadata={"gap10_area": "db.priv.public_grants", "db_engine": "postgresql"},
    ),
    # ── Encryption & transport ───────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.postgresql.ssl_enabled",
        title="PostgreSQL offers TLS to clients",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("ssl")},
        expect=Expectation("is_true", description="on"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Whether the server was built and configured to accept TLS.",
        rationale=(
            "With ssl off, every session — including the authentication "
            "exchange and every row returned — crosses the network in the "
            "clear, and no client setting can change that."
        ),
        remediation=(
            "Install a server certificate and key, set ssl = on, and restart "
            "the server."
        ),
        references=(_SSL_DOC,),
        tags=("database", "postgresql", "encryption"),
        metadata={"gap10_area": "db.tls.enabled", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.ssl_required",
        title="PostgreSQL requires TLS for remote connections",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT type || ' ' || COALESCE(address, '') || ' ' || "
                "auth_method FROM pg_hba_file_rules "
                "WHERE type IN ('host', 'hostnossl') "
                "AND auth_method <> 'reject' "
                "AND COALESCE(address, '') NOT IN "
                "('127.0.0.1', '::1', 'samehost', 'localhost')"
            ),
        },
        expect=Expectation("is_empty", description="every remote rule is hostssl"),
        absent=AbsencePolicy.PASS,
        description=(
            "pg_hba.conf rules that admit a remote client over an unencrypted "
            "connection. 'host' matches both encrypted and unencrypted; only "
            "'hostssl' requires TLS."
        ),
        rationale=(
            "Enabling TLS makes it available, not mandatory. While a 'host' "
            "rule matches a remote address, a client that simply does not ask "
            "for TLS is still admitted, and the server-side setting gives no "
            "indication that this is happening."
        ),
        remediation=(
            "Change remote 'host' rules to 'hostssl' in pg_hba.conf, keeping "
            "loopback entries as they are, and reload the server."
        ),
        references=(_HBA_DOC,),
        tags=("database", "postgresql", "encryption"),
        metadata={"gap10_area": "db.tls.enforced", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.ssl_min_version",
        title="PostgreSQL refuses TLS below 1.2",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "sql": _setting("ssl_min_protocol_version"),
        },
        expect=Expectation(
            "in", ["tlsv1.2", "tlsv1.3"], description="TLSv1.2 or TLSv1.3"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="The lowest TLS protocol version the server will negotiate.",
        rationale=(
            "TLS 1.0 and 1.1 are deprecated by RFC 8996 and permit cipher "
            "suites with known weaknesses. A server that still offers them "
            "will negotiate down for any client that asks."
        ),
        remediation="Set ssl_min_protocol_version = 'TLSv1.2' and reload.",
        references=(_SSL_DOC, "https://www.rfc-editor.org/rfc/rfc8996"),
        tags=("database", "postgresql", "encryption"),
        metadata={"gap10_area": "db.tls.min_version", "db_engine": "postgresql"},
    ),
    # ── Audit & logging ──────────────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.postgresql.log_statement",
        title="PostgreSQL logs schema and privilege changes",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("log_statement")},
        expect=Expectation("in", ["ddl", "mod", "all"], description="ddl, mod or all"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Which statement classes are written to the log. 'ddl' captures "
            "CREATE, ALTER, DROP, GRANT and REVOKE."
        ),
        rationale=(
            "At 'none' there is no record that a table was dropped or a "
            "privilege granted. An investigation into how an account acquired "
            "a right has nothing to read."
        ),
        remediation=(
            "Set log_statement = 'ddl' as a minimum and reload. 'mod' and "
            "'all' capture more at a proportionate cost in log volume."
        ),
        references=(_DOC,),
        tags=("database", "postgresql", "audit"),
        metadata={"gap10_area": "db.audit.enabled", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.log_disconnections",
        title="PostgreSQL records session end and duration",
        check_type="database_query",
        platforms=("database",),
        severity="low",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("log_disconnections")},
        expect=Expectation("is_true", description="on"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether session termination and duration are logged, which pairs "
            "with log_connections to bound a session in time."
        ),
        rationale=(
            "A connection record without a matching disconnection record "
            "cannot establish how long an account held a session, which is "
            "what correlating database activity with other evidence needs."
        ),
        remediation="Set log_disconnections = on and reload the server.",
        references=(_DOC,),
        tags=("database", "postgresql", "audit"),
        metadata={"gap10_area": "db.audit.connections", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.log_rotation",
        title="PostgreSQL rotates its log files",
        check_type="database_query",
        platforms=("database",),
        severity="low",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("log_rotation_age")},
        expect=Expectation("gt", 0, description="greater than 0 minutes"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="The age at which the server starts a new log file.",
        rationale=(
            "With rotation disabled the server writes to one file "
            "indefinitely. That file is eventually too large to read, and "
            "nothing bounds the disk it consumes."
        ),
        remediation=(
            "Set log_rotation_age (minutes) and log_rotation_size, and keep "
            "logging_collector on so the server manages the files."
        ),
        references=(_DOC,),
        tags=("database", "postgresql", "audit"),
        metadata={"gap10_area": "db.audit.retention", "db_engine": "postgresql"},
    ),
    # ── Configuration hardening ──────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.postgresql.listen_addresses",
        title="PostgreSQL does not listen on every interface",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("listen_addresses")},
        # `not_equals '*'` was the first version and it was wrong: PostgreSQL
        # treats '0.0.0.0' as every IPv4 address and '::' as every IPv6 one, so
        # a server bound to all interfaces passed the check by spelling it
        # differently. Found by hardening a real instance and watching it come
        # back compliant while still listening everywhere.
        expect=Expectation(
            "not_in",
            # These are the wildcard spellings the rule *refuses*, not an
            # address this process binds to. Flagging a bind-all here would be
            # flagging the check for the condition it exists to detect.
            ["*", "0.0.0.0", "::"],  # nosec B104
            description="a named address, not a wildcard",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="The interfaces the postmaster binds to.",
        rationale=(
            "Binding to every interface exposes the instance on networks it "
            "has no reason to be reachable from — a management VLAN, a second "
            "NIC, a container network — where pg_hba is the only remaining "
            "control."
        ),
        remediation=(
            "Set listen_addresses to the specific addresses clients use and "
            "restart. This is a restart-only setting."
        ),
        references=(
            "https://www.postgresql.org/docs/current/runtime-config-connection.html",
        ),
        tags=("database", "postgresql", "exposure"),
        metadata={"gap10_area": "db.conf.listen_exposure", "db_engine": "postgresql"},
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.version_supported",
        title="PostgreSQL is a release still receiving fixes",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("server_version_num")},
        # 140000 is PostgreSQL 14. Recorded 29 August 2026, when 13 had been
        # out of support for nine months. The boundary moves every November.
        expect=Expectation(
            "gte", 140000, description="PostgreSQL 14 or later (as at 2026-08)"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The running major version, against the oldest release under the "
            "PostgreSQL five-year support policy."
        ),
        rationale=(
            "An out-of-support release receives no fixes for vulnerabilities "
            "found after its end-of-life date, so its CVE exposure only grows "
            "and no patch will ever close it."
        ),
        remediation=(
            "Plan a major-version upgrade. Check the current support window at "
            "https://www.postgresql.org/support/versioning/ — this rule's "
            "boundary was set in August 2026 and moves each November."
        ),
        references=("https://www.postgresql.org/support/versioning/",),
        tags=("database", "postgresql", "patching"),
        metadata={
            "gap10_area": "db.conf.version_supported",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.system_table_mods",
        title="PostgreSQL does not permit direct system catalogue modification",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["postgresql"]},
        collect={"engine": "postgresql", "sql": _setting("allow_system_table_mods")},
        expect=Expectation("is_false", description="off"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the structure of system catalogues may be altered " "directly."
        ),
        rationale=(
            "With this on, a superuser can corrupt the catalogue in ways the "
            "server cannot recover from, and can alter the very tables that "
            "record who holds which privilege."
        ),
        remediation="Set allow_system_table_mods = off and restart the server.",
        references=(
            "https://www.postgresql.org/docs/current/runtime-config-developer.html",
        ),
        tags=("database", "postgresql", "hardening"),
        metadata={
            "gap10_area": "db.conf.dangerous_options",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.superuser_reserved",
        title="PostgreSQL reserves connection slots for administrators",
        check_type="database_query",
        platforms=("database",),
        severity="low",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "sql": _setting("superuser_reserved_connections"),
        },
        expect=Expectation("gte", 1, description="at least one reserved slot"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Connection slots held back from ordinary roles so an "
            "administrator can still connect."
        ),
        rationale=(
            "Without a reserve, an application that exhausts max_connections "
            "locks administrators out of the instance that needs fixing — the "
            "connection storm and the inability to diagnose it arrive "
            "together."
        ),
        remediation=("Set superuser_reserved_connections to at least 3 and restart."),
        references=(
            "https://www.postgresql.org/docs/current/runtime-config-connection.html",
        ),
        tags=("database", "postgresql", "availability"),
        metadata={
            "gap10_area": "db.conf.connection_limits",
            "db_engine": "postgresql",
        },
    ),
    ConfigCheck(
        check_id="ccure.db.postgresql.sample_databases",
        title="PostgreSQL carries no sample database",
        check_type="database_query",
        platforms=("database",),
        severity="low",
        os_match={"os_name_contains": ["postgresql"]},
        collect={
            "engine": "postgresql",
            "result": "rows",
            "sql": (
                "SELECT datname FROM pg_database WHERE datname IN "
                "('pagila', 'dellstore', 'dellstore2', 'sakila', 'northwind', "
                "'adventureworks', 'chinook', 'employees')"
            ),
        },
        expect=Expectation("is_empty", description="no sample database"),
        absent=AbsencePolicy.PASS,
        description=(
            "Well-known demonstration databases left on a production instance."
        ),
        rationale=(
            "Sample databases ship with permissive grants and predictable "
            "object names, and their presence usually means the instance was "
            "built from a tutorial rather than from a hardened baseline."
        ),
        remediation="DROP DATABASE for any sample database not in use.",
        references=(),
        tags=("database", "postgresql", "hardening"),
        metadata={
            "gap10_area": "db.conf.sample_databases",
            "db_engine": "postgresql",
        },
    ),
]


def postgresql_checks() -> List[ConfigCheck]:
    return list(POSTGRESQL_CHECKS)
