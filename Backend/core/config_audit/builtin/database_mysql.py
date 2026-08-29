"""
core/config_audit/builtin/database_mysql.py
─────────────────────────────────────────────────────────────────────────────
MySQL and MariaDB configuration and privilege checks. Phase 7 (GAP-10).

Every statement here was run against a live MySQL 8.0 instance before the rule
was written. Four things that came out of doing that, each of which changed a
rule or removed one:

* **``root`` legitimately holds SUPER, FILE, PROCESS and SHUTDOWN.** The first
  version of the privilege rules listed every account holding them and reported
  eight findings on a stock installation. They exclude ``root`` and the
  ``mysql.*`` internal accounts, so what remains is what a reviewer actually
  needs to see: some *other* account that acquired them.

* **``is_grantable`` returns 132 rows on a stock instance**, all of them root's.
  That is the measurement behind ``db.priv.grant_option`` being excluded from
  the GAP-10 denominator: a flat listing of grant-option holders is noise, and
  making it meaningful needs transitive closure over the grant graph.

* **``general_log`` is not the answer to "is auditing on".** Enabling it logs
  every statement including those containing credentials, and the MySQL manual
  advises against it in production. A rule demanding it would be bad advice
  wearing a compliance badge, so audit coverage is left to the engines that
  have a real audit facility rather than asserted here.

* **``root@%`` is the ``mysql`` image default.** It is still reported, because
  it is genuinely what it looks like — the superuser reachable from any address
  — and unlike the two cases above it is not something the software requires in
  order to work.

MariaDB
───────
MariaDB speaks the MySQL wire protocol and PyMySQL drives both, so
``normalize_engine`` folds it onto ``mysql``. Rules that read a variable
MariaDB does not have return no row, which is ABSENT, and the absence policy
decides — deliberately MANUAL_REVIEW for the settings rules, because "MariaDB
spells this differently" and "the setting is off" are different facts and only
one of them is a finding.
"""

from __future__ import annotations

from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["MYSQL_CHECKS", "mysql_checks"]

_DOC = "https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html"
_SEC_DOC = "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html"
_PRIV_DOC = "https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html"

#: Accounts MySQL creates for its own internal use, plus the bootstrap
#: superuser. Excluded from the privilege rules because their privileges are a
#: property of the product rather than of anyone's configuration decision — the
#: same reasoning that put ``NT SERVICE\*`` on the Phase 5 trusted list.
_SYSTEM_ACCOUNTS = (
    "'mysql.infoschema'@'localhost'",
    "'mysql.session'@'localhost'",
    "'mysql.sys'@'localhost'",
)


def _global(variable: str) -> str:
    """Read one global server variable."""
    return f"SELECT @@GLOBAL.{variable}"


MYSQL_CHECKS: List[ConfigCheck] = [
    # ── Authentication & accounts ────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mysql.empty_password",
        title="No MySQL account has an empty password",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={
            "engine": "mysql",
            "result": "rows",
            "sql": (
                "SELECT CONCAT(user, '@', host) FROM mysql.user "
                "WHERE authentication_string = '' AND plugin NOT IN "
                "('auth_socket', 'unix_socket', 'mysql_no_login')"
            ),
        },
        expect=Expectation("is_empty", description="no account without a password"),
        absent=AbsencePolicy.PASS,
        description=(
            "Accounts with no stored password. Accounts authenticating through "
            "the operating-system socket or explicitly barred from logging in "
            "are excluded, because for those an empty password column is "
            "normal and correct."
        ),
        rationale=(
            "An account with no password is usable by anyone who can reach the "
            "port, with whatever privileges it holds and from whatever hosts "
            "its host column permits."
        ),
        remediation=(
            "ALTER USER '<user>'@'<host>' IDENTIFIED BY '<password>'; or DROP "
            "USER for an account that is not needed."
        ),
        references=(_SEC_DOC,),
        tags=("database", "mysql", "authentication"),
        metadata={"gap10_area": "db.auth.empty_password", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.anonymous_accounts",
        title="MySQL has no anonymous account",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={
            "engine": "mysql",
            "result": "rows",
            "sql": (
                "SELECT CONCAT('anonymous@', host) FROM mysql.user " "WHERE user = ''"
            ),
        },
        expect=Expectation("is_empty", description="no anonymous account"),
        absent=AbsencePolicy.PASS,
        description=(
            "Accounts with an empty user name, which MySQL matches for any "
            "user name a client presents."
        ),
        rationale=(
            "An anonymous account lets a client connect under a name that was "
            "never created. It also changes how MySQL matches every other "
            "account, because the most specific host wins — so an anonymous "
            "entry for a host can take precedence over a named account and "
            "silently deny the privileges that account was granted."
        ),
        remediation="DROP USER ''@'<host>'; for each anonymous entry.",
        references=("https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html",),
        tags=("database", "mysql", "authentication"),
        metadata={"gap10_area": "db.auth.default_accounts", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.weak_auth_plugin",
        title="No MySQL account uses a legacy authentication plugin",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={
            "engine": "mysql",
            "result": "rows",
            "sql": (
                "SELECT CONCAT(user, '@', host, ' uses ', plugin) "
                "FROM mysql.user WHERE plugin IN "
                "('mysql_native_password', 'mysql_old_password')"
            ),
        },
        expect=Expectation("is_empty", description="no account on a legacy plugin"),
        absent=AbsencePolicy.PASS,
        description=(
            "Accounts still authenticating with mysql_native_password or the "
            "pre-4.1 mysql_old_password."
        ),
        rationale=(
            "Both store a bare SHA-1 of the password with no salt and no "
            "iteration, so the stored value is password-equivalent and "
            "identical passwords are visibly identical across accounts. "
            "mysql_native_password is deprecated as of MySQL 8.0.34."
        ),
        remediation=(
            "ALTER USER '<user>'@'<host>' IDENTIFIED WITH "
            "caching_sha2_password BY '<password>'; after confirming every "
            "client library supports it."
        ),
        references=(
            "https://dev.mysql.com/doc/refman/8.0/en/pluggable-authentication.html",
        ),
        tags=("database", "mysql", "authentication"),
        metadata={"gap10_area": "db.auth.weak_auth_method", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.root_remote",
        title="MySQL root is restricted to the local host",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={
            "engine": "mysql",
            "result": "rows",
            "sql": (
                "SELECT CONCAT(user, '@', host) FROM mysql.user "
                "WHERE user = 'root' AND host NOT IN "
                "('localhost', '127.0.0.1', '::1')"
            ),
        },
        expect=Expectation("is_empty", description="root@localhost only"),
        absent=AbsencePolicy.PASS,
        description=(
            "root accounts whose host column admits connections from beyond "
            "the local machine."
        ),
        rationale=(
            "root holds every privilege including FILE and SUPER. A root entry "
            "for '%' means one guessed or leaked password is a full compromise "
            "of the instance from anywhere that can reach the port, with no "
            "second factor and no network restriction in the way."
        ),
        remediation=(
            "DROP USER 'root'@'%'; and administer through a named account "
            "restricted to the hosts that need it, or over a local socket."
        ),
        references=(_SEC_DOC,),
        tags=("database", "mysql", "authentication"),
        metadata={"gap10_area": "db.auth.superuser_remote", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.validate_password",
        title="MySQL enforces a password policy",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        # Both forms, and the UNION is not belt-and-braces — it is the fix for a
        # false positive this rule shipped with. MySQL 5.7 installs
        # validate_password as a *plugin* (information_schema.plugins); MySQL 8
        # installs it as a *component* (mysql.component). Reading only the
        # plugin table reported "no password policy" against a hardened 8.0
        # server whose policy had, minutes earlier, rejected a generated
        # password for not meeting it.
        collect={
            "engine": "mysql",
            "result": "count",
            "sql": (
                "SELECT plugin_name AS item FROM information_schema.plugins "
                "WHERE plugin_name LIKE 'validate_password%' "
                "AND plugin_status = 'ACTIVE' "
                "UNION ALL "
                "SELECT component_urn AS item FROM mysql.component "
                "WHERE component_urn LIKE '%validate_password%'"
            ),
        },
        expect=Expectation(
            "gte", 1, description="the password plugin or component is active"
        ),
        # `count` never returns ABSENT, so this policy is unreachable — it is
        # declared because ConfigCheck requires a choice, and MANUAL_REVIEW is
        # the honest value for a state that would mean the read misbehaved.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the validate_password component or plugin is installed "
            "and active."
        ),
        rationale=(
            "Without it the server accepts any password an administrator "
            "types, including a single character, and nothing at the database "
            "layer enforces the organisation's policy."
        ),
        remediation=(
            "INSTALL COMPONENT 'file://component_validate_password'; then set "
            "validate_password.length and validate_password.policy to match "
            "the organisation's standard."
        ),
        references=("https://dev.mysql.com/doc/refman/8.0/en/validate-password.html",),
        tags=("database", "mysql", "authentication"),
        metadata={"gap10_area": "db.auth.password_policy", "db_engine": "mysql"},
    ),
    # ── Privileges ───────────────────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mysql.super_privilege",
        title="No ordinary MySQL account holds administrative privileges",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={
            "engine": "mysql",
            "result": "rows",
            "sql": (
                "SELECT CONCAT(grantee, ' holds ', privilege_type) "
                "FROM information_schema.user_privileges "
                "WHERE privilege_type IN ('SUPER', 'SHUTDOWN', 'PROCESS') "
                "AND grantee NOT LIKE '''root''@%' "
                "AND grantee NOT LIKE '''mysql.%'"
            ),
        },
        expect=Expectation("is_empty", description="no non-root account with SUPER"),
        absent=AbsencePolicy.PASS,
        description=(
            "Accounts other than root and MySQL's own internal accounts "
            "holding SUPER, SHUTDOWN or PROCESS."
        ),
        rationale=(
            "SUPER overrides read_only, permits changing global variables, and "
            "lets an account kill other sessions. PROCESS exposes the "
            "statements every other session is running, which routinely "
            "include credentials passed as literals."
        ),
        remediation=(
            "REVOKE SUPER, SHUTDOWN, PROCESS ON *.* FROM '<user>'@'<host>'; "
            "and grant the specific dynamic privilege the account needs "
            "(BINLOG_ADMIN, SYSTEM_VARIABLES_ADMIN)."
        ),
        references=(_PRIV_DOC,),
        tags=("database", "mysql", "privilege"),
        metadata={"gap10_area": "db.priv.superusers", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.file_privilege",
        title="No ordinary MySQL account holds the FILE privilege",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={
            "engine": "mysql",
            "result": "rows",
            "sql": (
                "SELECT CONCAT(user, '@', host) FROM mysql.user "
                "WHERE File_priv = 'Y' AND user <> 'root' "
                "AND user NOT LIKE 'mysql.%'"
            ),
        },
        expect=Expectation("is_empty", description="no non-root FILE holder"),
        absent=AbsencePolicy.PASS,
        description=(
            "Accounts other than root holding FILE, which permits reading and "
            "writing files on the server host through SQL."
        ),
        rationale=(
            "FILE turns a database login into a filesystem read of anything "
            "the mysqld account can read — /etc/passwd, application "
            "configuration, private keys — and a write of anything it can "
            "write, which includes locations that lead to code execution."
        ),
        remediation=(
            "REVOKE FILE ON *.* FROM '<user>'@'<host>'; and keep "
            "secure_file_priv pointed at a dedicated directory."
        ),
        references=(_PRIV_DOC,),
        tags=("database", "mysql", "privilege"),
        metadata={"gap10_area": "db.priv.filesystem_access", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.secure_file_priv",
        title="MySQL confines server-side file access to one directory",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        # COALESCE, and the reason is a bug this rule shipped with for an hour.
        # secure_file_priv is NULL when server-side file access is disabled
        # outright — the *most* hardened state there is. `not_empty` treats
        # None as empty, so the first version of this rule reported a locked
        # down server as failing and an unrestricted one ('') identically.
        # Folding NULL to a token first keeps the two apart.
        collect={
            "engine": "mysql",
            "sql": "SELECT COALESCE(@@GLOBAL.secure_file_priv, 'DISABLED')",
        },
        expect=Expectation(
            "not_equals",
            "",
            description="a directory, or NULL to disable file access entirely",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The directory LOAD DATA and SELECT ... INTO OUTFILE are confined "
            "to. An empty value means no confinement at all."
        ),
        rationale=(
            "With secure_file_priv empty, any account holding FILE can read "
            "and write anywhere the server process can. The privilege and this "
            "setting are two halves of one control, which is why both are "
            "checked."
        ),
        remediation=(
            "Set secure_file_priv to a dedicated directory in the server "
            "configuration and restart, or set it to NULL to disable "
            "server-side file access entirely."
        ),
        references=(_DOC,),
        tags=("database", "mysql", "privilege"),
        metadata={
            "gap10_area": "db.priv.dangerous_features",
            "db_engine": "mysql",
        },
    ),
    # ── Encryption & transport ───────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mysql.have_ssl",
        title="MySQL offers TLS to clients",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={"engine": "mysql", "sql": _global("have_ssl")},
        expect=Expectation("in", ["yes", "1"], description="YES"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Whether the server has a usable certificate and key.",
        rationale=(
            "Without TLS the authentication exchange and every row returned "
            "cross the network in the clear."
        ),
        remediation=(
            "Provide ssl_cert, ssl_key and ssl_ca in the server configuration "
            "and restart. MySQL 8 generates a self-signed set at first start "
            "if none is supplied."
        ),
        references=(
            "https://dev.mysql.com/doc/refman/8.0/en/encrypted-connections.html",
        ),
        tags=("database", "mysql", "encryption"),
        metadata={"gap10_area": "db.tls.enabled", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.require_secure_transport",
        title="MySQL requires encrypted client connections",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={"engine": "mysql", "sql": _global("require_secure_transport")},
        expect=Expectation("is_true", description="ON"),
        # MariaDB has no such variable, so the read legitimately returns
        # nothing there. Deferring is the honest answer: the server may still
        # require TLS per account through REQUIRE SSL, which this does not see.
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the server refuses connections that are neither encrypted "
            "nor over a local socket."
        ),
        rationale=(
            "Offering TLS is not requiring it. With this off a client that "
            "simply does not ask for encryption is still accepted, and nothing "
            "on the server indicates that it happened."
        ),
        remediation=(
            "SET PERSIST require_secure_transport = ON; after confirming every "
            "client connects over TLS or a local socket."
        ),
        references=(
            "https://dev.mysql.com/doc/refman/8.0/en/encrypted-connections.html",
        ),
        tags=("database", "mysql", "encryption"),
        metadata={"gap10_area": "db.tls.enforced", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.tls_version",
        title="MySQL offers no TLS version below 1.2",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={"engine": "mysql", "sql": _global("tls_version")},
        expect=Expectation(
            "not_matches",
            r"TLSv1(\.1)?(,|$)",
            description="no TLSv1 or TLSv1.1 in the offered list",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="The TLS protocol versions the server will negotiate.",
        rationale=(
            "TLS 1.0 and 1.1 are deprecated by RFC 8996. While they remain in "
            "the offered list the server will negotiate down for any client "
            "that asks for them."
        ),
        remediation="Set tls_version='TLSv1.2,TLSv1.3' and restart the server.",
        references=(_DOC, "https://www.rfc-editor.org/rfc/rfc8996"),
        tags=("database", "mysql", "encryption"),
        metadata={"gap10_area": "db.tls.min_version", "db_engine": "mysql"},
    ),
    # ── Configuration hardening ──────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mysql.local_infile",
        title="MySQL does not permit LOAD DATA LOCAL",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={"engine": "mysql", "sql": _global("local_infile")},
        expect=Expectation("is_false", description="OFF"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether the server accepts LOAD DATA LOCAL INFILE, which reads a "
            "file from the *client* rather than the server."
        ),
        rationale=(
            "The server tells the client which file to send. A malicious or "
            "compromised server can therefore request any file the client "
            "process can read — the 'rogue MySQL server' technique — so this "
            "is a risk to everything that connects, not only to the server."
        ),
        remediation="SET PERSIST local_infile = OFF;",
        references=(
            "https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html",
        ),
        tags=("database", "mysql", "hardening"),
        metadata={"gap10_area": "db.conf.dangerous_options", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.bind_address",
        title="MySQL does not listen on every interface",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={"engine": "mysql", "sql": _global("bind_address")},
        expect=Expectation(
            "not_in",
            # The wildcard spellings this rule refuses, not an address this
            # process binds to.
            ["*", "0.0.0.0", "::"],  # nosec B104
            description="a named address, not a wildcard",
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="The addresses mysqld binds its TCP listener to.",
        rationale=(
            "Binding to every interface exposes the instance on networks it "
            "has no reason to be reachable from, leaving the account host "
            "column as the only remaining control."
        ),
        remediation=(
            "Set bind_address to the specific addresses clients use and "
            "restart the server."
        ),
        references=(_DOC,),
        tags=("database", "mysql", "exposure"),
        metadata={"gap10_area": "db.conf.listen_exposure", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.version_supported",
        title="MySQL is a release still receiving fixes",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["mysql"]},
        collect={"engine": "mysql", "sql": _global("version")},
        # 8.0 is the oldest MySQL series under Oracle's Extended Support as at
        # August 2026; 5.7 left Extended Support in October 2023. MariaDB is
        # excluded from os_match above because its version numbers are on a
        # different series entirely and comparing them here would be wrong.
        expect=Expectation(
            "version_gte", "8.0", description="MySQL 8.0 or later (as at 2026-08)"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="The running server version against Oracle's support policy.",
        rationale=(
            "An out-of-support release receives no fixes for vulnerabilities "
            "found after its end date, so its exposure only grows."
        ),
        remediation=(
            "Plan an upgrade. Check the current support window at "
            "https://endoflife.date/mysql — this rule's boundary was set in "
            "August 2026."
        ),
        references=("https://endoflife.date/mysql",),
        tags=("database", "mysql", "patching"),
        metadata={"gap10_area": "db.conf.version_supported", "db_engine": "mysql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mysql.sample_databases",
        title="MySQL carries no sample schema",
        check_type="database_query",
        platforms=("database",),
        severity="low",
        os_match={"os_name_contains": ["mysql", "mariadb"]},
        collect={
            "engine": "mysql",
            "result": "rows",
            "sql": (
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name IN ('test', 'world', 'world_x', 'sakila', "
                "'employees', 'menagerie')"
            ),
        },
        expect=Expectation("is_empty", description="no sample schema"),
        absent=AbsencePolicy.PASS,
        description="Demonstration schemas left on a production instance.",
        rationale=(
            "The historical 'test' schema was writable by any account that "
            "could connect. The others ship with predictable object names and "
            "usually indicate the instance was built from a tutorial rather "
            "than a hardened baseline."
        ),
        remediation="DROP DATABASE for any sample schema not in use.",
        references=("https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html",),
        tags=("database", "mysql", "hardening"),
        metadata={"gap10_area": "db.conf.sample_databases", "db_engine": "mysql"},
    ),
]


def mysql_checks() -> List[ConfigCheck]:
    return list(MYSQL_CHECKS)
