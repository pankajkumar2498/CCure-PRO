"""
core/config_audit/builtin/database_mssql.py
─────────────────────────────────────────────────────────────────────────────
Microsoft SQL Server configuration and privilege checks. Phase 7 (GAP-10).

Every statement here was run against a live SQL Server 2022 instance before the
rule was written. Four things that came out of doing that:

* **``guest`` holds CONNECT in ``master``, and must.** SQL Server does not
  permit revoking it there, and a session reads permissions for the database it
  is connected to. A guest rule would therefore have reported a finding on
  every instance and had no correct remediation. Answering it properly needs a
  per-user-database sweep, which cannot be expressed as one read-only
  statement, so it is not attempted. Recorded as a limitation rather than
  shipped wrong.

* **``NT AUTHORITY\\*``, ``NT SERVICE\\*`` and ``BUILTIN\\*`` are sysadmin on a
  stock instance.** Listing them produced two findings on an untouched
  container. They are excluded, which is the same call Phase 5 made for the
  ``S-1-5-80-*`` virtual accounts — and it carries the same cost, recorded in
  the tracker: on a Windows deployment ``BUILTIN\\Administrators`` in sysadmin
  is a genuine hardening item, and this build will not report it.

* **``VIEW ANY DATABASE`` and the endpoint ``CONNECT`` grants are default
  grants to ``public``.** Reporting them made every instance look
  over-permissioned. Excluded by name so what remains is a grant somebody made.

* **``SERVERPROPERTY`` returns SQL_VARIANT, which pymssql hands back as raw
  bytes** — ``b'16.0.4265.3'``, not ``'16.0.4265.3'``. Every use is wrapped in
  CAST, without which the comparison runs against a Python bytes repr and no
  version rule can ever be true.

No ``EXEC``, anywhere
─────────────────────
``assert_read_only`` refuses it, and that is a real constraint rather than an
inconvenience: the conventional way to read SQL Server's login-audit level is
``EXEC xp_instance_regread``, which is a stored-procedure call into the
registry. Rather than widen the read-only guard for one setting, that area is
left unanswered. The guard is worth more than the check.
"""

from __future__ import annotations

import re
from typing import List

from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

__all__ = ["MSSQL_CHECKS", "mssql_checks"]

_CONF_DOC = (
    "https://learn.microsoft.com/sql/database-engine/configure-windows/"
    "server-configuration-options-sql-server-configuration-manager"
)
_AUDIT_DOC = "https://learn.microsoft.com/sql/relational-databases/security/auditing/sql-server-audit-database-engine"
_LOGIN_DOC = (
    "https://learn.microsoft.com/sql/relational-databases/security/"
    "authentication-access/principals-database-engine"
)

#: Principals SQL Server provisions for itself. Excluded from the sysadmin rule
#: because their membership is a property of the product rather than of anyone's
#: configuration decision — measured on a stock 2022 instance, where listing
#: them produced two findings on an untouched server.
_PROVISIONED_PRINCIPALS = (
    "NT AUTHORITY\\%",
    "NT SERVICE\\%",
    "BUILTIN\\%",
)


def _configuration(name: str) -> str:
    """
    Read one entry from sys.configurations as an integer.

    The name is interpolated rather than bound because these are module-level
    literals composed once at import — but it is validated anyway, for the same
    reason as the PostgreSQL helper: this is the shape that becomes an
    injection point the first time rules are made editable.
    """
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _]*", name):
        raise ValueError(f"not a SQL Server configuration name: {name!r}")
    # Interpolation is safe here because of the line above: the name has been
    # proven to be a bare identifier before it reaches the statement.
    return (
        "SELECT CAST(value_in_use AS INT) FROM sys.configurations "
        f"WHERE name = '{name}'"  # nosec B608
    )


MSSQL_CHECKS: List[ConfigCheck] = [
    # ── Authentication & accounts ────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mssql.blank_password",
        title="No SQL Server login has a blank password",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            "sql": (
                "SELECT name FROM sys.sql_logins "
                "WHERE PWDCOMPARE('', password_hash) = 1 AND is_disabled = 0"
            ),
        },
        expect=Expectation("is_empty", description="no login with a blank password"),
        absent=AbsencePolicy.PASS,
        description=(
            "Enabled SQL logins whose password is the empty string, tested with "
            "PWDCOMPARE against the stored hash."
        ),
        rationale=(
            "A blank password on an enabled login is usable by anyone who can "
            "reach the instance. PWDCOMPARE tests the stored verifier directly, "
            "so this establishes the fact rather than inferring it from policy "
            "settings."
        ),
        remediation=(
            "ALTER LOGIN [<name>] WITH PASSWORD = '<value>'; or DISABLE the "
            "login if it is not in use."
        ),
        references=(_LOGIN_DOC,),
        tags=("database", "mssql", "authentication"),
        metadata={"gap10_area": "db.auth.empty_password", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.login_named_password",
        title="No SQL Server login uses its own name as the password",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            "sql": (
                "SELECT name FROM sys.sql_logins "
                "WHERE PWDCOMPARE(name, password_hash) = 1 AND is_disabled = 0"
            ),
        },
        expect=Expectation(
            "is_empty", description="no login whose password is its name"
        ),
        absent=AbsencePolicy.PASS,
        description=("Enabled logins whose password is identical to the login name."),
        rationale=(
            "It is the first guess any credential-stuffing attempt makes, and "
            "PWDCOMPARE can establish it without attempting a single login — so "
            "the check produces no failed-authentication events and cannot lock "
            "an account out."
        ),
        remediation="ALTER LOGIN [<name>] WITH PASSWORD = '<value>';",
        references=(_LOGIN_DOC,),
        tags=("database", "mssql", "authentication"),
        metadata={"gap10_area": "db.auth.empty_password", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.password_policy",
        title="SQL Server logins are subject to the password policy",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            "sql": (
                "SELECT name FROM sys.sql_logins "
                "WHERE is_policy_checked = 0 AND is_disabled = 0"
            ),
        },
        expect=Expectation(
            "is_empty", description="every enabled login has CHECK_POLICY on"
        ),
        absent=AbsencePolicy.PASS,
        description=("Enabled SQL logins created or altered with CHECK_POLICY = OFF."),
        rationale=(
            "With CHECK_POLICY off, the login is exempt from the host's "
            "password complexity and lockout policy, so it accepts a password "
            "the organisation's standard would refuse and survives unlimited "
            "guessing."
        ),
        remediation=(
            "ALTER LOGIN [<name>] WITH CHECK_POLICY = ON; and reset the "
            "password, since the existing one was never tested against the "
            "policy."
        ),
        references=(_LOGIN_DOC,),
        tags=("database", "mssql", "authentication"),
        metadata={"gap10_area": "db.auth.password_policy", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.sa_enabled",
        title="The SQL Server sa login is disabled",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            # sid 0x01 identifies sa regardless of whether it has been renamed,
            # which a name comparison would miss — and renaming it is one of the
            # two things anyone does to it.
            "sql": (
                "SELECT name FROM sys.sql_logins "
                "WHERE sid = 0x01 AND is_disabled = 0"
            ),
        },
        expect=Expectation("is_empty", description="sa is disabled"),
        absent=AbsencePolicy.PASS,
        description=(
            "Whether the built-in sa login is enabled. Identified by its fixed "
            "SID rather than by name, so renaming it does not hide it."
        ),
        rationale=(
            "sa is a sysadmin whose name is known to every attacker and which "
            "no audit trail can attribute to a person. It is the single most "
            "targeted account name in SQL Server credential attacks."
        ),
        remediation=(
            "ALTER LOGIN [sa] DISABLE; after confirming no application uses "
            "it, and administer through named accounts."
        ),
        references=(_LOGIN_DOC,),
        tags=("database", "mssql", "authentication"),
        metadata={"gap10_area": "db.auth.default_accounts", "db_engine": "mssql"},
    ),
    # ── Privileges ───────────────────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mssql.sysadmin_members",
        title="SQL Server sysadmin membership is limited",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            "sql": (
                "SELECT p.name FROM sys.server_role_members m "
                "JOIN sys.server_principals r "
                "ON r.principal_id = m.role_principal_id "
                "JOIN sys.server_principals p "
                "ON p.principal_id = m.member_principal_id "
                "WHERE r.name = 'sysadmin' AND p.name <> 'sa' "
                "AND p.name NOT LIKE 'NT AUTHORITY\\%' "
                "AND p.name NOT LIKE 'NT SERVICE\\%' "
                "AND p.name NOT LIKE 'BUILTIN\\%'"
            ),
        },
        expect=Expectation(
            "is_empty", description="no sysadmin beyond sa and service accounts"
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "Members of the sysadmin server role, excluding sa and the "
            "principals SQL Server provisions for its own services."
        ),
        rationale=(
            "sysadmin bypasses every permission check in the instance and can "
            "reach the host through xp_cmdshell, CLR assemblies or a startup "
            "procedure. Membership is effectively administrator on the server, "
            "not merely on the database."
        ),
        remediation=(
            "ALTER SERVER ROLE sysadmin DROP MEMBER [<name>]; and grant the "
            "narrower fixed role or permission the account needs."
        ),
        references=(_LOGIN_DOC,),
        tags=("database", "mssql", "privilege"),
        metadata={"gap10_area": "db.priv.superusers", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.public_server_permissions",
        title="SQL Server public role holds no granted server permission",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            # CONNECT (on the default endpoints) and VIEW ANY DATABASE are
            # granted to public on every instance. Excluded by name so what
            # remains is a grant somebody actually made.
            "sql": (
                "SELECT pe.permission_name FROM sys.server_permissions pe "
                "JOIN sys.server_principals pr "
                "ON pr.principal_id = pe.grantee_principal_id "
                "WHERE pr.name = 'public' AND pe.state_desc = 'GRANT' "
                "AND pe.permission_name NOT LIKE 'CONNECT%' "
                "AND pe.permission_name <> 'VIEW ANY DATABASE'"
            ),
        },
        expect=Expectation("is_empty", description="no non-default grant to public"),
        absent=AbsencePolicy.PASS,
        description=(
            "Server-level permissions granted to the public role beyond the "
            "defaults every instance carries."
        ),
        rationale=(
            "Every login is a member of public and cannot be removed from it, "
            "so a grant there reaches accounts nobody has created yet and "
            "cannot be reasoned about from the login list."
        ),
        remediation=(
            "REVOKE <permission> FROM public; and grant it to the specific "
            "logins or roles that need it."
        ),
        references=(_LOGIN_DOC,),
        tags=("database", "mssql", "privilege"),
        metadata={"gap10_area": "db.priv.public_grants", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.bulk_operations",
        title="SQL Server bulk filesystem access is not granted broadly",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            "sql": (
                "SELECT pr.name FROM sys.server_permissions pe "
                "JOIN sys.server_principals pr "
                "ON pr.principal_id = pe.grantee_principal_id "
                "WHERE pe.permission_name = 'ADMINISTER BULK OPERATIONS' "
                "AND pe.state_desc = 'GRANT' AND pr.name <> 'sa'"
            ),
        },
        expect=Expectation(
            "is_empty", description="no principal holds bulk operations"
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "Principals granted ADMINISTER BULK OPERATIONS, which permits "
            "BULK INSERT and OPENROWSET(BULK …)."
        ),
        rationale=(
            "The permission reads any file the SQL Server service account can "
            "read, returned as a result set — configuration files, private "
            "keys, anything on a share the service account reaches. It is a "
            "filesystem read wearing a database permission."
        ),
        remediation=(
            "REVOKE ADMINISTER BULK OPERATIONS FROM [<name>]; and stage bulk "
            "loads through a controlled directory instead."
        ),
        references=(_LOGIN_DOC,),
        tags=("database", "mssql", "privilege"),
        metadata={"gap10_area": "db.priv.filesystem_access", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.dangerous_features",
        title="SQL Server command-execution features are disabled",
        check_type="database_query",
        platforms=("database",),
        severity="critical",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            "sql": (
                "SELECT name FROM sys.configurations WHERE name IN "
                "('xp_cmdshell', 'Ole Automation Procedures', 'clr enabled', "
                "'Ad Hoc Distributed Queries', "
                "'cross db ownership chaining', 'scan for startup procs') "
                "AND value_in_use <> 0"
            ),
        },
        expect=Expectation(
            "is_empty", description="none of the listed options is enabled"
        ),
        absent=AbsencePolicy.PASS,
        description=(
            "Server options that let SQL execute code outside the database "
            "engine: xp_cmdshell, OLE Automation, CLR, Ad Hoc Distributed "
            "Queries, cross-database ownership chaining and startup procedure "
            "scanning."
        ),
        rationale=(
            "xp_cmdshell runs operating-system commands as the service "
            "account, and OLE Automation and CLR reach the host the same way "
            "by other routes. Each turns a SQL injection flaw in any "
            "application using this instance into code execution on the "
            "server."
        ),
        remediation=(
            "sp_configure the named option to 0 followed by RECONFIGURE. "
            "Where a feature is genuinely required, restrict who may invoke it "
            "and record the exception."
        ),
        references=(_CONF_DOC,),
        tags=("database", "mssql", "privilege"),
        metadata={
            "gap10_area": "db.priv.dangerous_features",
            "db_engine": "mssql",
        },
    ),
    # ── Encryption ───────────────────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mssql.connection_encrypted",
        title="SQL Server encrypts client connections",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            # The scanner asks for encryption on every connection, so a session
            # reporting FALSE means the instance accepted an unencrypted one —
            # which is what "does not require encryption" means in practice.
            # ForceEncryption itself lives in the registry and there is no
            # catalogue view for it, so this is the observable that exists.
            "sql": (
                "SELECT CAST(encrypt_option AS VARCHAR(10)) "
                "FROM sys.dm_exec_connections WHERE session_id = @@SPID"
            ),
        },
        expect=Expectation("is_true", description="TRUE"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Whether this scanner's own session is encrypted, having requested "
            "encryption."
        ),
        rationale=(
            "The scanner requests encryption on connection. A session that is "
            "nonetheless unencrypted establishes that the instance accepts "
            "plaintext, so the authentication exchange and every result set "
            "cross the network in the clear for any client that does not ask."
        ),
        remediation=(
            "Install a certificate and set ForceEncryption in SQL Server "
            "Configuration Manager, then restart the service."
        ),
        references=(
            "https://learn.microsoft.com/sql/database-engine/configure-windows/"
            "configure-sql-server-encryption",
        ),
        tags=("database", "mssql", "encryption"),
        metadata={"gap10_area": "db.tls.enforced", "db_engine": "mssql"},
    ),
    # ── Audit ────────────────────────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mssql.audit_running",
        title="SQL Server has a running audit",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "count",
            "sql": (
                "SELECT name FROM sys.dm_server_audit_status "
                "WHERE status_desc = 'STARTED'"
            ),
        },
        expect=Expectation("gte", 1, description="at least one audit is started"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description="Server audit objects that are defined and running.",
        rationale=(
            "SQL Server Audit is the only facility that records privileged "
            "activity in a form an investigation can rely on. Without one "
            "running, no record exists of who granted a permission, read a "
            "table or enabled xp_cmdshell."
        ),
        remediation=(
            "CREATE SERVER AUDIT with a file or event-log target, then "
            "ALTER SERVER AUDIT ... WITH (STATE = ON)."
        ),
        references=(_AUDIT_DOC,),
        tags=("database", "mssql", "audit"),
        metadata={"gap10_area": "db.audit.enabled", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.audit_specification",
        title="SQL Server audit has an enabled specification",
        check_type="database_query",
        platforms=("database",),
        severity="medium",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "count",
            "sql": (
                "SELECT name FROM sys.server_audit_specifications "
                "WHERE is_state_enabled = 1"
            ),
        },
        expect=Expectation("gte", 1, description="at least one enabled specification"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "Server audit specifications that are enabled. A specification is "
            "what names the action groups an audit records."
        ),
        rationale=(
            "A running audit with no enabled specification records nothing. "
            "This is checked separately from the audit itself because the two "
            "fail independently and the combination looks configured from a "
            "distance — the audit object exists, the log file is created, and "
            "it stays empty."
        ),
        remediation=(
            "CREATE SERVER AUDIT SPECIFICATION covering at least "
            "SUCCESSFUL_LOGIN_GROUP, FAILED_LOGIN_GROUP, "
            "SERVER_ROLE_MEMBER_CHANGE_GROUP and "
            "SERVER_PERMISSION_CHANGE_GROUP, then set STATE = ON."
        ),
        references=(_AUDIT_DOC,),
        tags=("database", "mssql", "audit"),
        metadata={"gap10_area": "db.audit.ddl_privilege", "db_engine": "mssql"},
    ),
    # ── Configuration hardening ──────────────────────────────────────────────
    ConfigCheck(
        check_id="ccure.db.mssql.version_supported",
        title="SQL Server is a release still receiving fixes",
        check_type="database_query",
        platforms=("database",),
        severity="high",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            # CAST is load-bearing: SERVERPROPERTY returns SQL_VARIANT, which
            # pymssql surfaces as bytes, and a version comparison against a
            # bytes repr can never be true.
            "sql": (
                "SELECT CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') "
                "AS VARCHAR(64)), 4) AS INT)"
            ),
        },
        # Major version 14 is SQL Server 2017. SQL Server 2016 left Extended
        # Support on 14 July 2026, six weeks before this rule was written.
        expect=Expectation(
            "gte", 14, description="SQL Server 2017 or later (as at 2026-08)"
        ),
        absent=AbsencePolicy.MANUAL_REVIEW,
        description=(
            "The instance's major version against Microsoft's support " "lifecycle."
        ),
        rationale=(
            "An instance past Extended Support receives no security updates, "
            "so its exposure only grows and no patch will ever close it."
        ),
        remediation=(
            "Plan an upgrade. Check the current lifecycle at "
            "https://learn.microsoft.com/lifecycle/products/ — this rule's "
            "boundary was set in August 2026."
        ),
        references=("https://learn.microsoft.com/lifecycle/products/",),
        tags=("database", "mssql", "patching"),
        metadata={"gap10_area": "db.conf.version_supported", "db_engine": "mssql"},
    ),
    ConfigCheck(
        check_id="ccure.db.mssql.sample_databases",
        title="SQL Server carries no sample database",
        check_type="database_query",
        platforms=("database",),
        severity="low",
        os_match={"os_name_contains": ["microsoft sql server"]},
        collect={
            "engine": "mssql",
            "result": "rows",
            "sql": (
                "SELECT name FROM sys.databases WHERE name IN "
                "('AdventureWorks', 'AdventureWorksDW', 'AdventureWorks2019', "
                "'AdventureWorks2022', 'Northwind', 'pubs', "
                "'WideWorldImporters', 'WideWorldImportersDW')"
            ),
        },
        expect=Expectation("is_empty", description="no sample database"),
        absent=AbsencePolicy.PASS,
        description="Microsoft sample databases attached to the instance.",
        rationale=(
            "Sample databases ship with permissive object-level grants and "
            "predictable names, and their presence on a production instance "
            "usually indicates it was built from a walkthrough rather than "
            "from a hardened baseline."
        ),
        remediation="DROP DATABASE for any sample database not in use.",
        references=(),
        tags=("database", "mssql", "hardening"),
        metadata={"gap10_area": "db.conf.sample_databases", "db_engine": "mssql"},
    ),
]


def mssql_checks() -> List[ConfigCheck]:
    return list(MSSQL_CHECKS)
