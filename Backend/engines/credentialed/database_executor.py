"""
engines/credentialed/database_executor.py
─────────────────────────────────────────────────────────────────────────────
Authenticated sessions to a database engine, for the Phase 3 configuration
audit. Phase 7 of the gap-closure programme, closing GAP-10.

This is a transport, not a collector
────────────────────────────────────
It is the database counterpart of ``SSHScanner`` and ``WinRMExecutor``: it
opens an authenticated session, runs one read-only statement at a time, and
hands back a result that preserves whether the statement actually succeeded.
It decides nothing about compliance. The rules live in
``core/config_audit/builtin/database_*.py``, the comparison happens in
``ConfigAuditEngine``, and the finding is minted by the same code that mints
one for a Windows registry check.

Why it does not satisfy ``BaseExecutor``
────────────────────────────────────────
``BaseExecutor.run(command) -> CommandResult`` is a *shell* contract: stdout,
stderr, an exit code. A database answers with rows and typed values, and
flattening those into a stdout string would throw away the distinction between
"the query returned no rows" and "the query returned one row containing an
empty string" — which is the ABSENT-versus-COLLECTED distinction the whole
configuration engine is built to preserve. So this class deliberately declares
its own narrow protocol, and :class:`~core.config_audit.collectors.database.
DatabaseQueryCollector` is the only thing that speaks it.

The same reasoning as ``ShellRunner`` applies to :class:`QueryResult`: there is
no method here that returns a bare list of rows. A caller must look at ``ok``
before it looks at ``rows``, because a failed statement returns an empty list
and reading that as "the server has no such setting" is how a scanner reports
a clean bill of health for a machine that refused it.

Read-only, and enforced rather than intended
────────────────────────────────────────────
Rules are administrator-editable, so the SQL in a rule is an injection boundary
*inside the product* — the same position Phase 3 took on ``ps_quote`` and
``shlex.quote``. Three things follow, and none of them is style:

1. :func:`assert_read_only` refuses anything that is not a single read-only
   statement. Multiple statements, DDL, DML and transaction control are
   rejected before the driver ever sees them.
2. Rule-supplied values are **bound parameters**, never interpolated. Each
   driver's paramstyle differs, so the statement is written with ``%s``/``?``
   as that driver requires and the values travel separately.
3. The session is opened read-only where the engine can express it, so a rule
   that somehow got past (1) still cannot write.

A refused statement is UNAVAILABLE, never a verdict. A defect in a rule must
not manufacture a finding about a customer's database — the same arrow the
engine already draws from ``UNKNOWN_OPERATOR``.

Four error types, and they must stay four
─────────────────────────────────────────
A refused password, an authenticated account without the privilege to read a
catalogue, nothing listening, and a driver that is not installed need four
different actions from whoever reads the scan. Collapsing them is how a
missing Python package becomes "database unreachable" and someone spends an
afternoon on a firewall rule.
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("ccure.credentialed.database")

__all__ = [
    "DEFAULT_PORTS",
    "SUPPORTED_ENGINES",
    "DatabaseAuthenticationError",
    "DatabaseConfigurationError",
    "DatabaseConnectionError",
    "DatabaseError",
    "DatabasePermissionError",
    "DatabaseSession",
    "QueryResult",
    "assert_read_only",
    "available_engines",
    "normalize_engine",
]

#: The engines this build can authenticate to. Oracle and MongoDB are
#: deliberately absent: a driver exists for both, but neither could be stood up
#: as a disposable target in this environment, and this programme does not ship
#: an engine it has not validated against.
SUPPORTED_ENGINES: Tuple[str, ...] = ("postgresql", "mysql", "mssql")

DEFAULT_PORTS: Dict[str, int] = {
    "postgresql": 5432,
    "mysql": 3306,
    "mssql": 1433,
}

#: Accepted spellings for each engine. ``mariadb`` maps onto ``mysql`` because
#: it speaks the MySQL wire protocol and PyMySQL drives both; the *checks* still
#: tell them apart, through the version banner, where a setting differs.
_ENGINE_ALIASES: Dict[str, str] = {
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "pgsql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mysql",
    "mssql": "mssql",
    "sqlserver": "mssql",
    "sql_server": "mssql",
    "microsoft_sql_server": "mssql",
}


class DatabaseError(RuntimeError):
    """Base class for every database transport failure."""


class DatabaseConnectionError(DatabaseError):
    """Nothing answered, or the connection was dropped."""


class DatabaseAuthenticationError(DatabaseError):
    """The server understood the credential and refused it."""


class DatabasePermissionError(DatabaseError):
    """The credential authenticated but lacks the privilege the read needs."""


class DatabaseConfigurationError(DatabaseError):
    """
    The scanner cannot make the attempt — a driver that is not installed, a TLS
    arrangement that cannot be satisfied, an engine name nothing implements.

    Distinct from a connection error on purpose: "we did not ask" and "we asked
    and nothing answered" send whoever reads the scan to different places.
    """


def normalize_engine(engine: Optional[str]) -> str:
    """Fold an engine spelling onto its canonical name, or "" if unknown."""
    key = str(engine or "").strip().lower().replace(" ", "_").replace("-", "_")
    return _ENGINE_ALIASES.get(key, "")


# ── Read-only enforcement ────────────────────────────────────────────────────

#: Statement keywords a configuration read legitimately begins with. Everything
#: else is refused. An allow-list rather than a deny-list because a deny-list
#: has to anticipate every way to write, and it only has to miss once.
_READ_ONLY_LEADERS: Tuple[str, ...] = ("select", "show", "with", "values")

#: Written as a whole-word search so a column called ``updated_at`` or a
#: catalogue named ``pg_drop_replication_slot`` does not trip it. These are a
#: second line only: the leader check above is what actually decides.
_WRITE_TOKENS: Tuple[str, ...] = (
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "truncate",
    "grant",
    "revoke",
    "merge",
    "call",
    "exec",
    "execute",
    "commit",
    "rollback",
    "savepoint",
    "vacuum",
    "reindex",
    "copy",
    "load",
    "into",
    "shutdown",
    "reconfigure",
)


def _strip_sql_noise(sql: str) -> str:
    """
    Remove comments and string/identifier literals.

    Both matter. Comments hide a second statement from a naive scan, and a
    literal legitimately containing the word ``delete`` (``WHERE name =
    'delete_me'``) would otherwise be read as a write.
    """
    text = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    text = re.sub(r"--[^\n]*", " ", text)
    text = re.sub(r"#[^\n]*", " ", text)
    text = re.sub(r"'(?:''|[^'])*'", " '' ", text)
    text = re.sub(r'"(?:""|[^"])*"', ' "" ', text)
    text = re.sub(r"`(?:``|[^`])*`", " `` ", text)
    return text


def assert_read_only(sql: str) -> None:
    """
    Refuse anything that is not a single read-only statement.

    Raises :class:`DatabaseConfigurationError` — a rule that asks the scanner
    to write is a defect in the rule, and the honest outcome is "this check
    could not be performed", never a verdict about the database.
    """
    raw = str(sql or "").strip()
    if not raw:
        raise DatabaseConfigurationError("the rule supplied an empty statement")

    cleaned = _strip_sql_noise(raw).strip()

    # A trailing semicolon is ordinary; a semicolon with anything after it is a
    # second statement, which is the classic way a read becomes a write.
    if ";" in cleaned.rstrip().rstrip(";"):
        raise DatabaseConfigurationError(
            "the rule supplied more than one SQL statement; a configuration "
            "read is exactly one read-only statement"
        )

    leader = (cleaned.split() or [""])[0].lower().lstrip("(")
    if leader not in _READ_ONLY_LEADERS:
        raise DatabaseConfigurationError(
            f"statement begins with {leader!r}; a configuration read must begin "
            f"with one of {', '.join(_READ_ONLY_LEADERS).upper()}"
        )

    words = set(re.findall(r"[a-z_]+", cleaned.lower()))
    offending = sorted(words & set(_WRITE_TOKENS))
    if offending:
        raise DatabaseConfigurationError(
            f"statement contains write or control keyword(s) "
            f"{', '.join(offending)}; a configuration read may not modify the "
            f"database or its transaction state"
        )


# ── Result ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class QueryResult:
    """
    The outcome of one statement, with success preserved.

    ``ok`` is what a caller branches on. It is deliberately not a truthiness
    test on ``rows``: a query that legitimately matches nothing (no account has
    an empty password — the answer a hardened server gives) is a successful
    read, and a query the server refused is not. Reading an empty ``rows`` as
    "nothing is wrong" is precisely the failure this dataclass exists to make
    impossible to write by accident.
    """

    statement: str
    rows: List[Tuple[Any, ...]] = field(default_factory=list)
    columns: Tuple[str, ...] = ()
    ok: bool = False
    error: str = ""
    #: Set where the statement could not be attempted at all — no session, the
    #: driver raised before the server saw it. Distinct from a statement the
    #: server ran and rejected.
    transport_error: str = ""

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def scalar(self) -> Any:
        """
        The first column of the first row, or None where there is no row.

        None here means "no row", which the collector renders as ABSENT — not
        as a value of NULL and never as an empty reading. A column whose value
        genuinely *is* SQL NULL is distinguished by ``row_count``.
        """
        if not self.rows:
            return None
        first = self.rows[0]
        return first[0] if first else None

    def failure_detail(self) -> str:
        """A one-line reason suitable for ``CollectedState.unavailable``."""
        if self.transport_error:
            return f"statement could not be executed: {self.transport_error}"
        detail = (self.error or "").strip().splitlines()
        first = detail[0][:300] if detail else ""
        return f"statement failed{f': {first}' if first else ' with no diagnostic'}"

    def rendered_rows(self, limit: int = 40) -> List[str]:
        """
        Rows flattened to one readable line each, for evidence.

        Capped because an offender list is evidence, not a data export: a
        misconfigured server can return thousands of rows and a finding whose
        evidence is a thousand lines is one nobody reads.
        """
        out: List[str] = []
        for row in self.rows[:limit]:
            out.append(" | ".join("" if v is None else str(v) for v in row))
        if len(self.rows) > limit:
            out.append(f"… and {len(self.rows) - limit} more")
        return out


# ── Session ──────────────────────────────────────────────────────────────────


class DatabaseSession:
    """
    One authenticated, read-only session with one database instance.

    Always used as a context manager so the connection is closed even when a
    check raises::

        with DatabaseSession(engine="postgresql", host=ip, username=u,
                             password=p) as db:
            result = db.query("SHOW ssl")

    **Not thread-safe, and used sequentially on purpose.** DB-API connections
    generally are not, and ``ConfigAuditEngine.run`` evaluates checks one after
    another against one context — so unlike the Phase 2 WinRM work there is no
    parallel section here to make thread-local. If a future phase parallelises
    the audit, give each thread its own session; do not share this one. That is
    the same conclusion Phase 2 reached the expensive way.
    """

    def __init__(
        self,
        *,
        engine: str,
        host: str,
        username: str,
        password: Optional[str] = None,
        port: Optional[int] = None,
        database: Optional[str] = None,
        timeout: int = 15,
        use_tls: Optional[bool] = None,
        verify_cert: bool = False,
        ca_cert: Optional[str] = None,
    ) -> None:
        resolved = normalize_engine(engine)
        if not resolved:
            raise DatabaseConfigurationError(
                f"database engine {engine!r} is not one of "
                f"{', '.join(SUPPORTED_ENGINES)}"
            )
        self.engine = resolved
        self.host = host
        self.username = username
        self._password = password
        self.port = int(port or DEFAULT_PORTS[resolved])
        self.database = database or self._default_database(resolved)
        self.timeout = int(timeout)
        #: None means "use TLS if the server offers it". This is deliberate:
        #: requiring TLS would make the scanner unable to connect to exactly the
        #: servers whose missing TLS is the finding worth reporting.
        self.use_tls = use_tls
        self.verify_cert = bool(verify_cert)
        #: The CA to verify the target's certificate against, when verification
        #: is asked for. Must come from the credential rather than the
        #: environment — see the note on ``sslrootcert`` in
        #: :meth:`_connect_postgresql`.
        self._ca_cert = ca_cert

        self._conn: Any = None
        self._server_version: str = ""
        self._server_banner: str = ""
        self._tls_in_use: Optional[bool] = None

    # ── Identity ─────────────────────────────────────────────────────────────

    @staticmethod
    def _default_database(engine: str) -> str:
        return {
            "postgresql": "postgres",
            "mysql": "mysql",
            "mssql": "master",
        }[engine]

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def server_version(self) -> str:
        """The engine's version, as ``os_version_id`` for check targeting."""
        return self._server_version

    @property
    def server_banner(self) -> str:
        """The engine's own version banner, verbatim, for the evidence record."""
        return self._server_banner

    @property
    def product_name(self) -> str:
        """
        A product string that always names the engine — the value to pass as
        ``CollectionContext.os_name``.

        **Not the raw banner.** PostgreSQL answers ``SELECT version()`` with
        "PostgreSQL 16.15 on x86_64…" and SQL Server with "Microsoft SQL
        Server 2022…", but MySQL answers with a bare ``8.0.46``. A check
        targeting ``os_name_contains: ["mysql"]`` against that matched nothing,
        so every MySQL rule reported NOT_APPLICABLE and the whole rule set
        silently never ran. Found by pointing the engine at a second database
        product; on PostgreSQL alone it looked correct.

        MariaDB is named separately even though it is driven by the MySQL
        driver and normalises to the ``mysql`` engine. Its version numbers are
        on their own series, so a rule comparing "MySQL 8.0 or later" against
        MariaDB 10.11 would read a supported release as ancient — the same
        cross-distribution mismatch ``os_match`` exists to prevent.
        """
        banner = self._server_banner
        lowered = banner.lower()
        if "mariadb" in lowered:
            return banner if lowered.startswith("mariadb") else f"MariaDB {banner}"
        label = {
            "postgresql": "PostgreSQL",
            "mysql": "MySQL",
            "mssql": "Microsoft SQL Server",
        }[self.engine]
        if not banner:
            return label
        return banner if label.lower() in lowered else f"{label} {banner}"

    @property
    def tls_in_use(self) -> Optional[bool]:
        """
        Whether *this* session negotiated TLS. None where it could not be
        established — which is not the same as False and must not be rendered
        as one.
        """
        return self._tls_in_use

    @property
    def connected(self) -> bool:
        return self._conn is not None

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def __enter__(self) -> "DatabaseSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()

    def connect(self) -> None:
        if self._conn is not None:
            return
        opener = {
            "postgresql": self._connect_postgresql,
            "mysql": self._connect_mysql,
            "mssql": self._connect_mssql,
        }[self.engine]
        try:
            opener()
        except DatabaseError:
            raise
        except Exception as exc:  # noqa: BLE001 — classified below
            raise self._classify(exc) from exc
        self._read_identity()

    def disconnect(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None:
            return
        try:
            conn.close()
        except Exception as exc:  # noqa: BLE001 — closing is best effort
            log.debug("Closing %s session to %s: %s", self.engine, self.endpoint, exc)

    # ── Drivers ──────────────────────────────────────────────────────────────
    #
    # Imported inside each opener rather than at module import. A driver that is
    # not installed must surface as a DatabaseConfigurationError naming the
    # package — a coverage gap someone can fix — and never as an ImportError
    # that stops the whole scan module loading.

    def _connect_postgresql(self) -> None:
        try:
            import psycopg2  # noqa: WPS433 — deliberate lazy import
            import psycopg2.extensions
        except ImportError as exc:
            raise DatabaseConfigurationError(
                "the psycopg2 driver is not installed, so PostgreSQL instances "
                "cannot be assessed by this scanner (pip install psycopg2-binary)"
            ) from exc

        self._conn = psycopg2.connect(
            host=self.host,
            port=self.port,
            user=self.username,
            password=self._password,
            dbname=self.database,
            connect_timeout=self.timeout,
            # `prefer` uses TLS when the server offers it and falls back when it
            # does not. `require` would refuse the servers whose missing TLS is
            # the finding; `verify-full` would additionally need a CA the
            # scanner has no way to obtain for an arbitrary customer database.
            sslmode="verify-full" if self.verify_cert else "prefer",
            # **Explicitly cleared, and this is not defensive style.** libpq
            # applies PGSSLROOTCERT from the environment to any connection that
            # does not set it, and `Backend/.env` sets it to this deployment's
            # own private CA for the application database. Importing anything
            # that loads config therefore put that CA on the scanner's path,
            # and every PostgreSQL *target* was verified against it — so a
            # customer instance with a perfectly good certificate from any
            # other issuer failed with "certificate verify failed", which reads
            # as a fault on the target.
            #
            # Note the asymmetry that made it hard to see: passing `sslmode`
            # explicitly *does* override PGSSLMODE, so the mode was right and
            # only the trust anchor was wrong. Under `prefer` libpq still
            # verifies once a root certificate is configured.
            sslrootcert=(str(self._ca_cert or "") if self.verify_cert else ""),
            application_name="ccure-audit",
        )
        self._conn.set_session(readonly=True, autocommit=True)

    def _connect_mysql(self) -> None:
        try:
            import pymysql  # noqa: WPS433 — deliberate lazy import
        except ImportError as exc:
            raise DatabaseConfigurationError(
                "the PyMySQL driver is not installed, so MySQL and MariaDB "
                "instances cannot be assessed by this scanner "
                "(pip install PyMySQL)"
            ) from exc

        kwargs: Dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "user": self.username,
            "password": self._password or "",
            "database": self.database,
            "connect_timeout": self.timeout,
            "read_timeout": self.timeout,
            "program_name": "ccure-audit",
        }

        # libpq-style `prefer`, implemented by hand because PyMySQL has no such
        # mode: it uses TLS only when a `ssl` argument is supplied, and plain
        # text otherwise.
        #
        # Both directions matter and each was reached by pointing this at a
        # real server. Without the TLS attempt, a correctly hardened instance
        # (`require_secure_transport = ON`) refuses the scanner outright, so
        # the databases with the best posture would be the ones this product
        # could not assess. Without the plaintext fallback, an instance with no
        # certificate — whose missing TLS is the finding most worth reporting —
        # could not be assessed either.
        attempts: List[Optional[Dict[str, Any]]] = []
        if self.use_tls is not False:
            attempts.append({"check_hostname": bool(self.verify_cert)})
        if not self.use_tls:
            attempts.append(None)

        last: Optional[Exception] = None
        for ssl_options in attempts:
            try:
                if ssl_options is None:
                    self._conn = pymysql.connect(**kwargs)
                else:
                    self._conn = pymysql.connect(**kwargs, ssl=ssl_options)
                break
            except Exception as exc:  # noqa: BLE001 — retried, then classified
                last = exc
                # A refused credential is refused over either transport, so
                # retrying in plaintext would only produce a second identical
                # rejection and a second entry in the server's failed-login
                # log. Only a transport-level failure is worth retrying.
                if isinstance(self._classify(exc), DatabaseAuthenticationError):
                    raise
        if self._conn is None:
            raise (
                last
                if last is not None
                else DatabaseConnectionError(
                    f"mysql at {self.endpoint} could not be reached"
                )
            )
        self._conn.autocommit(True)
        # Belt and braces behind assert_read_only: even a statement that got
        # past the allow-list cannot write in a read-only session. Best effort,
        # because a server too old to accept it should still be assessable —
        # the allow-list is the control, this is the backstop.
        try:
            with self._conn.cursor() as cursor:
                cursor.execute("SET SESSION TRANSACTION READ ONLY")
        except Exception as exc:  # noqa: BLE001 — advisory only
            log.debug(
                "Could not set a read-only session on mysql at %s: %s",
                self.endpoint,
                exc,
            )

    def _connect_mssql(self) -> None:
        try:
            import pymssql  # noqa: WPS433 — deliberate lazy import
        except ImportError as exc:
            raise DatabaseConfigurationError(
                "the pymssql driver is not installed, so Microsoft SQL Server "
                "instances cannot be assessed by this scanner "
                "(pip install pymssql)"
            ) from exc

        self._conn = pymssql.connect(
            server=self.host,
            port=str(self.port),
            user=self.username,
            password=self._password or "",
            database=self.database,
            login_timeout=self.timeout,
            timeout=self.timeout,
            appname="ccure-audit",
            autocommit=True,
            # The driver's own read-only intent, behind assert_read_only.
            read_only=True,
            # `request` negotiates TLS where the instance offers it and
            # proceeds without where it does not. `require` would refuse
            # exactly the instances whose missing encryption is the finding.
            encryption="off" if self.use_tls is False else "request",
        )

    # ── Identity read ────────────────────────────────────────────────────────

    def _read_identity(self) -> None:
        """
        Establish the engine's product string and version.

        These become ``CollectionContext.os_name`` / ``os_version_id``, so the
        Phase 4 ``os_match`` targeting written for "Ubuntu 22.04 versus RHEL 9"
        works unchanged for "PostgreSQL 16 versus MySQL 8". No second targeting
        mechanism, which is the whole reason this reuses those two fields
        rather than inventing ``db_engine``/``db_version`` alongside them.

        A failure here is not fatal. The session authenticated, so checks that
        do not name a version constraint can still run; the ones that do will
        report an error saying the version was not identified, which is the
        correct answer and not a verdict.
        """
        statement = {
            "postgresql": "SELECT version()",
            "mysql": "SELECT version()",
            "mssql": "SELECT @@VERSION",
        }[self.engine]
        result = self.query(statement)
        if not result.ok:
            log.warning(
                "Could not read the version banner from %s at %s: %s",
                self.engine,
                self.endpoint,
                result.failure_detail(),
            )
            return
        banner = str(result.scalar() or "").strip()
        self._server_banner = banner.splitlines()[0] if banner else ""
        match = re.search(r"(\d+(?:\.\d+)+)", self._server_banner)
        self._server_version = match.group(1) if match else ""
        self._tls_in_use = self._probe_tls_in_use()

    def _probe_tls_in_use(self) -> Optional[bool]:
        """
        Whether this session is encrypted, asked of the server rather than the
        driver. None where the engine cannot answer — never False by default,
        because "we could not tell" and "it is plaintext" are different facts
        and only one of them is a finding.
        """
        statement = {
            "postgresql": ("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"),
            "mysql": "SHOW STATUS LIKE 'Ssl_cipher'",
            "mssql": (
                "SELECT encrypt_option FROM sys.dm_exec_connections "
                "WHERE session_id = @@SPID"
            ),
        }[self.engine]
        result = self.query(statement)
        if not result.ok or not result.rows:
            return None
        if self.engine == "mysql":
            # SHOW STATUS returns (name, value); an empty value means no cipher
            # was negotiated, which is the plaintext case.
            row = result.rows[0]
            return bool(len(row) > 1 and str(row[1] or "").strip())
        value = result.scalar()
        if isinstance(value, bool):
            return value
        return str(value or "").strip().upper() in {"TRUE", "T", "ON", "1", "YES"}

    # ── Query ────────────────────────────────────────────────────────────────

    def query(
        self,
        statement: str,
        params: Optional[Sequence[Any]] = None,
        timeout: Optional[int] = None,
    ) -> QueryResult:
        """
        Run one read-only statement.

        Never raises for a server-side problem: a refused statement comes back
        as ``ok=False`` carrying the reason, which the collector turns into
        UNAVAILABLE and the engine turns into ERROR. Raising here would abort
        the audit of every remaining check because one of them was refused.
        """
        if self._conn is None:
            return QueryResult(
                statement=statement,
                transport_error="no authenticated session to the database",
            )
        try:
            assert_read_only(statement)
        except DatabaseConfigurationError as exc:
            return QueryResult(statement=statement, transport_error=str(exc))

        cursor = None
        try:
            cursor = self._conn.cursor()
            self._apply_statement_timeout(cursor, timeout)
            cursor.execute(statement, tuple(params) if params else None)
            columns = tuple(str(desc[0]) for desc in (cursor.description or ()))
            rows = [tuple(row) for row in (cursor.fetchall() or ())]
            return QueryResult(statement=statement, rows=rows, columns=columns, ok=True)
        except Exception as exc:  # noqa: BLE001 — reported, never raised
            classified = self._classify(exc, context="query")
            if isinstance(classified, DatabaseConnectionError):
                # A dropped connection is a transport problem, not a statement
                # the server rejected, and every remaining check will hit it
                # too. Saying so is what lets the collector report the right
                # reason rather than "statement failed" thirty times.
                #
                # Reached only on a *positive* connectivity match — see the
                # ``context`` argument to _classify. The fallback must not land
                # here: an ordinary SQL error on a healthy session (a catalogue
                # view this engine version does not have) would otherwise be
                # reported as an unreachable database, which is the four-types
                # collapse this module exists to prevent.
                return QueryResult(statement=statement, transport_error=str(classified))
            return QueryResult(statement=statement, error=str(exc))
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception as close_exc:  # noqa: BLE001 — best effort
                    # Logged rather than swallowed silently, but never raised:
                    # a failure to close the cursor must not replace whatever
                    # the statement itself was reporting.
                    log.debug(
                        "Closing cursor on %s at %s: %s",
                        self.engine,
                        self.endpoint,
                        close_exc,
                    )

    def _apply_statement_timeout(self, cursor: Any, timeout: Optional[int]) -> None:
        """
        Bound a single statement so one catalogue view on a very large instance
        cannot hold the audit open indefinitely.

        Best effort by design: an engine that will not accept the setting still
        gets the query, because refusing to run a check because its timeout
        could not be set would turn a minor limitation into an unassessed host.
        """
        seconds = int(timeout or self.timeout)
        if seconds <= 0:
            return
        try:
            if self.engine == "postgresql":
                # Session-scoped, not ``SET LOCAL``: the session runs with
                # autocommit on, so there is no surrounding transaction for a
                # LOCAL setting to belong to and PostgreSQL would discard it
                # with a warning — a timeout that looks set and is not.
                cursor.execute("SET statement_timeout = %s", (seconds * 1000,))
            elif self.engine == "mysql":
                cursor.execute("SET SESSION max_execution_time = %s", (seconds * 1000,))
        except Exception as exc:  # noqa: BLE001 — advisory only
            log.debug(
                "Could not set a statement timeout on %s at %s: %s",
                self.engine,
                self.endpoint,
                exc,
            )

    # ── Classification ───────────────────────────────────────────────────────

    def _classify(self, exc: Exception, *, context: str = "connect") -> DatabaseError:
        """
        Turn a driver exception into one a person can act on.

        Every driver here reports authentication, connectivity and privilege
        problems through its own exception hierarchy *and* through message
        text, and the hierarchies do not agree with each other. So the message
        is inspected as well as the type. Being wrong is cheap — the original
        exception is chained — while being vague is not: "database unreachable"
        for a rejected password sends someone to the firewall.

        ``context`` decides only what an *unrecognised* failure becomes, and
        the two answers are genuinely different facts:

        ``connect``
            No session was ever established, so whatever went wrong stopped the
            scanner reaching the instance. A connection error is the honest
            summary.

        ``query``
            The session is open and authenticated. An unrecognised failure here
            is the server rejecting one statement — a catalogue view this
            engine version does not have, a column renamed between releases —
            and it says nothing about reachability. Calling it a connection
            error would report an unreachable database that the scanner is at
            that moment connected to, and would send the reader to the firewall
            for a defect in a rule.
        """
        if isinstance(exc, DatabaseError):
            return exc

        text = str(exc).strip() or type(exc).__name__
        lowered = text.lower()

        # SQLSTATE 28xxx is "invalid authorization specification" across every
        # engine here, and it is checked first because it is the one signal all
        # three agree on.
        sqlstate = str(getattr(exc, "pgcode", "") or "")
        if sqlstate.startswith("28") or any(
            marker in lowered
            for marker in (
                "authentication failed",
                "password authentication",
                "access denied for user",
                "login failed for user",
                "invalid credential",
                "auth_plugin",
                "using password: no",
                "using password: yes",
                # PostgreSQL's refusal when no pg_hba line matches the client's
                # address, database, user and encryption state. The instance
                # answered and said no, so it is an authorisation refusal — the
                # first version classified it as a connection error, which sent
                # the reader to the firewall for a server that was listening,
                # reachable, and deliberately declining the connection.
                "no pg_hba.conf entry",
                "no pg_hba entry",
            )
        ):
            return DatabaseAuthenticationError(
                f"{self.engine} at {self.endpoint} rejected the credential for "
                f"{self.username!r}. Check the password, and that the account "
                f"is permitted to connect from this scanner's address "
                f"(pg_hba.conf, the MySQL host part of the account, or the SQL "
                f"Server login's state). ({text})"
            )

        # SQLSTATE 42501 / 42000 family: authenticated, but not allowed.
        if sqlstate.startswith("425") or any(
            marker in lowered
            for marker in (
                "permission denied",
                "insufficient privilege",
                "must be superuser",
                "must be a member of",
                "command denied",
                "access is denied",
                "is not allowed to",
                "requires membership",
                "the server principal",
            )
        ):
            return DatabasePermissionError(
                f"{self.engine} at {self.endpoint} accepted {self.username!r} "
                f"but refused the read. The account needs privileges to read "
                f"the server's configuration and account catalogues. ({text})"
            )

        if any(
            marker in lowered
            for marker in (
                "ssl",
                "tls",
                "certificate",
                "self signed",
                "self-signed",
            )
        ):
            return DatabaseConfigurationError(
                f"TLS negotiation with {self.engine} at {self.endpoint} failed: "
                f"{text}. A self-signed server certificate needs certificate "
                f"verification disabled for this credential, or its CA trusted "
                f"by the scanner."
            )

        if isinstance(exc, (socket.timeout, socket.gaierror, OSError)) or any(
            marker in lowered
            for marker in (
                "could not connect",
                "connection refused",
                "actively refused",
                "timed out",
                "timeout expired",
                "unreachable",
                "no route",
                "can't connect",
                "cannot connect",
                "connection reset",
                "server closed the connection",
                "name or service not known",
                "adaptive server",
                "is not currently available",
            )
        ):
            return DatabaseConnectionError(
                f"nothing answered {self.engine} at {self.endpoint}: {text}. "
                f"Confirm the instance is listening on this port, that it "
                f"accepts remote connections, and that the firewall permits it."
            )

        if context == "query":
            # Open session, unrecognised statement failure. Deliberately the
            # base class: it is not a connection problem, not an authentication
            # problem and not a privilege problem, and claiming any of those
            # would be an assertion nothing established.
            return DatabaseError(
                f"{self.engine} at {self.endpoint} refused the statement: {text}"
            )
        return DatabaseConnectionError(
            f"{self.engine} error against {self.endpoint}: {text}"
        )


#: The Python package each engine's driver lives in. Read at request time by
#: ``available_engines`` rather than imported here, so this module stays
#: importable in a build that installed none of them.
_DRIVER_MODULES: Dict[str, str] = {
    "postgresql": "psycopg2",
    "mysql": "pymysql",
    "mssql": "pymssql",
}


def available_engines() -> Dict[str, bool]:
    """
    Which supported engines this build can actually open a session with.

    The same principle as ``WINRM_AVAILABLE``: the API reports capability from
    the code rather than from a hardcoded list in the UI, so a deployment that
    did not install a driver cannot be offered a credential type it would then
    fail to use. A missing driver is a coverage gap someone can close with a
    pip install, and it should say so rather than appearing at scan time as an
    unreachable database.
    """
    import importlib.util

    return {
        engine: importlib.util.find_spec(module) is not None
        for engine, module in _DRIVER_MODULES.items()
    }
