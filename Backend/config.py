"""
config.py
─────────────────────────────────────────────────────────────────────────
Centralized configuration for CCure Audit PRO.
Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).absolute().parent
DEFAULT_SQLITE_DB = BACKEND_DIR / "ccure_users.db"


def _selected_env_file() -> Path:
    """
    Select the environment file to load.
    Prioritizes .env if it exists, falling back to .env.test.
    If explicitly in a test environment, checks for .env.test first.
    """
    app_env = os.getenv(
        "APP_ENV", os.getenv("ENVIRONMENT", os.getenv("ENV", "development"))
    ).lower()

    if app_env in {"test", "testing"}:
        test_env = BACKEND_DIR / ".env.test"
        if test_env.exists():
            return test_env

    # Default to .env if it exists, otherwise fall back to .env.test
    if (BACKEND_DIR / ".env").exists():
        return BACKEND_DIR / ".env"
    return BACKEND_DIR / ".env.test"


ENV_FILE = _selected_env_file()

if not os.getenv("SKIP_DOTENV_LOAD"):
    load_dotenv(dotenv_path=ENV_FILE, override=False)


def _normalize_database_url(database_url: str) -> str:
    """Resolve relative SQLite paths against the Backend directory."""
    if not database_url.startswith("sqlite:///"):
        return database_url

    raw_path = database_url.replace("sqlite:///", "", 1)
    if raw_path == ":memory:":
        return database_url

    sqlite_path = Path(raw_path)

    if not sqlite_path.is_absolute():
        sqlite_path = (BACKEND_DIR / sqlite_path).resolve()

    return f"sqlite:///{sqlite_path.as_posix()}"


class DatabaseConfig:
    """Database configuration with SQLite/PostgreSQL support."""

    DATABASE_URL: str = _normalize_database_url(
        os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_SQLITE_DB.as_posix()}")
    )

    @staticmethod
    def get_engine_kwargs():
        """Return engine kwargs based on database type."""
        if DatabaseConfig.DATABASE_URL.startswith("sqlite"):
            return {"connect_args": {"check_same_thread": False}}
        elif DatabaseConfig.DATABASE_URL.startswith("postgresql"):
            # PostgreSQL-specific optimizations
            return {
                "pool_pre_ping": True,  # Test connections before using
                "pool_size": 10,  # Connection pool size
                "max_overflow": 20,  # Additional connections allowed
                "pool_recycle": 3600,  # Recycle connections every hour
            }
        return {}


class JWTConfig:
    """JWT authentication configuration."""

    SECRET_KEY: str = os.getenv(
        "JWT_SECRET_KEY",
        "dev-secret-key-change-in-production",  # ⚠️ Never use in production
    )
    ACCESS_TOKEN_EXPIRES_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "30")
    )
    REFRESH_TOKEN_EXPIRES_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "7"))
    MFA_ENCRYPTION_KEY: str = os.getenv("MFA_ENCRYPTION_KEY", SECRET_KEY)


class ScanConfig:
    """Scan engine configuration."""

    NMAP_TIMEOUT: int = int(os.getenv("NMAP_TIMEOUT", "300"))
    NMAP_THREADS: int = int(os.getenv("NMAP_THREADS", "20"))
    MAX_NMAP_PROCESSES: int = int(os.getenv("MAX_NMAP_PROCESSES", "20"))
    NMAP_PROCESS_WAIT_TIMEOUT: int = int(os.getenv("NMAP_PROCESS_WAIT_TIMEOUT", "900"))
    NMAP_CACHE_ENABLED: bool = os.getenv("NMAP_CACHE_ENABLED", "True").lower() == "true"
    NMAP_CACHE_TTL_HOURS: int = int(os.getenv("NMAP_CACHE_TTL_HOURS", "72"))
    # A scan left in 'running' with nothing working on it. `task_time_limit`
    # above cannot cover this: Celery's hard time limit is implemented by
    # signalling a billiard worker process, so it is silently inert under the
    # `--pool=threads` worker this deployment runs on Windows -- and it can do
    # nothing at all about a worker that has died, been restarted, or is
    # failing before it reaches any of the task's own error handling.
    #
    # Measured against the deployment's own history: the slowest scan on
    # record is a /24 vulnerability audit at roughly 25 minutes. 90 minutes is
    # therefore well clear of a legitimately slow scan while still bounding a
    # stuck one to something an operator will sit through once, not forever.
    # Set to 0 to disable the sweep.
    SCAN_STALL_TIMEOUT_MINUTES: int = int(os.getenv("SCAN_STALL_TIMEOUT_MINUTES", "90"))
    # A scan that was accepted and queued but that no worker ever picked up.
    # Separate from the running timeout because it is a different fault with a
    # different message: "no scanner is running" rather than "the scan hung".
    SCAN_QUEUE_TIMEOUT_MINUTES: int = int(os.getenv("SCAN_QUEUE_TIMEOUT_MINUTES", "15"))
    SCAN_IP_BLACKLIST: str = os.getenv("SCAN_IP_BLACKLIST", "")
    PASSIVE_FIRST_DEFAULT: bool = (
        os.getenv("PASSIVE_FIRST_DEFAULT", "False").lower() == "true"
    )

    #: Whether a network probe may *change* the target rather than only observe
    #: it. Off, and it has to stay off by default.
    #:
    #: Exactly one probe is gated by this today — the FTP anonymous-write test,
    #: which creates and removes a directory on the scanned host. That is the
    #: only place in the product that writes to a target, and this product
    #: scans production and OT segments where an audit that changes something
    #: is worse than the finding it would have produced.
    #:
    #: A deployment-wide switch rather than a per-scan one, deliberately: there
    #: is no scan-policy engine yet (GAP-12), and inventing half of one here
    #: would be a second mechanism to reconcile when the real one arrives.
    #: ``core/checks/intrusive.py`` is the seam that policy will take over.
    SCAN_ALLOW_INTRUSIVE: bool = (
        os.getenv("SCAN_ALLOW_INTRUSIVE", "False").lower() == "true"
    )


class CeleryConfig:
    """Celery task queue configuration."""

    BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    WORKER_CONCURRENCY: int = int(
        os.getenv("SCANNER_WORKER_CONCURRENCY", os.getenv("NMAP_THREADS", "20"))
    )
    WORKER_PREFETCH_MULTIPLIER: int = int(
        os.getenv("SCANNER_WORKER_PREFETCH_MULTIPLIER", "1")
    )


#: Environment variables that explicitly configure the vulnerability-intel
#: database. If any of these is set, the dedicated database is what the user
#: asked for and DATABASE_URL must not silently take its place.
_VULN_DB_ENV_KEYS = (
    "VULN_DB_HOST",
    "VULN_DB_PORT",
    "VULN_DB_NAME",
    "VULN_DB_USER",
    "VULN_DB_PASSWORD",
)


class VulnIntelConfig:
    """
    Configuration for the dedicated vulnerability-intelligence database.

    Resolution order for the connection URL:

      1. ``VULNERABILITY_INTEL_DATABASE_URL`` — explicit, always wins.
      2. The ``VULN_DB_*`` settings, when any of them is set.
      3. ``DATABASE_URL`` — only when no vulnerability-specific configuration
         exists at all (single-database deployments, CI).

    Step 2 previously did not exist: the URL fell straight through to
    ``DATABASE_URL``, so a deployment that configured ``VULN_DB_NAME=vuln_intel``
    silently had every CVE query sent to the application database instead. The
    dedicated CVE database was never read, and because the application database
    has no ``cve`` table the connectivity probe failed and the scanner quietly
    dropped to the small bundled SQLite snapshot.
    """

    HOST: str = os.getenv("VULN_DB_HOST", os.getenv("PGHOST", "localhost"))
    PORT: int = int(os.getenv("VULN_DB_PORT", os.getenv("PGPORT", "5432")))
    DATABASE: str = os.getenv("VULN_DB_NAME", os.getenv("PGDATABASE", "ccure_test"))
    USER: str = os.getenv("VULN_DB_USER", os.getenv("PGUSER", "ccure_user"))
    PASSWORD: str = os.getenv(
        "VULN_DB_PASSWORD", os.getenv("PGPASSWORD", "ccure_admin_2026")
    )

    # TLS settings for the assembled URL.
    #
    # These exist so TLS can be applied without hardcoding a host, which is the
    # mistake that broke this: an explicit
    # VULNERABILITY_INTEL_DATABASE_URL=…@127.0.0.1… was added to Backend/.env to
    # carry sslmode. That file is read by the host worker *and* by the API
    # container, and inside the container 127.0.0.1 is the container — so the
    # connection was refused and `core.cve_lookup` fell back to a stale bundled
    # SQLite file. Vulnerability data silently degraded with only an INFO line
    # to show it.
    #
    # Assembling the URL from VULN_DB_HOST instead means each side uses the
    # address that is correct for it (host.docker.internal in the container,
    # localhost on the host) and both still get verified TLS.
    SSLMODE: str = os.getenv("VULN_DB_SSLMODE", os.getenv("PGSSLMODE", ""))
    SSLROOTCERT: str = os.getenv("VULN_DB_SSLROOTCERT", os.getenv("PGSSLROOTCERT", ""))

    @staticmethod
    def is_explicitly_configured() -> bool:
        """True when the deployment names a dedicated CVE database."""
        return any(os.getenv(key) for key in _VULN_DB_ENV_KEYS)

    @staticmethod
    def _tls_query() -> str:
        """`?sslmode=…&sslrootcert=…`, or empty when TLS is not configured."""
        params = []
        if VulnIntelConfig.SSLMODE:
            params.append(f"sslmode={VulnIntelConfig.SSLMODE}")
        if VulnIntelConfig.SSLROOTCERT:
            # Forward slashes only: libpq treats a backslash as an escape inside
            # a connection URI, so C:\path\root.crt silently becomes C:pathroot.crt.
            cert = VulnIntelConfig.SSLROOTCERT.replace("\\", "/")
            params.append(f"sslrootcert={cert}")
        return ("?" + "&".join(params)) if params else ""

    @staticmethod
    def database_url() -> str:
        explicit_url = os.getenv("VULNERABILITY_INTEL_DATABASE_URL")
        if explicit_url:
            return explicit_url

        if VulnIntelConfig.is_explicitly_configured():
            return (
                f"postgresql://{VulnIntelConfig.USER}:{VulnIntelConfig.PASSWORD}"
                f"@{VulnIntelConfig.HOST}:{VulnIntelConfig.PORT}"
                f"/{VulnIntelConfig.DATABASE}{VulnIntelConfig._tls_query()}"
            )

        shared_url = os.getenv("DATABASE_URL")
        if shared_url:
            return shared_url

        return (
            f"postgresql://{VulnIntelConfig.USER}:{VulnIntelConfig.PASSWORD}"
            f"@{VulnIntelConfig.HOST}:{VulnIntelConfig.PORT}/{VulnIntelConfig.DATABASE}"
            f"{VulnIntelConfig._tls_query()}"
        )


class WebScanConfig:
    """Web Application Scanning (DAST) configuration."""

    # ── External Tool Binaries ────────────────────────────────────────────────
    NUCLEI_BINARY: str = os.getenv("NUCLEI_BINARY", "nuclei")
    NUCLEI_TEMPLATES_DIR: str = os.getenv(
        "NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates"
    )
    SUBFINDER_BINARY: str = os.getenv("SUBFINDER_BINARY", "subfinder")
    FFUF_BINARY: str = os.getenv("FFUF_BINARY", "ffuf")
    FFUF_WORDLIST: str = os.getenv("FFUF_WORDLIST", "/opt/wordlists/common.txt")
    SQLMAP_BINARY: str = os.getenv("SQLMAP_BINARY", "sqlmap")

    # ── Playwright / Crawling ─────────────────────────────────────────────────
    PLAYWRIGHT_TIMEOUT: int = int(os.getenv("PLAYWRIGHT_TIMEOUT", "60000"))  # ms
    MAX_CRAWL_DEPTH: int = int(os.getenv("MAX_CRAWL_DEPTH", "5"))
    MAX_CRAWL_URLS: int = int(os.getenv("MAX_CRAWL_URLS", "500"))
    CRAWL_CONCURRENCY: int = int(os.getenv("CRAWL_CONCURRENCY", "3"))
    #: Per-page budget for client-side rendering to settle after the document
    #: loads. Bounded on purpose: an application holding a websocket or polling
    #: open never reaches network idle, and waiting the full page timeout on
    #: each URL is what turns a few hundred pages into an overnight crawl.
    CRAWL_SETTLE_TIMEOUT: int = int(os.getenv("CRAWL_SETTLE_TIMEOUT", "5000"))  # ms

    # ── Scan Limits ───────────────────────────────────────────────────────────
    WEB_SCAN_TIMEOUT: int = int(os.getenv("WEB_SCAN_TIMEOUT", "14400"))  # 4 hours
    SCAN_RATE_LIMIT: int = int(os.getenv("WEB_SCAN_RATE_LIMIT", "5"))  # req/sec
    STEALTH_RATE_LIMIT: int = int(
        os.getenv("WEB_STEALTH_RATE_LIMIT", "2")
    )  # req/sec (WAF mode)
    MAX_RESPONSE_BODY_SIZE: int = int(
        os.getenv("MAX_RESPONSE_BODY_SIZE", "10240")
    )  # 10KB evidence cap

    # ── Out-of-Band (OAST) Detection ──────────────────────────────────────────
    # Blind SSRF, blind SQL injection and out-of-band RCE produce no difference
    # in the HTTP response — the only evidence is a callback the payload causes
    # the target to make to a server the scanner controls. Without one, those
    # classes cannot be detected at all, and a scan that does not test for them
    # must not be read as having cleared them.
    #
    # Nuclei defaults to ProjectDiscovery's public interact.sh, which requires
    # outbound internet from the scanner and sends interaction metadata to a
    # third party. Both are frequently unacceptable, so this is explicit:
    # set OAST_SERVER to a self-hosted interactsh, or set OAST_ENABLED=False to
    # turn it off deliberately. Either way the scan reports which it was.
    OAST_ENABLED: bool = os.getenv("OAST_ENABLED", "True").lower() == "true"
    OAST_SERVER: str = os.getenv("OAST_SERVER", "")
    OAST_TOKEN: str = os.getenv("OAST_TOKEN", "")

    # ── Nuclei Specific ───────────────────────────────────────────────────────
    NUCLEI_SEVERITY: str = os.getenv("NUCLEI_SEVERITY", "medium,high,critical")
    NUCLEI_CONCURRENCY: int = int(os.getenv("NUCLEI_CONCURRENCY", "25"))
    NUCLEI_BULK_SIZE: int = int(os.getenv("NUCLEI_BULK_SIZE", "25"))
    NUCLEI_TIMEOUT: int = int(os.getenv("NUCLEI_TIMEOUT", "7200"))  # 2 hours

    # ── SQLMap Specific ───────────────────────────────────────────────────────
    # Level 3, not 2. Verified against OWASP Juice Shop: the injectable search
    # parameter that level 3 finds (boolean-based blind on `q`) is missed
    # entirely at level 2. Level controls how many places per parameter sqlmap
    # tests — cookies and headers enter at 2, the fuller payload set at 3 — so a
    # level-2 scan reporting "not injectable" was frequently a scan that did not
    # test the payload the injection needed. For a tool whose entire job is
    # finding injection, testing too shallow to find it is the wrong default.
    SQLMAP_LEVEL: int = int(os.getenv("SQLMAP_LEVEL", "3"))
    SQLMAP_RISK: int = int(os.getenv("SQLMAP_RISK", "2"))
    SQLMAP_TIMEOUT: int = int(os.getenv("SQLMAP_TIMEOUT", "600"))  # 10 min per URL


class AdminConfig:
    """Default administrator account configuration."""

    EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "")
    PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "")


class EmailConfig:
    """SMTP and password reset email configuration."""

    SMTP_HOST: str = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "1025"))
    SMTP_USER: str | None = os.getenv("SMTP_USER", None) or None
    SMTP_PASSWORD: str | None = os.getenv("SMTP_PASSWORD", None) or None
    SMTP_SECURE: bool = os.getenv("SMTP_SECURE", "False").lower() == "true"
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "no-reply@ccureaudit.pro")
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")


class AccountSecurityConfig:
    """
    Gates on the account lifecycle.

    Both defaults are the restrictive ones. A deployment that wants open
    self-service has to say so out loud in its environment, because the failure
    mode of the permissive default is silent: registration keeps working and
    nobody notices that strangers can execute network scans.
    """

    # Master switch for POST /auth/register. Off by default: admin-provisioned
    # accounts (POST /admin/users) are the supported onboarding path.
    ALLOW_SELF_REGISTRATION: bool = (
        os.getenv("ALLOW_SELF_REGISTRATION", "False").lower() == "true"
    )

    # When self-registration is on, may a verified account log in before an
    # admin approves it? Off means email verification alone never yields a
    # session.
    SELF_REGISTRATION_AUTO_APPROVE: bool = (
        os.getenv("SELF_REGISTRATION_AUTO_APPROVE", "False").lower() == "true"
    )

    # Long enough to survive greylisting and a night's sleep; short enough that
    # a link leaked from a mailbox archive is usually already dead.
    EMAIL_VERIFICATION_TTL_HOURS: int = int(
        os.getenv("EMAIL_VERIFICATION_TTL_HOURS", "24")
    )

    # Unverified accounts are personal data with no purpose. Purged after this
    # many days by ccure.tasks.purge_stale_unverified_accounts.
    UNVERIFIED_ACCOUNT_TTL_DAYS: int = int(
        os.getenv("UNVERIFIED_ACCOUNT_TTL_DAYS", "7")
    )

    # When no Celery worker is consuming the mail queue, send the message from
    # the web process instead of publishing it to a queue nobody is reading.
    #
    # On by default because the alternative is a silent hole: `.delay()`
    # succeeds whenever Redis is up, so with the host worker stopped
    # registration returned 202, committed the token, and sent nothing. Turn it
    # off only to reproduce that older behaviour — the test suite does, so that
    # dispatch stays assertable via `.delay`.
    MAIL_INLINE_FALLBACK: bool = (
        os.getenv("MAIL_INLINE_FALLBACK", "True").lower() == "true"
    )


class EmailDomainGuardConfig:
    """
    Disposable / throwaway email domain screening.

    Measured before this was written: of the two temp-mail domains that reached
    the approval queue on 18 Aug 2026, the canonical `disposable-email-domains`
    list contained *neither*, and merging three lists (93k domains) still only
    caught one. A blocklist is therefore necessary and roughly half the answer;
    the other half is a risk verdict rendered to the human who approves the
    account. That is why `flag` is a first-class mode and not a debug setting.
    """

    # off     — the guard does nothing, and no verdict is computed.
    # flag    — verdicts are computed and recorded, nothing is ever refused.
    # enforce — a confirmed-disposable domain is refused at account creation.
    #
    # `enforce` is the default because refusing a known throwaway domain is the
    # point of the feature. `flag` exists for a staged rollout: run it for a
    # week, read the audit log, then flip. Both modes write the same verdict, so
    # the only difference is whether registration stops.
    MODE: str = os.getenv("EMAIL_DOMAIN_GUARD_MODE", "enforce").strip().lower()

    # How long a loaded rule set / corpus is trusted before the next request
    # re-reads it. The corpus is ~93k rows; re-reading it per request would put
    # a table scan on the login path for no benefit.
    CACHE_TTL_SECONDS: int = int(os.getenv("EMAIL_DOMAIN_CACHE_TTL_SECONDS", "300"))

    # The deferred half of the pipeline: MX presence and RDAP domain age. These
    # are network calls against a domain the *caller* chose, so they never run
    # inline — see auth/email_domain_guard.py. Turn off in an air-gapped
    # deployment; the blocklist half keeps working.
    ENRICHMENT_ENABLED: bool = (
        os.getenv("EMAIL_RISK_ENRICHMENT_ENABLED", "True").lower() == "true"
    )
    DNS_TIMEOUT_SECONDS: float = float(os.getenv("EMAIL_RISK_DNS_TIMEOUT", "3"))
    RDAP_TIMEOUT_SECONDS: float = float(os.getenv("EMAIL_RISK_RDAP_TIMEOUT", "5"))

    # A domain younger than this is *flagged*, never blocked. Deliberately not a
    # block rule: radiant-flow.org was 17 months old and still a throwaway, and
    # plenty of legitimate companies register a domain the week they incorporate.
    MIN_DOMAIN_AGE_DAYS: int = int(os.getenv("EMAIL_RISK_MIN_DOMAIN_AGE_DAYS", "90"))

    # Volume controls. The per-minute limiter (3/minute, slowapi) stops a burst;
    # these stop a patient bot. /auth/register also sends mail to an address the
    # caller chose, so the daily cap bounds the relay surface too.
    REGISTRATION_DAILY_IP_LIMIT: int = int(
        os.getenv("REGISTRATION_DAILY_IP_LIMIT", "10")
    )

    # The approval queue is an administrator's attention budget and it is
    # finite. Past this many pending accounts, registration is refused until
    # someone drains it. 0 disables the ceiling.
    PENDING_QUEUE_LIMIT: int = int(os.getenv("PENDING_APPROVAL_QUEUE_LIMIT", "200"))

    # A *verified* account that no admin ever approved is not covered by
    # UNVERIFIED_ACCOUNT_TTL_DAYS — purge_stale_unverified_accounts filters on
    # is_verified=False, and temp-mail users do click the verification link.
    # Without this TTL the queue only ever grows.
    UNAPPROVED_ACCOUNT_TTL_DAYS: int = int(
        os.getenv("UNAPPROVED_ACCOUNT_TTL_DAYS", "30")
    )

    # Sync safety. A source returning an empty body or an error page must not be
    # able to empty the corpus — that failure reads exactly like a clean run.
    SYNC_MIN_ROWS_PER_SOURCE: int = int(
        os.getenv("DISPOSABLE_SYNC_MIN_ROWS_PER_SOURCE", "500")
    )
    # A domain is retired only after being absent from every source across this
    # many consecutive successful syncs.
    SYNC_RETIRE_AFTER_MISSES: int = int(
        os.getenv("DISPOSABLE_RETIRE_AFTER_MISSES", "3")
    )


class AppConfig:
    """Application-wide configuration."""

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── Trusted proxies for client IP resolution ─────────────────────────────
    #
    # This list decides which hops are allowed to *speak about* the client
    # address, so it is a security control, not a logging convenience: the
    # resolved address is the rate-limiting bucket key and the value written to
    # the audit trail.
    #
    # The default used to include 10.0.0.0/8 and 192.168.0.0/16. This
    # deployment's own clients live at 10.180.6.0/24 — inside 10.0.0.0/8 — so
    # every real client was classified as a trusted proxy and skipped by the
    # chain walk. The correct address still came back, but only through the
    # "all hops trusted, take the leftmost" fallback, and the leftmost entry is
    # exactly the one a client controls if any hop ever appends instead of
    # overwriting X-Forwarded-For. It worked by luck of the topology, not by
    # design.
    #
    # List only the addresses of actual reverse proxies. Here that is host
    # nginx, which the API container sees as the Docker bridge gateway, plus
    # loopback for a direct local call. If you put a load balancer or WAF in
    # front, add *its* address — never the network your users sit on.
    TRUSTED_PROXIES: list = [
        ip.strip()
        for ip in os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1,172.16.0.0/12").split(",")
        if ip.strip()
    ]

    # ── Rate limiting ────────────────────────────────────────────────────────
    #
    # Per-endpoint limits are declared with @limiter.limit on the routes that
    # need them. These three settings cover what a decorator cannot.

    # Baseline ceiling applied to every API route that carries no explicit
    # limit of its own, per client IP. Deliberately generous — this is a
    # backstop against a runaway client or a scripted sweep, not a usability
    # tax, and the endpoints that need a real limit already have one. Set to an
    # empty string to disable the baseline entirely.
    #
    # Sized per *IP*, and an office behind one NAT address shares the bucket,
    # so it has to clear a whole floor of analysts using the dashboard at once.
    API_DEFAULT_RATE_LIMIT: str = os.getenv("API_DEFAULT_RATE_LIMIT", "600/minute")

    # Paths the baseline never applies to. Matched exactly unless the entry
    # ends in "*", which makes the text before it a prefix.
    #
    # "/" is this API's health endpoint and is polled by monitoring at a rate
    # that has nothing to do with abuse. Note it must be an *exact* entry — as
    # a prefix it would exempt the whole application, which is why the
    # middleware does not treat entries as prefixes by default.
    API_RATE_LIMIT_EXEMPT_PATHS: list = [
        p.strip()
        for p in os.getenv(
            "API_RATE_LIMIT_EXEMPT_PATHS",
            "/,/docs*,/redoc*,/openapi.json",
        ).split(",")
        if p.strip()
    ]

    # What happens to rate limiting when Redis is unreachable.
    #
    # Before this existed the answer was "every limited endpoint returns 500":
    # slowapi is constructed with swallow_errors=False, so a storage failure
    # propagated out of the decorator and login, registration and every scan
    # endpoint broke outright. That is not fail-closed in any useful sense — it
    # is an outage.
    #
    # With an in-memory fallback the limits keep being enforced from process
    # memory during the outage. Two caveats, both acceptable: the counters are
    # per worker process, so the effective limit is multiplied by the worker
    # count, and slowapi applies *these* limits in place of the per-route ones
    # while the fallback is active. It is a degraded control, not the absence
    # of one. Set empty to restore the old raise-on-failure behaviour.
    RATE_LIMIT_MEMORY_FALLBACK: str = os.getenv(
        "RATE_LIMIT_MEMORY_FALLBACK", "20/minute"
    )

    # ── Password-recovery anti-automation ────────────────────────────────────
    #
    # Two different abuses, so two different counters.
    #
    # PASSWORD_RESET_IP_HOURLY_LIMIT bounds token guessing. The token is 32
    # random bytes, so guessing it is not the realistic threat; what this
    # actually buys is that a script hammering /auth/reset-password shows up as
    # 429s in the audit trail instead of as unbounded 400s that nobody counts.
    #
    # PASSWORD_RESET_ACCOUNT_HOURLY_LIMIT bounds mail bombing. /auth/forgot-
    # password sends a message to an address the caller names, and the per-IP
    # limit does nothing about a caller who rotates addresses, so this one is
    # keyed on the *target account*. Set either to 0 to disable.
    PASSWORD_RESET_IP_HOURLY_LIMIT: int = int(
        os.getenv("PASSWORD_RESET_IP_HOURLY_LIMIT", "20")
    )
    PASSWORD_RESET_ACCOUNT_HOURLY_LIMIT: int = int(
        os.getenv("PASSWORD_RESET_ACCOUNT_HOURLY_LIMIT", "5")
    )

    # How long an expired refresh-token session row is kept before being swept.
    #
    # Not the same thing as the token's own 7-day lifetime: the row stops being
    # usable at expires_at, and this is how long the *record* of it survives
    # afterwards. 90 days keeps a full quarter of sign-in history for anyone
    # investigating an incident, while stopping a table that grows by ~48 rows
    # per signed-in user per day from growing forever. 0 disables the sweep.
    REFRESH_SESSION_RETENTION_DAYS: int = int(
        os.getenv("REFRESH_SESSION_RETENTION_DAYS", "90")
    )

    # ── Audit-trail export ───────────────────────────────────────────────────
    #
    # Two caps, deliberately independent of each other.
    #
    # The CSV cap bounds an evidence extract. It is a hard refusal, not a
    # truncation: an export that silently stops at the limit produces a file
    # that looks complete, and "this person did nothing after 14:00" is exactly
    # the wrong conclusion for a truncated audit extract to invite. Over the
    # cap the endpoint answers 413 naming the count, and the caller narrows the
    # date range.
    #
    # The PDF cap is much lower and is not a smaller version of the same
    # number. 50,000 rows is a reasonable machine-readable extract and an
    # unreadable document; the PDF is a summary somebody actually looks at, and
    # rendering it is CPU and memory inside the request.
    AUDIT_EXPORT_MAX_ROWS: int = int(os.getenv("AUDIT_EXPORT_MAX_ROWS", "50000"))
    AUDIT_EXPORT_PDF_MAX_ROWS: int = int(os.getenv("AUDIT_EXPORT_PDF_MAX_ROWS", "5000"))

    # Rows fetched per keyset page while streaming. Bounds the memory the
    # export holds at once — the whole point of paginating rather than
    # materialising the capped set — without making the round trips dominate.
    AUDIT_EXPORT_PAGE_SIZE: int = int(os.getenv("AUDIT_EXPORT_PAGE_SIZE", "1000"))

    # ── Audit-trail retention (phase 6a: legacy rows only) ───────────────────
    #
    # **Ships disabled and must stay disabled** until a retention period is
    # agreed with the business/compliance owner. 0 means no purge runs at all;
    # it is not a placeholder for "we will pick a number later in code". ISO
    # 27001 A.5.33 and A.8.15 require a *defined* period and do not supply one,
    # so inventing one here would be inventing a compliance position.
    AUDIT_LOG_RETENTION_DAYS: int = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "0"))

    # A floor the code refuses to go below whatever the environment says.
    # AUDIT_LOG_RETENTION_DAYS is an operator-supplied number and a typo in it
    # ("9" for "90") is unrecoverable — audit rows do not come back. This is
    # the guard that makes the typo an error rather than a data loss.
    AUDIT_RETENTION_MIN_DAYS: int = int(os.getenv("AUDIT_RETENTION_MIN_DAYS", "90"))

    # One transaction per batch, never one for the whole run: the purge holds
    # the organisation's chain-head lock for the duration of a batch, and a
    # run-long transaction would block every audit write in that tenant until
    # it finished.
    AUDIT_RETENTION_BATCH_SIZE: int = int(
        os.getenv("AUDIT_RETENTION_BATCH_SIZE", "1000")
    )

    # A ceiling per invocation. Retention runs daily, so a backlog drains over
    # several nights rather than in one very long transaction sequence — and a
    # misconfiguration removes at most this many rows before anyone looks.
    AUDIT_RETENTION_MAX_ROWS_PER_RUN: int = int(
        os.getenv("AUDIT_RETENTION_MAX_ROWS_PER_RUN", "50000")
    )

    # A purge is irreversible and `archive_mode` is off on this deployment, so
    # recovery granularity is "since the last dump". The purge refuses to run
    # without one this recent. 0 disables the check, and that fact is logged
    # loudly rather than passing silently.
    AUDIT_RETENTION_REQUIRE_BACKUP_HOURS: int = int(
        os.getenv("AUDIT_RETENTION_REQUIRE_BACKUP_HOURS", "24")
    )

    # Where backup_db.ps1 writes. Read only to check the age of the newest
    # dump; nothing here ever writes to or prunes this directory.
    AUDIT_RETENTION_BACKUP_DIR: str = os.getenv(
        "AUDIT_RETENTION_BACKUP_DIR", str(BACKEND_DIR.parent / "backups")
    )

    # Dry run is the default everywhere: the task, the CLI and the function all
    # default to reporting what they would delete and writing nothing at all.
    AUDIT_RETENTION_DRY_RUN: bool = (
        os.getenv("AUDIT_RETENTION_DRY_RUN", "True").lower() == "true"
    )

    # Database
    DATABASE_URL = DatabaseConfig.DATABASE_URL
    DATABASE_ENGINE_KWARGS = DatabaseConfig.get_engine_kwargs()

    # JWT
    JWT_SECRET_KEY = JWTConfig.SECRET_KEY
    ACCESS_TOKEN_EXPIRES_MINUTES = JWTConfig.ACCESS_TOKEN_EXPIRES_MINUTES
    REFRESH_TOKEN_EXPIRES_DAYS = JWTConfig.REFRESH_TOKEN_EXPIRES_DAYS
    MFA_ENCRYPTION_KEY = JWTConfig.MFA_ENCRYPTION_KEY

    # Derived Fernet key (32 bytes urlsafe base64 encoded)
    MFA_KEY: bytes = (
        lambda key=JWTConfig.MFA_ENCRYPTION_KEY: (
            __import__("base64").urlsafe_b64encode(
                __import__("hashlib").sha256(key.encode()).digest()
            )
        )
    )()

    # Scans
    NMAP_TIMEOUT = ScanConfig.NMAP_TIMEOUT
    NMAP_THREADS = ScanConfig.NMAP_THREADS
    MAX_NMAP_PROCESSES = ScanConfig.MAX_NMAP_PROCESSES
    NMAP_PROCESS_WAIT_TIMEOUT = ScanConfig.NMAP_PROCESS_WAIT_TIMEOUT
    NMAP_CACHE_ENABLED = ScanConfig.NMAP_CACHE_ENABLED
    NMAP_CACHE_TTL_HOURS = ScanConfig.NMAP_CACHE_TTL_HOURS
    SCAN_STALL_TIMEOUT_MINUTES = ScanConfig.SCAN_STALL_TIMEOUT_MINUTES
    SCAN_QUEUE_TIMEOUT_MINUTES = ScanConfig.SCAN_QUEUE_TIMEOUT_MINUTES

    # OT safety config
    PASSIVE_FIRST_DEFAULT = ScanConfig.PASSIVE_FIRST_DEFAULT
    SCAN_ALLOW_INTRUSIVE = ScanConfig.SCAN_ALLOW_INTRUSIVE
    SCAN_IP_BLACKLIST: list = []
    _raw_blacklist = ScanConfig.SCAN_IP_BLACKLIST
    if _raw_blacklist:
        import ipaddress

        for _item in _raw_blacklist.split(","):
            _item = _item.strip()
            if _item:
                try:
                    SCAN_IP_BLACKLIST.append(ipaddress.ip_network(_item, strict=False))
                except ValueError:
                    pass

    # Celery
    CELERY_BROKER_URL = CeleryConfig.BROKER_URL
    CELERY_RESULT_BACKEND = CeleryConfig.RESULT_BACKEND
    SCANNER_WORKER_CONCURRENCY = CeleryConfig.WORKER_CONCURRENCY
    SCANNER_WORKER_PREFETCH_MULTIPLIER = CeleryConfig.WORKER_PREFETCH_MULTIPLIER

    # Vulnerability intelligence
    VULN_DB_HOST = VulnIntelConfig.HOST
    VULN_DB_PORT = VulnIntelConfig.PORT
    VULN_DB_NAME = VulnIntelConfig.DATABASE
    VULN_DB_USER = VulnIntelConfig.USER
    VULN_DB_PASSWORD = VulnIntelConfig.PASSWORD
    VULN_DB_URL = VulnIntelConfig.database_url()

    # Initial Admin Seed
    DEFAULT_ADMIN_EMAIL = AdminConfig.EMAIL
    DEFAULT_ADMIN_PASSWORD = AdminConfig.PASSWORD

    # Email / SMTP Config
    SMTP_HOST = EmailConfig.SMTP_HOST
    SMTP_PORT = EmailConfig.SMTP_PORT
    SMTP_USER = EmailConfig.SMTP_USER
    SMTP_PASSWORD = EmailConfig.SMTP_PASSWORD
    SMTP_SECURE = EmailConfig.SMTP_SECURE
    SMTP_FROM_EMAIL = EmailConfig.SMTP_FROM_EMAIL
    FRONTEND_URL = EmailConfig.FRONTEND_URL

    # Account lifecycle gates
    ALLOW_SELF_REGISTRATION = AccountSecurityConfig.ALLOW_SELF_REGISTRATION
    SELF_REGISTRATION_AUTO_APPROVE = (
        AccountSecurityConfig.SELF_REGISTRATION_AUTO_APPROVE
    )
    EMAIL_VERIFICATION_TTL_HOURS = AccountSecurityConfig.EMAIL_VERIFICATION_TTL_HOURS
    UNVERIFIED_ACCOUNT_TTL_DAYS = AccountSecurityConfig.UNVERIFIED_ACCOUNT_TTL_DAYS
    MAIL_INLINE_FALLBACK = AccountSecurityConfig.MAIL_INLINE_FALLBACK

    # Disposable / throwaway email domain screening
    EMAIL_DOMAIN_GUARD_MODE = EmailDomainGuardConfig.MODE
    EMAIL_DOMAIN_CACHE_TTL_SECONDS = EmailDomainGuardConfig.CACHE_TTL_SECONDS
    EMAIL_RISK_ENRICHMENT_ENABLED = EmailDomainGuardConfig.ENRICHMENT_ENABLED
    EMAIL_RISK_DNS_TIMEOUT_SECONDS = EmailDomainGuardConfig.DNS_TIMEOUT_SECONDS
    EMAIL_RISK_RDAP_TIMEOUT_SECONDS = EmailDomainGuardConfig.RDAP_TIMEOUT_SECONDS
    EMAIL_RISK_MIN_DOMAIN_AGE_DAYS = EmailDomainGuardConfig.MIN_DOMAIN_AGE_DAYS
    REGISTRATION_DAILY_IP_LIMIT = EmailDomainGuardConfig.REGISTRATION_DAILY_IP_LIMIT
    PENDING_APPROVAL_QUEUE_LIMIT = EmailDomainGuardConfig.PENDING_QUEUE_LIMIT
    UNAPPROVED_ACCOUNT_TTL_DAYS = EmailDomainGuardConfig.UNAPPROVED_ACCOUNT_TTL_DAYS
    DISPOSABLE_SYNC_MIN_ROWS_PER_SOURCE = (
        EmailDomainGuardConfig.SYNC_MIN_ROWS_PER_SOURCE
    )
    DISPOSABLE_RETIRE_AFTER_MISSES = EmailDomainGuardConfig.SYNC_RETIRE_AFTER_MISSES

    # Scan authorisation. When True an organisation with no configured scope
    # (scan_scope_cidrs IS NULL) cannot scan at all, rather than falling back
    # to unrestricted. Left False so this ships without breaking existing orgs;
    # set it True once every org has a scope. See core/scan_scope.py.
    REQUIRE_SCAN_SCOPE: bool = (
        os.getenv("REQUIRE_SCAN_SCOPE", "False").lower() == "true"
    )

    @staticmethod
    def is_sqlite() -> bool:
        """Check if using SQLite database."""
        return AppConfig.DATABASE_URL.startswith("sqlite")

    @staticmethod
    def is_postgresql() -> bool:
        """Check if using PostgreSQL database."""
        return AppConfig.DATABASE_URL.startswith("postgresql")
