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
    SCAN_IP_BLACKLIST: str = os.getenv("SCAN_IP_BLACKLIST", "")
    PASSIVE_FIRST_DEFAULT: bool = (
        os.getenv("PASSIVE_FIRST_DEFAULT", "False").lower() == "true"
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

    @staticmethod
    def is_explicitly_configured() -> bool:
        """True when the deployment names a dedicated CVE database."""
        return any(os.getenv(key) for key in _VULN_DB_ENV_KEYS)

    @staticmethod
    def database_url() -> str:
        explicit_url = os.getenv("VULNERABILITY_INTEL_DATABASE_URL")
        if explicit_url:
            return explicit_url

        if VulnIntelConfig.is_explicitly_configured():
            return (
                f"postgresql://{VulnIntelConfig.USER}:{VulnIntelConfig.PASSWORD}"
                f"@{VulnIntelConfig.HOST}:{VulnIntelConfig.PORT}"
                f"/{VulnIntelConfig.DATABASE}"
            )

        shared_url = os.getenv("DATABASE_URL")
        if shared_url:
            return shared_url

        return (
            f"postgresql://{VulnIntelConfig.USER}:{VulnIntelConfig.PASSWORD}"
            f"@{VulnIntelConfig.HOST}:{VulnIntelConfig.PORT}/{VulnIntelConfig.DATABASE}"
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


class AppConfig:
    """Application-wide configuration."""

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Trusted proxies for client IP resolution (prevents IP spoofing)
    TRUSTED_PROXIES: list = [
        ip.strip()
        for ip in os.getenv(
            "TRUSTED_PROXIES", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
        ).split(",")
        if ip.strip()
    ]

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

    # OT safety config
    PASSIVE_FIRST_DEFAULT = ScanConfig.PASSIVE_FIRST_DEFAULT
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

    @staticmethod
    def is_sqlite() -> bool:
        """Check if using SQLite database."""
        return AppConfig.DATABASE_URL.startswith("sqlite")

    @staticmethod
    def is_postgresql() -> bool:
        """Check if using PostgreSQL database."""
        return AppConfig.DATABASE_URL.startswith("postgresql")
