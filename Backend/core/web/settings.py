"""
core/web/settings.py
─────────────────────────────────────────────────────────────────────────────
The settings the web-scanning engine reads, handed to it rather than taken from
the global configuration (Group 4, D2 in
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

Ten modules — the crawler, the ffuf, nuclei, sqlmap and subfinder wrappers,
the nuclei profiles, the OAST client, the worker self-check, the scan timeout
and the web orchestrator — used to import ``config.WebScanConfig`` and read
it. They read
:func:`current` now: whatever settings object was registered with
:func:`configure`. Audit's composition root registers
``config.WebScanConfig`` itself (``ccure_audit/web_settings.py``), so in the
application every value, and every test that patches an attribute on it, is
what it was. Another host — the D2 pilot, or a product reusing web DAST —
registers its own object instead and the engine never touches ``config``.

``READ`` is every setting the engine reads without a default, and
:func:`configure` refuses an object missing one, so a host finds out when it
starts rather than mid-scan. ``READ_WITH_DEFAULT`` names the rest, which each
reader defaults itself. A process that reads a setting with nothing registered
raises ``WebSettingsMissing``: the worker and the API load the registration
through Celery's ``imports``.
"""

from __future__ import annotations

from typing import Any, Optional

__all__ = [
    "READ",
    "READ_WITH_DEFAULT",
    "WebSettingsMissing",
    "configure",
    "current",
]

#: Settings the engine reads without a default: a host must supply each.
READ = (
    "ACCESS_CONTROL_MAX_CANDIDATES",
    "ACCESS_CONTROL_SAME_ORIGIN_ONLY",
    "ACCESS_CONTROL_SIMILARITY",
    "ACCESS_CONTROL_TIMEOUT_S",
    "CRAWL_CONCURRENCY",
    "CRAWL_RATE_LIMIT",
    "CRAWL_SETTLE_TIMEOUT",
    "FFUF_BINARY",
    "FFUF_MAX_WORDS_DEEP",
    "FFUF_MAX_WORDS_SMALL",
    "FFUF_MAX_WORDS_STANDARD",
    "FFUF_MEDIUM_MAX_ENDPOINTS",
    "FFUF_RATE",
    "FFUF_RECRAWL_MAX",
    "FFUF_SMALL_MAX_ENDPOINTS",
    "FFUF_WORDLIST",
    "FFUF_WORDLIST_DEEP",
    "FFUF_WORDLIST_SMALL",
    "INJECTION_CLASSES",
    "INJECTION_CMDI_DELAY_1",
    "INJECTION_CMDI_DELAY_2",
    "INJECTION_MAX_TARGETS",
    "INJECTION_SAME_ORIGIN_ONLY",
    "INJECTION_TIMEOUT_S",
    "MAX_CRAWL_DEPTH",
    "MAX_CRAWL_URLS",
    "MAX_RESPONSE_BODY_SIZE",
    "NUCLEI_BINARY",
    "NUCLEI_BULK_SIZE",
    "NUCLEI_CONCURRENCY",
    "NUCLEI_SEVERITY",
    "NUCLEI_TEMPLATES_DIR",
    "NUCLEI_TIMEOUT",
    "OAST_ENABLED",
    "OAST_MAX_TARGETS",
    "OAST_POLL_INTERVAL_S",
    "OAST_POLL_TIMEOUT_S",
    "OAST_RATE_LIMIT",
    "OAST_SERVER",
    "OAST_TOKEN",
    "PLAYWRIGHT_TIMEOUT",
    "SCAN_RATE_LIMIT",
    "SECURITY_HEADER_ENDPOINT_SAMPLE_MAX",
    "SQLMAP_BINARY",
    "SQLMAP_LEVEL",
    "SQLMAP_RISK",
    "SQLMAP_TIMEOUT",
    "STEALTH_RATE_LIMIT",
    "SUBFINDER_BINARY",
    "XSS_MAX_PAYLOADS_PER_PARAM",
    "XSS_MAX_TARGETS",
    "XSS_SAME_ORIGIN_ONLY",
    "XSS_TEST_DOM",
    "XSS_TEST_STORED",
    "XSS_TIMEOUT_MS",
)

#: Settings the engine reads with a default of its own.
READ_WITH_DEFAULT = (
    "NUCLEI_CONCURRENCY_DEEP",
    "NUCLEI_CONCURRENCY_FAST",
    "NUCLEI_EXCLUDE_TAGS",
    "NUCLEI_INCLUDE_DANGEROUS_TAGS",
    "NUCLEI_RATE_DEEP",
    "NUCLEI_RATE_FAST",
    "NUCLEI_RATE_STANDARD",
    "NUCLEI_TIMEOUT_DEEP",
    "NUCLEI_TIMEOUT_FAST",
    "OAST_ACTIVE_PROBES",
    "OAST_DOMAIN",
    "OAST_HTTP_URL",
    "WEB_SCAN_TIMEOUT",
)


class WebSettingsMissing(RuntimeError):
    """The web engine read a setting in a process that registered none."""


_settings: Optional[Any] = None


def configure(settings: Any) -> None:
    """
    Register the settings the engine reads. The same object again does
    nothing; a second, different one is refused, because which of the two
    answered would then depend on import order. An object missing a name in
    ``READ`` is refused.
    """
    global _settings
    if _settings is settings:
        return
    if _settings is not None:
        raise ValueError("web settings are already registered")
    missing = [name for name in READ if not hasattr(settings, name)]
    if missing:
        raise ValueError("web settings lack " + ", ".join(missing))
    _settings = settings


def current() -> Any:
    """The registered settings."""
    if _settings is None:
        raise WebSettingsMissing(
            "No web settings are registered in this process. Audit's "
            "composition root, ccure_audit/web_settings.py, registers "
            "config.WebScanConfig: the worker and the API load it."
        )
    return _settings
