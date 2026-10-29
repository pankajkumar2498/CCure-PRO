"""
The web DAST engine on settings of its own (Group 4, D2 in
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

The web DAST settings readers read ``core.web.settings.current()``, which
answers whatever object was registered: in Audit, ``config.WebScanConfig``
(``ccure_audit/web_settings.py``); here, ``PilotWebSettings``, which holds
exactly the names ``READ`` declares, with values no deployment uses. Every
assertion below would fail if a reader still went to the global configuration.

This module needs no conftest and imports no application module: the library
isolation harness runs it in a fresh interpreter that refuses ``config``,
``db`` and every forbidden package (``scripts/architecture/library_isolation.py``,
library ``web_dast``). The host-application half of the pilot is
``test_web_dast_pilot_host.py``.
"""

import pytest

from core.web import settings as web_settings
from core.web.crawling.browser import PlaywrightCrawler
from core.web.ffuf.wrapper import FfufWrapper
from core.web.nuclei import profiles
from core.web.nuclei.wrapper import NucleiWrapper
from core.web.oast.client import build_oast
from core.web.sqlmap.wrapper import SqlmapWrapper
from core.web.subfinder.wrapper import SubfinderWrapper


class PilotWebSettings:
    CRAWL_CONCURRENCY = 3
    CRAWL_RATE_LIMIT = 7
    CRAWL_SETTLE_TIMEOUT = 1234
    FFUF_BINARY = "/pilot/bin/ffuf"
    FFUF_MAX_WORDS_DEEP = 9003
    FFUF_MAX_WORDS_SMALL = 9001
    FFUF_MAX_WORDS_STANDARD = 9002
    FFUF_MEDIUM_MAX_ENDPOINTS = 20
    FFUF_SMALL_MAX_ENDPOINTS = 10
    FFUF_WORDLIST = "/pilot/wordlists/standard.txt"
    FFUF_WORDLIST_DEEP = "/pilot/wordlists/deep.txt"
    FFUF_WORDLIST_SMALL = "/pilot/wordlists/small.txt"
    MAX_CRAWL_DEPTH = 2
    MAX_CRAWL_URLS = 17
    MAX_RESPONSE_BODY_SIZE = 4096
    NUCLEI_BINARY = "/pilot/bin/nuclei"
    NUCLEI_BULK_SIZE = 11
    NUCLEI_CONCURRENCY = 13
    NUCLEI_SEVERITY = "critical"
    NUCLEI_TEMPLATES_DIR = "/pilot/nuclei-templates"
    NUCLEI_TIMEOUT = 321
    OAST_ENABLED = True
    OAST_SERVER = "oast.pilot.invalid"
    OAST_TOKEN = "pilot-token"
    PLAYWRIGHT_TIMEOUT = 4321
    SCAN_RATE_LIMIT = 19
    SQLMAP_BINARY = "/pilot/bin/sqlmap"
    SQLMAP_LEVEL = 2
    SQLMAP_RISK = 1
    SQLMAP_TIMEOUT = 654
    STEALTH_RATE_LIMIT = 5
    SUBFINDER_BINARY = "/pilot/bin/subfinder"
    # Read only by the web orchestrator, which this module does not load.
    ACCESS_CONTROL_MAX_CANDIDATES = 4
    ACCESS_CONTROL_SAME_ORIGIN_ONLY = True
    ACCESS_CONTROL_SIMILARITY = 0.9
    ACCESS_CONTROL_TIMEOUT_S = 30
    FFUF_RATE = 9
    FFUF_RECRAWL_MAX = 6
    INJECTION_CLASSES = "sqli"
    INJECTION_CMDI_DELAY_1 = 2
    INJECTION_CMDI_DELAY_2 = 4
    INJECTION_MAX_TARGETS = 8
    INJECTION_SAME_ORIGIN_ONLY = True
    INJECTION_TIMEOUT_S = 30
    OAST_MAX_TARGETS = 8
    OAST_POLL_INTERVAL_S = 1
    OAST_POLL_TIMEOUT_S = 10
    OAST_RATE_LIMIT = 3
    SECURITY_HEADER_ENDPOINT_SAMPLE_MAX = 5
    XSS_MAX_PAYLOADS_PER_PARAM = 2
    XSS_MAX_TARGETS = 8
    XSS_SAME_ORIGIN_ONLY = True
    XSS_TEST_DOM = False
    XSS_TEST_STORED = False
    XSS_TIMEOUT_MS = 5000
    # Two of the settings each reader defaults for itself.
    NUCLEI_EXCLUDE_TAGS = "dos,pilot"
    NUCLEI_CONCURRENCY_FAST = 23


@pytest.fixture
def pilot(monkeypatch):
    monkeypatch.setattr(web_settings, "_settings", None)
    web_settings.configure(PilotWebSettings)
    return PilotWebSettings


def test_the_pilot_declares_exactly_what_the_engine_requires():
    declared = {n for n in vars(PilotWebSettings) if n.isupper()}
    assert set(web_settings.READ) <= declared
    assert declared - set(web_settings.READ) <= set(web_settings.READ_WITH_DEFAULT)


def test_the_tool_wrappers_take_the_pilot_settings(pilot):
    sqlmap = SqlmapWrapper()
    assert (sqlmap.binary, sqlmap.timeout) == ("/pilot/bin/sqlmap", 654)
    assert SubfinderWrapper().binary == "/pilot/bin/subfinder"
    nuclei = NucleiWrapper()
    assert (nuclei.binary, nuclei.timeout, nuclei.templates_dir) == (
        "/pilot/bin/nuclei",
        321,
        "/pilot/nuclei-templates",
    )
    ffuf = FfufWrapper()
    assert (ffuf.binary, ffuf.wordlist) == (
        "/pilot/bin/ffuf",
        "/pilot/wordlists/standard.txt",
    )


def test_ffuf_tiers_follow_the_pilot_thresholds(pilot):
    assert [FfufWrapper.resolve_tier(n) for n in (10, 11, 20, 21)] == [
        "small",
        "standard",
        "standard",
        "deep",
    ]
    assert FfufWrapper.wordlist_for_tier("small") == (
        "/pilot/wordlists/small.txt",
        9001,
    )
    assert FfufWrapper.wordlist_for_tier("deep") == ("/pilot/wordlists/deep.txt", 9003)


def test_the_crawler_takes_the_pilot_settings(pilot):
    crawler = PlaywrightCrawler()
    assert (
        crawler.max_depth,
        crawler.max_urls,
        crawler.timeout,
        crawler.concurrency,
        crawler.rate_limit,
        crawler.settle_timeout,
    ) == (2, 17, 4321, 3, 7, 1234)


def test_nuclei_profiles_read_the_pilot_and_default_the_rest(pilot):
    assert profiles.default_exclude_tags() == ["dos", "pilot"]
    fast = profiles.profile_controls("FAST")
    # Declared by the pilot, then the reader's own default for the undeclared.
    assert (fast["concurrency"], fast["bulk_size"]) == (23, 11)
    assert (fast["timeout"], fast["rate_limit"]) == (1800, 150)


def test_nuclei_oast_uses_the_pilot_collaborator(pilot):
    args = []
    record = NucleiWrapper._configure_oast(args)
    assert record["server"] == "oast.pilot.invalid" and record["self_hosted"]
    assert args == ["-iserver", "oast.pilot.invalid", "-itoken", "pilot-token"]


def test_the_oast_client_reads_the_pilot_switch(pilot, monkeypatch):
    monkeypatch.setattr(PilotWebSettings, "OAST_ENABLED", False)
    assert build_oast("pilot-scan") is None


def test_an_unregistered_process_is_told_so(monkeypatch):
    monkeypatch.setattr(web_settings, "_settings", None)
    with pytest.raises(web_settings.WebSettingsMissing):
        SqlmapWrapper()


def test_a_host_must_supply_every_required_setting(monkeypatch):
    monkeypatch.setattr(web_settings, "_settings", None)

    class Incomplete:
        SQLMAP_BINARY = "/pilot/bin/sqlmap"

    with pytest.raises(ValueError, match="FFUF_BINARY"):
        web_settings.configure(Incomplete)
    assert web_settings._settings is None


def test_a_second_settings_object_is_refused(pilot):
    web_settings.configure(PilotWebSettings)  # the same one again: nothing
    with pytest.raises(ValueError):
        web_settings.configure(type("Other", (PilotWebSettings,), {}))
