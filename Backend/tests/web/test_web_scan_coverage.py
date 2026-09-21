"""
tests/test_web_scan_coverage.py
────────────────────────────────────────────────────────────────────────────
Web scanning: what ran, what did not, and what counts as the same finding.

Three defects found by running a real scan against a live nginx, all of the
same family — a result that looks clean because something was silently
dropped:

  * every ``if tool.is_available():`` guard skipped in silence, so a scanner
    image without nuclei produced a successful scan, zero findings, and no
    indication that the primary detector never ran;
  * deduplication keyed on ``finding_type``, which is a category rather than
    an identity, so eight missing security headers collapsed into one and the
    risk score was computed from the survivor alone;
  * tool discovery went through PATH only, so a scanner installed in the
    virtualenv — present and working — was reported unavailable whenever the
    worker was launched by absolute path, which is how services start.
"""

import asyncio
from core.web.correlation import _finding_identity, deduplicate_findings
from orchestrator.web_orchestrator import (
    ESSENTIAL_TOOLS,
    ToolCoverage,
    WebScanOrchestrator,
    is_active_probe_excluded_form_param,
    tool_unavailable_finding,
)

URL = "http://10.0.0.5"


def _finding(title, ftype="misconfig", severity="medium", tool="custom", **extra):
    return {
        "title": title,
        "finding_type": ftype,
        "severity": severity,
        "detected_by": tool,
        "matched_at": URL,
        **extra,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────────────────────


def test_distinct_checks_at_one_url_are_not_merged():
    """
    "misconfig" is a category covering every missing header, every permissive
    CORS policy and every exposed panel. Keying on it collapsed a host missing
    three headers into a single finding.
    """
    findings = deduplicate_findings(
        [
            _finding("Missing HSTS Header"),
            _finding("Missing Content-Security-Policy Header"),
            _finding("Missing X-XSS-Protection Header", severity="low"),
        ]
    )
    assert len(findings) == 3
    assert {f["title"] for f in findings} == {
        "Missing HSTS Header",
        "Missing Content-Security-Policy Header",
        "Missing X-XSS-Protection Header",
    }


def test_the_same_check_from_two_tools_still_merges():
    """Deduplication must still do its job — corroboration is not duplication."""
    findings = deduplicate_findings(
        [
            _finding("Missing HSTS Header", severity="medium", tool="custom"),
            _finding("Missing HSTS Header", severity="high", tool="nuclei"),
        ]
    )
    assert len(findings) == 1
    # The merge keeps the more severe assessment.
    assert findings[0]["severity"] == "high"


def test_the_same_check_at_two_urls_is_two_findings():
    findings = deduplicate_findings(
        [
            _finding("Missing HSTS Header"),
            _finding("Missing HSTS Header", matched_at="http://10.0.0.5/admin"),
        ]
    )
    assert len(findings) == 2


def test_template_id_identifies_a_finding_ahead_of_its_title():
    """Nuclei template ids are stable; titles are prose and can be reworded."""
    assert _finding_identity(
        {"template_id": "CVE-2021-44228", "title": "Log4Shell"}
    ) == ("cve-2021-44228")
    assert _finding_identity({"title": "Missing HSTS Header"}) == "missing hsts header"
    assert _finding_identity({"finding_type": "misconfig"}) == "misconfig"


def test_a_query_string_does_not_split_one_finding_into_many():
    """The existing URL normalisation must survive the sharper identity key."""
    findings = deduplicate_findings(
        [
            _finding("SQL Injection", ftype="sqli", matched_at=f"{URL}/x?id=1"),
            _finding("SQL Injection", ftype="sqli", matched_at=f"{URL}/x?id=2"),
        ]
    )
    assert len(findings) == 1


def test_distinct_query_parameters_at_one_path_are_not_merged():
    """One route can have two independent input flaws on different parameters."""
    findings = deduplicate_findings(
        [
            _finding("SQL Injection", ftype="sqli", matched_at=f"{URL}/x?id=1"),
            _finding("SQL Injection", ftype="sqli", matched_at=f"{URL}/x?name=2"),
        ]
    )
    assert len(findings) == 2


def test_structured_parameter_evidence_prevents_overmerge():
    findings = deduplicate_findings(
        [
            _finding(
                "Reflected XSS",
                ftype="xss",
                matched_at=f"{URL}/search",
                request_evidence="location=query; parameter=q; variant=reflected",
            ),
            _finding(
                "Reflected XSS",
                ftype="xss",
                matched_at=f"{URL}/search",
                request_evidence="location=query; parameter=page; variant=reflected",
            ),
        ]
    )
    assert len(findings) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Tool coverage
# ─────────────────────────────────────────────────────────────────────────────


class _Tool:
    def __init__(self, available=True, raises=False):
        self._available = available
        self._raises = raises

    def is_available(self):
        if self._raises:
            raise OSError("permission denied")
        return self._available


def test_an_unavailable_tool_is_recorded_with_what_it_would_have_checked():
    coverage = ToolCoverage()
    assert coverage.check(_Tool(available=False), "nuclei") is False

    row = coverage.as_dict()
    assert row["tools_unavailable"] == ["nuclei"]
    assert row["missing_essential"] == ["nuclei"]
    assert row["assessment_complete"] is False
    detail = coverage.tools["nuclei"]["detail"]
    assert "not installed" in detail
    assert "was not performed" in detail


def test_a_tool_that_errors_on_probe_is_not_reported_as_missing():
    """ "Failed" and "not installed" are different operational problems."""
    coverage = ToolCoverage()
    assert coverage.check(_Tool(raises=True), "nuclei") is False
    assert coverage.tools["nuclei"]["status"] == ToolCoverage.STATUS_FAILED
    assert coverage.as_dict()["tools_unavailable"] == []
    # It still did not run, so the assessment is still incomplete.
    assert coverage.as_dict()["assessment_complete"] is False


def test_a_non_essential_tool_does_not_invalidate_the_assessment():
    # subfinder is recon-only; its absence narrows discovery but does not make
    # the assessment incomplete. (Phase 15 made sqlmap essential — a missing
    # SQLi engine must invalidate a "clean" verdict — so this now uses a
    # genuinely non-essential tool to make the original point.)
    coverage = ToolCoverage()
    coverage.check(_Tool(available=False), "subfinder")
    coverage.ran("nuclei")
    coverage.ran("sqlmap")
    assert coverage.as_dict()["assessment_complete"] is True
    assert "subfinder" not in ESSENTIAL_TOOLS


def test_missing_sqlmap_invalidates_the_assessment():
    # Phase 15: an unavailable SQLi engine must not let a SQL-injectable app
    # read as clean — the scan is incomplete.
    coverage = ToolCoverage()
    coverage.ran("nuclei")
    coverage.check(_Tool(available=False), "sqlmap")
    assert "sqlmap" in ESSENTIAL_TOOLS
    assert coverage.as_dict()["assessment_complete"] is False


def test_skipped_is_distinct_from_unavailable():
    """
    Plain HTTP has no TLS to audit. Reporting that as a missing tool would send
    an operator installing something they already have.
    """
    coverage = ToolCoverage()
    coverage.skipped("sslyze", "Target is plain HTTP")
    assert coverage.tools["sslyze"]["status"] == ToolCoverage.STATUS_SKIPPED
    assert coverage.as_dict()["tools_unavailable"] == []


def test_the_coverage_finding_matches_the_stored_finding_contract():
    """
    `title` is NOT NULL on web_findings. A warning built on the wrong keys does
    not merely display badly — it fails to persist, losing the warning exactly
    when it matters.
    """
    finding = tool_unavailable_finding(URL, ["nuclei"])
    for required in ("title", "finding_type", "severity", "matched_at", "detected_by"):
        assert finding.get(required), f"missing {required}"
    assert "unassessed" in finding["description"]
    assert "not clean" in finding["description"]


def test_sensitive_form_fields_are_explicitly_skipped_for_active_probes():
    assert is_active_probe_excluded_form_param(
        {"location": "form", "param": "password"}
    )
    assert is_active_probe_excluded_form_param({"location": "form", "param": "csrf"})
    assert not is_active_probe_excluded_form_param(
        {"location": "form", "param": "search"}
    )
    assert not is_active_probe_excluded_form_param(
        {"location": "query", "param": "password"}
    )


def test_detect_reports_incompleteness_as_a_finding(monkeypatch):
    """A scan whose primary detector never ran must not look like a clean one."""
    import orchestrator.web_orchestrator as mod

    orch = WebScanOrchestrator(silent=True)
    monkeypatch.setattr(
        orch, "_check_security_headers", lambda url, **kwargs: _noop_async([])
    )
    monkeypatch.setattr(orch, "_check_cors", lambda url, **kwargs: _noop_async([]))

    class _Nuclei:
        def is_available(self):
            return False

    monkeypatch.setattr(
        mod, "ToolCoverage", ToolCoverage
    )  # explicit: real coverage object
    import core.web.nuclei.wrapper as nw

    monkeypatch.setattr(nw, "NucleiWrapper", _Nuclei)

    result = asyncio.run(orch.run_detect("ws", URL, [], {}, {}, False))

    assert result["success"] is True
    assert result["tool_coverage"]["assessment_complete"] is False
    titles = [f["title"] for f in result["findings"]]
    assert any("assessment incomplete" in t.lower() for t in titles)


async def _noop_async(value):
    return value


# ─────────────────────────────────────────────────────────────────────────────
# Tool discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_a_tool_beside_the_interpreter_is_found_without_an_active_env(
    tmp_path, monkeypatch
):
    """
    pip drops console scripts next to the interpreter. A worker started by
    absolute path has no active environment and therefore not that directory on
    PATH — so a tool that is installed and working reported as missing, and its
    checks were skipped in silence.
    """
    from core.web.base_wrapper import ToolWrapper

    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    binary = scripts / ("faketool.exe" if __import__("os").name == "nt" else "faketool")
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)

    monkeypatch.setattr(
        "core.web.base_wrapper.sys.executable", str(tmp_path / "python.exe")
    )
    monkeypatch.setattr("core.web.base_wrapper.shutil.which", _which_only_in(binary))

    class _Fake(ToolWrapper):
        def __init__(self):
            super().__init__(binary_path="faketool")

        def run(self, target, **kwargs):
            return {}

    tool = _Fake()
    assert tool.is_available() is True
    # The resolved absolute path replaces the bare name, so the subprocess call
    # does not repeat a search that PATH cannot satisfy.
    assert tool.binary == str(binary)


def test_an_explicit_path_override_wins(tmp_path, monkeypatch):
    from core.web.base_wrapper import ToolWrapper

    binary = tmp_path / "custom-nuclei"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setenv("CCURE_NUCLEI_PATH", str(binary))

    class _Fake(ToolWrapper):
        def __init__(self):
            super().__init__(binary_path="nuclei", name="nuclei")

        def run(self, target, **kwargs):
            return {}

    assert _Fake().resolve_binary() == str(binary)


def _which_only_in(binary):
    """A `which` that finds the file only when told to search its directory."""
    import os

    def _which(cmd, path=None):
        if path and os.path.dirname(str(binary)) == path:
            return str(binary)
        return None

    return _which


# ─────────────────────────────────────────────────────────────────────────────
# Persistence identity
# ─────────────────────────────────────────────────────────────────────────────


def test_a_finding_keeps_one_row_across_phases():
    """
    DETECT writes the custom checks, then AUDIT re-persists them. A random id
    suffix made the duplicate guard incapable of matching, so every custom
    finding was stored twice and counted twice.
    """
    from db.base import gen_web_finding_id

    first = gen_web_finding_id("ws_1", "misconfig", "missing hsts header")
    again = gen_web_finding_id("ws_1", "misconfig", "missing hsts header")
    assert first == again


def test_distinct_checks_keep_distinct_rows():
    """Determinism must not be bought by collapsing different findings."""
    from db.base import gen_web_finding_id

    hsts = gen_web_finding_id("ws_1", "misconfig", "missing hsts header")
    csp = gen_web_finding_id("ws_1", "misconfig", "missing csp header")
    assert hsts != csp


def test_the_same_check_on_two_assets_keeps_distinct_rows():
    from db.base import gen_web_finding_id

    a = gen_web_finding_id("wsa_1", "misconfig", "missing hsts header")
    b = gen_web_finding_id("wsa_2", "misconfig", "missing hsts header")
    assert a != b


def test_persistence_identity_matches_the_deduplicator():
    """
    Two different notions of "same finding" would let one layer merge what the
    other splits. They must be the one function.
    """
    from db.base import gen_web_finding_id

    finding = _finding("Missing HSTS Header")
    assert gen_web_finding_id(
        "ws_1", finding["finding_type"], _finding_identity(finding)
    ) == gen_web_finding_id("ws_1", "misconfig", "missing hsts header")


# ─────────────────────────────────────────────────────────────────────────────
# Scanning the discovered surface
# ─────────────────────────────────────────────────────────────────────────────


def test_the_crawled_surface_is_normalised_before_scanning():
    """
    Nuclei runs every selected template against every target, so a crawl that
    emits the same page four ways multiplies the work without testing anything
    new. Query strings are kept — they are where injection lives.
    """
    from core.web.nuclei.wrapper import _dedupe_targets

    assert _dedupe_targets(
        ["http://a/x", "http://a/x/", "http://a/y", "", None, "ftp://a/z"], "http://a"
    ) == ["http://a/x", "http://a/y"]

    assert _dedupe_targets(["http://a/s?id=1", "http://a/s?id=2"], "http://a") == [
        "http://a/s?id=1",
        "http://a/s?id=2",
    ]

    # Nothing usable from the crawl still scans the target itself.
    assert _dedupe_targets([], "http://a") == ["http://a"]
    assert _dedupe_targets(["not-a-url"], "http://a") == ["http://a"]


def test_the_target_list_is_capped():
    """A runaway crawl must not turn into an unbounded scan."""
    from core.web.nuclei.wrapper import MAX_NUCLEI_TARGETS, _dedupe_targets

    huge = [f"http://a/{i}" for i in range(MAX_NUCLEI_TARGETS + 50)]
    assert len(_dedupe_targets(huge, "http://a")) == MAX_NUCLEI_TARGETS


class _RecordingNuclei:
    """Captures what DETECT actually asks nuclei to scan."""

    called_with = {}

    def is_available(self):
        return True

    def run(self, **kwargs):
        type(self).called_with = kwargs
        return {
            "findings": [],
            "stats": {"targets_scanned": len(kwargs.get("targets") or [])},
        }


def _detect_with(monkeypatch, endpoints, options):
    import core.web.nuclei.wrapper as nw

    _RecordingNuclei.called_with = {}
    monkeypatch.setattr(nw, "NucleiWrapper", _RecordingNuclei)
    orch = WebScanOrchestrator(silent=True)
    monkeypatch.setattr(
        orch, "_check_security_headers", lambda url, **kwargs: _noop_async([])
    )
    monkeypatch.setattr(orch, "_check_cors", lambda url, **kwargs: _noop_async([]))
    result = asyncio.run(orch.run_detect("ws", URL, endpoints, {}, options, {}, False))
    return result, _RecordingNuclei.called_with


def test_detect_scans_the_endpoints_the_crawl_found(monkeypatch):
    """
    The defect this closes: the crawl enumerated the attack surface and the
    primary detector then scanned only the root URL, so a vulnerability on
    /admin/login was invisible unless a template guessed that path.
    """
    endpoints = [
        {"url": f"{URL}/admin/login", "method": "GET"},
        {"url": f"{URL}/api/v1/users", "method": "GET"},
    ]
    result, called = _detect_with(monkeypatch, endpoints, {})

    assert set(called["targets"]) == {
        URL,
        f"{URL}/admin/login",
        f"{URL}/api/v1/users",
    }
    assert result["tool_coverage"]["targets_scanned"] == 3


def test_detect_still_scans_the_target_when_the_crawl_found_nothing(monkeypatch):
    _result, called = _detect_with(monkeypatch, [], {})
    assert called["targets"] == [URL]


# ─────────────────────────────────────────────────────────────────────────────
# Scan depth policy
# ─────────────────────────────────────────────────────────────────────────────


def test_depth_defaults_to_full_coverage():
    """
    An unset or unrecognised depth must never quietly narrow the scan. Reduced
    coverage is a decision someone makes, not a fallback.
    """
    from orchestrator.web_orchestrator import DEFAULT_SCAN_DEPTH, resolve_scan_depth

    for options in ({}, {"scan_depth": ""}, {"scan_depth": "bogus"}):
        name, depth = resolve_scan_depth(options)
        assert name == DEFAULT_SCAN_DEPTH == "standard"
        assert depth["use_tech_tags"] is False
        assert depth["caveat"] == ""


def test_standard_depth_does_not_narrow_templates(monkeypatch):
    _result, called = _detect_with(monkeypatch, [], {"scan_depth": "standard"})
    assert called["tags"] is None
    assert called["severity"] == ["medium", "high", "critical"]


def test_quick_depth_is_opt_in_and_declares_what_it_traded(monkeypatch):
    """
    A fast pass has real value, but a narrowed scan that does not say so is
    indistinguishable from a thorough one that found nothing.
    """
    result, called = _detect_with(
        monkeypatch,
        [],
        {"scan_depth": "quick", "tech_stack": [{"name": "Nginx"}]},
    )

    assert called["severity"] == ["high", "critical"]
    assert "nginx" in called["tags"]
    # Generic checks survive the narrowing — a wrong fingerprint must not
    # switch off the checks that apply to any web target.
    for always in ("cve", "exposure", "misconfiguration", "default-login"):
        assert always in called["tags"]

    cov = result["tool_coverage"]
    assert cov["scan_depth"] == "quick"
    assert "not tested for" in cov["scan_depth_caveat"]
    # Select nuclei by name: the coverage tool list is sorted, and other tools
    # (e.g. "injection") now sort ahead of it, so an index assumption is wrong.
    nuclei_tool = next(t for t in cov["tools"] if t["tool"] == "nuclei")
    assert "narrowed to tags" in nuclei_tool["detail"]


def test_deep_depth_includes_low_and_informational(monkeypatch):
    _result, called = _detect_with(monkeypatch, [], {"scan_depth": "deep"})
    assert "info" in called["severity"] and "low" in called["severity"]


def test_depth_is_recorded_on_the_result(monkeypatch):
    """The report must be able to state how much of the corpus was run."""
    result, _called = _detect_with(monkeypatch, [], {})
    cov = result["tool_coverage"]
    assert cov["scan_depth"] == "standard"
    assert "all medium, high and critical" in cov["scan_depth_label"]
    assert cov["scan_depth_caveat"] == ""


def test_generic_tags_are_present_even_without_a_fingerprint():
    from orchestrator.web_orchestrator import tech_tags

    tags = tech_tags([])
    assert {"cve", "exposure", "misconfiguration", "default-login"} <= set(tags)
