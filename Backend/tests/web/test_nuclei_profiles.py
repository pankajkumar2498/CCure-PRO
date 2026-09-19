"""
Phase 10 — explicit nuclei scan profiles (FAST / STANDARD / DEEP).

Profile resolution, execution controls, the mandatory safety exclusions, the
metrics parser, and the wrapper wiring that records template count / executed /
skipped / duration / findings per profile. FAST and STANDARD must not regress,
and the dos/fuzz/intrusive/brute-force exclusions must be preserved unless an
operator explicitly opts in.
"""

import asyncio
import subprocess

import pytest

from config import WebScanConfig
from core.web.nuclei import profiles as P


# ── profile resolution ───────────────────────────────────────────────────────
def test_profile_for_depth():
    assert P.profile_for_depth("quick") == "FAST"
    assert P.profile_for_depth("standard") == "STANDARD"
    assert P.profile_for_depth("deep") == "DEEP"
    assert P.profile_for_depth("") == "STANDARD"
    assert P.profile_for_depth("bogus") == "STANDARD"


def test_normalize_profile_aliases():
    assert P.normalize_profile("fast") == "FAST"
    assert P.normalize_profile("QUICK") == "FAST"
    assert P.normalize_profile("standard") == "STANDARD"
    assert P.normalize_profile("normal") == "STANDARD"
    assert P.normalize_profile("deep") == "DEEP"
    assert P.normalize_profile("full") == "DEEP"
    assert P.normalize_profile("nonsense") is None
    assert P.normalize_profile("") is None


def test_resolve_profile_explicit_wins_over_depth():
    assert P.resolve_profile({"nuclei_profile": "deep"}, "quick") == "DEEP"
    assert P.resolve_profile({}, "quick") == "FAST"
    assert P.resolve_profile({"nuclei_profile": ""}, "standard") == "STANDARD"


# ── execution controls ───────────────────────────────────────────────────────
def test_standard_controls_do_not_regress():
    c = P.profile_controls("STANDARD")
    assert c["concurrency"] == WebScanConfig.NUCLEI_CONCURRENCY
    assert c["timeout"] == WebScanConfig.NUCLEI_TIMEOUT


def test_fast_is_faster_and_deep_is_broader():
    fast = P.profile_controls("FAST")
    deep = P.profile_controls("DEEP")
    std = P.profile_controls("STANDARD")
    # FAST: more concurrency, shorter timeout than standard.
    assert fast["concurrency"] >= std["concurrency"]
    assert fast["timeout"] <= std["timeout"]
    # DEEP: at least as long a timeout as standard (broader, longer run).
    assert deep["timeout"] >= std["timeout"]


def test_deep_timeout_and_concurrency_are_configurable(monkeypatch):
    monkeypatch.setattr(WebScanConfig, "NUCLEI_TIMEOUT_DEEP", 99999, raising=False)
    monkeypatch.setattr(WebScanConfig, "NUCLEI_CONCURRENCY_DEEP", 7, raising=False)
    c = P.profile_controls("DEEP")
    assert c["timeout"] == 99999
    assert c["concurrency"] == 7


# ── safety exclusions ────────────────────────────────────────────────────────
def test_safety_exclusions_on_by_default():
    tags = P.resolve_exclude_tags()
    for t in ("dos", "fuzz", "intrusive", "brute-force"):
        assert t in tags


def test_explicit_override_wins():
    assert P.resolve_exclude_tags(override=["only-this"]) == ["only-this"]
    # An explicit empty override means "exclude nothing" — the deliberate opt-in.
    assert P.resolve_exclude_tags(override=[]) == []


def test_include_dangerous_drops_exclusions():
    assert P.resolve_exclude_tags(include_dangerous=True) == []


def test_config_flag_drops_exclusions(monkeypatch):
    monkeypatch.setattr(
        WebScanConfig, "NUCLEI_INCLUDE_DANGEROUS_TAGS", True, raising=False
    )
    assert P.resolve_exclude_tags() == []


# ── metrics parser ───────────────────────────────────────────────────────────
_SAMPLE_STDERR = """\
[INF] Using Nuclei Engine 3.x
[INF] Templates loaded for current scan: 1543
[INF] Executing 1543 signed templates from projectdiscovery/nuclei-templates
{"duration":"1m0s","errors":0,"hosts":1,"matched":4,"percent":100,"requests":9000,"rps":150,"templates":1543,"total":9000}
"""


def test_parse_run_metrics_reads_counts_and_stats():
    m = P.parse_run_metrics(_SAMPLE_STDERR)
    assert m["templates_total"] == 1543
    assert m["templates_executed"] == 1543
    assert m["templates_skipped"] == 0
    assert m["requests"] == 9000
    assert m["matched"] == 4


def test_parse_run_metrics_handles_missing_output():
    m = P.parse_run_metrics("")
    assert m["templates_total"] is None
    assert m["templates_executed"] is None
    assert m["templates_skipped"] is None


def test_parse_run_metrics_reads_excluded_line():
    m = P.parse_run_metrics(
        "[INF] Templates loaded for current scan: 100\n"
        "[INF] Templates excluded: 25\n"
    )
    assert m["templates_total"] == 100
    assert m["templates_skipped"] == 25


# ── wrapper wiring: args + recorded metrics ──────────────────────────────────
class _FakeCompleted:
    def __init__(self, stderr):
        self.returncode = 0
        self.stdout = ""
        self.stderr = stderr


def _patch_wrapper(monkeypatch, captured):
    """Make NucleiWrapper runnable without the binary; capture args, fake output."""
    from core.web.nuclei.wrapper import NucleiWrapper

    monkeypatch.setattr(NucleiWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(NucleiWrapper, "is_available", lambda self: True)

    def fake_run_subprocess(self, args, timeout=None, **kw):
        captured["args"] = args
        captured["timeout"] = timeout
        # Write one JSONL finding to the -o file so parsing has something.
        out = args[args.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(
                '{"template-id":"x","matched-at":"http://t/","info":'
                '{"name":"n","severity":"high","tags":[],"classification":'
                '{"cwe-id":["CWE-79"]}}}\n'
            )
        return _FakeCompleted(_SAMPLE_STDERR)

    monkeypatch.setattr(NucleiWrapper, "_run_subprocess", fake_run_subprocess)
    return NucleiWrapper


def test_wrapper_applies_profile_and_records_metrics(monkeypatch):
    captured = {}
    NucleiWrapper = _patch_wrapper(monkeypatch, captured)
    w = NucleiWrapper()
    res = w.run(
        target="http://t/",
        severity=["high", "critical"],
        profile="FAST",
        concurrency=77,
        run_timeout=123,
    )
    args = captured["args"]
    # Safety exclusions present by default.
    assert "-exclude-tags" in args
    excl = args[args.index("-exclude-tags") + 1]
    for t in ("dos", "fuzz", "intrusive", "brute-force"):
        assert t in excl
    # Concurrency from the profile control, timeout passed to the subprocess.
    assert args[args.index("-concurrency") + 1] == "77"
    assert captured["timeout"] == 123
    # Metrics recorded.
    st = res["stats"]
    assert st["profile"] == "FAST"
    assert st["templates_total"] == 1543
    assert st["templates_executed"] == 1543
    assert st["templates_skipped"] == 0
    assert st["duration_s"] is not None
    assert st["total_findings"] == 1


def test_wrapper_can_opt_into_dangerous_tags(monkeypatch):
    captured = {}
    NucleiWrapper = _patch_wrapper(monkeypatch, captured)
    w = NucleiWrapper()
    w.run(target="http://t/", include_dangerous_tags=True)
    # No -exclude-tags when explicitly opted in.
    assert "-exclude-tags" not in captured["args"]


# ── orchestrator integration ─────────────────────────────────────────────────
URL = "http://target.invalid"


class _ProfileRecordingNuclei:
    called_with = {}

    def is_available(self):
        return True

    def run(self, **kwargs):
        type(self).called_with = kwargs
        return {
            "findings": [],
            "stats": {
                "targets_scanned": len(kwargs.get("targets") or [1]),
                "profile": (kwargs.get("profile") or "STANDARD"),
                "concurrency": kwargs.get("concurrency"),
                "duration_s": 1.0,
                "templates_total": 1000,
                "templates_executed": 1000,
                "templates_skipped": 0,
                "exclude_tags": ["dos", "fuzz", "intrusive", "brute-force"],
            },
        }


def _noop_async(value):
    async def _f(*a, **k):
        return value

    return _f()


def _detect(monkeypatch, options):
    import core.web.nuclei.wrapper as nw
    from orchestrator.web_orchestrator import WebScanOrchestrator

    _ProfileRecordingNuclei.called_with = {}
    monkeypatch.setattr(nw, "NucleiWrapper", _ProfileRecordingNuclei)
    orch = WebScanOrchestrator(silent=True)
    monkeypatch.setattr(orch, "_check_security_headers", lambda url: _noop_async([]))
    monkeypatch.setattr(orch, "_check_cors", lambda url: _noop_async([]))
    result = asyncio.run(orch.run_detect("ws", URL, [], {}, options, {}, False))
    return result, _ProfileRecordingNuclei.called_with


def test_detect_passes_profile_and_records_it(monkeypatch):
    result, called = _detect(monkeypatch, {"scan_depth": "standard"})
    assert called["profile"] == "STANDARD"
    assert called["concurrency"] == WebScanConfig.NUCLEI_CONCURRENCY
    cov = result["tool_coverage"]
    assert cov["nuclei_profile"] == "STANDARD"
    assert cov["nuclei_metrics"]["templates_total"] == 1000
    assert cov["nuclei_metrics"]["templates_executed"] == 1000
    assert "standard" in cov["nuclei_profile_label"].lower()


def test_detect_explicit_profile_overrides_depth(monkeypatch):
    result, called = _detect(
        monkeypatch, {"scan_depth": "standard", "nuclei_profile": "deep"}
    )
    assert called["profile"] == "DEEP"
    assert called["concurrency"] == WebScanConfig.NUCLEI_CONCURRENCY_DEEP
    assert result["tool_coverage"]["nuclei_profile"] == "DEEP"


def test_detect_quick_depth_maps_to_fast(monkeypatch):
    _result, called = _detect(monkeypatch, {"scan_depth": "quick"})
    assert called["profile"] == "FAST"
    assert called["concurrency"] == WebScanConfig.NUCLEI_CONCURRENCY_FAST
