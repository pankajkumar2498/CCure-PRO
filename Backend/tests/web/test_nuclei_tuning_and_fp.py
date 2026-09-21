"""
Phase 19 — nuclei profile tuning, timeout/partial coverage, and the
X-XSS-Protection false-positive fix.

PART A: a modern secure application does not send the deprecated
X-XSS-Protection header, so its absence must not be a finding — while the real
security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) still fire.

PART B: each profile carries a tuned request rate; nuclei's string-valued
-stats-json is parsed into real numbers (the count/executed/skipped/percent/rps
the report records).

PART C: a nuclei timeout preserves the partial findings, is recorded as PARTIAL
coverage (never a clean scan), and drives assessment_complete to False for the
essential tool.
"""

import http.server
import subprocess
import threading


# ── shared controlled HTTP target ────────────────────────────────────────────
def _server(headers: dict):
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def _header_findings(headers: dict):
    from orchestrator.web_orchestrator import WebScanOrchestrator

    orch = WebScanOrchestrator(silent=True)
    srv, port = _server(headers)
    try:
        return _run(orch._check_security_headers(f"http://127.0.0.1:{port}/"))
    finally:
        srv.shutdown()
        srv.server_close()


def _server_by_path(headers_by_path: dict):
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            headers = headers_by_path.get(path, headers_by_path.get("*", {}))
            self.send_response(200)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ── PART A: X-XSS-Protection false positive ──────────────────────────────────
# A modern secure app sets the real headers and omits the deprecated one.
_SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
}


def test_secure_modern_app_has_no_header_false_positive():
    findings = _header_findings(_SECURE_HEADERS)
    assert (
        findings == []
    ), f"unexpected header findings: {[f['title'] for f in findings]}"


def test_absent_xss_protection_is_never_flagged():
    # Even a bare app that is missing everything must not be told to add the
    # deprecated X-XSS-Protection header.
    findings = _header_findings({})
    titles = " ".join(f["title"].lower() for f in findings)
    assert "x-xss-protection" not in titles
    # …but the real headers it is missing are still reported.
    assert any("hsts" in f["title"].lower() for f in findings)
    assert any("content-security-policy" in f["title"].lower() for f in findings)


def test_real_missing_headers_still_fire():
    # Present everything except CSP → exactly the CSP finding, nothing spurious.
    partial = dict(_SECURE_HEADERS)
    partial.pop("Content-Security-Policy")
    findings = _header_findings(partial)
    titles = [f["title"] for f in findings]
    assert titles == ["Missing Content-Security-Policy Header"], titles


def test_security_headers_sample_discovered_endpoints():
    from orchestrator.web_orchestrator import WebScanOrchestrator

    endpoint_headers = dict(_SECURE_HEADERS)
    endpoint_headers.pop("Content-Security-Policy")
    srv, port = _server_by_path({"/": _SECURE_HEADERS, "/admin": endpoint_headers})
    base = f"http://127.0.0.1:{port}"
    try:
        findings = _run(
            WebScanOrchestrator(silent=True)._check_security_headers(
                f"{base}/", endpoints=[{"url": f"{base}/admin", "method": "GET"}]
            )
        )
    finally:
        srv.shutdown()
        srv.server_close()

    titles = [f["title"] for f in findings]
    assert titles == ["Missing Content-Security-Policy Header"], titles
    assert "/admin" in findings[0]["response_evidence"]
    assert "Sampled 2" in findings[0]["request_evidence"]


def test_cors_samples_discovered_endpoints():
    from orchestrator.web_orchestrator import WebScanOrchestrator

    srv, port = _server_by_path(
        {
            "/": {},
            "/api/users": {
                "Access-Control-Allow-Origin": "https://evil-attacker.com",
                "Access-Control-Allow-Credentials": "true",
            },
        }
    )
    base = f"http://127.0.0.1:{port}"
    try:
        findings = _run(
            WebScanOrchestrator(silent=True)._check_cors(
                f"{base}/", endpoints=[{"url": f"{base}/api/users", "method": "GET"}]
            )
        )
    finally:
        srv.shutdown()
        srv.server_close()

    assert len(findings) == 1
    assert findings[0]["title"] == "CORS Origin Reflection Vulnerability"
    assert findings[0]["severity"] == "critical"
    assert "/api/users" in findings[0]["response_evidence"]


# ── PART B: per-profile rate tuning ──────────────────────────────────────────
def test_each_profile_has_a_tuned_rate_and_controls():
    from core.web.nuclei.profiles import profile_controls

    fast = profile_controls("FAST")
    std = profile_controls("STANDARD")
    deep = profile_controls("DEEP")
    for c in (fast, std, deep):
        assert c["rate_limit"] > 0
        assert c["concurrency"] > 0
        assert c["timeout"] > 0
    # DEEP is gentler on the wire than FAST (more templates, so a lower rate),
    # and its timeout is the longest.
    assert deep["rate_limit"] <= fast["rate_limit"]
    assert deep["timeout"] >= std["timeout"] >= fast["timeout"]
    # The profile rate is decoupled from the conservative shared probe ceiling.
    from config import WebScanConfig

    assert fast["rate_limit"] > WebScanConfig.SCAN_RATE_LIMIT


# ── PART B: stats-json parsing (nuclei prints STRING values) ─────────────────
_STATS_STDERR = (
    "[INF] Templates loaded for current scan: 956\n"
    '{"duration":"0:00:03","errors":"2","hosts":"1","matched":"4","percent":"45",'
    '"requests":"494","rps":"151","templates":"956","total":"1074"}\n'
    '{"duration":"0:00:06","errors":"2","hosts":"1","matched":"7","percent":"100",'
    '"requests":"1074","rps":"146","templates":"956","total":"1074"}\n'
)


def test_parse_run_metrics_coerces_string_stats():
    from core.web.nuclei.profiles import parse_run_metrics

    m = parse_run_metrics(_STATS_STDERR)
    assert m["templates_total"] == 956
    assert m["percent"] == 100  # reads the LAST stats line
    assert m["requests"] == 1074
    assert m["requests_total"] == 1074
    assert m["rps"] == 146
    assert m["matched"] == 7
    assert m["errors"] == 2


def test_parse_run_metrics_partial_percent():
    # A stderr cut off mid-run (only the 45% line) reports 45% — the signal a
    # timeout uses to prove it did not finish.
    partial = (
        "[INF] Templates loaded for current scan: 956\n"
        + _STATS_STDERR.splitlines()[1]
        + "\n"
    )
    from core.web.nuclei.profiles import parse_run_metrics

    m = parse_run_metrics(partial)
    assert m["percent"] == 45
    assert m["templates_total"] == 956


# ── PART C: nuclei timeout → partial findings + PARTIAL coverage ─────────────
_PARTIAL_JSONL = (
    '{"template-id":"exposed-panel","info":{"name":"Exposed Panel",'
    '"severity":"high","tags":["panel"]},"matched-at":"http://t/admin"}\n'
    '{"template-id":"git-config","info":{"name":"Git Config Exposure",'
    '"severity":"medium","tags":["exposure"]},"matched-at":"http://t/.git/config"}\n'
)


def _timeout_after_partial_write(percent="45"):
    """A fake _run_subprocess that writes partial results to the -o file (as
    nuclei does incrementally) then raises TimeoutExpired with partial stats."""

    def _fake(self, args, timeout=None, **k):
        out = args[args.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(_PARTIAL_JSONL)
        stderr = (
            "[INF] Templates loaded for current scan: 956\n"
            '{"percent":"' + percent + '","requests":"494","rps":"151",'
            '"templates":"956","total":"1074","matched":"2","errors":"0"}\n'
        )
        raise subprocess.TimeoutExpired(
            cmd="nuclei", timeout=timeout or 1, stderr=stderr
        )

    return _fake


def test_nuclei_timeout_preserves_partial_findings(monkeypatch):
    from core.web.nuclei.wrapper import NucleiWrapper

    monkeypatch.setattr(NucleiWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(
        NucleiWrapper, "_run_subprocess", _timeout_after_partial_write()
    )
    # No templates dir on this host — skip the -t existence branch cleanly.
    w = NucleiWrapper()
    w.templates_dir = "/nonexistent-templates"
    res = w.run(target="http://t/", run_timeout=1)

    # The findings collected before the kill survive — not lost, not "clean".
    assert len(res["findings"]) == 2
    stats = res["stats"]
    assert stats["timed_out"] is True
    assert stats["coverage_complete"] is False
    assert stats["percent_complete"] == 45
    assert stats["timeout_limit_s"] == 1
    assert "PARTIAL" in stats["coverage_caveat"]


def test_completed_nuclei_is_not_marked_partial(monkeypatch):
    from core.web.nuclei.wrapper import NucleiWrapper

    class _Done:
        stderr = (
            "[INF] Templates loaded for current scan: 956\n"
            '{"percent":"100","requests":"1074","rps":"140","templates":"956",'
            '"total":"1074","matched":"2","errors":"0"}\n'
        )
        returncode = 0

    def _fake(self, args, timeout=None, **k):
        out = args[args.index("-o") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(_PARTIAL_JSONL)
        return _Done()

    monkeypatch.setattr(NucleiWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(NucleiWrapper, "_run_subprocess", _fake)
    w = NucleiWrapper()
    w.templates_dir = "/nonexistent-templates"
    res = w.run(target="http://t/", run_timeout=60)
    assert res["stats"]["timed_out"] is False
    assert res["stats"]["coverage_complete"] is True
    assert res["stats"]["percent_complete"] == 100
    assert res["stats"]["coverage_caveat"] == ""


# ── PART C: coverage state — a timeout is not a clean scan ────────────────────
def test_partial_essential_tool_makes_assessment_incomplete():
    from orchestrator.web_orchestrator import ToolCoverage

    cov = ToolCoverage()
    cov.partial("nuclei", "timed out at 45% of the corpus")
    d = cov.as_dict()
    assert "nuclei" in d["tools_partial"]
    assert "nuclei" in d["incomplete_essential"]
    assert d["assessment_complete"] is False  # never reads as clean


def test_completed_essential_tool_is_complete():
    from orchestrator.web_orchestrator import ToolCoverage

    cov = ToolCoverage()
    cov.ran("nuclei", "done")
    cov.ran("sqlmap", "done")
    d = cov.as_dict()
    assert d["incomplete_essential"] == []
    assert d["assessment_complete"] is True
