"""
Phase 9 — controlled OAST / blind vulnerability detection.

A self-hosted collaborator, collision-proof per-scan tokens that leak no scan
information, DNS + HTTP interaction correlation, and an active probe engine.
The end-to-end test proves the whole chain against a controlled vulnerable
target: target → payload → OAST callback → correlation → finding, with no
public interact.sh and no outbound internet.
"""

import asyncio
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen

import pytest

from core.web.oast import (
    HttpOastClient,
    LocalOastClient,
    OastEngine,
    OastReceiver,
    OastSession,
)
from core.web.oast.session import token_from_host, token_from_path


def _run(c):
    return asyncio.run(c)


# ── tokens: uniqueness, no cross-scan collision, no sensitive data ───────────
def test_tokens_unique_within_session():
    s = OastSession(base_domain="oast.test")
    toks = {s.mint("ssrf", url="http://t/a", param="p") for _ in range(500)}
    assert len(toks) == 500


def test_tokens_never_collide_across_sessions():
    a = OastSession(base_domain="oast.test")
    b = OastSession(base_domain="oast.test")
    assert a.prefix != b.prefix
    ta = {a.mint("ssrf") for _ in range(200)}
    tb = {b.mint("ssrf") for _ in range(200)}
    assert not (ta & tb)
    # b never claims a's token, even though both are live.
    for t in ta:
        assert not b.owns(t)
        assert a.owns(t)


def test_token_is_a_valid_dns_label_and_leaks_nothing():
    s = OastSession(base_domain="oast.ccure.internal", scan_id="wsc_secret_123")
    tok = s.mint(
        "ssrf",
        url="https://victim.example/account?id=42",
        param="id",
        payload_kind="oob-url",
    )
    # valid DNS label: lowercase hex, short
    assert tok.isalnum() and tok.islower() and len(tok) <= 63
    dom = s.domain_for(tok)
    url = s.http_url_for(tok)
    # nothing about the scan/target is derivable from the callback address.
    # Only meaningful (≥3-char) identifiers are checked: the token is random
    # lowercase hex, so a 2-char value like the param name "id" (no 'i' in hex)
    # or the value "42" (pure digits) can coincidentally appear as a substring
    # of a random token — a collision, not a leak — which made this assertion
    # flaky. The real guarantee is that no scan id or target host/path word is
    # derivable, and those are all long enough never to collide.
    for leak in ("wsc_secret_123", "victim", "example", "account"):
        assert leak not in dom
        assert leak not in url


# ── correlation from synthetic interactions (HTTP + DNS), dedup, ownership ───
def test_correlate_http_and_dns_interactions():
    s = OastSession(base_domain="oast.test")
    t_ssrf = s.mint("ssrf", url="http://t/fetch?u=1", param="u")
    t_cmd = s.mint("command_injection", url="http://t/ping?h=1", param="h")
    interactions = [
        {
            "token": t_ssrf,
            "protocol": "http",
            "remote_addr": "10.0.0.5",
            "timestamp": time.time(),
            "path": f"/{t_ssrf}",
        },
        {
            "token": t_cmd,
            "protocol": "dns",
            "remote_addr": "10.0.0.6",
            "timestamp": time.time(),
            "qname": f"{t_cmd}.oast.test",
        },
        # duplicate of the ssrf http hit → collapsed
        {
            "token": t_ssrf,
            "protocol": "http",
            "remote_addr": "10.0.0.5",
            "timestamp": time.time(),
        },
        # a foreign token from another scan → ignored
        {"token": "ffffff9999", "protocol": "http", "remote_addr": "10.0.0.7"},
    ]
    findings = s.correlate(interactions)
    types = sorted(f["finding_type"] for f in findings)
    assert types == ["command_injection", "ssrf"]
    for f in findings:
        assert f["is_verified"] is True
        assert f["detected_by"] == "ccure-oast"
        assert "out-of-band" in f["description"].lower()


def test_owns_rejects_foreign_and_unminted_tokens():
    s = OastSession(base_domain="oast.test")
    assert not s.owns("")
    assert not s.owns("deadbeef0001")  # right shape, wrong prefix
    t = s.mint("ssrf")
    assert s.owns(t)
    s.close()
    assert not s.owns(t)  # cleanup forgets it


# ── token extraction helpers ─────────────────────────────────────────────────
def test_token_extraction_from_host_and_path():
    assert (
        token_from_host("ab12cd0001.oast.ccure.internal", "oast.ccure.internal")
        == "ab12cd0001"
    )
    assert token_from_host("ab12cd0001.oast.test:80", "oast.test") == "ab12cd0001"
    assert token_from_path("/ab12cd0001") == "ab12cd0001"
    assert token_from_path("/ab12cd0001/callback?x=1") == "ab12cd0001"
    assert (
        token_from_path("/_ccure_oast/interactions") == ""
    )  # control path, not a token


# ── receiver + HTTP poll client ──────────────────────────────────────────────
def test_receiver_records_http_hit_and_client_polls_it():
    rec = OastReceiver(base_domain="oast.test", host="127.0.0.1", http_port=0).start()
    try:
        s = OastSession(base_domain="oast.test", http_base_url=rec.http_base_url)
        tok = s.mint("ssrf", url="http://t/x", param="u")
        # simulate the target's server-side callback
        urlopen(s.http_url_for(tok), timeout=5).read()
        client = HttpOastClient(rec.control_url)
        assert client.is_available()
        # poll and correlate
        deadline = time.time() + 5
        found = []
        while time.time() < deadline:
            found = s.correlate(client.poll())
            if found:
                break
            time.sleep(0.2)
        assert len(found) == 1
        assert found[0]["finding_type"] == "ssrf"
        assert found[0]["oast_protocol"] == "http"
    finally:
        rec.stop()


def test_poll_endpoint_requires_bearer_when_configured():
    rec = OastReceiver(
        base_domain="oast.test", host="127.0.0.1", http_port=0, auth_token="s3cret"
    ).start()
    try:
        import httpx

        # no bearer → 401
        r = httpx.get(rec.control_url + "health", timeout=5)
        assert r.status_code == 401
        # correct bearer → 200
        ok = HttpOastClient(rec.control_url, auth_token="s3cret")
        assert ok.is_available()
    finally:
        rec.stop()


# ── DNS interaction ──────────────────────────────────────────────────────────
def _dns_query(name: str) -> bytes:
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)  # type A, class IN
    return q


def test_receiver_records_dns_interaction():
    rec = OastReceiver(base_domain="oast.test", host="127.0.0.1", http_port=0)
    rec.start()
    port = rec.start_dns(0)
    try:
        s = OastSession(base_domain="oast.test")
        tok = s.mint("command_injection", url="http://t/ping?h=1", param="h")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(_dns_query(s.domain_for(tok)), ("127.0.0.1", port))
        try:
            sock.recvfrom(2048)  # a response is sent so a real resolver won't hang
        except socket.timeout:
            pass
        sock.close()
        deadline = time.time() + 5
        found = []
        while time.time() < deadline:
            found = s.correlate(rec.inbox.all())
            if found:
                break
            time.sleep(0.2)
        assert len(found) == 1
        assert found[0]["finding_type"] == "command_injection"
        assert found[0]["oast_protocol"] == "dns"
    finally:
        rec.stop()


# ── end-to-end: vulnerable SSRF target → callback → correlation → finding ────
def _make_ssrf_target():
    """A target with an SSRF hole: it fetches whatever the `url` param names."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/fetch":
                u = parse_qs(parsed.query).get("url", [""])[0]
                if u.startswith("http://") or u.startswith("https://"):
                    try:
                        urlopen(u, timeout=3).read()  # ← the SSRF
                    except Exception:
                        pass
            body = b"<html>ok</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return H


@pytest.fixture
def ssrf_target():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_ssrf_target())
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base
    finally:
        srv.shutdown()
        srv.server_close()


def test_end_to_end_blind_ssrf(ssrf_target):
    rec = OastReceiver(base_domain="oast.test", host="127.0.0.1", http_port=0).start()
    try:
        session = OastSession(base_domain="oast.test", http_base_url=rec.http_base_url)
        client = LocalOastClient(rec)
        eng = OastEngine(
            session,
            client,
            classes=("ssrf",),
            poll_timeout_s=6,
            poll_interval_s=0.3,
            rate_limit=50,
        )
        endpoints = [{"url": ssrf_target + "/fetch?url=placeholder", "method": "GET"}]
        res = _run(eng.scan(ssrf_target + "/", endpoints=endpoints, forms=[]))
        assert res["available"] is True
        vj = [f for f in res["findings"] if f["finding_type"] == "ssrf"]
        assert vj, f"blind SSRF not correlated; stats={res['stats']}"
        assert vj[0]["is_verified"] is True
        assert "out-of-band" in vj[0]["response_evidence"].lower()
        assert res["stats"]["interactions"] >= 1
    finally:
        rec.stop()


# ── timeout: no callback → no finding, bounded time ──────────────────────────
def test_timeout_yields_no_finding_and_returns_promptly():
    rec = OastReceiver(base_domain="oast.test", host="127.0.0.1", http_port=0).start()
    try:
        session = OastSession(base_domain="oast.test", http_base_url=rec.http_base_url)
        eng = OastEngine(
            session,
            LocalOastClient(rec),
            classes=("ssrf",),
            poll_timeout_s=1.5,
            poll_interval_s=0.3,
            rate_limit=50,
        )
        # A target that never calls back (points at a black hole endpoint).
        endpoints = [{"url": "http://127.0.0.1:9/fetch?url=x", "method": "GET"}]
        t0 = time.monotonic()
        res = _run(eng.scan("http://127.0.0.1:9/", endpoints=endpoints, forms=[]))
        elapsed = time.monotonic() - t0
        assert res["findings"] == []
        assert elapsed < 8  # bounded by poll_timeout, no hang
    finally:
        rec.stop()


# ── cancellation ─────────────────────────────────────────────────────────────
def test_cancellation_stops_the_poll_loop():
    rec = OastReceiver(base_domain="oast.test", host="127.0.0.1", http_port=0).start()
    try:
        session = OastSession(base_domain="oast.test", http_base_url=rec.http_base_url)
        eng = OastEngine(
            session,
            LocalOastClient(rec),
            classes=("ssrf",),
            poll_timeout_s=30,  # long, but cancellation must cut it short
            poll_interval_s=0.3,
            rate_limit=50,
        )
        endpoints = [{"url": "http://127.0.0.1:9/fetch?url=x", "method": "GET"}]
        t0 = time.monotonic()
        res = _run(
            eng.scan(
                "http://127.0.0.1:9/",
                endpoints=endpoints,
                forms=[],
                cancel_cb=lambda: True,
            )
        )
        assert res["findings"] == []
        assert time.monotonic() - t0 < 8
    finally:
        rec.stop()


# ── gating: no client / not configured → does not run ────────────────────────
def test_engine_unavailable_without_client():
    session = OastSession(base_domain="oast.test")
    eng = OastEngine(session, None, classes=("ssrf",))
    assert eng.is_available() is False
    res = _run(eng.scan("http://t/", endpoints=[], forms=[]))
    assert res["available"] is False
    assert res["findings"] == []


def test_build_oast_returns_none_when_unconfigured(monkeypatch):
    from config import WebScanConfig
    from core.web.oast import build_oast

    monkeypatch.setattr(WebScanConfig, "OAST_SERVER", "", raising=False)
    monkeypatch.setattr(WebScanConfig, "OAST_DOMAIN", "", raising=False)
    monkeypatch.setattr(WebScanConfig, "OAST_HTTP_URL", "", raising=False)
    assert build_oast(scan_id="x") is None


def test_build_oast_self_hosted(monkeypatch):
    from config import WebScanConfig
    from core.web.oast import build_oast

    monkeypatch.setattr(WebScanConfig, "OAST_ENABLED", True, raising=False)
    monkeypatch.setattr(WebScanConfig, "OAST_ACTIVE_PROBES", True, raising=False)
    monkeypatch.setattr(WebScanConfig, "OAST_SERVER", "", raising=False)
    monkeypatch.setattr(
        WebScanConfig, "OAST_DOMAIN", "oast.ccure.internal", raising=False
    )
    monkeypatch.setattr(
        WebScanConfig, "OAST_HTTP_URL", "http://10.0.0.9:8888", raising=False
    )
    built = build_oast(scan_id="wsc_1")
    assert built is not None
    session, client = built
    assert session.base_domain == "oast.ccure.internal"
    tok = session.mint("ssrf")
    assert session.http_url_for(tok).startswith("http://10.0.0.9:8888/")
