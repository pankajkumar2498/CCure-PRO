"""
Phase 17 — cookie security and TLS/SSL validation.

Cookie analysis is deterministic and runs everywhere: sensitive cookies are
held to Secure/HttpOnly/SameSite, preference cookies are not (no false-positive
flood), and the cookie value is never stored. The TLS test drives the real
sslyze wrapper against a controlled HTTPS target with an EXPIRED certificate and
is skipped cleanly where sslyze/cryptography are unavailable.
"""

import datetime
import http.server
import os
import ssl
import tempfile
import threading

import pytest

from core.web.cookies import analyze_cookies, classify_cookie, parse_set_cookie
from core.web.cookies.analyzer import split_set_cookie_header


# ── cookie classification + parsing ──────────────────────────────────────────
def test_classification_distinguishes_sensitive_from_preference():
    for n in (
        "sessionid",
        "PHPSESSID",
        "auth_token",
        "jwt",
        "csrftoken",
        "remember_me",
    ):
        assert classify_cookie(n) == "sensitive", n
    for n in ("theme", "lang", "currency", "sidebar_collapsed"):
        assert classify_cookie(n) == "preference", n


def test_parse_discards_the_value():
    c = parse_set_cookie("sessionid=SECRETVALUE; Secure; HttpOnly; SameSite=Lax")
    assert c["name"] == "sessionid"
    assert c["secure"] and c["httponly"] and c["samesite"] == "lax"
    assert "SECRETVALUE" not in str(c)


def test_split_handles_list_and_joined():
    assert split_set_cookie_header(["a=1", "b=2"]) == ["a=1", "b=2"]
    joined = "a=1; Path=/, b=2; Path=/"
    assert len(split_set_cookie_header(joined)) == 2


# ── analysis: positive, negative, no-FP, no value leak ───────────────────────
def test_sensitive_cookie_missing_flags_is_flagged():
    f = analyze_cookies(
        ["sessionid=abc123; Path=/"], is_https=True, matched_at="https://t/"
    )
    cwes = {x["cwe_id"] for x in f}
    assert "CWE-1004" in cwes  # HttpOnly
    assert "CWE-614" in cwes  # Secure
    assert all("abc123" not in str(x) for x in f)  # value never leaked
    assert all(x["finding_type"] == "insecure_cookie" for x in f)


def test_secure_cookie_is_not_flagged():
    f = analyze_cookies(
        ["sessionid=x; Secure; HttpOnly; SameSite=Lax"],
        is_https=True,
        matched_at="https://t/",
    )
    assert f == []


def test_preference_cookie_is_not_flagged():
    # the whole point: ordinary cookies missing HttpOnly are not false positives
    f = analyze_cookies(["theme=dark; Path=/"], is_https=True, matched_at="https://t/")
    assert f == []


def test_samesite_none_without_secure_is_flagged():
    f = analyze_cookies(
        ["auth=x; HttpOnly; Secure; SameSite=None"],
        is_https=True,
        matched_at="https://t/",
    )
    # Secure+HttpOnly present, but SameSite=None without Secure? Secure IS set
    # here, so no SameSite finding — only checks None *without* Secure.
    assert not any(x["cwe_id"] == "CWE-1275" for x in f)
    f2 = analyze_cookies(
        ["auth=x; HttpOnly; SameSite=None"], is_https=False, matched_at="http://t/"
    )
    assert any(x["cwe_id"] == "CWE-1275" for x in f2)


def test_missing_secure_only_applies_over_https():
    # over plain HTTP, a missing Secure is not itself flagged (nothing to secure)
    f = analyze_cookies(
        ["sessionid=x; HttpOnly"], is_https=False, matched_at="http://t/"
    )
    assert not any(x["cwe_id"] == "CWE-614" for x in f)


def test_insecure_cookie_maps_to_cwe_and_owasp():
    from core.web.standards_mapping import cwe_for, map_compliance

    assert cwe_for("insecure_cookie") == "CWE-614"
    assert map_compliance("insecure_cookie")["owasp"].startswith("A05")


# ── TLS normalization (no network) ───────────────────────────────────────────
def test_tls_finding_normalization():
    from core.web.standards_mapping import map_compliance, resolve_cwe

    f = {"finding_type": "tls_issue", "severity": "high", "cvss_score": 7.0}
    assert resolve_cwe(f) == "CWE-326"
    assert map_compliance("tls_issue")["owasp"].startswith("A02")


# ── TLS live against a controlled expired-cert HTTPS target ──────────────────
def _sslyze_ok():
    try:
        import cryptography  # noqa: F401
        from core.web.sslyze.wrapper import SSLyzeWrapper

        return SSLyzeWrapper().is_available()
    except Exception:
        return False


tls_required = pytest.mark.skipif(
    not _sslyze_ok(), reason="sslyze/cryptography unavailable"
)


def _expired_https_server():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=800))
        .not_valid_after(now - datetime.timedelta(days=400))  # EXPIRED
        .sign(key, hashes.SHA256())
    )
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)

    class _Quiet(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Quiet)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


@tls_required
def test_sslyze_flags_expired_certificate_live():
    from core.web.sslyze.wrapper import SSLyzeWrapper
    from core.web.standards_mapping import resolve_cwe

    srv, port = _expired_https_server()
    try:
        res = SSLyzeWrapper().run(f"127.0.0.1:{port}")
        findings = res.get("findings", [])
        tls = [f for f in findings if f.get("finding_type") == "tls_issue"]
        assert tls, "sslyze did not flag the expired certificate"
        expired = [f for f in tls if "expired" in (f.get("title", "").lower())]
        assert expired, f"no expired-cert finding: {[f.get('title') for f in tls]}"
        f = expired[0]
        assert f["severity"] in ("high", "critical", "medium")
        assert resolve_cwe(f) == "CWE-326"  # normalized weakness class
    finally:
        srv.shutdown()
        srv.server_close()
