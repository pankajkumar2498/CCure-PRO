"""The key source: parsing, refusal of private members, caching and refetch."""

from __future__ import annotations

import http.server
import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import jwk_of
from token_check import jwks
from token_check.jwks import JwksError, JwksKeySource, parse_jwks


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def test_parses_ec_p256_es256_keys():
    k = _key()
    keys = parse_jwks({"keys": [jwk_of("a", k)]})
    assert set(keys) == {"a"} and keys["a"].alg == "ES256"
    assert "BEGIN PUBLIC KEY" in keys["a"].public_pem


@pytest.mark.parametrize("member", sorted(jwks.PRIVATE_MEMBERS))
def test_a_set_publishing_a_private_member_is_refused_whole(member):
    good, bad = jwk_of("a", _key()), jwk_of("b", _key())
    bad[member] = "AAAA"
    with pytest.raises(JwksError, match="private"):
        parse_jwks({"keys": [good, bad]})


@pytest.mark.parametrize("change", [
    {"kty": "RSA"}, {"crv": "P-384"}, {"alg": "RS256"}, {"alg": None}, {"use": "enc"}, {"kid": ""},
])
def test_unusable_keys_are_skipped_not_guessed(change):
    usable = jwk_of("ok", _key())
    other = jwk_of("other", _key())
    other.update(change)
    keys = parse_jwks({"keys": [usable, other]})
    assert set(keys) == {"ok"}


@pytest.mark.parametrize("document", [
    None, [], {}, {"keys": {}}, {"keys": []}, {"keys": ["x"]},
    {"keys": [{"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "a", "x": "AA", "y": "AA"}]},
])
def test_unusable_sets_are_refused(document):
    with pytest.raises(JwksError):
        parse_jwks(document)


def test_a_point_off_the_curve_is_refused():
    bad = jwk_of("a", _key())
    bad["y"] = bad["x"]
    with pytest.raises(JwksError):
        parse_jwks({"keys": [bad]})


def test_duplicate_kids_are_refused():
    with pytest.raises(JwksError, match="duplicate"):
        parse_jwks({"keys": [jwk_of("a", _key()), jwk_of("a", _key())]})


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _Fetch:
    def __init__(self, *documents):
        self.documents = list(documents)
        self.calls = 0

    def __call__(self, url):
        self.calls += 1
        doc = self.documents[min(self.calls - 1, len(self.documents) - 1)]
        if isinstance(doc, Exception):
            raise doc
        return doc


def test_not_ready_until_a_set_is_loaded_and_failures_keep_the_last_good():
    k = _key()
    fetch = _Fetch(OSError("down"), {"keys": [jwk_of("a", k)]}, OSError("down again"))
    clock = _Clock()
    src = JwksKeySource("http://x", max_age=300, min_refetch=30, fetch=fetch, clock=clock)
    assert not src.ready and not src.refresh() and not src.ready
    assert src.refresh() and src.ready
    clock.now += 400  # stale → refetch fails → still serving the cached key
    assert src.verification_key("a") is not None
    assert fetch.calls == 3 and src.ready


def test_an_unknown_kid_refetches_at_most_once_per_interval():
    a, b = _key(), _key()
    fetch = _Fetch({"keys": [jwk_of("a", a)]}, {"keys": [jwk_of("a", a), jwk_of("b", b)]})
    clock = _Clock()
    src = JwksKeySource("http://x", max_age=300, min_refetch=30, fetch=fetch, clock=clock)
    src.refresh()
    clock.now += 5
    for _ in range(50):  # a burst of forged kids inside the floor
        assert src.verification_key("forged") is None
    assert fetch.calls == 1
    clock.now += 30
    assert src.verification_key("b") is not None  # a rotated-in key is picked up
    assert fetch.calls == 2


def test_a_removed_key_stops_verifying_after_max_age():
    a, b = _key(), _key()
    fetch = _Fetch({"keys": [jwk_of("a", a), jwk_of("b", b)]}, {"keys": [jwk_of("b", b)]})
    clock = _Clock()
    src = JwksKeySource("http://x", max_age=300, min_refetch=30, fetch=fetch, clock=clock)
    src.refresh()
    assert src.verification_key("a") is not None
    clock.now += 301
    assert src.verification_key("a") is None
    assert src.verification_key("b") is not None


# ── the HTTP fetch ────────────────────────────────────────────────────────────


@pytest.fixture
def server():
    routes = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            status, headers, body = routes[self.path]
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield routes, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_http_fetch_reads_a_set(server):
    routes, base = server
    routes["/ok"] = (200, {"Content-Type": "application/json"},
                     json.dumps({"keys": [jwk_of("a", _key())]}).encode())
    assert set(parse_jwks(jwks.http_fetch(base + "/ok"))) == {"a"}


def test_http_fetch_refuses_redirects(server):
    routes, base = server
    routes["/moved"] = (302, {"Location": base + "/ok"}, b"")
    routes["/ok"] = (200, {}, b"{}")
    with pytest.raises(JwksError, match="redirect"):
        jwks.http_fetch(base + "/moved")


def test_http_fetch_caps_the_body(server):
    routes, base = server
    routes["/big"] = (200, {}, b" " * (jwks.MAX_BODY_BYTES + 10))
    with pytest.raises(JwksError, match="64 KiB"):
        jwks.http_fetch(base + "/big")


def test_http_fetch_refuses_non_json(server):
    routes, base = server
    routes["/html"] = (200, {}, b"<html>")
    with pytest.raises(JwksError, match="JSON"):
        jwks.http_fetch(base + "/html")
