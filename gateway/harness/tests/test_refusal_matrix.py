"""
The gateway against the Phase 10.1 golden baseline — the complete refusal
matrix.

Every authentication-layer case recorded from the live application (edge_probe
_results.json, target "direct": the application with no proxy in front) is
replayed through the gateway, which now answers it without the application.
The gateway's response must equal the application's in status, body (except
``request_id``, which the gateway leaves null), header names and the values of
the security, content-type and CORS headers — apart from ``X-Request-ID``,
which a gateway refusal deliberately does not carry.

Valid-credential cases (valid_probe_results.json, summarised in the matrix)
are replayed with the harness key: recorded refusals must match in status and
message; recorded successes must be forwarded (200 / 101).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

import pytest

from conftest import GATEWAY, load_doc, request, websocket

SCAN = "scn_defa_c522b539_29sep26_fh9j"
WEB_SCAN = "wsc_test_f88fc2f1_29sep26_o19q"
GARBAGE = "not-a-token"
IGNORED = {"x-request-id", "date", "server", "content-length", "connection", "transfer-encoding"}
COMPARED_VALUES = ("content-type", "x-content-type-options", "x-frame-options", "referrer-policy",
                   "content-security-policy", "cross-origin-resource-policy",
                   "access-control-allow-origin", "access-control-allow-credentials", "vary")


def _b64(d):
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def _hs256():
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": "usr_probe", "type": "ticket", "exp": 4102444800}).encode())
    return f"{head}.{body}.{_b64(hmac.new(os.urandom(32), f'{head}.{body}'.encode(), hashlib.sha256).digest())}"


def _es256_unknown():
    head = _b64(json.dumps({"alg": "ES256", "typ": "JWT", "kid": "probe-unknown-kid"}).encode())
    body = _b64(json.dumps({"sub": "usr_probe", "type": "access", "exp": 4102444800}).encode())
    return f"{head}.{body}.{_b64(os.urandom(64))}"


def _none():
    return (_b64(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "."
            + _b64(json.dumps({"sub": "usr_probe", "type": "access", "exp": 4102444800}).encode()) + ".")


HS, ES, NONE = _hs256(), _es256_unknown(), _none()
J = {"Content-Type": "application/json"}


def _bearer(t):
    return {"Authorization": f"Bearer {t}"}


def _http_cases():
    dl = f"/api/reports/download/{SCAN}"
    return {
        "bearer-route missing": ("GET", "/api/scans", {}, None),
        "bearer-route empty-bearer": ("GET", "/api/scans", {"Authorization": "Bearer "}, None),
        "bearer-route garbage": ("GET", "/api/scans", _bearer(GARBAGE), None),
        "bearer-route basic-scheme": ("GET", "/api/scans", {"Authorization": "Basic dXNlcjpwYXNz"}, None),
        "bearer-route alg-none": ("GET", "/api/scans", _bearer(NONE), None),
        "bearer-route legacy-hs256-random-secret": ("GET", "/api/scans", _bearer(HS), None),
        "bearer-route es256-unknown-kid": ("GET", "/api/scans", _bearer(ES), None),
        "bearer-route POST missing": ("POST", "/api/scan/host-discovery", J, b"{}"),
        "download missing": ("GET", dl, {}, None),
        "download ticket-garbage": ("GET", f"{dl}?ticket={GARBAGE}", {}, None),
        "download ticket-legacy-hs256": ("GET", f"{dl}?ticket={HS}", {}, None),
        "download ticket-es256-unknown-kid": ("GET", f"{dl}?ticket={ES}", {}, None),
        "download bearer-garbage": ("GET", dl, _bearer(GARBAGE), None),
        "download ticket-garbage+bearer-garbage": ("GET", f"{dl}?ticket={GARBAGE}", _bearer(GARBAGE), None),
        "export missing": ("GET", f"/api/reports/export/{SCAN}", {}, None),
        "export ticket-garbage": ("GET", f"/api/reports/export/{SCAN}?ticket={GARBAGE}", {}, None),
        "delete-report missing (nonexistent id)": ("DELETE", "/api/reports/scn_probe_does_not_exist", {}, None),
        "delete-report ticket-garbage (nonexistent id)":
            ("DELETE", f"/api/reports/scn_probe_does_not_exist?ticket={GARBAGE}", {}, None),
        "sse /notifications/stream missing": ("GET", "/api/notifications/stream", {"Accept": "text/event-stream"}, None),
        "sse /notifications/stream garbage":
            ("GET", "/api/notifications/stream", {"Accept": "text/event-stream", **_bearer(GARBAGE)}, None),
        "sse /scans/events missing": ("GET", "/api/scans/events", {"Accept": "text/event-stream"}, None),
        "sse /scans/events garbage": ("GET", "/api/scans/events", {"Accept": "text/event-stream", **_bearer(GARBAGE)}, None),
        "ticket issuance without bearer": ("POST", "/api/auth/ticket", {}, None),
        "xrid client value, 403": ("GET", "/api/scans", {"X-Request-ID": "probe-rid-0002"}, None),
        "cors 403 allowed origin": ("GET", "/api/scans", {"Origin": "https://ccurepro.cdac.in"}, None),
    }


def _ws_cases():
    out = {}
    for route, sid in (("/scans/{}/progress", SCAN), ("/web-scans/{}/progress", WEB_SCAN)):
        path = "/api" + route.format(sid)
        out[f"ws {route} missing"] = (path, {})
        out[f"ws {route} ticket-garbage"] = (path + f"?ticket={GARBAGE}", {})
        out[f"ws {route} ticket-legacy-hs256"] = (path + f"?ticket={HS}", {})
        out[f"ws {route} ticket-es256-unknown-kid"] = (path + f"?ticket={ES}", {})
        out[f"ws {route} bearer-header-only garbage"] = (path, _bearer(GARBAGE))
    return out


@pytest.fixture(scope="module")
def recorded():
    return {c["id"]: c for c in load_doc("edge_probe_results.json")["cases"] if c["target"] == "direct"}


def _compare(case_id, app, got_status, got_headers, got_body):
    problems = []
    if got_status != app["status"]:
        problems.append(f"status {got_status}, application {app['status']}")
    app_names = {k for k, _ in app["headers"]} - IGNORED
    got_names = {k for k, _ in got_headers} - IGNORED
    if app_names != got_names:
        problems.append(f"headers {sorted(got_names ^ app_names)} differ")
    app_values = {k: v for k, v in app["headers"]}
    got_values = {k: v for k, v in got_headers}
    for name in COMPARED_VALUES:
        if app_values.get(name) != got_values.get(name):
            problems.append(f"{name}: {got_values.get(name)!r}, application {app_values.get(name)!r}")
    if "x-request-id" in got_values:
        problems.append("a gateway refusal carried X-Request-ID")
    if "www-authenticate" in got_values:
        problems.append("WWW-Authenticate appeared (X2-a)")
    sample = app.get("body_sample", "")
    if sample.startswith("{"):
        want = json.loads(sample)
        have = json.loads(got_body)
        if have.get("request_id") is not None:
            problems.append("request_id is not null")
        want.pop("request_id", None), have.pop("request_id", None)
        if want != have:
            problems.append(f"body {have}, application {want}")
    elif sample == "" and got_body not in (b"", ""):
        problems.append(f"body {got_body!r}, application empty")
    return [f"{case_id}: {p}" for p in problems]


def test_every_recorded_http_refusal_is_reproduced_by_the_gateway(mint, recorded):
    problems = []
    for case_id, (method, path, headers, body) in _http_cases().items():
        assert case_id in recorded, f"{case_id} missing from the characterisation"
        resp = request(method, path, headers, body)
        problems += _compare(case_id, recorded[case_id], resp.status, resp.headers, resp.body)
    assert not problems, "\n".join(problems)


def test_every_recorded_websocket_refusal_is_reproduced_by_the_gateway(mint, recorded):
    problems = []
    for case_id, (path, headers) in _ws_cases().items():
        assert case_id in recorded, f"{case_id} missing from the characterisation"
        status, hdrs, _, rest = websocket(path, headers)
        problems += _compare(case_id, recorded[case_id], status, hdrs, rest)
    assert not problems, "\n".join(problems)


def test_the_refusal_matrix_is_complete():
    """Every authentication-layer refusal the characterisation recorded is replayed."""
    recorded_ids = {c["id"] for c in load_doc("edge_probe_results.json")["cases"] if c["target"] == "direct"}
    auth_layer = {i for i in recorded_ids
                  if i.startswith(("bearer-route", "download ", "export ", "delete-report", "ws ", "sse "))
                  and "404 unknown path" not in i}
    replayed = set(_http_cases()) | set(_ws_cases())
    assert auth_layer <= replayed, sorted(auth_layer - replayed)


# ── valid-credential cases (valid_probe_results.json via the matrix) ─────────


def _matrix(dotted):
    node = load_doc("route_auth_matrix.json")
    for part in dotted.split("."):
        node = node[part]
    return node


def test_recorded_valid_credential_outcomes(mint):
    ticket, access = mint.token("ticket"), mint.token()
    dl = f"/api/reports/download/{SCAN}"
    cases = {
        "classes.bearer.valid": ("GET", "/api/scans", _bearer(access)),
        "classes.bearer.ticket_as_bearer": ("GET", "/api/scans", _bearer(ticket)),
        "classes.ticket_or_bearer.valid_bearer": ("GET", dl, _bearer(access)),
        "classes.ticket_or_bearer.valid_ticket": ("GET", f"{dl}?ticket={ticket}&size=1024", {}),
        "classes.ticket_or_bearer.ticket_replay_within_60s": ("GET", f"{dl}?ticket={ticket}&size=1024", {}),
        "classes.ticket_or_bearer.valid_ticket_plus_valid_bearer": ("GET", f"{dl}?ticket={ticket}&size=1024", _bearer(access)),
        "classes.ticket_or_bearer.access_token_as_ticket": ("GET", f"{dl}?ticket={access}", {}),
        "classes.ticket_or_bearer.valid_bearer_plus_garbage_ticket": ("GET", f"{dl}?ticket={GARBAGE}", _bearer(access)),
        "classes.ticket_or_bearer.expired_ticket": ("GET", f"{dl}?ticket={mint.expired('ticket')}", {}),
    }
    problems = []
    for key, (method, path, headers) in cases.items():
        want = _matrix(key)
        if "size=" not in path and method == "GET" and path.startswith("/api/reports/download") and want["status"] == 200:
            path += ("&" if "?" in path else "?") + "size=1024"
        resp = request(method, path, headers)
        if resp.status != want["status"]:
            problems.append(f"{key}: {resp.status}, recorded {want['status']}")
        elif want["status"] >= 400:
            if resp.json().get("message") != want.get("message"):
                problems.append(f"{key}: message {resp.json().get('message')!r}, recorded {want.get('message')!r}")
            if resp.header("x-request-id") is not None:
                problems.append(f"{key}: X-Request-ID on a gateway refusal")
    assert not problems, "\n".join(problems)


def test_recorded_valid_websocket_outcomes(mint):
    ticket, access = mint.token("ticket"), mint.token()
    cases = {
        "classes.ws_ticket.valid_ticket": f"/api/scans/{SCAN}/progress?ticket={ticket}",
        "classes.ws_ticket.ticket_reuse_same_route": f"/api/scans/{SCAN}/progress?ticket={ticket}",
        "classes.ws_ticket.ticket_reuse_other_route": f"/api/web-scans/{WEB_SCAN}/progress?ticket={ticket}",
        "classes.ws_ticket.access_token_as_ticket": f"/api/scans/{SCAN}/progress?ticket={access}",
    }
    for key, path in cases.items():
        status, _, frames, _ = websocket(path)
        assert status == _matrix(key)["status"], key
        if status == 101:
            assert json.loads(frames[0])["stub"] is True
