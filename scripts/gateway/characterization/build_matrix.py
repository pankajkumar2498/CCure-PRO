#!/usr/bin/env python3
"""
Phase 10.1 — assemble the machine-readable route/auth matrix from:

  * the live route table (route_table.py, run inside the api container);
  * edge_probe.py's observed anonymous / invalid-credential results;
  * live_valid_probe.py's valid-credential results, when present.

    python3 scripts/gateway/characterization/build_matrix.py \
        ROUTE_TABLE.json docs/architecture/phase10/edge_probe_results.json \
        [docs/architecture/phase10/valid_probe_results.json] \
        > docs/architecture/phase10/route_auth_matrix.json

Every behaviour in "classes" and "surfaces" cites the probe case ids it was
read from, so a claim in the matrix can be traced to an observed response.
"""
import json
import sys


def load(path):
    with open(path) as fh:
        return json.load(fh)


routes = load(sys.argv[1])
edge = {(c["target"], c["id"]): c for c in load(sys.argv[2])["cases"]}
valid = {}
if len(sys.argv) > 3:
    try:
        valid = {c["id"]: c for c in load(sys.argv[3])["cases"]}
    except FileNotFoundError:
        valid = {}


def obs(target, case):
    c = edge.get((target, case))
    if not c:
        return None
    body = c.get("body_sample", "")
    msg = None
    if body.startswith("{"):
        try:
            b = json.loads(body if body.endswith("}") else body + '"}')
            msg = b.get("message") or b.get("detail")
        except ValueError:
            msg = body[:80]
    hc = c.get("header_counts", {})
    return {
        "case": f"{target}:{case}", "status": c.get("status"), "message": msg,
        "x_request_id": hc.get("x-request-id", 0) > 0,
        "www_authenticate": "www-authenticate" in hc,
        "content_type": dict(c.get("headers", [])).get("content-type"),
    }


def both(case):
    return {"edge": obs("edge", case), "direct": obs("direct", case)}


def vobs(case):
    c = valid.get(case)
    if not c:
        return {"status": "pending live_valid_probe.py"}
    keep = ("status", "bytes", "sha256", "response_keys", "set_cookie", "frames", "sse_events",
            "sse_stopped", "rotated", "error", "ms")
    out = {"case": case, **{k: c[k] for k in keep if k in c}}
    body = c.get("body_sample", "")
    if body.startswith("{") and c.get("status", 200) >= 400:
        try:
            parsed = json.loads(body if body.endswith("}") else body[: body.rfind(",")] + "}")
            out["message"] = parsed.get("message") or parsed.get("detail")
        except ValueError:
            out["message"] = None
    return out


ENVELOPE = {
    "shape": {"success": False, "error_code": "HTTP_<status>", "message": "<text>",
              "detail": "<same text>", "request_id": "<same as X-Request-ID>"},
    "exception": "unmatched route answers the bare Starlette body {\"detail\": \"Not Found\"}",
    "cases": ["edge:bearer-route missing", "edge:bearer-route 404 unknown path, missing"],
}

classes = {
    "public": {
        "count": sum(1 for r in routes if r["auth"] == "public"),
        "behaviour": "reachable with no credential; empty bodies answer 422 VALIDATION_ERROR, "
                     "refresh/logout without a cookie answer 401",
        "observed": {f"{m} {p}": both(f"public {m} {p}") for m, p in
                     [(r["method"], r["path"]) for r in routes if r["auth"] == "public"]},
    },
    "bearer": {
        "count": sum(1 for r in routes if r["auth"] == "bearer"),
        "missing": both("bearer-route missing"),
        "empty_bearer": both("bearer-route empty-bearer"),
        "non_bearer_scheme": both("bearer-route basic-scheme"),
        "invalid_garbage": both("bearer-route garbage"),
        "invalid_alg_none": both("bearer-route alg-none"),
        "invalid_legacy_hs256": both("bearer-route legacy-hs256-random-secret"),
        "invalid_es256_unknown_kid": both("bearer-route es256-unknown-kid"),
        "post_missing": both("bearer-route POST missing"),
        "valid": vobs("bearer GET /scans?limit=1"),
        "access_token_after_logout": vobs("access token still accepted after logout"),
        "ticket_as_bearer": vobs("ticket used as bearer on /scans"),
    },
    "ticket_or_bearer": {
        "routes": [f'{r["method"]} {r["path"]}' for r in routes if r["auth"] == "ticket_or_bearer"],
        "precedence": "a ?ticket= is evaluated first; when present, the Authorization header is not consulted",
        "missing": both("download missing"),
        "invalid_ticket": both("download ticket-garbage"),
        "invalid_ticket_legacy_hs256": both("download ticket-legacy-hs256"),
        "invalid_ticket_es256_unknown_kid": both("download ticket-es256-unknown-kid"),
        "invalid_bearer": both("download bearer-garbage"),
        "invalid_ticket_and_invalid_bearer": both("download ticket-garbage+bearer-garbage"),
        "export_missing": both("export missing"),
        "export_invalid_ticket": both("export ticket-garbage"),
        "delete_missing": both("delete-report missing (nonexistent id)"),
        "delete_invalid_ticket": both("delete-report ticket-garbage (nonexistent id)"),
        "valid_bearer": vobs("download bearer"),
        "valid_bearer_direct": vobs("download bearer (direct :8000)"),
        "valid_ticket": vobs("download ticket"),
        "ticket_replay_within_60s": vobs("download same ticket again (replay within 60 s)"),
        "ticket_replay_direct": vobs("download ticket (direct :8000, same ticket)"),
        "valid_ticket_plus_valid_bearer": vobs("ticket + valid bearer on download"),
        "access_token_as_ticket": vobs("access token passed as ?ticket="),
        "valid_bearer_plus_garbage_ticket": vobs("valid bearer + garbage ticket on download"),
        "expired_ticket": vobs("download expired ticket (>60 s)"),
        "live_usage_m5": "1 HTTP 200 in retained host-nginx logs: GET /api/reports/download/<scan_id> "
                         "(29 Sep 2026); ticket support on downloads is in real use and is NOT WebSocket-only",
    },
    "ws_ticket": {
        "routes": [r["path"] for r in routes if r["auth"] == "ws_ticket"],
        "refusal": "HTTP 403 on the upgrade, empty text/plain body, no X-Request-ID, no API security "
                   "headers (edge adds HSTS + nosniff only); identical for missing, garbage, HS256, "
                   "unknown-kid tickets and for a bearer header without a ticket",
        "observed": {
            label: both(f"ws {route} {label}")
            for route in ("/scans/{}/progress", "/web-scans/{}/progress")
            for label in ("missing", "ticket-garbage", "ticket-legacy-hs256",
                          "ticket-es256-unknown-kid", "bearer-header-only garbage")
        },
        "valid_ticket": vobs("ws scans progress valid ticket"),
        "ticket_reuse_same_route": vobs("ws scans progress same ticket again"),
        "ticket_reuse_other_route": vobs("ws web-scans progress same ticket"),
        "valid_ticket_direct": vobs("ws scans progress same ticket (direct :8000)"),
        "access_token_as_ticket": vobs("ws scans progress access token as ticket"),
    },
    "sse": {
        "routes": [r["path"] for r in routes if r["response_kind"] == "sse"],
        "missing": {p: both(f"sse {p} missing") for p in ("/notifications/stream", "/scans/events")},
        "invalid": {p: both(f"sse {p} garbage") for p in ("/notifications/stream", "/scans/events")},
        "valid_notifications": vobs("sse notifications 8 s"),
        "valid_scan_events": vobs("sse scans/events 8 s"),
    },
    "stream_and_file": {
        "stream_routes": [f'{r["method"]} {r["path"]}' for r in routes if r["response_kind"] == "stream"],
        "file_routes": [f'{r["method"]} {r["path"]}' for r in routes if r["response_kind"] == "file"],
        "valid_streaming_soa": vobs("streaming: ISO SoA pdf"),
    },
}

surfaces = {
    "ir_future_stub": {
        "current": {p: {"missing": both(f"ir {p} missing"), "invalid": both(f"ir {p} garbage")}
                    for p in ("/ir/", "/ir/health", "/ir/incidents")},
        "note": "today /api/ir/* reaches the core and answers 404 {\"detail\":\"Not Found\"} whether or not "
                "a credential is sent; the proposal's stub is 401/403 then 503 MODULE_NOT_DEPLOYED",
    },
    "unknown_route": {"missing_credential": both("bearer-route 404 unknown path, missing"),
                      "note": "404 is answered before authentication"},
    "refresh_cookie": {
        "failure_paths": {k: both(k) for k in ("refresh no cookie", "refresh garbage cookie",
                                               "refresh legacy-hs256 cookie", "logout no cookie")},
        "failure_sets_no_cookie": not any(c.get("set_cookie") for c in load(sys.argv[2])["cases"]),
        "valid_rotation": vobs("refresh valid cookie"),
        "pre_rotation_reuse": vobs("refresh with the pre-rotation cookie (reuse)"),
        "logout": vobs("logout with current cookie"),
        "refresh_after_logout": vobs("refresh after logout"),
        "login_set_cookie": vobs("login") if "login" in valid else vobs("login verify-mfa"),
        "config": {"name": "ccure_refresh_token", "Secure": "static REFRESH_COOKIE_SECURE=True",
                   "SameSite": "lax", "Path": "/", "Domain": None, "HttpOnly": True,
                   "also_accepted_in_body": True},
    },
    "ticket_issuance": {"without_bearer": both("ticket issuance without bearer"),
                        "valid": vobs("ticket issue")},
    "x_request_id": {
        "none_sent": both("xrid none, 200"),
        "client_value_echoed_200": both("xrid client value, 200"),
        "client_value_echoed_403": both("xrid client value, 403"),
        "client_300_chars_echoed": both("xrid client 300-char value"),
        "absent_on": ["WebSocket refusals", "PNA preflight answers", "SPA responses",
                      "host-nginx-generated 429/301"],
    },
    "cors": {k: both(k) for k in (
        "cors preflight allowed origin /auth/login", "cors preflight disallowed origin /auth/login",
        "cors preflight allowed origin protected /scans", "cors PNA preflight allowed",
        "cors PNA preflight disallowed", "cors simple GET allowed origin",
        "cors simple GET disallowed origin", "cors 403 allowed origin")},
    "spa_query_tokens": {
        p: obs("edge", f"spa {p}") for p in (
            "/", "/index.html", "/reset-password?token=probe-not-a-token",
            "/verify-email?token=probe-not-a-token", "/assets/index-CkVhwOG4.js", "/api", "/API/scans")},
    "frontend_3200_api_proxy": {k: obs("frontend-3200", k) for k in ("3200 /api/ root", "3200 /api/scans missing")},
}


def refusal_ref(r):
    return {"public": None, "bearer": "classes.bearer", "ticket_or_bearer": "classes.ticket_or_bearer",
            "ws_ticket": "classes.ws_ticket", "service": "classes.service"}[r["auth"]]


def proposed(r):
    if r["auth"] == "public":
        return "none"
    if r["auth"] == "ws_ticket":
        return "ticket"
    if r["auth"] == "ticket_or_bearer":
        return "ticket_or_bearer" if r["method"] == "GET" else "OPEN: O4 (bearer proposed; ticket accepted today)"
    return "bearer"


matrix = {
    "schema": "ccure.phase10.route_auth_matrix/1",
    "baseline": "live application + host nginx at HEAD fc38b31, 29 Sep 2026",
    "error_envelope": ENVELOPE,
    "counts": {k: sum(1 for r in routes if r["auth"] == k) for k in
               ("public", "bearer", "ticket_or_bearer", "ws_ticket", "service")},
    "classes": classes,
    "surfaces": surfaces,
    "routes": [{**r, "refusal_behaviour": refusal_ref(r), "gateway_policy_proposed": proposed(r)}
               for r in routes],
}
json.dump(matrix, sys.stdout, indent=1)
