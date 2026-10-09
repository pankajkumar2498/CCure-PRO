"""
The harness's stand-in for the core API (Phase 10.2d). LOCAL HARNESS ONLY.

Built from the generated route policy (gateway/policy/route_policy.json), so
it serves exactly the application's routes, methods and WebSocket paths, in
the application's order, with FastAPI's own routing behaviour — which is what
makes the X6-a tests meaningful: an unrouted request forwarded by the gateway
gets the 404 / 405 (with ``Allow``) / 307 this router produces, and the same
answer is compared against a request sent to the stub directly.

It authenticates nothing: every handler reports what it received (method,
path, raw query, headers, peer), so the tests can see precisely what the
gateway forwarded. Like the real application it echoes a client
``X-Request-ID`` (or generates one) and sets its own security headers, so the
tests can prove the gateway neither duplicates nor drops them.

Special routes, for the streaming tests:
* ``GET /auth/jwks.json``                 — the harness JWKS (public keys only)
* ``GET /notifications/stream``, ``/scans/events`` — SSE, one event a second
* ``GET /reports/download/{scan_id}``      — a large deterministic body
* ``POST /compliance/controls/{control_id}/evidence`` — reads a large upload
* both WebSocket progress routes          — accept, send one frame, close
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from collections import OrderedDict

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, Response, StreamingResponse

POLICY = os.environ.get("CCURE_ROUTE_POLICY", "/gateway/policy/route_policy.json")
JWKS = os.environ.get("CCURE_HARNESS_JWKS", "/harness-keys/jwks.json")
CHUNK = 64 * 1024

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Cross-Origin-Resource-Policy": "same-site",
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# CORS as main.py configures it (explicit allow-list, credentials), so a
# preflight the gateway forwards gets the application's answer.
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ALLOW_ORIGINS", "").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_id_and_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


def _received(request_or_ws) -> dict:
    headers: dict[str, list[str]] = {}
    for name, value in request_or_ws.headers.raw:
        headers.setdefault(name.decode("latin-1").lower(), []).append(value.decode("latin-1"))
    return {
        "stub": True,
        "path": request_or_ws.url.path,
        "query": request_or_ws.scope.get("query_string", b"").decode("latin-1"),
        "headers": headers,
        "peer": request_or_ws.client.host if request_or_ws.client else None,
    }


async def generic(request: Request):
    body = _received(request)
    body["method"] = request.method
    return JSONResponse(body)


async def jwks(request: Request):
    try:
        with open(JWKS, "rb") as fh:
            return Response(fh.read(), media_type="application/json")
    except FileNotFoundError:
        return JSONResponse({"keys": []})


async def sse(request: Request):
    beats = int(request.query_params.get("beats", "5"))
    interval = float(request.query_params.get("interval", "1"))

    async def events():
        yield "event: connected\ndata: {}\n\n"
        for n in range(beats):
            await asyncio.sleep(interval)
            yield f"event: heartbeat\ndata: {{\"n\": {n}}}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def pattern(size: int):
    block = hashlib.sha256(b"ccure-harness").digest() * (CHUNK // 32)
    sent = 0
    while sent < size:
        piece = block[: min(CHUNK, size - sent)]
        sent += len(piece)
        yield piece


async def download(request: Request):
    size = int(request.query_params.get("size", str(30 * 1024 * 1024)))
    return StreamingResponse(pattern(size), media_type="application/pdf",
                             headers={"Content-Disposition": 'attachment; filename="harness.pdf"',
                                      "Content-Length": str(size)})


async def upload(request: Request):
    digest, size = hashlib.sha256(), 0
    async for chunk in request.stream():
        size += len(chunk)
        digest.update(chunk)
    body = _received(request)
    body.update(method=request.method, bytes=size, sha256=digest.hexdigest())
    return JSONResponse(body)


async def websocket_progress(websocket: WebSocket):
    await websocket.accept()
    payload = _received(websocket)
    payload.update(phase="complete", progress=100, scan_id=websocket.path_params.get("scan_id"))
    await websocket.send_text(json.dumps(payload))
    await websocket.close(code=1000)


SPECIAL = {
    ("GET", "/auth/jwks.json"): jwks,
    ("GET", "/notifications/stream"): sse,
    ("GET", "/scans/events"): sse,
    ("GET", "/reports/download/{scan_id}"): download,
    ("POST", "/compliance/controls/{control_id}/evidence"): upload,
}


def _build():
    with open(POLICY) as fh:
        policy = json.load(fh)
    grouped: "OrderedDict[int, dict]" = OrderedDict()
    for entry in policy["routes"]:
        route = grouped.setdefault(entry["order"], {"scope": entry["scope"], "path": entry["path"], "methods": []})
        route["methods"].append(entry["method"])
    for route in grouped.values():
        if route["scope"] == "websocket":
            app.add_api_websocket_route(route["path"], websocket_progress)
            continue
        specials = [m for m in route["methods"] if (m, route["path"]) in SPECIAL]
        if specials and len(route["methods"]) == 1:
            app.add_api_route(route["path"], SPECIAL[(specials[0], route["path"])], methods=route["methods"])
        else:
            app.add_api_route(route["path"], generic, methods=route["methods"])


_build()
