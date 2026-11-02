"""
``core.web.rate_limits`` — the web DAST routes' limits, enforced by the host's
limiter (D2, 2 Nov 2026).

``routers/web_scans.py`` declares its two limits through the port and names no
limiter; Audit's composition root registers ``core.rate_limiter.limiter``
(``ccure_audit/web_routes.py``). These pin that Audit's limits are registered
under the keys they always had, once each, and that the port enforces a limit
as slowapi's decorator did — the count, the 429 and the headers — whether the
route was declared before or after the limiter was registered.

No ``from __future__ import annotations`` here: FastAPI resolves a string
annotation through the endpoint wrapper's module, slowapi's or the port's,
and the router's annotations are objects too.
"""

import pytest
from core.rate_limiter import limiter as audit_limiter
from core.web import rate_limits
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

AUDIT_LIMITS = {
    "routers.web_scans.start_web_scan": ["5 per 1 minute"],
    "routers.web_scans.download_web_scan_report": ["10 per 1 minute"],
}


def test_audit_registers_its_own_limiter():
    assert rate_limits.current() is audit_limiter


def test_the_routes_keep_their_limit_keys_once_each():
    for key, limits in AUDIT_LIMITS.items():
        held = [str(limit.limit) for limit in audit_limiter._route_limits[key]]
        assert held == limits, key


# ── The port, on its own ──────────────────────────────────────────────────────


@pytest.fixture
def port(monkeypatch):
    monkeypatch.setattr(rate_limits, "_limiter", None)
    monkeypatch.setattr(rate_limits, "_routes", [])
    return rate_limits


def _limiter() -> Limiter:
    return Limiter(
        key_func=lambda request: "one-client",
        storage_uri="memory://",
        headers_enabled=True,
    )


def _host(limiter: Limiter, *routes) -> TestClient:
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    for path, endpoint in routes:
        app.get(path)(endpoint)
    return TestClient(app)


def _sync_route(port):
    @port.limit("2/minute")
    def limited_sync(request: Request, response: Response):
        return {"ok": True}

    return limited_sync


def _async_route(port):
    @port.limit("2/minute")
    async def limited_async(request: Request, response: Response):
        return {"ok": True}

    return limited_async


@pytest.mark.parametrize("declare", [_sync_route, _async_route])
@pytest.mark.parametrize("registered_first", [False, True])
def test_a_declared_limit_is_enforced(port, declare, registered_first):
    limiter = _limiter()
    if registered_first:
        port.configure(limiter)
    endpoint = declare(port)
    if not registered_first:
        port.configure(limiter)

    key = f"{endpoint.__module__}.{endpoint.__name__}"
    assert [str(limit.limit) for limit in limiter._route_limits[key]] == [
        "2 per 1 minute"
    ]
    client = _host(limiter, ("/limited", endpoint))
    first, second, third = (client.get("/limited") for _ in range(3))
    assert (first.status_code, second.status_code, third.status_code) == (
        200,
        200,
        429,
    )
    assert first.headers["X-RateLimit-Limit"] == "2"
    assert second.headers["X-RateLimit-Remaining"] == "0"


def test_registering_the_same_limiter_again_counts_nothing_twice(port):
    limiter = _limiter()
    endpoint = _sync_route(port)
    port.configure(limiter)
    port.configure(limiter)
    key = f"{endpoint.__module__}.{endpoint.__name__}"
    assert len(limiter._route_limits[key]) == 1


def test_a_second_limiter_is_refused(port):
    port.configure(_limiter())
    with pytest.raises(ValueError):
        port.configure(_limiter())


def test_a_limited_route_with_no_limiter_refuses_to_serve(port):
    endpoint = _sync_route(port)
    app = FastAPI()
    app.get("/limited")(endpoint)
    with pytest.raises(rate_limits.RateLimiterMissing):
        TestClient(app).get("/limited")


def test_the_route_keeps_its_signature(port):
    """FastAPI reads the parameters through the wrapper, as it read slowapi's."""
    import inspect

    endpoint = _async_route(port)
    assert list(inspect.signature(endpoint).parameters) == ["request", "response"]
    assert inspect.iscoroutinefunction(endpoint)
