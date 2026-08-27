"""
tests/security/test_rate_limit_headers.py
─────────────────────────────────────────
A `@limiter.limit` decorator must not be able to 500 the route it is applied to.

The limiter is built with `headers_enabled=True`, so after the handler returns
slowapi writes X-RateLimit-Limit / -Remaining / -Reset onto the response. It
locates that response one of exactly two ways:

  1. the handler returned a `Response` object, or
  2. the handler declared a `response: Response` parameter, which FastAPI fills
     in and whose headers it merges into the serialised reply.

A handler that does neither — the normal FastAPI style, `return {...}` — hands
upstream `_inject_headers` a `None`, and it answers with a bare
`raise Exception("parameter response must be an instance of ...")` raised from
inside the endpoint call. Every request to the route becomes a 500.

Twenty-one routes shipped in that state — `/scan/host-discovery`,
`/auth/reset-password`, `/web-scans`, the compliance scan trigger, evidence
upload, the AMT import, all four traditional scan endpoints — because the
August 2026 limit audit added limits to 21 routes and none of them grew the
parameter. Nothing caught it: `conftest` sets `limiter.enabled = False` for the
suite, and a disabled limiter skips header injection altogether, so the tests
asserting the limits are *registered* pass either way.

`test_every_limited_route_can_receive_headers` is the real guard: it is the
check whose absence let those 21 routes ship, and it fails on the next route
that carries a limit with no way to receive the headers.

`test_missing_response_parameter_degrades_instead_of_raising` covers the
backstop in `scan_helpers._HeaderSafeLimiter`, which turns that mistake into a
logged warning and a missing header rather than an outage. It exists so the
guard above is what catches the mistake — in CI, not on a live scan dispatch.
"""

import ast
import inspect
import textwrap

import pytest
from fastapi.routing import APIRoute
from starlette.responses import Response

# Return values that are Response objects. Matched by name because the guard is
# static; the alternative is calling every endpoint, which is not a unit test.
_RESPONSE_NAMES = {
    "Response",
    "JSONResponse",
    "ORJSONResponse",
    "UJSONResponse",
    "HTMLResponse",
    "PlainTextResponse",
    "RedirectResponse",
    "StreamingResponse",
    "FileResponse",
}


def _declares_response_parameter(endpoint) -> bool:
    """True when FastAPI will hand the handler a Response to write headers on.

    `inspect.signature` follows `__wrapped__`, which slowapi's `functools.wraps`
    sets, so this reads the handler's own signature rather than the wrapper's —
    the same signature FastAPI introspects to decide what to inject.
    """
    try:
        params = inspect.signature(endpoint).parameters
    except (TypeError, ValueError):  # pragma: no cover - not a Python callable
        return False
    param = params.get("response")
    if param is None:
        return False
    annotation = param.annotation
    return (
        annotation is inspect.Parameter.empty
        or annotation is Response
        or (isinstance(annotation, type) and issubclass(annotation, Response))
        or "Response" in str(annotation)
    )


def _returns_a_response(endpoint) -> bool:
    """True when every `return` in the handler yields a Response object.

    `inspect.unwrap` is required: `inspect.getsource` reads `__code__`, which on
    a decorated endpoint is slowapi's wrapper inside site-packages, not the
    handler. Every return has to qualify — one bare `return {...}` on an early
    branch is enough to reach `_inject_headers` with a dict.
    """
    func = inspect.unwrap(endpoint)
    try:
        source = textwrap.dedent(inspect.getsource(func))
    except (OSError, TypeError):  # pragma: no cover - source unavailable
        return False
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover
        return False
    body = tree.body[0]
    if not isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False

    returns = [n for n in ast.walk(body) if isinstance(n, ast.Return)]
    if not returns:
        return False
    for node in returns:
        value = node.value
        if value is None:
            return False
        call = value.func if isinstance(value, ast.Call) else value
        name = call.attr if isinstance(call, ast.Attribute) else getattr(call, "id", "")
        if name not in _RESPONSE_NAMES:
            return False
    return True


@pytest.fixture(scope="module")
def limited_routes():
    from main import app
    from scan_helpers import limiter

    registry = limiter._route_limits
    rows = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        key = f"{route.endpoint.__module__}.{route.endpoint.__name__}"
        if not registry.get(key):
            continue
        rows.append((key, route.path, route.endpoint))
    return rows


def test_limited_routes_are_discoverable(limited_routes):
    """A guard that inspects nothing passes trivially."""
    assert len(limited_routes) >= 40, (
        "expected the limiter registry to hold the ~42 limited routes; found "
        f"{len(limited_routes)}. If limits moved, fix this test — do not let it "
        "silently stop checking anything."
    )


def test_every_limited_route_can_receive_headers(limited_routes):
    """
    Each rate-limited handler must either return a Response or declare
    `response: Response`. Without one of the two, `headers_enabled=True` makes
    the route answer 500 on every request as soon as the limiter is enabled.
    """
    broken = [
        f"{key}  ({path})"
        for key, path, endpoint in limited_routes
        if not _declares_response_parameter(endpoint)
        and not _returns_a_response(endpoint)
    ]
    assert not broken, (
        "These rate-limited endpoints neither return a Response nor declare a "
        "`response: Response` parameter. With headers_enabled=True that is a "
        "500 on every request to them once the limiter is enabled — the suite "
        "disables it, so only a live server shows the fault. Add "
        "`response: Response` to the signature, immediately after "
        "`request: Request`:\n  " + "\n  ".join(sorted(broken))
    )


def _limiter_storage_is_reachable(limiter, current_limit) -> bool:
    """Whether the limiter's counter store can be read at all right now.

    Header injection reads window stats out of Redis. If that store is down,
    upstream `_inject_headers` re-raises after its fallback retry, which says
    nothing about the property under test here.
    """
    try:
        limiter.limiter.get_window_stats(current_limit[0], *current_limit[1])
        return True
    except Exception:
        return False


def test_missing_response_parameter_degrades_instead_of_raising():
    """
    The backstop: header injection with nothing to inject into must not raise.

    Upstream slowapi raises a bare `Exception` here, which surfaces as a 500
    from inside the endpoint. `_HeaderSafeLimiter` logs and returns instead, so
    a forgotten parameter costs an advisory header rather than the route. The
    limit itself is unaffected — `_route_limits` is not touched.
    """
    from limits import parse

    from scan_helpers import limiter

    limiter.enabled = True
    try:
        current_limit = (parse("5/minute"), ["1.2.3.4", "routers.example.endpoint"])
        for value in (None, {"available": True}, "text", 42):
            assert limiter._inject_headers(value, current_limit) is value
    finally:
        # conftest disables the limiter for the session; do not leak an enabled
        # one into whatever runs next.
        limiter.enabled = False


def test_limiter_still_injects_headers_into_a_real_response():
    """The degradation above must not have disabled header injection outright."""
    from limits import parse

    from scan_helpers import limiter

    limiter.enabled = True
    try:
        current_limit = (parse("5/minute"), ["1.2.3.4", "routers.example.endpoint"])
        if not _limiter_storage_is_reachable(limiter, current_limit):
            pytest.skip("rate limit counter store unreachable")
        response = Response()
        limiter._inject_headers(response, current_limit)
        assert "x-ratelimit-limit" in {k.lower() for k in response.headers.keys()}
    finally:
        limiter.enabled = False
