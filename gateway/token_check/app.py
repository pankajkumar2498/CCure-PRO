"""
The gateway-auth service: a plain ASGI application, no framework, two routes.

``GET /check`` — called by nginx ``auth_request`` for every protected request.
Reads only:

* ``Authorization``   — the client's header, passed through by nginx;
* ``X-Ccure-Policy``  — the route policy nginx looked up (generated map);
* ``X-Ccure-Method``  — the client request's method;
* ``X-Ccure-Args``    — the client request's raw query string (``$args``).

Answers ``204`` with ``X-Ccure-Auth-{Sub,Jti,Ptype,Kind}`` on success, or the
refusal's status (401/403) with ``X-Ccure-Refusal: <code>``; nginx renders the
application's own body for that code. It answers ``503`` while no key set is
loaded and ``500`` for a policy it does not know — both of which nginx turns
into a fail-closed 503 for the client. Never a pass on an error.

``GET /healthz`` — ``200`` once a key set is loaded, ``503`` before.

**What is logged, and what never is.** One line per refusal and per error: the
refusal code, the verification reason, the policy, and the **unverified**
``kid``/``jti``/``ptype`` of the credential (bounded, as ``tokens._refuse``
logs them). Never a header value, the query string, a token or a cookie.
Successful checks are not logged; nginx's access log records them with the
same principal fields.
"""

from __future__ import annotations

import asyncio
import logging
import time

from ccure_platform.identity import verification
from token_check import checker, config
from token_check.jwks import JwksKeySource

log = logging.getLogger("gateway_auth")

_LOGGED_VALUE_LIMIT = 64
#: Printable ASCII only in a response header value; anything else is dropped.
_HEADER_SAFE = {chr(c) for c in range(0x21, 0x7F)}


def _bounded(value) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= _LOGGED_VALUE_LIMIT else text[:_LOGGED_VALUE_LIMIT] + "…"


def _header_value(value) -> bytes:
    text = "".join(ch for ch in str(value if value is not None else "") if ch in _HEADER_SAFE)
    return text[:128].encode("ascii")


class GatewayAuth:
    """The ASGI application. Built with its settings and key source injected."""

    def __init__(self, settings: config.Settings, keys: JwksKeySource):
        self.settings = settings
        self.keys = keys

    # verification with this service's issuer, audience and public keys only
    def verify(self, token: str, kind: str):
        return verification.verify(
            token,
            expected_kind=kind,
            issuer=self.settings.issuer,
            audience=self.settings.user_audience,
            keyset=lambda: self.keys,
            legacy=None,  # no HS256 secret is ever held here
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        path, method = scope.get("path"), scope.get("method")
        if method != "GET" or path not in ("/check", "/healthz"):
            await _respond(send, 404)
            return
        if path == "/healthz":
            await _respond(send, 200 if self.keys.ready else 503)
            return
        await self._check(scope, send)

    async def _check(self, scope, send):
        headers = {}
        for name, value in scope.get("headers", []):
            key = name.decode("latin-1").lower()
            headers.setdefault(key, value)  # the first occurrence, as Starlette's .get()
        started = time.monotonic()
        policy = headers.get("x-ccure-policy", b"").decode("latin-1").strip()
        method = headers.get("x-ccure-method", b"").decode("latin-1").strip() or "GET"
        authorization = headers.get("authorization")
        authorization = authorization.decode("latin-1") if authorization is not None else None
        raw_query = headers.get("x-ccure-args", b"")

        needs_keys = not (method.upper() == "OPTIONS" or policy == "none")
        if needs_keys and not self.keys.ready:
            log.error("check: no key set loaded — refusing (policy=%s)", policy)
            await _respond(send, 503)
            return
        try:
            decision = await asyncio.to_thread(
                checker.decide,
                policy=policy,
                method=method,
                authorization=authorization,
                raw_query=raw_query,
                verify=self.verify,
            )
        except checker.PolicyError:
            log.error("check: unknown route policy %r — failing closed", _bounded(policy))
            await _respond(send, 500)
            return
        except Exception:  # a bug here must never become a pass
            log.exception("check: internal error — failing closed")
            await _respond(send, 500)
            return

        if decision.allowed:
            p = decision.principal
            # A route needing no credential (public, unrouted, OPTIONS) names no principal.
            await _respond(send, 204, [
                (b"x-ccure-auth-sub", _header_value(p.get("sub"))),
                (b"x-ccure-auth-jti", _header_value(p.get("jti"))),
                (b"x-ccure-auth-ptype", _header_value(p.get("ptype"))),
                (b"x-ccure-auth-kind", _header_value(p.get("kind"))),
            ] if p else [])
            return
        header = verification.header_of(decision.token) if decision.token else {}
        claims = verification.claims_of(decision.token) if decision.token else {}
        log.info(
            "check refused: code=%s reason=%s policy=%s kid=%r jti=%r ptype=%r ms=%.1f",
            decision.code, decision.reason, policy,
            _bounded(header.get("kid") if isinstance(header, dict) else None),
            _bounded(claims.get("jti")), _bounded(claims.get("ptype")),
            (time.monotonic() - started) * 1000,
        )
        await _respond(send, decision.status, [(b"x-ccure-refusal", decision.code.encode("ascii"))])

    async def _lifespan(self, receive, send):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                asyncio.get_running_loop().create_task(self._load_keys())
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _load_keys(self):
        """Keep trying until a key set is loaded; /healthz reports readiness."""
        delay = 1.0
        while not self.keys.ready:
            if await asyncio.to_thread(self.keys.refresh):
                log.info("gateway-auth ready: kids %s", ", ".join(self.keys.kids()))
                return
            await asyncio.sleep(delay)
            delay = min(delay * 2, 15.0)


async def _respond(send, status: int, headers=None):
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-length", b"0"), (b"cache-control", b"no-store"), *(headers or [])],
    })
    await send({"type": "http.response.body", "body": b""})


def create_app() -> GatewayAuth:
    """The uvicorn factory: ``uvicorn --factory token_check.app:create_app``."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    settings = config.load()
    keys = JwksKeySource(
        settings.jwks_url,
        max_age=settings.jwks_max_age_seconds,
        min_refetch=settings.jwks_min_refetch_seconds,
    )
    return GatewayAuth(settings, keys)
