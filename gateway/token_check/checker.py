"""
The decision: route policy × credential → allow, or a refusal code.

The code is the whole interface to nginx, which renders each one as the exact
response the application gives today (``REFUSALS`` is that table; the gateway
configuration is generated from it, so the two cannot drift). The
behaviour reproduced here was measured live in Phase 10.1
(``docs/architecture/phase10/route_auth_matrix.json``) and is pinned by
``tests/test_fastapi_parity.py`` against the real FastAPI and Starlette code:

* ``bearer`` — FastAPI's ``HTTPBearer()``:
  no header / no scheme / no credentials → 403 "Not authenticated";
  a scheme other than ``bearer`` (any case) → 403 "Invalid authentication
  credentials"; otherwise the credentials must verify as an ``access`` token →
  else 401 "Invalid or expired token".
* ``ticket_or_bearer`` — ``get_current_user_flexible``: a non-empty ``ticket``
  query parameter is verified as a ``ticket`` and **the Authorization header is
  not consulted** → else 401 "Invalid or expired download ticket.". Without a
  ticket, ``HTTPBearer(auto_error=False)``: anything but ``Bearer <x>`` →
  401 "Authentication token is missing."; otherwise as ``bearer``.
* ``ticket`` — the WebSocket ticket logins: the ticket must verify as a
  ``ticket`` with a ``sub``; the Authorization header is ignored; every refusal
  is the same bare 403.
* ``none`` — public routes, unrouted requests (X6-a) and every ``OPTIONS``:
  allowed without reading any credential.

The query string is parsed as Starlette parses it — latin-1, then
``parse_qsl(keep_blank_values=True)`` — and the **last** ``ticket`` wins.
nginx's ``$arg_ticket`` is the first and undecoded, which is why it is not used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import parse_qsl

from ccure_platform.identity import verification

#: Route policies nginx may send. Anything else is a configuration error.
POLICIES = frozenset({"none", "bearer", "ticket_or_bearer", "ticket"})

#: Refusal code → (status, message) — the application's own response today.
#: ``ws_refused`` has no message: a refused WebSocket upgrade is a bare 403.
REFUSALS = {
    "missing_bearer": (403, "Not authenticated"),
    "non_bearer_scheme": (403, "Invalid authentication credentials"),
    "invalid_bearer": (401, "Invalid or expired token"),
    "missing_flexible": (401, "Authentication token is missing."),
    "invalid_ticket": (401, "Invalid or expired download ticket."),
    "ws_refused": (403, ""),
}

#: A verifier: (token, expected kind) → payload dict, a Refusal, or None.
Verifier = Callable[[str, str], object]


class PolicyError(ValueError):
    """nginx sent a policy this service does not know — fail closed."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: Optional[str] = None  # a REFUSALS key when refused
    reason: Optional[str] = None  # why, for the log: a verification reason or a parse outcome
    token: Optional[str] = None  # the credential examined, for unverified log fields only
    principal: dict = field(default_factory=dict)

    @property
    def status(self) -> int:
        return 204 if self.allowed else REFUSALS[self.code][0]


def last_ticket(raw_query: bytes | str) -> str:
    """The ``ticket`` value exactly as ``request.query_params.get('ticket')``."""
    if isinstance(raw_query, bytes):
        raw_query = raw_query.decode("latin-1")
    value = None
    for key, item in parse_qsl(raw_query, keep_blank_values=True):
        if key == "ticket":
            value = item
    return value or ""


def scheme_and_credentials(authorization: Optional[str]) -> tuple[str, str]:
    """FastAPI's ``get_authorization_scheme_param``, verbatim."""
    if not authorization:
        return "", ""
    scheme, _, param = authorization.partition(" ")
    return scheme, param


def _principal(payload: dict) -> dict:
    return {
        "sub": payload.get("sub"),
        "jti": payload.get("jti"),
        "ptype": payload.get("ptype"),
        "kind": payload.get("type"),
    }


def _outcome(verify: Verifier, token: str, kind: str) -> tuple[Optional[dict], str]:
    outcome = verify(token, kind)
    if isinstance(outcome, verification.Refusal):
        return None, outcome.reason
    if not outcome:  # None, or a verified but empty payload: the app refuses both
        return None, "empty"
    return outcome, "ok"


def decide(
    *,
    policy: str,
    method: str,
    authorization: Optional[str],
    raw_query: bytes | str,
    verify: Verifier,
) -> Decision:
    if method.upper() == "OPTIONS" or policy == "none":
        return Decision(True, reason="no_credential_required")
    if policy not in POLICIES:
        raise PolicyError(f"unknown route policy {policy!r}")

    if policy == "ticket":
        ticket = last_ticket(raw_query)
        if not ticket:
            return Decision(False, "ws_refused", "missing_ticket")
        payload, reason = _outcome(verify, ticket, verification.TICKET)
        if payload is None:
            return Decision(False, "ws_refused", reason, ticket)
        if not payload.get("sub"):
            return Decision(False, "ws_refused", "missing_sub", ticket)
        return Decision(True, reason="ok", token=ticket, principal=_principal(payload))

    if policy == "ticket_or_bearer":
        ticket = last_ticket(raw_query)
        if ticket:
            payload, reason = _outcome(verify, ticket, verification.TICKET)
            if payload is None:
                return Decision(False, "invalid_ticket", reason, ticket)
            return Decision(True, reason="ok", token=ticket, principal=_principal(payload))

    strict = policy == "bearer"
    scheme, credentials = scheme_and_credentials(authorization)
    if not (authorization and scheme and credentials):
        return Decision(False, "missing_bearer" if strict else "missing_flexible", "no_credentials")
    if scheme.lower() != "bearer":
        return Decision(False, "non_bearer_scheme" if strict else "missing_flexible", "non_bearer_scheme")
    payload, reason = _outcome(verify, credentials, verification.ACCESS)
    if payload is None:
        return Decision(False, "invalid_bearer", reason, credentials)
    return Decision(True, reason="ok", token=credentials, principal=_principal(payload))
