"""
The one place tokens are signed and verified (Phase 9.1).

Every token the platform issues — ``access``, ``refresh``, ``ticket`` and
``mfa_challenge`` — is signed by :func:`sign` and checked by :func:`verify`.
Nothing else in the codebase may import a JWT library;
``tests/repo/test_token_guardrails.py`` fails if anything does.

**What 9.1 changed, and what it did not.** The token handling that lived in
``jwt_handler`` moved here unchanged: HS256, the ``JWT_SECRET_KEY`` from
``config.JWTConfig``, python-jose, the same claims and the same lifetimes. The
public functions in ``jwt_handler`` keep their names, signatures and results
and call into this module. ``tests/auth/test_token_characterisation.py`` was
written against the code before the move and passes unchanged after it.

**The one structural change: a token is verified *as a kind*.** Callers used to
decode a token and then check ``payload.get("type")`` by hand — ten call sites,
each one a place an access-token endpoint could forget and accept a refresh,
ticket or challenge token (finding F9-3). :func:`verify` takes the expected
kind as a required keyword argument and returns nothing for a token of any
other kind, so that check can no longer be forgotten.

**Issuer and audience** are not checked yet because today's tokens do not carry
them. They become required keyword-only arguments of :func:`verify` in the
steps that introduce the claims (Phase 9.3/9.4). Being keyword-only now means
that change fails every caller at once rather than letting one silently omit
them.

**The legacy decode.** :func:`decode_any_kind` is what ``jwt_handler.decode_token``
has always done — verify signature and expiry, return the payload whatever its
kind. It is kept, and kept separate, only for the callers the owner has put
outside Phase 9: the two WebSocket ticket logins (Phase 10) and the rate-limit
audit, both of which check the kind themselves. The guardrail test pins who may
call it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from config import JWTConfig
from jose import JWTError, jwt

#: The token kinds, as carried in the ``type`` claim. Unchanged.
ACCESS = "access"
REFRESH = "refresh"
TICKET = "ticket"
MFA_CHALLENGE = "mfa_challenge"
KINDS = frozenset({ACCESS, REFRESH, TICKET, MFA_CHALLENGE})

SECRET_KEY: str = JWTConfig.SECRET_KEY
ALGORITHM = "HS256"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sign(claims: Mapping[str, Any], lifetime: timedelta) -> str:
    """
    Sign ``claims`` with ``iat`` = now and ``exp`` = now + ``lifetime``.

    Exactly what ``jwt_handler._create_token`` did: the claims are copied,
    ``iat`` and ``exp`` set from one clock reading, HS256 with the configured
    secret.
    """
    now = _utcnow()
    payload = dict(claims)
    payload["iat"] = now
    payload["exp"] = now + lifetime
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_any_kind(token: str) -> dict | None:
    """
    The payload of a correctly signed, unexpired token of **any** kind, or None.

    The legacy behaviour of ``jwt_handler.decode_token``. New code uses
    :func:`verify`, which binds the kind; see the module docstring for the
    callers this is kept for.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def verify(token: str, *, expected_kind: str) -> dict | None:
    """
    The payload of ``token`` if it is correctly signed, unexpired **and of the
    expected kind**; otherwise None.

    ``expected_kind`` has no default. A kind this module does not issue is a
    programming error and raises, rather than quietly matching nothing.
    """
    if expected_kind not in KINDS:
        raise ValueError(f"unknown token kind {expected_kind!r}")
    payload = decode_any_kind(token)
    if not payload or payload.get("type") != expected_kind:
        return None
    return payload
