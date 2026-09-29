"""
The one place tokens are signed and verified (Phase 9.1, 9.3).

Every token the platform issues — ``access``, ``refresh``, ``ticket`` and
``mfa_challenge`` — is signed by :func:`sign` and checked by :func:`verify`.
Nothing else in the codebase may import a JWT library;
``tests/repo/test_token_guardrails.py`` fails if anything does.

**9.1** moved token handling here unchanged (HS256, python-jose, same claims and
lifetimes) and made the kind a required argument of :func:`verify`, so an
access-token endpoint can no longer accept a refresh, ticket or challenge token.

**9.3 adds verification of asymmetric tokens, and only verification.** Tokens
are still *issued* HS256; ES256 issuance is step 9.4. What 9.3 adds:

* **Keys are chosen by ``kid`` and nothing else.** An ES256 token must carry the
  ``kid`` of a key in the platform keyset (``keys.py``), and is verified with that
  key's own algorithm. The token's ``alg`` header can never choose the key type.
* **Issuer and audience are required** — :func:`verify` takes both as keyword-only
  arguments with no default. An asymmetric token must carry ``iss`` equal to the
  platform issuer, ``aud`` containing the expected audience, and ``sub``,
  ``jti``, ``iat``, ``nbf``, ``exp`` and ``ptype`` (``user`` for these four kinds).
* **The legacy HS256 path is fenced**: taken only when the header is
  ``alg: HS256`` with **no** ``kid``, and only while
  ``CCURE_ACCEPT_LEGACY_HS256`` is on (the default until step 9.6). It verifies
  with the HMAC secret, never with a public key. Legacy tokens carry no issuer or
  audience, so none is checked on that path — which is exactly why it is fenced
  and time-limited.
* ``none``, any other algorithm, an HS256 token carrying a ``kid``, an unknown
  ``kid``, and any ``jku`` / ``x5u`` / ``jwk`` / ``x5c`` / ``crit`` header are
  refused. No key is ever fetched from or embedded in a token.

**The legacy any-kind decode.** :func:`decode_any_kind` is what
``jwt_handler.decode_token`` has always done — any kind, no ``type`` check — kept
for the two WebSocket ticket logins (Phase 10) and the rate-limit audit. It
applies the same dual verification, with the platform issuer and user audience,
so those unchanged callers will accept ES256 tickets once 9.4 issues them.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from ccure_platform.identity import keys as keyset_mod
from config import JWTConfig
from jose import JWTError, jwt

log = logging.getLogger("ccure.tokens")

#: The token kinds, as carried in the ``type`` claim. Unchanged.
ACCESS = "access"
REFRESH = "refresh"
TICKET = "ticket"
MFA_CHALLENGE = "mfa_challenge"
KINDS = frozenset({ACCESS, REFRESH, TICKET, MFA_CHALLENGE})

#: The principal type each kind is issued to. Explicit, never inferred from
#: ``sub`` (owner's decision, Phase 9 review).
PTYPE_USER = "user"
KIND_PTYPE = {
    ACCESS: PTYPE_USER,
    REFRESH: PTYPE_USER,
    TICKET: PTYPE_USER,
    MFA_CHALLENGE: PTYPE_USER,
}

SECRET_KEY: str = JWTConfig.SECRET_KEY
ALGORITHM = "HS256"

#: The platform issuer and the audience of user tokens (owner's decisions,
#: 29 Sep 2026). The issuer must never change for the life of the platform.
ISSUER: str = JWTConfig.TOKEN_ISSUER
USER_AUDIENCE: str = JWTConfig.TOKEN_USER_AUDIENCE

#: Claims an asymmetric token must carry.
REQUIRED_ASYMMETRIC_CLAIMS = (
    "iss",
    "aud",
    "sub",
    "type",
    "ptype",
    "jti",
    "iat",
    "nbf",
    "exp",
)
_REFUSED_HEADERS = frozenset({"jku", "x5u", "jwk", "x5c", "crit"})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── the keyset ────────────────────────────────────────────────────────────────

_KEYSET_UNLOADED = object()
_keyset: Any = _KEYSET_UNLOADED
_keyset_problem: str | None = None


def _current_keyset() -> keyset_mod.KeySet | None:
    """
    The configured keyset, loaded once. None when no keyset directory is
    configured or it failed validation — asymmetric tokens are then refused and
    HS256 verification is unaffected. The reason is kept for the start-up log.
    """
    global _keyset, _keyset_problem
    if _keyset is _KEYSET_UNLOADED:
        directory = JWTConfig.TOKEN_KEYS_DIR
        if not directory:
            _keyset, _keyset_problem = (
                None,
                "not configured (CCURE_TOKEN_KEYS_DIR unset)",
            )
        else:
            try:
                _keyset, _keyset_problem = keyset_mod.load_keyset(directory), None
            except keyset_mod.KeySetError as exc:
                _keyset, _keyset_problem = None, f"refused: {exc}"
    return _keyset


def keyset_status() -> str:
    """One line for the start-up log: kids and states, or why there is no keyset."""
    keyset = _current_keyset()
    if keyset is None:
        return _keyset_problem or "not configured"
    return ", ".join(f"{k.kid} ({k.state})" for k in keyset.keys) or "empty"


def public_jwks() -> dict[str, Any] | None:
    """The JWK Set to publish, or None when there is no usable keyset."""
    keyset = _current_keyset()
    return keyset.jwks() if keyset is not None else None


# ── signing (HS256 until step 9.4) ────────────────────────────────────────────


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


# ── verification ─────────────────────────────────────────────────────────────


def _decode(token: str, *, issuer: str, audience: str) -> dict | None:
    """Signature, expiry and — for asymmetric tokens — issuer, audience, claims."""
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        return None
    if not isinstance(header, dict) or _REFUSED_HEADERS & set(header):
        return None
    alg, kid = header.get("alg"), header.get("kid")

    if alg == ALGORITHM and kid is None:
        # Legacy HS256, fenced: no kid, HMAC secret, until the 9.6 cut-off.
        if not JWTConfig.ACCEPT_LEGACY_HS256:
            return None
        try:
            return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            return None

    if not isinstance(kid, str) or not kid:
        return None
    keyset = _current_keyset()
    if keyset is None:
        return None
    key = keyset.verification_key(kid)
    if key is None or alg != key.alg:
        return None
    try:
        payload = jwt.decode(
            token,
            key.public_pem,
            algorithms=[key.alg],
            audience=audience,
            issuer=issuer,
            options={
                "require_aud": True,
                "require_iss": True,
                "require_sub": True,
                "require_jti": True,
                "require_iat": True,
                "require_nbf": True,
                "require_exp": True,
                "leeway": 0,
            },
        )
    except JWTError:
        return None
    if any(claim not in payload for claim in REQUIRED_ASYMMETRIC_CLAIMS):
        return None
    return payload


def decode_any_kind(token: str) -> dict | None:
    """
    The payload of a valid token of **any** kind, or None.

    The legacy behaviour of ``jwt_handler.decode_token``, for its fixed set of
    callers (see the module docstring). Asymmetric tokens are held to the
    platform issuer, the user audience and the ``user`` principal type.
    """
    payload = _decode(token, issuer=ISSUER, audience=USER_AUDIENCE)
    if payload and "kid" in _header(token) and payload.get("ptype") != PTYPE_USER:
        return None
    return payload


def _header(token: str) -> dict:
    try:
        return jwt.get_unverified_header(token)
    except JWTError:
        return {}


def verify(
    token: str, *, expected_kind: str, issuer: str, audience: str
) -> dict | None:
    """
    The payload of ``token`` if it is correctly signed, unexpired, **of the
    expected kind**, and — for an asymmetric token — issued by ``issuer`` for
    ``audience`` to the principal type that kind is issued to; otherwise None.

    ``expected_kind``, ``issuer`` and ``audience`` have no defaults. A kind this
    module does not issue is a programming error and raises.
    """
    if expected_kind not in KINDS:
        raise ValueError(f"unknown token kind {expected_kind!r}")
    payload = _decode(token, issuer=issuer, audience=audience)
    if not payload or payload.get("type") != expected_kind:
        return None
    if "kid" in _header(token) and payload.get("ptype") != KIND_PTYPE[expected_kind]:
        return None
    return payload
