"""
Token verification rules, with every input injected (Phase 10.2a).

These are the rules ``tokens.verify`` has applied since Phase 9, moved here
unchanged so that they exist exactly once and can be run by something that is
not the core service: the gateway's token check (Phase 10) verifies against the
platform's *public* keys and must not hold the JWT secret, the MFA key, a
private key or ``Backend/.env``. So this module reads no configuration, no key
directory, no environment, no database and no Redis, and logs nothing. Its
callers supply:

* ``keyset`` — a zero-argument callable returning something with
  ``verification_key(kid) -> key | None`` (each key exposing ``alg`` and
  ``public_pem``), or ``None`` when no keyset is usable. It is called only once
  a token has passed the header checks, as ``tokens._current_keyset`` always
  was. ``keys.KeySet`` satisfies it; a set built from a JWKS can too.
* ``legacy`` — :class:`LegacyHS256` carrying the HMAC secret while legacy
  verification is on, or ``None`` when it is off (``CCURE_ACCEPT_LEGACY_HS256=
  false``, the live setting since the 9.6b cut-off). A verifier holding no
  secret always passes ``None``.
* ``issuer`` / ``audience`` — keyword-only, no defaults, as before.

**Outcomes.** A verified payload is returned as the claims dict. A refusal is a
:class:`Refusal` naming the reason code, the unverified header and whether the
legacy path was taken; the caller logs it (``tokens`` does, on the
``ccure.tokens`` logger, exactly as before) and turns it into ``None``.
:func:`verify` can also return ``None`` itself, unlogged, for the one case the
Phase 9 code returned ``None`` without a refusal (a verified but empty payload).

Nothing here may be reimplemented elsewhere; ``tests/repo/test_token_guardrails
.py`` allows a JWT library in this module and ``tokens`` only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Optional, Protocol, Union

from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

#: The token kinds, as carried in the ``type`` claim.
ACCESS = "access"
REFRESH = "refresh"
TICKET = "ticket"
MFA_CHALLENGE = "mfa_challenge"
USER_KINDS = frozenset({ACCESS, REFRESH, TICKET, MFA_CHALLENGE})
#: The one kind issued to a service identity (Phase 9.5).
SERVICE_ACCESS = "service_access"
KINDS = USER_KINDS | {SERVICE_ACCESS}

#: The principal type each kind is issued to. Explicit, never inferred from
#: ``sub`` (owner's decision, Phase 9 review).
PTYPE_USER = "user"
PTYPE_SERVICE = "service"
KIND_PTYPE = {
    ACCESS: PTYPE_USER,
    REFRESH: PTYPE_USER,
    TICKET: PTYPE_USER,
    MFA_CHALLENGE: PTYPE_USER,
    SERVICE_ACCESS: PTYPE_SERVICE,
}

#: The legacy symmetric algorithm. A token with this ``alg`` and **no** ``kid``
#: takes the fenced legacy path; any other shape takes the keyset path.
LEGACY_ALGORITHM = "HS256"

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
#: Header members that would let a token name or embed its own key. Refused.
REFUSED_HEADERS = frozenset({"jku", "x5u", "jwk", "x5c", "crit"})

#: The service client assertion (RFC 7523): ES256, lifetime at most 60 s.
SERVICE_ASSERTION_ALGORITHM = "ES256"
SERVICE_ASSERTION_MAX_LIFETIME = timedelta(seconds=60)

#: python-jose options for an asymmetric user or service token. Leeway 0 (O15).
_ASYMMETRIC_OPTIONS = {
    "require_aud": True,
    "require_iss": True,
    "require_sub": True,
    "require_jti": True,
    "require_iat": True,
    "require_nbf": True,
    "require_exp": True,
    "leeway": 0,
}
#: The same for a service assertion, which carries no ``nbf``.
_ASSERTION_OPTIONS = {
    "require_aud": True,
    "require_iss": True,
    "require_sub": True,
    "require_jti": True,
    "require_iat": True,
    "require_exp": True,
    "leeway": 0,
}


class VerificationKey(Protocol):
    """A public verification key: its algorithm and its SPKI PEM."""

    @property
    def alg(self) -> str: ...

    @property
    def public_pem(self) -> str: ...


class KeySource(Protocol):
    """Where keys are looked up, by ``kid`` and nothing else."""

    def verification_key(self, kid: str) -> Optional[VerificationKey]: ...


@dataclass(frozen=True)
class LegacyHS256:
    """Legacy HS256 verification is on, with this secret. Never logged."""

    secret: str = field(repr=False)


@dataclass(frozen=True)
class Refusal:
    """Why a token was refused. Carries nothing that could be replayed."""

    reason: str
    header: Optional[Mapping[str, Any]]
    legacy: bool


Outcome = Union[dict, Refusal, None]
KeysetProvider = Callable[[], Optional[KeySource]]


# ── unverified reads (logging, audit, routing only) ──────────────────────────


def header_of(token: str) -> dict:
    """A token's header, **not verified**; ``{}`` if it cannot be read."""
    try:
        return jwt.get_unverified_header(token)
    except JWTError:
        return {}


def claims_of(token: str) -> dict:
    """A token's claims, **not verified**; ``{}`` if they cannot be read."""
    try:
        claims = jwt.get_unverified_claims(token)
    except JWTError:
        return {}
    return claims if isinstance(claims, dict) else {}


def reason_for(exc: JWTError) -> str:
    """A reason code for a python-jose refusal."""
    if isinstance(exc, ExpiredSignatureError):
        return "expired"
    message = str(exc).lower()
    if "missing" in message:
        return "missing_claim"
    if isinstance(exc, JWTClaimsError):
        if "audience" in message:
            return "wrong_audience"
        if "issuer" in message:
            return "wrong_issuer"
        if "not yet valid" in message:
            return "not_yet_valid"
        return "invalid_claims"
    if "signature" in message:
        return "bad_signature"
    return "malformed"


# ── verification ─────────────────────────────────────────────────────────────


def decode(
    token: str,
    *,
    issuer: str,
    audience: str,
    keyset: KeysetProvider,
    legacy: Optional[LegacyHS256],
) -> Union[dict, Refusal]:
    """Signature, expiry and — for asymmetric tokens — issuer, audience, claims."""
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        return Refusal("malformed", None, False)
    if not isinstance(header, dict):
        return Refusal("malformed", None, False)
    if REFUSED_HEADERS & set(header):
        return Refusal("refused_header", header, False)
    alg, kid = header.get("alg"), header.get("kid")

    if alg == LEGACY_ALGORITHM and kid is None:
        # Legacy HS256, fenced: no kid, HMAC secret, only while switched on.
        if legacy is None:
            return Refusal("legacy_disabled", header, True)
        try:
            return jwt.decode(token, legacy.secret, algorithms=[LEGACY_ALGORITHM])
        except JWTError as exc:
            return Refusal(reason_for(exc), header, True)

    if not isinstance(kid, str) or not kid:
        return Refusal("missing_kid", header, False)
    keys = keyset()
    if keys is None:
        return Refusal("no_keyset", header, False)
    key = keys.verification_key(kid)
    if key is None:
        return Refusal("unknown_kid", header, False)
    if alg != key.alg:
        return Refusal("alg_mismatch", header, False)
    try:
        payload = jwt.decode(
            token,
            key.public_pem,
            algorithms=[key.alg],
            audience=audience,
            issuer=issuer,
            options=dict(_ASYMMETRIC_OPTIONS),
        )
    except JWTError as exc:
        return Refusal(reason_for(exc), header, False)
    if any(claim not in payload for claim in REQUIRED_ASYMMETRIC_CLAIMS):
        return Refusal("missing_claim", header, False)
    return payload


def verify(
    token: str,
    *,
    expected_kind: str,
    issuer: str,
    audience: str,
    keyset: KeysetProvider,
    legacy: Optional[LegacyHS256],
) -> Outcome:
    """
    The payload of ``token`` if it is correctly signed, unexpired, **of the
    expected kind**, and — for an asymmetric token — issued by ``issuer`` for
    ``audience`` to the principal type that kind is issued to; otherwise a
    :class:`Refusal` (or ``None``, see the module docstring).

    A kind this module does not know is a programming error and raises.
    """
    if expected_kind not in KINDS:
        raise ValueError(f"unknown token kind {expected_kind!r}")
    payload = decode(
        token, issuer=issuer, audience=audience, keyset=keyset, legacy=legacy
    )
    if isinstance(payload, Refusal):
        return payload
    if not payload:
        return None
    header = header_of(token)
    is_legacy = "kid" not in header
    if is_legacy and KIND_PTYPE[expected_kind] == PTYPE_SERVICE:
        # HS256 rests on a secret the api and every worker hold; no service
        # may authenticate with it (no shared secret, owner's decision).
        return Refusal("legacy_service", header, True)
    if payload.get("type") != expected_kind:
        return Refusal("wrong_kind", header, is_legacy)
    if not is_legacy and payload.get("ptype") != KIND_PTYPE[expected_kind]:
        return Refusal("wrong_ptype", header, False)
    return payload


def decode_any_kind(
    token: str,
    *,
    issuer: str,
    audience: str,
    keyset: KeysetProvider,
    legacy: Optional[LegacyHS256],
) -> Outcome:
    """
    A valid token of **any** kind — the legacy ``decode_token`` behaviour.
    Asymmetric tokens are still held to ``issuer``, ``audience`` and the
    ``user`` principal type.
    """
    payload = decode(
        token, issuer=issuer, audience=audience, keyset=keyset, legacy=legacy
    )
    if isinstance(payload, Refusal):
        return payload
    header = header_of(token)
    if payload and "kid" in header and payload.get("ptype") != PTYPE_USER:
        return Refusal("wrong_ptype", header, False)
    return payload


def verify_service_assertion(
    assertion: str,
    *,
    key_for: Callable[[str, str], Any],
    audience: str,
    now: Callable[[], datetime],
) -> Union[dict, Refusal]:
    """
    The claims of a service's client assertion (RFC 7523), or a Refusal.

    Signed by the **service's own** key: ``key_for(service_id, kid)`` returns a
    key only if that kid is registered to that service. Required: ES256 with a
    kid; ``iss`` = ``sub`` = the service id; ``aud`` = ``audience`` (the token
    endpoint); ``jti``; ``iat`` not after ``now()``; ``exp`` within
    :data:`SERVICE_ASSERTION_MAX_LIFETIME` of ``iat``. Leeway 0. Replay of the
    jti is the caller's check, made after this one.
    """
    try:
        header = jwt.get_unverified_header(assertion)
        claims = jwt.get_unverified_claims(assertion)
    except JWTError:
        return Refusal("malformed", None, False)
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return Refusal("malformed", None, False)
    if REFUSED_HEADERS & set(header):
        return Refusal("refused_header", header, False)
    kid, service_id = header.get("kid"), claims.get("iss")
    if header.get("alg") != SERVICE_ASSERTION_ALGORITHM:
        return Refusal("alg_mismatch", header, False)
    if not isinstance(kid, str) or not kid:
        return Refusal("missing_kid", header, False)
    if not isinstance(service_id, str) or not service_id:
        return Refusal("missing_claim", header, False)
    key = key_for(service_id, kid)
    if key is None:
        return Refusal("unknown_service_key", header, False)
    try:
        verified = jwt.decode(
            assertion,
            key.public_pem,
            algorithms=[SERVICE_ASSERTION_ALGORITHM],
            audience=audience,
            issuer=service_id,
            options=dict(_ASSERTION_OPTIONS),
        )
    except JWTError as exc:
        return Refusal(reason_for(exc), header, False)
    if verified.get("sub") != service_id:
        return Refusal("subject_mismatch", header, False)
    iat, exp = verified.get("iat"), verified.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
        return Refusal("invalid_claims", header, False)
    if iat > now().timestamp():
        return Refusal("not_yet_valid", header, False)
    if exp - iat > SERVICE_ASSERTION_MAX_LIFETIME.total_seconds():
        return Refusal("lifetime_too_long", header, False)
    if not isinstance(verified.get("jti"), str) or not verified["jti"]:
        return Refusal("missing_claim", header, False)
    return verified
