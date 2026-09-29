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

**9.4 switches issuance to ES256.** :func:`sign` signs with the keyset's one
``active`` key, puts its ``kid`` in the header, and sets ``iss``, ``aud``,
``ptype``, ``nbf`` and (unless the caller chose one) ``jti`` itself, so no
caller can mint a token without them. ``CCURE_TOKEN_SIGNING_ALG=HS256`` is the
rollback: it issues exactly the token 9.3 issued, and tokens already issued
ES256 stay valid because verification accepts both. With ES256 selected and no
usable active key, :func:`assert_signing_ready` refuses — the API does not start
(design §3.7) rather than issue tokens nobody can verify, or silently fall back.

**9.5 adds service tokens.** :func:`sign_service_token` issues the one
service kind, ``service_access`` (``ptype`` ``service``, ``sub`` ``svc:<id>``,
``aud`` the service it is for, a ``tenant`` and a ``scope``), always ES256 with
the active key — never HS256, whose secret is shared. :func:`sign` refuses that
kind, and :func:`verify` refuses it on the legacy path. A service proves itself
with an assertion signed by its own key, checked by
:func:`verify_service_assertion` against the key registered to that service
(``ccure_platform/service_identity/``).

**Refusals are logged, never the token.** Every refusal names a reason code
(``expired``, ``unknown_kid``, ``wrong_audience``, …) with the unverified
``kid``, ``jti`` and ``ptype`` — enough to correlate, nothing to replay.
Responses stay uniform; only the log says why.

**The legacy any-kind decode.** :func:`decode_any_kind` is what
``jwt_handler.decode_token`` has always done — any kind, no ``type`` check — kept
for the two WebSocket ticket logins (Phase 10) and the rate-limit audit. It
applies the same dual verification, with the platform issuer and user audience,
so those unchanged callers will accept ES256 tickets once 9.4 issues them.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from ccure_platform.identity import keys as keyset_mod
from config import JWTConfig
from cryptography.hazmat.primitives import serialization
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

log = logging.getLogger("ccure.tokens")

#: The token kinds, as carried in the ``type`` claim. Unchanged.
ACCESS = "access"
REFRESH = "refresh"
TICKET = "ticket"
MFA_CHALLENGE = "mfa_challenge"
USER_KINDS = frozenset({ACCESS, REFRESH, TICKET, MFA_CHALLENGE})
#: The one kind issued to a service identity (Phase 9.5). Never by sign().
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

#: What tokens may be issued with (``CCURE_TOKEN_SIGNING_ALG``). ES256 is the
#: platform algorithm; HS256 is the rollback and issues exactly the 9.3 token.
SIGNING_ALGORITHMS = ("ES256", ALGORITHM)
#: Claims sign() sets itself on an ES256 token. A caller supplying one is a
#: programming error, refused rather than silently overwritten.
_SIGNER_SET_CLAIMS = frozenset({"iss", "aud", "ptype", "iat", "nbf", "exp"})


#: Service tokens (Phase 9.5, owner's decisions of 29 Sep 2026). The audience
#: is the service the token is for, never the user audience, so a service
#: token is refused wherever a user token is expected and the reverse.
CORE_SERVICE_AUDIENCE = "urn:ccure:core"
IR_SERVICE_AUDIENCE = "urn:ccure:ir"
SERVICE_AUDIENCES = frozenset({CORE_SERVICE_AUDIENCE, IR_SERVICE_AUDIENCE})
SERVICE_TOKEN_LIFETIME = timedelta(minutes=10)
#: A service's own sub namespace, which no user id can take.
SERVICE_SUBJECT_PREFIX = "svc:"
#: The client assertion (RFC 7523): audience is the token endpoint's URL, the
#: lifetime at most 60 seconds, and each jti is accepted once.
SERVICE_ASSERTION_AUDIENCE = f"{ISSUER}/api/auth/service-token"
SERVICE_ASSERTION_MAX_LIFETIME = timedelta(seconds=60)
_SERVICE_ASSERTION_ALGORITHM = "ES256"


class SigningUnavailable(RuntimeError):
    """Tokens cannot be issued as configured."""


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


# ── signing (ES256 since step 9.4; HS256 is the rollback) ─────────────────────


def signing_algorithm() -> str:
    """The configured issuance algorithm, or SigningUnavailable if unknown."""
    alg = (JWTConfig.TOKEN_SIGNING_ALG or "").strip().upper()
    if alg not in SIGNING_ALGORITHMS:
        raise SigningUnavailable(
            f"CCURE_TOKEN_SIGNING_ALG={JWTConfig.TOKEN_SIGNING_ALG!r} is not one "
            f"of {', '.join(SIGNING_ALGORITHMS)}"
        )
    return alg


def signing_key() -> keyset_mod.SigningKey:
    """The keyset's one ``active`` key, or SigningUnavailable."""
    keyset = _current_keyset()
    if keyset is None:
        raise SigningUnavailable(f"no usable token keyset: {_keyset_problem}")
    active = keyset.in_state("active")
    if not active:
        raise SigningUnavailable("the token keyset has no active key")
    return active[0]


def assert_signing_ready() -> str:
    """
    The start-up check (design §3.7): one line naming how tokens will be
    issued, or SigningUnavailable. main.py refuses to start on the latter —
    a core that cannot sign must not come up half-working.
    """
    if signing_algorithm() == ALGORITHM:
        return "HS256 (legacy issuance, CCURE_TOKEN_SIGNING_ALG=HS256)"
    key = signing_key()
    return f"{key.alg} with key {key.kid}"


def _private_pem(key: keyset_mod.SigningKey) -> str:
    return key.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def sign(claims: Mapping[str, Any], lifetime: timedelta) -> str:
    """
    Sign ``claims`` with ``iat`` = now and ``exp`` = now + ``lifetime``.

    ES256 (the default): the active key signs and its ``kid`` goes in the
    header; ``iss``, ``aud``, ``ptype`` and ``nbf`` (= ``iat``) are set here,
    and a ``jti`` unless the caller chose one (the refresh token does, because
    its session row is keyed on it). ``type`` must be a kind this module issues.

    HS256 (``CCURE_TOKEN_SIGNING_ALG=HS256``, the rollback): exactly what 9.3
    signed — the claims copied, ``iat`` and ``exp`` added, the HMAC secret.
    """
    now = _utcnow()
    payload = dict(claims)
    if payload.get("type") == SERVICE_ACCESS:
        # Service tokens come only from sign_service_token(), never HS256.
        raise ValueError("service tokens are issued by sign_service_token()")
    if signing_algorithm() == ALGORITHM:
        payload["iat"] = now
        payload["exp"] = now + lifetime
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    reserved = _SIGNER_SET_CLAIMS & set(payload)
    if reserved:
        raise ValueError(f"sign() sets {sorted(reserved)} itself")
    kind = payload.get("type")
    if kind not in USER_KINDS:
        raise ValueError(f"unknown token kind {kind!r}")
    key = signing_key()
    payload.update(
        iss=ISSUER,
        aud=USER_AUDIENCE,
        ptype=KIND_PTYPE[kind],
        iat=now,
        nbf=now,
        exp=now + lifetime,
    )
    payload.setdefault("jti", secrets.token_urlsafe(16))
    return jwt.encode(
        payload, _private_pem(key), algorithm=key.alg, headers={"kid": key.kid}
    )


def sign_service_token(
    *, service_id: str, audience: str, scopes: frozenset[str] | set[str], tenant: str
) -> str:
    """
    A ``service_access`` token (Phase 9.5) for ``service_id``, to call the
    service named by ``audience``, bound to one ``tenant``, carrying exactly
    ``scopes``. Always ES256 with the active key: a service token is never
    HS256, whatever CCURE_TOKEN_SIGNING_ALG says, because the HMAC secret is
    shared and service authentication must not rest on a shared secret.

    The caller has already authenticated the service and checked that the
    scopes and the tenant are granted; this function only refuses what no
    caller may ask for.
    """
    if audience not in SERVICE_AUDIENCES:
        raise ValueError(f"unknown service audience {audience!r}")
    if not service_id or SERVICE_SUBJECT_PREFIX in service_id:
        raise ValueError(f"invalid service id {service_id!r}")
    if not scopes:
        raise ValueError("a service token needs at least one scope")
    if not tenant:
        raise ValueError("a service token is bound to exactly one tenant")
    key = signing_key()
    now = _utcnow()
    payload = {
        "iss": ISSUER,
        "aud": audience,
        "sub": f"{SERVICE_SUBJECT_PREFIX}{service_id}",
        "type": SERVICE_ACCESS,
        "ptype": PTYPE_SERVICE,
        "scope": " ".join(sorted(scopes)),
        "tenant": str(tenant),
        "jti": secrets.token_urlsafe(16),
        "iat": now,
        "nbf": now,
        "exp": now + SERVICE_TOKEN_LIFETIME,
    }
    return jwt.encode(
        payload, _private_pem(key), algorithm=key.alg, headers={"kid": key.kid}
    )


# ── verification ─────────────────────────────────────────────────────────────

#: Reasons that are routine in normal use and logged at INFO; every other
#: refusal is WARNING, because it means a malformed, forged or misdirected token.
_ROUTINE_REFUSALS = frozenset({"expired", "wrong_kind"})
_LOGGED_VALUE_LIMIT = 64


def _loggable(value: Any) -> str | None:
    """An unverified header or claim value, bounded, for a log line."""
    if value is None:
        return None
    text = str(value)
    return (
        text if len(text) <= _LOGGED_VALUE_LIMIT else text[:_LOGGED_VALUE_LIMIT] + "…"
    )


def _refuse(reason: str, token: str, header: Mapping | None, *, legacy: bool) -> None:
    """
    Log why a token was refused and return None. The token itself is never
    logged: only the reason and the unverified kid, jti and ptype, which
    correlate a refusal with an issuance without being replayable.
    """
    try:
        claims = jwt.get_unverified_claims(token)
    except JWTError:
        claims = {}
    if not isinstance(claims, dict):
        claims = {}
    header = header if isinstance(header, Mapping) else {}
    log.log(
        logging.INFO if reason in _ROUTINE_REFUSALS else logging.WARNING,
        "token refused: reason=%s legacy=%s kid=%r jti=%r ptype=%r",
        reason,
        legacy,
        _loggable(header.get("kid")),
        _loggable(claims.get("jti")),
        _loggable(claims.get("ptype")),
    )
    return None


def _reason_for(exc: JWTError) -> str:
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


def _decode(token: str, *, issuer: str, audience: str) -> dict | None:
    """Signature, expiry and — for asymmetric tokens — issuer, audience, claims."""
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        return _refuse("malformed", token, None, legacy=False)
    if not isinstance(header, dict):
        return _refuse("malformed", token, None, legacy=False)
    if _REFUSED_HEADERS & set(header):
        return _refuse("refused_header", token, header, legacy=False)
    alg, kid = header.get("alg"), header.get("kid")

    if alg == ALGORITHM and kid is None:
        # Legacy HS256, fenced: no kid, HMAC secret, until the 9.6 cut-off.
        if not JWTConfig.ACCEPT_LEGACY_HS256:
            return _refuse("legacy_disabled", token, header, legacy=True)
        try:
            return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError as exc:
            return _refuse(_reason_for(exc), token, header, legacy=True)

    if not isinstance(kid, str) or not kid:
        return _refuse("missing_kid", token, header, legacy=False)
    keyset = _current_keyset()
    if keyset is None:
        return _refuse("no_keyset", token, header, legacy=False)
    key = keyset.verification_key(kid)
    if key is None:
        return _refuse("unknown_kid", token, header, legacy=False)
    if alg != key.alg:
        return _refuse("alg_mismatch", token, header, legacy=False)
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
    except JWTError as exc:
        return _refuse(_reason_for(exc), token, header, legacy=False)
    if any(claim not in payload for claim in REQUIRED_ASYMMETRIC_CLAIMS):
        return _refuse("missing_claim", token, header, legacy=False)
    return payload


def decode_any_kind(token: str) -> dict | None:
    """
    The payload of a valid token of **any** kind, or None.

    The legacy behaviour of ``jwt_handler.decode_token``, for its fixed set of
    callers (see the module docstring). Asymmetric tokens are held to the
    platform issuer, the user audience and the ``user`` principal type.
    """
    payload = _decode(token, issuer=ISSUER, audience=USER_AUDIENCE)
    header = _header(token)
    if payload and "kid" in header and payload.get("ptype") != PTYPE_USER:
        return _refuse("wrong_ptype", token, header, legacy=False)
    return payload


def _header(token: str) -> dict:
    try:
        return jwt.get_unverified_header(token)
    except JWTError:
        return {}


def unverified_header(token: str) -> dict:
    """A token's header, **not verified** — for logging and audit only."""
    return _header(token)


def unverified_claims(token: str) -> dict:
    """A token's claims, **not verified** — for logging and audit only."""
    try:
        claims = jwt.get_unverified_claims(token)
    except JWTError:
        return {}
    return claims if isinstance(claims, dict) else {}


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
    if not payload:
        return None
    header = _header(token)
    legacy = "kid" not in header
    if legacy and KIND_PTYPE[expected_kind] == PTYPE_SERVICE:
        # HS256 rests on a secret the api and every worker hold; no service
        # may authenticate with it (no shared secret, owner's decision).
        return _refuse("legacy_service", token, header, legacy=True)
    if payload.get("type") != expected_kind:
        return _refuse("wrong_kind", token, header, legacy=legacy)
    if not legacy and payload.get("ptype") != KIND_PTYPE[expected_kind]:
        return _refuse("wrong_ptype", token, header, legacy=False)
    return payload


# ── service assertions (RFC 7523 client authentication, Phase 9.5) ────────────


def verify_service_assertion(
    assertion: str, *, key_for: Callable[[str, str], Any]
) -> dict | None:
    """
    The claims of a service's client assertion, or None (reason logged).

    The assertion is signed by the **service's own** private key. ``key_for``
    is the registry's lookup ``(service_id, kid) -> key | None``: it returns a
    key only if that kid is registered **to that service**, so one service's
    key can never authenticate another, and a platform signing key — never
    registered to a service — authenticates nothing.

    Required: ES256 with a kid; ``iss`` = ``sub`` = the service id; ``aud`` =
    the token endpoint; ``jti``; ``iat`` not in the future; ``exp`` within
    ``SERVICE_ASSERTION_MAX_LIFETIME`` of ``iat``. Leeway 0 (O15). Whether the
    jti was seen before is the caller's check, after this one, so an
    unauthenticated caller can never fill the replay store.
    """
    try:
        header = jwt.get_unverified_header(assertion)
        claims = jwt.get_unverified_claims(assertion)
    except JWTError:
        return _refuse("malformed", assertion, None, legacy=False)
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return _refuse("malformed", assertion, None, legacy=False)
    if _REFUSED_HEADERS & set(header):
        return _refuse("refused_header", assertion, header, legacy=False)
    kid, service_id = header.get("kid"), claims.get("iss")
    if header.get("alg") != _SERVICE_ASSERTION_ALGORITHM:
        return _refuse("alg_mismatch", assertion, header, legacy=False)
    if not isinstance(kid, str) or not kid:
        return _refuse("missing_kid", assertion, header, legacy=False)
    if not isinstance(service_id, str) or not service_id:
        return _refuse("missing_claim", assertion, header, legacy=False)
    key = key_for(service_id, kid)
    if key is None:
        return _refuse("unknown_service_key", assertion, header, legacy=False)
    try:
        verified = jwt.decode(
            assertion,
            key.public_pem,
            algorithms=[_SERVICE_ASSERTION_ALGORITHM],
            audience=SERVICE_ASSERTION_AUDIENCE,
            issuer=service_id,
            options={
                "require_aud": True,
                "require_iss": True,
                "require_sub": True,
                "require_jti": True,
                "require_iat": True,
                "require_exp": True,
                "leeway": 0,
            },
        )
    except JWTError as exc:
        return _refuse(_reason_for(exc), assertion, header, legacy=False)
    if verified.get("sub") != service_id:
        return _refuse("subject_mismatch", assertion, header, legacy=False)
    iat, exp = verified.get("iat"), verified.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
        return _refuse("invalid_claims", assertion, header, legacy=False)
    now = _utcnow().timestamp()
    if iat > now:
        return _refuse("not_yet_valid", assertion, header, legacy=False)
    if exp - iat > SERVICE_ASSERTION_MAX_LIFETIME.total_seconds():
        return _refuse("lifetime_too_long", assertion, header, legacy=False)
    if not isinstance(verified.get("jti"), str) or not verified["jti"]:
        return _refuse("missing_claim", assertion, header, legacy=False)
    return verified
