"""
The key source: the platform's published JWK Set, fetched from the core and
cached. It implements what ``verification`` asks of a key source —
``verification_key(kid)`` returning something with ``alg`` and
``public_pem`` — from public members only.

Rules, each of which is a way a key source goes wrong silently:

* **Only EC P-256 / ES256 signing keys are taken.** Anything else in the set is
  skipped with a warning, never guessed at.
* **A set carrying a private member is refused whole.** ``d`` (or any RFC 7517
  private member) in a published set means the publisher is misconfigured; the
  last good set stays in force and the refusal is logged at ERROR.
* **A failed fetch never empties the cache.** The last good set stays until a
  good one replaces it. An empty or unparseable set counts as a failed fetch.
* **An unknown ``kid`` may trigger a refetch, at most once per
  ``min_refetch`` seconds**, so a rotated-in key is picked up within one
  request and a stream of forged kids cannot hammer the core.
* **The whole set is refetched after ``max_age`` seconds**, so a key removed
  from the set stops verifying here too.
* **No redirects are followed and the body is capped** (64 KiB): the URL is
  configuration, but the response is still input.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

log = logging.getLogger("gateway_auth.jwks")

#: RFC 7517 / 7518 private key members. None may appear in a published set.
PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
MAX_BODY_BYTES = 64 * 1024
FETCH_TIMEOUT_SECONDS = 2.0


class JwksError(Exception):
    """A fetched key set cannot be used."""


@dataclass(frozen=True)
class PublicKey:
    kid: str
    alg: str
    public_pem: str


def _b64url_int(value: str) -> int:
    if not isinstance(value, str) or not value:
        raise JwksError("coordinate is not a base64url string")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise JwksError("coordinate is not base64url") from exc
    if len(raw) != 32:
        raise JwksError("P-256 coordinate is not 32 bytes")
    return int.from_bytes(raw, "big")


def parse_jwks(document: object) -> dict[str, PublicKey]:
    """The usable keys of a JWK Set, by kid, or JwksError."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise JwksError("not a JWK Set")
    keys: dict[str, PublicKey] = {}
    for jwk in document["keys"]:
        if not isinstance(jwk, dict):
            raise JwksError("a key is not an object")
        leaked = PRIVATE_MEMBERS & set(jwk)
        if leaked:
            raise JwksError(f"the set publishes private member(s) {sorted(leaked)}")
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            log.warning("jwks: skipping a key without a kid")
            continue
        if (jwk.get("kty"), jwk.get("crv"), jwk.get("alg")) != ("EC", "P-256", "ES256"):
            log.warning("jwks: skipping kid=%r: not an EC P-256 ES256 key", kid[:64])
            continue
        if jwk.get("use") not in (None, "sig"):
            log.warning("jwks: skipping kid=%r: use=%r", kid[:64], jwk.get("use"))
            continue
        if kid in keys:
            raise JwksError(f"duplicate kid {kid[:64]!r}")
        try:
            public = ec.EllipticCurvePublicNumbers(
                _b64url_int(jwk.get("x")), _b64url_int(jwk.get("y")), ec.SECP256R1()
            ).public_key()
        except ValueError as exc:  # not a point on the curve
            raise JwksError(f"kid {kid[:64]!r} is not a valid P-256 point") from exc
        pem = public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        keys[kid] = PublicKey(kid=kid, alg="ES256", public_pem=pem)
    if not keys:
        raise JwksError("the set holds no usable key")
    return keys


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise JwksError(f"refusing to follow a {code} redirect")


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_fetch(url: str) -> object:
    """GET ``url`` and parse it as JSON, bounded in time and size."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with _OPENER.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        body = response.read(MAX_BODY_BYTES + 1)
    if len(body) > MAX_BODY_BYTES:
        raise JwksError("the key set is larger than 64 KiB")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise JwksError("the key set is not JSON") from exc


class JwksKeySource:
    """A cached, self-refreshing key source over a published JWK Set."""

    def __init__(
        self,
        url: str,
        *,
        max_age: float,
        min_refetch: float,
        fetch: Callable[[str], object] = http_fetch,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._url = url
        self._max_age = max_age
        self._min_refetch = min_refetch
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, PublicKey] = {}
        self._loaded_at: Optional[float] = None
        self._attempted_at: Optional[float] = None

    # -- state ---------------------------------------------------------------

    @property
    def ready(self) -> bool:
        return bool(self._keys)

    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    # -- fetching ------------------------------------------------------------

    def refresh(self) -> bool:
        """Fetch the set now. True if a good set was installed."""
        with self._lock:
            return self._refresh_locked()

    def _refresh_locked(self) -> bool:
        self._attempted_at = self._clock()
        try:
            keys = parse_jwks(self._fetch(self._url))
        except Exception as exc:  # any failure keeps the last good set
            level = logging.ERROR if isinstance(exc, JwksError) and "private" in str(exc) else logging.WARNING
            log.log(level, "jwks: fetch failed, keeping %d cached key(s): %s",
                    len(self._keys), exc)
            return False
        if set(keys) != set(self._keys):
            log.info("jwks: key set now %s", ", ".join(sorted(keys)))
        self._keys = keys
        self._loaded_at = self._clock()
        return True

    def _maybe_refresh(self, *, unknown_kid: bool) -> None:
        now = self._clock()
        stale = self._loaded_at is None or now - self._loaded_at >= self._max_age
        if not (stale or unknown_kid):
            return
        with self._lock:
            now = self._clock()
            if self._attempted_at is not None and now - self._attempted_at < self._min_refetch:
                return
            stale = self._loaded_at is None or now - self._loaded_at >= self._max_age
            if stale or unknown_kid:
                self._refresh_locked()

    # -- the KeySource protocol ---------------------------------------------

    def verification_key(self, kid: str) -> Optional[PublicKey]:
        self._maybe_refresh(unknown_kid=kid not in self._keys)
        return self._keys.get(kid)
