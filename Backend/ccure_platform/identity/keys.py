"""
The platform's token signing keys (Phase 9.3).

A **keyset** is a directory holding one PEM file per private key and a manifest,
``keyset.json``, that names each key's ``kid`` and lifecycle state. The API loads
it read-only; the Celery workers and beat never mount it
(docs/architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md §3.2, §4).

**States** (design §3.2):

    next      published in the JWKS, verifies, does not sign — a key
              distributed ahead of a rotation
    active    published, verifies, and is the key tokens are signed with
              (signing begins in step 9.4; in 9.3 nothing signs with it)
    retired   published and verifies, no longer signs — kept until every
              token it signed has expired
    removed   absent from the manifest: its tokens no longer verify

At most one key is ``active`` and at most one is ``next``.

**Identity of a key.** ``kid`` is the RFC 7638 JWK thumbprint of the public key,
so it names the key material itself. The manifest's ``kid`` must equal the
thumbprint computed from the file, or the keyset is refused — a manifest cannot
point a trusted ``kid`` at a different key.

**Algorithm.** ES256 (P-256) only: the owner's decision. Each key carries its
algorithm, and a verifier uses exactly that algorithm for that key.

**Refusal, never repair.** Anything wrong — a missing file, a thumbprint
mismatch, a second active key, an unknown state or algorithm, a key that is not
P-256, an empty keyset — raises :class:`KeySetError`. Deciding what the API does then is the
caller's business; nothing here guesses.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

MANIFEST = "keyset.json"
MANIFEST_VERSION = 1
ALGORITHM = "ES256"
STATES = ("next", "active", "retired")
#: Private JWK members. None may ever appear in a published key set.
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class KeySetError(Exception):
    """The keyset cannot be trusted as configured."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_jwk_members(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """The required members of an EC P-256 public JWK (RFC 7518 §6.2.1)."""
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise KeySetError(f"key is on {public_key.curve.name}, not P-256")
    numbers = public_key.public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def jwk_thumbprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """RFC 7638 thumbprint: SHA-256 over the required members, lexically ordered."""
    canonical = json.dumps(
        public_jwk_members(public_key), separators=(",", ":"), sort_keys=True
    )
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


@dataclass(frozen=True)
class SigningKey:
    kid: str
    state: str
    alg: str
    #: The private key object. Excluded from repr so it never reaches a log.
    private_key: ec.EllipticCurvePrivateKey = field(repr=False, compare=False)

    @property
    def public_pem(self) -> str:
        return (
            self.private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    def public_jwk(self) -> dict[str, str]:
        jwk = public_jwk_members(self.private_key.public_key())
        jwk.update({"kid": self.kid, "alg": self.alg, "use": "sig"})
        return jwk


@dataclass(frozen=True)
class KeySet:
    keys: tuple[SigningKey, ...]

    def verification_key(self, kid: str) -> SigningKey | None:
        """The key for ``kid`` if it is in a state that verifies."""
        for key in self.keys:
            if key.kid == kid:
                return key
        return None

    def in_state(self, state: str) -> tuple[SigningKey, ...]:
        return tuple(k for k in self.keys if k.state == state)

    def jwks(self) -> dict[str, Any]:
        """The published JWK Set: public members only, every verifying key."""
        return {"keys": [k.public_jwk() for k in self.keys]}


def _load_private_key(path: str) -> ec.EllipticCurvePrivateKey:
    try:
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
    except FileNotFoundError as exc:
        raise KeySetError(f"key file {os.path.basename(path)!r} is missing") from exc
    except (ValueError, TypeError) as exc:
        raise KeySetError(
            f"key file {os.path.basename(path)!r} is not an unencrypted PEM private key"
        ) from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise KeySetError(f"key file {os.path.basename(path)!r} is not an EC key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise KeySetError(f"key file {os.path.basename(path)!r} is not P-256")
    return key


def read_manifest(directory: str) -> dict[str, Any]:
    path = os.path.join(directory, MANIFEST)
    try:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except FileNotFoundError as exc:
        raise KeySetError(f"{MANIFEST} is missing from the keyset directory") from exc
    except json.JSONDecodeError as exc:
        raise KeySetError(f"{MANIFEST} is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("version") != MANIFEST_VERSION:
        raise KeySetError(
            f"{MANIFEST} must be an object with version {MANIFEST_VERSION}"
        )
    if not isinstance(manifest.get("keys"), list):
        raise KeySetError(f"{MANIFEST} must list its keys")
    return manifest


def load_keyset(directory: str) -> KeySet:
    """Load and fully validate the keyset in ``directory``, or raise KeySetError."""
    manifest = read_manifest(directory)
    keys: list[SigningKey] = []
    seen: set[str] = set()
    for entry in manifest["keys"]:
        if not isinstance(entry, dict):
            raise KeySetError("every manifest entry must be an object")
        kid, state, alg, filename = (
            entry.get("kid"),
            entry.get("state"),
            entry.get("alg"),
            entry.get("file"),
        )
        if not isinstance(kid, str) or not kid:
            raise KeySetError("a manifest entry has no kid")
        if kid in seen:
            raise KeySetError(f"kid {kid} appears twice")
        if state not in STATES:
            raise KeySetError(f"kid {kid} has unknown state {state!r}")
        if alg != ALGORITHM:
            raise KeySetError(
                f"kid {kid} has algorithm {alg!r}; only {ALGORITHM} is allowed"
            )
        if (
            not isinstance(filename, str)
            or not filename
            or os.path.basename(filename) != filename
            or filename.startswith(".")
        ):
            raise KeySetError(f"kid {kid} names an unsafe file {filename!r}")
        private_key = _load_private_key(os.path.join(directory, filename))
        actual = jwk_thumbprint(private_key.public_key())
        if actual != kid:
            raise KeySetError(
                f"kid {kid} does not match its key file (thumbprint {actual})"
            )
        seen.add(kid)
        keys.append(SigningKey(kid=kid, state=state, alg=alg, private_key=private_key))
    if not keys:
        # An empty set would publish as a JWKS that trusts nothing, which a
        # verifier caches; "not configured" (503) is the honest answer.
        raise KeySetError(f"{MANIFEST} lists no keys")
    for state in ("active", "next"):
        if sum(k.state == state for k in keys) > 1:
            raise KeySetError(f"more than one {state} key")
    return KeySet(keys=tuple(keys))
