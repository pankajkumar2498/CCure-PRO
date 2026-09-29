"""
The service-identity registry (Phase 9.5).

A directory holding ``services.json`` and one PEM file per service **public**
key, mounted read-only into the api only. It is a static registry by the
owner's decision (29 Sep 2026): no database table until a reviewed schema is
approved. Changing it — registering, disabling, adding or removing a key —
is done with ``scripts/security/register_service_identity.py`` and takes
effect when the api restarts.

    {"version": 1,
     "services": [
       {"id": "ir", "name": "Incident Response", "module": "ir",
        "status": "active",                  # or "disabled"
        "audience": "urn:ccure:core",        # the service it may call
        "scopes": ["audit:findings:read"],   # the most it may be granted
        "tenants": ["org_default"],          # the tenants it may act for
        "keys": [{"kid": "<RFC 7638 thumbprint>", "file": "ir-….pem"}]}]}

**Refusal, never repair.** Anything wrong refuses the whole registry: an
unknown field value, a duplicate id or kid, a kid that is not its key's
thumbprint, a key that is not P-256, a file holding a **private** key, a kid
that is also a platform signing key. A refused registry authenticates no
service; human sign-in is unaffected.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from ccure_platform.identity import keys as keyset_mod
from ccure_platform.identity import tokens
from config import JWTConfig
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

MANIFEST = "services.json"
MANIFEST_VERSION = 1
STATUSES = ("active", "disabled")
_SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
#: module:resource:action, e.g. audit:findings:read. Each module decides what
#: a scope permits (design §3.5); the registry only bounds what may be granted.
SCOPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")


class RegistryError(Exception):
    """The registry cannot be trusted as configured."""


@dataclass(frozen=True)
class ServiceKey:
    kid: str
    public_pem: str = field(repr=False)


@dataclass(frozen=True)
class ServiceIdentity:
    id: str
    name: str
    module: str
    status: str
    audience: str
    scopes: frozenset[str]
    tenants: tuple[str, ...]
    keys: tuple[ServiceKey, ...]

    @property
    def active(self) -> bool:
        return self.status == "active"

    @property
    def subject(self) -> str:
        return f"{tokens.SERVICE_SUBJECT_PREFIX}{self.id}"

    def key(self, kid: str) -> ServiceKey | None:
        for key in self.keys:
            if key.kid == kid:
                return key
        return None


@dataclass(frozen=True)
class ServiceRegistry:
    services: tuple[ServiceIdentity, ...] = ()

    def get(self, service_id: str) -> ServiceIdentity | None:
        for service in self.services:
            if service.id == service_id:
                return service
        return None

    def key_for(self, service_id: str, kid: str) -> ServiceKey | None:
        """The key ``kid`` only if it is registered to ``service_id``."""
        service = self.get(service_id)
        return service.key(kid) if service else None

    def by_subject(self, subject: str) -> ServiceIdentity | None:
        if not subject.startswith(tokens.SERVICE_SUBJECT_PREFIX):
            return None
        return self.get(subject[len(tokens.SERVICE_SUBJECT_PREFIX) :])


def _load_public_key(path: str) -> ec.EllipticCurvePublicKey:
    name = os.path.basename(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError as exc:
        raise RegistryError(f"key file {name!r} is missing") from exc
    if b"PRIVATE KEY" in data:
        # The platform must never hold a service's private key.
        raise RegistryError(f"key file {name!r} holds a private key")
    try:
        loaded = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise RegistryError(f"key file {name!r} is not a PEM public key") from exc
    if not isinstance(loaded, ec.EllipticCurvePublicKey):
        raise RegistryError(f"key file {name!r} is not an EC key")
    if not isinstance(loaded.curve, ec.SECP256R1):
        raise RegistryError(f"key file {name!r} is not a P-256 key")
    return loaded


def _strings(value: Any, what: str, service_id: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise RegistryError(f"service {service_id}: {what} must be a list of strings")
    if len(set(value)) != len(value):
        raise RegistryError(f"service {service_id}: {what} has duplicates")
    return value


def read_manifest(directory: str) -> dict[str, Any]:
    path = os.path.join(directory, MANIFEST)
    try:
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except FileNotFoundError as exc:
        raise RegistryError(f"{MANIFEST} is missing from the registry") from exc
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{MANIFEST} is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("version") != MANIFEST_VERSION:
        raise RegistryError(f"{MANIFEST} must be an object with version 1")
    if not isinstance(manifest.get("services"), list):
        raise RegistryError(f"{MANIFEST} must list its services")
    return manifest


def load_registry(
    directory: str, *, forbidden_kids: Iterable[str] = ()
) -> ServiceRegistry:
    """Load and fully validate the registry, or raise RegistryError."""
    manifest = read_manifest(directory)
    forbidden = set(forbidden_kids)
    services: list[ServiceIdentity] = []
    seen_ids: set[str] = set()
    seen_kids: set[str] = set()
    for entry in manifest["services"]:
        if not isinstance(entry, dict):
            raise RegistryError("every service entry must be an object")
        service_id = entry.get("id")
        if not isinstance(service_id, str) or not _SERVICE_ID.match(service_id):
            raise RegistryError(f"invalid service id {service_id!r}")
        if service_id in seen_ids:
            raise RegistryError(f"service {service_id} appears twice")
        name, module = entry.get("name"), entry.get("module")
        if not isinstance(name, str) or not name:
            raise RegistryError(f"service {service_id}: name is required")
        if not isinstance(module, str) or not module:
            raise RegistryError(f"service {service_id}: module is required")
        if entry.get("status") not in STATUSES:
            raise RegistryError(f"service {service_id}: unknown status")
        if entry.get("audience") not in tokens.SERVICE_AUDIENCES:
            raise RegistryError(f"service {service_id}: unknown audience")
        scopes = _strings(entry.get("scopes"), "scopes", service_id)
        bad = [s for s in scopes if not SCOPE_PATTERN.match(s)]
        if bad:
            raise RegistryError(f"service {service_id}: invalid scopes {bad}")
        tenants = _strings(entry.get("tenants"), "tenants", service_id)
        if not tenants:
            raise RegistryError(f"service {service_id}: at least one tenant")
        raw_keys = entry.get("keys")
        if not isinstance(raw_keys, list):
            raise RegistryError(f"service {service_id}: keys must be a list")
        service_keys: list[ServiceKey] = []
        for raw in raw_keys:
            kid, filename = (raw or {}).get("kid"), (raw or {}).get("file")
            if (
                not isinstance(filename, str)
                or not filename
                or os.path.basename(filename) != filename
                or filename.startswith(".")
            ):
                raise RegistryError(
                    f"service {service_id}: unsafe key file {filename!r}"
                )
            public_key = _load_public_key(os.path.join(directory, filename))
            actual = keyset_mod.jwk_thumbprint(public_key)
            if kid != actual:
                raise RegistryError(
                    f"service {service_id}: kid {kid} does not match its key "
                    f"(thumbprint {actual})"
                )
            if kid in seen_kids:
                raise RegistryError(f"kid {kid} is registered to two services")
            if kid in forbidden:
                raise RegistryError(f"kid {kid} is a platform signing key")
            seen_kids.add(kid)
            service_keys.append(
                ServiceKey(
                    kid=kid,
                    public_pem=public_key.public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode("ascii"),
                )
            )
        seen_ids.add(service_id)
        services.append(
            ServiceIdentity(
                id=service_id,
                name=name,
                module=module,
                status=entry["status"],
                audience=entry["audience"],
                scopes=frozenset(scopes),
                tenants=tuple(tenants),
                keys=tuple(service_keys),
            )
        )
    return ServiceRegistry(services=tuple(services))


# ── the registry this process uses ────────────────────────────────────────────

_UNLOADED = object()
_registry: Any = _UNLOADED
_registry_problem: str | None = None


def _platform_kids() -> set[str]:
    jwks = tokens.public_jwks()
    return {k["kid"] for k in jwks["keys"]} if jwks else set()


def current_registry() -> ServiceRegistry | None:
    """
    The configured registry, loaded once per process. An empty registry when
    none is configured; None when one is configured and refused, in which case
    no service authenticates and the reason is kept for the start-up log.
    """
    global _registry, _registry_problem
    if _registry is _UNLOADED:
        directory = JWTConfig.SERVICE_REGISTRY_DIR
        if not directory:
            _registry = ServiceRegistry()
            _registry_problem = "none registered (CCURE_SERVICE_REGISTRY_DIR unset)"
        else:
            try:
                _registry = load_registry(directory, forbidden_kids=_platform_kids())
                _registry_problem = None
            except RegistryError as exc:
                _registry, _registry_problem = None, f"refused: {exc}"
    return _registry


def registry_status() -> str:
    """One line for the start-up log."""
    registry = current_registry()
    if registry is None or not registry.services:
        return _registry_problem or "none registered"
    return ", ".join(
        f"{s.id} ({s.status}, {len(s.keys)} key(s))" for s in registry.services
    )
