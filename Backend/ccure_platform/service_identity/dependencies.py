"""
Accepting a service token (Phase 9.5).

``service_principal_for(audience)`` and ``require_service_scope(scope)`` are
what an endpoint called by another service will depend on. They arrive now
with **no production consumer** — the first is Phase 14's integration
endpoints — and are deliberately not exported from ``ccure_platform.api``
until then (design §3.5); the tests exercise them on a test-only route.

Three rules, each tested:

* **Tenant context comes from the verified token only.** The ``tenant`` claim
  is the tenant. ``X-Tenant-ID`` — or any header, body field or query
  parameter — is never read here.
* **Humans and services never cross.** A user token is refused (wrong kind,
  audience and principal type), and ``current_user`` refuses a service token
  for the same reasons.
* **The identity is re-checked on every request.** A service disabled in the
  registry since its token was issued is refused, even inside the token's ten
  minutes, and so is a token naming a tenant the identity is no longer granted.
"""

from __future__ import annotations

from dataclasses import dataclass

from ccure_platform.identity import tokens
from ccure_platform.service_identity.registry import current_registry
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ServicePrincipal:
    """The authenticated service calling an endpoint."""

    service_id: str
    tenant: str
    scopes: frozenset[str]
    audience: str
    token_jti: str


def _unauthorised() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired service token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def service_principal_for(audience: str):
    """A dependency authenticating a service token issued for ``audience``."""
    if audience not in tokens.SERVICE_AUDIENCES:
        raise ValueError(f"unknown service audience {audience!r}")

    def _principal(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> ServicePrincipal:
        if credentials is None:
            raise _unauthorised()
        payload = tokens.verify(
            credentials.credentials,
            expected_kind=tokens.SERVICE_ACCESS,
            issuer=tokens.ISSUER,
            audience=audience,
        )
        if not payload:
            raise _unauthorised()
        registry = current_registry()
        identity = registry.by_subject(str(payload.get("sub"))) if registry else None
        tenant = payload.get("tenant")
        if (
            identity is None
            or not identity.active
            or identity.audience != audience
            or not isinstance(tenant, str)
            or tenant not in identity.tenants
        ):
            raise _unauthorised()
        return ServicePrincipal(
            service_id=identity.id,
            tenant=tenant,
            scopes=frozenset(str(payload.get("scope", "")).split()),
            audience=audience,
            token_jti=str(payload.get("jti")),
        )

    return _principal


def require_service_scope(scope: str, *, audience: str = tokens.CORE_SERVICE_AUDIENCE):
    """
    A dependency admitting a service token that carries ``scope``. The platform
    states the scopes; the module owning the endpoint decides what each one
    permits (design §3.5).
    """
    principal_dependency = service_principal_for(audience)

    def _require(
        principal: ServicePrincipal = Depends(principal_dependency),
    ) -> ServicePrincipal:
        if scope not in principal.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The service token does not carry the required scope.",
            )
        return principal

    return _require
