"""
POST /auth/service-token — a service exchanges a signed assertion for a
short-lived service token (Phase 9.5; RFC 6749 client credentials with RFC 7523
``private_key_jwt`` client authentication).

Order of checks (design §3.4): the assertion's signature against the key
registered **to that service**; the identity's status; single use of the
assertion; the requested scopes against those allowed; the tenant against those
granted and against the organisation's own state. Only then is a token signed
and the issuance written to the audit log, in one transaction.

Every authentication failure answers the same 401 ``invalid_client`` — which
service ids exist and why one failed is in the server log, never the response.
Scope and tenant refusals come after authentication, so they may be specific.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import NoReturn

from ccure_platform.identity import tokens
from ccure_platform.service_identity import registry as registry_mod
from ccure_platform.service_identity.replay import (
    ReplayStoreUnavailable,
    claim_assertion,
)
from core.rate_limiter import limiter
from db.base import get_db
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.service_identity")

router = APIRouter(prefix="/auth", tags=["Service identity"])

GRANT_TYPE = "client_credentials"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class ServiceTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    tenant: str


def _refuse(
    status_code: int, detail: str, reason: str, service_id: str | None
) -> NoReturn:
    log.warning(
        "service token refused: reason=%s service=%r", reason, (service_id or "")[:64]
    )
    raise HTTPException(status_code=status_code, detail=detail)


@router.post("/service-token", response_model=ServiceTokenResponse)
@limiter.limit("30/minute")
def service_token(
    request: Request,
    response: Response,
    grant_type: str = Form(...),
    client_assertion_type: str = Form(...),
    client_assertion: str = Form(...),
    scope: str = Form(""),
    tenant: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    Exchange a service's signed client assertion for a 10-minute service token.

    Form-encoded, as RFC 6749 §4.4 and RFC 7523 §2.2 specify:
    `grant_type=client_credentials`,
    `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
    `client_assertion=<JWT signed ES256 by the service's own key>`,
    `scope=<space-separated scopes>` and, for a service granted more than one
    tenant, `tenant=<organisation id>`.

    Answers 401 `invalid_client` for any authentication failure, 400
    `invalid_scope` or `invalid_request`, 403 for a tenant the service is not
    granted, and 503 when the service registry or the replay store is
    unavailable.
    """
    if grant_type != GRANT_TYPE:
        _refuse(400, "unsupported_grant_type", "grant_type", None)
    if client_assertion_type != ASSERTION_TYPE:
        _refuse(400, "invalid_request", "assertion_type", None)

    registry = registry_mod.current_registry()
    if registry is None:
        _refuse(503, "Service authentication is unavailable.", "registry", None)

    claims = tokens.verify_service_assertion(client_assertion, key_for=registry.key_for)
    if claims is None:
        _refuse(401, "invalid_client", "assertion", None)
    identity = registry.get(claims["iss"])
    if identity is None or not identity.active:
        _refuse(401, "invalid_client", "inactive", claims["iss"])

    ttl = int(claims["exp"] - datetime.now(timezone.utc).timestamp()) + 1
    try:
        first_use = claim_assertion(identity.id, claims["jti"], ttl)
    except ReplayStoreUnavailable:
        _refuse(
            503, "Service authentication is unavailable.", "replay_store", identity.id
        )
    if not first_use:
        _refuse(401, "invalid_client", "replayed", identity.id)

    requested = frozenset(scope.split())
    if not requested:
        _refuse(400, "invalid_scope", "no_scope", identity.id)
    if not requested <= identity.scopes:
        _refuse(400, "invalid_scope", "scope_not_allowed", identity.id)

    if tenant is None:
        if len(identity.tenants) != 1:
            _refuse(400, "invalid_request", "tenant_required", identity.id)
        tenant = identity.tenants[0]
    if tenant not in identity.tenants:
        _refuse(403, "The service is not granted this tenant.", "tenant", identity.id)
    from ccure_platform.models import Organization

    organisation = db.query(Organization).filter(Organization.id == tenant).first()
    if organisation is None or not organisation.is_active:
        _refuse(
            403, "The service is not granted this tenant.", "tenant_state", identity.id
        )

    try:
        token = tokens.sign_service_token(
            service_id=identity.id,
            audience=identity.audience,
            scopes=requested,
            tenant=tenant,
        )
    except tokens.SigningUnavailable:
        _refuse(503, "Service authentication is unavailable.", "signing", identity.id)
    issued = tokens.unverified_claims(token)

    from ccure_platform.audit_log.writer import log_audit_event

    log_audit_event(
        db,
        None,
        "service.token_issued",
        resource_type="service_identity",
        resource_id=identity.id,
        changes={
            "audience": identity.audience,
            "scopes": sorted(requested),
            # Not "token_jti": the audit log redacts any key naming a token.
            "issued_jti": issued.get("jti"),
            "assertion_jti": claims["jti"],
            "assertion_kid": tokens.unverified_header(client_assertion).get("kid"),
        },
        request=request,
        org_id=tenant,
        system_actor=identity.subject,
    )
    db.commit()

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return ServiceTokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=int(tokens.SERVICE_TOKEN_LIFETIME.total_seconds()),
        scope=" ".join(sorted(requested)),
        tenant=tenant,
    )
