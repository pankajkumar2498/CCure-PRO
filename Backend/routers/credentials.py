"""
routers/credentials.py
─────────────────────────────────────────────────────────────────────────────
The platform credential store — create, edit, list, validate, delete.

Endpoints
─────────
  GET    /credentials                 list (tenant-scoped, secrets never returned)
  POST   /credentials                 create
  GET    /credentials/types           what this build can authenticate with
  GET    /credentials/{id}            one credential
  PATCH  /credentials/{id}            edit (secret optional — omit to keep)
  POST   /credentials/{id}/validate   test it against a host, now
  DELETE /credentials/{id}            delete

Why this router exists rather than more endpoints on /compliance
────────────────────────────────────────────────────────────────
The ``credentials`` RBAC resource — ``credentials:create``, ``:read``,
``:delete`` — has existed in the permission seed since before this phase and
was **never wired to an API**. The only credential endpoints were under
``/compliance``, gated on ``compliance:read`` and
``compliance:manage_integrations``.

That is the wrong authorisation for the job: an analyst who scans Windows hosts
needs to manage scanning credentials, and requiring a compliance permission for
it either locks them out or pushes somebody into granting compliance access for
an unrelated reason. This is not a parallel workflow — it is the API the
existing permissions were defined for. The compliance endpoints keep working;
they read the same table.

Three properties this module is responsible for
───────────────────────────────────────────────
**A secret goes in and never comes out.** Every response is built by
:func:`_serialize`, which has no branch that can emit ``encrypted_password`` or
``encrypted_key_content`` — not even redacted. A test asserts the response body
contains no secret material.

**Tenant isolation is in the query.** Another organisation's credential returns
404, not 403, so the two are indistinguishable from outside.

**Validation authenticates for real, and says precisely what failed.** A
credential that cannot be told apart from an unreachable host is a support
ticket. The four WinRM error classes map to four different messages and a
``reason`` field the UI can branch on.
"""

import logging
from typing import Any, Dict, Optional

from ccure_platform.api import (
    CurrentUser,
    require_authorized,
    resolve_active_organisation,
)
from ccure_platform.api import log_audit_event
from core import credential_vault
from core.security_crypto import encrypt_credential
from db.base import get_db
from db.models import ComplianceCredential
from db.models.compliance import (
    AUTH_METHODS,
    AUTH_REQUIRES_KEY,
    USABLE_AUTH_METHODS,
    AUTH_REQUIRES_PASSWORD,
    CREDENTIAL_TYPE_DATABASE,
    CREDENTIAL_TYPE_SSH,
    CREDENTIAL_TYPE_WINDOWS,
    DATABASE_TRANSPORTS,
    TRANSPORT_WINRM,
    USABLE_CREDENTIAL_TYPES,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator
from core.rate_limiter import limiter
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.credentials")

router = APIRouter(prefix="/credentials", tags=["Credentials"])


#: The type rules live in the credential service, which both credential
#: surfaces share; re-exported here because callers and tests import them from
#: this module.
TYPE_AUTH_MATRIX = credential_vault.TYPE_AUTH_MATRIX
TYPE_TRANSPORTS = credential_vault.TYPE_TRANSPORTS
TYPE_DEFAULTS = credential_vault.TYPE_DEFAULTS
_database_default_port = credential_vault.database_default_port


def _database_drivers() -> Dict[str, bool]:
    """Which database engines this build has a driver for."""
    from engines.credentialed.database_executor import available_engines

    return available_engines()


def _resolve_org(user: CurrentUser, requested: Optional[str]) -> str:
    # Scope is decided by the platform (RBAC-5): a client-named organisation is a
    # request, honoured only with cross-organisation reach and an active target.
    return resolve_active_organisation(user, requested)


def _get(db: Session, credential_id: str, org_id: str) -> ComplianceCredential:
    try:
        return credential_vault.get_for_org(db, org_id, credential_id)
    except credential_vault.CredentialNotFound:
        raise HTTPException(status_code=404, detail="Credential not found.") from None


def _serialize(cred: ComplianceCredential) -> Dict[str, Any]:
    """
    Everything about a credential except anything that could be used as one.

    There is deliberately no ``encrypted_password`` branch here, not even a
    redacted one: a field that is present-but-masked invites a future edit that
    unmasks it "just for debugging". ``has_secret`` answers the only question
    the UI actually has.
    """
    return {
        "id": cred.id,
        "tenant_id": cred.tenant_id,
        "name": cred.name,
        "username": cred.username,
        "domain": cred.domain,
        "principal": cred.principal(),
        "credential_type": cred.credential_type,
        "transport": cred.transport,
        "auth_method": cred.auth_method,
        "port": cred.port,
        "options": dict(cred.options or {}),
        "has_secret": bool(cred.encrypted_password or cred.encrypted_key_content),
        "created_at": cred.created_at.isoformat() if cred.created_at else None,
        "updated_at": cred.updated_at.isoformat() if cred.updated_at else None,
    }


# Prefixed ``ScanCredential`` because ``routers/compliance.py`` already
# defines a ``CredentialCreate``. FastAPI keys OpenAPI component schemas by
# class name: with both present it emits one as
# ``routers__credentials__CredentialCreate`` and gives the clean name to
# whichever it saw first — arbitrary, and it lands in every generated client.
# Phase 1 hit the identical collision with ``ScheduleCreate``, where the
# duplicate silently *replaced* compliance's schema instead.
class ScanCredentialCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=1, max_length=150)
    credential_type: str = Field(CREDENTIAL_TYPE_SSH)
    auth_method: str = Field("password")
    #: SecretStr so the value cannot be logged by an accidental repr of the
    #: request model — FastAPI logs validation errors with the body.
    password: Optional[SecretStr] = None
    private_key: Optional[SecretStr] = None
    domain: Optional[str] = Field(None, max_length=255)
    transport: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    options: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("credential_type")
    @classmethod
    def _check_type(cls, value: str) -> str:
        text = str(value or "").strip().lower()
        if text not in USABLE_CREDENTIAL_TYPES:
            raise ValueError(
                f"credential_type must be one of "
                f"{', '.join(USABLE_CREDENTIAL_TYPES)}. The column also admits "
                f"database, network_device and snmp, but nothing can "
                f"authenticate with them yet, so creating one would produce a "
                f"credential that never works."
            )
        return text

    @field_validator("auth_method")
    @classmethod
    def _check_method(cls, value: str) -> str:
        text = str(value or "").strip().lower()
        if text not in USABLE_AUTH_METHODS:
            # Validated against the *usable* set, not the column's vocabulary.
            # The column admits a reserved method so a later phase needs no
            # migration; the API refuses it so nobody saves a credential that
            # cannot authenticate.
            raise ValueError(
                f"auth_method must be one of {', '.join(USABLE_AUTH_METHODS)}"
            )
        return text

    @field_validator("options")
    @classmethod
    def _no_secrets_in_options(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        """
        ``options`` is returned to the UI and written to logs. A caller that put
        a password there would have it stored in clear and echoed straight back
        out of :func:`_serialize`.
        """
        banned = {"password", "secret", "private_key", "key", "passphrase", "token"}
        offending = sorted(k for k in (value or {}) if k.strip().lower() in banned)
        if offending:
            raise ValueError(
                f"options must not carry secret material ({', '.join(offending)}). "
                f"Secrets belong in the password or private_key field, which are "
                f"encrypted at rest; options is returned to clients in clear."
            )
        return value or {}


class ScanCredentialUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    username: Optional[str] = Field(None, min_length=1, max_length=150)
    auth_method: Optional[str] = None
    password: Optional[SecretStr] = None
    private_key: Optional[SecretStr] = None
    domain: Optional[str] = Field(None, max_length=255)
    transport: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    options: Optional[Dict[str, Any]] = None


class ScanCredentialValidateRequest(BaseModel):
    #: The host to authenticate against. A credential is not valid or invalid
    #: on its own — only against a target — so this is required rather than
    #: defaulted to something the server guesses.
    target: str = Field(..., min_length=1, max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)


def _apply_type_rules(
    credential_type: str,
    auth_method: str,
    transport: Optional[str],
    port: Optional[int],
) -> tuple:
    try:
        return credential_vault.apply_type_rules(
            credential_type, auth_method, transport, port
        )
    except credential_vault.CredentialRuleViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@router.get("/types")
@limiter.limit("30/minute")
def credential_types(
    request: Request,
    response: Response,
    user: CurrentUser = Depends(require_authorized("audit.credential.read")),
):
    """
    What this build can authenticate with — read from the code, not hardcoded
    in the UI, so a build without pywinrm cannot offer Windows credentials it
    would then fail to use.
    """
    from engines.credentialed.smb_executor import IMPACKET_AVAILABLE
    from engines.credentialed.winrm_executor import WINRM_AVAILABLE

    # A Windows credential is usable if *either* transport is installed, and the
    # UI needs to know which. Reporting only WinRM's availability would hide the
    # SMB path on a build that has it — and SMB is the one that reaches a client
    # SKU with WinRM switched off, which is the case it exists for.
    windows_transports = [
        {
            "value": "winrm",
            "label": "WinRM (default)",
            "default_port": 5985,
            "available": WINRM_AVAILABLE,
            "unavailable_reason": (
                None if WINRM_AVAILABLE else "pywinrm is not installed"
            ),
        },
        {
            "value": "smb",
            "label": "SMB / Remote Registry / WMI",
            "default_port": 445,
            "available": IMPACKET_AVAILABLE,
            "unavailable_reason": (
                None if IMPACKET_AVAILABLE else "impacket is not installed"
            ),
        },
    ]

    return {
        "types": [
            {
                "value": CREDENTIAL_TYPE_SSH,
                "label": "SSH (Linux / Unix)",
                "auth_methods": list(TYPE_AUTH_MATRIX[CREDENTIAL_TYPE_SSH]),
                "default_port": 22,
                "available": True,
            },
            {
                "value": CREDENTIAL_TYPE_WINDOWS,
                "label": "Windows (WinRM or SMB)",
                "auth_methods": list(TYPE_AUTH_MATRIX[CREDENTIAL_TYPE_WINDOWS]),
                "default_port": 5985,
                "available": WINRM_AVAILABLE or IMPACKET_AVAILABLE,
                "transports": windows_transports,
                "unavailable_reason": (
                    None
                    if (WINRM_AVAILABLE or IMPACKET_AVAILABLE)
                    else "neither pywinrm nor impacket is installed"
                ),
            },
            {
                "value": CREDENTIAL_TYPE_DATABASE,
                "label": "Database",
                "auth_methods": list(TYPE_AUTH_MATRIX[CREDENTIAL_TYPE_DATABASE]),
                "default_port": TYPE_DEFAULTS[CREDENTIAL_TYPE_DATABASE]["port"],
                "available": any(_database_drivers().values()),
                "unavailable_reason": (
                    None
                    if any(_database_drivers().values())
                    else "no database driver is installed in this environment"
                ),
                # A database credential is only usable against the engine it
                # names, so the engine list is part of the type rather than a
                # free-text field. Availability is per engine and read from the
                # installed drivers: a deployment without pymssql should not be
                # offered SQL Server and left to discover at scan time that it
                # cannot connect.
                "engines": [
                    {
                        "value": transport,
                        "default_port": _database_default_port(transport),
                        "available": _database_drivers().get(transport, False),
                    }
                    for transport in DATABASE_TRANSPORTS
                ],
            },
        ]
    }


@router.get("")
@limiter.limit("60/minute")
def list_credentials(
    request: Request,
    response: Response,
    credential_type: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.credential.read")),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, org_id)
    rows = credential_vault.list_for_org(db, org, credential_type)
    return {"credentials": [_serialize(c) for c in rows], "total": len(rows)}


@router.post("", status_code=201)
@limiter.limit("20/minute")
def create_credential(
    request: Request,
    response: Response,
    body: ScanCredentialCreate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.credential.manage")),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, org_id)
    try:
        cred = credential_vault.create(
            db,
            actor=user,
            org_id=org,
            name=body.name,
            username=body.username,
            credential_type=body.credential_type,
            auth_method=body.auth_method,
            password=(
                body.password.get_secret_value() if body.password is not None else None
            ),
            private_key=(
                body.private_key.get_secret_value()
                if body.private_key is not None
                else None
            ),
            domain=body.domain,
            transport=body.transport,
            port=body.port,
            options=body.options,
            request=request,
        )
    except credential_vault.CredentialRuleViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except credential_vault.MissingSecret as exc:
        noun = "password" if exc.field == "password" else "private key"
        raise HTTPException(
            status_code=400,
            detail=f"auth_method {body.auth_method!r} requires a {noun}.",
        ) from None
    except credential_vault.DuplicateCredentialName:
        raise HTTPException(
            status_code=409, detail=f"A credential named {body.name!r} already exists."
        ) from None
    return _serialize(cred)


@router.get("/{credential_id}")
@limiter.limit("60/minute")
def get_credential(
    request: Request,
    response: Response,
    credential_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.credential.read")),
    db: Session = Depends(get_db),
):
    return _serialize(_get(db, credential_id, _resolve_org(user, org_id)))


@router.patch("/{credential_id}")
@limiter.limit("20/minute")
def update_credential(
    request: Request,
    response: Response,
    credential_id: str,
    body: ScanCredentialUpdate,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.credential.manage")),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, org_id)
    cred = _get(db, credential_id, org)
    fields = body.model_dump(exclude_unset=True)

    auth_method = fields.get("auth_method", cred.auth_method)
    if auth_method not in AUTH_METHODS:
        raise HTTPException(status_code=400, detail="Unknown auth_method.")
    transport, port = _apply_type_rules(
        cred.credential_type,
        auth_method,
        fields.get("transport", cred.transport),
        fields.get("port", cred.port),
    )

    # A secret is replaced only when one is supplied. An edit that changed the
    # port would otherwise blank the password, and the credential would start
    # failing authentication for a reason nothing in the UI explains.
    if body.password is not None:
        cred.encrypted_password = encrypt_credential(body.password.get_secret_value())
        cred.encrypted_key_content = None
    if body.private_key is not None:
        cred.encrypted_key_content = encrypt_credential(
            body.private_key.get_secret_value()
        )
        cred.encrypted_password = None

    for key in ("name", "username", "domain", "options"):
        if key in fields:
            setattr(cred, key, fields[key])
    cred.auth_method = auth_method
    cred.transport = transport
    cred.port = port

    # Changing the method without supplying matching material would violate
    # ck_compliance_credential_auth as a 500. Caught here as a 400 that says
    # what to do.
    if auth_method in AUTH_REQUIRES_PASSWORD and not cred.encrypted_password:
        raise HTTPException(
            status_code=400,
            detail=(
                f"auth_method {auth_method!r} needs a password, and this "
                f"credential has none stored. Supply `password` with the change."
            ),
        )
    if auth_method in AUTH_REQUIRES_KEY and not cred.encrypted_key_content:
        raise HTTPException(
            status_code=400,
            detail=(
                f"auth_method {auth_method!r} needs a private key, and this "
                f"credential has none stored. Supply `private_key` with the change."
            ),
        )

    log_audit_event(
        db,
        user,
        "credential.updated",
        "credential",
        cred.id,
        changes={
            "fields": sorted(fields.keys()),
            "secret_replaced": bool(
                body.password is not None or body.private_key is not None
            ),
        },
        request=request,
    )
    db.commit()
    db.refresh(cred)
    return _serialize(cred)


@router.post("/{credential_id}/validate")
@limiter.limit("10/minute")
def validate_credential(
    request: Request,
    response: Response,
    credential_id: str,
    body: ScanCredentialValidateRequest,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.credential.validate")),
    db: Session = Depends(get_db),
):
    """
    Authenticate this credential against a host, now, and report exactly what
    happened.

    A real connection is made. There is no "looks plausible" answer: the point
    is to find out before a scheduled scan does, at 02:00, with nobody watching.

    The target is re-checked against the organisation's authorised scan scope,
    because this makes an outbound authentication attempt at a caller-named
    address — otherwise it is a way to make this host try credentials against
    anything on the network.
    """
    from core.scan_scope import ScanScopeError, enforce_org_scan_scope, org_scan_scope

    org = _resolve_org(user, org_id)
    cred = _get(db, credential_id, org)
    target = body.target.strip()

    try:
        enforce_org_scan_scope([target], org_scan_scope(db, org))
    except ScanScopeError as exc:
        raise HTTPException(status_code=403, detail=exc.message) from exc

    port = int(body.port or cred.port or 0)
    outcome: Dict[str, Any] = {
        "credential_id": cred.id,
        "target": target,
        "port": port,
        "transport": cred.transport,
        "ok": False,
        "reason": None,
        "detail": None,
        "authenticated_as": None,
    }

    try:
        if cred.transport == TRANSPORT_WINRM:
            from engines.credentialed.winrm_executor import WinRMExecutor

            # The row was found within this organisation above (`_get`).
            material = credential_vault.connection_material(cred)
            with WinRMExecutor(
                ip=target,
                username=material["username"],
                password=material["password"],
                port=port or 5985,
                auth_method=material["auth_method"],
                timeout=20,
                **{
                    k: v
                    for k, v in (material.get("options") or {}).items()
                    if k in ("use_tls", "verify_cert", "winrm_path")
                },
            ) as conn:
                who = conn.run(
                    "[System.Security.Principal.WindowsIdentity]::" "GetCurrent().Name"
                )
                outcome["ok"] = True
                outcome["reason"] = "authenticated"
                outcome["authenticated_as"] = who.stdout.strip() or material["username"]
                outcome["detail"] = "WinRM authentication succeeded."
        else:
            from engines.credentialed.ssh_scanner import SSHScanner

            material = credential_vault.connection_material(cred)
            with SSHScanner(
                ip=target,
                username=material["username"],
                password=material["password"],
                key_content=material["key_content"],
                port=port or 22,
                timeout=15,
            ) as conn:
                who = conn.run("id -un 2>/dev/null || whoami")
                outcome["ok"] = True
                outcome["reason"] = "authenticated"
                outcome["authenticated_as"] = who.stdout.strip() or material["username"]
                outcome["detail"] = "SSH authentication succeeded."
    except Exception as exc:  # noqa: BLE001 — classified below
        # The four WinRM classes carry distinct, actionable meanings and are
        # preserved as distinct `reason` values. Flattening them to "failed" is
        # what turns a fixable firewall rule into a support ticket.
        name = type(exc).__name__
        reason = {
            "WinRMAuthenticationError": "authentication_failed",
            "WinRMPermissionError": "insufficient_privileges",
            "WinRMConnectionError": "unreachable",
            "WinRMConfigurationError": "configuration_error",
        }.get(name, "failed")
        outcome["reason"] = reason
        outcome["detail"] = str(exc)[:600]
        log.info(
            "Credential validation failed: cred=%s target=%s reason=%s",
            cred.id,
            target,
            reason,
        )

    log_audit_event(
        db,
        user,
        "credential.validated",
        "credential",
        cred.id,
        # The target and the outcome, never the material. An operator needs to
        # see that somebody tested a credential against a host and what came
        # back.
        changes={"target": target, "reason": outcome["reason"], "ok": outcome["ok"]},
        request=request,
        status="success" if outcome["ok"] else "failure",
    )
    db.commit()
    return outcome


@router.delete("/{credential_id}")
@limiter.limit("20/minute")
def delete_credential(
    request: Request,
    response: Response,
    credential_id: str,
    org_id: Optional[str] = Query(None),
    user: CurrentUser = Depends(require_authorized("audit.credential.delete")),
    db: Session = Depends(get_db),
):
    """
    Delete a credential.

    Schedules referencing it are **not** deleted: ``scan_schedules.credential_id``
    is ON DELETE SET NULL, and the dispatcher fails such a schedule loudly with
    "no credential is attached" rather than running an unauthenticated scan that
    would report the host as clean. Cascading the delete would silently remove
    the customer's scheduling instead.
    """
    org = _resolve_org(user, org_id)
    try:
        name, affected = credential_vault.delete(
            db, actor=user, org_id=org, credential_id=credential_id, request=request
        )
    except credential_vault.CredentialNotFound:
        raise HTTPException(status_code=404, detail="Credential not found.") from None
    return {
        "success": True,
        "id": credential_id,
        "name": name,
        "schedules_affected": affected,
        "note": (
            (
                f"{affected} schedule(s) referenced this credential and will now "
                "fail with 'no credential is attached' until one is reattached."
            )
            if affected
            else None
        ),
    }
