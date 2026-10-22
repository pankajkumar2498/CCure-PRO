"""
core/credential_vault.py
─────────────────────────────────────────────────────────────────────────────
The stored-credential service: the one place a credential is created, listed,
found or deleted, and the type rules every write is held to.

Two HTTP surfaces read and write ``compliance_credentials``: ``/credentials``,
the credential API, and ``/compliance/credentials``, which predates it and
which three screens still call. They used to carry their own copies of the
logic, and the copies had drifted apart:

* the compliance list answered ``audit.compliance.read``, which the viewer role
  holds and ``audit.credential.read`` does not — so a viewer could enumerate
  every credential's name, username and port;
* its create and delete answered ``audit.compliance.manage_integrations``, so a
  custom role could delete credentials without ``audit.credential.delete``;
* it applied no type, transport or port rules, carried no rate limit, recorded
  different audit actions for the same act, and did not report the schedules a
  deletion leaves without a credential.

Both routers are now adapters over this module, and both require the
credential permissions below. Each keeps its own request and response shapes,
status codes and messages — those are what their callers depend on — so this
module raises domain errors and leaves their translation to HTTP to the router.

Secrets arrive here as plain strings, are encrypted before they reach the row,
and are never logged, returned or written to the audit trail.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ccure_platform import api as platform_api
from core.security_crypto import decrypt_credential, encrypt_credential
from db.base import gen_compliance_credential_id
from db.models.credentials import (
    AUTH_METHOD_NTLM_HASH,
    AUTH_REQUIRES_KEY,
    AUTH_REQUIRES_PASSWORD,
    CREDENTIAL_TYPE_DATABASE,
    CREDENTIAL_TYPE_SSH,
    CREDENTIAL_TYPE_WINDOWS,
    DATABASE_TRANSPORTS,
    TRANSPORT_POSTGRESQL,
    TRANSPORT_SMB,
    TRANSPORT_SSH,
    TRANSPORT_WINRM,
    ComplianceCredential,
)
from sqlalchemy.orm import Session

#: The authorisation policy for stored credentials, whichever route is used.
#: Routers spell these keys as literals in ``require_authorized(...)`` because
#: the authorization inventory reads them from the source;
#: ``tests/security/test_credential_api_consolidation.py`` asserts every
#: credential route requires exactly these.
PERMISSION_READ = "audit.credential.read"
PERMISSION_MANAGE = "audit.credential.manage"
PERMISSION_DELETE = "audit.credential.delete"


#: Which authentication methods each credential type can actually use.
#:
#: Deliberately here rather than as a database CHECK: this matrix grows every
#: time a credential type is added (Phases 10 and 11), and a CHECK migration on
#: a table holding customer credentials for each growth is the cost that
#: avoids. ``test_credential_type_auth_matrix_is_enforced`` asserts the API
#: applies it.
TYPE_AUTH_MATRIX: Dict[str, tuple] = {
    CREDENTIAL_TYPE_SSH: ("password", "key"),
    # ``kerberos`` is gone from this matrix, not because Windows does not use
    # it but because this build cannot: pywinrm raises "requested auth method
    # is kerberos, but pykerberos is not installed" at the first command, so a
    # credential saved with it failed on the customer's network rather than at
    # the moment somebody saved it. It stays in the column's vocabulary — see
    # USABLE_AUTH_METHODS — so the phase that implements it adds a mechanism
    # rather than a migration.
    #
    # ``ntlm_hash`` is Pass-the-Hash over SMB, which also means a domain estate
    # need not store a reversible plaintext password here to be scanned.
    CREDENTIAL_TYPE_WINDOWS: ("password", "ntlm", "ntlm_hash"),
    # Password only. Every engine here also supports certificate and
    # integrated authentication, and none of those is implemented, so offering
    # them would let a user save a credential the scanner cannot use.
    CREDENTIAL_TYPE_DATABASE: ("password",),
}

#: Which transports each credential type may use.
#:
#: New in Phase 7, and it closes a gap rather than only serving the new type:
#: transport was previously defaulted per type but never *validated*, so a
#: Windows credential could be stored with an arbitrary transport from the
#: column's vocabulary. With database engines in that vocabulary the
#: consequence stops being cosmetic — a Windows credential carrying transport
#: ``postgresql`` would be dispatched at a database session.
TYPE_TRANSPORTS: Dict[str, tuple] = {
    CREDENTIAL_TYPE_SSH: (TRANSPORT_SSH,),
    # A Windows host is reachable either way: WinRM natively, or SSH through
    # the OpenSSH-on-Windows arrangement this product used to require.
    CREDENTIAL_TYPE_WINDOWS: (TRANSPORT_WINRM, TRANSPORT_SMB, TRANSPORT_SSH),
    CREDENTIAL_TYPE_DATABASE: DATABASE_TRANSPORTS,
}

#: Default transport and port per type, applied when the caller does not say.
#:
#: The database default is PostgreSQL because it is the only engine whose
#: driver this product already depended on before Phase 7. There is no
#: defensible "generic" database port, so a caller naming a database credential
#: without a transport gets the one engine that was always present rather than
#: a guess.
TYPE_DEFAULTS: Dict[str, Dict[str, Any]] = {
    CREDENTIAL_TYPE_SSH: {"transport": TRANSPORT_SSH, "port": 22},
    CREDENTIAL_TYPE_WINDOWS: {"transport": TRANSPORT_WINRM, "port": 5985},
    CREDENTIAL_TYPE_DATABASE: {"transport": TRANSPORT_POSTGRESQL, "port": 5432},
}


class CredentialError(Exception):
    """Base for the refusals this service makes; the router picks the status."""


class CredentialRuleViolation(CredentialError):
    """The type, auth method and transport do not fit together."""


class MissingSecret(CredentialError):
    """The auth method needs material that was not supplied."""

    def __init__(self, field: str, auth_method: str):
        self.field = field  # "password" or "private_key"
        self.auth_method = auth_method
        super().__init__(f"auth_method {auth_method!r} requires a {field}")


class DuplicateCredentialName(CredentialError):
    """The organisation already has a credential with this name."""


class CredentialNotFound(CredentialError):
    """No such credential in this organisation — the same answer for one that
    exists in another, so the two cannot be told apart from outside."""


def database_default_port(transport: str) -> int:
    """
    Default port per database transport, sourced from ``DEFAULT_PORTS`` in the
    executor so the two cannot drift — a credential defaulted to 5432 for a
    MySQL transport would fail at scan time on a customer's network rather than
    at the moment somebody saved it.
    """
    from engines.credentialed.database_executor import DEFAULT_PORTS

    return int(DEFAULT_PORTS.get(transport, 5432))


def apply_type_rules(
    credential_type: str,
    auth_method: str,
    transport: Optional[str],
    port: Optional[int],
) -> tuple:
    """Validate a credential's shape and resolve its transport and port."""
    allowed = TYPE_AUTH_MATRIX.get(credential_type, ())
    if auth_method not in allowed:
        raise CredentialRuleViolation(
            f"a {credential_type} credential cannot use auth_method "
            f"{auth_method!r}; expected one of {', '.join(allowed)}"
        )

    defaults = TYPE_DEFAULTS.get(credential_type, {})
    resolved_transport = transport or defaults.get("transport", TRANSPORT_SSH)

    permitted = TYPE_TRANSPORTS.get(credential_type, ())
    if permitted and resolved_transport not in permitted:
        raise CredentialRuleViolation(
            f"a {credential_type} credential cannot use transport "
            f"{resolved_transport!r}; expected one of {', '.join(permitted)}"
        )

    if port:
        resolved_port = int(port)
    elif credential_type == CREDENTIAL_TYPE_DATABASE:
        # The port follows the engine, not the type. Defaulting a MySQL
        # credential to PostgreSQL's 5432 would store something that cannot
        # connect and would surface as an unreachable host at scan time.
        resolved_port = database_default_port(resolved_transport)
    else:
        resolved_port = int(defaults.get("port", 22))

    return (resolved_transport, resolved_port)


def get_for_org(db: Session, org_id: str, credential_id: str) -> ComplianceCredential:
    """One credential of *org_id*. Tenant isolation is in the query."""
    row = (
        db.query(ComplianceCredential)
        .filter(
            ComplianceCredential.id == credential_id,
            ComplianceCredential.tenant_id == org_id,
        )
        .first()
    )
    if row is None:
        raise CredentialNotFound(credential_id)
    return row


def list_for_org(
    db: Session, org_id: str, credential_type: Optional[str] = None
) -> list:
    """Every credential of *org_id*, by name. Rows, not secrets — the caller
    serialises, and no serialiser in this product emits encrypted material."""
    query = db.query(ComplianceCredential).filter(
        ComplianceCredential.tenant_id == org_id
    )
    if credential_type:
        query = query.filter(ComplianceCredential.credential_type == credential_type)
    return query.order_by(ComplianceCredential.name.asc()).all()


def resolve(
    db: Session, credential_id: str, *, org_id: Optional[str]
) -> Dict[str, Any]:
    """
    Decrypt a stored credential for use, scoped to *org_id*.

    Returns the connection material; the caller is responsible for discarding
    it. *org_id* is the organisation the credential is used for — a scan's own
    tenant — and filtering on it is what keeps one tenant from naming another
    tenant's credential id. ``None`` applies no tenant filter, which is right
    only for a caller that has already found the row within its organisation.
    """
    query = db.query(ComplianceCredential).filter(
        ComplianceCredential.id == credential_id
    )
    if org_id:
        query = query.filter(ComplianceCredential.tenant_id == org_id)

    cred = query.first()
    if not cred:
        raise ValueError(
            f"Stored credential with ID {credential_id} not found or access denied."
        )
    return connection_material(cred)


def connection_material(cred: ComplianceCredential) -> Dict[str, Any]:
    """
    One stored credential's connection material, decrypted.

    The caller is responsible for discarding it. Holds the secret the
    credential's auth method presents and nothing else.
    """
    material = {
        # The username in the form this credential's auth method expects.
        # NTLM wants DOMAIN\user, Kerberos wants user@REALM, SSH wants the bare
        # name — `principal()` owns that mapping so the two callers of this
        # function cannot disagree about it.
        "username": cred.principal(),
        "port": cred.port,
        "auth_method": cred.auth_method,
        "credential_type": cred.credential_type,
        "transport": cred.transport,
        "domain": cred.domain,
        "options": dict(cred.options or {}),
        "password": None,
        "key_content": None,
        #: Unlocks an encrypted private key. Separate from ``password``: the two
        #: unlock different things and a key credential may carry only this one.
        "key_passphrase": None,
        #: Pass-the-Hash material. Kept out of ``password`` deliberately — every
        #: transport that receives a password would present this as one, and
        #: only the SMB executor knows how to send a hash.
        "nt_hash": None,
    }
    # Driven by the shared AUTH_REQUIRES_* sets rather than an if/elif on two
    # literal method names. The literal form is what made ``ntlm`` and
    # ``kerberos`` resolve to a credential with no material at all: both
    # present a password, neither matched ``== "password"``, so the connection
    # was attempted with None and failed as "authentication rejected" — a
    # misleading message for a credential that was never actually sent.
    if cred.auth_method == AUTH_METHOD_NTLM_HASH and cred.encrypted_password:
        # The hash is stored in the password column and must not leave this
        # function as one: handing it to a transport that expects a password
        # would present the hash as plaintext against the account.
        material["nt_hash"] = decrypt_credential(cred.encrypted_password)
    elif cred.auth_method in AUTH_REQUIRES_PASSWORD and cred.encrypted_password:
        material["password"] = decrypt_credential(cred.encrypted_password)
    elif cred.auth_method in AUTH_REQUIRES_KEY and cred.encrypted_key_content:
        material["key_content"] = decrypt_credential(cred.encrypted_key_content)
        if cred.encrypted_key_passphrase:
            material["key_passphrase"] = decrypt_credential(
                cred.encrypted_key_passphrase
            )
    return material


def create(
    db: Session,
    *,
    actor,
    org_id: str,
    name: str,
    username: str,
    auth_method: str,
    credential_type: str = CREDENTIAL_TYPE_SSH,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    domain: Optional[str] = None,
    transport: Optional[str] = None,
    port: Optional[int] = None,
    options: Optional[Dict[str, Any]] = None,
    request=None,
) -> ComplianceCredential:
    """Validate, encrypt, store and audit one credential, and commit."""
    transport, port = apply_type_rules(credential_type, auth_method, transport, port)

    encrypted_password = None
    encrypted_key = None
    # ``None`` means the field was not supplied. Both routers have always
    # accepted a supplied-but-empty value (a pydantic SecretStr is truthy
    # whatever it holds), so absence, not falsiness, is the test here.
    if auth_method in AUTH_REQUIRES_PASSWORD:
        if password is None:
            raise MissingSecret("password", auth_method)
        encrypted_password = encrypt_credential(password)
    elif auth_method in AUTH_REQUIRES_KEY:
        if private_key is None:
            raise MissingSecret("private_key", auth_method)
        encrypted_key = encrypt_credential(private_key)

    if (
        db.query(ComplianceCredential.id)
        .filter(
            ComplianceCredential.tenant_id == org_id,
            ComplianceCredential.name == name,
        )
        .first()
    ):
        raise DuplicateCredentialName(name)

    org_row = platform_api.organisation(db, org_id)
    cred = ComplianceCredential(
        id=gen_compliance_credential_id(org_row.slug if org_row else org_id),
        tenant_id=org_id,
        name=name,
        username=username,
        domain=domain or None,
        credential_type=credential_type,
        transport=transport,
        auth_method=auth_method,
        port=port,
        options=options or {},
        encrypted_password=encrypted_password,
        encrypted_key_content=encrypted_key,
    )
    db.add(cred)
    platform_api.log_audit_event(
        db,
        actor,
        "credential.created",
        "credential",
        cred.id,
        # Deliberately records what kind of credential it is and never any part
        # of the material — not even its length, which narrows a brute force.
        changes={
            "name": cred.name,
            "credential_type": cred.credential_type,
            "transport": cred.transport,
            "auth_method": cred.auth_method,
        },
        request=request,
    )
    db.commit()
    db.refresh(cred)
    return cred


def delete(
    db: Session, *, actor, org_id: str, credential_id: str, request=None
) -> tuple:
    """
    Delete one credential, audit it, commit, and return ``(name,
    schedules_affected)``.

    Schedules referencing it are **not** deleted: ``scan_schedules.credential_id``
    is ON DELETE SET NULL, and the dispatcher fails such a schedule loudly with
    "no credential is attached" rather than running an unauthenticated scan that
    would report the host as clean. Cascading the delete would silently remove
    the customer's scheduling instead.
    """
    cred = get_for_org(db, org_id, credential_id)
    name = cred.name

    from db.models.scan_schedules import ScanSchedule

    affected = (
        db.query(ScanSchedule.id)
        .filter(ScanSchedule.credential_id == cred.id, ScanSchedule.org_id == org_id)
        .count()
    )

    platform_api.log_audit_event(
        db,
        actor,
        "credential.deleted",
        "credential",
        cred.id,
        changes={"name": name, "schedules_affected": affected},
        request=request,
    )
    db.delete(cred)
    db.commit()
    return name, affected
