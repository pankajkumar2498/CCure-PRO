"""
One credential policy, whichever route a caller uses.

``/compliance/credentials`` predates ``/credentials`` and three screens still
call it. It carried its own copy of the credential logic, and the copy drifted
(docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md, finding S2):

* its list answered ``audit.compliance.read``, which ``platform.viewer`` — also
  the self-registration default role — holds and ``audit.credential.read`` does
  not, so a viewer could enumerate every credential's name and username;
* its create and delete answered ``audit.compliance.manage_integrations``, so a
  custom role could delete credentials without ``audit.credential.delete``;
* it applied no type rules and no rate limit, and recorded different audit
  actions for the same act.

Both routers are now adapters over ``core.credential_vault``. These tests pin
the shared policy in three ways: statically (the route dependency trees and
limiter registry), through HTTP for each role that matters, and against the
compatibility contract the legacy path's callers depend on — its shapes,
status codes and messages are unchanged.

Bearer tokens are built directly rather than through ``POST /auth/login``: the
login commits, which in this suite commits every pending fixture row with it.
The organisation and users are committed here deliberately instead, because
``resolve_active_organisation`` reads them through its own session.
"""

import inspect
import uuid

import pytest
from fastapi.routing import APIRoute
from native_rbac import create_user, fixture_role, system_role

from auth.jwt_handler import create_access_token
from core import credential_vault
from core.security_crypto import encrypt_credential
from db.base import gen_compliance_credential_id, gen_user_id, utcnow
from db.models import ComplianceCredential, Organization, User
from db.models.users import AuditLog

LEGACY = "/compliance/credentials"
CANONICAL = "/credentials"

#: Asserted absent from every response and audit row in this module.
SECRET = "consolidation-secret-" + uuid.uuid4().hex

#: The policy, per operation, on both surfaces.
EXPECTED_ROUTE_PERMISSIONS = {
    ("GET", "/compliance/credentials"): "audit.credential.read",
    ("GET", "/credentials"): "audit.credential.read",
    ("POST", "/compliance/credentials"): "audit.credential.manage",
    ("POST", "/credentials"): "audit.credential.manage",
    ("DELETE", "/compliance/credentials/{id}"): "audit.credential.delete",
    ("DELETE", "/credentials/{credential_id}"): "audit.credential.delete",
}

#: The legacy create and list response shape (``CredentialResponse``).
LEGACY_FIELDS = {"id", "name", "username", "auth_method", "port", "created_at"}


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _headers(user: User) -> dict:
    token = create_access_token(user.id, user.username, org_id=user.org_id)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def org(db_session) -> Organization:
    organization = Organization(
        name="Credential Consolidation Org",
        slug=f"credcons-{uuid.uuid4().hex[:8]}",
        is_active=True,
    )
    db_session.add(organization)
    db_session.commit()
    return organization


@pytest.fixture
def other_org(db_session) -> Organization:
    organization = Organization(
        name="Credential Consolidation Other",
        slug=f"credother-{uuid.uuid4().hex[:8]}",
        is_active=True,
    )
    db_session.add(organization)
    db_session.commit()
    return organization


@pytest.fixture
def user_with(db_session, org):
    """An active, approved account in ``org`` holding exactly *role*."""

    def _make(role) -> User:
        uid = uuid.uuid4().hex[:8]
        user = create_user(
            db_session,
            id=gen_user_id(org.slug, f"cc{uid}"),
            username=f"cc{uid}",
            email=f"cc{uid}@test.com",
            full_name="Credential consolidation",
            password_hash="x",
            org_id=org.id,
            role=role,
            is_active=True,
            is_verified=True,
            approved_at=utcnow(),
            approved_by="fixture",
        )
        db_session.commit()
        return user

    return _make


@pytest.fixture
def as_role(db_session, user_with):
    """Headers for a seeded system role, by its native key."""

    def _make(key: str) -> dict:
        role = system_role(db_session, key)
        assert role is not None, f"seeded role {key!r} missing"
        return _headers(user_with(role))

    return _make


@pytest.fixture
def as_grants(db_session, user_with):
    """Headers for a custom role holding exactly *keys*."""

    def _make(*keys: str) -> dict:
        role = fixture_role(db_session, f"credcons_{uuid.uuid4().hex[:10]}", keys=keys)
        db_session.commit()
        return _headers(user_with(role))

    return _make


def _legacy_body(**overrides) -> dict:
    body = {
        "name": f"cred-{uuid.uuid4().hex[:8]}",
        "username": "svc_scan",
        "auth_method": "password",
        "password": SECRET,
        "port": 22,
    }
    body.update(overrides)
    return body


def _stored(db, org: Organization, name: str | None = None) -> ComplianceCredential:
    cred = ComplianceCredential(
        id=gen_compliance_credential_id(org.slug),
        tenant_id=org.id,
        name=name or f"stored-{uuid.uuid4().hex[:8]}",
        username="root",
        auth_method="password",
        port=22,
        encrypted_password=encrypt_credential(SECRET),
    )
    db.add(cred)
    db.commit()
    return cred


# ─────────────────────────────────────────────────────────────────────────────
# One policy, read from the routes themselves
# ─────────────────────────────────────────────────────────────────────────────


def _permission_guards(route: APIRoute) -> set[str]:
    found = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        call = dep.call
        if getattr(call, "__qualname__", "").startswith("require_authorized."):
            found.add(inspect.getclosurevars(call).nonlocals["key"])
        stack.extend(dep.dependencies)
    return found


def test_both_surfaces_require_the_credential_permissions():
    from main import app

    seen = {}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            if (method, route.path) in EXPECTED_ROUTE_PERMISSIONS:
                seen[(method, route.path)] = _permission_guards(route)

    assert set(seen) == set(EXPECTED_ROUTE_PERMISSIONS), "a credential route is missing"
    for key, expected in EXPECTED_ROUTE_PERMISSIONS.items():
        assert seen[key] == {expected}, key


def test_the_policy_is_the_services():
    assert {
        credential_vault.PERMISSION_READ,
        credential_vault.PERMISSION_MANAGE,
        credential_vault.PERMISSION_DELETE,
    } == set(EXPECTED_ROUTE_PERMISSIONS.values())


def test_no_credential_route_answers_a_compliance_permission():
    """The keys the legacy path used to require must not come back."""
    from main import app

    for route in app.routes:
        if isinstance(route, APIRoute) and "credentials" in route.path:
            guards = _permission_guards(route)
            assert "audit.compliance.read" not in guards, route.path
            assert "audit.compliance.manage_integrations" not in guards, route.path


@pytest.mark.parametrize(
    "legacy,canonical",
    [
        ("routers.compliance.list_credentials", "routers.credentials.list_credentials"),
        (
            "routers.compliance.create_credential",
            "routers.credentials.create_credential",
        ),
        (
            "routers.compliance.delete_credential",
            "routers.credentials.delete_credential",
        ),
    ],
)
def test_both_surfaces_carry_the_same_rate_limit(legacy, canonical):
    import main  # noqa: F401 — registers every route's limits
    from core.rate_limiter import limiter

    def limits(key):
        return sorted(str(item.limit) for item in limiter._route_limits.get(key, ()))

    assert limits(legacy), f"{legacy} has no rate limit"
    assert limits(legacy) == limits(canonical)


# ─────────────────────────────────────────────────────────────────────────────
# Who may do what, through HTTP
# ─────────────────────────────────────────────────────────────────────────────


def test_a_viewer_cannot_enumerate_credentials_on_either_path(
    client, db_session, org, as_role
):
    stored = _stored(db_session, org)
    headers = as_role("platform.viewer")

    for path in (LEGACY, CANONICAL):
        response = client.get(path, headers=headers)
        assert response.status_code == 403, path
        assert stored.name not in response.text
        assert stored.username not in response.text


def test_a_viewer_cannot_create_or_delete_through_the_legacy_path(
    client, db_session, org, as_role
):
    stored = _stored(db_session, org)
    headers = as_role("platform.viewer")

    assert client.post(LEGACY, json=_legacy_body(), headers=headers).status_code == 403
    assert client.delete(f"{LEGACY}/{stored.id}", headers=headers).status_code == 403


def test_compliance_permissions_alone_no_longer_reach_credentials(
    client, db_session, org, as_grants
):
    """
    The keys the legacy path used to answer, held without any credential
    permission: nothing may be listed, created or deleted.
    """
    stored = _stored(db_session, org)
    headers = as_grants("audit.compliance.read", "audit.compliance.manage_integrations")

    assert client.get(LEGACY, headers=headers).status_code == 403
    assert client.post(LEGACY, json=_legacy_body(), headers=headers).status_code == 403
    assert client.delete(f"{LEGACY}/{stored.id}", headers=headers).status_code == 403
    db_session.expire_all()
    assert db_session.get(ComplianceCredential, stored.id) is not None


def test_credential_read_alone_lists_but_cannot_change(
    client, db_session, org, as_grants
):
    stored = _stored(db_session, org)
    headers = as_grants("audit.credential.read")

    listed = client.get(LEGACY, headers=headers)
    assert listed.status_code == 200
    assert stored.id in {row["id"] for row in listed.json()}
    assert client.post(LEGACY, json=_legacy_body(), headers=headers).status_code == 403
    assert client.delete(f"{LEGACY}/{stored.id}", headers=headers).status_code == 403


def test_the_scanner_role_can_read_the_credentials_it_scans_with(
    client, db_session, org, as_role
):
    """
    ``platform.scanner`` holds ``audit.credential.read`` and not
    ``audit.compliance.read``, so the scan screens' credential picker — which
    calls the legacy path — used to be refused for it.
    """
    stored = _stored(db_session, org)
    response = client.get(LEGACY, headers=as_role("platform.scanner"))

    assert response.status_code == 200
    assert stored.id in {row["id"] for row in response.json()}


def test_an_analyst_can_create_but_not_delete(client, db_session, org, as_role):
    headers = as_role("platform.analyst")

    created = client.post(LEGACY, json=_legacy_body(), headers=headers)
    assert created.status_code == 201
    cred_id = created.json()["id"]
    assert client.delete(f"{LEGACY}/{cred_id}", headers=headers).status_code == 403
    assert client.delete(f"{CANONICAL}/{cred_id}", headers=headers).status_code == 403


def test_an_organisation_administrator_can_delete(client, db_session, org, as_role):
    stored = _stored(db_session, org)
    response = client.delete(
        f"{LEGACY}/{stored.id}", headers=as_role("platform.org_admin")
    )

    assert response.status_code == 200
    db_session.expire_all()
    assert db_session.get(ComplianceCredential, stored.id) is None


def test_another_organisations_credential_is_invisible_and_untouchable(
    client, db_session, org, other_org, as_role
):
    foreign = _stored(db_session, other_org)
    headers = as_role("platform.org_admin")

    listed = client.get(LEGACY, headers=headers)
    assert listed.status_code == 200
    assert foreign.id not in {row["id"] for row in listed.json()}
    # 404, not 403: another organisation's credential is indistinguishable
    # from one that does not exist.
    assert client.delete(f"{LEGACY}/{foreign.id}", headers=headers).status_code == 404
    assert (
        client.delete(f"{CANONICAL}/{foreign.id}", headers=headers).status_code == 404
    )
    db_session.expire_all()
    assert db_session.get(ComplianceCredential, foreign.id) is not None


# ─────────────────────────────────────────────────────────────────────────────
# The legacy path's contract, which its callers depend on
# ─────────────────────────────────────────────────────────────────────────────


def test_legacy_create_keeps_its_response_shape_and_stores_through_the_vault(
    client, db_session, org, as_role
):
    response = client.post(
        LEGACY, json=_legacy_body(), headers=as_role("platform.org_admin")
    )

    assert response.status_code == 201
    body = response.json()
    assert set(body) == LEGACY_FIELDS
    assert SECRET not in response.text

    # The vault's rules applied: a typed, transport-resolved SSH credential,
    # visible through the canonical API with its secret stored.
    db_session.expire_all()
    row = db_session.get(ComplianceCredential, body["id"])
    assert (row.credential_type, row.transport, row.port) == ("ssh", "ssh", 22)
    assert row.encrypted_password and SECRET not in row.encrypted_password
    canonical = client.get(
        f"{CANONICAL}/{body['id']}", headers=as_role("platform.org_admin")
    )
    assert canonical.status_code == 200
    assert canonical.json()["has_secret"] is True


def test_legacy_list_keeps_its_response_shape(client, db_session, org, as_role):
    _stored(db_session, org)
    response = client.get(LEGACY, headers=as_role("platform.org_admin"))

    assert response.status_code == 200
    rows = response.json()
    assert isinstance(rows, list) and rows
    for row in rows:
        assert set(row) == LEGACY_FIELDS
    assert SECRET not in response.text
    assert "encrypted" not in response.text


def test_legacy_refusals_keep_their_status_and_message(
    client, db_session, org, as_role
):
    headers = as_role("platform.org_admin")
    first = _legacy_body()
    assert client.post(LEGACY, json=first, headers=headers).status_code == 201

    duplicate = client.post(LEGACY, json=first, headers=headers)
    assert duplicate.status_code == 400
    assert duplicate.json()["detail"] == "A credential with this name already exists"

    no_password = client.post(LEGACY, json=_legacy_body(password=None), headers=headers)
    assert no_password.status_code == 400
    assert (
        no_password.json()["detail"]
        == "Password is required for password authentication"
    )

    no_key = client.post(
        LEGACY,
        json=_legacy_body(auth_method="key", password=None),
        headers=headers,
    )
    assert no_key.status_code == 400
    assert (
        no_key.json()["detail"]
        == "Private key content is required for key authentication"
    )

    missing = client.delete(f"{LEGACY}/ccrd_does_not_exist", headers=headers)
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Credential not found"


def test_legacy_delete_keeps_its_response(client, db_session, org, as_role):
    stored = _stored(db_session, org)
    response = client.delete(
        f"{LEGACY}/{stored.id}", headers=as_role("platform.org_admin")
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Credential deleted successfully"}


def test_the_canonical_paths_keep_their_own_status_codes(
    client, db_session, org, as_role
):
    """The canonical API answers a duplicate with 409, and still does."""
    headers = as_role("platform.org_admin")
    body = {
        "name": f"canon-{uuid.uuid4().hex[:8]}",
        "username": "svc",
        "credential_type": "ssh",
        "auth_method": "password",
        "password": SECRET,
    }
    assert client.post(CANONICAL, json=body, headers=headers).status_code == 201
    duplicate = client.post(CANONICAL, json=body, headers=headers)
    assert duplicate.status_code == 409
    assert (
        duplicate.json()["detail"]
        == f"A credential named {body['name']!r} already exists."
    )


# ─────────────────────────────────────────────────────────────────────────────
# One audit vocabulary
# ─────────────────────────────────────────────────────────────────────────────


def test_the_legacy_path_records_the_canonical_audit_actions(
    client, db_session, org, as_role
):
    headers = as_role("platform.org_admin")
    created = client.post(LEGACY, json=_legacy_body(), headers=headers).json()
    assert (
        client.delete(f"{LEGACY}/{created['id']}", headers=headers).status_code == 200
    )

    db_session.expire_all()
    rows = (
        db_session.query(AuditLog).filter(AuditLog.resource_id == created["id"]).all()
    )
    actions = {row.action for row in rows}
    assert {"credential.created", "credential.deleted"} <= actions
    # The pre-consolidation names, which no severity table classified.
    assert not actions & {"create_credential", "delete_credential"}
    for row in rows:
        assert SECRET not in repr(row.changes)
        # Classified by Audit's event definitions, not the unclassified default.
        assert row.severity == "high", row.action


# ─────────────────────────────────────────────────────────────────────────────
# The service itself
# ─────────────────────────────────────────────────────────────────────────────


def test_the_service_refuses_a_credential_of_another_organisation(
    db_session, org, other_org
):
    foreign = _stored(db_session, other_org)
    with pytest.raises(credential_vault.CredentialNotFound):
        credential_vault.get_for_org(db_session, org.id, foreign.id)
    assert foreign.id not in {
        c.id for c in credential_vault.list_for_org(db_session, org.id)
    }


def test_the_service_applies_the_type_rules():
    with pytest.raises(credential_vault.CredentialRuleViolation):
        credential_vault.apply_type_rules("ssh", "ntlm", None, None)
    with pytest.raises(credential_vault.CredentialRuleViolation):
        credential_vault.apply_type_rules("windows", "password", "postgresql", None)
    assert credential_vault.apply_type_rules("ssh", "password", None, None) == (
        "ssh",
        22,
    )
