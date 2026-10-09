"""
Service identities and service tokens — Phase 9.5.

A service proves who it is with a short assertion signed by **its own** private
key (RFC 7523 ``private_key_jwt``); the platform checks it against the public
key registered to that service and issues a 10-minute ES256 ``service_access``
token. These tests use throwaway registries built by the real registration
tool, and the throwaway platform keyset ``conftest.py`` generates.

Covered: valid issuance and its audit event; invalid, expired and replayed
assertions; wrong audience and issuer; the wrong key; missing and excess
scopes; tenant binding; human and service tokens never crossing; X-Tenant-ID
never overriding the token; least-privilege scope enforcement; and key
isolation — no secret shared between the platform and a service.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from ccure_platform.identity import jwt_handler, tokens
from ccure_platform.service_identity import registry as reg
from ccure_platform.service_identity.dependencies import (
    require_service_scope,
    service_principal_for,
)
from db.models import AuditLog, Organization
from scripts.security import register_service_identity as tool

READ = "audit:findings:read"
WRITE = "audit:incident_evidence:write"
ENDPOINT = "/auth/service-token"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


# ── fixtures ──────────────────────────────────────────────────────────────────


class Service:
    """A registered service and the private key only it holds."""

    def __init__(self, service_id, private_key, kid):
        self.id = service_id
        self.private_key = private_key
        self.kid = kid

    @property
    def pem(self) -> str:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def assertion(self, **overrides) -> str:
        now = int(datetime.now(timezone.utc).timestamp())
        claims = {
            "iss": self.id,
            "sub": self.id,
            "aud": tokens.SERVICE_ASSERTION_AUDIENCE,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + 60,
        }
        headers = {"kid": overrides.pop("kid", self.kid)}
        key = overrides.pop("signing_pem", self.pem)
        algorithm = overrides.pop("algorithm", "ES256")
        for name, value in overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        return jose_jwt.encode(claims, key, algorithm=algorithm, headers=headers)


def _generate(registry_dir, private_dir, service_id) -> Service:
    kid = tool.generate_key(str(registry_dir), service_id, str(private_dir))
    path = os.path.join(private_dir, f"{service_id}-es256-{kid[:8]}.key.pem")
    with open(path, "rb") as fh:
        private_key = serialization.load_pem_private_key(fh.read(), password=None)
    return Service(service_id, private_key, kid)


@pytest.fixture
def second_org(db_session):
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        id=f"org_{uid}",
        name=f"Other Org {uid}",
        slug=f"other-org-{uid}",
        is_active=True,
    )
    db_session.add(org)
    db_session.commit()
    return org


@pytest.fixture
def services(tmp_path, test_org, second_org, monkeypatch):
    """ir: bound to test_org; rank: granted two tenants. Loaded as the registry."""
    registry_dir, private_dir = tmp_path / "registry", tmp_path / "private"
    registry_dir.mkdir()
    tool.register(
        str(registry_dir),
        "ir",
        name="Incident Response",
        module="ir",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=[READ, WRITE],
        tenants=[test_org.id],
    )
    tool.register(
        str(registry_dir),
        "rank",
        name="Rank",
        module="rank",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=[READ],
        tenants=[test_org.id, second_org.id],
    )
    made = {
        "ir": _generate(registry_dir, private_dir, "ir"),
        "rank": _generate(registry_dir, private_dir, "rank"),
        "dir": registry_dir,
    }
    _load(monkeypatch, registry_dir)
    return made


def _platform_kids():
    return {k["kid"] for k in tokens.public_jwks()["keys"]}


def _load(monkeypatch, registry_dir):
    monkeypatch.setattr(
        reg,
        "_registry",
        reg.load_registry(str(registry_dir), forbidden_kids=_platform_kids()),
    )


def _request(client, assertion, scope=READ, **extra):
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
        "scope": scope,
    }
    data.update(extra)
    return client.post(ENDPOINT, data=data)


def _service_token(client, service, scope=READ, **extra) -> str:
    response = _request(client, service.assertion(), scope=scope, **extra)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _consumer() -> TestClient:
    """A test-only consumer of the service dependencies (design §3.5)."""
    app = FastAPI()

    @app.get("/read")
    def read(principal=Depends(require_service_scope(READ))):
        return {"service": principal.service_id, "tenant": principal.tenant}

    @app.get("/write")
    def write(principal=Depends(require_service_scope(WRITE))):
        return {"service": principal.service_id}

    @app.get("/ir-audience")
    def ir_audience(
        principal=Depends(service_principal_for(tokens.IR_SERVICE_AUDIENCE)),
    ):
        return {"service": principal.service_id}

    return TestClient(app)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ── valid service authentication ──────────────────────────────────────────────


def test_a_service_obtains_a_token(client, services, test_org):
    response = _request(client, services["ir"].assertion(), scope=READ)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 600
    assert body["scope"] == READ
    assert body["tenant"] == test_org.id
    assert response.headers["cache-control"] == "no-store"
    token = body["access_token"]
    header = jose_jwt.get_unverified_header(token)
    assert header == {"alg": "ES256", "kid": tokens.signing_key().kid, "typ": "JWT"}
    claims = jose_jwt.get_unverified_claims(token)
    assert set(claims) == {
        "iss",
        "aud",
        "sub",
        "type",
        "ptype",
        "scope",
        "tenant",
        "jti",
        "iat",
        "nbf",
        "exp",
    }
    assert claims["iss"] == "https://ccurepro.cdac.in"
    assert claims["aud"] == "urn:ccure:core"
    assert claims["sub"] == "svc:ir"
    assert (claims["type"], claims["ptype"]) == ("service_access", "service")
    assert claims["tenant"] == test_org.id
    assert claims["exp"] - claims["iat"] == 600
    assert claims["nbf"] == claims["iat"]


def test_the_token_verifies_as_a_service_token_and_from_the_jwks_alone(
    client, services
):
    token = _service_token(client, services["ir"])
    payload = tokens.verify(
        token,
        expected_kind=tokens.SERVICE_ACCESS,
        issuer=tokens.ISSUER,
        audience=tokens.CORE_SERVICE_AUDIENCE,
    )
    assert payload["sub"] == "svc:ir"
    kid = jose_jwt.get_unverified_header(token)["kid"]
    (jwk,) = [k for k in tokens.public_jwks()["keys"] if k["kid"] == kid]
    assert jose_jwt.decode(
        token,
        jwk,
        algorithms=["ES256"],
        audience="urn:ccure:core",
        issuer=tokens.ISSUER,
    )


def test_issuance_is_audited_without_the_token(client, services, db_session, test_org):
    response = _request(client, services["ir"].assertion(), scope=READ)
    token = response.json()["access_token"]
    jti = jose_jwt.get_unverified_claims(token)["jti"]
    row = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.action == "service.token_issued", AuditLog.org_id == test_org.id
        )
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    assert row is not None
    assert row.actor_username == "svc:ir"
    assert row.user_id is None
    assert row.resource_id == "ir"
    assert row.changes["issued_jti"] == jti
    assert row.changes["scopes"] == [READ]
    assert token not in str(row.changes)


def test_service_tokens_are_es256(client, services):
    token = _service_token(client, services["ir"])
    assert jose_jwt.get_unverified_header(token)["alg"] == "ES256"


# ── invalid, expired and replayed assertions ──────────────────────────────────


def _invalid_client(response):
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "invalid_client"


@pytest.mark.parametrize(
    "name, overrides",
    [
        ("expired", lambda now: {"iat": now - 120, "exp": now - 60}),
        ("issued in the future", lambda now: {"iat": now + 30, "exp": now + 60}),
        ("lifetime over 60 s", lambda now: {"iat": now, "exp": now + 61}),
        ("wrong audience", lambda now: {"aud": "urn:ccure:api"}),
        (
            "audience of another server",
            lambda now: {"aud": "https://evil/api/auth/service-token"},
        ),
        ("no audience", lambda now: {"aud": None}),
        ("no jti", lambda now: {"jti": None}),
        ("no exp", lambda now: {"exp": None}),
        ("no iat", lambda now: {"iat": None}),
        ("sub is not the service", lambda now: {"sub": "rank"}),
    ],
)
def test_an_invalid_assertion_is_refused(client, services, name, overrides):
    now = int(datetime.now(timezone.utc).timestamp())
    _invalid_client(_request(client, services["ir"].assertion(**overrides(now))))


def test_a_malformed_assertion_is_refused(client, services):
    for bad in ("garbage", "a.b.c", services["ir"].assertion()[:-4] + "AAAA"):
        _invalid_client(_request(client, bad))
    # An empty field is a malformed request, refused before authentication.
    assert _request(client, "").status_code == 422


def test_a_replayed_assertion_is_refused(client, services):
    assertion = services["ir"].assertion()
    assert _request(client, assertion).status_code == 200
    _invalid_client(_request(client, assertion))


def test_the_replay_store_failing_refuses_rather_than_accepts(
    client, services, monkeypatch
):
    import core.redis_client

    def broken():
        raise ConnectionError("redis down")

    monkeypatch.setattr(core.redis_client, "get_redis_client", broken)
    response = _request(client, services["ir"].assertion())
    assert response.status_code == 503


def test_a_disabled_service_is_refused(client, services, monkeypatch):
    tool.set_status(str(services["dir"]), "ir", "disabled")
    _load(monkeypatch, services["dir"])
    _invalid_client(_request(client, services["ir"].assertion()))


def test_an_unknown_service_is_refused_like_any_other_failure(client, services):
    stranger = Service("nobody", ec.generate_private_key(ec.SECP256R1()), "kid-x")
    _invalid_client(_request(client, stranger.assertion()))


def test_a_refused_registry_authenticates_no_one(client, services, monkeypatch):
    monkeypatch.setattr(reg, "_registry", None)
    assert _request(client, services["ir"].assertion()).status_code == 503


@pytest.mark.parametrize(
    "field, value",
    [
        ("grant_type", "password"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
        ),
    ],
)
def test_other_grants_are_refused(client, services, field, value):
    response = _request(client, services["ir"].assertion(), **{field: value})
    assert response.status_code == 400


# ── wrong key, and key isolation ──────────────────────────────────────────────


def test_an_assertion_signed_by_an_unregistered_key_is_refused(client, services):
    impostor = ec.generate_private_key(ec.SECP256R1())
    forged = Service("ir", impostor, services["ir"].kid)  # ir's kid, another key
    _invalid_client(_request(client, forged.assertion()))


def test_one_services_key_cannot_authenticate_another(client, services):
    """rank signs as ir, with rank's own registered key and kid."""
    rank = services["rank"]
    _invalid_client(_request(client, rank.assertion(iss="ir", sub="ir")))


def test_the_platform_signing_key_authenticates_no_service(client, services):
    platform = tokens.signing_key()
    as_platform = Service("ir", platform.private_key, platform.kid)
    _invalid_client(_request(client, as_platform.assertion()))


def test_no_shared_secret_can_authenticate_a_service(client, services):
    """No HMAC secret — the platform holds none now — opens anything here."""
    a_secret = "any-hmac-secret-an-attacker-might-guess"
    secret_signed = services["ir"].assertion(signing_pem=a_secret, algorithm="HS256")
    _invalid_client(_request(client, secret_signed))
    no_kid = jose_jwt.encode(
        {"iss": "ir", "sub": "ir", "aud": tokens.SERVICE_ASSERTION_AUDIENCE},
        a_secret,
        algorithm="HS256",
    )
    _invalid_client(_request(client, no_kid))


def test_a_service_cannot_mint_its_own_service_token(services):
    """A token signed by a service's key is not a platform token."""
    now = int(datetime.now(timezone.utc).timestamp())
    self_made = jose_jwt.encode(
        {
            "iss": tokens.ISSUER,
            "aud": tokens.CORE_SERVICE_AUDIENCE,
            "sub": "svc:ir",
            "type": "service_access",
            "ptype": "service",
            "scope": READ,
            "tenant": "org_x",
            "jti": "x",
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        },
        services["ir"].pem,
        algorithm="ES256",
        headers={"kid": services["ir"].kid},
    )
    assert (
        tokens.verify(
            self_made,
            expected_kind=tokens.SERVICE_ACCESS,
            issuer=tokens.ISSUER,
            audience=tokens.CORE_SERVICE_AUDIENCE,
        )
        is None
    )


def test_an_hs256_service_token_is_refused(services):
    forged = jose_jwt.encode(
        {
            "sub": "svc:ir",
            "type": "service_access",
            "ptype": "service",
            "scope": READ,
            "tenant": "org_x",
            "exp": int(datetime.now(timezone.utc).timestamp()) + 60,
        },
        "any-hmac-secret-an-attacker-might-guess",
        algorithm="HS256",
    )
    assert (
        tokens.verify(
            forged,
            expected_kind=tokens.SERVICE_ACCESS,
            issuer=tokens.ISSUER,
            audience=tokens.CORE_SERVICE_AUDIENCE,
        )
        is None
    )


def test_service_keys_are_never_published(client, services):
    published = _platform_kids()
    assert services["ir"].kid not in published
    assert services["rank"].kid not in published


def test_sign_never_issues_a_service_token():
    with pytest.raises(ValueError):
        tokens.sign({"sub": "svc:ir", "type": "service_access"}, timedelta(minutes=1))


@pytest.mark.parametrize(
    "overrides",
    [
        {"audience": "urn:ccure:api"},
        {"scopes": frozenset()},
        {"tenant": ""},
        {"service_id": "svc:ir"},
    ],
)
def test_sign_service_token_refuses_what_no_caller_may_ask_for(overrides):
    args = dict(
        service_id="ir",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=frozenset({READ}),
        tenant="org_x",
    )
    args.update(overrides)
    with pytest.raises(ValueError):
        tokens.sign_service_token(**args)


# ── scopes ────────────────────────────────────────────────────────────────────


def test_a_missing_scope_is_refused(client, services):
    response = _request(client, services["ir"].assertion(), scope="")
    assert (response.status_code, response.json()["detail"]) == (400, "invalid_scope")


def test_a_scope_beyond_the_identity_is_refused(client, services):
    response = _request(client, services["rank"].assertion(), scope=f"{READ} {WRITE}")
    assert (response.status_code, response.json()["detail"]) == (400, "invalid_scope")


def test_the_token_carries_only_the_scopes_requested(client, services):
    token = _service_token(client, services["ir"], scope=READ)
    assert jose_jwt.get_unverified_claims(token)["scope"] == READ


def test_least_privilege_is_enforced_by_the_consumer(client, services):
    consumer = _consumer()
    read_only = _service_token(client, services["ir"], scope=READ)
    assert consumer.get("/read", headers=_bearer(read_only)).status_code == 200
    response = consumer.get("/write", headers=_bearer(read_only))
    assert response.status_code == 403
    both = _service_token(client, services["ir"], scope=f"{READ} {WRITE}")
    assert consumer.get("/write", headers=_bearer(both)).status_code == 200


# ── tenant binding ────────────────────────────────────────────────────────────


def test_a_bound_service_gets_its_tenant(client, services, test_org):
    token = _service_token(client, services["ir"])
    assert jose_jwt.get_unverified_claims(token)["tenant"] == test_org.id


def test_a_bound_service_cannot_ask_for_another_tenant(client, services, second_org):
    response = _request(client, services["ir"].assertion(), tenant=second_org.id)
    assert response.status_code == 403


def test_a_multi_tenant_service_must_name_the_tenant(client, services, second_org):
    response = _request(client, services["rank"].assertion())
    assert (response.status_code, response.json()["detail"]) == (400, "invalid_request")
    token = _service_token(client, services["rank"], tenant=second_org.id)
    assert jose_jwt.get_unverified_claims(token)["tenant"] == second_org.id


def test_an_inactive_organisation_gets_no_token(client, services, db_session, test_org):
    test_org.is_active = False
    db_session.commit()
    assert _request(client, services["ir"].assertion()).status_code == 403


def test_x_tenant_id_cannot_override_the_token(client, services, test_org, second_org):
    consumer = _consumer()
    token = _service_token(client, services["ir"])
    response = consumer.get(
        "/read", headers={**_bearer(token), "X-Tenant-ID": second_org.id}
    )
    assert response.status_code == 200
    assert response.json()["tenant"] == test_org.id
    # Nor can the header steer issuance: the token names the granted tenant.
    response = client.post(
        ENDPOINT,
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": services["ir"].assertion(),
            "scope": READ,
        },
        headers={"X-Tenant-ID": second_org.id},
    )
    assert response.status_code == 200
    assert (
        jose_jwt.get_unverified_claims(response.json()["access_token"])["tenant"]
        == test_org.id
    )


def test_a_revoked_tenant_grant_refuses_a_live_token(
    client, services, monkeypatch, second_org
):
    consumer = _consumer()
    token = _service_token(client, services["ir"])
    tool.set_tenants(str(services["dir"]), "ir", [second_org.id])
    _load(monkeypatch, services["dir"])
    assert consumer.get("/read", headers=_bearer(token)).status_code == 401


def test_disabling_a_service_refuses_its_live_tokens(client, services, monkeypatch):
    consumer = _consumer()
    token = _service_token(client, services["ir"])
    assert consumer.get("/read", headers=_bearer(token)).status_code == 200
    tool.set_status(str(services["dir"]), "ir", "disabled")
    _load(monkeypatch, services["dir"])
    assert consumer.get("/read", headers=_bearer(token)).status_code == 401


def test_a_token_for_one_service_is_refused_by_another(client, services):
    token = _service_token(client, services["ir"])  # aud urn:ccure:core
    assert _consumer().get("/ir-audience", headers=_bearer(token)).status_code == 401


# ── humans and services never cross ───────────────────────────────────────────


def test_a_human_token_cannot_authenticate_as_a_service(client, services, test_user):
    consumer = _consumer()
    for kind_token in (
        jwt_handler.create_access_token(
            test_user.id,
            test_user.username,
            org_id=test_user.org_id,
        ),
        jwt_handler.create_download_ticket(test_user.id, test_user.username),
    ):
        assert consumer.get("/read", headers=_bearer(kind_token)).status_code == 401
    human = jwt_handler.create_access_token(test_user.id, test_user.username)
    _invalid_client(_request(client, human))  # nor as a client assertion


def test_a_service_token_cannot_authenticate_as_a_human(client, services, db_session):
    from ccure_platform.identity.dependencies import get_current_user_flexible
    from fastapi import HTTPException

    token = _service_token(client, services["ir"])
    response = client.get("/auth/me", headers=_bearer(token))
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"
    assert jwt_handler.decode_token(token) is None  # WebSockets, rate-limit audit
    with pytest.raises(HTTPException):
        get_current_user_flexible(ticket=token, credentials=None, db=db_session)
    for kind in tokens.USER_KINDS:
        assert (
            tokens.verify(
                token,
                expected_kind=kind,
                issuer=tokens.ISSUER,
                audience=tokens.USER_AUDIENCE,
            )
            is None
        )


def test_service_subjects_cannot_collide_with_user_ids():
    assert tokens.SERVICE_SUBJECT_PREFIX == "svc:"
    from db.base import gen_user_id

    assert not gen_user_id("any-org", "svc").startswith("svc:")


# ── the registry and the tool ─────────────────────────────────────────────────


def test_the_registry_refuses_a_private_key(tmp_path):
    registry_dir = tmp_path / "r"
    registry_dir.mkdir()
    tool.register(
        str(registry_dir),
        "ir",
        name="IR",
        module="ir",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=[READ],
        tenants=["org_x"],
    )
    private = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "priv.pem").write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(reg.RegistryError, match="private key"):
        tool.add_key(str(registry_dir), "ir", str(tmp_path / "priv.pem"))
    # And if one is placed there by hand, the registry refuses to load.
    kid = tool.add_key(str(registry_dir), "ir", _public_pem_file(tmp_path, private))
    entry_file = next(f for f in os.listdir(registry_dir) if f.endswith(".pem"))
    (registry_dir / entry_file).write_bytes((tmp_path / "priv.pem").read_bytes())
    with pytest.raises(reg.RegistryError, match="private key"):
        reg.load_registry(str(registry_dir))
    assert kid


def _public_pem_file(tmp_path, private_key) -> str:
    path = tmp_path / f"pub-{uuid.uuid4().hex[:6]}.pem"
    path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(path)


def test_a_platform_signing_key_cannot_be_registered_to_a_service(tmp_path):
    registry_dir = tmp_path / "r"
    registry_dir.mkdir()
    tool.register(
        str(registry_dir),
        "ir",
        name="IR",
        module="ir",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=[READ],
        tenants=["org_x"],
    )
    platform = tokens.signing_key().private_key
    tool.add_key(str(registry_dir), "ir", _public_pem_file(tmp_path, platform))
    with pytest.raises(reg.RegistryError, match="platform signing key"):
        reg.load_registry(str(registry_dir), forbidden_kids=_platform_kids())


def test_one_key_cannot_belong_to_two_services(tmp_path):
    registry_dir = tmp_path / "r"
    registry_dir.mkdir()
    for sid in ("ir", "rank"):
        tool.register(
            str(registry_dir),
            sid,
            name=sid,
            module=sid,
            audience=tokens.CORE_SERVICE_AUDIENCE,
            scopes=[READ],
            tenants=["org_x"],
        )
    key = ec.generate_private_key(ec.SECP256R1())
    tool.add_key(str(registry_dir), "ir", _public_pem_file(tmp_path, key))
    with pytest.raises((reg.RegistryError, FileExistsError)):
        tool.add_key(str(registry_dir), "rank", _public_pem_file(tmp_path, key))


def test_generate_key_never_writes_a_private_key_into_the_registry(tmp_path):
    registry_dir = tmp_path / "r"
    registry_dir.mkdir()
    tool.register(
        str(registry_dir),
        "ir",
        name="IR",
        module="ir",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=[READ],
        tenants=["org_x"],
    )
    with pytest.raises(reg.RegistryError):
        tool.generate_key(str(registry_dir), "ir", str(registry_dir))
    kid = tool.generate_key(str(registry_dir), "ir", str(tmp_path / "ir-private"))
    for name in os.listdir(registry_dir):
        assert b"PRIVATE KEY" not in (registry_dir / name).read_bytes()
    private_files = list((tmp_path / "ir-private").iterdir())
    assert len(private_files) == 1
    assert oct(private_files[0].stat().st_mode)[-3:] == "600"
    assert reg.load_registry(str(registry_dir)).key_for("ir", kid)


def _manifest_with(tmp_path, **entry_overrides):
    registry_dir = tmp_path / "r"
    registry_dir.mkdir()
    tool.register(
        str(registry_dir),
        "ir",
        name="IR",
        module="ir",
        audience=tokens.CORE_SERVICE_AUDIENCE,
        scopes=[READ],
        tenants=["org_x"],
    )
    import json

    path = registry_dir / reg.MANIFEST
    manifest = json.loads(path.read_text())
    manifest["services"][0].update(entry_overrides)
    path.write_text(json.dumps(manifest))
    return registry_dir


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": "IR"},
        {"id": "svc:ir"},
        {"status": "enabled"},
        {"audience": "urn:ccure:api"},
        {"scopes": ["read-everything"]},
        {"scopes": [READ, READ]},
        {"tenants": []},
        {"keys": [{"kid": "x", "file": "../../etc/passwd"}]},
    ],
)
def test_an_invalid_registry_is_refused_whole(tmp_path, overrides):
    with pytest.raises(reg.RegistryError):
        reg.load_registry(str(_manifest_with(tmp_path, **overrides)))


def test_a_kid_that_is_not_its_keys_thumbprint_is_refused(tmp_path):
    registry_dir = _manifest_with(tmp_path)
    key = ec.generate_private_key(ec.SECP256R1())
    tool.add_key(str(registry_dir), "ir", _public_pem_file(tmp_path, key))
    import json

    path = registry_dir / reg.MANIFEST
    manifest = json.loads(path.read_text())
    manifest["services"][0]["keys"][0]["kid"] = "forged-kid"
    path.write_text(json.dumps(manifest))
    with pytest.raises(reg.RegistryError, match="does not match"):
        reg.load_registry(str(registry_dir))


def test_no_registry_configured_means_no_service_authenticates(client, monkeypatch):
    from config import JWTConfig

    monkeypatch.setattr(JWTConfig, "SERVICE_REGISTRY_DIR", "")
    monkeypatch.setattr(reg, "_registry", reg._UNLOADED)
    assert reg.current_registry().services == ()
    assert "unset" in reg.registry_status()
    stranger = Service("ir", ec.generate_private_key(ec.SECP256R1()), "kid-x")
    _invalid_client(_request(client, stranger.assertion()))


def test_the_endpoint_is_rate_limited():
    from core.rate_limiter import limiter

    assert limiter._route_limits.get(
        "ccure_platform.service_identity.router.service_token"
    )


def test_service_identities_are_not_users(services, db_session):
    from db.models import User

    assert db_session.query(User).filter(User.id.like("svc:%")).count() == 0
    assert db_session.query(User).filter(User.username.in_(["ir", "rank"])).count() == 0
