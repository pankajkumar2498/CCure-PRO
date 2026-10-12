from native_rbac import system_role, create_user, grant_permissions

from auth.jwt_handler import create_access_token
from core.audit import log_audit_event
from db.models import AuditLog, Organization, User
from rbac_testing import system_role_id


def _auth_headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


def test_org_admin_user_listing_is_tenant_scoped(client, db_session):
    org_a = Organization(name="Org A", slug="org-a", is_active=True)
    org_b = Organization(name="Org B", slug="org-b", is_active=True)
    db_session.add_all([org_a, org_b])

    superadmin_role = system_role(db_session, "platform.superadmin")
    org_admin_role = system_role(db_session, "platform.org_admin")

    for role in (superadmin_role, org_admin_role):
        grant_permissions(db_session, role, "platform.user.read")

    org_admin_a = create_user(
        db_session,
        username="orgadmin-a",
        email="orgadmin-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    user_a = create_user(
        db_session,
        username="user-a",
        email="user-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    user_b = create_user(
        db_session,
        username="user-b",
        email="user-b@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([org_admin_a, user_a, user_b])
    db_session.commit()
    db_session.refresh(org_admin_a)

    response = client.get("/admin/users/", headers=_auth_headers(org_admin_a))

    assert response.status_code == 200
    payload = response.json()
    usernames = {item["username"] for item in payload["users"]}
    assert usernames == {"orgadmin-a", "user-a"}
    assert "user-b" not in usernames


def test_superadmin_user_listing_can_see_all_users(client, db_session):
    org_a = Organization(name="Org SA A", slug="org-sa-a", is_active=True)
    org_b = Organization(name="Org SA B", slug="org-sa-b", is_active=True)
    db_session.add_all([org_a, org_b])

    superadmin_role = system_role(db_session, "platform.superadmin")
    org_admin_role = system_role(db_session, "platform.org_admin")

    grant_permissions(db_session, superadmin_role, "platform.user.read")

    superadmin = create_user(
        db_session,
        username="superadmin",
        email="superadmin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=superadmin_role,
        is_active=True,
        is_verified=True,
    )
    user_a = create_user(
        db_session,
        username="tenant-a-user",
        email="tenant-a-user@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    user_b = create_user(
        db_session,
        username="tenant-b-user",
        email="tenant-b-user@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([superadmin, user_a, user_b])
    db_session.commit()
    db_session.refresh(superadmin)

    response = client.get("/admin/users/", headers=_auth_headers(superadmin))

    assert response.status_code == 200
    usernames = {item["username"] for item in response.json()["users"]}
    assert {"superadmin", "tenant-a-user", "tenant-b-user"}.issubset(usernames)


def test_org_admin_audit_logs_are_tenant_scoped(client, db_session):
    org_a = Organization(
        name="Audit Org A",
        slug="audit-org-a",
        is_active=True,
    )
    org_b = Organization(
        name="Audit Org B",
        slug="audit-org-b",
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = system_role(db_session, "platform.superadmin")
    org_admin_role = system_role(db_session, "platform.org_admin")

    for role in (superadmin_role, org_admin_role):
        grant_permissions(db_session, role, "platform.audit_log.read")

    org_admin_a = create_user(
        db_session,
        username="audit-admin-a",
        email="audit-admin-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    user_a = create_user(
        db_session,
        username="audit-user-a",
        email="audit-user-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    user_b = create_user(
        db_session,
        username="audit-user-b",
        email="audit-user-b@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([org_admin_a, user_a, user_b])
    db_session.commit()
    db_session.refresh(org_admin_a)
    db_session.refresh(user_a)
    db_session.refresh(user_b)

    log_audit_event(db_session, user_a, "scan.created", "scan", "asset-a")
    log_audit_event(db_session, user_b, "scan.created", "scan", "asset-b")
    db_session.commit()

    response = client.get("/admin/audit-logs/", headers=_auth_headers(org_admin_a))

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["logs"][0]["resource_id"] == "asset-a"
    assert payload["logs"][0]["user_id"] == str(user_a.id)


def test_superadmin_audit_logs_can_see_all_tenants(client, db_session):
    org_a = Organization(
        name="Audit SA A",
        slug="audit-sa-a",
        is_active=True,
    )
    org_b = Organization(
        name="Audit SA B",
        slug="audit-sa-b",
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = system_role(db_session, "platform.superadmin")
    org_admin_role = system_role(db_session, "platform.org_admin")

    grant_permissions(db_session, superadmin_role, "platform.audit_log.read")

    superadmin = create_user(
        db_session,
        username="audit-superadmin",
        email="audit-superadmin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=superadmin_role,
        is_active=True,
        is_verified=True,
    )
    user_a = create_user(
        db_session,
        username="audit-sa-user-a",
        email="audit-sa-user-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    user_b = create_user(
        db_session,
        username="audit-sa-user-b",
        email="audit-sa-user-b@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([superadmin, user_a, user_b])
    db_session.commit()
    db_session.refresh(superadmin)
    db_session.refresh(user_a)
    db_session.refresh(user_b)

    log_audit_event(db_session, user_a, "scan.created", "scan", "sa-asset-a")
    log_audit_event(db_session, user_b, "scan.created", "scan", "sa-asset-b")
    db_session.commit()

    response = client.get("/admin/audit-logs/", headers=_auth_headers(superadmin))

    assert response.status_code == 200
    resource_ids = {log["resource_id"] for log in response.json()["logs"]}
    assert {"sa-asset-a", "sa-asset-b"}.issubset(resource_ids)


def test_access_token_contains_org_and_role_claims(client, db_session):
    org = Organization(name="Token Org", slug="token-org", is_active=True)
    role = system_role(db_session, "platform.org_admin")
    db_session.add(org)
    db_session.flush()

    user = create_user(
        db_session,
        username="token-user",
        email="token-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(user.id, user.username, org_id=org.id)

    from auth.jwt_handler import decode_token

    payload = decode_token(token)
    assert payload["sub"] == str(user.id)
    assert "role" not in payload  # RBAC-8: no role claim is issued
    assert payload["org_id"] == str(org.id)


def test_superadmin_create_user_requires_explicit_organization(client, db_session):
    org = Organization(
        name="Create Org",
        slug="create-org",
        is_active=True,
    )
    db_session.add(org)

    superadmin_role = system_role(db_session, "platform.superadmin")
    analyst_role = system_role(db_session, "platform.analyst")

    grant_permissions(db_session, superadmin_role, "platform.user.create")

    superadmin = create_user(
        db_session,
        username="creator-superadmin",
        email="creator-superadmin@test.com",
        password_hash="hash",
        org_id=org.id,
        role=superadmin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add(superadmin)
    db_session.commit()
    db_session.refresh(superadmin)

    response = client.post(
        "/admin/users/",
        headers=_auth_headers(superadmin),
        json={
            "username": "missing-org-user",
            "email": "missing-org-user@test.com",
            "password": "SecurePass123!",
            "rbac_role_id": system_role_id(db_session, "platform.analyst"),
        },
    )

    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "organization_id is required when superadmin creates a user"
    )


def test_superadmin_create_user_assigns_selected_organization(client, db_session):
    org_a = Organization(
        name="Create Org A",
        slug="create-org-a",
        is_active=True,
    )
    org_b = Organization(
        name="Create Org B",
        slug="create-org-b",
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = system_role(db_session, "platform.superadmin")
    analyst_role = system_role(db_session, "platform.analyst")

    grant_permissions(db_session, superadmin_role, "platform.user.create")

    superadmin = create_user(
        db_session,
        username="assign-superadmin",
        email="assign-superadmin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=superadmin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add(superadmin)
    db_session.commit()
    db_session.refresh(superadmin)

    response = client.post(
        "/admin/users/",
        headers=_auth_headers(superadmin),
        json={
            "username": "assigned-user",
            "email": "assigned-user@test.com",
            "password": "SecurePass123!",
            "rbac_role_id": system_role_id(db_session, "platform.analyst"),
            "organization_id": str(org_b.id),
        },
    )

    assert response.status_code == 200
    created_user = (
        db_session.query(User).filter(User.username == "assigned-user").first()
    )
    assert created_user is not None
    assert str(created_user.org_id) == str(org_b.id)


def test_org_admin_create_user_rejects_an_explicit_foreign_organization(
    client, db_session
):
    org_a = Organization(
        name="Forced Org A",
        slug="forced-org-a",
        is_active=True,
    )
    org_b = Organization(
        name="Forced Org B",
        slug="forced-org-b",
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    org_admin_role = system_role(db_session, "platform.org_admin")
    analyst_role = system_role(db_session, "platform.analyst")

    grant_permissions(db_session, org_admin_role, "platform.user.create")

    org_admin = create_user(
        db_session,
        username="forced-org-admin",
        email="forced-org-admin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add(org_admin)
    db_session.commit()
    db_session.refresh(org_admin)

    response = client.post(
        "/admin/users/",
        headers=_auth_headers(org_admin),
        json={
            "username": "forced-org-user",
            "email": "forced-org-user@test.com",
            "password": "SecurePass123!",
            "rbac_role_id": system_role_id(db_session, "platform.analyst"),
            "organization_id": str(org_b.id),
        },
    )

    assert response.status_code == 403
    assert (
        db_session.query(User).filter(User.username == "forced-org-user").first()
        is None
    )


def test_list_users_excludes_deleted_by_default_and_deleted_scope_returns_them(
    client, db_session
):
    org = Organization(
        name="Deleted Scope Org",
        slug="deleted-scope-org",
        is_active=True,
    )
    db_session.add(org)

    org_admin_role = system_role(db_session, "platform.org_admin")

    grant_permissions(db_session, org_admin_role, "platform.user.read")
    grant_permissions(
        db_session, org_admin_role, "platform.user.delete", "platform.user.purge"
    )

    admin = create_user(
        db_session,
        username="deleted-scope-admin",
        email="deleted-scope-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    active_user = create_user(
        db_session,
        username="active-user",
        email="active-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    deleted_user = create_user(
        db_session,
        username="deleted-user",
        email="deleted-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role=org_admin_role,
        is_active=False,
        is_deleted=True,
        is_verified=True,
    )
    db_session.add_all([admin, active_user, deleted_user])
    db_session.commit()
    db_session.refresh(admin)

    active_response = client.get("/admin/users/", headers=_auth_headers(admin))
    deleted_response = client.get(
        "/admin/users/?scope=deleted", headers=_auth_headers(admin)
    )

    assert active_response.status_code == 200
    assert deleted_response.status_code == 200
    assert {item["username"] for item in active_response.json()["users"]} == {
        "deleted-scope-admin",
        "active-user",
    }
    assert {item["username"] for item in deleted_response.json()["users"]} == {
        "deleted-user"
    }


def test_soft_delete_restore_and_purge_user_flow(client, db_session):
    org = Organization(
        name="Lifecycle Org",
        slug="lifecycle-org",
        is_active=True,
    )
    db_session.add(org)

    org_admin_role = system_role(db_session, "platform.org_admin")

    grant_permissions(db_session, org_admin_role, "platform.user.read")
    grant_permissions(
        db_session, org_admin_role, "platform.user.delete", "platform.user.purge"
    )

    admin = create_user(
        db_session,
        username="lifecycle-admin",
        email="lifecycle-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    target = create_user(
        db_session,
        username="lifecycle-target",
        email="lifecycle-target@test.com",
        password_hash="hash",
        org_id=org.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([admin, target])
    db_session.commit()
    db_session.refresh(admin)
    db_session.refresh(target)

    delete_response = client.delete(
        f"/admin/users/{target.id}/", headers=_auth_headers(admin)
    )
    db_session.refresh(target)

    assert delete_response.status_code == 200
    assert target.is_deleted is True
    assert target.is_active is False
    assert target.deleted_at is not None

    restore_response = client.post(
        f"/admin/users/{target.id}/restore/", headers=_auth_headers(admin)
    )
    db_session.refresh(target)

    assert restore_response.status_code == 200
    assert target.is_deleted is False
    assert target.deleted_at is None
    assert target.is_active is False

    second_delete_response = client.delete(
        f"/admin/users/{target.id}/", headers=_auth_headers(admin)
    )
    assert second_delete_response.status_code == 200

    target_id = str(target.id)
    purge_response = client.delete(
        f"/admin/users/{target.id}/purge/", headers=_auth_headers(admin)
    )
    assert purge_response.status_code == 200
    assert db_session.query(User).filter(User.id == target_id).first() is None


def test_purge_user_preserves_audit_logs_by_nulling_user_reference(client, db_session):
    org = Organization(
        name="Purge Audit Org",
        slug="purge-audit-org",
        is_active=True,
    )
    db_session.add(org)

    org_admin_role = system_role(db_session, "platform.org_admin")

    grant_permissions(
        db_session, org_admin_role, "platform.user.delete", "platform.user.purge"
    )

    admin = create_user(
        db_session,
        username="purge-admin",
        email="purge-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role=org_admin_role,
        is_active=True,
        is_verified=True,
    )
    target = create_user(
        db_session,
        username="purge-target",
        email="purge-target@test.com",
        password_hash="hash",
        org_id=org.id,
        role=org_admin_role,
        is_active=False,
        is_deleted=True,
        is_verified=True,
    )
    db_session.add_all([admin, target])
    db_session.commit()
    db_session.refresh(admin)
    db_session.refresh(target)

    log_audit_event(db_session, target, "user.login", "user", str(target.id))
    db_session.commit()
    audit_log = db_session.query(AuditLog).filter(AuditLog.user_id == target.id).first()
    assert audit_log is not None

    target_id = str(target.id)
    response = client.delete(
        f"/admin/users/{target.id}/purge/", headers=_auth_headers(admin)
    )
    db_session.refresh(audit_log)

    assert response.status_code == 200
    assert audit_log.user_id is None
    assert db_session.query(User).filter(User.id == target_id).first() is None


def test_deleted_user_cannot_log_in(client, db_session):
    org = Organization(
        name="Deleted Login Org",
        slug="deleted-login-org",
        is_active=True,
    )
    role = system_role(db_session, "platform.org_admin")
    db_session.add(org)
    db_session.flush()

    from auth.jwt_handler import hash_password
    from db.base import utcnow

    deleted_user = create_user(
        db_session,
        username="deleted-login-user",
        email="deleted-login-user@test.com",
        password_hash=hash_password("CorrectHorse1!"),
        org_id=org.id,
        role=role,
        is_active=False,
        is_deleted=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    db_session.add(deleted_user)
    db_session.commit()

    # A wrong password gets the generic 401 and learns nothing. This assertion
    # replaces an earlier one expecting 403 "Account deleted" here: disclosing
    # account state before the credential is verified let anyone confirm that
    # an address was registered — and that it had been deleted — by submitting
    # it with any password at all.
    wrong = client.post(
        "/auth/login",
        json={"email": "deleted-login-user@test.com", "password": "wrong-password"},
    )
    assert wrong.status_code == 401
    assert wrong.json()["detail"] == "Invalid email or password"

    # The correct password still cannot produce a session for a deleted account.
    correct = client.post(
        "/auth/login",
        json={"email": "deleted-login-user@test.com", "password": "CorrectHorse1!"},
    )
    assert correct.status_code == 403
    assert correct.json()["detail"] == "Account deleted"
