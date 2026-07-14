from auth.jwt_handler import create_access_token
from core.audit import log_audit_event
from db.models import AuditLog, Organization, Permission, Role, RolePermission, User


def _grant_permission(db_session, role: Role, resource: str, action: str) -> None:
    permission = (
        db_session.query(Permission)
        .filter(Permission.resource == resource, Permission.action == action)
        .first()
    )
    if permission is None:
        permission = Permission(
            resource=resource, action=action, description=f"{resource}:{action}"
        )
        db_session.add(permission)
        db_session.flush()

    exists = (
        db_session.query(RolePermission)
        .filter(
            RolePermission.role_id == role.id,
            RolePermission.permission_id == permission.id,
        )
        .first()
    )
    if exists is None:
        db_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
        db_session.flush()


def _auth_headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
        role=getattr(user.role, "name", None),
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


def test_org_admin_user_listing_is_tenant_scoped(client, db_session):
    org_a = Organization(
        name="Org A", slug="org-a", max_assets=100, max_users=10, is_active=True
    )
    org_b = Organization(
        name="Org B", slug="org-b", max_assets=100, max_users=10, is_active=True
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = Role(
        name="superadmin", description="Platform admin", is_system_role=True
    )
    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add_all([superadmin_role, org_admin_role])
    db_session.flush()

    for role in (superadmin_role, org_admin_role):
        _grant_permission(db_session, role, "users", "read")

    org_admin_a = User(
        username="orgadmin-a",
        email="orgadmin-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_a = User(
        username="user-a",
        email="user-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_b = User(
        username="user-b",
        email="user-b@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role_id=org_admin_role.id,
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
    org_a = Organization(
        name="Org SA A", slug="org-sa-a", max_assets=100, max_users=10, is_active=True
    )
    org_b = Organization(
        name="Org SA B", slug="org-sa-b", max_assets=100, max_users=10, is_active=True
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = Role(
        name="superadmin", description="Platform admin", is_system_role=True
    )
    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add_all([superadmin_role, org_admin_role])
    db_session.flush()

    _grant_permission(db_session, superadmin_role, "users", "read")

    superadmin = User(
        username="superadmin",
        email="superadmin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_a = User(
        username="tenant-a-user",
        email="tenant-a-user@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_b = User(
        username="tenant-b-user",
        email="tenant-b-user@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role_id=org_admin_role.id,
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
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    org_b = Organization(
        name="Audit Org B",
        slug="audit-org-b",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = Role(
        name="superadmin", description="Platform admin", is_system_role=True
    )
    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add_all([superadmin_role, org_admin_role])
    db_session.flush()

    for role in (superadmin_role, org_admin_role):
        _grant_permission(db_session, role, "audit", "read")

    org_admin_a = User(
        username="audit-admin-a",
        email="audit-admin-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_a = User(
        username="audit-user-a",
        email="audit-user-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_b = User(
        username="audit-user-b",
        email="audit-user-b@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role_id=org_admin_role.id,
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
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    org_b = Organization(
        name="Audit SA B",
        slug="audit-sa-b",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = Role(
        name="superadmin", description="Platform admin", is_system_role=True
    )
    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add_all([superadmin_role, org_admin_role])
    db_session.flush()

    _grant_permission(db_session, superadmin_role, "audit", "read")

    superadmin = User(
        username="audit-superadmin",
        email="audit-superadmin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_a = User(
        username="audit-sa-user-a",
        email="audit-sa-user-a@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user_b = User(
        username="audit-sa-user-b",
        email="audit-sa-user-b@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role_id=org_admin_role.id,
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
    org = Organization(
        name="Token Org", slug="token-org", max_assets=100, max_users=10, is_active=True
    )
    role = Role(name="org_admin", description="Org admin", is_system_role=True)
    db_session.add_all([org, role])
    db_session.flush()

    user = User(
        username="token-user",
        email="token-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(user.id, user.username, role=role.name, org_id=org.id)

    from auth.jwt_handler import decode_token

    payload = decode_token(token)
    assert payload["sub"] == str(user.id)
    assert payload["role"] == "org_admin"
    assert payload["org_id"] == str(org.id)


def test_superadmin_create_user_requires_explicit_organization(client, db_session):
    org = Organization(
        name="Create Org",
        slug="create-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)

    superadmin_role = Role(
        name="superadmin", description="Platform admin", is_system_role=True
    )
    db_session.add(superadmin_role)
    db_session.flush()
    analyst_role = db_session.query(Role).filter(Role.name == "analyst").first()

    _grant_permission(db_session, superadmin_role, "users", "create")

    superadmin = User(
        username="creator-superadmin",
        email="creator-superadmin@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=superadmin_role.id,
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
            "role_id": analyst_role.id,
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
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    org_b = Organization(
        name="Create Org B",
        slug="create-org-b",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    superadmin_role = Role(
        name="superadmin", description="Platform admin", is_system_role=True
    )
    db_session.add(superadmin_role)
    db_session.flush()
    analyst_role = db_session.query(Role).filter(Role.name == "analyst").first()

    _grant_permission(db_session, superadmin_role, "users", "create")

    superadmin = User(
        username="assign-superadmin",
        email="assign-superadmin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=superadmin_role.id,
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
            "role_id": analyst_role.id,
            "organization_id": str(org_b.id),
        },
    )

    assert response.status_code == 200
    created_user = (
        db_session.query(User).filter(User.username == "assigned-user").first()
    )
    assert created_user is not None
    assert str(created_user.org_id) == str(org_b.id)


def test_org_admin_create_user_is_forced_into_own_organization(client, db_session):
    org_a = Organization(
        name="Forced Org A",
        slug="forced-org-a",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    org_b = Organization(
        name="Forced Org B",
        slug="forced-org-b",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add_all([org_a, org_b])

    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add(org_admin_role)
    db_session.flush()
    analyst_role = db_session.query(Role).filter(Role.name == "analyst").first()

    _grant_permission(db_session, org_admin_role, "users", "create")

    org_admin = User(
        username="forced-org-admin",
        email="forced-org-admin@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=org_admin_role.id,
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
            "role_id": analyst_role.id,
            "organization_id": str(org_b.id),
        },
    )

    assert response.status_code == 200
    created_user = (
        db_session.query(User).filter(User.username == "forced-org-user").first()
    )
    assert created_user is not None
    assert str(created_user.org_id) == str(org_a.id)


def test_list_users_excludes_deleted_by_default_and_deleted_scope_returns_them(
    client, db_session
):
    org = Organization(
        name="Deleted Scope Org",
        slug="deleted-scope-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)

    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add(org_admin_role)
    db_session.flush()

    _grant_permission(db_session, org_admin_role, "users", "read")
    _grant_permission(db_session, org_admin_role, "users", "delete")

    admin = User(
        username="deleted-scope-admin",
        email="deleted-scope-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    active_user = User(
        username="active-user",
        email="active-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    deleted_user = User(
        username="deleted-user",
        email="deleted-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=org_admin_role.id,
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
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)

    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add(org_admin_role)
    db_session.flush()

    _grant_permission(db_session, org_admin_role, "users", "read")
    _grant_permission(db_session, org_admin_role, "users", "delete")

    admin = User(
        username="lifecycle-admin",
        email="lifecycle-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    target = User(
        username="lifecycle-target",
        email="lifecycle-target@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=org_admin_role.id,
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
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    db_session.add(org)

    org_admin_role = Role(
        name="org_admin", description="Org admin", is_system_role=True
    )
    db_session.add(org_admin_role)
    db_session.flush()

    _grant_permission(db_session, org_admin_role, "users", "delete")

    admin = User(
        username="purge-admin",
        email="purge-admin@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    target = User(
        username="purge-target",
        email="purge-target@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=org_admin_role.id,
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
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    role = Role(name="org_admin", description="Org admin", is_system_role=True)
    db_session.add_all([org, role])
    db_session.flush()

    deleted_user = User(
        username="deleted-login-user",
        email="deleted-login-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=role.id,
        is_active=False,
        is_deleted=True,
        is_verified=True,
    )
    db_session.add(deleted_user)
    db_session.commit()

    response = client.post(
        "/auth/login",
        json={"email": "deleted-login-user@test.com", "password": "wrong-password"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Account deleted"
