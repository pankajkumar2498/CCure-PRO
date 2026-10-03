import os
import tempfile

from auth.jwt_handler import create_access_token
from db.models import Organization, Permission, Role, RolePermission, Scan, User


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

    link = (
        db_session.query(RolePermission)
        .filter(
            RolePermission.role_id == role.id,
            RolePermission.permission_id == permission.id,
        )
        .first()
    )
    if link is None:
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


from routers.reports import _REPORTS_DIR


def _temp_report_path() -> str:
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(dir=_REPORTS_DIR, delete=False, suffix=".pdf")
    try:
        handle.write(b"%PDF-1.4\n%rbac-test\n")
    finally:
        handle.close()
    return handle.name


def test_report_download_requires_reports_read_permission(client, db_session):
    org = Organization(
        name="Reports Org",
        slug="reports-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    role = Role(
        name="limited_reports", description="No report read", is_system_role=False
    )
    db_session.add_all([org, role])
    db_session.flush()

    user = User(
        username="limited-report-user",
        email="limited-report-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.flush()

    scan = Scan(
        id="scn_reports_read_1",
        org_id=org.id,
        created_by=str(user.id),
        scan_no=1,
        target_str="10.1.1.0/24",
        target_hosts=[],
        scan_type="adaptive",
        pipeline_mode="basic",
        status="complete",
        report_executive_path=_temp_report_path(),
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(user)

    try:
        response = client.get(
            f"/reports/download/{scan.id}", headers=_auth_headers(user)
        )
        assert response.status_code == 403
        assert "audit.report.read" in response.json()["detail"]
    finally:
        if scan.report_executive_path and os.path.exists(scan.report_executive_path):
            os.remove(scan.report_executive_path)


def test_superadmin_can_download_report_across_orgs(client, db_session):
    org_a = Organization(
        name="SA Reports A",
        slug="sa-reports-a",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    org_b = Organization(
        name="SA Reports B",
        slug="sa-reports-b",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    superadmin_role = db_session.query(Role).filter_by(name="superadmin").first()
    analyst_role = Role(
        name="analyst_reports", description="Analyst", is_system_role=False
    )
    db_session.add_all([org_a, org_b, analyst_role])
    db_session.flush()

    _grant_permission(db_session, analyst_role, "reports", "read")

    superadmin = User(
        username="super-reports",
        email="super-reports@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
    )
    other_user = User(
        username="other-org-user",
        email="other-org-user@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role_id=analyst_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([superadmin, other_user])
    db_session.flush()

    report_path = _temp_report_path()
    scan = Scan(
        id="scn_reports_super_1",
        org_id=org_b.id,
        created_by=str(other_user.id),
        scan_no=9,
        target_str="10.9.9.0/24",
        target_hosts=[],
        scan_type="adaptive",
        pipeline_mode="basic",
        status="complete",
        report_executive_path=report_path,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(superadmin)

    try:
        response = client.get(
            f"/reports/download/{scan.id}", headers=_auth_headers(superadmin)
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/pdf")
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)


def test_report_delete_requires_reports_delete_permission(client, db_session):
    org = Organization(
        name="Reports Delete Org",
        slug="reports-delete-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    role = Role(
        name="report-reader-only", description="Read-only reports", is_system_role=False
    )
    db_session.add_all([org, role])
    db_session.flush()

    _grant_permission(db_session, role, "reports", "read")

    user = User(
        username="report-reader-only",
        email="report-reader-only@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.flush()

    report_path = _temp_report_path()
    scan = Scan(
        id="scn_reports_delete_1",
        org_id=org.id,
        created_by=str(user.id),
        scan_no=3,
        target_str="10.3.3.0/24",
        target_hosts=[],
        scan_type="adaptive",
        pipeline_mode="basic",
        status="complete",
        report_executive_path=report_path,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(user)

    try:
        response = client.delete(f"/reports/{scan.id}", headers=_auth_headers(user))
        assert response.status_code == 403
        assert "audit.report.delete" in response.json()["detail"]
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)
