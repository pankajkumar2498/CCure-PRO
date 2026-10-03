from native_rbac import system_role, create_user, fixture_role, grant_permissions

import os
import tempfile

from auth.jwt_handler import create_access_token
from db.models import Organization, Scan, User


def _auth_headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
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
    role = fixture_role(db_session, "limited_reports")
    db_session.add_all([org, role])
    db_session.flush()

    user = create_user(
        db_session,
        username="limited-report-user",
        email="limited-report-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role=role,
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
    superadmin_role = system_role(db_session, "platform.superadmin")
    analyst_role = fixture_role(db_session, "analyst_reports")
    db_session.add_all([org_a, org_b, analyst_role])
    db_session.flush()

    grant_permissions(db_session, analyst_role, "audit.report.read")

    superadmin = create_user(
        db_session,
        username="super-reports",
        email="super-reports@test.com",
        password_hash="hash",
        org_id=org_a.id,
        role=superadmin_role,
        is_active=True,
        is_verified=True,
    )
    other_user = create_user(
        db_session,
        username="other-org-user",
        email="other-org-user@test.com",
        password_hash="hash",
        org_id=org_b.id,
        role=analyst_role,
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
    role = fixture_role(db_session, "report-reader-only")
    db_session.add_all([org, role])
    db_session.flush()

    grant_permissions(db_session, role, "audit.report.read")

    user = create_user(
        db_session,
        username="report-reader-only",
        email="report-reader-only@test.com",
        password_hash="hash",
        org_id=org.id,
        role=role,
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
