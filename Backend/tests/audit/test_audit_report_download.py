"""
tests/audit/test_audit_report_download.py
─────────────────────────────────────────────────────────────────────────────
Regression cover for the defect this phase exists to fix.

``routers/reports.py`` recorded report downloads by constructing
``AuditLog(user_id=..., action="REPORT_DOWNLOAD", target=..., details=...)``
directly. ``AuditLog`` has no ``target`` or ``details`` column, ``org_id`` is
NOT NULL and part of its primary key, and — decisively — the name ``AuditLog``
was never imported into that module at all. Every call raised ``NameError``,
the bare ``except Exception: pass`` around it swallowed the error, and **no
report download in the history of this deployment produced an audit row**.

A report leaving the platform is exactly the kind of event an audit trail
exists to hold, so this asserts the row is really written, not merely that the
download succeeds.
"""

import os
import tempfile

from auth.jwt_handler import create_access_token
from db.models import (
    AuditLog,
    Organization,
    Permission,
    Role,
    RolePermission,
    Scan,
    User,
)
from routers.reports import _REPORTS_DIR


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


def _temp_report_path() -> str:
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(dir=_REPORTS_DIR, delete=False, suffix=".pdf")
    try:
        handle.write(b"%PDF-1.4\n%audit-download-test\n")
    finally:
        handle.close()
    return handle.name


def _downloadable_scan(db_session):
    org = Organization(
        name="Audit Download Org",
        slug="audit-download-org",
        max_assets=100,
        max_users=10,
        is_active=True,
    )
    role = Role(
        name="audit_download_reader",
        description="Can read reports",
        is_system_role=False,
    )
    db_session.add_all([org, role])
    db_session.flush()

    _grant_permission(db_session, role, "reports", "read")

    user = User(
        username="audit-download-user",
        email="audit-download-user@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.flush()

    scan = Scan(
        id="scn_audit_download_1",
        org_id=org.id,
        created_by=str(user.id),
        scan_no=77,
        target_str="10.9.9.0/24",
        target_hosts=[],
        scan_type="adaptive",
        pipeline_mode="basic",
        status="complete",
        report_executive_path=_temp_report_path(),
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(user)
    return org, user, scan


def test_report_download_writes_an_audit_row(client, db_session):
    """The core regression: a successful download must leave a trace."""
    org, user, scan = _downloadable_scan(db_session)

    try:
        response = client.get(
            f"/reports/download/{scan.id}", headers=_auth_headers(user)
        )
        assert response.status_code == 200, response.text

        rows = (
            db_session.query(AuditLog)
            .filter(AuditLog.action == "report.downloaded")
            .all()
        )
        assert len(rows) == 1, (
            "a report download must produce exactly one audit row; " f"got {len(rows)}"
        )

        row = rows[0]
        assert row.org_id == org.id
        assert row.user_id == user.id
        assert row.resource_type == "scan"
        assert row.resource_id == str(scan.id)
        assert row.status == "success"
        assert row.severity == "low"
        # The correlation id proves it went through log_audit_event with the
        # live request rather than being constructed by hand again.
        assert row.request_id
    finally:
        if scan.report_executive_path and os.path.exists(scan.report_executive_path):
            os.remove(scan.report_executive_path)


def test_download_audit_records_which_format_left_the_platform(client, db_session):
    """
    "A report was downloaded" is not enough for an investigation: the
    technical PDF carries far more detail than the executive one.
    """
    org, user, scan = _downloadable_scan(db_session)

    try:
        response = client.get(
            f"/reports/download/{scan.id}?fmt=executive", headers=_auth_headers(user)
        )
        assert response.status_code == 200, response.text

        row = (
            db_session.query(AuditLog)
            .filter(AuditLog.action == "report.downloaded")
            .one()
        )
        assert row.changes["format"] == "executive_pdf"
        assert row.changes["scan_no"] == 77
    finally:
        if scan.report_executive_path and os.path.exists(scan.report_executive_path):
            os.remove(scan.report_executive_path)


def test_failure_to_audit_does_not_deny_the_download(client, db_session, monkeypatch):
    """
    The guard around the audit write is deliberate: a caller entitled to the
    file still gets it if auditing fails. What must not happen — and what did
    happen before this fix — is the failure passing silently.
    """
    org, user, scan = _downloadable_scan(db_session)

    import routers.reports as reports_module

    def _explode(*args, **kwargs):
        raise RuntimeError("audit backend unavailable")

    monkeypatch.setattr(reports_module, "log_audit_event", _explode)

    warnings = []
    monkeypatch.setattr(
        reports_module.log, "warning", lambda *a, **k: warnings.append(a)
    )

    try:
        response = client.get(
            f"/reports/download/{scan.id}", headers=_auth_headers(user)
        )
        assert response.status_code == 200, response.text
        assert warnings, "a failed audit write must be logged, not swallowed"
    finally:
        if scan.report_executive_path and os.path.exists(scan.report_executive_path):
            os.remove(scan.report_executive_path)
