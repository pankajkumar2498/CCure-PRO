"""
Web-scan authorisation and audit trail — Phase 1, findings F2 and F5.

F2: every `/web-scans` route depended on `get_current_user` alone, so any
authenticated account — a `viewer` included — could launch sqlmap, ffuf and
nuclei at a URL of its choosing, cancel another user's scan, or accept the risk
on a finding. The network-scan routes have always required `scans:execute`.

F5: nothing on the web-scan path wrote to the tamper-evident audit log, so the
launch of active attack traffic, its cancellation and every triage decision
left no trace.

The handlers are called directly rather than through TestClient with a login:
logging in commits, and in this suite that commits every pending fixture row
with it (CLAUDE.md, "Scan comparison and finding lifecycle").
"""

import inspect
import json
import uuid

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from starlette.requests import Request

from auth.rbac import require_permission, user_has_permission
from db.base import gen_user_id, utcnow
from db.models import Permission, Role, RolePermission, User
from db.models.users import AuditLog
from db.models.web_scans import WebFinding, WebScan
from routers import web_scans as web_scans_router
from routers.web_scans import (
    _TRIAGE_AUDIT_ACTIONS,
    StartWebScanRequest,
    TriageFindingRequest,
    cancel_web_scan,
    start_web_scan,
    triage_finding,
)

_PREFIX = "wsc_authz_"

#: (method, path) → the permission atom that route must require.
EXPECTED_ROUTE_PERMISSIONS = {
    ("POST", "/web-scans"): ("scans", "execute"),
    ("GET", "/web-scans"): ("scans", "read"),
    ("GET", "/web-scans/{scan_id}"): ("scans", "read"),
    ("GET", "/web-scans/{scan_id}/findings"): ("findings", "read"),
    ("GET", "/web-scans/{scan_id}/assets"): ("scans", "read"),
    ("GET", "/web-scans/{scan_id}/parameters"): ("scans", "read"),
    ("GET", "/web-scans/{scan_id}/forms"): ("scans", "read"),
    ("GET", "/web-scans/{scan_id}/api-operations"): ("scans", "read"),
    ("POST", "/web-scans/{scan_id}/cancel"): ("scans", "execute"),
    ("PATCH", "/web-scans/{scan_id}/findings/{finding_id}"): ("findings", "update"),
    ("GET", "/web-scans/{scan_id}/findings/{finding_id}/screenshot"): (
        "findings",
        "read",
    ),
    ("GET", "/web-scans/{scan_id}/report"): ("scans", "read"),
}


# ── helpers ──────────────────────────────────────────────────────────────────


def _permission_guards(route: APIRoute) -> set[tuple[str, str]]:
    """Every (resource, action) a route's dependency tree enforces."""
    found = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        call = dep.call
        if getattr(call, "__qualname__", "").startswith("require_permission."):
            nonlocals = inspect.getclosurevars(call).nonlocals
            found.add((nonlocals["resource"], nonlocals["action"]))
        stack.extend(dep.dependencies)
    return found


def _request(method: str = "POST") -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/web-scans",
            "headers": [(b"user-agent", b"pytest-authz")],
            "client": ("127.0.0.1", 50000),
            "query_string": b"",
        }
    )


def _user_with_role(db, org, role: Role, label: str) -> User:
    uid = uuid.uuid4().hex[:8]
    user = User(
        id=gen_user_id(org.slug, f"{label}{uid}"),
        username=f"{label}{uid}",
        email=f"{label}{uid}@test.com",
        full_name=label,
        password_hash="x",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _role(db, name: str) -> Role:
    role = db.query(Role).filter(Role.name == name).first()
    assert role is not None, f"seeded role {name!r} missing from the test database"
    return role


def _custom_role(db, atoms: list[tuple[str, str]]) -> Role:
    """A role holding exactly `atoms` — the seeded roles cannot express
    'may update findings but may not accept risk'."""
    role = Role(name=f"authz_{uuid.uuid4().hex[:10]}", is_system_role=False)
    db.add(role)
    db.flush()
    for resource, action in atoms:
        perm = (
            db.query(Permission)
            .filter(Permission.resource == resource, Permission.action == action)
            .first()
        )
        assert perm is not None, f"permission {resource}:{action} not seeded"
        db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.commit()
    db.refresh(role)
    return role


def _web_scan(db, org_id: str, status: str = "running") -> WebScan:
    scan = WebScan(
        id=f"{_PREFIX}{uuid.uuid4().hex[:12]}",
        org_id=org_id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="authz test",
        status=status,
        created_at=utcnow(),
        started_at=utcnow(),
    )
    db.add(scan)
    db.commit()
    return scan


def _web_finding(db, scan: WebScan) -> WebFinding:
    finding = WebFinding(
        id=f"{scan.id}_f1",
        web_scan_id=scan.id,
        org_id=scan.org_id,
        finding_type="xss",
        title="Reflected XSS",
        severity="high",
        status="open",
    )
    db.add(finding)
    db.commit()
    return finding


def _audit_rows(db, resource_id: str) -> list[AuditLog]:
    db.expire_all()
    return (
        db.query(AuditLog)
        .filter(AuditLog.resource_id == resource_id)
        .order_by(AuditLog.id)
        .all()
    )


@pytest.fixture
def cleanup_web_rows(db_session):
    yield
    db_session.rollback()
    db_session.query(WebFinding).filter(
        WebFinding.web_scan_id.like(f"{_PREFIX}%")
    ).delete(synchronize_session=False)
    db_session.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
        synchronize_session=False
    )
    db_session.commit()


# ── F2: every route requires its permission ─────────────────────────────────


def test_every_web_scan_route_requires_its_permission_atom():
    routes = {}
    for route in web_scans_router.router.routes:
        if not isinstance(route, APIRoute):
            continue  # the progress WebSocket authenticates by ticket
        for method in route.methods:
            routes[(method, route.path)] = route

    assert set(routes) == set(EXPECTED_ROUTE_PERMISSIONS), (
        "the web-scan route set changed; classify the new route here: "
        f"{sorted(set(routes) ^ set(EXPECTED_ROUTE_PERMISSIONS))}"
    )
    for key, atom in EXPECTED_ROUTE_PERMISSIONS.items():
        guards = _permission_guards(routes[key])
        assert atom in guards, f"{key} requires {guards or 'no permission'}, not {atom}"


def test_viewer_cannot_launch_or_cancel_a_web_scan(db_session, test_org):
    viewer = _user_with_role(
        db_session, test_org, _role(db_session, "viewer"), "viewer"
    )
    guard = require_permission("scans", "execute")
    with pytest.raises(HTTPException) as exc:
        guard(user=viewer, db=db_session)
    assert exc.value.status_code == 403


def test_analyst_can_launch_a_web_scan(db_session, test_org):
    analyst = _user_with_role(
        db_session, test_org, _role(db_session, "analyst"), "analyst"
    )
    guard = require_permission("scans", "execute")
    assert guard(user=analyst, db=db_session) is analyst


def test_user_has_permission_edges(db_session, test_org):
    superadmin = _user_with_role(
        db_session, test_org, _role(db_session, "superadmin"), "super"
    )
    assert user_has_permission(db_session, superadmin, "anything", "at_all") is True

    roleless = User(id="roleless", org_id=test_org.id)
    assert user_has_permission(db_session, roleless, "scans", "read") is False

    viewer = _user_with_role(db_session, test_org, _role(db_session, "viewer"), "vw")
    assert user_has_permission(db_session, viewer, "scans", "read") is True
    assert user_has_permission(db_session, viewer, "scans", "execute") is False


# ── accept-risk split and triage audit (F2 + F5) ────────────────────────────


def test_accepting_risk_on_a_web_finding_needs_accept_risk(
    db_session, test_org, cleanup_web_rows
):
    role = _custom_role(db_session, [("findings", "update"), ("findings", "read")])
    triager = _user_with_role(db_session, test_org, role, "triager")
    scan = _web_scan(db_session, test_org.id)
    finding = _web_finding(db_session, scan)

    with pytest.raises(HTTPException) as exc:
        triage_finding(
            scan_id=scan.id,
            finding_id=finding.id,
            body=TriageFindingRequest(status="accepted_risk", reason="compensated"),
            request=_request("PATCH"),
            org_id=None,
            db=db_session,
            user=triager,
        )
    assert exc.value.status_code == 403
    assert "findings:accept_risk" in exc.value.detail

    db_session.expire_all()
    assert db_session.get(WebFinding, finding.id).status == "open"
    assert _audit_rows(db_session, finding.id) == []


def test_every_triage_status_has_an_audit_action():
    valid = {
        "open",
        "confirmed",
        "false_positive",
        "accepted_risk",
        "fixed",
        "reopened",
    }
    assert set(_TRIAGE_AUDIT_ACTIONS) == valid


def test_triage_writes_an_audit_event(db_session, test_org, cleanup_web_rows):
    analyst = _user_with_role(db_session, test_org, _role(db_session, "analyst"), "tri")
    scan = _web_scan(db_session, test_org.id)
    finding = _web_finding(db_session, scan)

    result = triage_finding(
        scan_id=scan.id,
        finding_id=finding.id,
        body=TriageFindingRequest(status="accepted_risk", reason="WAF rule 9412"),
        request=_request("PATCH"),
        org_id=None,
        db=db_session,
        user=analyst,
    )
    assert result["status"] == "accepted_risk"

    rows = _audit_rows(db_session, finding.id)
    assert [r.action for r in rows] == ["web_finding.accepted_risk"]
    row = rows[0]
    assert row.user_id == analyst.id
    assert row.org_id == test_org.id
    assert row.severity == "high"
    assert row.changes["status"] == {"from": "open", "to": "accepted_risk"}
    assert row.changes["reason"] == "WAF rule 9412"


# ── F5: cancel and launch are audited ────────────────────────────────────────


def test_cancel_writes_an_audit_event(db_session, test_org, cleanup_web_rows):
    analyst = _user_with_role(db_session, test_org, _role(db_session, "analyst"), "can")
    scan = _web_scan(db_session, test_org.id, status="running")

    cancel_web_scan(
        scan_id=scan.id,
        request=_request(),
        org_id=None,
        db=db_session,
        user=analyst,
    )

    rows = _audit_rows(db_session, scan.id)
    assert [r.action for r in rows] == ["web_scan.cancelled"]
    assert rows[0].changes["status"] == {"from": "running", "to": "cancelled"}


def test_launch_is_audited_without_leaking_auth_secrets(
    db_session, test_org, cleanup_web_rows, monkeypatch
):
    analyst = _user_with_role(db_session, test_org, _role(db_session, "analyst"), "lau")

    class _Task:
        id = "task-authz-test"

    import core.web.tasks as web_tasks

    monkeypatch.setattr(web_tasks.run_web_recon_task, "delay", lambda **kw: _Task())
    # Scan ids come from gen_web_scan_id; pin the prefix so cleanup finds it.
    monkeypatch.setattr(
        web_scans_router,
        "gen_web_scan_id",
        lambda *a, **k: f"{_PREFIX}{uuid.uuid4().hex[:12]}",
    )

    secret = "S3cret-" + uuid.uuid4().hex
    body = StartWebScanRequest(
        target_url="https://app.target.invalid/login",
        scan_name="audit launch",
        authorization_confirmed=True,
        auth={
            "type": "form_login",
            "login_url": "https://app.target.invalid/login",
            "username": "scanner",
            "password": secret,
        },
    )
    response = start_web_scan(
        request=_request(),
        response=None,
        body=body,
        idempotency_key=None,
        org_id=None,
        db=db_session,
        user=analyst,
    )
    scan_id = response["web_scan_id"]

    rows = _audit_rows(db_session, scan_id)
    assert [r.action for r in rows] == ["web_scan.created"]
    row = rows[0]
    assert row.severity == "medium"
    assert row.changes["authorization_confirmed"] is True
    assert row.changes["target_url"] == "https://app.target.invalid/login"
    assert row.changes["auth_type"] == "form_login"
    assert secret not in json.dumps(row.changes, default=str)
