"""
Phase 23c — first-class site-map entities (Codex item 1): WebForm + WebApiOperation.

Forms and API operations were only WebAssets with a flag and JSONB. This proves
they now persist as first-class, queryable rows: forms with their inputs and
file-upload/password flags, and REST/GraphQL/SOAP operations classified and
inventoried — both idempotent, both attached to the scan and org.
"""

import pytest

from core.web.tasks import (
    _api_operation_of,
    _persist_web_api_operations,
    _persist_web_forms,
)
from db.base import SessionLocal, utcnow
from db.models.web_scans import WebApiOperation, WebForm, WebScan

_PREFIX = "wsc_sm_"


@pytest.fixture
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        for m in (WebForm, WebApiOperation):
            db.query(m).filter(m.web_scan_id.like(f"{_PREFIX}%")).delete(
                synchronize_session=False
            )
        db.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


def _mk_scan(session, suffix):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=org.id,
        target_url="http://t.invalid/",
        target_domain="t.invalid",
        authorization_confirmed=True,
        status="running",
        created_at=utcnow(),
        started_at=utcnow(),
    )
    session.add(scan)
    session.commit()
    return scan, org.id


# ── classification ─────────────────────────────────────────────────────────────
def test_classify_rest_graphql_soap_and_non_api():
    assert (
        _api_operation_of(
            {
                "url": "http://a/svc",
                "source": "wsdl",
                "parameters": {"soap": ["GetUser"]},
            }
        )["kind"]
        == "soap"
    )
    gql = _api_operation_of(
        {
            "url": "http://a/graphql",
            "request_body": '{"query":"{me}"}',
            "method": "POST",
        }
    )
    assert gql["kind"] == "graphql"
    assert (
        _api_operation_of({"url": "http://a/api/x", "is_api": True})["kind"] == "rest"
    )
    assert _api_operation_of({"url": "http://a/index.html"}) is None


# ── WebForm ─────────────────────────────────────────────────────────────────────
def test_forms_persist_with_inputs_and_flags(session):
    scan, org_id = _mk_scan(session, "forms")
    forms = [
        {
            "url": "http://t.invalid/login",
            "method": "POST",
            "inputs": [
                {"name": "user", "type": "text"},
                {"name": "pw", "type": "password"},
            ],
            "has_password": True,
            "has_file_upload": False,
            "page_url": "http://t.invalid/",
            "source": "crawler",
        },
        {
            "url": "http://t.invalid/upload",
            "method": "POST",
            "inputs": [{"name": "file", "type": "file"}],
            "has_file_upload": True,
        },
    ]
    _persist_web_forms(session, scan.id, org_id, forms)
    session.commit()
    rows = session.query(WebForm).filter(WebForm.web_scan_id == scan.id).all()
    assert len(rows) == 2
    login = next(r for r in rows if r.action_url.endswith("/login"))
    assert login.has_password and login.input_count == 2
    upload = next(r for r in rows if r.action_url.endswith("/upload"))
    assert upload.has_file_upload
    # idempotent
    _persist_web_forms(session, scan.id, org_id, forms)
    session.commit()
    assert session.query(WebForm).filter(WebForm.web_scan_id == scan.id).count() == 2


# ── WebApiOperation ─────────────────────────────────────────────────────────────
def test_api_operations_persist_and_classify(session):
    scan, org_id = _mk_scan(session, "ops")
    endpoints = [
        {
            "url": "http://t.invalid/svc",
            "source": "wsdl",
            "parameters": {"soap": ["GetUser"]},
        },
        {"url": "http://t.invalid/api/users/1", "is_api": True, "method": "GET"},
        {
            "url": "http://t.invalid/graphql",
            "request_body": '{"query":"{me}"}',
            "method": "POST",
        },
        {"url": "http://t.invalid/about.html"},  # not an API op
    ]
    _persist_web_api_operations(session, scan.id, org_id, endpoints)
    session.commit()
    rows = (
        session.query(WebApiOperation)
        .filter(WebApiOperation.web_scan_id == scan.id)
        .all()
    )
    kinds = {r.kind for r in rows}
    assert kinds == {"soap", "rest", "graphql"}  # the html page is excluded
    soap = next(r for r in rows if r.kind == "soap")
    assert soap.operation_name == "GetUser" and soap.spec_source == "wsdl"
    # idempotent
    _persist_web_api_operations(session, scan.id, org_id, endpoints)
    session.commit()
    assert (
        session.query(WebApiOperation)
        .filter(WebApiOperation.web_scan_id == scan.id)
        .count()
        == 3
    )
