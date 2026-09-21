"""
Phase 22 — proof-based finding evidence (Codex P1 item 10).

Phase 20/21 audit: the full HTTP request/response is persisted on a web finding
but the API detail dropped everything except payload_used, and the PDF showed
only excerpts — a reader could not answer "which exact request caused this?".
These tests prove the request/response evidence and a reproduce-curl now flow
DB -> API (_finding_detail) -> PDF.
"""

import pytest

from db.base import SessionLocal, utcnow
from db.models.web_scans import WebFinding, WebScan

_PREFIX = "wsc_proof_"


@pytest.fixture
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.query(WebFinding).filter(WebFinding.web_scan_id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


def _mk(session, suffix):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=org.id,
        target_url="http://t/",
        target_domain="t",
        authorization_confirmed=True,
        scan_name="proof",
        status="complete",
        created_at=utcnow(),
        started_at=utcnow(),
    )
    session.add(scan)
    session.commit()
    return scan, org.id


def _finding(scan, org_id):
    return WebFinding(
        id=f"{_PREFIX}f1",
        web_scan_id=scan.id,
        org_id=org_id,
        finding_type="sqli",
        title="SQL Injection",
        severity="critical",
        status="open",
        detected_by="sqlmap",
        matched_at="http://t/api/search",
        request_method="POST",
        request_url="http://t/api/search",
        request_headers="Content-Type: application/json",
        request_body='{"q": "1 AND 1=1"}',
        response_code=200,
        response_headers="Content-Type: application/json",
        response_body='{"rows": [[1,"a"],[2,"b"]]}',
        payload_used='{"q": "1 AND 1=1"}',
    )


def test_finding_detail_exposes_full_evidence_and_curl(session):
    from routers.web_scans import _finding_detail

    scan, org_id = _mk(session, "api")
    row = _finding(scan, org_id)
    session.add(row)
    session.commit()

    d = _finding_detail(row)
    assert d["request_headers"] == "Content-Type: application/json"
    assert d["request_body"] == '{"q": "1 AND 1=1"}'
    assert d["response_headers"] == "Content-Type: application/json"
    assert '"rows"' in d["response_body"]
    # curl reproduction carries method, header, body and url
    curl = d["curl_command"]
    assert curl.startswith("curl -i -X POST")
    assert "http://t/api/search" in curl
    assert "1 AND 1=1" in curl


def test_curl_is_none_without_request_url(session):
    from routers.web_scans import _finding_detail

    scan, org_id = _mk(session, "nocurl")
    row = WebFinding(
        id=f"{_PREFIX}f2",
        web_scan_id=scan.id,
        org_id=org_id,
        finding_type="misconfig",
        title="no request",
        severity="low",
        status="open",
    )
    session.add(row)
    session.commit()
    assert _finding_detail(row)["curl_command"] is None


def test_pdf_renders_request_response_and_curl(session):
    import os

    import reportlab.rl_config as rlc
    from reporting.web_pdf_generator import WebScanReportGenerator
    from routers.web_scans import _finding_detail

    scan, org_id = _mk(session, "pdf")
    row = _finding(scan, org_id)
    session.add(row)
    session.commit()

    scan_dict = {
        "id": scan.id,
        "scan_name": "proof",
        "target_url": "http://t/",
        "status": "complete",
    }
    fl = [_finding_detail(row)]
    prev = rlc.pageCompression
    rlc.pageCompression = 0
    try:
        pdf = WebScanReportGenerator().generate(scan_dict, fl, [])
    finally:
        rlc.pageCompression = prev
    blob = open(pdf, "rb").read()
    # section labels only emitted when the evidence is present
    assert b"Response Evidence" in blob
    assert b"Reproduce" in blob  # the curl label
    os.remove(pdf)
