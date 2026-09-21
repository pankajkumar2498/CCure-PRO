"""
Web finding persistence — CWE round-trip.

`web_findings` has carried a `cwe_id` column since the table was created
(migration g8h9i0j1k2l3), but the WebFinding model never mapped it, so no web
finding could record a weakness class and passing `cwe_id=` to the model raised
TypeError inside the findings sync — which failed the whole DETECT phase the
first time the active XSS engine tried to write CWE-79. This pins the mapping
and that `_persist_web_findings` writes it through.

Uses a real session and cleans up, per the finding-comparison tests' rule about
committed fixture rows surviving the per-test rollback.
"""

import pytest

from core.web.tasks import _persist_web_findings
from db.base import SessionLocal, utcnow
from db.models.web_scans import WebFinding, WebScan

_PREFIX = "wsc_cwetest_"


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


def _org_id(session):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    assert org is not None
    return org.id


def test_web_finding_persists_cwe(session):
    org_id = _org_id(session)
    scan = WebScan(
        id=f"{_PREFIX}1",
        org_id=org_id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="cwe test",
        status="complete",
        created_at=utcnow(),
    )
    session.add(scan)
    session.commit()

    findings = [
        {
            "finding_type": "xss",
            "title": "REFLECTED Cross-Site Scripting (XSS) in 'q'",
            "description": "proven execution",
            "severity": "high",
            "detected_by": "ccure-xss",
            "cwe_id": "CWE-79",
            "matched_at": "http://target.invalid/?q=x",
            "request_url": "http://target.invalid/?q=x",
            "request_method": "GET",
            "payload_used": "<img src=x onerror=...>",
            "is_verified": True,
        }
    ]
    _persist_web_findings(session, scan.id, org_id, findings)
    session.commit()

    row = session.query(WebFinding).filter(WebFinding.web_scan_id == scan.id).first()
    assert row is not None
    assert row.cwe_id == "CWE-79"
    assert row.finding_type == "xss"
    # OWASP mapping is filled centrally from finding_type.
    assert "A03" in (row.owasp_category or "")
