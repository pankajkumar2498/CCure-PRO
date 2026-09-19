"""
Phase 21 — web-finding remediation persistence.

Phase 20 found the detection engines produced remediation text but it was
dropped at persistence, so the API, UI and PDF report never showed it. This
proves the full path — engine finding -> resolve_remediation -> DB -> API
(_finding_detail) -> PDF — carries the same remediation text, and that a finding
type with no engine text falls back to the central default while an unmapped
type stays honestly empty.
"""

import pytest

from core.web.standards_mapping import remediation_for, resolve_remediation
from db.base import SessionLocal, utcnow
from db.models.web_scans import WebFinding, WebScan

_PREFIX = "wsc_rem_"


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


def _mk_scan(session, suffix):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=org.id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="remediation test",
        status="running",
        created_at=utcnow(),
        started_at=utcnow(),
    )
    session.add(scan)
    session.commit()
    return scan, org.id


# ── resolve_remediation precedence ───────────────────────────────────────────
def test_engine_remediation_wins():
    f = {"finding_type": "sqli", "remediation": "custom engine guidance"}
    assert resolve_remediation(f) == "custom engine guidance"


def test_central_default_fills_when_engine_silent():
    # nuclei/misconfig/header findings carry no engine remediation
    for ft in ("sqli", "xss", "insecure_cookie", "tls_issue", "misconfig", "idor"):
        f = {"finding_type": ft}
        assert resolve_remediation(f), f"no default remediation for {ft}"
        assert resolve_remediation(f) == remediation_for(ft)


def test_unmapped_type_stays_empty():
    assert resolve_remediation({"finding_type": "totally_unknown_type_xyz"}) is None
    # blank engine text does not count as supplied
    assert (
        resolve_remediation(
            {"finding_type": "totally_unknown_type_xyz", "remediation": "  "}
        )
        is None
    )


# ── full path: engine finding -> DB -> API -> PDF ────────────────────────────
def test_remediation_persists_and_flows_to_api_and_pdf(session):
    from core.web.tasks import _persist_web_findings
    from routers.web_scans import _finding_detail

    scan, org_id = _mk_scan(session, "path")
    findings = [
        {
            "finding_type": "sqli",
            "title": "SQL Injection detected",
            "severity": "critical",
            "matched_at": "http://target.invalid/item?id=1",
            "detected_by": "sqlmap",
            "payload_used": "id=1 AND 1=1",
            "remediation": "Use parameterised queries (engine text).",
        },
        {
            # no engine remediation -> central default must fill it
            "finding_type": "misconfig",
            "title": "Missing Content-Security-Policy Header",
            "severity": "medium",
            "matched_at": "http://target.invalid/",
            "detected_by": "custom",
        },
    ]
    _persist_web_findings(session, scan.id, org_id, findings)
    session.commit()

    rows = session.query(WebFinding).filter(WebFinding.web_scan_id == scan.id).all()
    by_type = {r.finding_type: r for r in rows}
    # 1. DB persisted, engine text preserved
    assert by_type["sqli"].remediation == "Use parameterised queries (engine text)."
    # 1b. central default filled the silent one
    assert by_type["misconfig"].remediation
    assert by_type["misconfig"].remediation == remediation_for("misconfig")

    # 2. API detail exposes it
    detail = _finding_detail(by_type["sqli"])
    assert detail["remediation"] == "Use parameterised queries (engine text)."

    # 3. PDF renders it. The content stream is normally compressed, so disable
    # ReportLab page compression for this assertion and grep the rendered bytes.
    import os

    import reportlab.rl_config as rlc
    from reporting.web_pdf_generator import WebScanReportGenerator

    scan_dict = {
        "id": scan.id,
        "scan_name": scan.scan_name,
        "target_url": scan.target_url,
        "status": "complete",
    }
    fl = [_finding_detail(r) for r in rows]
    prev = rlc.pageCompression
    rlc.pageCompression = 0
    try:
        pdf_path = WebScanReportGenerator().generate(scan_dict, fl, [])
    finally:
        rlc.pageCompression = prev

    assert os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0
    blob = open(pdf_path, "rb").read()
    # The "Remediation:" label is only emitted when a finding carries
    # remediation, so its presence proves the remediation block rendered. (Body
    # text cannot be grepped reliably — ReportLab splits it per glyph for
    # kerning — so the DB/API assertions above cover the exact text content.)
    assert b"Remediation" in blob
    os.remove(pdf_path)


def test_existing_findings_without_remediation_remain_valid(session):
    # A row written before the column existed (NULL remediation) still reads.
    scan, org_id = _mk_scan(session, "legacy")
    row = WebFinding(
        id=f"{_PREFIX}legacy_f1",
        web_scan_id=scan.id,
        org_id=org_id,
        finding_type="cve",
        title="legacy finding",
        severity="high",
        status="open",
        remediation=None,
    )
    session.add(row)
    session.commit()
    from routers.web_scans import _finding_detail

    d = _finding_detail(row)
    assert d["remediation"] is None  # honest absence, no crash
