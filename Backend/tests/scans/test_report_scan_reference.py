"""
Every report names the scan it came from.

A Basic Network Scan's PDFs (scan #1, 13 Oct 2026) printed "Scan reference:
Not recorded": the host-discovery path built the report context without the
scan id, so neither the number nor the id reached the report. Asset Discovery
and Vulnerability Audit printed "#3" / "#6" with no id — a row counter that
two organisations can share.
"""

from __future__ import annotations

import uuid

from db.base import gen_user_id
from db.models.rbac import Organization
from db.models.scans import Scan
from reporting.pdf_generator import _scan_reference_text
from scan_helpers import resolve_report_context
from native_rbac import create_user


def test_the_report_context_carries_both_halves_of_the_reference(db_session):
    org = Organization(
        id=f"org_{uuid.uuid4().hex[:8]}",
        name="Reference",
        slug=f"reference-{uuid.uuid4().hex[:8]}",
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.flush()
    user = create_user(
        db_session,
        id=gen_user_id(org.slug, "reporter"),
        username=f"reporter{uuid.uuid4().hex[:6]}",
        email=f"reporter-{uuid.uuid4().hex[:6]}@test.com",
        full_name="Reporter",
        password_hash="x",
        org_id=org.id,
    )
    scan = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=org.id,
        created_by=user.id,
        scan_no=1,
        target_str="10.180.6.30",
        target_hosts=["10.180.6.30"],
        pipeline_mode="basic",
        status="complete",
    )
    db_session.add(scan)
    db_session.commit()

    context = resolve_report_context(db_session, user.id, scan_id=scan.id, hosts=[])

    assert context["scan_id"] == scan.id
    assert context["scan_no"] == scan.scan_no
    assert _scan_reference_text(context) == f"#1 · {scan.id}"


def test_the_report_context_states_the_feed_date(db_session, monkeypatch):
    """A report written at scan completion printed "Vulnerability feed: Not recorded"."""
    import core.vuln_intel as vuln_intel

    monkeypatch.setattr(
        vuln_intel,
        "get_feed_freshness",
        lambda: {"last_modified": "2026-10-13T02:30:00+00:00", "cve_count": 370000},
    )
    context = resolve_report_context(db_session, "nobody", hosts=[])
    assert context["cve_feed_updated"] == "2026-10-13T02:30:00+00:00"
    assert context["cve_feed_size"] == 370000
