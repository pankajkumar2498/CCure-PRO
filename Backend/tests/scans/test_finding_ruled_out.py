"""
A finding a later scan rules out is "ruled out", never "fixed".

An unauthenticated scan of 10.180.6.30 raised 49 PostgreSQL CVEs against
nmap's "PostgreSQL 9.6.0 or later". The credentialed scan that followed read
the real version, 18.3, re-verified those candidates and ruled 41 of them out
("version outside range"). The sync's sweep then marked all 41 *fixed*, with a
fixed_at — a remediation nobody made — and the comparison would have handed
them to remediation verification as fixes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from core.findings.comparison import (
    CLASS_FIXED,
    CLASS_RULED_OUT,
    AssessmentScope,
    _classify,
)
from db.models.findings import AssetVulnerability
from db.models.rbac import Organization
from db.models.scans import Scan

IP = "10.77.6.30"


@pytest.fixture()
def world(db_session, monkeypatch):
    from db.base import gen_asset_id
    from db.models import Asset
    from scans import asset_syncer

    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)
    org = Organization(
        id=f"org_ro_{uuid.uuid4().hex[:8]}",
        name="ruled-out",
        slug=f"ruledout{uuid.uuid4().hex[:6]}",
    )
    db_session.add(org)
    db_session.flush()
    db_session.add(
        Asset(
            id=gen_asset_id(org.slug, IP),
            org_id=org.id,
            ip_address=IP,
            custom_attributes={},
        )
    )
    db_session.commit()

    def sync(cves, suppressed=()):
        scan_id = f"scn_ro_{uuid.uuid4().hex[:8]}"
        db_session.add(
            Scan(
                id=scan_id,
                org_id=org.id,
                target_str=IP,
                pipeline_mode="vulnerability_audit",
                status="complete",
            )
        )
        db_session.commit()
        host = {
            "ip_address": IP,
            "is_active": True,
            "cves": list(cves),
            "suppressed_cves": list(suppressed),
        }
        asset_syncer.sync_vulnerability_audit(db_session, scan_id, org.id, None, [host])
        db_session.commit()

    def status():
        db_session.expire_all()
        return {
            r.vuln_id: r.status
            for r in db_session.query(AssetVulnerability).filter(
                AssetVulnerability.org_id == org.id
            )
        }

    return sync, status


def _pg(cve):
    return {
        "cve_id": cve,
        "severity": "High",
        "cvss": 8.8,
        "cvss_score": 8.8,
        "port": 5432,
    }


RULED_OUT = (
    "Ruled out: the version detected on this host (18.3) falls outside the "
    "vulnerable range published for this record."
)


def test_a_finding_this_scan_ruled_out_is_not_recorded_as_fixed(world):
    sync, status = world
    sync([_pg("CVE-2019-9193"), _pg("CVE-2017-7546")])
    sync(
        [],
        suppressed=[
            {"identifier": "CVE-2019-9193", "host": IP, "reason": RULED_OUT},
            {
                "identifier": "CVE-2017-7546",
                "host": IP,
                "reason": "Below the reporting confidence threshold",
            },
        ],
    )
    assert status() == {"CVE-2019-9193": "ruled_out", "CVE-2017-7546": "fixed"}


def test_a_ruled_out_finding_that_returns_reopens(world):
    sync, status = world
    sync([_pg("CVE-2019-9193")])
    sync(
        [],
        suppressed=[{"identifier": "CVE-2019-9193", "host": IP, "reason": RULED_OUT}],
    )
    sync([_pg("CVE-2019-9193")])
    assert status() == {"CVE-2019-9193": "open"}


def _row(status, fixed_at):
    t0 = datetime(2026, 10, 13, 5, 0, tzinfo=timezone.utc)
    return (
        AssetVulnerability(
            id="fnd_x",
            asset_id="ast_x",
            vuln_id="CVE-2019-9193",
            source_family="network_service",
            status=status,
            first_found_at=t0,
            last_found_at=t0,
            fixed_at=fixed_at,
        ),
        t0,
    )


def test_the_comparison_reports_ruled_out_not_fixed():
    scope = AssessmentScope(
        recorded=True, assets=("ast_x",), families=("network_service",)
    )
    row, t0 = _row("ruled_out", datetime(2026, 10, 13, 6, 8, tzinfo=timezone.utc))
    kwargs = dict(
        baseline_start=t0 - timedelta(minutes=3),
        baseline_end=t0 + timedelta(minutes=2),
        current_start=t0 + timedelta(minutes=30),
        current_scope=scope,
    )
    assert _classify(row, **kwargs) == CLASS_RULED_OUT
    row.status = "fixed"
    assert _classify(row, **kwargs) == CLASS_FIXED


def test_remediation_figures_leave_ruled_out_findings_out():
    from core.remediation.states import is_remediation_work
    from sqlalchemy.dialects import postgresql

    sql = str(
        is_remediation_work(AssetVulnerability.status).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert "ruled_out" in sql and "IS NULL" in sql
