"""
An unauthenticated rescan never retires what a credentialed audit found.

The vulnerability-audit pipeline filed every finding under network_service,
including the package, configuration and privilege findings its credentialed
enrichment adds. The sweep is family-scoped, so the next unauthenticated audit
of the host "covered" them and marked every one fixed: on 13 Oct 2026 scan #19
(unauthenticated, 10.180.6.45) retired all 2,281 findings of scan #17
(credentialed, same host) and #20 retired 1,360 of #18's — remediations nobody
made, written into the timeline the comparison and remediation verification
read. Absence is not a fix unless the scan looked.
"""

from __future__ import annotations

import uuid

import pytest
from core.config_audit.findings import config_definition_id
from db.models.findings import AssetVulnerability
from db.models.rbac import Organization
from db.models.scans import Scan

IP = "10.77.6.45"
CHECK = "ccure.linux.shadow.permissions"
CFG_ID = config_definition_id(CHECK, "config_check")

NET = {
    "cve_id": "CVE-2024-6387",
    "severity": "High",
    "cvss": 8.1,
    "cvss_score": 8.1,
    "port": 22,
    "detection_method": "version_match",
}
PKG = {
    "cve_id": "CVE-2024-3094",
    "severity": "Critical",
    "cvss": 10.0,
    "cvss_score": 10.0,
    "package": "xz-utils",
    "installed_version": "5.6.0-0.2",
    "detection_method": "credentialed_package",
    "finding_origin": "credentialed",
}
CFG = {
    "cve_id": CFG_ID,
    "severity": "High",
    "detection_method": "config_check",
    "finding_origin": "credentialed",
    "package": "",
}


def report(*, lookup_failures=(), passed=(CHECK,), packages=2):
    return {
        "package_count": packages,
        "inventory_complete": True,
        "package_coverage": {"lookup_failures": list(lookup_failures)},
        "config_audit": {
            "assessed": True,
            "results": [{"check_id": c, "outcome": "pass"} for c in passed],
        },
    }


@pytest.fixture()
def world(db_session, monkeypatch):
    from db.base import gen_asset_id
    from db.models import Asset
    from scans import asset_syncer

    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)
    org = Organization(
        id=f"org_cf_{uuid.uuid4().hex[:8]}",
        name="cred-family",
        slug=f"credfam{uuid.uuid4().hex[:6]}",
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

    def sync(cves, credentialed=None):
        scan_id = f"scn_cf_{uuid.uuid4().hex[:8]}"
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
            "cves": [dict(c) for c in cves],
            "suppressed_cves": [],
        }
        if credentialed is not None:
            host.update({"credentialed": True, "credentialed_report": credentialed})
        asset_syncer.sync_vulnerability_audit(db_session, scan_id, org.id, None, [host])
        db_session.commit()
        return scan_id

    def rows():
        db_session.expire_all()
        return {
            r.vuln_id: r
            for r in db_session.query(AssetVulnerability).filter(
                AssetVulnerability.org_id == org.id
            )
        }

    return sync, rows


def _status(rows):
    return {k: r.status for k, r in rows.items()}


def test_an_unauthenticated_rescan_leaves_credentialed_findings_open(world):
    sync, rows = world
    sync([NET, PKG, CFG], credentialed=report())
    sync([NET])  # the unauthenticated audit: no credentialed report at all
    assert _status(rows()) == {
        "CVE-2024-6387": "open",
        "CVE-2024-3094": "open",
        CFG_ID: "open",
    }
    sync([])  # and the network finding it no longer sees is still retired
    assert rows()["CVE-2024-6387"].status == "fixed"


def test_credentialed_findings_are_filed_under_their_own_family(world):
    sync, rows = world
    sync([NET, PKG, CFG], credentialed=report())
    stored = rows()
    assert stored["CVE-2024-6387"].source_family == "network_service"
    assert stored["CVE-2024-3094"].source_family == "credentialed_package"
    assert stored[CFG_ID].source_family == "credentialed_package"


def test_a_failed_feed_lookup_retires_no_package_finding(world):
    sync, rows = world
    sync([NET, PKG, CFG], credentialed=report())
    sync([NET, CFG], credentialed=report(lookup_failures=["Batch OSV query: lost"]))
    assert rows()["CVE-2024-3094"].status == "open"


def test_a_check_that_reached_no_verdict_is_not_fixed(world):
    sync, rows = world
    sync([NET, PKG, CFG], credentialed=report())
    sync([NET, PKG], credentialed=report(passed=()))
    assert rows()[CFG_ID].status == "open"


def test_a_complete_credentialed_rescan_retires_what_it_no_longer_sees(world):
    sync, rows = world
    sync([NET, PKG, CFG], credentialed=report())
    sync([NET], credentialed=report())
    assert _status(rows()) == {
        "CVE-2024-6387": "open",
        "CVE-2024-3094": "fixed",
        CFG_ID: "fixed",
    }


def test_rows_filed_as_network_before_the_fix_are_still_protected(world, db_session):
    sync, rows = world
    sync([NET, PKG, CFG], credentialed=report())
    # How a pipeline audit stored them before 14 Oct 2026.
    for row in rows().values():
        row.source_family = "network_service"
        row.proof = "Source_Family:network_service"
    db_session.commit()
    sync([NET])
    assert rows()["CVE-2024-3094"].status == "open"
    assert rows()[CFG_ID].status == "open"
