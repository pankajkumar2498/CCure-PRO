"""
What the finding sync stores must agree with what the reports say.

Two disagreements found on 13 Oct 2026, scans of 10.180.6.30:

* Severity. Network and configuration checks carry a declared severity and no
  CVSS score. The sync derived severity from the score alone, so three checks
  the report counted as Medium and Low were stored "unscored": the findings
  page read 48/7/3-unscored where every report of the scan read 49/9.
* Identity. A finding was keyed by (asset, CVE, family), so one CVE affecting
  six installed Siemens products — reported as six findings — was stored as
  one row naming whichever product was written last.
"""

from __future__ import annotations

import uuid

import pytest
from db.models.findings import AssetVulnerability
from db.models.rbac import Organization
from db.models.scans import Scan

IP = "10.77.8.30"


@pytest.fixture()
def world(db_session, monkeypatch):
    from db.base import gen_asset_id
    from db.models import Asset
    from scans import asset_syncer

    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)
    org = Organization(
        id=f"org_id_{uuid.uuid4().hex[:8]}",
        name="identity",
        slug=f"identity{uuid.uuid4().hex[:6]}",
    )
    db_session.add(org)
    db_session.flush()
    asset = Asset(
        id=gen_asset_id(org.slug, IP),
        org_id=org.id,
        ip_address=IP,
        hostname="PANKAJM-HPNEW",
        custom_attributes={},
    )
    db_session.add(asset)
    db_session.commit()

    def sync(cves):
        scan_id = f"scn_id_{uuid.uuid4().hex[:8]}"
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
            "hostname": "PANKAJM-HPNEW",
            "is_active": True,
            "cves": cves,
        }
        asset_syncer.sync_vulnerability_audit(db_session, scan_id, org.id, None, [host])
        db_session.commit()
        return scan_id

    def rows():
        db_session.expire_all()
        return (
            db_session.query(AssetVulnerability)
            .filter(AssetVulnerability.org_id == org.id)
            .order_by(AssetVulnerability.id)
            .all()
        )

    return sync, rows, asset.id


def _check(cve_id, severity):
    return {
        "cve_id": cve_id,
        "severity": severity,
        "cvss": 0.0,
        "cvss_score": 0.0,
        "definition_type": "plugin_check",
        "detection_method": "config_check",
        "confidence": "Confirmed",
    }


def _package_cve(cve_id, package, version, cvss=7.8):
    return {
        "cve_id": cve_id,
        "severity": "High",
        "cvss": cvss,
        "cvss_score": cvss,
        "package": package,
        "installed_version": version,
        "detection_method": "credentialed_package",
        "confidence": "Confirmed",
    }


# ── severity ────────────────────────────────────────────────────────────────


def test_a_check_with_no_cvss_keeps_its_declared_severity(world):
    sync, rows, _ = world
    sync(
        [
            _check("CCURE-CHK-TLS-CERTIFICATE-HOSTNAME-MISMATCH", "Medium"),
            _check("CCURE-CHK-HTTP-MISSING-SECURITY-HEADERS", "Low"),
            _package_cve("CVE-2025-30033", "SIMATIC ProSave", "19.00.0000", cvss=7.8),
        ]
    )
    severities = {r.vuln_id: r.severity for r in rows()}
    assert severities == {
        "CCURE-CHK-TLS-CERTIFICATE-HOSTNAME-MISMATCH": "medium",
        "CCURE-CHK-HTTP-MISSING-SECURITY-HEADERS": "low",
        "CVE-2025-30033": "high",
    }


def test_a_check_with_no_rating_at_all_is_unscored_not_none(world):
    sync, rows, _ = world
    sync([_check("CCURE-CHK-SOMETHING-UNRATED", "")])
    assert rows()[0].severity == "unscored"


# ── one CVE, several products ──────────────────────────────────────────────


def test_one_cve_on_several_products_is_one_row_per_product(world):
    sync, rows, _ = world
    sync(
        [
            _package_cve(
                "CVE-2025-30033",
                "SIMATIC WinCC Runtime Advanced V17.0 UPD6",
                "V17.0 UPD6",
            ),
            _package_cve("CVE-2025-30033", "TIA Administrator V3", "V3.0"),
            _package_cve("CVE-2025-30033", "SIMATIC ProSave V19.0", "19.00.0000"),
        ]
    )
    stored = rows()
    assert sorted(r.component for r in stored) == [
        "SIMATIC ProSave V19.0",
        "SIMATIC WinCC Runtime Advanced V17.0 UPD6",
        "TIA Administrator V3",
    ]
    assert {r.vuln_id for r in stored} == {"CVE-2025-30033"}
    assert len({r.id for r in stored}) == 3


def test_a_single_product_keeps_its_existing_id(world):
    sync, rows, asset_id = world
    sync([_package_cve("CVE-2025-30176", "Siemens TIA Portal V19", "V19")])
    (row,) = rows()
    assert "__" not in row.id
    assert row.id.endswith("_CVE-2025-30176")


def test_the_choice_of_base_row_does_not_depend_on_order(world):
    sync, rows, _ = world
    a = _package_cve("CVE-2025-15467", "User Management Component", "V2.12")
    b = _package_cve(
        "CVE-2025-15467", "SIMATIC WinCC Runtime Advanced V17.0 UPD6", "V17.0"
    )
    sync([a, b])
    first = {r.component: r.id for r in rows()}
    sync([b, a])
    second = {r.component: r.id for r in rows() if r.status == "open"}
    assert first == second


def test_upgrading_one_product_closes_only_its_row(world):
    sync, rows, _ = world
    wincc = _package_cve(
        "CVE-2025-30033", "SIMATIC WinCC Runtime Advanced V17.0 UPD6", "V17.0"
    )
    prosave = _package_cve("CVE-2025-30033", "SIMATIC ProSave V19.0", "19.00.0000")
    sync([wincc, prosave])
    sync([wincc])  # ProSave was upgraded
    status = {r.component: r.status for r in rows()}
    assert status["SIMATIC WinCC Runtime Advanced V17.0 UPD6"] == "open"
    assert status["SIMATIC ProSave V19.0"] == "fixed"


def test_an_authenticated_os_build_reaches_the_asset(world, db_session):
    """Windows 11 Pro was stored with an empty os_version beside build 26300.9550."""
    from db.models import Asset
    from scans import asset_syncer

    sync, _rows, asset_id = world
    asset = db_session.get(Asset, asset_id)
    scan_id = f"scn_id_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=asset.org_id,
            target_str=IP,
            pipeline_mode="vulnerability_audit",
            status="complete",
        )
    )
    db_session.commit()
    host = {
        "ip_address": IP,
        "is_active": True,
        "os_guess": "Microsoft Windows 11 Pro",
        "credentialed": True,
        "credentialed_report": {"system_info": {"os_version_id": "10.0.26300.9550"}},
        "cves": [],
    }
    asset_syncer.sync_vulnerability_audit(
        db_session, scan_id, asset.org_id, None, [host]
    )
    db_session.commit()
    db_session.refresh(asset)
    assert asset.os_version == "10.0.26300.9550"
