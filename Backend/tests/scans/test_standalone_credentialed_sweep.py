"""
A standalone credentialed scan retires a package finding only if it assessed packages.

The sweep treated an absent package CVE as fixed whenever the audit ran. With no
inventory collected, or a feed lookup that failed (13 Oct 2026: 2,699 packages,
0 CVEs, after a corrupted vuln_intel connection), the CVE list carries no
package CVEs at all, and every open package finding on the host would have been
recorded as remediated. Shares core.findings.credentialed_scope with the
pipeline's sweep (test_pipeline_credentialed_family).
"""

from __future__ import annotations

import uuid

from db.models.findings import AssetVulnerability
from db.models.scans import Scan

IP = "10.77.9.45"
PKG = {
    "cve_id": "CVE-2024-3094",
    "severity": "Critical",
    "cvss_score": 10.0,
    "package": "xz-utils",
    "installed_version": "5.6.0-0.2",
    "detection_method": "credentialed_package",
}


def _sync(db_session, org, user, cve_list, stored_report):
    from core.tasks import _sync_credentialed_asset_identity

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str=IP,
            scan_type="credentialed",
            pipeline_mode="credentialed",
        )
    )
    db_session.commit()
    _sync_credentialed_asset_identity(
        db_session,
        user_id=user.id,
        ip=IP,
        scan_id=scan_id,
        os_type="linux",
        system_data={"os_name": "Ubuntu 24.04.5 LTS", "hostname_short": "h1"},
        stored_report={"open_ports_credentialed": [], **stored_report},
        cve_list=[dict(c) for c in cve_list],
        severity_counts={},
    )
    db_session.commit()


def _status(db_session, org):
    db_session.expire_all()
    return {
        r.vuln_id: r.status
        for r in db_session.query(AssetVulnerability).filter(
            AssetVulnerability.org_id == org.id
        )
    }


COMPLETE = {"package_count": 2, "packages": [{"name": "xz-utils"}]}


def test_a_failed_lookup_leaves_package_findings_open(db_session, test_org, test_user):
    _sync(db_session, test_org, test_user, [PKG], COMPLETE)
    _sync(
        db_session,
        test_org,
        test_user,
        [],
        {
            **COMPLETE,
            "package_coverage": {"lookup_failures": ["Batch OSV query: lost"]},
        },
    )
    assert _status(db_session, test_org)["CVE-2024-3094"] == "open"


def test_no_inventory_leaves_package_findings_open(db_session, test_org, test_user):
    _sync(db_session, test_org, test_user, [PKG], COMPLETE)
    _sync(db_session, test_org, test_user, [], {"package_count": 0, "packages": []})
    assert _status(db_session, test_org)["CVE-2024-3094"] == "open"


def test_a_complete_audit_retires_what_it_no_longer_sees(
    db_session, test_org, test_user
):
    _sync(db_session, test_org, test_user, [PKG], COMPLETE)
    _sync(db_session, test_org, test_user, [], COMPLETE)
    assert _status(db_session, test_org)["CVE-2024-3094"] == "fixed"
