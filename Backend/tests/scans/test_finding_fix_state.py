"""
"Affected, no fix released" is its own state, not a missing fixed version.

Ubuntu marks most CVEs it tracks as affecting a package with no fix released:
2,241 of one Ubuntu 24.04 desktop's 2,355 package findings were such records
(14 Oct 2026), and nothing stored could tell them from the 15 NVD matches that
simply named no fixed release — both left ``component_fixed_version`` NULL, and
the grouped view told the operator to re-scan for a version that does not
exist.

``fix_state`` records the advisory's own answer. It never changes a finding's
status or severity: an unfixed vulnerability is still present and still
counted.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from core.findings.fix_state import fix_state_for
from db.models.findings import AssetVulnerability
from db.models.rbac import Organization
from db.models.scans import Scan

IP = "10.77.8.45"


def _osv(cve, package, *, ecosystem="Ubuntu:24.04:LTS", fixed="", cvss=7.8):
    return {
        "cve_id": cve,
        "severity": "High",
        "cvss": cvss,
        "cvss_score": cvss,
        "package": package,
        "installed_ver": "6.8.0-146.146",
        "installed_version": "6.8.0-146.146",
        "fixed_ver": fixed,
        "source": "osv_match",
        "matched_by": f"osv:{ecosystem}",
        "detection_method": "credentialed_package",
        "confidence": "Confirmed",
    }


def _nvd(cve, package, *, fixed=""):
    return {
        **_osv(cve, package, fixed=fixed),
        "source": "cpe_match",
        "matched_by": "cpe",
    }


# ── the classification ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "finding, expected",
    [
        (_osv("CVE-1", "linux"), "no_fix_released"),
        (_osv("CVE-1", "linux", ecosystem="Ubuntu:Pro:24.04:LTS"), "no_fix_released"),
        (_osv("CVE-1", "openssl", fixed="3.0.13-0ubuntu3.5"), "fix_released"),
        # An NVD range that names no exclusive end has not said "no fix".
        (_nvd("CVE-1", "curl"), None),
        (_nvd("CVE-1", "curl", fixed="8.9.0"), "fix_released"),
        # Not measured: in a feed that uses last_affected an open range is not
        # that claim (sync_osv stores last_affected as an open window).
        (_osv("CVE-1", "openssl", ecosystem="Debian:12"), None),
        ({"cve_id": "CCURE-CFG-X", "detection_method": "config_check"}, None),
        (_osv("CVE-1", "linux", fixed="none"), "no_fix_released"),
        ({**_osv("CVE-1", "linux"), "matched_by": "Ubuntu:24.04:LTS"}, None),
    ],
)
def test_fix_state_for(finding, expected):
    assert fix_state_for(finding) == expected


# ── what the two writers store ───────────────────────────────────────────────


@pytest.fixture()
def pipeline(db_session, monkeypatch):
    from db.base import gen_asset_id
    from db.models import Asset
    from scans import asset_syncer

    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)
    org = Organization(
        id=f"org_fx_{uuid.uuid4().hex[:8]}",
        name="fixstate",
        slug=f"fixstate{uuid.uuid4().hex[:6]}",
    )
    db_session.add(org)
    db_session.flush()
    asset = Asset(
        id=gen_asset_id(org.slug, IP),
        org_id=org.id,
        ip_address=IP,
        hostname="ubuntu-desktop",
        custom_attributes={},
    )
    db_session.add(asset)
    db_session.commit()

    def sync(cves):
        scan_id = f"scn_fx_{uuid.uuid4().hex[:8]}"
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
            "cves": cves,
            "credentialed": True,
            "credentialed_report": {
                "package_count": 2,
                "inventory_complete": True,
                "package_coverage": {"lookup_failures": []},
            },
        }
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

    return sync, rows, org


def test_the_pipeline_stores_the_advisorys_answer_and_nothing_else_changes(pipeline):
    sync, rows, _ = pipeline
    sync(
        [
            _osv("CVE-2026-0001", "linux", cvss=9.8),
            _osv("CVE-2026-0002", "openssl", fixed="3.0.13-0ubuntu3.5"),
            _nvd("CVE-2026-0003", "curl"),
        ]
    )
    stored = rows()
    assert {k: r.fix_state for k, r in stored.items()} == {
        "CVE-2026-0001": "no_fix_released",
        "CVE-2026-0002": "fix_released",
        "CVE-2026-0003": None,
    }
    unfixed = stored["CVE-2026-0001"]
    # Still a genuine, open, critical finding.
    assert (unfixed.status, unfixed.severity) == ("open", "critical")
    assert unfixed.component_fixed_version is None


def test_a_fix_released_later_is_picked_up_on_the_next_scan(pipeline):
    sync, rows, _ = pipeline
    sync([_osv("CVE-2026-0001", "linux")])
    assert rows()["CVE-2026-0001"].fix_state == "no_fix_released"
    sync([_osv("CVE-2026-0001", "linux", fixed="6.8.0-150.150")])
    after = rows()["CVE-2026-0001"]
    assert (after.fix_state, after.component_fixed_version) == (
        "fix_released",
        "6.8.0-150.150",
    )


def test_the_standalone_credentialed_writer_stores_it_too(db_session):
    from db.models.assets import Asset
    from scans.db_helpers import utcnow

    from scans.tasks.credentialed_sync import _sync_credentialed_vulnerabilities

    org_id = f"org_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name="S",
            slug=f"s-{uuid.uuid4().hex[:8]}",
            is_active=True,
            settings={},
        )
    )
    db_session.commit()
    asset = Asset(
        id=f"ast_{org_id}_10_0_0_9",
        org_id=org_id,
        ip_address="10.0.0.9",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org_id,
            target_str="10.0.0.9",
            scan_type="credentialed",
            pipeline_mode="credentialed",
        )
    )
    db_session.commit()

    _sync_credentialed_vulnerabilities(
        db_session,
        asset,
        org_id,
        scan_id,
        [
            _osv("CVE-2026-0101", "linux"),
            _osv("CVE-2026-0102", "openssl", fixed="3.0.13-0ubuntu3.5"),
        ],
    )
    db_session.commit()
    db_session.expire_all()
    stored = {
        r.vuln_id: r.fix_state
        for r in db_session.query(AssetVulnerability).filter(
            AssetVulnerability.org_id == org_id
        )
    }
    assert stored == {
        "CVE-2026-0101": "no_fix_released",
        "CVE-2026-0102": "fix_released",
    }


# ── the filter ──────────────────────────────────────────────────────────────


@pytest.fixture()
def api(pipeline, db_session, monkeypatch):
    from routers import findings as router

    sync, _, org = pipeline
    sync(
        [
            _osv("CVE-2026-0001", "linux", cvss=9.8),
            _osv("CVE-2026-0004", "linux", cvss=5.5),
            _osv("CVE-2026-0002", "openssl", fixed="3.0.13-0ubuntu3.5"),
            _nvd("CVE-2026-0003", "curl"),
        ]
    )
    monkeypatch.setattr(router, "_resolve_org", lambda user, org_id: org.id)

    def listed(fix_state):
        out = router.list_findings(
            severity=None,
            status=None,
            priority=None,
            in_kev=None,
            search=None,
            asset_id=None,
            scan_id=None,
            fix_state=fix_state,
            sort_by="priority",
            skip=0,
            limit=50,
            org_id=None,
            db=db_session,
            user=None,
        )
        return out["total"], {f["vuln_id"]: f["fix_state"] for f in out["findings"]}

    def grouped(fix_state):
        out = router.list_findings_grouped(
            severity=None,
            status=None,
            asset_id=None,
            scan_id=None,
            fix_state=fix_state,
            skip=0,
            limit=50,
            org_id=None,
            db=db_session,
            user=None,
        )
        return {
            g["component"]: (g["finding_count"], g["no_fix_released_count"])
            for g in out["groups"]
        }

    return listed, grouped


def test_the_list_filters_by_fix_state_and_reports_it(api):
    listed, _ = api
    assert listed("no_fix_released") == (
        2,
        {"CVE-2026-0001": "no_fix_released", "CVE-2026-0004": "no_fix_released"},
    )
    assert listed("fix_released") == (1, {"CVE-2026-0002": "fix_released"})
    # Not recorded is NULL, and never folded into "no fix released".
    assert listed("not_recorded") == (1, {"CVE-2026-0003": None})
    assert listed("fix_released,not_recorded")[0] == 2
    assert listed(None)[0] == 4


def test_an_unknown_fix_state_is_refused_rather_than_ignored(api):
    listed, _ = api
    with pytest.raises(HTTPException) as refused:
        listed("unfixed")
    assert refused.value.status_code == 400


def test_a_group_says_how_many_of_its_findings_have_no_released_fix(api):
    _, grouped = api
    assert grouped(None) == {"linux": (2, 2), "openssl": (1, 0), "curl": (1, 0)}
    assert grouped("no_fix_released") == {"linux": (2, 2)}
