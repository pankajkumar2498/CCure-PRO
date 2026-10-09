"""
FindingReadService — Phase 5 step 5.5.

The export's finding-read logic now lives in ``ccure_audit.services.finding_read``.
These tests pin:

* the export resolves every moved name to the service — one implementation;
* the views agree with the export's finding rows column for column, on the
  same data, including the computed SLA state and the definition type;
* cursor paging never skips or repeats a finding and is bounded;
* tenant scoping, view purity, and no writes.

Byte-identity of the export itself was proven separately against the scratch
restore (see the 5.5 commit message); the export tests run unchanged.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from ccure_audit.services.finding_read import FindingReadService
from ccure_audit.services.views import impurities
from reporting import exports

HOST = "10.20.30.42"
START = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
END = START + timedelta(minutes=10)

MOVED = ("_owner_names", "_definition_titles", "finding_context_map", "finding_pairs")


@pytest.mark.parametrize("name", MOVED)
def test_the_export_uses_the_service_implementation(name):
    assert getattr(exports, name).__module__ == "ccure_audit.services.finding_read"


@pytest.fixture()
def world(db_session):
    """
    One organisation with a user, one asset, one scan, and seven findings
    covering the remediation states the export renders differently: open,
    assigned with an owner, overdue, risk-accepted, verified fixed, reopened,
    and a configuration check.
    """
    from native_rbac import create_user, system_role
    from db.models import Organization
    from db.models.assets import Asset
    from db.models.findings import AssetVulnerability, VulnerabilityDefinition
    from db.models.scans import Scan

    suffix = uuid.uuid4().hex[:8]
    org_id = f"org_fread_{suffix}"
    db_session.add(
        Organization(id=org_id, name=f"FRead {suffix}", slug=f"fread-{suffix}")
    )
    db_session.flush()
    user_id = f"usr_fread_{suffix}"
    db_session.add(
        create_user(
            db_session,
            id=user_id,
            org_id=org_id,
            role=system_role(db_session, "platform.viewer"),
            username=f"owner_{suffix}",
            email=f"owner_{suffix}@test.com",
            password_hash="x",
        )
    )
    asset_id = f"ast_{org_id}_10_20_30_42"
    db_session.add(
        Asset(id=asset_id, org_id=org_id, ip_address=HOST, hostname="fread-host")
    )
    scan = Scan(
        id=f"scn_fread_{suffix}",
        org_id=org_id,
        scan_no=3,
        target_str=HOST,
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        created_at=START,
        started_at=START,
        completed_at=END,
        options={},
    )
    db_session.add(scan)
    db_session.flush()

    def definition(def_id, *, cve=True, title):
        db_session.merge(
            VulnerabilityDefinition(
                id=def_id,
                cve_id=def_id if cve else None,
                definition_type="cve" if cve else "config_check",
                title=title,
                description="fixture",
                severity="high",
            )
        )

    specs = [
        ("CVE-9999-50001", dict(remediation_state="open")),
        (
            "CVE-9999-50002",
            dict(
                remediation_state="assigned",
                remediation_owner=user_id,
                assigned_at=START,
            ),
        ),
        (
            "CVE-9999-50003",
            dict(remediation_state="open", sla_due_at=START - timedelta(days=30)),
        ),
        (
            "CVE-9999-50004",
            dict(
                status="accepted",
                remediation_state="risk_accepted",
                accepted_at=START,
                accepted_by=user_id,
                exception_expires_at=START + timedelta(days=180),
                accepted_risk_reason="Compensating control in place.",
            ),
        ),
        (
            "CVE-9999-50005",
            dict(
                status="fixed",
                remediation_state="verified_fixed",
                fixed_at=END,
                verified_at=END,
                verified_scan_id=scan.id,
            ),
        ),
        (
            "CVE-9999-50006",
            dict(remediation_state="reopened", reopened_at=END, reopened_count=2),
        ),
        ("CCURE-CFG-TEST-FREAD-PWLEN", dict(remediation_state="open")),
    ]
    for def_id, extra in specs:
        definition(def_id, cve=def_id.startswith("CVE-"), title=f"Title of {def_id}")
    db_session.flush()
    for def_id, extra in specs:
        row = dict(
            id=f"fnd_{asset_id}_{def_id}",
            org_id=org_id,
            asset_id=asset_id,
            vuln_id=def_id,
            scan_id=scan.id,
            severity="high",
            cvss_score=Decimal("7.5"),
            status="open",
            source_family="credentialed_package",
            evidence=f"evidence for {def_id}",
            first_found_at=START,
            last_found_at=END,
            sla_due_at=START + timedelta(days=3650),
            sla_basis="high",
            in_kev=def_id.endswith("1"),
            epss_score=Decimal("0.12345"),
            has_exploit=def_id.endswith("2"),
            exploit_sources=["exploitdb"] if def_id.endswith("2") else None,
        )
        row.update(extra)
        db_session.add(AssetVulnerability(**row))
    db_session.flush()
    db_session.refresh(scan)
    try:
        yield {
            "org_id": org_id,
            "scan": scan,
            "user_id": user_id,
            "ids": [s[0] for s in specs],
        }
    finally:
        db_session.rollback()


def test_views_agree_with_the_export_rows(db_session, world):
    page = FindingReadService(db_session).findings(
        org_id=world["org_id"], scan_id=world["scan"].id
    )
    assert impurities(page) == [], impurities(page)
    assert len(page.items) == len(world["ids"])

    rows = exports.finding_export_rows(db_session, world["scan"])
    col = {name: i for i, name in enumerate(exports.FINDING_EXPORT_COLUMNS)}
    by_id = {row[col["Finding ID"]]: row for row in rows}
    assert set(by_id) == {v.finding_id for v in page.items}

    for v in page.items:
        row = by_id[v.finding_id]
        assert row[col["Identifier"]] == v.definition_id
        assert row[col["Definition Type"]] == v.definition_type
        assert row[col["Title"]] == v.title
        assert row[col["Severity"]] == (v.severity or "")
        assert row[col["CVSS Score"]] == exports._text(v.cvss_score)
        assert row[col["Status"]] == v.status
        assert row[col["In CISA KEV"]] == exports._text(v.in_kev)
        assert row[col["EPSS Probability"]] == exports._text(v.epss_score)
        assert row[col["Evidence"]] == (v.evidence or "")
        assert row[col["First Found"]] == exports._iso(v.first_found_at)
        assert row[col["Fixed At"]] == exports._iso(v.fixed_at)
        assert row[col["Remediation State"]] == v.remediation_state
        assert row[col["SLA Due"]] == exports._iso(v.sla_due_at)
        assert row[col["SLA State"]] == v.sla_state
        assert row[col["Verified At"]] == exports._iso(v.verified_at)
        assert row[col["Verified By Scan"]] == (v.verified_scan_id or "")
        assert row[col["Reopened Count"]] == str(v.reopened_count)
        assert row[col["Risk Accepted At"]] == exports._iso(v.accepted_at)
        assert row[col["Risk Acceptance Reason"]] == (v.accepted_risk_reason or "")
        assert row[col["Exploit Availability"]] == exports._text(v.has_exploit)


def test_the_views_carry_typed_values_and_the_real_states(db_session, world):
    items = {
        v.definition_id: v
        for v in FindingReadService(db_session)
        .findings(org_id=world["org_id"], scan_id=world["scan"].id)
        .items
    }
    assert items["CVE-9999-50003"].sla_state == "overdue"
    assert items["CVE-9999-50004"].sla_state == "resolved"
    assert items["CVE-9999-50004"].accepted_by_id == world["user_id"]
    assert items["CVE-9999-50002"].remediation_owner_id == world["user_id"]
    assert items["CVE-9999-50002"].exploit_sources == ("exploitdb",)
    assert items["CVE-9999-50005"].verified_scan_id == world["scan"].id
    assert items["CCURE-CFG-TEST-FREAD-PWLEN"].definition_type == "config_check"
    assert items["CVE-9999-50001"].definition_type == "cve"
    one = items["CVE-9999-50001"]
    assert isinstance(one.cvss_score, Decimal) and one.first_found_at.tzinfo is not None


def test_paging_never_skips_or_repeats(db_session, world):
    service = FindingReadService(db_session)
    seen, after, pages = [], None, 0
    while True:
        page = service.findings(
            org_id=world["org_id"], scan_id=world["scan"].id, after=after, limit=3
        )
        seen.extend(v.finding_id for v in page.items)
        pages += 1
        if page.next_after is None:
            break
        after = page.next_after
    assert pages == 3  # 7 findings, 3 per page
    assert seen == sorted(seen)
    assert len(seen) == len(set(seen)) == len(world["ids"])


def test_the_page_size_is_bounded(db_session, world):
    service = FindingReadService(db_session)
    page = service.findings(
        org_id=world["org_id"], scan_id=world["scan"].id, limit=10**6
    )
    assert len(page.items) == len(world["ids"]) and page.next_after is None
    with pytest.raises(ValueError, match="limit"):
        service.findings(org_id=world["org_id"], scan_id=world["scan"].id, limit=0)


def test_another_tenants_assessment_is_not_found(db_session, world):
    service = FindingReadService(db_session)
    with pytest.raises(LookupError, match="for this tenant"):
        service.findings(org_id="org_somebody_else", scan_id=world["scan"].id)
    with pytest.raises(ValueError, match="org_id is required"):
        service.findings(org_id="", scan_id=world["scan"].id)


def test_reading_writes_nothing(db_session, world):
    FindingReadService(db_session).findings(
        org_id=world["org_id"], scan_id=world["scan"].id
    )
    assert not db_session.new and not db_session.dirty and not db_session.deleted


def test_every_view_maps_to_a_contract_finding(db_session, world):
    """Service → view → Phase 5.6 mapper, on real rows."""
    from ccure_audit.integration.mappers.findings import finding

    items = {
        v.definition_id: finding(v)
        for v in FindingReadService(db_session)
        .findings(org_id=world["org_id"], scan_id=world["scan"].id)
        .items
    }
    assert len(items) == len(world["ids"])
    verified = items["CVE-9999-50005"].remediation
    assert verified.verified_by.assessment_id == world["scan"].id
    accepted = items["CVE-9999-50004"].remediation.risk_acceptance
    assert accepted.reason == "Compensating control in place."
    assert items["CVE-9999-50003"].remediation.sla_state.value == "overdue"
    assert items["CVE-9999-50001"].exploit.availability.value == "actively_exploited"
    assert items["CVE-9999-50002"].exploit.availability.value == "public_exploit"
    config = items["CCURE-CFG-TEST-FREAD-PWLEN"]
    assert config.definition.cve_id is None
    assert config.exploit.availability.value == "not_applicable"
    assert config.exploit.in_cisa_kev is None
