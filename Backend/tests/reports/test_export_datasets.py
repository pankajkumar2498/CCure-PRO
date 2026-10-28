"""
tests/reports/test_export_datasets.py
─────────────────────────────────────────────────────────────────────────────
What an export *says* (GAP-15).

These drive `reporting.exports` against real rows — a real `Scan` with real
stored phase payloads, real `AssetVulnerability` findings with their GAP-14
remediation record, real `compliance_rules` crosswalked to real controls in a
real installed framework. A mocked row would prove the branch was taken and
nothing about whether the export tells the truth.

The property under defence
──────────────────────────
**No assessment state is converted and no row is silently dropped.** A check
that errored is exported as ERROR, not as something a reader takes for a human
review decision; a check that did not apply is NOT_APPLICABLE, not blank; a
host whose audit never ran is NOT_ASSESSED, not absent. The reconciliation
requirement — that the database, the report and the file agree — is only
meaningful if those six states survive the trip.
"""

from __future__ import annotations

from native_rbac import system_role, create_user, fixture_role


import uuid
from datetime import datetime, timedelta, timezone

import pytest

from db.models.assets import Asset
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)
from db.models.findings import AssetVulnerability, VulnerabilityDefinition
from db.models.rbac import Organization
from db.models.scans import Scan, ScanPhase
from reporting.exports import (
    CONFIG_VERDICT_COLUMNS,
    FINDING_EXPORT_COLUMNS,
    VERDICT_NOT_ASSESSED,
    comparison_export_rows,
    compliance_verdict_rows,
    control_map_for_checks,
    export_payload,
    finding_context_map,
    finding_export_rows,
    scan_context,
    workbook_sheets,
)

SCAN_START = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
SCAN_END = SCAN_START + timedelta(minutes=10)
HOST = "10.20.30.40"
FAMILY = "credentialed_package"


def _column(name: str) -> int:
    return CONFIG_VERDICT_COLUMNS.index(name)


def _finding_column(name: str) -> int:
    return FINDING_EXPORT_COLUMNS.index(name)


def _result(check_id: str, outcome: str, **kw) -> dict:
    """One stored `CheckResult.as_dict()`, as the engine wrote it."""
    evidence = kw.pop("evidence", None)
    if evidence is None and outcome in ("pass", "fail"):
        evidence = [
            {
                "collector": "linux_file",
                "description": kw.get("title", check_id),
                "expected": "PermitRootLogin no",
                "observed": "yes",
                "raw": "CCURE::VALUE::yes",
                "collected_at": SCAN_END.isoformat(),
            }
        ]
    return {
        "check_id": check_id,
        "outcome": outcome,
        "title": kw.get("title", f"Check {check_id}"),
        "severity": kw.get("severity", "high"),
        "target": HOST,
        "evidence": evidence or [],
        "remediation": kw.get("remediation", "Set the directive and restart."),
        "references": kw.get("references", ["https://example.invalid/doc"]),
        "detection_method": "config_check",
        "confidence": "Confirmed",
        "qod": 95,
        "cve_ids": [],
        "error": kw.get("error"),
        "metadata": kw.get(
            "metadata", {"domain": "host_configuration", "check_type": "config_file"}
        ),
    }


@pytest.fixture()
def world(db_session):
    """
    One organisation, one asset, one completed credentialed scan whose stored
    phase payload carries a configuration audit covering all five outcomes.
    """
    org_id = f"org_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name="Export Co",
            slug=f"exp-{uuid.uuid4().hex[:8]}",
            is_active=True,
            settings={},
        )
    )
    db_session.flush()

    asset_id = f"ast_{org_id}_10_20_30_40"
    db_session.add(
        Asset(
            id=asset_id,
            org_id=org_id,
            ip_address=HOST,
            hostname="export-target",
            last_seen_at=SCAN_END,
        )
    )

    scan = Scan(
        id=f"scn_exp_{uuid.uuid4().hex[:8]}",
        org_id=org_id,
        scan_no=41,
        target_str=HOST,
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        created_at=SCAN_START,
        started_at=SCAN_START,
        completed_at=SCAN_END,
        options={},
    )
    db_session.add(scan)
    db_session.flush()

    results = [
        _result("ccure.linux.ssh.permit_root_login", "fail"),
        _result("ccure.linux.ssh.protocol", "pass"),
        _result(
            "ccure.win.uac.enabled",
            "not_applicable",
            metadata={
                "domain": "host_configuration",
                "check_type": "registry",
                "not_applicable_reason": "check targets windows; this host is linux",
            },
        ),
        _result(
            "ccure.linux.audit.rules",
            "manual_review",
            metadata={"domain": "logging", "check_type": "config_file"},
        ),
        _result(
            "ccure.linux.file_caps",
            "error",
            error="getcap is not installed, so nothing was established",
            metadata={"domain": "host_configuration", "check_type": "privilege"},
        ),
    ]

    db_session.add(
        ScanPhase(
            id=f"sph_{scan.id}_credentialed",
            scan_id=scan.id,
            phase_key="credentialed",
            phase_order=3,
            status="complete",
            started_at=SCAN_START,
            completed_at=SCAN_END,
            summary={
                "scan_type": "credentialed",
                "_phase_data": [
                    {
                        "ip_address": HOST,
                        "credentialed_report": {
                            "target": HOST,
                            "config_audit": {
                                "assessed": True,
                                "platform": "linux",
                                "checks_run": len(results),
                                "checks_assessed": 2,
                                "counts": {
                                    "pass": 1,
                                    "fail": 1,
                                    "not_applicable": 1,
                                    "manual_review": 1,
                                    "error": 1,
                                },
                                "results": results,
                            },
                        },
                    }
                ],
            },
        )
    )
    db_session.flush()
    db_session.refresh(scan)

    return {
        "org_id": org_id,
        "asset_id": asset_id,
        "scan": scan,
        "results": results,
    }


@pytest.fixture()
def installed_framework(db_session, world):
    """A benchmark framework the tenant has installed, with one crosswalk."""
    framework_id = f"cfw_bm_export_{uuid.uuid4().hex[:6]}"
    db_session.add(
        ComplianceFramework(
            id=framework_id,
            code=f"BM_EXPORT_{uuid.uuid4().hex[:6].upper()}",
            name="CCURE Linux Baseline (test)",
            version="1.0",
            is_active=True,
        )
    )
    db_session.flush()

    control_id = f"cct_{framework_id}_5_2_8"
    db_session.add(
        ComplianceControl(
            id=control_id,
            framework_id=framework_id,
            control_number="5.2.8",
            theme="BENCHMARK",
            title="Ensure SSH root login is disabled",
            description="The benchmark's recommendation text.",
            scannability="auto",
            tags=[],
            profiles=["L1"],
        )
    )
    db_session.add(
        ComplianceRule(
            id="ccure.linux.ssh.permit_root_login",
            rule_family_code=f"fam_{uuid.uuid4().hex[:8]}",
            version_number=1,
            check_type="config_file",
            target_platform="linux",
            check_definition={"config_check": True},
            severity="high",
            status="active",
            tags=[],
        )
    )
    db_session.flush()
    db_session.add(
        ComplianceRuleControl(
            rule_id="ccure.linux.ssh.permit_root_login", control_id=control_id
        )
    )
    db_session.add(
        ComplianceTenantFramework(
            id=f"ctf_{uuid.uuid4().hex[:8]}",
            tenant_id=world["org_id"],
            framework_id=framework_id,
            is_enabled=True,
        )
    )
    db_session.flush()
    return {"framework_id": framework_id, "control_id": control_id}


# ─────────────────────────────────────────────────────────────────────────────
# The six states
# ─────────────────────────────────────────────────────────────────────────────


class TestVerdictStates:
    def test_every_outcome_is_exported_under_its_own_label(self, db_session, world):
        """
        Five stored outcomes, five distinct labels, nothing blank.

        This is the requirement the compliance register cannot satisfy:
        `compliance_findings.status` has no ERROR member, so `compliance_sync`
        maps ERROR onto `manual_review`. Reading the export from there would
        make a check that could not run indistinguishable from one a human is
        meant to review.
        """
        # exp.comp.states  exp.comp.verdicts
        rows = compliance_verdict_rows(db_session, world["scan"])
        verdicts = {row[_column("Verdict")] for row in rows}

        assert verdicts == {
            "PASS",
            "FAIL",
            "NOT_APPLICABLE",
            "MANUAL_REVIEW",
            "ERROR",
        }
        assert "" not in verdicts

    def test_an_errored_check_is_not_reported_as_reviewed(self, db_session, world):
        # exp.comp.states
        rows = compliance_verdict_rows(db_session, world["scan"])
        errored = [r for r in rows if r[_column("Check ID")] == "ccure.linux.file_caps"]
        assert len(errored) == 1
        assert errored[0][_column("Verdict")] == "ERROR"
        assert "getcap" in errored[0][_column("Error")]

    def test_a_not_applicable_check_carries_its_reason(self, db_session, world):
        """
        "This host is not what the check is for" and "we could not tell" are
        different facts, and only the first is a legitimate reason to leave the
        score. The reason travels so a reader can tell which they have.
        """
        # exp.comp.applicability
        rows = compliance_verdict_rows(db_session, world["scan"])
        row = next(r for r in rows if r[_column("Check ID")] == "ccure.win.uac.enabled")
        assert row[_column("Verdict")] == "NOT_APPLICABLE"
        assert "targets windows" in row[_column("Applicability")]

    def test_a_host_whose_audit_never_ran_exports_not_assessed(self, db_session, world):
        """
        An empty compliance sheet reads as a clean host. A host the audit could
        not run on gets one explicit row carrying the engine's own reason.
        """
        # exp.comp.not_assessed
        phase = (
            db_session.query(ScanPhase)
            .filter(ScanPhase.scan_id == world["scan"].id)
            .first()
        )
        summary = dict(phase.summary)
        summary["_phase_data"] = [
            {
                "ip_address": HOST,
                "credentialed_report": {
                    "target": HOST,
                    "config_audit": {
                        "assessed": False,
                        "reason": "no checks selected for linux under the effective policy",
                    },
                },
            }
        ]
        phase.summary = summary
        db_session.flush()
        db_session.expire(world["scan"])

        rows = compliance_verdict_rows(db_session, world["scan"])
        assert len(rows) == 1
        assert rows[0][_column("Verdict")] == VERDICT_NOT_ASSESSED
        assert "no checks selected" in rows[0][_column("Applicability")]

    def test_a_scan_with_no_configuration_audit_exports_nothing_rather_than_zeroes(
        self, db_session, world
    ):
        # exp.comp.not_assessed
        db_session.query(ScanPhase).filter(
            ScanPhase.scan_id == world["scan"].id
        ).delete()
        db_session.flush()
        db_session.expire(world["scan"])
        assert compliance_verdict_rows(db_session, world["scan"]) == []


# ─────────────────────────────────────────────────────────────────────────────
# Content the export must carry
# ─────────────────────────────────────────────────────────────────────────────


class TestVerdictContent:
    def test_evidence_expected_and_observed_reach_the_row(self, db_session, world):
        # exp.comp.evidence
        rows = compliance_verdict_rows(db_session, world["scan"])
        row = next(
            r
            for r in rows
            if r[_column("Check ID")] == "ccure.linux.ssh.permit_root_login"
        )
        assert row[_column("Expected")] == "PermitRootLogin no"
        assert row[_column("Observed")] == "yes"
        assert "CCURE::VALUE::yes" in row[_column("Evidence")]

    def test_remediation_and_references_reach_the_row(self, db_session, world):
        # exp.comp.remediation
        rows = compliance_verdict_rows(db_session, world["scan"])
        row = rows[0]
        assert "restart" in row[_column("Remediation")]
        assert "example.invalid" in row[_column("References")]

    def test_scan_asset_and_organisation_are_on_every_row(self, db_session, world):
        # exp.comp.scan_context
        rows = compliance_verdict_rows(db_session, world["scan"])
        assert rows
        for row in rows:
            assert row[_column("Scan ID")] == world["scan"].id
            assert row[_column("Host")] == HOST
            assert row[_column("Asset ID")] == world["asset_id"]
            assert row[_column("Organization")] == "Export Co"
            assert row[_column("Scan Completed")].startswith("2026-09-01T10:10")

    def test_duplicate_evidence_lines_are_collapsed(self, db_session, world):
        """
        A rule with seven registry objects that all found nothing printed the
        same sentence seven times in the PDF before it was collapsed there. A
        cell has the same problem and less room.
        """
        # exp.comp.evidence
        phase = (
            db_session.query(ScanPhase)
            .filter(ScanPhase.scan_id == world["scan"].id)
            .first()
        )
        summary = dict(phase.summary)
        repeated = [
            {
                "collector": "windows_registry",
                "description": "d",
                "expected": "e",
                "observed": "o",
                "raw": "0 item(s) collected",
            }
            for _ in range(7)
        ]
        summary["_phase_data"][0]["credentialed_report"]["config_audit"]["results"] = [
            _result("ccure.win.many", "fail", evidence=repeated)
        ]
        phase.summary = summary
        db_session.flush()
        db_session.expire(world["scan"])

        rows = compliance_verdict_rows(db_session, world["scan"])
        assert rows[0][_column("Evidence")] == "0 item(s) collected"


class TestControlMapping:
    def test_a_crosswalked_check_names_its_framework_and_control(
        self, db_session, world, installed_framework
    ):
        # exp.comp.control_map  exp.comp.profile
        rows = compliance_verdict_rows(db_session, world["scan"])
        row = next(
            r
            for r in rows
            if r[_column("Check ID")] == "ccure.linux.ssh.permit_root_login"
        )
        assert row[_column("Framework ID")] == installed_framework["framework_id"]
        assert row[_column("Framework Name")] == "CCURE Linux Baseline (test)"
        assert row[_column("Control ID")] == installed_framework["control_id"]
        assert row[_column("Control Title")] == "Ensure SSH root login is disabled"
        assert row[_column("Profile")] == "L1"

    def test_a_check_mapping_to_nothing_still_gets_a_row(
        self, db_session, world, installed_framework
    ):
        """
        Dropping unmapped checks would silently lose every built-in check and
        every benchmark rule the tenant has not crosswalked — real assessment
        results. An empty mapping column is not a missing row.
        """
        # exp.comp.verdicts
        rows = compliance_verdict_rows(db_session, world["scan"])
        unmapped = [
            r for r in rows if r[_column("Check ID")] == "ccure.linux.file_caps"
        ]
        assert len(unmapped) == 1
        assert unmapped[0][_column("Framework ID")] == ""
        assert unmapped[0][_column("Verdict")] == "ERROR"

    def test_a_framework_the_tenant_has_not_installed_is_never_named(
        self, db_session, world, installed_framework
    ):
        """
        The same enabled-and-active intersection `compliance_sync` writes
        through. A tenant who never installed a benchmark must not acquire a
        row naming its controls because a host happened to be scanned.
        """
        # exp.comp.control_map  exp.api.tenant_isolation
        db_session.query(ComplianceTenantFramework).filter(
            ComplianceTenantFramework.tenant_id == world["org_id"]
        ).delete()
        db_session.flush()

        mapping = control_map_for_checks(
            db_session,
            org_id=world["org_id"],
            check_ids=["ccure.linux.ssh.permit_root_login"],
        )
        assert mapping == {}

        rows = compliance_verdict_rows(db_session, world["scan"])
        assert {r[_column("Framework ID")] for r in rows} == {""}

    def test_the_control_map_is_not_an_n_plus_one(
        self, db_session, world, installed_framework
    ):
        """
        955 benchmark rules is the real size of this call. One query per check
        is the N+1 the brief names, so the count is asserted rather than
        assumed — it must not grow with the number of checks.
        """
        # exp.comp.control_map
        from sqlalchemy import event

        statements: list[str] = []

        def record(conn, cursor, statement, params, context, executemany):
            statements.append(statement)

        engine = db_session.get_bind()
        event.listen(engine, "before_cursor_execute", record)
        try:
            control_map_for_checks(
                db_session,
                org_id=world["org_id"],
                check_ids=[f"ccure.bulk.{i}" for i in range(400)],
            )
        finally:
            event.remove(engine, "before_cursor_execute", record)

        selects = [s for s in statements if s.strip().upper().startswith("SELECT")]
        assert len(selects) <= 4, (
            "the control map must be a fixed number of queries regardless of "
            f"how many checks are passed; issued {len(selects)}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# GAP-12: the scan's own immutable policy snapshot
# ─────────────────────────────────────────────────────────────────────────────


class TestPolicyContext:
    def test_a_scan_with_no_snapshot_says_so_rather_than_inventing_one(
        self, db_session, world
    ):
        # exp.find.policy_context
        context = scan_context(db_session, world["scan"])
        assert context["policy"] == {"recorded": False}

        rows = compliance_verdict_rows(db_session, world["scan"], context=context)
        assert {r[_column("Configuration ID")] for r in rows} == {""}

        summary = dict(workbook_sheets({"scan": context, "datasets": {}})[0][2])
        assert "No scan policy was recorded" in summary["Policy"]

    def test_the_snapshot_travels_onto_every_row(self, db_session, world):
        """
        Read from the scan's own snapshot, never from the policy row it names.
        The policy may since have been edited; that changes nothing about what
        this scan assessed, which is the whole reason the snapshot exists.
        """
        # exp.find.policy_context  exp.comp.scan_context
        from core.scan_policy import record_policy_snapshot
        from core.scan_policy.spec import EffectivePolicy

        policy = EffectivePolicy(
            policy_id="pol_export_1",
            policy_name="Ubuntu 24.04 STIG, high only",
            policy_family_code="fam_export",
            version_number=3,
            source="policy",
            min_severity="high",
        )
        record_policy_snapshot(world["scan"], policy)
        db_session.flush()

        rows = compliance_verdict_rows(db_session, world["scan"])
        assert rows
        for row in rows:
            assert row[_column("Policy Name")] == "Ubuntu 24.04 STIG, high only"
            assert row[_column("Policy Version")] == "3"
            assert row[_column("Configuration ID")] == policy.fingerprint()


# ─────────────────────────────────────────────────────────────────────────────
# Findings, with the GAP-14 record
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def finding(db_session, world):
    db_session.merge(
        VulnerabilityDefinition(
            id="CVE-2026-1111",
            cve_id="CVE-2026-1111",
            definition_type="cve",
            title="A real published flaw",
            description="fixture",
            severity="high",
        )
    )
    db_session.flush()
    row = AssetVulnerability(
        id=f"fnd_{world['asset_id']}_CVE-2026-1111",
        org_id=world["org_id"],
        asset_id=world["asset_id"],
        vuln_id="CVE-2026-1111",
        scan_id=world["scan"].id,
        severity="high",
        status="open",
        source_family=FAMILY,
        evidence="openssl 3.0.2 is installed",
        first_found_at=SCAN_START,
        last_found_at=SCAN_END,
        remediation_state="in_remediation",
        sla_due_at=SCAN_START - timedelta(days=5),
        sla_basis="high",
        reopened_count=2,
        reopened_at=SCAN_START,
        accepted_at=None,
        remediation_notes="Package upgrade scheduled.",
    )
    db_session.add(row)
    db_session.flush()
    return row


class TestFindingExport:
    def test_the_remediation_and_sla_record_reaches_the_row(
        self, db_session, world, finding
    ):
        # exp.find.core  exp.find.definition_type  exp.find.lifecycle
        # exp.find.remediation_state  exp.find.sla
        rows = finding_export_rows(db_session, world["scan"])
        assert len(rows) == 1
        row = rows[0]

        assert row[_finding_column("Identifier")] == "CVE-2026-1111"
        assert row[_finding_column("Definition Type")] == "cve"
        assert row[_finding_column("Title")] == "A real published flaw"
        assert row[_finding_column("Remediation State")] == "in_remediation"
        assert row[_finding_column("SLA Basis")] == "high"
        assert row[_finding_column("First Found")].startswith("2026-09-01T10:00")
        assert row[_finding_column("Reopened Count")] == "2"
        assert row[_finding_column("Remediation Notes")] == "Package upgrade scheduled."

    def test_overdue_is_computed_against_now_not_stored(
        self, db_session, world, finding
    ):
        """
        `sla_due_at` is materialised because "everything overdue" must be one
        indexed predicate. Whether a finding *is* overdue is a function of the
        current time, so a stored copy would be stale the moment it was
        written.
        """
        # exp.find.sla
        rows = finding_export_rows(db_session, world["scan"])
        assert rows[0][_finding_column("SLA State")] == "overdue"
        assert rows[0][_finding_column("Overdue")] == "Yes"

    def test_an_unrated_finding_is_not_reported_as_within_sla(
        self, db_session, world, finding
    ):
        # exp.find.sla
        finding.sla_due_at = None
        finding.severity = "unscored"
        db_session.flush()
        rows = finding_export_rows(db_session, world["scan"])
        assert rows[0][_finding_column("SLA State")] != "within_sla"

    def test_verification_provenance_is_exported(self, db_session, world, finding):
        """
        `verified_scan_id` is the citation. A verified-fixed row that could not
        name the assessment behind it would be exactly the unevidenced claim
        GAP-14 exists to refuse.
        """
        # exp.find.verification
        finding.remediation_state = "verified_fixed"
        finding.verified_at = SCAN_END
        finding.verified_scan_id = world["scan"].id
        db_session.flush()

        row = finding_export_rows(db_session, world["scan"])[0]
        assert row[_finding_column("Verified At")].startswith("2026-09-01T10:10")
        assert row[_finding_column("Verified By Scan")] == world["scan"].id

    def test_risk_acceptance_is_exported(self, db_session, world, finding):
        # exp.find.risk_acceptance
        finding.remediation_state = "risk_accepted"
        finding.accepted_at = SCAN_START
        finding.exception_expires_at = SCAN_START + timedelta(days=90)
        finding.accepted_risk_reason = "Compensating control in place."
        db_session.flush()

        row = finding_export_rows(db_session, world["scan"])[0]
        assert row[_finding_column("Risk Accepted At")].startswith("2026-09-01")
        assert row[_finding_column("Risk Acceptance Expires")].startswith("2026-11-30")
        assert (
            row[_finding_column("Risk Acceptance Reason")]
            == "Compensating control in place."
        )

    def test_the_owner_is_named_by_something_a_person_recognises(
        self, db_session, world, finding
    ):
        # exp.find.owner

        role = system_role(db_session, "platform.analyst") or fixture_role(
            db_session, f"r_{uuid.uuid4().hex[:6]}"
        )
        db_session.add(role)
        db_session.flush()
        owner = create_user(
            db_session,
            username=f"owner-{uuid.uuid4().hex[:6]}",
            email="owner@export.test",
            password_hash="hash",
            org_id=world["org_id"],
            role=role,
            is_active=True,
            is_verified=True,
        )
        db_session.add(owner)
        db_session.flush()

        finding.remediation_owner = owner.id
        db_session.flush()

        row = finding_export_rows(db_session, world["scan"])[0]
        assert row[_finding_column("Remediation Owner")] == "owner@export.test"

    def test_filters_narrow_and_an_empty_result_is_an_empty_list(
        self, db_session, world, finding
    ):
        # exp.api.filters
        assert finding_export_rows(db_session, world["scan"], severity=["high"])
        assert (
            finding_export_rows(db_session, world["scan"], severity=["critical"]) == []
        )
        assert (
            finding_export_rows(
                db_session, world["scan"], remediation_state=["verified_fixed"]
            )
            == []
        )
        assert finding_export_rows(db_session, world["scan"], overdue_only=True)

    def test_another_organisations_findings_are_never_exported(
        self, db_session, world, finding
    ):
        """
        The scan is fetched through the caller's own tenant-scoped lookup, and
        every query here re-filters on org_id anyway. This asserts the second
        half: a finding on the same asset id but a different organisation does
        not appear.
        """
        # exp.api.tenant_isolation
        other_org = f"org_{uuid.uuid4().hex[:8]}"
        db_session.add(
            Organization(
                id=other_org,
                name="Other Co",
                slug=f"oth-{uuid.uuid4().hex[:8]}",
                is_active=True,
                settings={},
            )
        )
        db_session.flush()
        other_asset = f"ast_{other_org}_10_20_30_40"
        db_session.add(
            Asset(
                id=other_asset,
                org_id=other_org,
                ip_address=HOST,
                last_seen_at=SCAN_END,
            )
        )
        db_session.flush()
        db_session.add(
            AssetVulnerability(
                id=f"fnd_{other_asset}_CVE-2026-1111",
                org_id=other_org,
                asset_id=other_asset,
                vuln_id="CVE-2026-1111",
                scan_id=world["scan"].id,
                severity="high",
                status="open",
                source_family=FAMILY,
                first_found_at=SCAN_START,
                last_found_at=SCAN_END,
            )
        )
        db_session.flush()

        rows = finding_export_rows(db_session, world["scan"])
        assert [r[_finding_column("Asset ID")] for r in rows] == [world["asset_id"]]


# ─────────────────────────────────────────────────────────────────────────────
# The CSV bridge
# ─────────────────────────────────────────────────────────────────────────────


#: The minted catalogue identifier for the configuration check the fixture
#: below reports. Built with the real minting function rather than typed out,
#: because the whole point of the join this exercises is that the payload and
#: the catalogue agree on it.
from core.config_audit.findings import config_definition_id  # noqa: E402

CONFIG_DEFINITION_ID = config_definition_id(
    "ccure.linux.ssh.permit_root_login", "config_check"
)
CONFIG_TITLE = "SSH does not permit password-based root login"


def _config_finding_payload() -> dict:
    """
    One host carrying one configuration finding, exactly as
    ``scans.tasks.credentialed._run_configuration_audit`` emits it.

    Copied in shape rather than invented: ``detection_method="config_check"``
    is what makes the finding authoritative and keeps it above the reporting
    confidence threshold, and the minted identifier travelling in ``cve_id``
    rather than in ``plugin_id`` is precisely the thing that makes the
    remediation join non-obvious.
    """
    return {
        "data": [
            {
                "ip_address": HOST,
                "cves": [
                    {
                        "cve_id": CONFIG_DEFINITION_ID,
                        "cve": CONFIG_DEFINITION_ID,
                        "definition_type": "config_check",
                        "title": CONFIG_TITLE,
                        "severity": "High",
                        "description": CONFIG_TITLE,
                        "desc": CONFIG_TITLE,
                        "detection_method": "config_check",
                        "confidence": "Confirmed",
                        "qod": 95,
                        "evidence": "Expected: PermitRootLogin no\nObserved: yes",
                        "remediation": "Set PermitRootLogin no and restart sshd.",
                        "source": "config_audit",
                    }
                ],
            }
        ]
    }


@pytest.fixture()
def config_finding(db_session, world):
    """The database side of the same finding: catalogue row plus the finding."""
    # Get-or-create: `vulnerability_definitions` is a global catalogue and the
    # per-test purge is scoped to an organisation's own rows, so a second test
    # in the same session would otherwise collide on the primary key.
    existing = (
        db_session.query(VulnerabilityDefinition)
        .filter(VulnerabilityDefinition.id == CONFIG_DEFINITION_ID)
        .first()
    )
    if existing is None:
        db_session.add(
            VulnerabilityDefinition(
                id=CONFIG_DEFINITION_ID,
                cve_id=None,
                definition_type="config_check",
                title=CONFIG_TITLE,
                description=CONFIG_TITLE,
                severity="high",
            )
        )
    else:
        # The title is what the join under test resolves on, so a row left by
        # an earlier run must be brought back to what this module asserts.
        existing.title = CONFIG_TITLE
    db_session.flush()
    row = AssetVulnerability(
        id=f"fnd_{world['asset_id']}_cfg",
        org_id=world["org_id"],
        asset_id=world["asset_id"],
        vuln_id=CONFIG_DEFINITION_ID,
        scan_id=world["scan"].id,
        severity="high",
        status="open",
        source_family="credentialed_config",
        evidence="Expected: PermitRootLogin no\nObserved: yes",
        first_found_at=SCAN_START,
        last_found_at=SCAN_END,
        remediation_state="pending_verification",
        sla_due_at=SCAN_START - timedelta(days=1),
        sla_basis="high",
    )
    db_session.add(row)
    db_session.flush()
    return row


class TestFindingsCsvCompatibility:
    def test_the_existing_columns_keep_their_positions(self):
        """
        A consumer that reads this CSV by index — which is what a spreadsheet
        macro and most ETL scripts do — must keep working. The remediation
        columns are appended, never interleaved.
        """
        # exp.find.compat  exp.fmt.csv_findings
        from reporting.csv_generator import NETWORK_HEADERS, REMEDIATION_HEADERS

        combined = [*NETWORK_HEADERS, *REMEDIATION_HEADERS]
        assert combined[: len(NETWORK_HEADERS)] == list(NETWORK_HEADERS)
        assert combined[0] == "Host"
        assert combined[NETWORK_HEADERS.index("Status")] == "Status"
        assert combined[len(NETWORK_HEADERS)] == "Remediation State"

    def test_the_generator_writes_the_same_file_when_given_no_context(self, tmp_path):
        """
        The generator is called from the scan pipeline too, which has no
        session to look a remediation record up with. Omitting the context must
        produce the file it always produced, plus empty cells — never a
        different shape between two scans.
        """
        # exp.find.compat  exp.fmt.csv_findings
        import csv

        from reporting.csv_generator import (
            INTEL_HEADERS,
            NETWORK_HEADERS,
            REMEDIATION_HEADERS,
            generate_scan_csv,
        )

        path = str(tmp_path / "findings.csv")
        generate_scan_csv(_config_finding_payload(), path, scan_type="network")

        with open(path, newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.reader(handle))

        # The exploitation block was appended after the remediation block in the
        # September 2026 report gap closure. The assertion below is deliberately
        # *stronger* than the one it replaces rather than merely updated: it used
        # to pin the remediation columns only by their being the tail of the row,
        # which any later append would have satisfied by accident. It now pins
        # their start index, so a block inserted in front of them — the change
        # that would silently shift nine columns under every existing reader —
        # fails here.
        remediation_start = len(NETWORK_HEADERS)
        remediation_end = remediation_start + len(REMEDIATION_HEADERS)

        assert rows[0][:remediation_start] == list(NETWORK_HEADERS)
        assert rows[0][remediation_start:remediation_end] == list(REMEDIATION_HEADERS)
        assert rows[0][remediation_end:] == list(INTEL_HEADERS)

        assert len(rows) == 2, "the finding must survive into the export"
        assert rows[1][NETWORK_HEADERS.index("Host")] == HOST
        # The point of the test is unchanged: with no remediation context the
        # remediation cells are empty rather than absent, so the shape does not
        # change between two scans.
        assert rows[1][remediation_start:remediation_end] == [""] * len(
            REMEDIATION_HEADERS
        )
        assert len(rows[1]) == len(rows[0])

    def test_the_context_map_keys_on_host_and_identifier(
        self, db_session, world, finding
    ):
        # exp.find.remediation_state
        mapping = finding_context_map(db_session, world["scan"])
        assert (HOST.lower(), "CVE-2026-1111") in mapping
        record = mapping[(HOST.lower(), "CVE-2026-1111")]
        assert record["remediation_state"] == "in_remediation"
        assert record["overdue"] == "Yes"

    def test_a_configuration_finding_is_reachable_by_title(
        self, db_session, world, config_finding
    ):
        """
        A configuration finding has no CVE, so the normalizer leaves
        ``cve_ids`` empty and falls back to the title for ``plugin_id``. The
        title is therefore the only key it has, and without it every benchmark
        finding in the product — which is most of them — would export an empty
        remediation record.
        """
        # exp.find.remediation_state
        mapping = finding_context_map(db_session, world["scan"])
        assert (HOST.lower(), CONFIG_TITLE.upper()) in mapping
        assert (HOST.lower(), CONFIG_DEFINITION_ID.upper()) in mapping

    def test_the_context_reaches_the_csv_cells(
        self, db_session, world, config_finding, tmp_path
    ):
        # exp.find.remediation_state  exp.find.sla  exp.fmt.csv_findings
        import csv

        from reporting.csv_generator import NETWORK_HEADERS, generate_scan_csv

        path = str(tmp_path / "enriched.csv")
        generate_scan_csv(
            _config_finding_payload(),
            path,
            scan_type="network",
            remediation_context=finding_context_map(db_session, world["scan"]),
        )

        with open(path, newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.reader(handle))

        header, row = rows[0], rows[1]
        assert row[header.index("Remediation State")] == "pending_verification"
        assert row[header.index("Overdue")] == "Yes"
        assert row[header.index("SLA State")] == "overdue"
        # The pre-existing columns still say exactly what they always said.
        assert row[NETWORK_HEADERS.index("Host")] == HOST
        assert row[NETWORK_HEADERS.index("Finding")] == CONFIG_TITLE

    def test_a_title_shared_by_two_findings_on_one_host_resolves_by_neither(
        self, db_session, world, config_finding
    ):
        """
        Showing one finding's owner and due date against its same-titled
        sibling would be worse than showing none. The identifier key still
        resolves both, so nothing is lost that can be answered correctly.
        """
        # exp.find.remediation_state
        db_session.merge(
            VulnerabilityDefinition(
                id="CCURE-CFG-CCURE-LINUX-SSH-TWIN",
                cve_id=None,
                definition_type="config_check",
                title=CONFIG_TITLE,
                description="a second check with the same title",
                severity="medium",
            )
        )
        db_session.flush()
        db_session.add(
            AssetVulnerability(
                id=f"fnd_{world['asset_id']}_cfg_twin",
                org_id=world["org_id"],
                asset_id=world["asset_id"],
                vuln_id="CCURE-CFG-CCURE-LINUX-SSH-TWIN",
                scan_id=world["scan"].id,
                severity="medium",
                status="open",
                source_family="credentialed_config",
                first_found_at=SCAN_START,
                last_found_at=SCAN_END,
                remediation_state="open",
            )
        )
        db_session.flush()

        mapping = finding_context_map(db_session, world["scan"])
        assert (HOST.lower(), CONFIG_TITLE.upper()) not in mapping
        assert (HOST.lower(), CONFIG_DEFINITION_ID.upper()) in mapping
        assert (HOST.lower(), "CCURE-CFG-CCURE-LINUX-SSH-TWIN") in mapping


# ─────────────────────────────────────────────────────────────────────────────
# GAP-13
# ─────────────────────────────────────────────────────────────────────────────


class TestComparisonExport:
    def test_the_five_classes_survive_into_the_export(self):
        """
        Every value comes from GAP-13's own classification, upper-cased for the
        sheet. Nothing here decides anything: a finding can never be exported
        as FIXED by a scan that did not assess it, because that refusal lives
        in core/findings/comparison.py and is not repeated.
        """
        # exp.cmp.classes  exp.cmp.reuse
        from core.findings import CLASSIFICATIONS
        from core.findings.comparison import FindingDelta, ScanComparison

        comparison = ScanComparison(
            current_scan_id="scn_curr",
            baseline_scan_id="scn_base",
            comparable=True,
            findings=[
                FindingDelta(
                    finding_id=f"fnd_{index}",
                    vuln_id=f"CVE-2026-{index:04d}",
                    asset_id="ast_1",
                    classification=classification,
                    severity="high",
                )
                for index, classification in enumerate(CLASSIFICATIONS)
            ],
        )

        rows = comparison_export_rows(comparison)
        changes = {row[COMPARISON_COLUMN_CHANGE] for row in rows}
        assert changes == {c.upper() for c in CLASSIFICATIONS}
        assert "NOT_ASSESSED" in changes
        assert "FIXED" in changes

    def test_the_baseline_is_named_on_every_row(self):
        # exp.cmp.baseline
        from core.findings.comparison import FindingDelta, ScanComparison

        comparison = ScanComparison(
            current_scan_id="scn_curr",
            baseline_scan_id="scn_base",
            comparable=True,
            findings=[
                FindingDelta(
                    finding_id="fnd_1",
                    vuln_id="CVE-2026-0001",
                    asset_id="ast_1",
                    classification="fixed",
                )
            ],
        )
        row = comparison_export_rows(comparison)[0]
        assert row[0] == "scn_curr"
        assert row[1] == "scn_base"

    def test_no_comparison_is_an_empty_list_not_a_row_of_zeroes(self):
        # exp.cmp.reuse
        assert comparison_export_rows(None) == []


COMPARISON_COLUMN_CHANGE = 5


# ─────────────────────────────────────────────────────────────────────────────
# Assembly
# ─────────────────────────────────────────────────────────────────────────────


class TestPayloadAssembly:
    def test_the_payload_carries_counts_that_match_its_own_rows(
        self, db_session, world, finding
    ):
        """
        The reconciliation requirement, at the smallest scale it can be
        asserted: the count the summary reports is produced from the rows that
        were exported, so a count can never agree with the source and disagree
        with the delivered file.
        """
        # exp.fmt.json  exp.comp.verdicts
        payload = export_payload(
            db_session, world["scan"], datasets=("compliance", "findings")
        )

        compliance = payload["datasets"]["compliance"]
        assert compliance["row_count"] == len(compliance["rows"])
        assert sum(compliance["verdict_counts"].values()) == compliance["row_count"]

        findings = payload["datasets"]["findings"]
        assert findings["row_count"] == len(findings["rows"]) == 1

    def test_an_absent_dataset_and_an_empty_one_are_different(self, db_session, world):
        # exp.fmt.json
        payload = export_payload(db_session, world["scan"], datasets=("findings",))
        assert "compliance" not in payload["datasets"]
        assert payload["datasets"]["findings"]["rows"] == []

        sheets = {name for name, _h, _r in workbook_sheets(payload)}
        assert "Compliance Verdicts" not in sheets
        assert "Findings" in sheets

    def test_the_summary_sheet_states_the_row_count_of_every_other_sheet(
        self, db_session, world, finding
    ):
        # exp.comp.scan_context
        payload = export_payload(
            db_session, world["scan"], datasets=("compliance", "findings")
        )
        sheets = workbook_sheets(payload)
        assert sheets[0][0] == "Summary"

        summary_rows = sheets[0][2]
        flat = {row[0]: row[1] for row in summary_rows if len(row) == 2}
        assert flat["Scan ID"] == world["scan"].id
        assert flat["Compliance"] == str(payload["datasets"]["compliance"]["row_count"])
        assert flat["Findings"] == "1"
        assert "UTC" in flat["Timestamps"]


class TestOtherCsvExportsAreUnchanged:
    """
    This phase adds columns to the findings CSV. It must not touch the other
    two CSV shapes, which answer different questions and have their own
    consumers.
    """

    def test_the_host_inventory_export_is_untouched(self, tmp_path):
        """
        A host-discovery scan produces hosts and no findings by design, so the
        findings exporter over it writes a header and nothing else. That is why
        the host inventory is a separate shape — and it must not acquire the
        remediation columns, because a host is not a finding and has no owner
        or due date.
        """
        # exp.fmt.csv_hosts  exp.find.compat
        import csv

        from reporting.csv_generator import (
            HOST_INVENTORY_HEADERS,
            REMEDIATION_HEADERS,
            generate_host_inventory_csv,
        )

        payload = {
            "data": [
                {
                    "ip_address": HOST,
                    "hostname": "export-target",
                    "is_active": True,
                    "open_ports": [
                        {"port": 22, "protocol": "tcp", "service": "ssh"},
                        {"port": 161, "protocol": "udp", "service": "snmp"},
                    ],
                }
            ]
        }
        path = str(tmp_path / "hosts.csv")
        generate_host_inventory_csv(payload, path)

        with open(path, newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.reader(handle))

        assert rows[0] == list(HOST_INVENTORY_HEADERS)
        for column in REMEDIATION_HEADERS:
            assert column not in rows[0]
        assert rows[1][HOST_INVENTORY_HEADERS.index("IP Address")] == HOST
        # The transport is part of the observation: an SNMP service on 161/udp
        # and a listener on 161/tcp are different findings.
        assert "161/udp" in rows[1][HOST_INVENTORY_HEADERS.index("Open Ports")]

    def test_the_suppressed_sidecar_is_still_written_beside_the_findings(
        self, tmp_path
    ):
        """
        The PDF appendix samples the suppressed list and refers the reader to
        this file for the complete audit trail, so the two must be produced
        together. A candidate the scanner ruled out is not a finding, and it is
        not silently dropped either.
        """
        # exp.fmt.csv_suppressed  exp.find.compat
        import csv
        import os

        from reporting.csv_generator import (
            SUPPRESSED_HEADERS,
            generate_scan_csv,
            suppressed_csv_path,
        )

        payload = {
            "data": [
                {
                    "ip_address": HOST,
                    "cves": [
                        {
                            "cve_id": CONFIG_DEFINITION_ID,
                            "cve": CONFIG_DEFINITION_ID,
                            "definition_type": "config_check",
                            "title": CONFIG_TITLE,
                            "severity": "High",
                            "description": CONFIG_TITLE,
                            "detection_method": "config_check",
                            "confidence": "Confirmed",
                            "qod": 95,
                            "source": "config_audit",
                        },
                        # No detection method and no version range, so the
                        # normalizer withholds it as unverified.
                        {
                            "cve_id": "CVE-2026-2222",
                            "cve": "CVE-2026-2222",
                            "title": "An unverified match",
                            "severity": "Medium",
                            "description": "no CPE range published",
                        },
                    ],
                }
            ]
        }
        path = str(tmp_path / "findings.csv")
        generate_scan_csv(payload, path, scan_type="network")

        sidecar = suppressed_csv_path(path)
        assert os.path.isfile(sidecar), "the suppressed sidecar must be written"
        with open(sidecar, newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.reader(handle))

        assert rows[0] == list(SUPPRESSED_HEADERS)
        assert any("CVE-2026-2222" in row for row in rows[1:])

    def test_the_web_export_keeps_its_own_column_set(self, tmp_path):
        """
        The remediation record is per host finding, not per URL, and the
        /web-scans path renders this file. Altering an existing report was not
        this phase's business.
        """
        # exp.find.compat
        import csv

        from reporting.csv_generator import (
            REMEDIATION_HEADERS,
            WEB_HEADERS,
            generate_scan_csv,
        )

        path = str(tmp_path / "web.csv")
        generate_scan_csv({"data": []}, path, scan_type="web")

        with open(path, newline="", encoding="utf-8-sig") as handle:
            header = next(csv.reader(handle))

        assert header == list(WEB_HEADERS)
        for column in REMEDIATION_HEADERS:
            assert column not in header


class TestComplianceReportSurfaceIsUnchanged:
    def test_every_framework_report_endpoint_still_exists(self):
        """
        Thirteen `/compliance/reports/*` endpoints render the governance
        deliverable. This phase adds a data export beside them and must not
        remove, rename or re-scope one — the export is an addition, not a
        replacement, and an auditor's Statement of Applicability is not a
        spreadsheet of verdicts.
        """
        # exp.fmt.compliance_docs
        from routers.compliance import router

        paths = {
            str(route.path)
            for route in router.routes
            if "/reports/" in str(getattr(route, "path", ""))
        }
        assert "/compliance/reports/soa" in paths
        assert "/compliance/reports/executive" in paths
        assert (
            len(paths) >= 13
        ), f"the compliance report surface has shrunk to {len(paths)} routes"


class TestCredentialedCsvPayload:
    """
    Found by GAP-15's real-target export validation: a credentialed scan's CSV
    download returned the **host inventory** — one row naming the machine — in
    place of the 45 findings the scan had reported, with HTTP 200 either way.

    `build_legacy_scan_results` renders the credentialed phase as
    `{"data": [{"ip_address": ...}], "report": {..., "cves": [...]}}`. The
    normalizer reads findings off the entries in `data`, finds an entry
    carrying nothing but an address, and returns zero — so `scan_has_findings`
    answered False and the branch fell through to the inventory exporter.

    The PDF path never hit it, because `_load_scan_report_paths` already
    reshapes the payload before generating.
    """

    def _payload(self, cves):
        return {
            "summary": {"scan_type": "credentialed"},
            "data": [{"ip_address": HOST}],
            "report": {"target": HOST, "cves": cves},
        }

    def _config_cve(self):
        return {
            "cve_id": CONFIG_DEFINITION_ID,
            "cve": CONFIG_DEFINITION_ID,
            "definition_type": "config_check",
            "title": CONFIG_TITLE,
            "severity": "High",
            "description": CONFIG_TITLE,
            "detection_method": "config_check",
            "confidence": "Confirmed",
            "qod": 95,
            "source": "config_audit",
        }

    def test_the_findings_reach_the_exporter(self):
        # exp.fmt.csv_findings  exp.find.compat
        from reporting.csv_generator import scan_has_findings
        from routers.reports import _flatten_credentialed_payload
        from scans.finding_normalizer import build_scan_report

        raw = self._payload([self._config_cve()])
        assert (
            scan_has_findings(raw) is False
        ), "the unreshaped payload is the defect being guarded against"

        flat = _flatten_credentialed_payload("credentialed", raw)
        assert scan_has_findings(flat) is True

        report = build_scan_report(flat)
        assert len(report.vulnerabilities) == 1
        assert report.vulnerabilities[0].host == HOST

    def test_a_multi_host_scan_attributes_each_finding_to_its_own_host(self):
        """
        `report` is the first host, kept for the consumers that predate
        multi-host support; `reports` is the complete set. Taking the first for
        every host would file one machine's findings against another.
        """
        # exp.fmt.csv_findings
        from routers.reports import _flatten_credentialed_payload
        from scans.finding_normalizer import build_scan_report

        second = dict(self._config_cve(), title="A second host's finding")
        raw = {
            "data": [{"ip_address": HOST}, {"ip_address": "10.20.30.41"}],
            "report": {"target": HOST, "cves": [self._config_cve()]},
            "reports": [
                {"target": HOST, "cves": [self._config_cve()]},
                {"target": "10.20.30.41", "cves": [second]},
            ],
        }
        flat = _flatten_credentialed_payload("credentialed", raw)
        report = build_scan_report(flat)

        by_host = {f.host: f.plugin_name for f in report.vulnerabilities}
        assert by_host[HOST] == CONFIG_TITLE
        assert by_host["10.20.30.41"] == "A second host's finding"

    def test_every_other_phase_is_returned_untouched(self):
        """
        Phase 1, 2 and 3 payloads already carry their findings on the host
        entries. Reshaping them would be a change to an export this phase was
        told to preserve.
        """
        # exp.find.compat
        from routers.reports import _flatten_credentialed_payload

        payload = {"data": [{"ip_address": HOST, "cves": [{"cve_id": "CVE-2026-1"}]}]}
        assert _flatten_credentialed_payload("phase2", payload) is payload
        assert _flatten_credentialed_payload("phase1", payload) is payload

    def test_a_payload_with_no_report_is_returned_untouched(self):
        # exp.find.compat
        from routers.reports import _flatten_credentialed_payload

        payload = {"data": [{"ip_address": HOST}]}
        assert _flatten_credentialed_payload("credentialed", payload) is payload

    def test_a_report_with_no_host_list_still_exports_its_findings(self):
        """
        No address is a reason to synthesise one from the report's own target,
        not a reason to lose the findings.
        """
        # exp.fmt.csv_findings
        from reporting.csv_generator import scan_has_findings
        from routers.reports import _flatten_credentialed_payload

        raw = {"data": [], "report": {"target": HOST, "cves": [self._config_cve()]}}
        flat = _flatten_credentialed_payload("credentialed", raw)
        assert flat["data"][0]["ip_address"] == HOST
        assert scan_has_findings(flat) is True
