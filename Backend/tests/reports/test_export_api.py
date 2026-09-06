"""
tests/reports/test_export_api.py
─────────────────────────────────────────────────────────────────────────────
The export endpoints (GAP-15).

Every test that asks for a file **opens the bytes that came back** and reads
the cells or the rows out of them. A 200 with the right Content-Type proves the
route was reached; it proves nothing about whether the workbook contains the
verdicts, whether the states survived, or whether the response is quietly a PDF
with a spreadsheet's media type on it — which is the exact defect this phase
was asked to remove.

The property under defence
──────────────────────────
**A caller gets the format they asked for, only for a scan they may read, and
only for their own organisation.** An unsupported format is refused rather than
swapped; another tenant's scan is a 404 whatever id is named.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timedelta, timezone

import pytest

openpyxl = pytest.importorskip("openpyxl")

from auth.jwt_handler import create_access_token  # noqa: E402
from db.models import Organization, Permission, Role, RolePermission, User  # noqa: E402
from db.models.assets import Asset  # noqa: E402
from db.models.findings import AssetVulnerability, VulnerabilityDefinition  # noqa: E402
from db.models.scans import Scan, ScanPhase  # noqa: E402

XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

SCAN_START = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
SCAN_END = SCAN_START + timedelta(minutes=10)
HOST = "10.44.55.66"

#: A check title carrying a leading "=", which a spreadsheet executes on open
#: unless the cell is marked as text. Benchmark content and host configuration
#: are exactly where such a string arrives from.
HOSTILE_TITLE = "=cmd|'/c calc'!A1"

#: The minted catalogue identifier for the configuration check whose title
#: is above. Built with the product's own minting function rather than typed
#: out, because the join this exercises depends on the payload and the
#: catalogue agreeing on it.
from core.config_audit.findings import config_definition_id  # noqa: E402

#: Deliberately not the identifier tests/reports/test_export_datasets.py mints.
#: `vulnerability_definitions` is a global catalogue and outlives the per-test
#: purge, which is scoped to an organisation's own rows — so two modules minting
#: one id with different titles leave whichever ran first in the table, and the
#: other module's title-based assertions then read a title it never wrote.
CONFIG_DEFINITION_ID = config_definition_id(
    "ccure.export.api.hostile_title", "config_check"
)


def _grant(db_session, role: Role, resource: str, action: str) -> None:
    permission = (
        db_session.query(Permission)
        .filter(Permission.resource == resource, Permission.action == action)
        .first()
    )
    if permission is None:
        permission = Permission(
            resource=resource, action=action, description=f"{resource}:{action}"
        )
        db_session.add(permission)
        db_session.flush()
    link = (
        db_session.query(RolePermission)
        .filter(
            RolePermission.role_id == role.id,
            RolePermission.permission_id == permission.id,
        )
        .first()
    )
    if link is None:
        db_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
        db_session.flush()


def _headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
        role=getattr(user.role, "name", None),
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


def _result(check_id: str, outcome: str, title: str, **kw) -> dict:
    return {
        "check_id": check_id,
        "outcome": outcome,
        "title": title,
        "severity": kw.get("severity", "high"),
        "target": HOST,
        "evidence": [
            {
                "collector": "linux_file",
                "description": title,
                "expected": "PermitRootLogin no",
                "observed": "yes",
                "raw": "CCURE::VALUE::yes",
            }
        ],
        "remediation": "Set the directive and restart.",
        "references": [],
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
    Two organisations. The first has a completed credentialed scan carrying
    configuration verdicts and one finding; the second exists so cross-tenant
    access has something real to fail against.
    """
    suffix = uuid.uuid4().hex[:8]

    org = Organization(
        id=f"org_exp_{suffix}",
        name="Export API Co",
        slug=f"exp-api-{suffix}",
        max_assets=100,
        max_users=10,
        is_active=True,
        settings={},
    )
    other_org = Organization(
        id=f"org_oth_{suffix}",
        name="Other API Co",
        slug=f"oth-api-{suffix}",
        max_assets=100,
        max_users=10,
        is_active=True,
        settings={},
    )
    reader_role = Role(
        name=f"exp_reader_{suffix}", description="reports:read", is_system_role=False
    )
    blind_role = Role(
        name=f"exp_blind_{suffix}", description="no reports", is_system_role=False
    )
    db_session.add_all([org, other_org, reader_role, blind_role])
    db_session.flush()

    _grant(db_session, reader_role, "reports", "read")
    _grant(db_session, reader_role, "scans", "read_all")

    reader = User(
        username=f"exp-reader-{suffix}",
        email=f"exp-reader-{suffix}@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=reader_role.id,
        is_active=True,
        is_verified=True,
    )
    blind = User(
        username=f"exp-blind-{suffix}",
        email=f"exp-blind-{suffix}@test.com",
        password_hash="hash",
        org_id=org.id,
        role_id=blind_role.id,
        is_active=True,
        is_verified=True,
    )
    outsider = User(
        username=f"exp-out-{suffix}",
        email=f"exp-out-{suffix}@test.com",
        password_hash="hash",
        org_id=other_org.id,
        role_id=reader_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([reader, blind, outsider])
    db_session.flush()

    asset = Asset(
        id=f"ast_{org.id}_10_44_55_66",
        org_id=org.id,
        ip_address=HOST,
        hostname="export-api-target",
        last_seen_at=SCAN_END,
    )
    db_session.add(asset)

    scan = Scan(
        id=f"scn_expapi_{suffix}",
        org_id=org.id,
        created_by=str(reader.id),
        scan_no=77,
        target_str=HOST,
        target_hosts=[],
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
        _result("ccure.linux.ssh.permit_root_login", "fail", HOSTILE_TITLE),
        _result("ccure.linux.ssh.protocol", "pass", "SSH protocol 2 only"),
        _result(
            "ccure.win.uac.enabled",
            "not_applicable",
            "UAC is enabled",
            metadata={
                "domain": "host_configuration",
                "check_type": "registry",
                "not_applicable_reason": "check targets windows; this host is linux",
            },
        ),
        _result(
            "ccure.linux.audit.rules", "manual_review", "Audit rules are configured"
        ),
        _result(
            "ccure.linux.file_caps",
            "error",
            "File capabilities are enumerated",
            error="getcap is not installed",
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
                "_phase_data": [
                    {
                        "ip_address": HOST,
                        # A credentialed scan merges the audit's FAIL results
                        # into the host's own `cves` list — that is what makes
                        # them ordinary findings. Without it `scan_has_findings`
                        # is correctly False and the CSV branch exports the host
                        # inventory instead, which is a different deliverable.
                        "cves": [
                            {
                                "cve_id": CONFIG_DEFINITION_ID,
                                "cve": CONFIG_DEFINITION_ID,
                                "definition_type": "config_check",
                                "title": HOSTILE_TITLE,
                                "severity": "High",
                                "description": HOSTILE_TITLE,
                                "desc": HOSTILE_TITLE,
                                "detection_method": "config_check",
                                "confidence": "Confirmed",
                                "qod": 95,
                                "evidence": "Expected: PermitRootLogin no",
                                "remediation": "Set the directive and restart.",
                                "source": "config_audit",
                            }
                        ],
                        "credentialed_report": {
                            "target": HOST,
                            "config_audit": {
                                "assessed": True,
                                "platform": "linux",
                                "checks_run": len(results),
                                "checks_assessed": 2,
                                "results": results,
                            },
                        },
                    }
                ]
            },
        )
    )

    # The catalogue is global and outlives the per-test purge, which is scoped
    # to an organisation's own rows. Get-or-create rather than insert, so a
    # second test in the same session does not collide on the primary key.
    if (
        db_session.query(VulnerabilityDefinition)
        .filter(VulnerabilityDefinition.id == "CVE-2026-7777")
        .first()
        is None
    ):
        db_session.add(
            VulnerabilityDefinition(
                id="CVE-2026-7777",
                cve_id="CVE-2026-7777",
                definition_type="cve",
                title="An export-visible flaw",
                description="fixture",
                severity="high",
            )
        )
    db_session.flush()
    if (
        db_session.query(VulnerabilityDefinition)
        .filter(VulnerabilityDefinition.id == CONFIG_DEFINITION_ID)
        .first()
        is None
    ):
        db_session.add(
            VulnerabilityDefinition(
                id=CONFIG_DEFINITION_ID,
                cve_id=None,
                definition_type="config_check",
                title=HOSTILE_TITLE,
                description=HOSTILE_TITLE,
                severity="high",
            )
        )
        db_session.flush()
    db_session.add(
        AssetVulnerability(
            id=f"fnd_{asset.id}_cfg",
            org_id=org.id,
            asset_id=asset.id,
            vuln_id=CONFIG_DEFINITION_ID,
            scan_id=scan.id,
            severity="high",
            status="open",
            source_family="credentialed_config",
            first_found_at=SCAN_START,
            last_found_at=SCAN_END,
            remediation_state="pending_verification",
            sla_due_at=SCAN_START - timedelta(days=2),
            sla_basis="high",
        )
    )
    db_session.add(
        AssetVulnerability(
            id=f"fnd_{asset.id}_CVE-2026-7777",
            org_id=org.id,
            asset_id=asset.id,
            vuln_id="CVE-2026-7777",
            scan_id=scan.id,
            severity="high",
            status="open",
            source_family="credentialed_package",
            first_found_at=SCAN_START,
            last_found_at=SCAN_END,
            remediation_state="in_remediation",
            sla_due_at=SCAN_START - timedelta(days=3),
            sla_basis="high",
        )
    )

    other_scan = Scan(
        id=f"scn_other_{suffix}",
        org_id=other_org.id,
        created_by=str(outsider.id),
        scan_no=1,
        target_str="10.99.99.99",
        target_hosts=[],
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        created_at=SCAN_START,
        started_at=SCAN_START,
        completed_at=SCAN_END,
        options={},
    )
    db_session.add(other_scan)
    db_session.commit()
    db_session.refresh(reader)
    db_session.refresh(blind)
    db_session.refresh(outsider)

    return {
        "scan": scan,
        "other_scan": other_scan,
        "reader": reader,
        "blind": blind,
        "outsider": outsider,
    }


def _load_workbook(response):
    return openpyxl.load_workbook(io.BytesIO(response.content))


# ─────────────────────────────────────────────────────────────────────────────
# The format contract
# ─────────────────────────────────────────────────────────────────────────────


class TestDownloadFormats:
    def test_fmt_xlsx_returns_a_real_workbook(self, client, world):
        """
        ``?fmt=XLSX`` used to be a 400 because there was no Excel exporter, and
        before that it fell through to the executive PDF with HTTP 200 — so a
        caller writing the bytes to a .xlsx file got something Excel refuses to
        open, with nothing anywhere saying why.
        """
        # exp.fmt.xlsx  exp.api.format_param
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt=XLSX",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == XLSX_MEDIA_TYPE
        assert not response.content.startswith(
            b"%PDF"
        ), "an XLSX request must never be answered with a PDF"
        assert response.content[:2] == b"PK", "an .xlsx is a ZIP archive"

        workbook = _load_workbook(response)
        assert "Summary" in workbook.sheetnames
        assert "Compliance Verdicts" in workbook.sheetnames
        assert "Findings" in workbook.sheetnames

    @pytest.mark.parametrize("alias", ["xlsx", "XLSX", "excel", "Workbook"])
    def test_the_spelling_of_the_format_does_not_matter(self, client, world, alias):
        # exp.api.format_param
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt={alias}",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == XLSX_MEDIA_TYPE

    @pytest.mark.parametrize("bad", ["ODS", "sarif", "html", "docx", ""])
    def test_an_unsupported_format_is_refused_never_swapped(self, client, world, bad):
        """
        The refusal is the feature. Falling through to a PDF with HTTP 200 is
        what made a broken Excel export look like a working one.
        """
        # exp.api.no_silent_fallback
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt={bad}",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 400
        assert not response.content.startswith(b"%PDF")
        assert "Unsupported report format" in response.json()["detail"]
        assert "XLSX" in response.json()["detail"]

    def test_the_existing_pdf_formats_are_untouched(self, client, world):
        """
        This phase adds a format; it must not change one. Both PDF names still
        resolve to their own report and neither becomes a workbook.
        """
        # exp.fmt.pdf_exec  exp.fmt.pdf_tech
        for fmt in ("JSON", "XML", "executive", "technical"):
            response = client.get(
                f"/reports/download/{world['scan'].id}?fmt={fmt}",
                headers=_headers(world["reader"]),
            )
            # This scan stores no PDF and has no phase payload the generator
            # can rebuild one from, so the honest answer is 404 — the point is
            # that it is never an XLSX and never a 400.
            assert response.status_code in (200, 404)
            assert response.headers.get("content-type") != XLSX_MEDIA_TYPE

    def test_the_csv_download_still_works_and_now_carries_remediation(
        self, client, world
    ):
        # exp.fmt.csv_findings  exp.find.remediation_state
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt=CSV",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")

        rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
        header = rows[0]
        assert header[0] == "Host", "the pre-existing columns keep their positions"
        assert "Remediation State" in header
        assert "SLA Due" in header

        assert len(rows) == 2, "the finding must survive into the export"
        row = rows[1]
        assert row[header.index("Host")] == HOST
        assert row[header.index("Remediation State")] == "pending_verification"
        assert row[header.index("Overdue")] == "Yes"


# ─────────────────────────────────────────────────────────────────────────────
# Contents
# ─────────────────────────────────────────────────────────────────────────────


class TestWorkbookContents:
    def test_every_verdict_state_reaches_the_sheet(self, client, world):
        # exp.comp.states  exp.comp.verdicts
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt=XLSX",
            headers=_headers(world["reader"]),
        )
        sheet = _load_workbook(response)["Compliance Verdicts"]
        header = [c.value for c in sheet[1]]
        verdicts = {
            row[header.index("Verdict")].value for row in sheet.iter_rows(min_row=2)
        }

        assert verdicts == {
            "PASS",
            "FAIL",
            "NOT_APPLICABLE",
            "MANUAL_REVIEW",
            "ERROR",
        }

    def test_a_hostile_check_title_cannot_become_a_formula(self, client, world):
        """
        The title came off loaded benchmark content. Opened in Excel without
        this, the cell is executed.
        """
        # exp.xl.formula_injection
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt=XLSX",
            headers=_headers(world["reader"]),
        )
        sheet = _load_workbook(response)["Compliance Verdicts"]
        header = [c.value for c in sheet[1]]
        titles = [
            row[header.index("Title")].value for row in sheet.iter_rows(min_row=2)
        ]
        hostile = [t for t in titles if t and "cmd|" in t]
        assert hostile, "the fixture's hostile title must be present"
        for value in hostile:
            assert value.startswith("'"), f"unescaped formula in a cell: {value!r}"

    def test_the_findings_sheet_carries_the_remediation_record(self, client, world):
        # exp.find.remediation_state  exp.find.sla
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt=XLSX",
            headers=_headers(world["reader"]),
        )
        sheet = _load_workbook(response)["Findings"]
        header = [c.value for c in sheet[1]]
        rows = {
            row[header.index("Identifier")]: row
            for row in sheet.iter_rows(min_row=2, values_only=True)
        }

        cve_row = rows["CVE-2026-7777"]
        assert cve_row[header.index("Remediation State")] == "in_remediation"
        assert cve_row[header.index("Overdue")] == "Yes"
        assert cve_row[header.index("Definition Type")] == "cve"

        # The configuration finding beside it, which is the kind the benchmark
        # content produces and the kind with no CVE at all.
        config_row = rows[CONFIG_DEFINITION_ID]
        assert config_row[header.index("Definition Type")] == "config_check"
        assert config_row[header.index("Remediation State")] == "pending_verification"

    def test_the_summary_sheet_names_the_scan_and_counts_the_rest(self, client, world):
        # exp.comp.scan_context
        response = client.get(
            f"/reports/download/{world['scan'].id}?fmt=XLSX",
            headers=_headers(world["reader"]),
        )
        workbook = _load_workbook(response)
        summary = {
            row[0]: row[1] for row in workbook["Summary"].iter_rows(values_only=True)
        }
        assert summary["Scan ID"] == world["scan"].id
        assert summary["Organization"] == "Export API Co"
        assert summary["Compliance"] == "5"
        assert summary["Findings"] == "2"


# ─────────────────────────────────────────────────────────────────────────────
# The export endpoint
# ─────────────────────────────────────────────────────────────────────────────


class TestExportEndpoint:
    def test_json_returns_the_columns_and_the_rows(self, client, world):
        # exp.fmt.json
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=json&dataset=compliance",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        block = payload["datasets"]["compliance"]

        assert block["columns"][0] == "Scan ID"
        assert block["row_count"] == len(block["rows"]) == 5
        assert sum(block["verdict_counts"].values()) == 5
        assert payload["scan"]["scan_id"] == world["scan"].id

    def test_csv_returns_one_named_dataset(self, client, world):
        # exp.api.filters
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=csv&dataset=findings",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")

        rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
        assert rows[0][0] == "Finding ID"
        assert len(rows) == 3

    def test_csv_with_every_dataset_is_refused_rather_than_guessed(self, client, world):
        """
        A CSV is one table. Exporting whichever happened to be first would be a
        silent choice about what the caller receives.
        """
        # exp.api.no_silent_fallback
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=csv&dataset=all",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 400
        assert "one table" in response.json()["detail"]

    @pytest.mark.parametrize("bad", ["ods", "pdf", "sarif"])
    def test_an_unsupported_export_format_is_refused(self, client, world, bad):
        # exp.api.no_silent_fallback
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt={bad}",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 400
        assert "Unsupported export format" in response.json()["detail"]

    def test_an_unknown_dataset_is_refused(self, client, world):
        # exp.api.filters
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=json&dataset=everything",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 400
        assert "Unknown dataset" in response.json()["detail"]

    def test_a_verdict_filter_narrows_the_rows_and_not_the_states(self, client, world):
        # exp.api.filters  exp.comp.states
        response = client.get(
            f"/reports/export/{world['scan'].id}"
            "?fmt=json&dataset=compliance&verdict=FAIL&verdict=ERROR",
            headers=_headers(world["reader"]),
        )
        block = response.json()["datasets"]["compliance"]
        assert set(block["verdict_counts"]) == {"FAIL", "ERROR"}
        assert block["row_count"] == 2

    def test_a_filter_that_matches_nothing_is_an_empty_dataset_not_an_error(
        self, client, world
    ):
        """
        Zero rows is an answer. A 404 here would make "nothing matched" look
        like "the scan does not exist".
        """
        # exp.api.filters
        response = client.get(
            f"/reports/export/{world['scan'].id}"
            "?fmt=json&dataset=findings&severity=critical",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200
        assert response.json()["datasets"]["findings"]["rows"] == []

    def test_the_comparison_dataset_carries_gap13_classes(self, client, world):
        """
        The scan has no earlier sibling, so the comparison is legitimately
        absent — and the dataset says so with a reason rather than shipping a
        table of zeroes that reads as "nothing changed".
        """
        # exp.cmp.classes  exp.cmp.reuse  exp.cmp.baseline
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=json&dataset=comparison",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200
        block = response.json()["datasets"]["comparison"]
        assert block["rows"] == []
        assert block["comparable"] is False

    def test_a_named_baseline_in_another_organisation_is_a_404(self, client, world):
        """
        A baseline is a second scan, so it needs the same visibility check as
        the first. Without it, naming another tenant's scan as a baseline is a
        cross-tenant read wearing a query parameter.
        """
        # exp.api.tenant_isolation  exp.cmp.baseline
        response = client.get(
            f"/reports/export/{world['scan'].id}"
            f"?fmt=json&dataset=comparison&baseline={world['other_scan'].id}",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Authorisation
# ─────────────────────────────────────────────────────────────────────────────


class TestExportAuthorisation:
    @pytest.mark.parametrize(
        "path", ["/reports/download/{sid}?fmt=XLSX", "/reports/export/{sid}?fmt=json"]
    )
    def test_reports_read_is_required(self, client, world, path):
        # exp.api.rbac
        response = client.get(
            path.format(sid=world["scan"].id), headers=_headers(world["blind"])
        )
        assert response.status_code == 403
        assert "reports:read" in response.json()["detail"]

    @pytest.mark.parametrize(
        "path", ["/reports/download/{sid}?fmt=XLSX", "/reports/export/{sid}?fmt=json"]
    )
    def test_another_organisations_scan_is_not_exportable(self, client, world, path):
        """
        404 rather than 403, deliberately: a 403 would confirm the id exists.
        """
        # exp.api.tenant_isolation
        response = client.get(
            path.format(sid=world["scan"].id), headers=_headers(world["outsider"])
        )
        assert response.status_code == 404

    def test_an_unknown_scan_id_is_a_404(self, client, world):
        # exp.api.tenant_isolation
        response = client.get(
            "/reports/export/scn_does_not_exist?fmt=json",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 404

    def test_an_anonymous_caller_gets_nothing(self, client, world):
        # exp.api.rbac
        response = client.get(f"/reports/export/{world['scan'].id}?fmt=json")
        assert response.status_code in (401, 403)

    def test_a_failed_scan_exports_nothing_rather_than_an_empty_file(
        self, client, db_session, world
    ):
        """
        A 200 carrying a header row and nothing else makes a failed scan look
        like a successful download of a clean estate.
        """
        # exp.api.no_silent_fallback
        world["scan"].status = "failed"
        world["scan"].failure_reason = "the credential was refused"
        db_session.commit()

        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=json",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 404
        assert "credential was refused" in response.json()["detail"]

    def test_the_generated_filename_carries_nothing_a_caller_controls(
        self, client, world
    ):
        """
        ``filename=`` lands in a response header, where a quote or a newline is
        a header-injection primitive rather than a cosmetic problem. The name
        is built from product-minted identifiers and filtered anyway.
        """
        # exp.api.rbac
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=xlsx&dataset=compliance",
            headers=_headers(world["reader"]),
        )
        disposition = response.headers.get("content-disposition", "")
        assert "scan_77_" in disposition
        assert "compliance.xlsx" in disposition
        for forbidden in ("\n", "\r", "/", "\\", ".."):
            assert forbidden not in disposition


# ─────────────────────────────────────────────────────────────────────────────
# Bounds
# ─────────────────────────────────────────────────────────────────────────────


def test_both_export_routes_are_rate_limited():
    """
    Assembling verdict rows, finding rows and an unbounded comparison, then
    writing a file, is not a cheap request. `conftest` disables the limiter for
    the suite, so registration is asserted against the limiter's own table —
    exercising a 429 here would prove only that the limiter is off.
    """
    # exp.api.rate_limit
    from scan_helpers import limiter

    registered = {
        key.split(".")[-1] for key in (getattr(limiter, "_route_limits", {}) or {})
    }
    endpoints = {
        f"{r.endpoint.__module__}.{r.endpoint.__name__}"
        for r in __import__("routers.reports", fromlist=["router"]).router.routes
        if getattr(r, "endpoint", None) is not None
    }
    assert any("download_report" in e for e in endpoints)
    assert any("export_scan_dataset" in e for e in endpoints)

    limits = getattr(limiter, "_route_limits", {}) or {}
    joined = " ".join(limits.keys())
    assert "download_report" in joined or "download_report" in registered
    assert "export_scan_dataset" in joined or "export_scan_dataset" in registered


class TestExportAuditTrail:
    def test_an_export_that_leaves_the_platform_is_recorded(
        self, client, db_session, world
    ):
        """
        An export is a copy of the organisation's assessment results leaving
        the platform, so it belongs in the audit trail for the same reason a
        report download does. The action names the dataset and the format,
        because "somebody exported something" is not an audit record.

        Note the shape this replaces: the download endpoint's audit call used
        to construct AuditLog inline with a name never imported into the
        module, and a bare `except: pass` swallowed the NameError — so no
        report download ever produced an audit row.
        """
        # exp.api.audit
        from db.models import AuditLog

        before = (
            db_session.query(AuditLog)
            .filter(AuditLog.resource_id == world["scan"].id)
            .count()
        )

        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=json&dataset=compliance",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 200

        rows = (
            db_session.query(AuditLog)
            .filter(AuditLog.resource_id == world["scan"].id)
            .all()
        )
        assert len(rows) > before
        actions = {r.action for r in rows}
        assert "report.downloaded" in actions

        changes = [r.changes for r in rows if r.action == "report.downloaded"]
        assert any(
            "export:compliance:json" == (c or {}).get("format") for c in changes
        ), f"the audit entry must name the dataset and the format; got {changes}"

    def test_a_refused_export_is_not_recorded_as_a_download(
        self, client, db_session, world
    ):
        """
        A 400 delivered nothing, so an audit row claiming a download would be a
        false record of data leaving the platform.
        """
        # exp.api.audit
        from db.models import AuditLog

        before = (
            db_session.query(AuditLog)
            .filter(AuditLog.resource_id == world["scan"].id)
            .count()
        )
        response = client.get(
            f"/reports/export/{world['scan'].id}?fmt=ods",
            headers=_headers(world["reader"]),
        )
        assert response.status_code == 400
        after = (
            db_session.query(AuditLog)
            .filter(AuditLog.resource_id == world["scan"].id)
            .count()
        )
        assert after == before
