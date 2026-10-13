"""
tests/scans/test_finding_comparison.py
─────────────────────────────────────────────────────────────────────────────
Scan-to-scan finding comparison (GAP-13).

These drive `compare_scans` against **real rows** — real `Scan`, `Asset` and
`AssetVulnerability` records with real lifecycle timestamps — rather than
mocks, because the whole mechanism is a statement about what those timestamps
mean. A mocked row would prove the branch was taken and nothing about whether
the reconstruction is right.

The property under defence
──────────────────────────
A finding is **never** reported fixed because it was absent from a scan. It is
reported fixed only when the scan that could have found it looked and did not.
On a real Windows host, 126 STIG findings are absent from `cve_list` when the
audit passes *and* when the audit never ran; only the recorded assessment scope
tells those apart. Get it wrong and the report tells somebody a vulnerability
was remediated when a credential expired.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from core.findings import (
    CLASS_FIXED,
    CLASS_NEW,
    CLASS_NOT_ASSESSED,
    CLASS_REAPPEARED,
    CLASS_STILL_OPEN,
    compare_scans,
    read_assessment_scope,
    record_assessment_scope,
)
from db.models.assets import Asset
from db.models.findings import AssetVulnerability, VulnerabilityDefinition
from db.models.rbac import Organization
from db.models.scans import Scan

FAMILY = "credentialed_package"


def _utc(offset_minutes: int) -> datetime:
    """A deterministic clock: T0 is the baseline, later offsets are the present."""
    return datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc) + timedelta(
        minutes=offset_minutes
    )


BASELINE_START = _utc(0)
BASELINE_END = _utc(10)
CURRENT_START = _utc(60)
CURRENT_END = _utc(70)


@pytest.fixture()
def world(db_session):
    """An organisation, one asset, and two completed scans ten minutes apart."""
    org_id = f"org_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name="Cmp",
            slug=f"cmp-{uuid.uuid4().hex[:8]}",
            is_active=True,
            settings={},
        )
    )
    db_session.flush()

    asset_id = f"ast_{org_id}_10_0_0_1"
    db_session.add(
        Asset(
            id=asset_id,
            org_id=org_id,
            ip_address="10.0.0.1",
            last_seen_at=CURRENT_END,
        )
    )

    baseline = Scan(
        id=f"scn_base_{uuid.uuid4().hex[:8]}",
        org_id=org_id,
        target_str="10.0.0.1",
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        created_at=BASELINE_START,
        started_at=BASELINE_START,
        completed_at=BASELINE_END,
    )
    current = Scan(
        id=f"scn_curr_{uuid.uuid4().hex[:8]}",
        org_id=org_id,
        target_str="10.0.0.1",
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        created_at=CURRENT_START,
        started_at=CURRENT_START,
        completed_at=CURRENT_END,
    )
    db_session.add_all([baseline, current])
    db_session.flush()

    # Both scans looked at this asset for this family, unless a test says
    # otherwise.
    for scan in (baseline, current):
        record_assessment_scope(scan, assets=[asset_id], families=[FAMILY])
    db_session.flush()

    return {
        "org_id": org_id,
        "asset_id": asset_id,
        "baseline": baseline,
        "current": current,
    }


def _definition(db_session, vuln_id: str) -> None:
    """
    `asset_vulnerabilities.vuln_id` is a foreign key into the catalogue, so a
    finding cannot exist without its definition. Created once per id.
    """
    if db_session.query(VulnerabilityDefinition).filter_by(id=vuln_id).first():
        return
    db_session.add(
        VulnerabilityDefinition(
            id=vuln_id,
            # `ck_vuln_def_cve_id_matches_type` requires a `cve` row to carry a
            # cve_id and a check row not to.
            cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
            definition_type="cve" if vuln_id.startswith("CVE-") else "config_check",
            title=f"Fixture {vuln_id}",
            description="fixture",
            severity="high",
        )
    )
    db_session.flush()


def _finding(
    db_session,
    world,
    vuln_id: str,
    *,
    status: str,
    first_found: datetime,
    last_found: datetime,
    fixed_at: datetime | None = None,
    severity: str = "high",
    family: str = FAMILY,
) -> AssetVulnerability:
    _definition(db_session, vuln_id)
    return AssetVulnerability(
        id=f"fnd_{world['asset_id']}_{vuln_id}_{family}",
        org_id=world["org_id"],
        asset_id=world["asset_id"],
        vuln_id=vuln_id,
        scan_id=world["current"].id,
        severity=severity,
        status=status,
        source_family=family,
        first_found_at=first_found,
        last_found_at=last_found,
        fixed_at=fixed_at,
    )


def _compare(db_session, world, **kw):
    return compare_scans(
        db_session, current=world["current"], baseline=world["baseline"], **kw
    )


# ─────────────────────────────────────────────────────────────────────────────
# The four classes
# ─────────────────────────────────────────────────────────────────────────────


class TestClassification:
    def test_a_finding_open_in_both_scans_is_still_open(self, db_session, world):
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0001",
                status="open",
                first_found=BASELINE_START,
                last_found=CURRENT_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_STILL_OPEN] == 1
        assert result.counts[CLASS_NEW] == 0

    def test_a_finding_first_seen_by_the_current_scan_is_new(self, db_session, world):
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0002",
                status="open",
                first_found=CURRENT_START,
                last_found=CURRENT_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_NEW] == 1
        assert result.counts[CLASS_STILL_OPEN] == 0

    def test_a_finding_the_current_scan_looked_for_and_did_not_find_is_fixed(
        self, db_session, world
    ):
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0003",
                status="fixed",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
                fixed_at=CURRENT_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_FIXED] == 1

    def test_a_finding_fixed_at_the_baseline_and_open_now_has_reappeared(
        self, db_session, world
    ):
        """The unambiguous regression: fixed during the baseline, back now."""
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0004",
                status="open",
                first_found=_utc(-100),
                last_found=CURRENT_END,
                fixed_at=_utc(5),  # fixed inside the baseline's own window
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_REAPPEARED] == 1
        assert result.counts[CLASS_NEW] == 0, (
            "a finding that has come back is not a new one; folding them "
            "together hides the regression"
        )

    def test_a_fix_predating_the_baseline_reads_as_unchanged_not_a_regression(
        self, db_session, world
    ):
        """
        The ambiguous case, and the reading is deliberate.

        `fixed_at` holds only the most recent fix and is not cleared when a
        finding returns, so a CVE fixed two scans ago and open ever since still
        carries that timestamp. Read as a regression it is reported as one on
        every subsequent scan forever — measured on the disposable target,
        where four curl CVEs were correctly flagged reappeared once and then
        wrongly flagged again on the next comparison.

        Since the finding is open now and its fix predates the baseline, it must
        have returned at or before the baseline, so the baseline saw it open.
        The cost is that a regression which happened *between* an old fix and
        the baseline is reported as unchanged rather than as a regression — a
        single under-report, against crying wolf indefinitely.
        """
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0044",
                status="open",
                first_found=_utc(-100),
                last_found=CURRENT_END,
                fixed_at=_utc(-50),  # fixed before the baseline even started
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_STILL_OPEN] == 1
        assert result.counts[CLASS_REAPPEARED] == 0


# ─────────────────────────────────────────────────────────────────────────────
# The rule this exists for
# ─────────────────────────────────────────────────────────────────────────────


class TestAbsenceIsNotAFix:
    def test_absent_without_an_assessed_scope_is_not_assessed_not_fixed(
        self, db_session, world
    ):
        """
        The scan did not look at this family. The finding is absent from it and
        must not be reported fixed.
        """
        # Cleared first: `record_assessment_scope` merges by design, because one
        # scan records from several paths. Adding here would leave the original
        # family in place and the finding would be correctly reported fixed.
        world["current"].options = {}
        record_assessment_scope(
            world["current"], assets=[world["asset_id"]], families=["some_other_family"]
        )
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0005",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_NOT_ASSESSED] == 1
        assert result.counts[CLASS_FIXED] == 0

    def test_absent_on_a_host_this_scan_never_reached_is_not_assessed(
        self, db_session, world
    ):
        world["current"].options = {}
        record_assessment_scope(
            world["current"], assets=["ast_some_other_host"], families=[FAMILY]
        )
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0006",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world, asset_ids=[world["asset_id"]])
        assert result.counts[CLASS_FIXED] == 0
        assert result.counts[CLASS_NOT_ASSESSED] == 1

    def test_a_scan_with_no_recorded_scope_can_never_report_a_fix(
        self, db_session, world
    ):
        """
        Scans predating this phase recorded nothing. Unknown reach must not be
        read as "assessed everything", which is the reading that invents fixes.
        """
        world["current"].options = {}
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0007",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_FIXED] == 0
        assert result.counts[CLASS_NOT_ASSESSED] == 1
        assert "no assessment scope" in result.reason

    def test_the_summary_line_names_the_not_assessed_count(self, db_session, world):
        world["current"].options = {}
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0008",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        db_session.flush()
        line = _compare(db_session, world).summary_line()
        assert "not assessed" in line, (
            "a reader told '0 fixed' and not told '1 not assessed' has been "
            "given a number that implies the scan established something"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Scans that should not be compared
# ─────────────────────────────────────────────────────────────────────────────


class TestComparability:
    def test_identical_consecutive_scans_report_no_change(self, db_session, world):
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-0009",
                status="open",
                first_found=BASELINE_START,
                last_found=CURRENT_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_NEW] == 0
        assert result.counts[CLASS_FIXED] == 0
        assert result.counts[CLASS_REAPPEARED] == 0
        assert result.counts[CLASS_STILL_OPEN] == 1

    def test_a_baseline_that_finished_after_the_current_scan_began_is_refused(
        self, db_session, world
    ):
        world["baseline"].completed_at = _utc(90)
        db_session.flush()
        result = _compare(db_session, world)
        assert result.comparable is False
        assert "baseline" in result.reason

    def test_scans_from_two_organisations_are_refused(self, db_session, world):
        other = f"org_{uuid.uuid4().hex[:8]}"
        db_session.add(
            Organization(
                id=other,
                name="Other",
                slug=f"o-{uuid.uuid4().hex[:8]}",
                is_active=True,
                settings={},
            )
        )
        world["baseline"].org_id = other
        db_session.flush()
        result = _compare(db_session, world)
        assert result.comparable is False
        assert "organisation" in result.reason


# ─────────────────────────────────────────────────────────────────────────────
# Tenant isolation and scale
# ─────────────────────────────────────────────────────────────────────────────


class TestIsolationAndScale:
    def test_another_tenants_findings_never_enter_the_comparison(
        self, db_session, world
    ):
        stranger = f"org_{uuid.uuid4().hex[:8]}"
        db_session.add(
            Organization(
                id=stranger,
                name="Stranger",
                slug=f"s-{uuid.uuid4().hex[:8]}",
                is_active=True,
                settings={},
            )
        )
        db_session.flush()
        _definition(db_session, "CVE-2024-9999")
        db_session.add(
            AssetVulnerability(
                id=f"fnd_stranger_{uuid.uuid4().hex[:6]}",
                org_id=stranger,
                asset_id=world["asset_id"],  # same asset id, different tenant
                vuln_id="CVE-2024-9999",
                scan_id=world["current"].id,
                severity="critical",
                status="open",
                source_family=FAMILY,
                first_found_at=CURRENT_START,
                last_found_at=CURRENT_END,
            )
        )
        db_session.flush()
        result = _compare(db_session, world)
        assert all(f.vuln_id != "CVE-2024-9999" for f in result.findings)
        assert result.counts[CLASS_NEW] == 0

    def test_counts_are_complete_even_when_the_returned_list_is_capped(
        self, db_session, world
    ):
        """
        `limit` bounds the rows, never the totals. A truncated count is a wrong
        number; a short list is a sample.
        """
        for i in range(25):
            db_session.add(
                _finding(
                    db_session,
                    world,
                    f"CVE-2024-1{i:03d}",
                    status="open",
                    first_found=CURRENT_START,
                    last_found=CURRENT_END,
                )
            )
        db_session.flush()
        result = _compare(db_session, world, limit_findings=5)
        assert result.counts[CLASS_NEW] == 25
        assert len(result.findings) == 5

    def test_severity_filtering_narrows_both_rows_and_counts(self, db_session, world):
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-2001",
                status="open",
                first_found=CURRENT_START,
                last_found=CURRENT_END,
                severity="low",
            )
        )
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-2002",
                status="open",
                first_found=CURRENT_START,
                last_found=CURRENT_END,
                severity="critical",
            )
        )
        db_session.flush()
        result = _compare(db_session, world, severities=["critical"])
        assert result.counts[CLASS_NEW] == 1
        assert result.findings[0].severity == "critical"

    def test_two_findings_differing_only_by_family_are_distinct(
        self, db_session, world
    ):
        """
        The row id is minted from (asset, vuln_id, source_family), so the same
        CVE seen over the network and through a credentialed package query is
        two findings — and each family's sweep only ever touches its own, so
        one path's absence cannot fix the other's.

        Note what the schema does *not* say: ``uq_asset_vuln_scan_asset_cve`` is
        UNIQUE on (org_id, scan_id, asset_id, vuln_id) and does not include the
        family, so the two rows cannot share a ``scan_id``. They are given
        different ones here, which is also what happens in practice — the two
        paths are last seen by different scans.
        """
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-3001",
                status="open",
                first_found=CURRENT_START,
                last_found=CURRENT_END,
            )
        )
        network = _finding(
            db_session,
            world,
            "CVE-2024-3001",
            status="open",
            first_found=CURRENT_START,
            last_found=CURRENT_END,
            family="network_service",
        )
        network.scan_id = world["baseline"].id
        db_session.add(network)
        db_session.flush()
        result = _compare(db_session, world)
        assert result.counts[CLASS_NEW] == 2


# ─────────────────────────────────────────────────────────────────────────────
# Assessment scope record
# ─────────────────────────────────────────────────────────────────────────────


class TestAssessmentScope:
    def test_scope_merges_rather_than_replaces(self, db_session, world):
        """
        One scan writes findings from several paths. The configuration audit's
        record must not erase the package matcher's.
        """
        scan = world["current"]
        record_assessment_scope(scan, assets=["a1"], families=["f1"])
        record_assessment_scope(scan, assets=["a2"], families=["f2"])
        scope = read_assessment_scope(scan)
        assert set(scope.assets) >= {"a1", "a2"}
        assert set(scope.families) >= {"f1", "f2"}

    def test_an_unrecorded_scope_covers_nothing(self):
        from core.findings import AssessmentScope

        assert AssessmentScope().covers("any", "any") is False

    def test_scope_survives_a_database_round_trip(self, db_session, world):
        """
        `scans.options` is JSON; an in-place mutation would not be flushed, and
        the scope would silently vanish between the scan and the comparison.
        """
        record_assessment_scope(world["current"], assets=["a9"], families=["f9"])
        db_session.flush()
        db_session.expire(world["current"])
        reloaded = db_session.query(Scan).filter(Scan.id == world["current"].id).one()
        assert "a9" in read_assessment_scope(reloaded).assets


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────


class TestTheComparisonReachesTheReport:
    def test_no_comparison_leaves_the_report_untouched(self):
        """
        The delta is an addition. A report generated without one must render
        exactly what it rendered before this section existed.
        """
        from reporting.pdf_generator import _build_styles, _comparison_section

        styles = _build_styles()
        assert _comparison_section(None, styles) == []
        assert _comparison_section({}, styles) == []

    def _text(self, flowables):
        chunks = []
        for flowable in flowables:
            text = getattr(flowable, "text", None)
            if text:
                chunks.append(str(text))
            for row in getattr(flowable, "_cellvalues", None) or []:
                for cell in row:
                    inner = getattr(cell, "text", None)
                    if inner:
                        chunks.append(str(inner))
        return "\n".join(chunks)

    def test_the_counts_and_summary_line_render(self, db_session, world):
        from reporting.pdf_generator import _build_styles, _comparison_section

        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-4001",
                status="open",
                first_found=CURRENT_START,
                last_found=CURRENT_END,
            )
        )
        db_session.flush()
        payload = _compare(db_session, world).as_dict()
        text = self._text(_comparison_section(payload, _build_styles()))
        assert "Change since the previous scan" in text
        assert "1 new" in text
        assert "CVE-2024-4001" in text

    def test_an_incomparable_pair_says_so_rather_than_showing_zeroes(
        self, db_session, world
    ):
        from reporting.pdf_generator import _build_styles, _comparison_section

        world["baseline"].completed_at = _utc(90)
        db_session.flush()
        payload = _compare(db_session, world).as_dict()
        text = self._text(_comparison_section(payload, _build_styles()))
        assert "Not comparable" in text

    def test_the_executive_report_carries_a_one_line_summary(self):
        """
        The executive report answers "better or worse". A total with nothing to
        compare it against cannot, so the delta gets one line there too — and
        only when there is one to give.
        """
        import io as _io

        src = _io.open("reporting/pdf_generator.py", encoding="utf-8").read()
        exec_body = src.split("def generate_executive_pdf")[1].split("def ")[0]
        assert "scan_comparison" in exec_body
        assert "Since the previous scan" in exec_body
        # Guarded, so a report with no comparison renders exactly as before.
        assert "comparable" in exec_body

    def test_the_not_assessed_row_is_labelled_as_not_a_fix(self, db_session, world):
        from reporting.pdf_generator import _build_styles, _comparison_section

        world["current"].options = {}
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-4002",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        db_session.flush()
        payload = _compare(db_session, world).as_dict()
        text = self._text(_comparison_section(payload, _build_styles()))
        assert "NOT reported fixed" in text


# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────
#
# These call the route function directly with a real session rather than going
# through TestClient. The reason is specific: `auth_headers` performs a login,
# the application commits during that request, and because the app shares this
# session every uncommitted fixture row is committed with it. Those rows then
# survive the per-test rollback and collide with later tests — measured as 13
# failures and 19 errors elsewhere in the suite, none of them in this file.
#
# Calling the function directly exercises exactly the same code, including
# `_get_scan_or_404`, which is where the organisation scoping and per-user
# visibility rule live.


def _scan_in(db_session, org_id, *, ident, start, end, status="complete"):
    scan = Scan(
        id=ident,
        org_id=org_id,
        target_str="10.0.0.1",
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status=status,
        created_at=start,
        started_at=start,
        completed_at=end,
    )
    db_session.add(scan)
    db_session.flush()
    return scan


class TestComparisonApi:
    def _call(self, db_session, user, scan_id, **kw):
        from fastapi import Response
        from starlette.requests import Request as StarletteRequest

        from routers.scan_history import compare_scan

        # The route carries `@limiter.limit`, so it takes `request` and
        # `response` — without the latter slowapi is handed None and raises
        # inside the endpoint. conftest disables the limiter for the suite, so
        # a minimal scope is enough to satisfy the signature.
        scope = {
            "type": "http",
            "method": "GET",
            "path": f"/scans/{scan_id}/comparison",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
        }
        params = dict(
            request=StarletteRequest(scope),
            response=Response(),
            baseline=None,
            asset_id=None,
            severity=None,
            limit=500,
            include_findings=True,
            org_id=None,
            db=db_session,
            user=user,
        )
        params.update(kw)
        return compare_scan(scan_id=scan_id, **params)

    def test_a_scan_from_another_tenant_is_not_found(
        self, db_session, test_user, world
    ):
        """
        Naming another tenant's scan id must not reach its findings. The route
        reuses `_get_scan_or_404`, so this is the same 404 every other scan
        route gives.
        """
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as excinfo:
            self._call(db_session, test_user, world["current"].id)
        assert excinfo.value.status_code == 404

    def test_a_first_scan_reports_no_baseline_rather_than_failing(
        self, db_session, test_user
    ):
        ident = f"scn_first_{uuid.uuid4().hex[:8]}"
        _scan_in(
            db_session,
            test_user.org_id,
            ident=ident,
            start=CURRENT_START,
            end=CURRENT_END,
        )
        body = self._call(db_session, test_user, ident)
        assert body["comparable"] is False
        assert body["baseline_scan_id"] is None
        assert "nothing to compare" in body["reason"]

    def test_a_comparison_returns_counts_a_summary_and_the_finding(
        self, db_session, test_user
    ):
        org_id = test_user.org_id
        base_id = f"scn_b_{uuid.uuid4().hex[:8]}"
        curr_id = f"scn_c_{uuid.uuid4().hex[:8]}"
        _scan_in(
            db_session, org_id, ident=base_id, start=BASELINE_START, end=BASELINE_END
        )
        current = _scan_in(
            db_session, org_id, ident=curr_id, start=CURRENT_START, end=CURRENT_END
        )
        asset_id = f"ast_{org_id}_10_0_0_9"
        db_session.add(
            Asset(
                id=asset_id,
                org_id=org_id,
                ip_address="10.0.0.9",
                last_seen_at=CURRENT_END,
            )
        )
        record_assessment_scope(current, assets=[asset_id], families=[FAMILY])
        _definition(db_session, "CVE-2024-7001")
        db_session.add(
            AssetVulnerability(
                id=f"fnd_{asset_id}_CVE-2024-7001_{FAMILY}",
                org_id=org_id,
                asset_id=asset_id,
                vuln_id="CVE-2024-7001",
                scan_id=curr_id,
                severity="high",
                status="open",
                source_family=FAMILY,
                first_found_at=CURRENT_START,
                last_found_at=CURRENT_END,
            )
        )
        db_session.flush()

        body = self._call(db_session, test_user, curr_id, baseline=base_id)
        assert body["comparable"] is True
        assert body["counts"]["new"] == 1
        assert "1 new" in body["summary"]
        assert body["findings"][0]["vuln_id"] == "CVE-2024-7001"
        assert body["findings"][0]["classification"] == "new"

    def test_findings_can_be_omitted_for_a_counts_only_call(
        self, db_session, test_user
    ):
        org_id = test_user.org_id
        base_id = f"scn_b2_{uuid.uuid4().hex[:8]}"
        curr_id = f"scn_c2_{uuid.uuid4().hex[:8]}"
        _scan_in(
            db_session, org_id, ident=base_id, start=BASELINE_START, end=BASELINE_END
        )
        _scan_in(
            db_session, org_id, ident=curr_id, start=CURRENT_START, end=CURRENT_END
        )
        body = self._call(
            db_session, test_user, curr_id, baseline=base_id, include_findings=False
        )
        assert "findings" not in body

    def test_no_secret_appears_in_the_comparison_payload(self, db_session, test_user):
        """
        The payload carries the scan's recorded assessment scope, which lives in
        `scans.options` — the column CLAUDE.md forbids putting a credential in.
        This keeps that true from the reading side.
        """
        import json

        org_id = test_user.org_id
        base_id = f"scn_b3_{uuid.uuid4().hex[:8]}"
        curr_id = f"scn_c3_{uuid.uuid4().hex[:8]}"
        _scan_in(
            db_session, org_id, ident=base_id, start=BASELINE_START, end=BASELINE_END
        )
        _scan_in(
            db_session, org_id, ident=curr_id, start=CURRENT_START, end=CURRENT_END
        )
        body = json.dumps(
            self._call(db_session, test_user, curr_id, baseline=base_id), default=str
        ).lower()
        for forbidden in ("password", "secret", "encrypted_password", "private_key"):
            assert forbidden not in body


class TestNarrowedScanCannotReportAFix:
    """
    Found by GAP-15's real-target export validation, on a live Ubuntu 24.04
    container scanned twice four minutes apart with nothing changed between.

    The second scan ran under a GAP-12 policy naming one benchmark at severity
    `medium`, so it selected 203 checks where the first selected 843. Five
    configuration findings the first scan reported were therefore never
    evaluated by the second — and the comparison called all five **FIXED**,
    because `covers()` answers a question about *families* and every
    credentialed finding, CVE and configuration alike, carries the family
    `credentialed_package`.

    The scan's own sweep had it right the whole time: those rows were still
    `status="open"` with `fixed_at` NULL, because the sweep consults the set of
    checks that actually reached a verdict. The comparison had no access to
    that set. It does now, and the two mechanisms can no longer disagree.
    """

    def _narrow(self, world, assessed):
        record_assessment_scope(
            world["current"],
            assets=[world["asset_id"]],
            families=[FAMILY],
            detail={"assessed_checks": list(assessed)},
        )

    def test_a_configuration_check_the_scan_did_not_run_is_not_assessed(
        self, db_session, world
    ):
        db_session.add(
            _finding(
                db_session,
                world,
                "CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        # The current scan reached a verdict on a different check only.
        self._narrow(world, ["CCURE-CFG-CCURE-LINUX-SSH-PROTOCOL"])
        db_session.flush()

        result = _compare(db_session, world)
        assert result.counts[CLASS_FIXED] == 0
        assert result.counts[CLASS_NOT_ASSESSED] == 1

    def test_a_configuration_check_the_scan_did_run_is_still_a_fix(
        self, db_session, world
    ):
        """
        The fix must not cost a real remediation its classification.
        """
        db_session.add(
            _finding(
                db_session,
                world,
                "CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        self._narrow(world, ["CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING"])
        db_session.flush()

        result = _compare(db_session, world)
        assert result.counts[CLASS_FIXED] == 1
        assert result.counts[CLASS_NOT_ASSESSED] == 0

    def test_a_cve_is_unaffected_by_the_check_set(self, db_session, world):
        """
        The package matcher runs over the whole installed inventory, so a CVE
        it does not report on a host it inventoried really is gone. Requiring a
        CVE to appear in the check set would make every package fix
        unreportable.
        """
        db_session.add(
            _finding(
                db_session,
                world,
                "CVE-2024-9911",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        self._narrow(world, ["CCURE-CFG-CCURE-LINUX-SSH-PROTOCOL"])
        db_session.flush()

        result = _compare(db_session, world)
        assert result.counts[CLASS_FIXED] == 1

    def test_a_scan_that_recorded_no_check_set_keeps_the_previous_behaviour(
        self, db_session, world
    ):
        """
        Every scan that ran before this record existed has no check set, and
        "we do not know which checks ran" must not silently reclassify every
        historical comparison. The degradation is to the behaviour those
        comparisons already had.
        """
        db_session.add(
            _finding(
                db_session,
                world,
                "CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING",
                status="open",
                first_found=BASELINE_START,
                last_found=BASELINE_END,
            )
        )
        db_session.flush()

        scope = read_assessment_scope(world["current"])
        assert scope.assessed_checks == frozenset()
        assert scope.covers_check("CCURE-CFG-ANYTHING") is True

        result = _compare(db_session, world)
        assert result.counts[CLASS_FIXED] == 1
