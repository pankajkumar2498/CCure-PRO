"""
Guards on which compliance frameworks this installation offers.

Eleven of the thirteen seeded catalogues are parked while ISO/IEC 27001:2022
and NIST CSF 2.0 are finished. Parking is a visibility and enforcement
decision, never a data one — the catalogues stay seeded because ISO's and
NIST's crosswalks resolve into them and `main.py`'s bootstrap treats a missing
framework as damage to repair.

Two holes existed before this and both are asserted here:

  * `ComplianceTenantFramework.is_enabled` gated the register, scans, findings,
    attestation, evidence, schedules and the dashboard — but **none of the
    thirteen report endpoints checked anything at all**, so
    `/compliance/reports/nis2` rendered a full PDF for a framework no tenant had
    installed and the workspace did not list.
  * The marketplace would let a tenant admin re-install a parked framework and
    then scan against a catalogue that is not finished.

`ComplianceFramework.is_active` is deliberately *not* the mechanism: it is a
column no query in the codebase reads, so setting it would look like it worked
and change nothing. There is a test for that below so nobody reaches for it.
"""

from core.compliance_seeds import all_seed_paths

from testpaths import BACKEND_ROOT

import pytest
from core import compliance_frameworks


# ─────────────────────────────────────────────────────────────────────────────
# The list itself
# ─────────────────────────────────────────────────────────────────────────────


def test_the_two_finished_frameworks_are_the_default():
    assert compliance_frameworks.DEFAULT_ACTIVE_FRAMEWORK_IDS == (
        "cfw_iso27001_2022",
        "cfw_nist_csf_v2",
    )
    assert compliance_frameworks.active_framework_ids() == (
        "cfw_iso27001_2022",
        "cfw_nist_csf_v2",
    )


def test_every_seeded_catalogue_is_either_active_or_parked():
    """A framework missing from both lists would be unreachable and untestable."""
    import json

    seeded = set()
    for path in all_seed_paths():
        with open(path, encoding="utf-8") as fh:
            framework = json.load(fh)["framework"]
        # `seed_compliance.py` derives the id from `code`; the `id` key is
        # present in only five of the thirteen files and is not authoritative.
        seeded.add(f"cfw_{framework['code'].lower()}")

    known = set(compliance_frameworks.ALL_FRAMEWORK_IDS)
    assert seeded == known, (
        f"seed files and ALL_FRAMEWORK_IDS disagree: "
        f"only seeded {sorted(seeded - known)}, only listed {sorted(known - seeded)}"
    )

    active = set(compliance_frameworks.active_framework_ids())
    parked = set(compliance_frameworks.parked_framework_ids())
    assert active | parked == known
    assert not (active & parked)


def test_environment_override_is_honoured_and_fails_safe(monkeypatch):
    monkeypatch.setenv("COMPLIANCE_ACTIVE_FRAMEWORKS", "cfw_nis2, cfw_gdpr")
    assert compliance_frameworks.active_framework_ids() == ("cfw_nis2", "cfw_gdpr")
    assert compliance_frameworks.is_active("cfw_nis2")
    assert not compliance_frameworks.is_active("cfw_iso27001_2022")

    # An empty override reads as a configuration accident, not as "disable
    # compliance entirely", so it falls back rather than switching everything
    # off.
    monkeypatch.setenv("COMPLIANCE_ACTIVE_FRAMEWORKS", "   ")
    assert (
        compliance_frameworks.active_framework_ids()
        == compliance_frameworks.DEFAULT_ACTIVE_FRAMEWORK_IDS
    )


def test_every_report_slug_maps_to_a_known_framework():
    """The report guard resolves a slug back to the framework it renders."""
    known = set(compliance_frameworks.ALL_FRAMEWORK_IDS)
    for slug, framework_id in compliance_frameworks.REPORT_SLUG_TO_FRAMEWORK.items():
        assert framework_id in known, f"{slug} maps to unknown {framework_id}"


def test_is_active_column_is_still_unused():
    """`ComplianceFramework.is_active` is a trap, not a switch.

    It is set True at seed time and read by no query. If someone starts using
    it, this test should be deleted deliberately rather than the column being
    quietly repurposed as a second, half-working parking mechanism.
    """

    backend = BACKEND_ROOT
    hits = []
    for path in list(backend.glob("routers/*.py")) + list(backend.glob("core/*.py")):
        # This module explains why the column is not used; naming it in prose
        # is the point.
        if path.name == "compliance_frameworks.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "ComplianceFramework.is_active" in text:
            hits.append(path.name)
    assert not hits, (
        "ComplianceFramework.is_active is now read by "
        f"{hits} — parking is meant to run through core.compliance_frameworks"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Enforcement
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def installed_active_frameworks(db_session, test_user):
    """Install the active frameworks for the test tenant.

    `require_active_framework` is an installation-wide check; the routes then
    apply the per-tenant `is_enabled` check on top of it. A test org starts
    with nothing installed, so without this the tenant check answers 400/404
    and the installation-wide guard is never the thing being measured.
    """
    from db.models.compliance import ComplianceTenantFramework

    for framework_id in compliance_frameworks.active_framework_ids():
        row = (
            db_session.query(ComplianceTenantFramework)
            .filter_by(tenant_id=test_user.org_id, framework_id=framework_id)
            .first()
        )
        if row:
            row.is_enabled = True
        else:
            db_session.add(
                ComplianceTenantFramework(
                    id=f"ctf_{test_user.org_id}_{framework_id}",
                    tenant_id=test_user.org_id,
                    framework_id=framework_id,
                    is_enabled=True,
                )
            )
    db_session.commit()
    return compliance_frameworks.active_framework_ids()


def test_guard_distinguishes_parked_from_unknown():
    """403 for a parked catalogue, 404 for one that does not exist.

    Telling a caller that NIS 2 does not exist would be false — it is seeded,
    its controls are live and ISO crosswalks into it.
    """
    from fastapi import HTTPException
    from routers.compliance import require_active_framework

    require_active_framework("cfw_iso27001_2022")
    require_active_framework("cfw_nist_csf_v2")

    with pytest.raises(HTTPException) as parked:
        require_active_framework("cfw_nis2")
    assert parked.value.status_code == 403
    assert "cfw_iso27001_2022" in parked.value.detail

    with pytest.raises(HTTPException) as unknown:
        require_active_framework("cfw_not_a_framework")
    assert unknown.value.status_code == 404


@pytest.mark.parametrize(
    "slug",
    [
        "cis_v8_1",
        "soc2_type2",
        "cert_in_2022",
        "pci_dss_v4",
        "dpdp_2023",
        "gdpr",
        "nist_800_53_r5",
        "iec_62443",
        "nist_800_82",
        "nerc_cip",
        "nis2",
    ],
)
def test_parked_framework_reports_are_refused(client, auth_headers, slug):
    """Every one of these rendered a PDF for a parked framework before."""
    res = client.get(f"/compliance/reports/{slug}?fmt=pdf", headers=auth_headers)
    assert res.status_code == 403, f"{slug} returned {res.status_code}"


@pytest.mark.parametrize("slug", ["soa", "nist_csf"])
def test_active_framework_reports_still_render(
    client, auth_headers, slug, installed_active_frameworks
):
    res = client.get(f"/compliance/reports/{slug}?fmt=pdf", headers=auth_headers)
    assert res.status_code == 200, res.text
    assert res.content[:5] == b"%PDF-"


def test_soa_is_refused_for_a_parked_framework(
    client, auth_headers, installed_active_frameworks
):
    """The SoA names its framework by parameter rather than by route."""
    ok = client.get(
        "/compliance/reports/soa?framework_id=cfw_iso27001_2022", headers=auth_headers
    )
    assert ok.status_code == 200

    refused = client.get(
        "/compliance/reports/soa?framework_id=cfw_pci_dss_v4", headers=auth_headers
    )
    assert refused.status_code == 403


def test_parked_framework_cannot_be_installed(client, auth_headers):
    res = client.post("/compliance/marketplace/cfw_nis2/install", headers=auth_headers)
    assert res.status_code == 403


def test_marketplace_lists_only_active_frameworks(client, auth_headers):
    res = client.get("/compliance/marketplace", headers=auth_headers)
    assert res.status_code == 200
    body = res.json()

    listed = [f["framework_id"] for f in body["data"]]
    assert listed == ["cfw_iso27001_2022", "cfw_nist_csf_v2"], listed
    # The query behind this has no ORDER BY, so the order is asserted: the card
    # grid used to come out in whatever order Postgres returned.
    assert body["active_framework_ids"] == listed
    assert "cfw_nis2" in body["parked_framework_ids"]


def test_dashboard_and_register_refuse_a_parked_framework(client, auth_headers):
    for path in (
        "/compliance/summary?framework_id=cfw_nis2",
        "/compliance/findings?framework_id=cfw_nis2",
        "/compliance/frameworks/cfw_nis2/controls",
        "/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022"
        "&target_framework_id=cfw_nis2",
    ):
        res = client.get(path, headers=auth_headers)
        assert res.status_code == 403, f"{path} returned {res.status_code}"


def test_the_two_active_frameworks_are_unaffected(
    client, auth_headers, installed_active_frameworks
):
    """The whole point: parking eleven must not touch the two that remain."""
    for path in (
        "/compliance/summary?framework_id=cfw_iso27001_2022",
        "/compliance/summary?framework_id=cfw_nist_csf_v2",
        "/compliance/findings?framework_id=cfw_iso27001_2022",
        "/compliance/findings?framework_id=cfw_nist_csf_v2",
        "/compliance/frameworks/cfw_iso27001_2022/controls",
        "/compliance/frameworks/cfw_nist_csf_v2/controls",
        "/compliance/gap-analysis?source_framework_id=cfw_iso27001_2022"
        "&target_framework_id=cfw_nist_csf_v2",
        "/compliance/summary",
    ):
        res = client.get(path, headers=auth_headers)
        assert res.status_code == 200, f"{path} returned {res.status_code}: {res.text}"


def test_activation_fixture_reopens_a_parked_framework(
    client, auth_headers, activate_frameworks
):
    """The escape hatch the parked frameworks' own suites rely on."""
    refused = client.get("/compliance/reports/nis2?fmt=pdf", headers=auth_headers)
    assert refused.status_code == 403

    activate_frameworks("cfw_nis2")
    allowed = client.get("/compliance/reports/nis2?fmt=pdf", headers=auth_headers)
    assert allowed.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Nothing runs in the background for a parked framework
# ─────────────────────────────────────────────────────────────────────────────


def test_scheduled_scans_skip_a_parked_framework(db_session, test_user):
    """The only path that starts a scan without a request.

    `POST /compliance/schedules` requires the framework to be enabled *at the
    moment the schedule is created*, and nothing re-checked it afterwards — so
    a framework uninstalled or parked later kept being scanned every five
    minutes on beat, writing findings and scores for a framework the workspace
    does not show.
    """
    from datetime import datetime, timedelta, timezone

    from core.compliance_tasks import run_scheduled_scans
    from db.models.compliance import (
        CompliancePolicy,
        ComplianceScanRun,
        ComplianceScanSchedule,
        ComplianceTenantFramework,
    )

    parked = "cfw_nis2"
    policy_id = "cpl_parked_probe_policy"
    schedule_id = "csh_parked_probe"

    db_session.add(
        CompliancePolicy(
            id=policy_id,
            framework_id=parked,
            tenant_id=test_user.org_id,
            policy_family_code="POL-PARKED-PROBE",
            version_number=1,
            name="Parked probe policy",
            target_platform="any",
            status="active",
            is_active=True,
        )
    )
    # Enabled for the tenant on purpose: the installation-wide list is the
    # thing under test, and a tenant flag alone must not be enough.
    if (
        not db_session.query(ComplianceTenantFramework)
        .filter_by(tenant_id=test_user.org_id, framework_id=parked)
        .first()
    ):
        db_session.add(
            ComplianceTenantFramework(
                id=f"ctf_{test_user.org_id}_{parked}",
                tenant_id=test_user.org_id,
                framework_id=parked,
                is_enabled=True,
            )
        )
    db_session.add(
        ComplianceScanSchedule(
            id=schedule_id,
            tenant_id=test_user.org_id,
            framework_id=parked,
            policy_id=policy_id,
            frequency="daily",
            scope={},
            is_active=True,
            next_run_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )
    db_session.commit()

    before = (
        db_session.query(ComplianceScanRun)
        .filter(ComplianceScanRun.framework_id == parked)
        .count()
    )
    try:
        result = run_scheduled_scans()
        assert result["success"] is True

        db_session.expire_all()
        after = (
            db_session.query(ComplianceScanRun)
            .filter(ComplianceScanRun.framework_id == parked)
            .count()
        )
        assert after == before, "beat started a compliance scan for a parked framework"
    finally:
        db_session.query(ComplianceScanRun).filter(
            ComplianceScanRun.schedule_id == schedule_id
        ).delete(synchronize_session=False)
        db_session.query(ComplianceScanSchedule).filter_by(id=schedule_id).delete()
        db_session.query(CompliancePolicy).filter_by(id=policy_id).delete()
        db_session.commit()


def test_scan_history_and_schedules_hide_parked_frameworks(client, auth_headers):
    """A run or schedule survives its framework being parked.

    Both listings were tenant-scoped only, so historical rows kept appearing
    with a framework name and a score the workspace can no longer open, and the
    schedule list offered an edit button on something that will never fire.
    """
    runs = client.get("/compliance/scans", headers=auth_headers)
    assert runs.status_code == 200
    active = set(compliance_frameworks.active_framework_ids())
    for row in runs.json()["data"]:
        assert row.get("framework_id", next(iter(active))) in active, row

    scoped = client.get("/compliance/scans?framework_id=cfw_nis2", headers=auth_headers)
    assert scoped.status_code == 403

    schedules = client.get("/compliance/schedules", headers=auth_headers)
    assert schedules.status_code == 200
    for row in schedules.json()["data"]:
        assert row["framework_id"] in active, row


def test_a_shared_rule_never_resolves_outside_the_scan_framework(db_session):
    """Crosswalk inheritance links one rule to controls in many frameworks.

    96 rules are linked to controls in both an active and a parked framework.
    `resolve_controls_for_rule` is what stops a parked framework's control
    receiving a finding from an ISO or NIST scan — and, before it existed, 57
    of 114 ISO policy rules resolved to a control in a different standard.
    """
    from core.compliance_tasks import resolve_controls_for_rule
    from db.models.compliance import ComplianceControl, ComplianceRuleControl

    rows = (
        db_session.query(ComplianceRuleControl.rule_id, ComplianceControl.framework_id)
        .join(
            ComplianceControl,
            ComplianceControl.id == ComplianceRuleControl.control_id,
        )
        .all()
    )
    if not rows:
        pytest.skip("compliance catalogue is not seeded in this database")

    active = set(compliance_frameworks.active_framework_ids())
    by_rule: dict = {}
    for rule_id, framework_id in rows:
        by_rule.setdefault(rule_id, set()).add(framework_id)

    shared = [
        rule_id
        for rule_id, frameworks in by_rule.items()
        if (frameworks & active) and (frameworks - active)
    ]
    assert shared, "expected crosswalked rules spanning active and parked frameworks"

    owner_of = {c.id: c.framework_id for c in db_session.query(ComplianceControl).all()}
    leaked = []
    for rule_id in shared:
        for framework_id in active:
            for control_id in resolve_controls_for_rule(
                db_session, rule_id, framework_id
            ):
                if owner_of.get(control_id) != framework_id:
                    leaked.append((rule_id, framework_id, control_id))

    assert not leaked, f"rule resolved outside its scan framework: {leaked[:5]}"


@pytest.fixture
def reverify_probe(db_session, test_user):
    """A failing finding on a real control, plus a rule that would re-verify it.

    Returns a factory so one test can build the same probe against an active
    framework and a parked one and compare what `run_reverify_evaluation` does
    with each.
    """
    from datetime import datetime, timezone

    from db.models.compliance import (
        ComplianceControl,
        ComplianceFinding,
        ComplianceFindingHistory,
        ComplianceRule,
        ComplianceTenantFramework,
    )

    created: list = []

    def _build(framework_id: str, *, tenant_enabled: bool = True):
        control = (
            db_session.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == framework_id)
            .first()
        )
        if control is None:
            pytest.skip(f"{framework_id} is not seeded in this database")

        suffix = framework_id.replace("cfw_", "")[:14]
        rule_id = f"crl_reverify_probe_{suffix}"
        finding_id = f"cfnd_reverify_probe_{suffix}"

        rule = ComplianceRule(
            id=rule_id,
            rule_family_code=f"REVERIFY-PROBE-{suffix.upper()}",
            version_number=1,
            check_type="port_state",
            evidence_source="services_ports",
            target_platform="any",
            check_definition={
                "key": "open_ports",
                "operator": "not_contains",
                "expected": 23,
            },
            severity="high",
            status="active",
        )
        # The rule has to exist before the finding's foreign key is checked.
        db_session.add(rule)
        db_session.flush()

        finding = ComplianceFinding(
            id=finding_id,
            tenant_id=test_user.org_id,
            control_id=control.id,
            rule_id=rule_id,
            source="auto_scan",
            status="fail",
            evidence={"probe": True},
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db_session.add(finding)

        row = (
            db_session.query(ComplianceTenantFramework)
            .filter_by(tenant_id=test_user.org_id, framework_id=framework_id)
            .first()
        )
        if row:
            row.is_enabled = tenant_enabled
        else:
            db_session.add(
                ComplianceTenantFramework(
                    id=f"ctf_{test_user.org_id}_{framework_id}",
                    tenant_id=test_user.org_id,
                    framework_id=framework_id,
                    is_enabled=tenant_enabled,
                )
            )
        db_session.commit()
        created.append((finding_id, rule_id))
        return finding_id

    yield _build

    for finding_id, rule_id in created:
        db_session.query(ComplianceFindingHistory).filter_by(
            finding_id=finding_id
        ).delete(synchronize_session=False)
        db_session.query(ComplianceFinding).filter_by(id=finding_id).delete()
        db_session.query(ComplianceRule).filter_by(id=rule_id).delete()
    db_session.commit()


def test_reverify_is_refused_for_a_parked_framework(db_session, reverify_probe):
    """Defence in depth on the one compliance task with no framework check.

    `run_reverify_evaluation` takes a finding id and writes a verdict onto it.
    It was safe only by inheritance — reachable solely from
    `run_reremediation_task`, itself reachable only from the two remediation
    endpoints, both of which refuse a framework the tenant has not enabled.
    Nothing in the function itself stopped a caller added later from rewriting
    a parked framework's finding.
    """
    from core.compliance_tasks import run_reverify_evaluation
    from db.models.compliance import ComplianceFinding, ComplianceFindingHistory

    finding_id = reverify_probe("cfw_nis2", tenant_enabled=True)

    result = run_reverify_evaluation(finding_id)
    assert result["success"] is False
    assert "not enabled on this installation" in result["error"]

    # The finding must be untouched — refusing has to mean refusing, not
    # writing a verdict and then reporting failure.
    db_session.expire_all()
    finding = db_session.query(ComplianceFinding).filter_by(id=finding_id).first()
    assert finding.status == "fail"
    assert finding.evidence == {"probe": True}
    assert (
        db_session.query(ComplianceFindingHistory)
        .filter_by(finding_id=finding_id)
        .count()
        == 0
    ), "a refused re-verification must not write a history row"


def test_reverify_is_refused_when_the_tenant_has_uninstalled_the_framework(
    db_session, reverify_probe, activate_frameworks
):
    """The installation list and the tenant flag are different questions.

    A framework can be offered by the deployment and still be uninstalled by
    this particular organisation, which is the state every request path already
    refuses.
    """
    from core.compliance_tasks import run_reverify_evaluation

    activate_frameworks("cfw_nis2")
    finding_id = reverify_probe("cfw_nis2", tenant_enabled=False)

    result = run_reverify_evaluation(finding_id)
    assert result["success"] is False
    assert "not installed for this organisation" in result["error"]


@pytest.mark.parametrize("framework_id", ["cfw_iso27001_2022", "cfw_nist_csf_v2"])
def test_reverify_still_runs_for_the_active_frameworks(
    db_session, reverify_probe, framework_id
):
    """The guard must not change behaviour for ISO 27001 or NIST CSF 2.0.

    The probe's asset_id is None, so there is no evidence to re-collect and the
    expected verdict is `manual_review` — "could not complete" rather than
    "failed to fix anything", which is the distinction re-verification is
    required to make. What matters here is that it *ran*: a verdict was
    written and a history row recorded.
    """
    from core.compliance_tasks import run_reverify_evaluation
    from db.models.compliance import ComplianceFinding, ComplianceFindingHistory

    finding_id = reverify_probe(framework_id, tenant_enabled=True)

    result = run_reverify_evaluation(finding_id)
    assert result["success"] is True, result
    assert result["verdict"] in ("pass", "fail", "manual_review")

    db_session.expire_all()
    finding = db_session.query(ComplianceFinding).filter_by(id=finding_id).first()
    assert finding.status == result["verdict"]
    assert (
        db_session.query(ComplianceFindingHistory)
        .filter_by(finding_id=finding_id)
        .count()
        == 1
    )


def test_no_findings_or_scores_exist_for_a_parked_framework(db_session):
    """The load-bearing claim: parked means no compliance processing at all."""
    from db.models.compliance import (
        ComplianceControl,
        ComplianceFinding,
        ComplianceScore,
    )

    active = set(compliance_frameworks.active_framework_ids())
    owner_of = {c.id: c.framework_id for c in db_session.query(ComplianceControl).all()}
    if not owner_of:
        pytest.skip("compliance catalogue is not seeded in this database")

    stray_scores = (
        db_session.query(ComplianceScore.framework_id)
        .filter(ComplianceScore.framework_id.notin_(list(active)))
        .distinct()
        .all()
    )
    assert not stray_scores, f"scores exist for parked frameworks: {stray_scores}"

    stray_findings = {
        owner_of.get(f.control_id, "ORPHAN")
        for f in db_session.query(ComplianceFinding).all()
    } - active
    assert (
        not stray_findings
    ), f"findings exist against parked or orphaned controls: {sorted(stray_findings)}"
