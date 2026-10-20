"""
tests/scans/test_scan_policy_record.py
─────────────────────────────────────────────────────────────────────────────
GAP-12 — reproducibility: the historical record, the report, and GAP-13.

The requirement this file exists for: **a completed scan must be able to answer
"exactly what configuration produced this?" without consulting the policy row,
which may since have been edited, versioned, archived or deleted.**

These call the route functions directly with a real session rather than driving
them through ``TestClient``, for the reason CLAUDE.md records against
``test_finding_comparison.py``: a login through the client commits, taking every
uncommitted fixture row with it. The same code is exercised, including the
tenant-scoped lookup.

Coverage areas exercised: pol.record.snapshot, pol.record.fingerprint,
pol.record.api, pol.record.report, pol.record.comparison, pol.bind.scan.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from core.scan_policy import effective_from_config, read_policy_snapshot
from db.models import Organization, ScanPolicy, User
from db.models.scans import Scan
from sqlalchemy.orm import Session


def _utc(offset_minutes: int = 0) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)


def _rendered(story) -> str:
    """
    Every word the section puts on the page, table cells included.

    Reading only top-level ``Paragraph.text`` misses everything inside a
    ``Table``, which is where ``_grid`` puts the settings — so a test written
    that way passes on a section that renders no settings at all.
    """
    out: list[str] = []

    def walk(item):
        text = getattr(item, "text", None)
        if isinstance(text, str):
            out.append(text)
        rows = getattr(item, "_cellvalues", None)
        if rows:
            for row in rows:
                for cell in row:
                    if isinstance(cell, (list, tuple)):
                        for sub in cell:
                            walk(sub)
                    else:
                        walk(cell)

    for item in story:
        walk(item)
    return " ".join(out)


@pytest.fixture
def policy_row(db_session: Session, test_org: Organization) -> ScanPolicy:
    policy = ScanPolicy(
        id=f"spol_{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        name="STIG Ubuntu only",
        policy_family_code="stig-ubuntu",
        version_number=1,
        scan_kind="credentialed",
        config={"min_severity": "high", "platforms": ["linux"]},
        status="active",
        is_enabled=True,
    )
    db_session.add(policy)
    db_session.commit()
    db_session.refresh(policy)
    return policy


def _scan(db_session: Session, org: Organization, user: User, **options) -> Scan:
    scan = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=org.id,
        created_by=str(user.id),
        target_str="192.0.2.10",
        target_hosts=["192.0.2.10"],
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        started_at=_utc(-10),
        completed_at=_utc(-5),
        options=dict(options),
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


# ─────────────────────────────────────────────────────────────────────────────
# pol.record.snapshot — the immutability requirement
# ─────────────────────────────────────────────────────────────────────────────


def test_editing_a_policy_does_not_alter_a_completed_scans_record(
    db_session: Session, test_org: Organization, test_user: User, policy_row: ScanPolicy
):
    """
    **The requirement of this phase.** Scan A ran under a policy; the policy is
    then edited. Scan A's recorded configuration must be exactly what it was.
    """
    from core.scan_policy import record_policy_snapshot, resolve_policy

    scan = _scan(db_session, test_org, test_user)
    resolution = resolve_policy(
        db_session,
        policy_id=policy_row.id,
        org_id=test_org.id,
        scan_kind="credentialed",
        has_credential=True,
    )
    record_policy_snapshot(scan, resolution.policy)
    db_session.commit()

    original_fingerprint = resolution.policy.fingerprint()
    assert read_policy_snapshot(scan).min_severity == "high"

    # The policy is edited afterwards — narrowed further, in fact.
    policy_row.config = {"min_severity": "critical", "platforms": ["windows"]}
    db_session.commit()
    db_session.refresh(scan)

    recorded = read_policy_snapshot(scan)
    assert recorded.min_severity == "high", "the scan's record must not follow the edit"
    assert recorded.platforms == ("linux",)
    assert recorded.fingerprint() == original_fingerprint


def test_a_scans_record_survives_the_policy_being_deleted(
    db_session: Session, test_org: Organization, test_user: User, policy_row: ScanPolicy
):
    """
    The snapshot is in ``scans.options``, not a foreign key, precisely so that
    deleting a policy cannot erase the record of what a scan assessed.
    """
    from core.scan_policy import record_policy_snapshot, resolve_policy

    scan = _scan(db_session, test_org, test_user)
    resolution = resolve_policy(
        db_session,
        policy_id=policy_row.id,
        org_id=test_org.id,
        scan_kind="credentialed",
        has_credential=True,
    )
    record_policy_snapshot(scan, resolution.policy)
    db_session.commit()

    db_session.delete(policy_row)
    db_session.commit()
    db_session.refresh(scan)

    recorded = read_policy_snapshot(scan)
    assert recorded is not None
    assert recorded.policy_name == "STIG Ubuntu only"
    assert recorded.min_severity == "high"


def test_two_scans_under_the_same_policy_share_a_fingerprint(
    db_session: Session, test_org: Organization, test_user: User, policy_row: ScanPolicy
):
    from core.scan_policy import record_policy_snapshot, resolve_policy

    fingerprints = set()
    for _ in range(2):
        scan = _scan(db_session, test_org, test_user)
        resolution = resolve_policy(
            db_session,
            policy_id=policy_row.id,
            org_id=test_org.id,
            scan_kind="credentialed",
            has_credential=True,
        )
        record_policy_snapshot(scan, resolution.policy)
        db_session.commit()
        fingerprints.add(read_policy_snapshot(scan).fingerprint())
    assert len(fingerprints) == 1


# ─────────────────────────────────────────────────────────────────────────────
# pol.record.api
# ─────────────────────────────────────────────────────────────────────────────


def _read_policy(db_session, scan_id, user):
    from routers.scan_history import scan_policy_record

    return scan_policy_record(
        request=None,
        response=None,
        scan_id=scan_id,
        org_id=None,
        db=db_session,
        user=user,
    )


def test_the_api_reports_a_scans_recorded_configuration(
    db_session: Session, test_org: Organization, test_user: User, policy_row: ScanPolicy
):
    from core.scan_policy import record_policy_snapshot, resolve_policy

    scan = _scan(db_session, test_org, test_user)
    resolution = resolve_policy(
        db_session,
        policy_id=policy_row.id,
        org_id=test_org.id,
        scan_kind="credentialed",
        has_credential=True,
    )
    record_policy_snapshot(scan, resolution.policy)
    db_session.commit()

    payload = _read_policy(db_session, scan.id, test_user)
    assert payload["policy"]["recorded"] is True
    assert payload["policy"]["policy_name"] == "STIG Ubuntu only"
    assert payload["effective"]["min_severity"] == "high"
    assert payload["policy_current_state"]["matches_snapshot"] is True


def test_the_api_reports_that_the_policy_has_diverged_since(
    db_session: Session, test_org: Organization, test_user: User, policy_row: ScanPolicy
):
    """
    Reported, never used to change the record. A policy edited since is exactly
    the case the snapshot exists for, and this is how a reader learns the two
    have diverged.
    """
    from core.scan_policy import record_policy_snapshot, resolve_policy

    scan = _scan(db_session, test_org, test_user)
    resolution = resolve_policy(
        db_session,
        policy_id=policy_row.id,
        org_id=test_org.id,
        scan_kind="credentialed",
        has_credential=True,
    )
    record_policy_snapshot(scan, resolution.policy)
    db_session.commit()

    policy_row.config = {"min_severity": "low"}
    db_session.commit()

    payload = _read_policy(db_session, scan.id, test_user)
    assert payload["policy_current_state"]["matches_snapshot"] is False
    assert "edited since" in payload["policy_current_state"]["note"]
    # And the record itself is untouched.
    assert payload["effective"]["min_severity"] == "high"


def test_the_api_reports_a_deleted_policy_without_losing_the_record(
    db_session: Session, test_org: Organization, test_user: User, policy_row: ScanPolicy
):
    from core.scan_policy import record_policy_snapshot, resolve_policy

    scan = _scan(db_session, test_org, test_user)
    resolution = resolve_policy(
        db_session,
        policy_id=policy_row.id,
        org_id=test_org.id,
        scan_kind="credentialed",
        has_credential=True,
    )
    record_policy_snapshot(scan, resolution.policy)
    db_session.commit()
    db_session.delete(policy_row)
    db_session.commit()

    payload = _read_policy(db_session, scan.id, test_user)
    assert payload["policy_current_state"]["exists"] is False
    assert payload["effective"]["min_severity"] == "high"


def test_a_scan_predating_the_phase_reports_unrecorded_not_a_default(
    db_session: Session, test_org: Organization, test_user: User
):
    """
    Inventing a configuration record for an older scan would put a claim in
    front of an auditor that nothing supports.
    """
    scan = _scan(db_session, test_org, test_user, origin="manual")
    payload = _read_policy(db_session, scan.id, test_user)
    assert payload["policy"] == {"recorded": False}
    assert "effective" not in payload


def test_another_tenants_scan_policy_is_not_readable(
    db_session: Session, test_org: Organization, test_user: User
):
    from fastapi import HTTPException

    other = Organization(
        id=f"org_{uuid.uuid4().hex[:8]}",
        name="Other",
        slug=f"other-{uuid.uuid4().hex[:6]}",
        is_active=True,
    )
    db_session.add(other)
    db_session.commit()

    scan = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=other.id,
        target_str="198.51.100.1",
        target_hosts=["198.51.100.1"],
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        options={},
    )
    db_session.add(scan)
    db_session.commit()

    with pytest.raises(HTTPException) as exc:
        _read_policy(db_session, scan.id, test_user)
    assert exc.value.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# pol.record.comparison — GAP-13 carries both policies
# ─────────────────────────────────────────────────────────────────────────────


def test_the_comparison_reports_when_two_scans_used_the_same_policy(
    db_session: Session, test_org: Organization, test_user: User, policy_row: ScanPolicy
):
    from core.findings.comparison import compare_scans
    from core.scan_policy import record_policy_snapshot

    policy = effective_from_config(
        policy_row.config, policy_id=policy_row.id, policy_name=policy_row.name
    )
    baseline = _scan(db_session, test_org, test_user)
    current = _scan(db_session, test_org, test_user)
    for scan in (baseline, current):
        record_policy_snapshot(scan, policy)
    db_session.commit()

    comparison = compare_scans(db_session, current=current, baseline=baseline)
    assert comparison.policies_match is True
    assert comparison.current_policy["policy_name"] == "STIG Ubuntu only"
    assert comparison.as_dict()["policies_match"] is True


def test_the_comparison_reports_when_the_configurations_differ(
    db_session: Session, test_org: Organization, test_user: User
):
    """
    Two scans of the same host are not equivalent assessments if one assessed
    more than the other, and a delta between them partly reflects that.
    """
    from core.findings.comparison import compare_scans
    from core.scan_policy import record_policy_snapshot

    baseline = _scan(db_session, test_org, test_user)
    current = _scan(db_session, test_org, test_user)
    record_policy_snapshot(baseline, effective_from_config({"min_severity": "low"}))
    record_policy_snapshot(current, effective_from_config({"min_severity": "critical"}))
    db_session.commit()

    comparison = compare_scans(db_session, current=current, baseline=baseline)
    assert comparison.policies_match is False
    assert comparison.current_policy["recorded"] is True
    assert comparison.baseline_policy["recorded"] is True


def test_two_unrecorded_scans_are_not_reported_as_matching(
    db_session: Session, test_org: Organization, test_user: User
):
    """
    "We do not know how either was configured" is not "they were configured
    identically", and only the second licenses a direct comparison.
    """
    from core.findings.comparison import compare_scans

    baseline = _scan(db_session, test_org, test_user)
    current = _scan(db_session, test_org, test_user)
    comparison = compare_scans(db_session, current=current, baseline=baseline)
    assert comparison.policies_match is False
    assert comparison.current_policy == {"recorded": False}


def test_a_rename_between_two_scans_still_compares_as_the_same_configuration(
    db_session: Session, test_org: Organization, test_user: User
):
    from core.findings.comparison import compare_scans
    from core.scan_policy import record_policy_snapshot

    baseline = _scan(db_session, test_org, test_user)
    current = _scan(db_session, test_org, test_user)
    record_policy_snapshot(
        baseline,
        effective_from_config({"min_severity": "high"}, policy_name="Old name"),
    )
    record_policy_snapshot(
        current,
        effective_from_config(
            {"min_severity": "high"}, policy_name="New name", version_number=7
        ),
    )
    db_session.commit()

    comparison = compare_scans(db_session, current=current, baseline=baseline)
    assert comparison.policies_match is True


# ─────────────────────────────────────────────────────────────────────────────
# pol.record.report — the mandatory reporting requirement
# ─────────────────────────────────────────────────────────────────────────────


def test_the_report_section_is_empty_without_a_snapshot():
    """
    A report generated for a scan that predates this phase must be
    byte-for-byte what it was before — the property ``_comparison_section``
    already preserves and for the same reason.
    """
    from reporting.pdf_generator import _build_styles, _policy_section

    styles = _build_styles()
    assert _policy_section(None, styles) == []
    assert _policy_section({}, styles) == []
    assert _policy_section({"recorded": False}, styles) == []


def test_the_report_section_names_every_setting_an_auditor_needs():
    """
    An auditor reading a finding list must be able to answer "what was actually
    assessed" from the artefact in front of them.
    """
    from core.findings.comparison import policy_context
    from reporting.pdf_generator import _build_styles, _policy_section

    class _S:
        id = "scn_x"
        options = {}

    scan = _S()
    from core.scan_policy import record_policy_snapshot

    record_policy_snapshot(
        scan,
        effective_from_config(
            {
                "framework_ids": ["cfw_bm_stig_ubuntu2404"],
                "benchmark_profile": "stig",
                "min_severity": "high",
                "excluded_check_ids": ["rule_x"],
            },
            policy_name="Ubuntu STIG",
            policy_family_code="ubuntu-stig",
            version_number=3,
        ),
    )
    context = policy_context(scan)
    story = _policy_section(context, _build_styles())
    assert story, "a recorded policy must produce a report section"

    rendered = _rendered(story)
    # Every field the brief names as mandatory reporting.
    for expected in (
        "Ubuntu STIG",
        "cfw_bm_stig_ubuntu2404",
        "stig",
        "high and above",
        "rule_x",
        "ubuntu-stig v3",
    ):
        assert expected in rendered, f"the report must name {expected!r}"


def test_the_report_says_plainly_when_no_policy_was_selected():
    """
    "No policy was selected" and "this report does not show policies" are
    different facts, and only the first is a fact about the scan.
    """
    from core.findings.comparison import policy_context
    from core.scan_policy import effective_for_request, record_policy_snapshot
    from reporting.pdf_generator import _build_styles, _policy_section

    class _S:
        id = "scn_y"
        options = {}

    scan = _S()
    record_policy_snapshot(scan, effective_for_request({"custom_ports": "22"}))
    story = _policy_section(policy_context(scan), _build_styles())
    rendered = _rendered(story)
    assert "No stored policy was selected" in rendered
    assert "None (scan request defaults)" in rendered


def test_the_comparison_section_warns_when_the_policies_differ():
    from reporting.pdf_generator import _build_styles, _comparison_section

    story = _comparison_section(
        {
            "current_scan_id": "scn_b",
            "baseline_scan_id": "scn_a",
            "comparable": True,
            "summary": "3 new, 10 unchanged, 2 fixed",
            "counts": {},
            "severity_counts": {},
            "current_policy": {
                "recorded": True,
                "policy_name": "Strict",
                "version_number": 2,
                "fingerprint": "aaaa1111bbbb2222",
            },
            "baseline_policy": {
                "recorded": True,
                "policy_name": "Loose",
                "version_number": 1,
                "fingerprint": "cccc3333dddd4444",
            },
            "policies_match": False,
            "current_scope": {"recorded": True, "families": [], "assets": []},
            "baseline_scope": {"recorded": True, "families": [], "assets": []},
        },
        _build_styles(),
    )
    rendered = _rendered(story)
    assert "different" in rendered
    assert "Strict" in rendered and "Loose" in rendered


def test_the_comparison_section_confirms_a_matching_configuration():
    from reporting.pdf_generator import _build_styles, _comparison_section

    story = _comparison_section(
        {
            "current_scan_id": "scn_b",
            "baseline_scan_id": "scn_a",
            "comparable": True,
            "summary": "0 new, 10 unchanged",
            "counts": {},
            "severity_counts": {},
            "current_policy": {"recorded": True, "fingerprint": "aaaa1111bbbb2222"},
            "baseline_policy": {"recorded": True, "fingerprint": "aaaa1111bbbb2222"},
            "policies_match": True,
            "current_scope": {"recorded": True, "families": [], "assets": []},
            "baseline_scope": {"recorded": True, "families": [], "assets": []},
        },
        _build_styles(),
    )
    rendered = _rendered(story)
    assert "same assessment configuration" in rendered
    assert "changes in the estate" in rendered


def test_the_methodology_appendix_carries_the_policy():
    """
    The appendix is where a reader skimming for scope looks, and it must not
    silently reuse the pre-existing "Scan policy" row, which is the scan *type*.
    """
    from reporting.pdf_generator import _scan_configuration
    from scans.report_inputs import report_inputs

    class _F:
        reachable_hosts = []
        unreachable_hosts = []
        excluded = []
        vulnerabilities = []

    rows = _scan_configuration(
        {
            "scan_policy": {
                "recorded": True,
                "policy_name": "Ubuntu STIG",
                "fingerprint": "aaaa1111bbbb2222cccc",
                "summary": {
                    "Benchmarks": "cfw_bm_stig_ubuntu2404",
                    "Benchmark profile": "stig",
                    "Severity threshold": "high and above",
                },
            }
        },
        {},
        _F(),
        "vulnerability_audit",
        # Neither the metadata nor the summary records coverage or truncation.
        report_inputs({}, {}),
    )
    labels = {label for label, _value in rows}
    assert "Assessment policy" in labels
    assert "Configuration ID" in labels
    # The pre-existing row is untouched and still means the scan type.
    assert "Scan policy" in labels
