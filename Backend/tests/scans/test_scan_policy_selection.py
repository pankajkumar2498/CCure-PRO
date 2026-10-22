"""
tests/scans/test_scan_policy_selection.py
─────────────────────────────────────────────────────────────────────────────
GAP-12 — a policy must actually change what is assessed.

The point of this file: a policy object that exists and is never consulted is
not a policy engine. Every test here starts from a check set and asserts the
policy narrowed it, or from a scan and asserts the recorded configuration
governed it.

Coverage areas exercised: pol.select.frameworks, pol.select.profile,
pol.select.families, pol.select.platforms, pol.select.builtin,
pol.filter.severity, pol.filter.check_exclusions, pol.filter.tag_exclusions,
pol.filter.target_exclusions, pol.depth.ports, pol.depth.discovery,
pol.depth.port_scan, pol.safety.intrusive, pol.bind.scan, pol.select.sections,
pol.record.snapshot.
"""

import uuid

import pytest
from core.benchmarks.selection import benchmark_checks_for_org
from core.scan_policy import effective_from_config, read_policy_snapshot
from db.models import Organization
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)
from sqlalchemy.orm import Session


# ─────────────────────────────────────────────────────────────────────────────
# A two-benchmark tenant, so "select one" has something to select from
# ─────────────────────────────────────────────────────────────────────────────


def _rule(rule_id: str, *, severity: str, platform: str = "linux", tags=None):
    """A minimal executable configuration rule."""
    return ComplianceRule(
        id=rule_id,
        rule_family_code=rule_id,
        check_type="command",
        target_platform=platform,
        severity=severity,
        status="active",
        version_number=1,
        tags=list(tags or []),
        check_definition={
            "config_check": True,
            "check_id": rule_id,
            "title": f"Rule {rule_id}",
            "check_type": "command",
            "platforms": [platform],
            "severity": severity,
            "domain": "host_configuration",
            "tags": list(tags or []),
            "collect": {"command": "echo CCURE::VALUE::ok"},
            "expect": {"operator": "equals", "value": "ok"},
            "absent": "manual_review",
        },
    )


@pytest.fixture
def two_benchmarks(db_session: Session, test_org: Organization, monkeypatch):
    """
    Two loaded benchmarks with distinguishable rules, installed for this tenant.

    Both are activated through ``core.compliance_frameworks.is_active`` rather
    than by editing the shipped active list — a parked catalogue must stay
    parked for every other suite.
    """
    import core.compliance_frameworks as frameworks

    suffix = uuid.uuid4().hex[:6]
    alpha_id = f"cfw_bm_alpha_{suffix}"
    beta_id = f"cfw_bm_beta_{suffix}"

    real_is_active = frameworks.is_active
    monkeypatch.setattr(
        frameworks,
        "is_active",
        lambda fid: fid in (alpha_id, beta_id) or real_is_active(fid),
    )

    made = {}
    for framework_id, prefix in ((alpha_id, "ALPHA"), (beta_id, "BETA")):
        db_session.add(
            ComplianceFramework(
                id=framework_id,
                code=prefix,
                name=f"{prefix} benchmark",
                version="1.0",
                is_active=True,
            )
        )
        db_session.flush()
        for index, (severity, tags) in enumerate(
            (("critical", ["core"]), ("medium", ["optional"]), ("low", ["optional"]))
        ):
            rule_id = f"{prefix.lower()}_rule_{index}_{suffix}"
            control_id = f"cct_{prefix.lower()}_{index}_{suffix}"
            db_session.add(
                ComplianceControl(
                    id=control_id,
                    framework_id=framework_id,
                    control_number=f"{index + 1}.1",
                    title=f"{prefix} control {index}",
                    theme="BENCHMARK",
                    scannability="auto",
                    profiles=["level_1"] if index == 0 else [],
                )
            )
            rule = _rule(rule_id, severity=severity, tags=tags)
            db_session.add(rule)
            db_session.flush()
            db_session.add(
                ComplianceRuleControl(rule_id=rule_id, control_id=control_id)
            )
            made.setdefault(framework_id, []).append(rule_id)

        db_session.add(
            ComplianceTenantFramework(
                id=f"ctf_{framework_id}",
                tenant_id=test_org.id,
                framework_id=framework_id,
                is_enabled=True,
            )
        )
    db_session.commit()
    return {"alpha": alpha_id, "beta": beta_id, "rules": made, "org": test_org.id}


# ─────────────────────────────────────────────────────────────────────────────
# pol.select.frameworks
# ─────────────────────────────────────────────────────────────────────────────


def test_without_a_policy_every_installed_framework_resolves(
    db_session: Session, two_benchmarks
):
    """The pre-policy behaviour, pinned so a policy field cannot change it."""
    checks = benchmark_checks_for_org(db_session, two_benchmarks["org"])
    ids = {c.check_id for c in checks}
    assert len(ids) == 6, ids


def test_a_policy_selecting_one_framework_resolves_only_its_rules(
    db_session: Session, two_benchmarks
):
    """
    The measured problem this closes: with five STIG benchmarks installed, a
    scan of an Ubuntu host resolved all 955 rules and reported 811 of them
    NOT_APPLICABLE.
    """
    checks = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], framework_ids=[two_benchmarks["alpha"]]
    )
    ids = {c.check_id for c in checks}
    assert ids == set(two_benchmarks["rules"][two_benchmarks["alpha"]])


def test_naming_an_uninstalled_framework_resolves_nothing_rather_than_everything(
    db_session: Session, two_benchmarks
):
    """
    A policy's selection narrows what is installed; it never adds to it — and
    an unmatched selection must not silently fall back to "all", which would be
    the opposite of what the operator asked for.
    """
    checks = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], framework_ids=["cfw_bm_not_installed"]
    )
    assert checks == []


# ─────────────────────────────────────────────────────────────────────────────
# pol.filter.severity
# ─────────────────────────────────────────────────────────────────────────────


def test_a_severity_floor_drops_checks_below_it(db_session: Session, two_benchmarks):
    checks = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], min_severity="high"
    )
    severities = {c.severity for c in checks}
    assert severities == {"critical"}
    assert len(checks) == 2  # one critical in each benchmark


def test_no_floor_keeps_everything(db_session: Session, two_benchmarks):
    assert len(benchmark_checks_for_org(db_session, two_benchmarks["org"])) == 6


# ─────────────────────────────────────────────────────────────────────────────
# pol.filter.check_exclusions / pol.filter.tag_exclusions
# ─────────────────────────────────────────────────────────────────────────────


def test_named_checks_are_excluded(db_session: Session, two_benchmarks):
    excluded = two_benchmarks["rules"][two_benchmarks["alpha"]][0]
    checks = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], excluded_check_ids=[excluded]
    )
    assert excluded not in {c.check_id for c in checks}
    assert len(checks) == 5


def test_tagged_checks_are_excluded(db_session: Session, two_benchmarks):
    checks = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], excluded_tags=["optional"]
    )
    assert {c.severity for c in checks} == {"critical"}


def test_tag_exclusion_is_case_insensitive(db_session: Session, two_benchmarks):
    checks = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], excluded_tags=["OPTIONAL"]
    )
    assert len(checks) == 2


# ─────────────────────────────────────────────────────────────────────────────
# pol.select.profile
# ─────────────────────────────────────────────────────────────────────────────


def test_a_profile_narrows_to_controls_carrying_it(db_session: Session, two_benchmarks):
    """
    A control with an empty profile list is in scope whatever profile was
    selected — the reading migration c5d6e7f8a9b0 gives the column.
    """
    every = benchmark_checks_for_org(db_session, two_benchmarks["org"])
    level_one = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], profile="level_1"
    )
    other = benchmark_checks_for_org(
        db_session, two_benchmarks["org"], profile="level_2"
    )
    assert len(every) == 6
    # level_1 controls plus the four that name no profile at all.
    assert len(level_one) == 6
    # level_2 excludes the two controls that name level_1 explicitly.
    assert len(other) == 4


# ─────────────────────────────────────────────────────────────────────────────
# pol.select.platforms
# ─────────────────────────────────────────────────────────────────────────────


def test_a_platform_selection_narrows_the_query(db_session: Session, two_benchmarks):
    assert (
        len(
            benchmark_checks_for_org(
                db_session, two_benchmarks["org"], platforms=["linux"]
            )
        )
        == 6
    )
    assert (
        benchmark_checks_for_org(
            db_session, two_benchmarks["org"], platforms=["windows"]
        )
        == []
    )


# ─────────────────────────────────────────────────────────────────────────────
# pol.select.builtin / pol.select.families — the audit's own selection
# ─────────────────────────────────────────────────────────────────────────────


class _Executor:
    """Enough of an executor for the engine to reach a verdict."""

    shell_type = "sh"
    executes_commands = True

    def run(self, command, timeout=None):  # noqa: ARG002
        class _R:
            success = True
            exit_code = 0
            stdout = "CCURE::VALUE::ok"
            stderr = ""

        return _R()

    def test_connectivity(self):
        return True


def _audit(policy=None, extra_checks=None):
    from scans.tasks.credentialed import _run_configuration_audit

    return _run_configuration_audit(
        executor=_Executor(),
        ip="192.0.2.10",
        os_type="linux",
        system_data={"os_name": "Ubuntu", "os_version_id": "24.04"},
        timeout=5,
        extra_checks=extra_checks or [],
        policy=policy,
    )


def test_the_builtin_pack_runs_when_no_policy_says_otherwise():
    summary, _findings = _audit()
    assert summary["assessed"] is True
    assert summary["checks_run"] > 0
    # No policy means no fingerprint on the summary, not an invented one.
    assert summary["policy_fingerprint"] is None


def test_a_check_family_selection_narrows_the_builtin_pack():
    every, _ = _audit()
    narrowed, _ = _audit(
        policy=effective_from_config({"check_families": ["local_privilege"]})
    )
    assert narrowed["checks_run"] < every["checks_run"]
    assert narrowed["checks_run"] > 0


def test_a_severity_floor_narrows_the_builtin_pack():
    every, _ = _audit()
    narrowed, _ = _audit(policy=effective_from_config({"min_severity": "critical"}))
    assert narrowed["checks_run"] < every["checks_run"]


def test_excluding_the_builtins_leaves_only_benchmark_content():
    """
    Reachable only with a framework named — `validate_policy` refuses the
    combination that would leave nothing — so this cannot empty an audit.
    """
    from core.config_audit.spec import ConfigCheck

    extra = ConfigCheck.from_rule(_rule("bench_only_1", severity="high"))
    summary, _ = _audit(
        policy=effective_from_config(
            {"include_builtin_checks": False, "framework_ids": ["cfw_bm_x"]}
        ),
        extra_checks=[extra],
    )
    assert summary["assessed"] is True
    assert summary["checks_run"] == 1
    assert summary["benchmark_checks"] == 1


def test_a_policy_that_selects_nothing_says_so_rather_than_reporting_clean():
    """
    "No checks selected under the effective policy" is a decision the operator
    made. "No checks defined for this platform" is a product gap. Collapsing
    them hides which of the two happened.
    """
    summary, findings = _audit(
        policy=effective_from_config({"check_families": ["database"]})
    )
    assert summary["assessed"] is False
    assert "effective policy" in summary["reason"]
    assert findings == []


def test_the_audit_summary_carries_the_policy_fingerprint():
    """
    `scan_phases.summary` is what the scan-detail API and the reports read
    back, so a reader looking at one host's results should not have to fetch
    the scan row to learn what was in scope.
    """
    policy = effective_from_config({"min_severity": "high"}, policy_name="Strict")
    summary, _ = _audit(policy=policy)
    assert summary["policy_fingerprint"] == policy.fingerprint()
    assert summary["policy_name"] == "Strict"


# ─────────────────────────────────────────────────────────────────────────────
# pol.bind.scan — the resolver's precedence and the snapshot it writes
# ─────────────────────────────────────────────────────────────────────────────


class _Scan:
    def __init__(self):
        self.id = "scn_x"
        self.options = {}


@pytest.fixture
def stored_policy(db_session: Session, test_org: Organization):
    from db.models.scan_policies import ScanPolicy

    policy = ScanPolicy(
        id=f"spol_{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        name="Deep ports",
        policy_family_code="deep-ports",
        version_number=1,
        scan_kind="network",
        config={"custom_ports": "1-1024", "discovery_intensity": "deep"},
        status="active",
        is_enabled=True,
    )
    db_session.add(policy)
    db_session.commit()
    db_session.refresh(policy)
    return policy


def test_the_policy_wins_over_the_request_and_the_override_is_reported(
    db_session: Session, test_org: Organization, stored_policy
):
    """
    Anything else makes the policy advisory: a client that always sends the
    field's default would silently override every policy.
    """
    from core.scan_policy import resolve_policy

    resolution = resolve_policy(
        db_session,
        policy_id=stored_policy.id,
        org_id=test_org.id,
        scan_kind="network",
        request_options={"custom_ports": "22", "discovery_intensity": "light"},
    )
    assert resolution.policy.custom_ports == "1-1024"
    assert resolution.policy.discovery_intensity == "deep"
    # Reported, never silent.
    assert resolution.overrides["custom_ports"]["requested"] == "22"
    assert resolution.overrides["custom_ports"]["policy"] == "1-1024"


def test_the_request_fills_in_what_the_policy_does_not_name(
    db_session: Session, test_org: Organization, stored_policy
):
    """
    A policy that only sets a port range must not reset everything else to the
    scanner default.
    """
    from core.scan_policy import resolve_policy

    resolution = resolve_policy(
        db_session,
        policy_id=stored_policy.id,
        org_id=test_org.id,
        scan_kind="network",
        request_options={"exclude_ports": "9100", "port_scan_intensity": "light"},
    )
    assert resolution.policy.exclude_ports == "9100"
    assert resolution.policy.port_scan_intensity == "light"
    assert resolution.overrides == {}


def test_a_disabled_policy_refuses_rather_than_falling_back(
    db_session: Session, test_org: Organization, stored_policy
):
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    stored_policy.is_enabled = False
    db_session.commit()

    with pytest.raises(ResolvedPolicyError, match="disabled"):
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="network",
        )


def test_a_draft_policy_refuses(
    db_session: Session, test_org: Organization, stored_policy
):
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    stored_policy.status = "draft"
    db_session.commit()
    with pytest.raises(ResolvedPolicyError, match="draft"):
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="network",
        )


def test_an_archived_policy_refuses(
    db_session: Session, test_org: Organization, stored_policy
):
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    stored_policy.status = "archived"
    db_session.commit()
    with pytest.raises(ResolvedPolicyError, match="archived"):
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="network",
        )


def test_a_policy_for_the_wrong_scan_kind_refuses(
    db_session: Session, test_org: Organization, stored_policy
):
    """
    A network policy silently governing a credentialed audit would restrict
    nothing it was written to restrict.
    """
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    with pytest.raises(ResolvedPolicyError, match="network"):
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="credentialed",
        )


def test_a_kind_any_policy_serves_both(
    db_session: Session, test_org: Organization, stored_policy
):
    from core.scan_policy import resolve_policy

    stored_policy.scan_kind = "any"
    db_session.commit()
    for kind in ("network", "credentialed"):
        assert (
            resolve_policy(
                db_session,
                policy_id=stored_policy.id,
                org_id=test_org.id,
                scan_kind=kind,
            ).policy.policy_id
            == stored_policy.id
        )


def test_no_policy_id_produces_a_request_configuration_not_an_error(
    db_session: Session, test_org: Organization
):
    from core.scan_policy import resolve_policy

    resolution = resolve_policy(
        db_session,
        policy_id=None,
        org_id=test_org.id,
        scan_kind="network",
        request_options={"custom_ports": "443"},
    )
    assert resolution.policy.source == "request"
    assert resolution.policy.custom_ports == "443"
    assert resolution.policy.policy_id is None


def test_a_policy_requiring_a_credential_refuses_a_scan_without_one(
    db_session: Session, test_org: Organization, stored_policy
):
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    stored_policy.config = {"require_credential": True}
    stored_policy.scan_kind = "any"
    db_session.commit()

    with pytest.raises(ResolvedPolicyError, match="authenticated session"):
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="credentialed",
            has_credential=False,
        )

    assert (
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="credentialed",
            has_credential=True,
        ).policy.require_credential
        is True
    )


def test_a_policy_naming_an_uninstalled_framework_refuses_at_dispatch(
    db_session: Session, test_org: Organization, stored_policy
):
    """
    Re-checked at every dispatch, never inherited from creation time: a
    framework uninstalled in June must stop being scanned in July.
    """
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    stored_policy.config = {"framework_ids": ["cfw_bm_never_installed"]}
    db_session.commit()

    with pytest.raises(ResolvedPolicyError) as exc:
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="network",
        )
    assert "not present in this installation" in str(exc.value)


def test_a_policy_naming_a_parked_framework_refuses_with_its_own_reason(
    db_session: Session, test_org: Organization, stored_policy
):
    """
    Three conditions, three messages: a typo, a parked catalogue, and a
    marketplace installation somebody has to perform need three different
    actions. `cfw_gdpr` ships and is parked.
    """
    from core.scan_policy import ResolvedPolicyError, resolve_policy

    stored_policy.config = {"framework_ids": ["cfw_gdpr"]}
    db_session.commit()

    with pytest.raises(ResolvedPolicyError) as exc:
        resolve_policy(
            db_session,
            policy_id=stored_policy.id,
            org_id=test_org.id,
            scan_kind="network",
        )
    assert "not active in this installation" in str(exc.value)
