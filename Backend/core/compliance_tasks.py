"""
core/compliance_tasks.py
Celery background worker tasks for the Policy Compliance Engine.
"""

import hashlib
import logging
import re
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from core.celery_app import celery_app
from core.compliance_evidence import ComplianceEvidenceProvider
from core.compliance_frameworks import is_active as is_active_framework
from core.config_audit.operators import evaluate as _shared_evaluate
from core.config_audit.spec import ConfigCheck
from db.base import SessionLocal
from db.models import Asset, Service
from db.models.compliance import (
    ComplianceControl,
    ComplianceException,
    ComplianceFinding,
    ComplianceFindingHistory,
    CompliancePolicyRule,
    ComplianceRemediation,
    ComplianceRemediationRequest,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceRuleDependency,
    ComplianceScanRun,
    ComplianceScore,
    ComplianceTenantFramework,
)
from db.models.credentials import ComplianceCredential
from sqlalchemy import or_
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.compliance.tasks")

# Risk weights used by the weighted score. Shared so the scorer and any caller
# reporting "why is this control weighted like that" agree.
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}

# Evidence sources that can only be collected by authenticating to the host.
# A rule reading one of these on a host with no working credentials has not
# been assessed; it has not failed.
CREDENTIALED_EVIDENCE_SOURCES: frozenset = frozenset(
    {
        "offline_configuration",
        "malware_scan",
        "vulnerability_audit",
        "credential_validation",
    }
)


# ─────────────────────────────────────────────────────────────────────────────
# Identity Helpers
#
# Finding and score ids used to be built by slicing the tail off each component
# (`control_id[-8:]`, `rule_id[-8:]`, `framework_id[-8:]`). Two controls whose
# ids agree in their last eight characters — which is common once a framework
# numbers its controls `..._8_15` / `..._8_16` — collapsed onto one row, and the
# second finding silently overwrote the first. Ids are hashed instead: the
# components are joined with a separator that cannot appear inside them and
# digested, so distinct inputs cannot collide and the id stays inside the
# column width.
# ─────────────────────────────────────────────────────────────────────────────

ORG_LEVEL_SENTINEL = "__org__"


def _stable_id(prefix: str, *parts: Optional[str]) -> str:
    """Builds a collision-free, deterministic id from its components."""
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]
    return f"{prefix}_{digest}"


def finding_id_for(
    org_id: str, asset_id: Optional[str], control_id: str, rule_id: Optional[str]
) -> str:
    """Deterministic id for an auto-scan finding.

    Callers outside this module (the attestation endpoint) rely on this being
    the *only* way an org-level finding id is derived, so a human attestation
    and the scan's placeholder for the same control resolve to one row rather
    than two rows whose statuses then fight each other in the rollup.
    """
    return _stable_id(
        "cfnd",
        org_id,
        asset_id or ORG_LEVEL_SENTINEL,
        control_id,
        rule_id or "",
    )


def org_finding_id_for(org_id: str, control_id: str) -> str:
    """Deterministic id for the single org-level finding of a manual control."""
    return _stable_id("cfnd", org_id, ORG_LEVEL_SENTINEL, control_id, "")


def _history_id() -> str:
    """History rows are append-only, so they need uniqueness, not determinism."""
    return f"cfh_{uuid.uuid4().hex[:24]}"


# ─────────────────────────────────────────────────────────────────────────────
# Status Rollup
#
# One shared precedence table. Four call sites used to roll findings up and
# only one of them did it correctly: the other three built
# `{f.control_id: f for f in findings}`, an unordered dict comprehension in
# which the last row the database happened to return decided the control. A
# host with SSH closed and SMB open could therefore score `pass` on a control
# covering both. Everything rolls up through here now.
# ─────────────────────────────────────────────────────────────────────────────

# Worst-first. A control is only as compliant as its weakest evidence, with one
# deliberate exception: an explicit human attestation outranks the engine's own
# "not yet assessed" placeholder, because a reviewed control is more
# authoritative than an unreviewed one, not less. `manual_review` therefore
# sits *below* `pass` and `not_applicable` rather than above them.
_STATUS_PRECEDENCE = (
    "fail",
    "pending_reverify",
    "remediation_applied",
    "manual_review",
    "exception",
    "pass",
    "not_applicable",
)

# Statuses a human recorded deliberately. When any of these is present for a
# control, the engine's unreviewed placeholders are discarded before the
# precedence table is applied.
_ATTESTED_STATUSES = frozenset({"pass", "fail", "not_applicable", "exception"})


def _worst_rule_id(db: Session, findings: list) -> Optional[str]:
    """Picks the most severe rule among a control's findings, for weighting."""
    rule_ids = [f.rule_id for f in findings if f.rule_id]
    if not rule_ids:
        return None
    rules = db.query(ComplianceRule).filter(ComplianceRule.id.in_(rule_ids)).all()
    if not rules:
        return None
    return max(
        rules,
        key=lambda r: SEVERITY_WEIGHTS.get((r.severity or "medium").lower(), 5.0),
    ).id


def roll_up_statuses(entries: list) -> Optional[str]:
    """Collapses every finding on one control into a single verdict.

    `entries` is a list of (status, source) pairs. Returns None when there is
    nothing to roll up, which the scorer reads as "not assessed".
    """
    if not entries:
        return None

    attested = [
        status
        for status, source in entries
        if source == "manual_attestation" and status in _ATTESTED_STATUSES
    ]
    considered = attested if attested else [status for status, _ in entries]

    for candidate in _STATUS_PRECEDENCE:
        if candidate in considered:
            return candidate
    return considered[0] if considered else None


# ─────────────────────────────────────────────────────────────────────────────
# Rule → Control Resolution
#
# A rule is deliberately crosswalked to controls in many frameworks, so asking
# for "the" control of a rule has no answer without naming the framework. The
# previous `.first()` with no ORDER BY and no framework filter returned an
# arbitrary row: measured on the live catalogue, 57 of the 114 rules in the ISO
# default policy resolved to a control belonging to a *different* standard, so
# an ISO scan wrote half its findings onto DPDP, GDPR and IEC 62443 controls
# and ISO itself scored as unassessed. Postgres is also free to return a
# different row each time, so the same scan could score differently twice.
# ─────────────────────────────────────────────────────────────────────────────


def resolve_controls_for_rule(
    db: Session, rule_id: str, framework_id: str
) -> list[str]:
    """Returns every control this rule covers *within one framework*, ordered.

    Ordering is explicit so the result is reproducible across runs. An empty
    list means the rule contributes nothing to this framework and the caller
    must skip it rather than guess a control.
    """
    rows = (
        db.query(ComplianceControl.id)
        .join(
            ComplianceRuleControl,
            ComplianceRuleControl.control_id == ComplianceControl.id,
        )
        .filter(
            ComplianceRuleControl.rule_id == rule_id,
            ComplianceControl.framework_id == framework_id,
        )
        .order_by(ComplianceControl.control_number, ComplianceControl.id)
        .all()
    )
    return [r[0] for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Operator Evaluation Helper
# ─────────────────────────────────────────────────────────────────────────────


def _evaluate_operator(operator: str, actual: Any, expected: Any) -> bool:
    """
    Applies criteria operators to normalize evidence values.

    The implementation moved to ``core/config_audit/operators.py`` in Phase 3,
    where the configuration audit engine needs the same comparisons plus a few
    more. This is now a delegate rather than a second copy: two evaluators for
    one vocabulary is how ``gte`` comes to mean different things in two parts
    of one product, and the seeded rule catalogue depends on these semantics
    exactly as they were.

    Behaviour here is unchanged. The shared module can additionally report
    "the comparison could not be performed" for an unimplemented operator —
    which the previous bare ``return False`` recorded as a *failure* against
    every host — but this entry point keeps collapsing that to False so no
    existing compliance rule changes verdict. New callers should use
    ``evaluate_detailed`` and honour the third state.
    """
    return _shared_evaluate(operator, actual, expected)


def _evaluate_operator_legacy(operator: str, actual: Any, expected: Any) -> bool:
    """
    The pre-Phase-3 implementation, retained as the reference the shared
    module is tested against.

    ``tests/scans/test_config_audit_operators.py`` runs both over a truth table
    covering every shared operator against list, scalar, numeric, empty and
    None inputs, and fails on any disagreement. Keeping the original code is
    what makes that test meaningful — a test comparing a function to itself
    proves nothing, and simply asserting the new behaviour would not have
    caught a semantic drift introduced during the move.
    """
    # Emptiness is a verdict in its own right and has to be decided before the
    # None guard: "this host lists no NTP server" (A.8.17) and "this host was
    # never asked about NTP" are different findings, and only the caller's
    # missing-key check can tell them apart. By the time a key is present, an
    # empty list is an observation.
    if operator in ("not_empty", "is_empty"):
        empty = actual is None or (
            len(actual) == 0
            if isinstance(actual, (list, tuple, set, dict, str))
            else False
        )
        return empty if operator == "is_empty" else not empty

    if actual is None:
        return False

    # Handle expected list structure safely
    if isinstance(expected, (list, tuple, set)):
        expected_str_list = [str(x).strip().lower() for x in expected]
    else:
        expected_str_list = [str(expected).strip().lower()]

    expected_str = expected_str_list[0] if expected_str_list else ""

    # 1. Actual value is list-like (e.g. ntp_servers, open_ports)
    if isinstance(actual, (list, tuple, set)):
        actual_str_list = [str(x).strip().lower() for x in actual]

        if operator == "contains":
            return any(exp in actual_str_list for exp in expected_str_list)
        elif operator == "not_contains":
            return not any(exp in actual_str_list for exp in expected_str_list)

    # 2. Actual value is a scalar string
    actual_str = str(actual).strip().lower()

    if operator in ("equals", "=="):
        return actual_str == expected_str
    elif operator == "not_equals":
        return actual_str != expected_str
    elif operator == "contains":
        return any(exp in actual_str for exp in expected_str_list)
    elif operator == "not_contains":
        return not any(exp in actual_str for exp in expected_str_list)
    elif operator in ("gte", "lte", "gt", "lt"):
        try:
            act_num = float(actual)
            exp_num = float(expected)
            if operator == "gte":
                return act_num >= exp_num
            elif operator == "lte":
                return act_num <= exp_num
            elif operator == "gt":
                return act_num > exp_num
            elif operator == "lt":
                return act_num < exp_num
        except (ValueError, TypeError):
            return False
    elif operator in ("version_gte", "version_lte"):

        def parse_v(v):
            return [int(x) for x in re.findall(r"\d+", str(v))]

        try:
            act_v = parse_v(actual)
            exp_v = parse_v(expected)
            if operator == "version_gte":
                return act_v >= exp_v
            else:
                return act_v <= exp_v
        except Exception:
            return False

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Dependency Prerequisite Check Helper
# ─────────────────────────────────────────────────────────────────────────────


def _check_prerequisites(
    db: Session, asset: Asset, rule: ComplianceRule, org_id: str
) -> bool:
    """Verifies rule dependency prerequisites and credentialed scan status."""
    # 1. Verify credential status for credential-dependent rules.
    #
    # `credential_validation` belongs on this list and was missing from it. Its
    # own evidence key is "did the credentialed scan succeed", so on a host
    # that was never authenticated the rule evaluated to a *failure* rather
    # than routing to manual_review like the other three credentialed sources —
    # reporting a control as breached when the only fact established was that
    # the scanner had no credentials for that host.
    if rule.evidence_source in CREDENTIALED_EVIDENCE_SOURCES:
        creds_status = (asset.custom_attributes or {}).get(
            "credentialed_status", "unknown"
        )
        if creds_status != "success":
            return False

    # 2. Check rule dependency links
    deps = (
        db.query(ComplianceRuleDependency)
        .filter(ComplianceRuleDependency.rule_id == rule.id)
        .all()
    )

    for dep in deps:
        finding = (
            db.query(ComplianceFinding)
            .filter(
                ComplianceFinding.asset_id == asset.id,
                ComplianceFinding.rule_id == dep.depends_on_rule_id,
                ComplianceFinding.tenant_id == org_id,
            )
            .first()
        )

        if not finding or finding.status != "pass":
            return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Task 1: Trigger Scan baseline run
# ─────────────────────────────────────────────────────────────────────────────


@celery_app.task(name="compliance.run_scan", queue="compliance")
def run_scan_task(scan_run_id: str, org_id: str) -> dict:
    """Evaluates rules mapping against asset scope configurations."""
    db = SessionLocal()
    run = None
    try:
        run = (
            db.query(ComplianceScanRun)
            .filter(ComplianceScanRun.id == scan_run_id)
            .first()
        )
        if not run:
            log.error(f"Scan run {scan_run_id} not found.")
            return {"success": False, "error": "Scan run not found"}

        run.status = "running"
        run.started_at = run.started_at or datetime.now(timezone.utc)
        db.commit()

        framework_id = run.framework_id

        # 1. Resolve Asset Scope
        scope = run.scope or {}
        asset_ids = scope.get("asset_ids", [])
        asset_tags = scope.get("asset_tags", [])

        asset_query = db.query(Asset).filter(Asset.org_id == org_id)
        if asset_ids:
            asset_query = asset_query.filter(Asset.id.in_(asset_ids))
        assets = asset_query.all()

        # Tag scoping was accepted by the API, stored on the run, and then
        # never applied — a scan the operator scoped to "cde" silently
        # assessed every asset in the organisation. Matching is
        # case-insensitive against both the asset's tag list and the
        # `tags` key some collectors write into custom_attributes.
        if asset_tags:
            wanted = {str(t).strip().lower() for t in asset_tags if str(t).strip()}
            scoped = []
            for asset in assets:
                have = {str(t).strip().lower() for t in (asset.tags or [])}
                extra = (asset.custom_attributes or {}).get("tags") or []
                if isinstance(extra, (list, tuple)):
                    have |= {str(t).strip().lower() for t in extra}
                if wanted & have:
                    scoped.append(asset)
            assets = scoped

        # Apply CDE scope filter if run has cde_scope defined
        if run.cde_scope:
            filtered_assets = []
            cde_scope_lower = run.cde_scope.lower()
            for asset in assets:
                asset_tags_list = [t.lower() for t in (asset.tags or [])]
                cde_scope_attr = (asset.custom_attributes or {}).get("cde_scope")
                if (
                    "cde" in asset_tags_list
                    or cde_scope_lower in asset_tags_list
                    or (
                        cde_scope_attr
                        and str(cde_scope_attr).lower() == cde_scope_lower
                    )
                ):
                    filtered_assets.append(asset)
            assets = filtered_assets

        if not assets:
            # Nothing was assessed, and the run must say so (finding F6). It was
            # recorded as `completed`, which the workspace announced as a
            # finished compliance scan — a run over zero assets is not a clean
            # result. `not_assessed` also keeps it out of `_latest_run_id`, so
            # the previous real results stay the ones shown. The reason travels
            # in `error_message`, the run's only free-text field.
            run.status = "not_assessed"
            run.finished_at = datetime.now(timezone.utc)
            run.error_message = (
                "No assets matched this scan's scope, so nothing was assessed. "
                "Check the asset selection or tags, or run a network scan first."
            )
            db.commit()
            return {
                "success": True,
                "status": "not_assessed",
                "message": "No assets in scope.",
            }

        # Flush stale Redis evidence cache for targeted assets using pipeline
        resolved_asset_ids = [a.id for a in assets]
        ComplianceEvidenceProvider.invalidate_asset_evidence_cache(resolved_asset_ids)

        # 2. Resolve Policy Rules
        #
        # Only `active` rules are evaluated. The documented lifecycle is
        # draft -> active -> archived, where a draft is still being authored and
        # an archived version has been superseded; evaluating either produces
        # findings against a check the organisation has not published or has
        # already replaced. Ordering keeps the evaluation sequence — and so the
        # evidence timestamps — reproducible between runs.
        policy_rules = (
            db.query(CompliancePolicyRule)
            .filter(CompliancePolicyRule.policy_id == run.policy_id)
            .all()
        )
        rule_ids = [pr.rule_id for pr in policy_rules]
        rules = (
            db.query(ComplianceRule)
            .filter(
                ComplianceRule.id.in_(rule_ids),
                ComplianceRule.status == "active",
            )
            .order_by(ComplianceRule.rule_family_code, ComplianceRule.version_number)
            .all()
        )

        # Resolve each rule to the controls it covers *in this run's framework*,
        # once, up front. A rule that maps to no control here belongs to another
        # standard and is skipped: writing its verdict onto an arbitrary control
        # is what made an ISO scan populate DPDP and IEC 62443 instead.
        controls_for_rule: dict[str, list[str]] = {
            rule.id: resolve_controls_for_rule(db, rule.id, framework_id)
            for rule in rules
        }
        skipped_foreign = [r.id for r in rules if not controls_for_rule[r.id]]
        if skipped_foreign:
            log.info(
                "Scan run %s: %d of %d policy rules map to no control in %s and "
                "were skipped.",
                scan_run_id,
                len(skipped_foreign),
                len(rules),
                framework_id,
            )
        rules = [r for r in rules if controls_for_rule[r.id]]

        # 3. Evaluation Loop
        now = datetime.now(timezone.utc)
        for asset in assets:
            for rule in rules:
                control_ids = controls_for_rule[rule.id]

                # 3.0. A configuration-audit rule is not evaluated here.
                #
                # These are Phase 3 rules — a registry value, a file mode, a
                # service state — and they are evaluated by the configuration
                # audit engine against a *live host* during a credentialed
                # scan, then written by `core.compliance_sync`.
                #
                # This loop would find no `key` in the check definition, read
                # that as missing evidence, and write `manual_review` **over
                # the real verdict the host scan produced**. A compliance scan
                # would then silently blank every benchmark result the last
                # credentialed scan established.
                #
                # Skipping leaves the existing finding untouched, which is
                # correct: it is refreshed when the host is next scanned, and
                # its `updated_at` is the honest answer to "how old is this
                # verdict".
                if ConfigCheck.is_config_rule(rule):
                    continue

                # 3.1. Prerequisite verification
                if not _check_prerequisites(db, asset, rule, org_id):
                    _save_finding(
                        db,
                        org_id,
                        asset.id,
                        rule,
                        control_ids,
                        run_id=scan_run_id,
                        status="manual_review",
                        evidence={
                            "message": (
                                "This check needs a successful credentialed scan of "
                                "the host, or a prerequisite check that has not "
                                "passed. The control has not been assessed."
                            ),
                            "evidence_source": rule.evidence_source,
                        },
                    )
                    continue

                # 3.1.5 Platform compatibility check
                platform_verdict = _platform_applicability(asset, rule)
                if platform_verdict is not None:
                    status, message = platform_verdict
                    _save_finding(
                        db,
                        org_id,
                        asset.id,
                        rule,
                        control_ids,
                        run_id=scan_run_id,
                        status=status,
                        evidence={"message": message},
                    )
                    continue

                # 3.2. Check if rule is a manual check (skip per-asset findings to avoid org score deadlock)
                if rule.evidence_source == "manual":
                    continue

                # 3.3. Resolve normalized evidence
                if rule.evidence_source:
                    evidence = ComplianceEvidenceProvider.get_normalized_evidence(
                        db, asset.id, rule.evidence_source
                    )
                else:
                    evidence = {"configured_value": "configured"}

                # 3.3. Criteria matching
                check_def = rule.check_definition or {}
                key = check_def.get("key")

                # A control with no evidence has not been assessed, and an
                # unassessed control is not a failed one. Previously any missing
                # key evaluated to False and was recorded as "fail", so an asset
                # that had simply never been scanned for a given source reported
                # as non-compliant against every rule using it — a finding the
                # customer cannot act on and an auditor cannot accept.
                evidence_missing = (
                    not evidence
                    or evidence.get("_evidence_available") is False
                    or (key and key not in evidence)
                )
                if evidence_missing:
                    _save_finding(
                        db,
                        org_id,
                        asset.id,
                        rule,
                        control_ids,
                        run_id=scan_run_id,
                        status="manual_review",
                        evidence={
                            "message": (
                                evidence.get("_reason")
                                if isinstance(evidence, dict)
                                and evidence.get("_reason")
                                else (
                                    f"No '{rule.evidence_source}' evidence has been "
                                    f"collected for this asset, so the control could "
                                    f"not be evaluated."
                                )
                            ),
                            "evidence_source": rule.evidence_source,
                            "required_key": key,
                        },
                    )
                    continue

                actual_val = evidence.get(key) if key else None

                passed = _evaluate_operator(
                    operator=check_def.get("operator", "equals"),
                    actual=actual_val,
                    expected=check_def.get("expected"),
                )

                status = "pass" if passed else "fail"
                _save_finding(
                    db,
                    org_id,
                    asset.id,
                    rule,
                    control_ids,
                    run_id=scan_run_id,
                    status=status,
                    evidence=evidence,
                )

            # 3.4. Calculate Asset Compliance Score
            _calculate_compliance_score(db, org_id, framework_id, asset.id, scan_run_id)

        # 3.4.5 Process manual governance rules at organization level (asset_id = None)
        #
        # One org-level finding per control, at a deterministic id, refreshed on
        # every run. It used to be written once and never again — and under an id
        # that could not collide with the one the attestation endpoint derives,
        # so attesting a control produced a *second* org-level row whose `pass`
        # then lost the rollup to the stale placeholder's `manual_review`. For
        # ISO, where 63 of 93 controls are attestation-only, that made two thirds
        # of the framework impossible to comply with.
        manual_rules = [r for r in rules if r.evidence_source == "manual"]
        for m_rule in manual_rules:
            for control_id in controls_for_rule[m_rule.id]:
                existing = (
                    db.query(ComplianceFinding)
                    .filter(
                        ComplianceFinding.id == org_finding_id_for(org_id, control_id)
                    )
                    .first()
                )
                # Never overwrite a human's attestation with a placeholder.
                if existing and existing.source == "manual_attestation":
                    continue
                _save_finding(
                    db,
                    org_id,
                    None,
                    m_rule,
                    [control_id],
                    run_id=scan_run_id,
                    status="manual_review",
                    evidence={
                        "message": (
                            "This control is governance, process or physical in "
                            "nature and cannot be verified by a scan. Record a "
                            "manual attestation with supporting evidence."
                        )
                    },
                )

        # 3.5. Calculate Org Compliance Score (asset_id = None)
        _calculate_compliance_score(db, org_id, framework_id, None, scan_run_id)

        # 4. Conclude scan run
        run.status = "completed"
        run.finished_at = datetime.now(timezone.utc)
        db.commit()

        log.info(f"Compliance scan run {scan_run_id} completed successfully.")
        return {"success": True, "scan_run_id": scan_run_id}

    except Exception as exc:
        db.rollback()
        log.exception(f"Compliance scan run {scan_run_id} failed.")
        # `run` is re-read after the rollback: the object from before the
        # rollback is detached, and writing through it raises a second
        # exception that hides the first. The message is persisted so the
        # operator sees why the run failed instead of a progress spinner that
        # simply stops.
        try:
            failed_run = (
                db.query(ComplianceScanRun)
                .filter(ComplianceScanRun.id == scan_run_id)
                .first()
            )
            if failed_run:
                failed_run.status = "failed"
                failed_run.finished_at = datetime.now(timezone.utc)
                failed_run.error_message = str(exc)[:2000]
                db.commit()
        except Exception:
            log.exception("Could not record failure state for run %s", scan_run_id)
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


def _platform_applicability(asset: Asset, rule: ComplianceRule):
    """Decides whether a platform-scoped rule applies to this host.

    Returns None when the rule should be evaluated, or a (status, message)
    pair when it should not. Matching used to be a bare substring test against
    `os_family or os_name`, so a Linux host whose family had not been
    fingerprinted but whose `os_name` read "Ubuntu 24.04.4 LTS" contained
    neither "linux" nor "windows" and had every platform rule marked
    not_applicable — a silent, total loss of coverage that reads in the UI as
    "this control does not apply here".
    """
    target = (rule.target_platform or "any").lower()
    if target == "any":
        return None

    haystack = " ".join(
        part.lower() for part in (asset.os_family, asset.os_name) if part
    )
    if not haystack:
        return (
            "manual_review",
            "The operating system of this host has not been fingerprinted, so a "
            "platform-specific control could not be evaluated. Run a credentialed "
            "or OS-detection scan first.",
        )

    aliases = _PLATFORM_ALIASES.get(target, (target,))
    if any(alias in haystack for alias in aliases):
        return None

    return (
        "not_applicable",
        f"This control applies to {rule.target_platform} hosts. "
        f"This host is {asset.os_family or asset.os_name}.",
    )


# Distribution and edition names that identify a platform without ever
# containing the platform's own word.
_PLATFORM_ALIASES: dict[str, tuple[str, ...]] = {
    "linux": (
        "linux",
        "ubuntu",
        "debian",
        "rocky",
        "alma",
        "centos",
        "rhel",
        "red hat",
        "fedora",
        "suse",
        "opensuse",
        "amazon linux",
        "oracle linux",
        "alpine",
        "arch",
        "gentoo",
        "raspbian",
        "kali",
        "mint",
    ),
    "windows": ("windows", "win32", "win64", "microsoft windows"),
    "network_device": (
        "network_device",
        "ios",
        "ios-xe",
        "nx-os",
        "junos",
        "fortios",
        "pan-os",
        "routeros",
        "switch",
        "router",
        "firewall",
    ),
    "cloud": ("cloud", "aws", "azure", "gcp"),
    "database": ("database", "mysql", "postgres", "oracle", "mssql", "mongodb"),
}


def _save_finding(
    db: Session,
    org_id: str,
    asset_id: Optional[str],
    rule: ComplianceRule,
    control_ids: list,
    run_id: Optional[str],
    status: str,
    evidence: dict,
):
    """Records this rule's verdict against every control it covers.

    `control_ids` is resolved by the caller from the scan run's own framework.
    It is a list, not a single id, because a rule can legitimately satisfy
    several controls of one standard, and each of those controls needs its own
    finding — the score is computed per control, so folding them into one row
    loses the others.

    There is deliberately no fallback control. The previous default pointed at
    `cct_iso27001_2022_8.9`, an id that has never existed (the real one uses
    underscores), so a rule with no mapping produced a foreign-key violation on
    a RESTRICT column rather than the intended graceful degradation.
    """
    if not control_ids:
        log.warning(
            "Rule %s resolved to no control in this run's framework; skipping.",
            rule.id,
        )
        return

    for control_id in control_ids:
        _save_finding_for_control(
            db, org_id, asset_id, rule, control_id, run_id, status, evidence
        )


def _save_finding_for_control(
    db: Session,
    org_id: str,
    asset_id: Optional[str],
    rule: ComplianceRule,
    control_id: str,
    run_id: Optional[str],
    status: str,
    evidence: dict,
):
    """Saves or updates one compliance finding, recording the timeline transition."""
    from sqlalchemy.exc import IntegrityError

    # Org-level findings for manual controls share one id per control so that a
    # later human attestation lands on the same row rather than beside it.
    if asset_id is None and rule.evidence_source == "manual":
        finding_id = org_finding_id_for(org_id, control_id)
    else:
        finding_id = finding_id_for(org_id, asset_id, control_id, rule.id)

    finding = (
        db.query(ComplianceFinding).filter(ComplianceFinding.id == finding_id).first()
    )
    now = datetime.now(timezone.utc)

    # Check for active exception waiver
    waiver = (
        db.query(ComplianceException)
        .filter(
            ComplianceException.finding_id == finding_id,
            ComplianceException.tenant_id == org_id,
            ComplianceException.status == "approved",
            ComplianceException.expires_at > now,
        )
        .first()
    )

    target_status = "exception" if waiver else status

    # Query cde_scope, sdf_scope, and privacy_role
    cde_scope = None
    sdf_scope = None
    privacy_role = None
    if run_id:
        run = db.query(ComplianceScanRun).filter(ComplianceScanRun.id == run_id).first()
        if run:
            cde_scope = run.cde_scope
            sdf_scope = run.sdf_scope
            privacy_role = run.privacy_role

    ctrl_obj = (
        db.query(ComplianceControl).filter(ComplianceControl.id == control_id).first()
    )
    if not ctrl_obj:
        log.warning(
            "Control %s referenced by rule %s does not exist; finding not written.",
            control_id,
            rule.id,
        )
        return
    if not sdf_scope and ctrl_obj.sdf_scope:
        sdf_scope = ctrl_obj.sdf_scope
    if not privacy_role and ctrl_obj.privacy_role:
        privacy_role = ctrl_obj.privacy_role

    had_transition = False
    old_status = None

    try:
        # A SAVEPOINT, and the failure handling below rolls back to *it*. The
        # previous handler called db.rollback(), which unwinds the whole
        # session — and run_scan_task commits only at the start and the end, so
        # a single constraint violation anywhere in the loop silently discarded
        # every finding the run had produced so far.
        with db.begin_nested() as nested:
            try:
                if not finding:
                    finding = ComplianceFinding(
                        id=finding_id,
                        scan_run_id=run_id,
                        tenant_id=org_id,
                        asset_id=asset_id,
                        control_id=control_id,
                        rule_id=rule.id,
                        source="auto_scan",
                        status=target_status,
                        evidence=evidence,
                        first_seen=now,
                        last_seen=now,
                        cde_scope=cde_scope,
                        sdf_scope=sdf_scope,
                        privacy_role=privacy_role,
                    )
                    db.add(finding)
                    had_transition = True
                    old_status = "new"
                else:
                    if finding.status != target_status:
                        old_status = finding.status
                        finding.status = target_status
                        had_transition = True
                    finding.scan_run_id = run_id
                    finding.rule_id = rule.id
                    finding.source = "auto_scan"
                    finding.last_seen = now
                    finding.evidence = evidence
                    finding.cde_scope = cde_scope
                    finding.sdf_scope = sdf_scope
                    finding.privacy_role = privacy_role

                if had_transition:
                    db.add(
                        ComplianceFindingHistory(
                            id=_history_id(),
                            finding_id=finding_id,
                            status=target_status,
                            source="auto_scan",
                            note=(
                                f"Status transitioned from {old_status} to "
                                f"{target_status} during scan run {run_id}"
                            ),
                        )
                    )
                db.flush()
            except IntegrityError:
                nested.rollback()
                raise
    except IntegrityError:
        # Another worker inserted this finding between our read and our write.
        # Re-read and update in place; only this savepoint was discarded, so
        # everything the run wrote before now is intact.
        log.info("Finding %s was written concurrently; merging.", finding_id)
        finding = (
            db.query(ComplianceFinding)
            .filter(ComplianceFinding.id == finding_id)
            .first()
        )
        if not finding:
            log.warning(
                "Finding %s could not be written or re-read; skipping.", finding_id
            )
            return
        finding.scan_run_id = run_id
        finding.last_seen = now
        finding.evidence = evidence
        finding.cde_scope = cde_scope
        finding.sdf_scope = sdf_scope
        finding.privacy_role = privacy_role
        if finding.status != target_status:
            old_status = finding.status
            finding.status = target_status
            db.add(
                ComplianceFindingHistory(
                    id=_history_id(),
                    finding_id=finding_id,
                    status=target_status,
                    source="auto_scan",
                    note=(
                        f"Status transitioned from {old_status} to "
                        f"{target_status} during scan run {run_id}"
                    ),
                )
            )
        db.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Scoring Logic Implementation
# ─────────────────────────────────────────────────────────────────────────────


def _calculate_compliance_score(
    db: Session,
    org_id: str,
    framework_id: str,
    asset_id: str | None,
    scan_run_id: str,
    saq_profile: str | None = None,
):
    """Calculates both simple and risk-weighted compliance scores for an asset or tenant, including theme scores."""
    if saq_profile is None and scan_run_id:
        run = (
            db.query(ComplianceScanRun)
            .filter(ComplianceScanRun.id == scan_run_id)
            .first()
        )
        if run and run.scope:
            saq_profile = run.scope.get("saq_profile")

    themes = [None]
    if not asset_id:
        distinct_themes = (
            db.query(ComplianceControl.theme)
            .filter(ComplianceControl.framework_id == framework_id)
            .distinct()
            .all()
        )
        themes.extend([t[0] for t in distinct_themes if t[0] is not None])

    for theme in themes:
        # Fetch framework controls matching the theme (if specified)
        control_query = db.query(ComplianceControl).filter(
            ComplianceControl.framework_id == framework_id
        )
        if theme:
            control_query = control_query.filter(ComplianceControl.theme == theme)
        controls = control_query.all()

        # Apply SAQ profile filter on controls
        if saq_profile:
            controls = [
                c
                for c in controls
                if c.saq_profiles
                and saq_profile.lower() in [p.lower() for p in c.saq_profiles]
            ]

        if not controls:
            continue

        control_ids = [c.id for c in controls]

        finding_query = db.query(ComplianceFinding).filter(
            ComplianceFinding.tenant_id == org_id,
            ComplianceFinding.control_id.in_(control_ids),
        )
        if asset_id:
            # Org-level attestations (asset_id IS NULL) still apply to a
            # per-asset view of a manual control — the human attested the
            # control for the organisation, which covers this host too.
            finding_query = finding_query.filter(
                or_(
                    ComplianceFinding.asset_id == asset_id,
                    ComplianceFinding.asset_id.is_(None),
                )
            )
        findings = finding_query.all()

        # One rolled-up verdict per control, through the shared precedence
        # table. The asset branch used to build `{f.control_id: f}`, an
        # unordered dict comprehension in which the last row won — so a control
        # carrying twelve rules reported whichever of the twelve the database
        # returned last, and the asset score disagreed with the org score.
        by_control: dict[str, list] = {}
        for f in findings:
            by_control.setdefault(f.control_id, []).append(f)

        rolled: dict[str, str] = {}
        rule_for_control: dict[str, Optional[str]] = {}
        for c_id, f_list in by_control.items():
            verdict = roll_up_statuses([(f.status, f.source) for f in f_list])
            if verdict is None:
                continue
            rolled[c_id] = verdict
            # Weight the control by its most severe *contributing* rule rather
            # than an arbitrary one, so a control carrying both a critical and
            # an informational check is not weighted as informational.
            rule_for_control[c_id] = _worst_rule_id(db, f_list)

        total = len(controls)
        applicable = 0
        passed = 0
        failed = 0
        na = 0
        pending = 0

        # Risk weights accumulator
        weighted_total = 0.0
        weighted_passed = 0.0

        for c in controls:
            verdict = rolled.get(c.id)
            if verdict is None:
                pending += 1
                applicable += 1
                weighted_total += SEVERITY_WEIGHTS["medium"]
                continue

            weight = SEVERITY_WEIGHTS["medium"]
            rule_id = rule_for_control.get(c.id)
            if rule_id:
                rule = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == rule_id)
                    .first()
                )
                if rule:
                    weight = float(
                        SEVERITY_WEIGHTS.get(
                            (rule.severity or "medium").lower(),
                            SEVERITY_WEIGHTS["medium"],
                        )
                    )

            if verdict in ("pass", "exception"):
                passed += 1
                applicable += 1
                weighted_passed += weight
                weighted_total += weight
            elif verdict in ("fail", "pending_reverify"):
                failed += 1
                applicable += 1
                weighted_total += weight
            elif verdict == "not_applicable":
                na += 1
            else:  # manual_review, remediation_applied
                pending += 1
                applicable += 1
                weighted_total += weight

        # `applicable` counts assessed *and* unassessed controls, so score_pct
        # alone cannot distinguish "we checked and failed" from "we never
        # checked". `assessed_pct` below is the conformity figure over controls
        # that actually reached a verdict; both are reported.
        score_pct = (passed / applicable) * 100 if applicable > 0 else 0.0
        weighted_score = (
            (weighted_passed / weighted_total) * 100 if weighted_total > 0 else 0.0
        )

        # Unique ID per org, framework, theme, asset, and optional SAQ profile.
        # Hashed — the previous form sliced the tail off framework, theme and
        # asset ids, so two frameworks whose ids agreed in their last eight
        # characters shared one score row.
        score_id = _stable_id(
            "csc",
            org_id,
            framework_id,
            theme or "overall",
            asset_id or "summary",
            (saq_profile or "").lower(),
        )
        score_rec = (
            db.query(ComplianceScore).filter(ComplianceScore.id == score_id).first()
        )

        if not score_rec:
            score_rec = ComplianceScore(
                id=score_id,
                tenant_id=org_id,
                framework_id=framework_id,
                scan_run_id=scan_run_id,
                asset_id=asset_id,
                theme=theme,
                total_controls=total,
                applicable_controls=applicable,
                pass_count=passed,
                fail_count=failed,
                na_count=na,
                pending_count=pending,
                score_pct=score_pct,
                weighted_score_pct=weighted_score,
            )
            db.add(score_rec)
        else:
            score_rec.scan_run_id = scan_run_id
            score_rec.theme = theme
            score_rec.total_controls = total
            score_rec.applicable_controls = applicable
            score_rec.pass_count = passed
            score_rec.fail_count = failed
            score_rec.na_count = na
            score_rec.pending_count = pending
            score_rec.score_pct = score_pct
            score_rec.weighted_score_pct = weighted_score

        db.flush()


# Helper functions for remediation script execution to keep main functions under 40 lines
def _resolve_remediation_credentials(
    db: Session, request: ComplianceRemediationRequest | None, kwargs: dict
) -> dict:
    """Resolves credentials from either JIT kwargs, stored credentials, or database request ticket."""
    from core.security_crypto import decrypt_credential

    username = kwargs.get("jit_username")
    port = kwargs.get("jit_port") or 22
    auth_method = kwargs.get("jit_auth_method")
    dec_password = None
    dec_key_content = None

    stored_cred_id = kwargs.get("stored_cred_id")
    if request and request.credential_id:
        stored_cred_id = request.credential_id

    if stored_cred_id:
        cred = db.query(ComplianceCredential).filter_by(id=stored_cred_id).first()
        if cred:
            username = cred.username
            port = cred.port
            auth_method = cred.auth_method
            if cred.encrypted_password:
                dec_password = decrypt_credential(cred.encrypted_password)
            if cred.encrypted_key_content:
                dec_key_content = decrypt_credential(cred.encrypted_key_content)
    elif request and request.auth_method:
        username = request.username
        port = request.port or 22
        auth_method = request.auth_method
        if request.encrypted_password:
            dec_password = decrypt_credential(request.encrypted_password)
        if request.encrypted_key_content:
            dec_key_content = decrypt_credential(request.encrypted_key_content)
    elif auth_method:
        if kwargs.get("jit_enc_password"):
            dec_password = decrypt_credential(kwargs["jit_enc_password"])
        if kwargs.get("jit_enc_key_content"):
            dec_key_content = decrypt_credential(kwargs["jit_enc_key_content"])

    return {
        "username": username,
        "port": port,
        "auth_method": auth_method,
        "password": dec_password,
        "key_content": dec_key_content,
    }


def _extract_platform_commands(command: str, platform: str) -> str:
    """Extracts lines from a multi-platform script matching the target platform."""
    lines = command.splitlines()
    extracted = []
    current_platform = None
    target = str(platform).lower()

    # If there are no platform headers, run the whole script as fallback
    if not any(
        "--- windows" in line.lower() or "--- linux" in line.lower() for line in lines
    ):
        return command

    for line in lines:
        normalized_line = line.strip().lower()
        if "--- windows" in normalized_line:
            current_platform = "windows"
            continue
        elif "--- linux" in normalized_line or "--- bash" in normalized_line:
            current_platform = "linux"
            continue

        if current_platform == target:
            extracted.append(line)

    return "\n".join(extracted).strip()


ROLLBACK_COMMANDS = {
    "PORT-NETBIOS": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block NetBIOS" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 139/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 139 -j DROP"
    ),
    "PORT-SMB": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block SMB" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 445/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 445 -j DROP"
    ),
    "PORT-SSH": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block SSH" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 22/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 22 -j DROP"
    ),
    "PORT-HTTP": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block HTTP" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 80/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 80 -j DROP"
    ),
    "PORT-MYSQL": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block MySQL" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 3306/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 3306 -j DROP"
    ),
    "PORT-POSTGRES": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block PostgreSQL" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 5432/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 5432 -j DROP"
    ),
    "PORT-ORACLE": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block Oracle DB" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 1521/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 1521 -j DROP"
    ),
    "PORT-INTEL-AMT": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block Intel AMT" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 623/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 623 -j DROP"
    ),
    "PORT-WINRM": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block WinRM" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 5985/tcp\n"
        "sudo ufw delete deny 5986/tcp"
    ),
    "PORT-TOMCAT": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block Tomcat" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 8080/tcp\n"
        "sudo iptables -D INPUT -p tcp --dport 8080 -j DROP"
    ),
    "PORT-OPCUA": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Remove-NetFirewallRule -DisplayName "Block OPC UA" -ErrorAction SilentlyContinue\n\n'
        "# --- LINUX (Bash) ---\n"
        "sudo ufw delete deny 4840/tcp"
    ),
    "CONFIG-SMBV1": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 1 -Force -ErrorAction SilentlyContinue\n'
        "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue\n\n"
        "# --- LINUX (Bash) ---\n"
        "sudo sed -i '/server min protocol = SMB2/d' /etc/samba/smb.conf 2>/dev/null || true\n"
        "sudo systemctl restart smbd 2>/dev/null || true"
    ),
    "CONFIG-NETBIOS": (
        "# --- WINDOWS (PowerShell) ---\n"
        '$adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"\n'
        "foreach ($adapter in $adapters) {\n"
        "    $adapter.SetTcpipNetbios(1) | Out-Null\n"
        "}\n\n"
        "# --- LINUX (Bash) ---\n"
        "sudo systemctl enable --now nmbd 2>/dev/null || true"
    ),
    "CONFIG-LEGACY-TLS": (
        "# --- WINDOWS (PowerShell) ---\n"
        '$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")\n'
        "foreach ($proto in $protocols) {\n"
        '    foreach ($type in @("Client", "Server")) {\n'
        '        $path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\$type"\n'
        "        if (Test-Path $path) {\n"
        '            Set-ItemProperty -Path $path -Name "Enabled" -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue\n'
        '            Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -Type DWORD -Force -ErrorAction SilentlyContinue\n'
        "        }\n"
        "    }\n"
        "}\n\n"
        "# --- LINUX (Bash) ---\n"
        "# No generic rollback for OpenSSL minimum protocol config"
    ),
    "CONFIG-TELNET": (
        "# --- WINDOWS (PowerShell) ---\n"
        "Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction SilentlyContinue\n"
        "Set-Service -Name TlntSvr -StartupType Automatic -ErrorAction SilentlyContinue\n"
        "Start-Service -Name TlntSvr -ErrorAction SilentlyContinue\n\n"
        "# --- LINUX (Bash) ---\n"
        "sudo systemctl enable --now telnet.socket 2>/dev/null || true"
    ),
    "CONFIG-RDP-NLA": (
        "# --- WINDOWS (PowerShell) ---\n"
        'Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Force\n\n'
        "# --- LINUX (Bash) ---\n"
        "# RDP NLA is a Windows-only configuration"
    ),
}


#: A ``sudo`` whose standard input is a pipe from the command before it, as in
#: ``echo 'line' | sudo tee /etc/file``. ``||`` is an ordinary shell fallback
#: and is not a pipe, so the lookarounds are load-bearing.
_PIPE_INTO_SUDO = re.compile(r"(?<!\|)\|(?!\|)\s*sudo\b")


def _redact_secret(text: str, secret: str | None) -> str:
    """Mask *secret* wherever it appears in *text* — the last line of defence
    for anything that reaches the stored execution log."""
    if not text or not secret:
        return text
    return text.replace(secret, "***REDACTED***")


def _execute_ssh_remediation(
    ip: str,
    port: int,
    username: str,
    password: str | None,
    key_content: str | None,
    command: str,
    target_platform: str,
) -> dict:
    """Executes script command on target host, wrapping Windows shell commands appropriately."""
    from engines.credentialed.ssh_scanner import SSHScanner

    platform = "linux"
    norm_platform = str(target_platform).lower()
    if "windows" in norm_platform:
        platform = "windows"
    elif "linux" in norm_platform:
        platform = "linux"
    elif command.strip().startswith("# --- WINDOWS"):
        platform = "windows"

    # Extract only the commands relevant to the active platform
    command = _extract_platform_commands(command, platform)
    clean_command = command

    if platform == "windows":
        import base64

        utf16_cmd = command.encode("utf-16le")
        b64_cmd = base64.b64encode(utf16_cmd).decode("ascii")
        command = (
            f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command {b64_cmd}"
            if len(b64_cmd) < 10
            else f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {b64_cmd}"
        )
    elif platform == "linux" and password and _PIPE_INTO_SUDO.search(command):
        # ``sudo -S`` reads its password from its own standard input, and in
        # this shape that is the pipe rather than the session: sudo would take
        # the piped data as the password, and the only way to hand it the real
        # one is the command line. Refused before connecting, so the target
        # sees neither a failed sudo attempt nor the secret. The injection this
        # replaced wrote the password into the file such a command creates
        # whenever sudo needed none.
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "error": (
                "The remediation command pipes data into sudo, which would read "
                "that data as its password. Rewrite it so sudo runs the whole "
                "pipeline (for example sudo sh -c '…'), or run it with a key "
                "credential whose account needs no sudo password."
            ),
        }

    scanner = SSHScanner(
        ip=ip,
        username=username,
        password=password,
        key_content=key_content,
        port=port,
        timeout=10,
    )
    try:
        scanner.connect()
        # On Linux every sudo in the command reads the password from the
        # remote command's standard input (``SSHScanner.run_sudo``). It is never
        # placed in the command text, where ``ps`` shows it to every local user
        # on the target and an ``execve`` audit rule records it.
        if platform == "linux":
            res = scanner.run_sudo(command, timeout=60)
        else:
            res = scanner.run(command, timeout=60)
        return {
            "success": res.success,
            "stdout": _redact_secret(res.stdout, password),
            "stderr": _redact_secret(res.stderr, password),
            "exit_code": res.exit_code,
            "error": "",
            "executed_command": clean_command,
        }
    except Exception as e:
        detail = _redact_secret(str(e), password)
        return {
            "success": False,
            "stdout": "",
            "stderr": detail,
            "exit_code": -1,
            "error": f"SSH connection or execution failed: {detail}",
        }
    finally:
        scanner.disconnect()


def _sanitize_remediation_logs(text: str) -> str:
    """Filter out tokens, keys, passwords, and sensitive credentials from logs."""
    if not text:
        return ""
    text = re.sub(
        r"(pass|password|pwd|secret|key|token|auth_token)\s*[:=]\s*['\"][^'\"]+['\"]",
        r"\1: [REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"(pass|password|pwd|secret|key|token|auth_token)\s*[:=]\s*[^\s]+",
        r"\1: [REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"(?<=://)[^/:]+:[^/@]+(?=@)", "[REDACTED_CREDENTIALS]", text)
    text = re.sub(
        r"-----BEGIN [A-Z]+ PRIVATE KEY-----.+?-----END [A-Z]+ PRIVATE KEY-----",
        "[REDACTED SSH KEY]",
        text,
        flags=re.DOTALL,
    )
    text = re.sub(
        r"echo\s+['\"][^'\"]+['\"]\s*\|\s*sudo\s+-S",
        "echo '[REDACTED_PASSWORD]' | sudo -S",
        text,
    )
    return text


def _run_active_reverification_probes(
    db: Session, finding: ComplianceFinding, rule: ComplianceRule, ip: str
) -> None:
    """Perform direct verification checks e.g., lightweight TCP socket connection probes."""
    check_def = rule.check_definition or {}
    evidence_source = rule.evidence_source

    if evidence_source == "services_ports":
        port = check_def.get("port")
        if not port:
            expected = check_def.get("expected")
            if isinstance(expected, dict):
                port = expected.get("port")
            elif isinstance(expected, (int, str)):
                port = expected

            if not port:
                args = check_def.get("args")
                if isinstance(args, dict):
                    port = args.get("port")

        if port:
            port = int(port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                result = sock.connect_ex((ip, port))
                is_open = result == 0
            except Exception:
                is_open = False
            finally:
                sock.close()

            svc = (
                db.query(Service)
                .filter_by(asset_id=finding.asset_id, port=port)
                .first()
            )
            if svc:
                # A live TCP connect from the scanner is a direct reachability
                # observation, so it sets both the state and the reachability
                # flag. Leaving the flag behind would let a re-verified port
                # keep whatever the original scan concluded.
                svc.state = "open" if is_open else "closed"
                svc.network_reachable = is_open
                svc.updated_at = datetime.now(timezone.utc)
                db.add(svc)
                db.commit()


def _invalidate_evidence_cache(
    finding: ComplianceFinding, rule: ComplianceRule
) -> None:
    """Invalidate Redis cache for compliance evidence provider."""
    from core.redis_client import get_redis_client

    redis_client = get_redis_client()
    if redis_client:
        cache_key = f"compliance:evidence:{finding.asset_id}:{rule.evidence_source}"
        try:
            redis_client.delete(cache_key)
        except Exception as e:
            log.warning(f"Failed to clear Redis evidence cache: {e}")


def _finalize_successful_remediation(
    db: Session, finding: ComplianceFinding, user_id: str, exit_code: int
) -> None:
    """Record positive verdict history trail and queue passive rules engine scan."""
    finding.status = "remediation_applied"
    finding.remediation_applied_by = user_id
    finding.remediation_applied_at = datetime.now(timezone.utc)

    # Track reboot pending in Asset custom_attributes
    rule = db.query(ComplianceRule).filter_by(id=finding.rule_id).first()
    if rule and rule.rule_family_code in (
        "CONFIG-SMBV1",
        "CONFIG-LEGACY-TLS",
        "CONFIG-RDP-NLA",
    ):
        asset = db.query(Asset).filter_by(id=finding.asset_id).first()
        if asset:
            attrs = dict(asset.custom_attributes or {})
            attrs["reboot_pending"] = True
            asset.custom_attributes = attrs
            db.add(asset)

    history = ComplianceFindingHistory(
        id=_history_id(),
        finding_id=finding.id,
        status="remediation_applied",
        changed_by=user_id,
        source="remediation",
        note=f"Executed script fix. Exit code: {exit_code}",
    )
    db.add(history)
    db.commit()
    run_reverify_evaluation.delay(finding.id)


def _finalize_failed_remediation(
    db: Session,
    req: ComplianceRemediationRequest | None,
    finding: ComplianceFinding,
    error_msg: str,
) -> None:
    """Logs error traces to database, reverts finding status, and commits transactions."""
    finding.status = "fail"
    if req:
        req.status = "failed"
        if not req.execution_log:
            req.execution_log = _sanitize_remediation_logs(f"FAILURE:\n{error_msg}")
        elif error_msg:
            if error_msg not in req.execution_log:
                req.execution_log += f"\n\nFAILURE:\n{error_msg}"
        db.add(req)
    db.commit()


@celery_app.task(name="compliance.run_remediation", queue="compliance")
def run_reremediation_task(
    finding_id: str,
    remediation_id: str,
    user_id: str,
    remediation_request_id: str | None = None,
    **kwargs,
) -> dict:
    """Remediation script dispatch execution via out-of-process Celery worker."""
    db = SessionLocal()
    try:
        finding = db.query(ComplianceFinding).filter_by(id=finding_id).first()
        remediation = (
            db.query(ComplianceRemediation).filter_by(id=remediation_id).first()
        )
        if not finding or not remediation:
            return {
                "success": False,
                "error": "Finding or Remediation script not found",
            }

        req = (
            db.query(ComplianceRemediationRequest)
            .filter_by(id=remediation_request_id)
            .first()
            if remediation_request_id
            else None
        )
        is_rollback = kwargs.get("is_rollback", False) or (
            remediation_request_id.startswith("crrq_rollback_")
            if remediation_request_id
            else False
        )

        creds = _resolve_remediation_credentials(db, req, kwargs)
        if not creds.get("username") or (
            not creds.get("password") and not creds.get("key_content")
        ):
            raise ValueError("Credentials resolution failed or incomplete.")

        asset = db.query(Asset).filter_by(id=finding.asset_id).first()
        if not asset or not asset.ip_address:
            raise ValueError("Asset IP address could not be resolved.")

        rule = db.query(ComplianceRule).filter_by(id=finding.rule_id).first()

        if is_rollback:
            command_to_run = (
                ROLLBACK_COMMANDS.get(rule.rule_family_code)
                if (rule and rule.rule_family_code)
                else None
            )
            if not command_to_run:
                raise ValueError(
                    f"No rollback command defined for rule family code: {rule.rule_family_code if rule else 'None'}"
                )
        else:
            command_to_run = remediation.fix_command

        res = _execute_ssh_remediation(
            ip=asset.ip_address,
            port=creds["port"],
            username=creds["username"],
            password=creds["password"],
            key_content=creds["key_content"],
            command=command_to_run,
            target_platform=asset.os_family
            or asset.os_name
            or (rule.target_platform if rule else "any"),
        )

        executed_cmd = res.get("executed_command") or command_to_run
        cmd_label = (
            "COMMAND RUN ON TARGET (ROLLBACK)"
            if is_rollback
            else "COMMAND RUN ON TARGET"
        )
        raw_log = f"{cmd_label}:\n{executed_cmd}\n\nSTDOUT:\n{res['stdout']}\nSTDERR:\n{res['stderr']}\nERROR:\n{res['error']}"
        sanitized_log = _sanitize_remediation_logs(raw_log)

        if req:
            req.execution_log = sanitized_log
            req.username = req.encrypted_password = req.encrypted_key_content = (
                req.port
            ) = req.auth_method = None
            req.status = "executed" if res["success"] else "failed"
            db.add(req)
            db.commit()

            # If this is a successful rollback, update the original request's status to failed
            if is_rollback and res["success"]:
                orig_req_id = remediation_request_id.replace(
                    "crrq_rollback_", "crrq_", 1
                )
                orig_req = (
                    db.query(ComplianceRemediationRequest)
                    .filter_by(id=orig_req_id)
                    .first()
                )
                if orig_req:
                    orig_req.status = "failed"
                    db.add(orig_req)
                    db.commit()

        if not res["success"]:
            _finalize_failed_remediation(
                db, req, finding, res["error"] or "Execution failed"
            )
            return {"success": False, "error": res["error"]}

        if rule:
            _run_active_reverification_probes(db, finding, rule, asset.ip_address)
            _invalidate_evidence_cache(finding, rule)

        if is_rollback:
            finding.status = "fail"
            history = ComplianceFindingHistory(
                id=_history_id(),
                finding_id=finding.id,
                status="fail",
                changed_by=user_id,
                source="remediation",
                note="Remediation successfully rolled back.",
            )
            db.add(history)
            db.commit()
        else:
            _finalize_successful_remediation(db, finding, user_id, res["exit_code"])

        return {"success": True, "finding_id": finding_id}

    except Exception as exc:
        db.rollback()
        log.exception(f"Remediation execution task failed for finding {finding_id}")
        _finalize_failed_remediation(db, req, finding, str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="compliance.prune_remediation_logs", queue="compliance")
def prune_compliance_remediation_logs() -> dict:
    """Prunes remediation execution request logs older than the tenant's retention policy (default 7 years)."""
    db = SessionLocal()
    try:
        from db.models.compliance import ComplianceEvidenceRetentionPolicy

        policies = db.query(ComplianceEvidenceRetentionPolicy).all()
        tenant_retention = {
            p.tenant_id: p.retain_years for p in policies if p.tenant_id
        }

        requests = (
            db.query(ComplianceRemediationRequest)
            .filter(
                ComplianceRemediationRequest.status.in_(
                    ["executed", "failed", "rejected"]
                )
            )
            .all()
        )

        pruned_count = 0
        now = datetime.now(timezone.utc)
        for req in requests:
            retain_years = tenant_retention.get(req.tenant_id, 7)
            cutoff = now - timedelta(days=365 * retain_years)
            if req.created_at < cutoff:
                req.execution_log = f"[PRUNED] Output removed after {retain_years} years retention policy on {now.strftime('%d-%b-%Y')}."
                db.add(req)
                pruned_count += 1

        db.commit()
        return {"success": True, "pruned_count": pruned_count}
    except Exception as exc:
        db.rollback()
        log.exception("Failed to run periodic remediation log pruning")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@celery_app.task(name="compliance.run_reverify", queue="compliance")
def run_reverify_evaluation(finding_id: str) -> dict:
    """Re-evaluates a failing check to confirm the remediation resolved it."""
    db = SessionLocal()
    try:
        finding = (
            db.query(ComplianceFinding)
            .filter(ComplianceFinding.id == finding_id)
            .first()
        )
        if not finding:
            return {"success": False, "error": "Finding not found"}

        # Defence in depth. Nothing can currently deliver a parked framework's
        # finding here — this task is reachable only from
        # `run_reremediation_task`, which is reachable only from the two
        # remediation endpoints, and both refuse a framework the tenant does
        # not have enabled. But that is an inherited property of the call
        # chain, not a property of this function: it takes a finding id and
        # writes a verdict, and a caller added later would rewrite a parked
        # framework's finding with no check anywhere in between.
        #
        # Both layers are checked, for the same reason the request paths check
        # both: the installation-wide list decides what this deployment offers,
        # and the tenant flag decides what this organisation installed.
        control = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.id == finding.control_id)
            .first()
        )
        if not control:
            return {"success": False, "error": "Control not found"}

        if not is_active_framework(control.framework_id):
            log.info(
                "Re-verification refused for finding %s: framework %s is not "
                "enabled on this installation.",
                finding_id,
                control.framework_id,
            )
            return {
                "success": False,
                "error": (
                    f"Framework {control.framework_id} is not enabled on this "
                    "installation."
                ),
            }

        installed = (
            db.query(ComplianceTenantFramework)
            .filter(
                ComplianceTenantFramework.tenant_id == finding.tenant_id,
                ComplianceTenantFramework.framework_id == control.framework_id,
                ComplianceTenantFramework.is_enabled == True,  # noqa: E712
            )
            .first()
        )
        if not installed:
            log.info(
                "Re-verification refused for finding %s: tenant %s does not have "
                "%s installed.",
                finding_id,
                finding.tenant_id,
                control.framework_id,
            )
            return {
                "success": False,
                "error": (
                    f"Framework {control.framework_id} is not installed for this "
                    "organisation."
                ),
            }

        rule = (
            db.query(ComplianceRule)
            .filter(ComplianceRule.id == finding.rule_id)
            .first()
        )
        if not rule:
            return {"success": False, "error": "Rule check config not found"}

        # Fetch fresh evidence
        evidence = ComplianceEvidenceProvider.get_normalized_evidence(
            db, finding.asset_id, rule.evidence_source
        )

        check_def = rule.check_definition or {}
        key = check_def.get("key")

        # Re-verification has to make the same unassessed-vs-failed distinction
        # the main scan makes. Without it, a remediation whose evidence source
        # had not been re-collected was reported as having failed to fix
        # anything, which is worse than saying nothing.
        if (
            not evidence
            or evidence.get("_evidence_available") is False
            or (key and key not in evidence)
        ):
            target_status = "manual_review"
            note = (
                "Re-verification could not complete: no fresh "
                f"'{rule.evidence_source}' evidence is available for this asset."
            )
            finding.evidence = {
                "message": note,
                "evidence_source": rule.evidence_source,
                "required_key": key,
            }
        else:
            passed = _evaluate_operator(
                operator=check_def.get("operator", "equals"),
                actual=evidence.get(key) if key else None,
                expected=check_def.get("expected"),
            )
            target_status = "pass" if passed else "fail"
            note = f"Reverification completed. Check result: {target_status.upper()}"
            finding.evidence = evidence

        finding.status = target_status
        finding.last_seen = datetime.now(timezone.utc)

        history = ComplianceFindingHistory(
            id=_history_id(),
            finding_id=finding.id,
            status=target_status,
            source="remediation",
            note=note,
        )
        db.add(history)
        db.commit()

        return {"success": True, "verdict": target_status}

    except Exception as exc:
        db.rollback()
        log.exception(f"Reverification task failed for finding {finding_id}")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


# `continuous` is deliberately hourly rather than "every beat tick": the beat
# entry fires this task once a minute, and a schedule that re-armed instantly
# would queue a full compliance scan every 60 seconds per tenant.
_SCHEDULE_INTERVALS: dict[str, timedelta] = {
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
    "quarterly": timedelta(days=90),
    "continuous": timedelta(hours=1),
}


@celery_app.task(name="compliance.run_scheduled_scans", queue="compliance")
def run_scheduled_scans() -> dict:
    """Periodic task executed by Celery Beat to query and trigger scheduled compliance scans."""
    from db.base import gen_compliance_scan_run_id
    from db.models.compliance import ComplianceScanSchedule
    from sqlalchemy import or_

    db = SessionLocal()
    triggered = 0
    now = datetime.now(timezone.utc)
    try:
        schedules = (
            db.query(ComplianceScanSchedule)
            .filter(
                ComplianceScanSchedule.is_active == True,
                or_(
                    ComplianceScanSchedule.next_run_at.is_(None),
                    ComplianceScanSchedule.next_run_at <= now,
                ),
            )
            .all()
        )

        if not schedules:
            log.debug("No compliance scan schedules are due — nothing to do.")
            return {"success": True, "triggered_count": 0}

        for sched in schedules:
            # A schedule with no policy has nothing to evaluate: run_scan_task
            # would resolve an empty rule set and report a clean, meaningless
            # "completed". Skip it loudly instead.
            if not sched.policy_id:
                log.warning(
                    "Compliance schedule %s has no policy attached; skipping.",
                    sched.id,
                )
                continue

            # This is the only path that starts a compliance scan without a
            # request, and it checked neither of the two things every
            # request-driven path checks. `POST /compliance/schedules` requires
            # the framework to be enabled *at the moment the schedule is
            # created*; nothing re-checked it afterwards, so a framework
            # uninstalled or parked later kept being scanned on beat — writing
            # findings and scores for a framework the workspace does not show.
            if not is_active_framework(sched.framework_id):
                log.info(
                    "Compliance schedule %s targets %s, which is not enabled on "
                    "this installation; skipping.",
                    sched.id,
                    sched.framework_id,
                )
                continue

            installed = (
                db.query(ComplianceTenantFramework)
                .filter(
                    ComplianceTenantFramework.tenant_id == sched.tenant_id,
                    ComplianceTenantFramework.framework_id == sched.framework_id,
                    ComplianceTenantFramework.is_enabled == True,  # noqa: E712
                )
                .first()
            )
            if not installed:
                log.info(
                    "Compliance schedule %s targets %s, which tenant %s does not "
                    "have installed; skipping.",
                    sched.id,
                    sched.framework_id,
                    sched.tenant_id,
                )
                continue

            scan_run_id = gen_compliance_scan_run_id(sched.tenant_id)
            scan_run = ComplianceScanRun(
                id=scan_run_id,
                tenant_id=sched.tenant_id,
                framework_id=sched.framework_id,
                policy_id=sched.policy_id,
                schedule_id=sched.id,
                scope=sched.scope or {},
                status="queued",
                # `created_at` used to be passed here and there is no such
                # column on this model, so every invocation of this task raised
                # TypeError, was swallowed by the except below, and reported
                # `{"success": False}` — scheduled compliance scanning had never
                # once run. The run's creation time is `created_at` on the row
                # now; see migration a1b2c3d4e5f6.
                created_at=now,
            )
            db.add(scan_run)
            db.flush()

            # Calculate next run timestamp based on frequency
            freq = (sched.frequency or "weekly").lower()
            delta = _SCHEDULE_INTERVALS.get(freq, timedelta(days=1))

            sched.last_run_at = now
            sched.next_run_at = now + delta
            db.commit()

            # Dispatch background scan execution
            run_scan_task.delay(scan_run_id, sched.tenant_id)
            triggered += 1

        if triggered:
            log.info("Scheduled compliance scans: triggered %d scan(s).", triggered)

        return {"success": True, "triggered_count": triggered}
    except Exception as exc:
        db.rollback()
        log.exception("Error executing scheduled compliance scans worker.")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()
