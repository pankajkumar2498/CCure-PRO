"""
core/compliance_tasks.py
Celery background worker tasks for the Policy Compliance Engine.
"""

import logging
from typing import Any, Optional
import re
import socket
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from core.celery_app import celery_app
from db.base import SessionLocal
from db.models import Asset, Service
from db.models.compliance import (
    ComplianceScanRun,
    CompliancePolicyRule,
    ComplianceRule,
    ComplianceRuleDependency,
    ComplianceRuleControl,
    ComplianceFinding,
    ComplianceFindingHistory,
    ComplianceScore,
    ComplianceException,
    ComplianceRemediation,
    ComplianceControl,
    ComplianceCredential,
    ComplianceRemediationRequest,
)
from core.compliance_evidence import ComplianceEvidenceProvider

log = logging.getLogger("ccure.compliance.tasks")


# ─────────────────────────────────────────────────────────────────────────────
# Operator Evaluation Helper
# ─────────────────────────────────────────────────────────────────────────────


def _evaluate_operator(operator: str, actual: Any, expected: Any) -> bool:
    """Applies criteria operators to normalize evidence values."""
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
    # 1. Verify credential status for credential-dependent rules
    if rule.evidence_source in (
        "offline_configuration",
        "malware_scan",
        "vulnerability_audit",
    ):
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
        db.commit()

        # 1. Resolve Asset Scope
        scope = run.scope or {}
        asset_ids = scope.get("asset_ids", [])
        asset_tags = scope.get("asset_tags", [])

        asset_query = db.query(Asset).filter(Asset.org_id == org_id)
        if asset_ids:
            asset_query = asset_query.filter(Asset.id.in_(asset_ids))
        assets = asset_query.all()

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
            run.status = "completed"
            run.finished_at = datetime.now(timezone.utc)
            db.commit()
            return {"success": True, "message": "No assets in scope."}

        # Flush stale Redis evidence cache for targeted assets using pipeline
        resolved_asset_ids = [a.id for a in assets]
        ComplianceEvidenceProvider.invalidate_asset_evidence_cache(resolved_asset_ids)

        # 2. Resolve Policy Rules
        policy_rules = (
            db.query(CompliancePolicyRule)
            .filter(CompliancePolicyRule.policy_id == run.policy_id)
            .all()
        )
        rule_ids = [pr.rule_id for pr in policy_rules]
        rules = db.query(ComplianceRule).filter(ComplianceRule.id.in_(rule_ids)).all()

        # 3. Evaluation Loop
        now = datetime.now(timezone.utc)
        for asset in assets:
            for rule in rules:
                # 3.1. Prerequisite verification
                if not _check_prerequisites(db, asset, rule, org_id):
                    _save_finding(
                        db,
                        org_id,
                        asset.id,
                        rule,
                        run_id=scan_run_id,
                        status="manual_review",
                        evidence={"message": "Prerequisite check failed."},
                    )
                    continue

                # 3.1.5 Platform compatibility check
                if rule.target_platform and rule.target_platform.lower() != "any":
                    asset_os = (asset.os_family or asset.os_name or "").lower()
                    if not asset_os:
                        _save_finding(
                            db,
                            org_id,
                            asset.id,
                            rule,
                            run_id=scan_run_id,
                            status="manual_review",
                            evidence={
                                "message": "OS fingerprint missing. Cannot evaluate platform-dependent rule."
                            },
                        )
                        continue

                    rule_plat = rule.target_platform.lower()
                    if rule_plat not in asset_os:
                        _save_finding(
                            db,
                            org_id,
                            asset.id,
                            rule,
                            run_id=scan_run_id,
                            status="not_applicable",
                            evidence={
                                "message": f"Rule target platform is {rule.target_platform}, but host platform is {asset.os_family or asset.os_name}."
                            },
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
                    run_id=scan_run_id,
                    status=status,
                    evidence=evidence,
                )

            # 3.4. Calculate Asset Compliance Score
            _calculate_compliance_score(
                db, org_id, run.framework_id, asset.id, scan_run_id
            )

        # 3.4.5 Process manual governance rules at organization level (asset_id = None)
        manual_rules = [r for r in rules if r.evidence_source == "manual"]
        for m_rule in manual_rules:
            link = (
                db.query(ComplianceRuleControl)
                .filter(ComplianceRuleControl.rule_id == m_rule.id)
                .first()
            )
            control_id = link.control_id if link else None
            if control_id:
                existing_org_finding = (
                    db.query(ComplianceFinding)
                    .filter(
                        ComplianceFinding.tenant_id == org_id,
                        ComplianceFinding.control_id == control_id,
                        ComplianceFinding.asset_id.is_(None),
                    )
                    .first()
                )
                if not existing_org_finding:
                    _save_finding(
                        db,
                        org_id,
                        None,
                        m_rule,
                        run_id=scan_run_id,
                        status="manual_review",
                        evidence={
                            "message": "This control requires manual attestation of administrative policies."
                        },
                    )

        # 3.5. Calculate Org Compliance Score (asset_id = None)
        _calculate_compliance_score(db, org_id, run.framework_id, None, scan_run_id)

        # 4. Conclude scan run
        run.status = "completed"
        run.finished_at = datetime.now(timezone.utc)
        db.commit()

        log.info(f"Compliance scan run {scan_run_id} completed successfully.")
        return {"success": True, "scan_run_id": scan_run_id}

    except Exception as exc:
        db.rollback()
        log.exception(f"Compliance scan run {scan_run_id} failed.")
        if run:
            run.status = "failed"
            db.commit()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


def _save_finding(
    db: Session,
    org_id: str,
    asset_id: str,
    rule: ComplianceRule,
    run_id: str,
    status: str,
    evidence: dict,
):
    """Saves or updates a compliance finding, recording the timeline transition."""
    # Find matching control mapping
    link = (
        db.query(ComplianceRuleControl)
        .filter(ComplianceRuleControl.rule_id == rule.id)
        .first()
    )
    control_id = (
        link.control_id if link else "cct_iso27001_2022_8.9"
    )  # Default fallback configuration control

    asset_suffix = asset_id[-8:] if asset_id else "orglevel"
    finding_id = f"cfnd_{org_id[:4]}_{asset_suffix}_{control_id[-8:]}_{rule.id[-8:]}"

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

    # Query cde_scope from the scan run
    cde_scope = None
    if run_id:
        run = db.query(ComplianceScanRun).filter(ComplianceScanRun.id == run_id).first()
        if run:
            cde_scope = run.cde_scope

    from sqlalchemy.exc import IntegrityError

    had_transition = False
    old_status = None

    try:
        with db.begin_nested():
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
                )
                db.add(finding)
                had_transition = True
                old_status = "new"
            else:
                # Keep track of status shifts
                if finding.status != target_status:
                    old_status = finding.status
                    finding.status = target_status
                    had_transition = True
                finding.scan_run_id = run_id
                finding.last_seen = now
                finding.evidence = evidence
                finding.cde_scope = cde_scope

            if had_transition:
                history = ComplianceFindingHistory(
                    id=f"cfh_{org_id[:4]}_{datetime.now().strftime('%M%S%f')}",
                    finding_id=finding_id,
                    status=target_status,
                    source="auto_scan",
                    note=f"Status transitioned from {old_status} to {target_status} during scan run {run_id}",
                )
                db.add(history)
            db.flush()
    except IntegrityError:
        # Concurrently inserted or updated by another task running in parallel
        db.rollback()
        finding = (
            db.query(ComplianceFinding)
            .filter(ComplianceFinding.id == finding_id)
            .first()
        )
        if finding:
            finding.scan_run_id = run_id
            finding.last_seen = now
            finding.evidence = evidence
            finding.cde_scope = cde_scope
            if finding.status != target_status:
                old_status = finding.status
                finding.status = target_status
                history = ComplianceFindingHistory(
                    id=f"cfh_{org_id[:4]}_{datetime.now().strftime('%M%S%f')}",
                    finding_id=finding_id,
                    status=target_status,
                    source="auto_scan",
                    note=f"Status transitioned from {old_status} to {target_status} during scan run {run_id}",
                )
                db.add(history)
            db.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Scoring Logic Implementation
# ─────────────────────────────────────────────────────────────────────────────


def _calculate_compliance_score(
    db: Session,
    org_id: str,
    framework_id: str,
    asset_id: Optional[str],
    scan_run_id: str,
    saq_profile: Optional[str] = None,
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
            finding_query = finding_query.filter(ComplianceFinding.asset_id == asset_id)
            findings = finding_query.all()
            finding_map = {f.control_id: f for f in findings}
        else:
            # Rollup across all assets for the organization
            findings = finding_query.all()
            control_findings = {}
            for f in findings:
                control_findings.setdefault(f.control_id, []).append(f)

            finding_map = {}
            for c_id, f_list in control_findings.items():
                statuses = [f.status for f in f_list]
                if "fail" in statuses:
                    rolled_status = "fail"
                elif "pending_reverify" in statuses:
                    rolled_status = "pending_reverify"
                elif "remediation_applied" in statuses:
                    rolled_status = "remediation_applied"
                elif "manual_review" in statuses:
                    rolled_status = "manual_review"
                elif "exception" in statuses:
                    rolled_status = "exception"
                elif "pass" in statuses:
                    rolled_status = "pass"
                else:
                    rolled_status = "not_applicable"

                rule_id = next((f.rule_id for f in f_list if f.rule_id), None)

                class RolledUpFinding:
                    def __init__(self, status, rule_id):
                        self.status = status
                        self.rule_id = rule_id

                finding_map[c_id] = RolledUpFinding(rolled_status, rule_id)

        total = len(controls)
        applicable = 0
        passed = 0
        failed = 0
        na = 0
        pending = 0

        # Risk weights accumulator
        weighted_total = 0.0
        weighted_passed = 0.0

        severity_weights = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.0,
        }

        for c in controls:
            f = finding_map.get(c.id)
            if not f:
                pending += 1
                applicable += 1
                continue

            weight = 5.0  # Default weight
            if f.rule_id:
                rule = (
                    db.query(ComplianceRule)
                    .filter(ComplianceRule.id == f.rule_id)
                    .first()
                )
                if rule:
                    weight = float(severity_weights.get(rule.severity.lower(), 5.0))

            if f.status in ("pass", "exception"):
                passed += 1
                applicable += 1
                weighted_passed += weight
                weighted_total += weight
            elif f.status in ("fail", "pending_reverify"):
                failed += 1
                applicable += 1
                weighted_total += weight
            elif f.status == "not_applicable":
                na += 1
            elif f.status in ("manual_review", "remediation_applied"):
                pending += 1
                applicable += 1
                weighted_total += weight

        score_pct = (passed / applicable) * 100 if applicable > 0 else 0.0
        weighted_score = (
            (weighted_passed / weighted_total) * 100 if weighted_total > 0 else 0.0
        )

        # Unique ID per org, framework, theme, asset, and optional SAQ profile
        suffix = f"_{saq_profile.lower()}" if saq_profile else ""
        score_id = f"csc_{org_id[:4]}_{framework_id[-8:]}_{theme.lower() if theme else 'overall'}_{asset_id[-8:] if asset_id else 'summary'}{suffix}"
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
    db: Session, request: Optional[ComplianceRemediationRequest], kwargs: dict
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


def _inject_sudo_password(command: str, password: Optional[str]) -> str:
    """Injects sudo password using -S parameter for non-interactive execution."""
    if not password:
        return command
    import re

    escaped_password = password.replace("'", "'\\''")
    pattern = r"\bsudo\b"
    replacement = f"echo '{escaped_password}' | sudo -S"
    return re.sub(pattern, replacement, command)


def _execute_ssh_remediation(
    ip: str,
    port: int,
    username: str,
    password: Optional[str],
    key_content: Optional[str],
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
    elif platform == "linux":
        command = _inject_sudo_password(command, password)

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
        res = scanner.run(command, timeout=60)
        return {
            "success": res.success,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "exit_code": res.exit_code,
            "error": "",
            "executed_command": clean_command,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "error": f"SSH connection or execution failed: {str(e)}",
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
                svc.state = "open" if is_open else "closed"
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
        id=f"cfh_{finding.tenant_id[:4]}_{datetime.now().strftime('%M%S%f')}",
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
    req: Optional[ComplianceRemediationRequest],
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
    remediation_request_id: Optional[str] = None,
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
                id=f"cfh_{finding.tenant_id[:4]}_{datetime.now().strftime('%M%S%f')}",
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
        actual_val = evidence.get(key) if key else None

        passed = _evaluate_operator(
            operator=check_def.get("operator", "equals"),
            actual=actual_val,
            expected=check_def.get("expected"),
        )

        target_status = "pass" if passed else "fail"
        finding.status = target_status
        finding.last_seen = datetime.now(timezone.utc)
        finding.evidence = evidence

        history = ComplianceFindingHistory(
            id=f"cfh_{finding.tenant_id[:4]}_{datetime.now().strftime('%M%S%f')}",
            finding_id=finding.id,
            status=target_status,
            source="remediation",
            note=f"Reverification completed. Check result: {target_status.upper()}",
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


@celery_app.task(name="compliance.run_scheduled_scans", queue="compliance")
def run_scheduled_scans() -> dict:
    """Periodic task executed by Celery Beat to query and trigger scheduled compliance scans."""
    from db.models.compliance import ComplianceScanSchedule
    from db.base import gen_compliance_scan_run_id
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

        for sched in schedules:
            scan_run_id = gen_compliance_scan_run_id(sched.tenant_id)
            scan_run = ComplianceScanRun(
                id=scan_run_id,
                tenant_id=sched.tenant_id,
                framework_id=sched.framework_id,
                policy_id=sched.policy_id,
                schedule_id=sched.id,
                scope=sched.scope or {},
                status="queued",
                created_at=now,
            )
            db.add(scan_run)
            db.flush()

            # Calculate next run timestamp based on frequency
            freq = (sched.frequency or "weekly").lower()
            if freq == "daily":
                delta = timedelta(days=1)
            elif freq == "weekly":
                delta = timedelta(weeks=1)
            elif freq == "monthly":
                delta = timedelta(days=30)
            elif freq == "quarterly":
                delta = timedelta(days=90)
            else:
                delta = timedelta(days=1)

            sched.last_run_at = now
            sched.next_run_at = now + delta
            db.commit()

            # Dispatch background scan execution
            run_scan_task.delay(scan_run_id, sched.tenant_id)
            triggered += 1

        return {"success": True, "triggered_count": triggered}
    except Exception as exc:
        db.rollback()
        log.exception("Error executing scheduled compliance scans worker.")
        return {"success": False, "error": str(exc)}
    finally:
        db.close()
