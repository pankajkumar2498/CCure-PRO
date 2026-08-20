"""
core/compliance_evidence.py
Translates raw scans and asset findings into normalized payloads for rule check evaluations.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.redis_client import get_redis_client
from db.models.assets import Asset
from db.models.findings import (
    OBSERVED_SERVICE_STATES,
    AssetVulnerability,
    Service,
    TLSDetail,
    VulnerabilityDefinition,
)
from db.models.topology import NetworkLink
from sqlalchemy import or_
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.compliance.evidence")
redis = get_redis_client()


def _days_since(value) -> Optional[int]:
    """Whole days between an ISO-8601 timestamp and now, or None."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).days


EPL_CACHE_TTL = 300  # 5 minutes cache

# The complete set of evidence sources a rule may declare. This is the single
# source of truth: `_fetch_and_translate` dispatches on it, cache invalidation
# iterates it, and `tests/test_compliance_rule_wiring.py` asserts that every
# active rule names one of these and reads a key the adapter actually emits.
#
# `manual` is included because it is a legitimate rule declaration — the scan
# loop skips those rules and produces an org-level attestation placeholder
# instead — but it has no adapter and never reaches `_fetch_and_translate`.
EVIDENCE_SOURCES: tuple[str, ...] = (
    "vulnerability_audit",
    "malware_scan",
    "services_ports",
    "tls_certificates",
    "network_topology",
    "credential_validation",
    "offline_configuration",
    "web_vulnerability_audit",
)

VALID_RULE_EVIDENCE_SOURCES: frozenset = frozenset(EVIDENCE_SOURCES) | {"manual"}


class ComplianceEvidenceProvider:
    @staticmethod
    def get_cache_key(asset_id: str, source: str) -> str:
        return f"compliance:evidence:{asset_id}:{source}"

    @classmethod
    def invalidate_asset_evidence_cache(
        cls, asset_ids: list, sources: list = None
    ) -> None:
        """Batch-flushes evidence cache keys in Redis using a pipeline."""
        if not redis or not asset_ids:
            return

        # These must be the names `_fetch_and_translate` dispatches on, because
        # that is what `get_cache_key` uses to build the key. Three of the
        # names here used to be inventions — `active_services`,
        # `tls_ssl_configuration` and `network_link_topology` are not evidence
        # sources — so the flush deleted keys that never existed and left the
        # real ones in place. A scan that had just re-collected a host's ports
        # then evaluated against evidence up to five minutes old.
        known_sources = sources or list(EVIDENCE_SOURCES)

        try:
            pipe = redis.pipeline()
            keys_count = 0
            for aid in asset_ids:
                for src in known_sources:
                    pipe.delete(cls.get_cache_key(aid, src))
                    keys_count += 1
            pipe.execute()
            log.info(
                f"Invalidated {keys_count} Redis evidence cache keys for assets: {asset_ids}"
            )
        except Exception as e:
            log.warning(f"Failed to clear Redis evidence cache pipeline: {e!s}")

    @classmethod
    def get_normalized_evidence(
        cls, db: Session, asset_id: str, source: str
    ) -> dict[str, Any]:
        """Resolves normalise evidence, utilizing Redis cache."""
        cache_key = cls.get_cache_key(asset_id, source)
        try:
            cached_data = redis.get(cache_key)
            if cached_data:
                log.debug(f"Cache hit for evidence {cache_key}")
                return json.loads(cached_data)
        except Exception as e:
            log.warning(f"Failed to query Redis cache: {e!s}")

        # Cache miss - fetch and translate
        log.info(
            f"Cache miss. Resolving raw findings for asset {asset_id}, source {source}"
        )
        payload = cls._fetch_and_translate(db, asset_id, source)

        try:
            redis.setex(cache_key, EPL_CACHE_TTL, json.dumps(payload))
        except Exception as e:
            log.warning(f"Failed to save evidence to Redis cache: {e!s}")

        return payload

    @classmethod
    def _fetch_and_translate(
        cls, db: Session, asset_id: str, source: str
    ) -> dict[str, Any]:
        """Routes to specific scanner adapters based on source."""
        if source == "vulnerability_audit":
            return cls._adapt_vulnerability_audit(db, asset_id)
        elif source == "malware_scan":
            return cls._adapt_malware_scan(db, asset_id)
        elif source == "services_ports":
            return cls._adapt_services_ports(db, asset_id)
        elif source == "tls_certificates":
            return cls._adapt_tls_certificates(db, asset_id)
        elif source == "network_topology":
            return cls._adapt_network_topology(db, asset_id)
        elif source == "credential_validation":
            return cls._adapt_credential_validation(db, asset_id)
        elif source == "offline_configuration":
            return cls._adapt_offline_configuration(db, asset_id)
        elif source == "web_vulnerability_audit":
            return cls._adapt_web_vulnerability_audit(db, asset_id)

        # No adapter for this source. Returning an empty payload made every key
        # look absent, and an absent key evaluated to a failed control — so an
        # unsupported or not-yet-collected evidence source reported the asset as
        # non-compliant rather than as unassessed. The caller has to be able to
        # tell those apart.
        log.warning(
            "No evidence adapter for source '%s'; asset %s cannot be assessed "
            "against rules that depend on it",
            source,
            asset_id,
        )
        return {
            "_evidence_available": False,
            "_reason": f"No evidence adapter is implemented for source '{source}'.",
        }

    # ── 1. Vulnerability Audit Mapping ──────────────────────────────────────────
    @staticmethod
    def _adapt_vulnerability_audit(db: Session, asset_id: str) -> dict[str, Any]:
        # Only open findings are evidence of a current condition. Every row for
        # the asset was previously counted, including ones the syncer had closed
        # as fixed on a later scan and ones an approver had formally accepted —
        # so a host that had remediated every critical still failed a "no
        # critical vulnerabilities" control, permanently and invisibly.
        vulns = (
            db.query(AssetVulnerability)
            .join(VulnerabilityDefinition)
            .filter(
                AssetVulnerability.asset_id == asset_id,
                AssetVulnerability.status == "open",
            )
            .all()
        )

        def severity_of(finding: AssetVulnerability) -> str:
            # The finding's own severity is the one the scan recorded for this
            # host, recomputed from the published CVSS vector. The catalogue
            # column is the feed's label for the CVE in general and the two
            # disagree often enough to change a control's verdict.
            return (
                finding.severity
                or (finding.vulnerability.severity if finding.vulnerability else "")
                or ""
            ).lower()

        severities = [severity_of(v) for v in vulns]

        def score_of(finding: AssetVulnerability) -> float:
            raw = finding.cvss_score
            if raw is None and finding.vulnerability is not None:
                raw = finding.vulnerability.cvss_v3_score
            return float(raw) if raw is not None else 0.0

        return {
            "total_vulnerabilities": len(vulns),
            "critical_count": severities.count("critical"),
            "high_count": severities.count("high"),
            "medium_count": severities.count("medium"),
            "low_count": severities.count("low"),
            "vulnerabilities": [
                {
                    "cve_id": v.vulnerability.cve_id if v.vulnerability else v.id,
                    "cvss_score": score_of(v),
                    "severity": severity_of(v).title(),
                }
                for v in vulns
            ],
        }

    # ── 2. Malware Scan Mapping ───────────────────────────────────────────────
    @staticmethod
    def _adapt_malware_scan(db: Session, asset_id: str) -> dict[str, Any]:
        # Checks if anti-malware services are present and active
        services = db.query(Service).filter(Service.asset_id == asset_id).all()
        malware_processes = [
            "defender",
            "clamav",
            "sentinel",
            "mcafee",
            "symantec",
            "crowdstrike",
        ]

        active_av_agents = []
        for svc in services:
            svc_name = (svc.service_name or "").lower()
            if any(av in svc_name for av in malware_processes):
                active_av_agents.append(svc.service_name)

        # Query custom_attributes from the Asset directly
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset and asset.custom_attributes:
            sys_info = asset.custom_attributes.get("credentialed_system_info", {})
            running_svcs = sys_info.get("running_services", [])
            for svc in running_svcs:
                svc_name = (svc.get("name") or svc.get("description") or "").lower()
                if any(av in svc_name for av in malware_processes):
                    active_av_agents.append(svc.get("name") or svc.get("description"))

        # Deduplicate
        active_av_agents = list(set(active_av_agents))

        return {
            "malware_detected": False,  # Managed by agent alerts
            "anti_malware_agents_active": len(active_av_agents) > 0,
            "agents_list": active_av_agents,
        }

    # ── 3. Services & Ports Mapping ───────────────────────────────────────────
    @staticmethod
    def _adapt_services_ports(db: Session, asset_id: str) -> dict[str, Any]:
        services = db.query(Service).filter(Service.asset_id == asset_id).all()
        # A service bound to loopback is not an open port for the purposes of
        # any control that asks what this host exposes, so host_only rows are
        # excluded here rather than counted and then explained away.
        ports_list = [
            svc.port for svc in services if svc.state in OBSERVED_SERVICE_STATES
        ]

        return {
            "open_ports_count": len(ports_list),
            "open_ports": ports_list,
            "services_list": [
                {"port": s.port, "protocol": s.protocol, "name": s.service_name}
                for s in services
            ],
        }

    # ── 4. TLS & Certificates Mapping ────────────────────────────────────────
    @staticmethod
    def _adapt_tls_certificates(db: Session, asset_id: str) -> dict[str, Any]:
        tls_certs = (
            db.query(TLSDetail).join(Service).filter(Service.asset_id == asset_id).all()
        )

        expired_count = sum(1 for t in tls_certs if t.cert_is_expired)
        weak_ciphers = sum(1 for t in tls_certs if t.is_weak_cipher)
        self_signed = sum(1 for t in tls_certs if t.cert_is_self_signed)

        protocols = list({t.protocol_version for t in tls_certs if t.protocol_version})

        return {
            "active_certificates_count": len(tls_certs),
            "expired_certificates_count": expired_count,
            "weak_ciphers_count": weak_ciphers,
            "self_signed_count": self_signed,
            "supported_protocols": protocols,
        }

    # ── 5. Network Topology Mapping ───────────────────────────────────────────
    @staticmethod
    def _adapt_network_topology(db: Session, asset_id: str) -> dict[str, Any]:
        links = (
            db.query(NetworkLink)
            .filter(
                or_(
                    NetworkLink.source_asset_id == asset_id,
                    NetworkLink.target_asset_id == asset_id,
                )
            )
            .all()
        )

        return {
            "connections_count": len(links),
            "network_neighbors": [
                {"source": l.source_ip, "target": l.target_ip, "type": l.link_type}
                for l in links
            ],
        }

    # ── 6. Credential Validation Mapping ──────────────────────────────────────
    @staticmethod
    def _adapt_credential_validation(db: Session, asset_id: str) -> dict[str, Any]:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        creds_status = (
            (asset.custom_attributes or {}).get("credentialed_status", "unknown")
            if asset
            else "unknown"
        )

        pwd_attrs = (
            (asset.custom_attributes or {}).get("password_policy") or {}
            if asset
            else {}
        )

        # Only `credentialed_scan_successful` is always known — it is a fact
        # about this scanner, not about the host. The password-policy keys used
        # to carry defaults (`False`, `0`, `8`) that were indistinguishable
        # from a collected value, so an uncollected policy was reported as a
        # measured failure.
        payload: dict[str, Any] = {
            "credentialed_scan_successful": creds_status == "success",
            "password_complexity_configured": pwd_attrs.get("complexity"),
            "password_history_length": pwd_attrs.get("history_length"),
            "minimum_password_length": pwd_attrs.get("min_length"),
            "password_max_age_days": pwd_attrs.get("max_age_days"),
            "account_lockout_threshold": pwd_attrs.get("lockout_threshold"),
        }

        # Every key this adapter can serve is named in the literal above so the
        # catalogue guard in tests/test_compliance_rule_wiring.py can read the
        # adapter's key surface statically. Uncollected keys are then dropped,
        # which routes the rule to `manual_review` rather than to a `fail`
        # computed from a value nobody measured.
        return {k: v for k, v in payload.items() if v is not None}

    # ── 7. Offline Configuration Scan Mapping ─────────────────────────────────
    @staticmethod
    def _adapt_offline_configuration(db: Session, asset_id: str) -> dict[str, Any]:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        registry_attrs = (
            (asset.custom_attributes or {}).get("registry_hardening", {})
            if asset
            else {}
        )
        custom_attrs = (asset.custom_attributes or {}) if asset else {}

        rdp_disabled = registry_attrs.get("rdp_disabled", False)
        rdp_nla_enforced = registry_attrs.get("rdp_nla_enforced", False) or rdp_disabled

        # --- PCI-DSS v4.0 FIM (File Integrity Monitoring) Detection ---
        fim_active = registry_attrs.get("fim_active", False) or custom_attrs.get(
            "fim_active", False
        )
        fim_monitored_dirs = registry_attrs.get(
            "fim_monitored_dirs", []
        ) or custom_attrs.get("fim_monitored_dirs", [])

        # --- PCI-DSS v4.0 PAM MFA Module Detection (Linux pam_duo.so, pam_google_authenticator.so) ---
        pam_mfa_modules = custom_attrs.get("pam_mfa_modules", [])
        pam_mfa_enforced = len(pam_mfa_modules) > 0

        # --- PCI-DSS v4.0 ASV Scan Freshness Tracking ---
        # Track last PASSING ASV scan date, not just any scan execution
        asv_last_passing_scan_date = custom_attrs.get("asv_last_passing_scan_date")
        asv_scan_fresh = False
        if asv_last_passing_scan_date:
            try:
                last_scan = datetime.fromisoformat(
                    asv_last_passing_scan_date.replace("Z", "+00:00")
                )
                days_since = (datetime.now(timezone.utc) - last_scan).days
                asv_scan_fresh = days_since <= 90  # Quarterly cadence
            except (ValueError, TypeError):
                asv_scan_fresh = False

        # --- PCI-DSS v4.0 Daily Log Review (Req 10.4.1) ---
        pci_log_daily_reviewed = custom_attrs.get("pci_log_daily_reviewed", False)

        # --- PCI-DSS v4.0 IR Tabletop Exercise Freshness (Req 12.10.2) ---
        ir_last_test_date = custom_attrs.get("ir_last_test_date")
        ir_test_fresh_365d = False
        if ir_last_test_date:
            try:
                last_test = datetime.fromisoformat(
                    ir_last_test_date.replace("Z", "+00:00")
                )
                days_since_test = (datetime.now(timezone.utc) - last_test).days
                ir_test_fresh_365d = days_since_test <= 365
            except (ValueError, TypeError):
                ir_test_fresh_365d = False

        # --- PCI-DSS v4.0 Session Timeout Configuration (Req 8.2.8) ---
        session_timeout_minutes = registry_attrs.get(
            "session_timeout_minutes"
        ) or custom_attrs.get("session_timeout_minutes")

        # --- PCI-DSS v4.0 Account Lockout Policy (Req 8.3.4) ---
        account_lockout_threshold = registry_attrs.get(
            "account_lockout_threshold"
        ) or custom_attrs.get("account_lockout_threshold")

        # --- PCI-DSS v4.0 WAF Active (Req 6.4.1) ---
        waf_active = custom_attrs.get("waf_active", False)

        # --- PCI-DSS v4.0 IDS/IPS Active (Req 11.5.1) ---
        ids_ips_active = custom_attrs.get("ids_ips_active", False)

        # --- PCI-DSS v4.0 Log Retention (Req 10.5.1: >= 365 days) ---
        log_retention_days = registry_attrs.get("retention_days") or custom_attrs.get(
            "log_retention_days"
        )

        # --- NIST 800-53 / CERT-In operational hygiene ---
        # These were referenced by seeded rules and emitted by nothing, so the
        # rules could only ever report "not assessed".
        last_scan_days_ago = _days_since(custom_attrs.get("last_vuln_scan_at"))
        disk_encryption_enabled = registry_attrs.get(
            "disk_encryption_enabled"
        ) or custom_attrs.get("disk_encryption_enabled")
        password_complexity_enforced = (
            (custom_attrs.get("password_policy") or {}).get("complexity")
            if isinstance(custom_attrs.get("password_policy"), dict)
            else None
        )

        payload = {
            "uac_enabled": registry_attrs.get("uac_enabled", False),
            "firewall_profile_active": registry_attrs.get("firewall_active", False),
            "remote_desktop_disabled": rdp_disabled,
            "audit_policy_configured": registry_attrs.get("audit_configured", False),
            # New normalized protocol hardening attributes
            "smbv1_disabled": registry_attrs.get("smbv1_disabled", False),
            "netbios_disabled": registry_attrs.get("netbios_disabled", False),
            "legacy_tls_disabled": registry_attrs.get("legacy_tls_disabled", False),
            "telnet_disabled": registry_attrs.get("telnet_disabled", False),
            "rdp_nla_enforced": rdp_nla_enforced,
            # --- CERT-In Technical Checks ---
            "retention_days": registry_attrs.get("retention_days")
            or custom_attrs.get("log_retention_days"),
            "ntp_servers": registry_attrs.get("ntp_servers")
            or custom_attrs.get("ntp_servers")
            or [],
            "incident_reporting_sla_hours": registry_attrs.get(
                "incident_reporting_sla_hours"
            )
            or custom_attrs.get("incident_reporting_sla_hours"),
            "vpn_log_retention_years": registry_attrs.get("vpn_log_retention_years")
            or custom_attrs.get("vpn_log_retention_years"),
            # --- PCI-DSS v4.0 ---
            # Every one of these was computed above and then dropped on the
            # floor: the return statement simply did not include them, so the
            # five PCI rules that read them reported "not assessed" forever
            # while the adapter did the work each time.
            "fim_active": fim_active,
            "fim_monitored_dirs": fim_monitored_dirs,
            "pam_mfa_enforced": pam_mfa_enforced,
            "pam_mfa_modules": pam_mfa_modules,
            "asv_scan_fresh": asv_scan_fresh,
            "pci_log_daily_reviewed": pci_log_daily_reviewed,
            "ir_test_fresh_365d": ir_test_fresh_365d,
            "session_timeout_minutes": session_timeout_minutes,
            "account_lockout_threshold": account_lockout_threshold,
            "waf_active": waf_active,
            "ids_ips_active": ids_ips_active,
            "log_retention_days": log_retention_days,
            # --- NIST SP 800-53 Rev. 5 ---
            "last_scan_days_ago": last_scan_days_ago,
            "disk_encryption_enabled": disk_encryption_enabled,
            "password_complexity_enforced": password_complexity_enforced,
            "mfa_enforced_admin": custom_attrs.get("mfa_enforced_admin"),
            "account_review_completed": custom_attrs.get("account_review_completed"),
            "log_review_frequency_days": custom_attrs.get("log_review_frequency_days"),
            "backup_frequency_days": custom_attrs.get("backup_frequency_days"),
            "scrm_plan_documented": custom_attrs.get("scrm_plan_documented"),
            # --- DPDP Act 2023 & GDPR Technical Checks ---
            # These used to default to True — an organisation that had never
            # recorded whether it encrypts personal data, appointed a DPO or
            # ran a DPIA was reported as compliant with all three. A privacy
            # control nobody has answered is unassessed, not satisfied, and the
            # engine already renders a missing key as `manual_review`. Absent
            # keys are therefore stripped below rather than invented here.
            "pii_encryption_enabled": custom_attrs.get("pii_encryption_enabled"),
            "dpo_designated": custom_attrs.get("dpo_designated"),
            "dpia_conducted": custom_attrs.get("dpia_conducted"),
            "breach_notification_sla_hours": custom_attrs.get(
                "breach_notification_sla_hours"
            ),
            "consent_management_active": custom_attrs.get("consent_management_active"),
            "pii_retention_days": custom_attrs.get("pii_retention_days"),
        }

        # A key whose value is None was not collected. Leaving it present makes
        # the engine evaluate it — and `_evaluate_operator` returns False for a
        # None actual, which records a *failure* against a control nobody
        # measured. Dropping the key routes it to `manual_review` instead,
        # which is the distinction the whole engine is built around.
        return {k: v for k, v in payload.items() if v is not None}

    # ── 8. Web Vulnerability Audit Mapping ─────────────────────────────────────────
    @staticmethod
    def _adapt_web_vulnerability_audit(db: Session, asset_id: str) -> dict[str, Any]:
        """Query open WebFinding records for the web asset to drive policy compliance."""
        from db.models.web_scans import WebFinding

        findings = (
            db.query(WebFinding)
            .filter(WebFinding.web_asset_id == asset_id, WebFinding.status == "open")
            .all()
        )

        return {
            "critical_web_vuln_count": sum(
                1 for f in findings if f.severity == "critical"
            ),
            "high_web_vuln_count": sum(1 for f in findings if f.severity == "high"),
            "sqli_detected": any(f.finding_type == "sqli" for f in findings),
            "xss_detected": any(f.finding_type == "xss" for f in findings),
            "tls_issue_detected": any(f.finding_type == "tls_issue" for f in findings),
        }
