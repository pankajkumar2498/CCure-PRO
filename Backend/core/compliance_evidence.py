"""
core/compliance_evidence.py
Translates raw scans and asset findings into normalized payloads for rule check evaluations.
"""

import json
import logging
from typing import Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_

from db.models.assets import Asset
from db.models.findings import (
    Service,
    TLSDetail,
    AssetVulnerability,
    VulnerabilityDefinition,
)
from db.models.topology import NetworkLink
from core.redis_client import get_redis_client

log = logging.getLogger("ccure.compliance.evidence")
redis = get_redis_client()

EPL_CACHE_TTL = 300  # 5 minutes cache


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

        known_sources = sources or [
            "active_services",
            "tls_ssl_configuration",
            "vulnerability_audit",
            "offline_configuration",
            "malware_scan",
            "network_link_topology",
        ]

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
            log.warning(f"Failed to clear Redis evidence cache pipeline: {str(e)}")

    @classmethod
    def get_normalized_evidence(
        cls, db: Session, asset_id: str, source: str
    ) -> Dict[str, Any]:
        """Resolves normalise evidence, utilizing Redis cache."""
        cache_key = cls.get_cache_key(asset_id, source)
        try:
            cached_data = redis.get(cache_key)
            if cached_data:
                log.debug(f"Cache hit for evidence {cache_key}")
                return json.loads(cached_data)
        except Exception as e:
            log.warning(f"Failed to query Redis cache: {str(e)}")

        # Cache miss - fetch and translate
        log.info(
            f"Cache miss. Resolving raw findings for asset {asset_id}, source {source}"
        )
        payload = cls._fetch_and_translate(db, asset_id, source)

        try:
            redis.setex(cache_key, EPL_CACHE_TTL, json.dumps(payload))
        except Exception as e:
            log.warning(f"Failed to save evidence to Redis cache: {str(e)}")

        return payload

    @classmethod
    def _fetch_and_translate(
        cls, db: Session, asset_id: str, source: str
    ) -> Dict[str, Any]:
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

        return {}

    # ── 1. Vulnerability Audit Mapping ──────────────────────────────────────────
    @staticmethod
    def _adapt_vulnerability_audit(db: Session, asset_id: str) -> Dict[str, Any]:
        vulns = (
            db.query(AssetVulnerability)
            .join(VulnerabilityDefinition)
            .filter(AssetVulnerability.asset_id == asset_id)
            .all()
        )

        critical_count = sum(
            1 for v in vulns if (v.vulnerability.severity or "").lower() == "critical"
        )
        high_count = sum(
            1 for v in vulns if (v.vulnerability.severity or "").lower() == "high"
        )
        medium_count = sum(
            1 for v in vulns if (v.vulnerability.severity or "").lower() == "medium"
        )
        low_count = sum(
            1 for v in vulns if (v.vulnerability.severity or "").lower() == "low"
        )

        return {
            "total_vulnerabilities": len(vulns),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "vulnerabilities": [
                {
                    "cve_id": v.vulnerability.cve_id,
                    "cvss_score": (
                        float(v.vulnerability.cvss_v3_score)
                        if v.vulnerability.cvss_v3_score
                        else 0.0
                    ),
                    "severity": v.vulnerability.severity,
                }
                for v in vulns
            ],
        }

    # ── 2. Malware Scan Mapping ───────────────────────────────────────────────
    @staticmethod
    def _adapt_malware_scan(db: Session, asset_id: str) -> Dict[str, Any]:
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
    def _adapt_services_ports(db: Session, asset_id: str) -> Dict[str, Any]:
        services = db.query(Service).filter(Service.asset_id == asset_id).all()
        ports_list = [svc.port for svc in services if svc.state == "open"]

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
    def _adapt_tls_certificates(db: Session, asset_id: str) -> Dict[str, Any]:
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
    def _adapt_network_topology(db: Session, asset_id: str) -> Dict[str, Any]:
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
    def _adapt_credential_validation(db: Session, asset_id: str) -> Dict[str, Any]:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        creds_status = (
            (asset.custom_attributes or {}).get("credentialed_status", "unknown")
            if asset
            else "unknown"
        )

        # Check if auth/password configuration baselines are checked in custom_attributes
        pwd_attrs = (
            (asset.custom_attributes or {}).get("password_policy", {}) if asset else {}
        )

        return {
            "credentialed_scan_successful": creds_status == "success",
            "password_complexity_configured": pwd_attrs.get("complexity", False),
            "password_history_length": pwd_attrs.get("history_length", 0),
            "minimum_password_length": pwd_attrs.get("min_length", 8),
        }

    # ── 7. Offline Configuration Scan Mapping ─────────────────────────────────
    @staticmethod
    def _adapt_offline_configuration(db: Session, asset_id: str) -> Dict[str, Any]:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        registry_attrs = (
            (asset.custom_attributes or {}).get("registry_hardening", {})
            if asset
            else {}
        )
        custom_attrs = (asset.custom_attributes or {}) if asset else {}

        rdp_disabled = registry_attrs.get("rdp_disabled", False)
        rdp_nla_enforced = registry_attrs.get("rdp_nla_enforced", False) or rdp_disabled

        return {
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
            "mfa_enforced_admin": registry_attrs.get("mfa_enforced_admin")
            or custom_attrs.get("mfa_enforced_admin"),
            "last_scan_days_ago": custom_attrs.get("last_scan_days_ago"),
        }
