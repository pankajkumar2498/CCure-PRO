"""
core/findings/evidence.py
─────────────────────────────────────────────────────────────────────────────
The findings store's compliance evidence: what three of compliance's evidence
sources say about one asset, read from the findings tables.

``vulnerability_audit``  the asset's open findings, by severity
``services_ports``       its service inventory and the ports it exposes
``tls_certificates``     the TLS details of its services

and :func:`service_names`, the inventory's half of ``malware_scan``, which the
asset registry completes with the processes a credentialed scan collected.

G4 (C4 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) moved these,
unchanged, out of ``core/compliance_evidence.py``, which queried the findings
tables itself. Compliance now asks its registry, and Audit's composition root,
``ccure_audit/evidence_providers.py``, registers these with it; nothing here
imports compliance.

A rule reads its key from the dict literal a provider returns, and
``tests/compliance/test_compliance_rule_wiring.py`` reads those literals
statically, so every key a provider can serve is named in one.
"""

from typing import Any, List, Optional

from db.models.findings import (
    OBSERVED_SERVICE_STATES,
    AssetVulnerability,
    Service,
    TLSDetail,
    VulnerabilityDefinition,
)
from sqlalchemy.orm import Session

__all__ = [
    "service_names",
    "services_ports",
    "tls_certificates",
    "vulnerability_audit",
]


def vulnerability_audit(db: Session, asset_id: str) -> dict[str, Any]:
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


def services_ports(db: Session, asset_id: str) -> dict[str, Any]:
    services = db.query(Service).filter(Service.asset_id == asset_id).all()
    # A service bound to loopback is not an open port for the purposes of
    # any control that asks what this host exposes, so host_only rows are
    # excluded here rather than counted and then explained away.
    ports_list = [svc.port for svc in services if svc.state in OBSERVED_SERVICE_STATES]

    return {
        "open_ports_count": len(ports_list),
        "open_ports": ports_list,
        "services_list": [
            {"port": s.port, "protocol": s.protocol, "name": s.service_name}
            for s in services
        ],
    }


def tls_certificates(db: Session, asset_id: str) -> dict[str, Any]:
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


def service_names(db: Session, asset_id: str) -> List[Optional[str]]:
    """
    The name of every service row the asset has, in the order the query
    returns them: the service inventory's half of ``malware_scan``.

    Before G4 the malware adapter queried these rows itself and read each
    ``service_name``; it is handed this list now, in the same order.
    """
    services = db.query(Service).filter(Service.asset_id == asset_id).all()
    return [svc.service_name for svc in services]
