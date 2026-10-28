"""
core/web/evidence.py
─────────────────────────────────────────────────────────────────────────────
Web application scanning's compliance evidence: ``web_vulnerability_audit``,
what the latest completed web scan of a host found.

G4 (C4 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) moved it,
unchanged, out of ``core/compliance_evidence.py``, which queried the web-scan
tables itself. The asset it is about arrives as an identity, so this module
reads no asset table; Audit's composition root,
``ccure_audit/evidence_providers.py``, registers it with compliance.
"""

from typing import Any

from db.models.web_scans import WebFinding, WebScan
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

__all__ = ["web_vulnerability_audit"]


def web_vulnerability_audit(db: Session, asset) -> dict[str, Any]:
    """
    Web-application evidence for a network asset, or an explicit "not assessed".

    This used to filter ``WebFinding.web_asset_id == asset_id``. The id it is
    handed is a network ``Asset.id`` (``ast_…``); ``web_asset_id`` holds
    web-scan asset ids (``was_…``). The two never meet, so the query always
    returned nothing and every web rule read "0 critical findings, no SQLi" —
    a PASS on evidence nobody had collected (finding F3).

    There is no stored link between a network asset and a web scan, so the
    link is made explicitly: the most recent **completed** web scan in the
    same organisation whose target host is this asset's IP address or
    hostname (port ignored). Only that scan's findings are evidence. With no
    such scan the answer is ``_evidence_available: False`` — the rules then
    record ``manual_review`` with the reason, because "no web scan ran against
    this host" and "a web scan found nothing" are different facts.

    Current conditions are the statuses a finding can hold while still true
    of the application: ``open``, ``confirmed`` and ``reopened``. The
    network-finding adapter likewise leaves accepted and fixed findings out.

    *asset* is the network asset's identity — anything carrying ``org_id``,
    ``ip_address`` and ``hostname``, which the asset registry's
    ``asset_identity`` answers — or None when there is no such asset. Before
    G4 this read the asset row itself.
    """
    if asset is None:
        return {
            "_evidence_available": False,
            "_reason": "Asset not found; web-application evidence cannot be read.",
        }

    hosts = set()
    if asset.ip_address:
        hosts.add(str(asset.ip_address).split("/")[0].lower())
    if asset.hostname:
        hosts.add(asset.hostname.strip().lower())
    hosts.discard("")
    if not hosts:
        return {
            "_evidence_available": False,
            "_reason": (
                "The asset has neither an IP address nor a hostname to match "
                "against a web application scan target."
            ),
        }

    domain = func.lower(WebScan.target_domain)
    host_match = or_(
        *[domain == host for host in hosts],
        *[domain.like(f"{host}:%") for host in hosts],
    )
    latest = (
        db.query(WebScan)
        .filter(
            WebScan.org_id == asset.org_id,
            WebScan.status == "complete",
            WebScan.is_deleted == False,  # noqa: E712
            host_match,
        )
        .order_by(WebScan.completed_at.desc().nullslast())
        .first()
    )
    if latest is None:
        return {
            "_evidence_available": False,
            "_reason": (
                "No completed web application scan targets this host "
                f"({', '.join(sorted(hosts))}); web-application rules are not "
                "assessed."
            ),
        }

    findings = (
        db.query(WebFinding)
        .filter(
            WebFinding.web_scan_id == latest.id,
            WebFinding.status.in_(("open", "confirmed", "reopened")),
        )
        .all()
    )

    return {
        "critical_web_vuln_count": sum(1 for f in findings if f.severity == "critical"),
        "high_web_vuln_count": sum(1 for f in findings if f.severity == "high"),
        "sqli_detected": any(f.finding_type == "sqli" for f in findings),
        "xss_detected": any(f.finding_type == "xss" for f in findings),
        "tls_issue_detected": any(f.finding_type == "tls_issue" for f in findings),
    }
