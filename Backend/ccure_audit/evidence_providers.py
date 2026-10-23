"""
Audit's compliance evidence providers, registered with compliance (G4, C4 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

Compliance consumes evidence; it does not query the tables evidence comes from.
Each producing capability answers for the sources it owns — the findings store
(``core/findings/evidence.py``), the asset registry (``core/asset_evidence.py``),
the network topology (``core/topology/evidence.py``) and web application
scanning (``core/web/evidence.py``) — and this module registers those answers
with compliance's registry, ``core.compliance_evidence``.

Registered here rather than by each producer: a producer importing compliance
would be a lateral edge (findings, assets) or an upward one (topology and web
scanning are a layer below compliance), and composing two producers' answers
into one source would have nowhere else to live. Two sources are composed:

* ``malware_scan``: the findings store's service names, then the processes a
  credentialed scan collected onto the asset record — the order the one
  adapter read them in before G4;
* ``web_vulnerability_audit``: the asset registry's identity of the asset,
  matched by web scanning against its scans' targets.

Loaded by name in every process that evaluates compliance: ``core/celery_app.py``
names it in Celery's ``imports``, which the worker loads at start-up and
``main.py`` loads through the same call. A process that evaluated compliance
without it would raise ``EvidenceProviderMissing`` rather than score every
automated rule as not assessed.
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from core import asset_evidence
from core.compliance_evidence import register_evidence_provider
from core.findings import evidence as findings_evidence
from core.topology import evidence as topology_evidence
from core.web import evidence as web_evidence
from sqlalchemy.orm import Session


def malware_scan(db: Session, asset_id: str) -> Dict[str, Any]:
    """Anti-malware agents among the asset's services and collected processes."""
    return asset_evidence.malware_scan(
        db, asset_id, findings_evidence.service_names(db, asset_id)
    )


def web_vulnerability_audit(db: Session, asset_id: str) -> Dict[str, Any]:
    """What the latest completed web scan of the asset's host found."""
    return web_evidence.web_vulnerability_audit(
        db, asset_evidence.asset_identity(db, asset_id)
    )


#: Every evidence source compliance declares, and who answers it.
PROVIDERS: Dict[str, Callable[[Session, str], Dict[str, Any]]] = {
    "vulnerability_audit": findings_evidence.vulnerability_audit,
    "malware_scan": malware_scan,
    "services_ports": findings_evidence.services_ports,
    "tls_certificates": findings_evidence.tls_certificates,
    "network_topology": topology_evidence.network_topology,
    "credential_validation": asset_evidence.credential_validation,
    "offline_configuration": asset_evidence.offline_configuration,
    "web_vulnerability_audit": web_vulnerability_audit,
}

for _source, _provider in PROVIDERS.items():
    register_evidence_provider(_source, _provider)
