"""
core/topology/evidence.py
─────────────────────────────────────────────────────────────────────────────
The network topology's compliance evidence: ``network_topology``, the links
the SNMP topology recorded for one asset.

G4 (C4 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) moved it,
unchanged, out of ``core/compliance_evidence.py``, which queried
``network_links`` itself. Audit's composition root,
``ccure_audit/evidence_providers.py``, registers it with compliance; nothing
here imports compliance.
"""

from typing import Any

from db.models.topology import NetworkLink
from sqlalchemy import or_
from sqlalchemy.orm import Session

__all__ = ["network_topology"]


def network_topology(db: Session, asset_id: str) -> dict[str, Any]:
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
