"""
core/asset_hosts.py
─────────────────────────────────────────────────────────────────────────────
The asset registry's answer to the findings side's host port,
``core.findings.hosts`` (G6, C7 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

* :meth:`AssetHosts.projection` — every asset as a host, a subquery of the
  columns the findings side reads (``HOST_COLUMNS``), for it to join findings
  to;
* :meth:`AssetHosts.record_open_findings` — the asset's open-finding counts and
  the risk derived from them, written after a person changes a finding's
  status. Moved unchanged from ``routers/findings.py``, which wrote the asset
  row itself.

Audit's composition root, ``ccure_audit/host_directory.py``, registers
:data:`DIRECTORY` with the findings side. This module imports nothing of the
findings capability but the port's column list.
"""

from __future__ import annotations

from typing import Mapping

from core.findings.hosts import HOST_COLUMNS
from db.models.assets import Asset
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.sql.selectable import Subquery

__all__ = ["AssetHosts", "DIRECTORY"]


class AssetHosts:
    """The asset table, as the hosts findings are on."""

    def projection(self) -> Subquery:
        return select(*(getattr(Asset, name) for name in HOST_COLUMNS)).subquery(
            "hosts"
        )

    def record_open_findings(
        self, db: Session, asset_id: str, severity_counts: Mapping[str, int]
    ) -> bool:
        sev_map = severity_counts
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return False
        asset.vuln_counts = {
            "critical": sev_map.get("critical", 0),
            "high": sev_map.get("high", 0),
            "medium": sev_map.get("medium", 0),
            "low": sev_map.get("low", 0),
        }

        # Recompute a simple aggregate risk score from counts (same logic as credentialed sync)
        computed = min(
            100,
            (asset.vuln_counts.get("critical", 0) * 25)
            + (asset.vuln_counts.get("high", 0) * 15)
            + (asset.vuln_counts.get("medium", 0) * 8)
            + (asset.vuln_counts.get("low", 0) * 3),
        )
        # Assigned unconditionally. Guarding this with `computed >=
        # risk_score` meant risk could only ever ratchet upwards: an asset
        # whose findings were all fixed or accepted kept its old score and
        # stayed "Critical" on the dashboard while its own vuln_counts read
        # zero — the two numbers came from the same rows and disagreed.
        asset.risk_score = int(computed)
        if computed >= 90:
            asset.risk_level = "Critical"
        elif computed >= 70:
            asset.risk_level = "High"
        elif computed >= 40:
            asset.risk_level = "Medium"
        elif computed > 0:
            asset.risk_level = "Low"
        else:
            asset.risk_level = "Info"
        return True


#: The one instance the composition root registers.
DIRECTORY = AssetHosts()
