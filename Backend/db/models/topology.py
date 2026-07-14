"""
db/models/topology.py
─────────────────────
NetworkLink model for storing discovered L2/L3 topology connections.

Each link represents a physical or logical wire between two network endpoints
discovered via SNMP ARP tables, LLDP, CDP, or FDB walks.

Design decisions:
  - source_asset_id / target_asset_id are nullable FK refs to assets.
    SET NULL on asset deletion — links remain as topology history.
  - gen_network_link_id sorts MACs alphabetically so a link between
    Switch A and Switch B always has the same primary key regardless
    of which side reports the discovery.
  - ensure_topology_schema() is a safe additive migration — runs on startup
    and only creates the table if it doesn't exist.
"""

from sqlalchemy import BigInteger, Column, Integer, String, ForeignKey, Index
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, utcnow


class NetworkLink(Base):
    """Represents a discovered network link between two endpoints."""

    __tablename__ = "network_links"

    # Deterministic ID: lnk_{org_token}_{sorted_src_mac}_{sorted_dst_mac}
    id = Column(String(200), primary_key=True)
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id = Column(
        String(100),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Source endpoint
    source_mac = Column(String(50), nullable=False)
    source_port = Column(String(100), nullable=True)  # e.g., "GigabitEthernet1/0/14"
    source_asset_id = Column(
        String(200),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Target endpoint
    target_mac = Column(String(50), nullable=False)
    target_port = Column(String(100), nullable=True)
    target_ip = Column(String(50), nullable=True)
    target_asset_id = Column(
        String(200),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Enriched port details (populated from SNMP interface walks)
    source_port_desc = Column(
        String(255), nullable=True
    )  # e.g., "GigabitEthernet1/0/24 (Uplink to Core)"
    target_port_desc = Column(String(255), nullable=True)
    vlan_id = Column(Integer, nullable=True)  # Access VLAN for the port
    speed_bps = Column(BigInteger, nullable=True)  # Port speed in bits per second

    link_type = Column(String(50), default="physical")  # physical | logical | arp
    created_at = Column(TIMESTAMPTZ, default=utcnow)

    # Relationships
    scan = relationship("Scan", backref="network_links")
    organization = relationship("Organization", backref="network_links")
    source_asset = relationship(
        "Asset", foreign_keys=[source_asset_id], backref="links_as_source"
    )
    target_asset = relationship(
        "Asset", foreign_keys=[target_asset_id], backref="links_as_target"
    )

    __table_args__ = (
        Index("ix_network_links_org_id", "org_id"),
        Index("ix_network_links_scan_id", "scan_id"),
    )


def ensure_topology_schema():
    """
    Additive migration: create the network_links table if it doesn't exist,
    then ensure all enriched SNMP columns are present.

    Safe to call on every startup — no-ops for columns/tables that already exist.
    """
    from db.base import engine
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    table_exists = "network_links" in inspector.get_table_names()

    with engine.begin() as conn:
        if not table_exists:
            conn.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS network_links (
                    id               VARCHAR(200) PRIMARY KEY,
                    org_id           VARCHAR(100) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    scan_id          VARCHAR(100) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    source_mac       VARCHAR(50)  NOT NULL,
                    source_port      VARCHAR(100),
                    source_port_desc VARCHAR(255),
                    source_asset_id  VARCHAR(200) REFERENCES assets(id) ON DELETE SET NULL,
                    target_mac       VARCHAR(50)  NOT NULL,
                    target_port      VARCHAR(100),
                    target_port_desc VARCHAR(255),
                    target_ip        VARCHAR(50),
                    target_asset_id  VARCHAR(200) REFERENCES assets(id) ON DELETE SET NULL,
                    vlan_id          INTEGER,
                    speed_bps        BIGINT,
                    link_type        VARCHAR(50)  DEFAULT 'physical',
                    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_network_links_org_id ON network_links(org_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_network_links_scan_id ON network_links(scan_id)"
                )
            )
        else:
            # Incremental migration: add enriched SNMP columns if missing
            existing_cols = {
                col["name"] for col in inspector.get_columns("network_links")
            }
            new_columns = {
                "source_port_desc": "VARCHAR(255)",
                "target_port_desc": "VARCHAR(255)",
                "vlan_id": "INTEGER",
                "speed_bps": "BIGINT",
            }
            for col_name, col_type in new_columns.items():
                if col_name not in existing_cols:
                    conn.execute(
                        text(
                            f"ALTER TABLE network_links ADD COLUMN {col_name} {col_type}"
                        )
                    )
