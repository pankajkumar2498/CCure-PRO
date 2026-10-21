"""
db/models/topology.py
─────────────────────
NetworkLink model for storing discovered L2/L3 topology connections.

Each link represents an adjacency between two network endpoints observed via
SNMP ARP tables, LLDP, CDP, or FDB walks.

Design decisions:
  - source_key / target_key are the canonical endpoint identities produced by
    core.topology.identity. They are NOT always MAC addresses: an LLDP chassis
    ID may be a locally assigned name and a CDP device ID is a hostname, so the
    key is one of "<mac>", "ip:<addr>" or "name:<label>". source_mac/target_mac
    hold a real MAC only when one is known, and are NULL otherwise — writing a
    non-MAC into them is what made asset lookups fail against the MACADDR
    column on assets.
  - Endpoints are stored in canonical (sorted-key) order so the reciprocal
    reports of one wire — switch A naming B, and B naming A — collapse onto a
    single row instead of overwriting each other's ports half-way.
  - source_asset_id / target_asset_id are nullable FK refs to assets.
    SET NULL on asset deletion — links remain as topology history.
  - gen_network_link_id sorts endpoint keys so a link between Switch A and
    Switch B always has the same primary key regardless of which side
    reported it.
  - first_seen_at / last_seen_at let the map distinguish live adjacency from
    history. Without them an org-wide map is the union of every link ever
    recorded, including decommissioned hosts.
  - ensure_topology_schema() is a safe additive migration — runs on startup
    and only creates or extends what is missing.
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import BigInteger, Column, ForeignKey, Index, Integer, String
from sqlalchemy.orm import relationship


class NetworkLink(Base):
    """Represents a discovered network link between two endpoints."""

    __tablename__ = "network_links"

    # Deterministic ID: lnk_{org_token}_{sorted_src_key}_{sorted_dst_key}
    id = Column(String(200), primary_key=True)
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: Scan that most recently observed this link.
    scan_id = Column(
        String(100),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Source endpoint
    source_key = Column(String(200), nullable=True)  # canonical identity
    source_mac = Column(String(50), nullable=True)  # real MAC, when known
    source_port = Column(String(100), nullable=True)  # e.g., "GigabitEthernet1/0/14"
    source_ip = Column(String(50), nullable=True)
    source_asset_id = Column(
        String(200),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Target endpoint
    target_key = Column(String(200), nullable=True)  # canonical identity
    target_mac = Column(String(50), nullable=True)  # real MAC, when known
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

    #: Strongest evidence backing this link: lldp | cdp | arp | fdb.
    link_type = Column(String(50), default="physical")
    #: Every protocol that observed it, comma-separated and sorted — an LLDP
    #: adjacency that also shows up in the FDB is still an LLDP adjacency.
    observed_types = Column(String(100), nullable=True)

    first_seen_at = Column(TIMESTAMPTZ, default=utcnow)
    last_seen_at = Column(TIMESTAMPTZ, default=utcnow, index=True)
    created_at = Column(TIMESTAMPTZ, default=utcnow)

    # Relationships
    scan = relationship("Scan", backref="network_links")
    # One-sided (B8): Audit's models attach no attribute to the platform's
    # Organization.
    organization = relationship("Organization")
    source_asset = relationship(
        "Asset", foreign_keys=[source_asset_id], backref="links_as_source"
    )
    target_asset = relationship(
        "Asset", foreign_keys=[target_asset_id], backref="links_as_target"
    )

    __table_args__ = (
        Index("ix_network_links_org_id", "org_id"),
        Index("ix_network_links_scan_id", "scan_id"),
        Index("ix_network_links_org_last_seen", "org_id", "last_seen_at"),
    )


#: Columns added after the table's first release, applied in order on startup.
#: (name, DDL type, optional backfill statement)
_ADDITIVE_COLUMNS: list[tuple[str, str, str | None]] = [
    ("source_port_desc", "VARCHAR(255)", None),
    ("target_port_desc", "VARCHAR(255)", None),
    ("vlan_id", "INTEGER", None),
    ("speed_bps", "BIGINT", None),
    ("source_ip", "VARCHAR(50)", None),
    (
        "source_key",
        "VARCHAR(200)",
        "UPDATE network_links SET source_key = source_mac WHERE source_key IS NULL",
    ),
    (
        "target_key",
        "VARCHAR(200)",
        "UPDATE network_links SET target_key = target_mac WHERE target_key IS NULL",
    ),
    (
        "observed_types",
        "VARCHAR(100)",
        "UPDATE network_links SET observed_types = link_type "
        "WHERE observed_types IS NULL",
    ),
    (
        "first_seen_at",
        "TIMESTAMP WITH TIME ZONE",
        "UPDATE network_links SET first_seen_at = created_at "
        "WHERE first_seen_at IS NULL",
    ),
    (
        "last_seen_at",
        "TIMESTAMP WITH TIME ZONE",
        "UPDATE network_links SET last_seen_at = created_at WHERE last_seen_at IS NULL",
    ),
]


def ensure_topology_schema(engine=None, table: str = "network_links"):
    """
    Additive migration: create the network_links table if it doesn't exist,
    then ensure all later columns and indexes are present.

    Safe to call on every startup — no-ops for anything that already exists.

    `engine` and `table` exist so the upgrade path can be exercised against a
    throwaway table. Every deployed install reaches production through the
    `else` branch below, and the alternative — testing it by renaming the live
    table — takes an ACCESS EXCLUSIVE lock that blocks on any other open
    transaction.
    """
    from sqlalchemy import inspect, text

    if engine is None:
        from db.base import engine

    inspector = inspect(engine)
    table_exists = table in inspector.get_table_names()

    def _sql(statement: str) -> str:
        return statement.replace("network_links", table)

    with engine.begin() as conn:
        if not table_exists:
            conn.execute(
                text(
                    _sql(
                        """
                CREATE TABLE IF NOT EXISTS network_links (
                    id               VARCHAR(200) PRIMARY KEY,
                    org_id           VARCHAR(100) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    scan_id          VARCHAR(100) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    source_key       VARCHAR(200),
                    source_mac       VARCHAR(50),
                    source_port      VARCHAR(100),
                    source_port_desc VARCHAR(255),
                    source_ip        VARCHAR(50),
                    source_asset_id  VARCHAR(200) REFERENCES assets(id) ON DELETE SET NULL,
                    target_key       VARCHAR(200),
                    target_mac       VARCHAR(50),
                    target_port      VARCHAR(100),
                    target_port_desc VARCHAR(255),
                    target_ip        VARCHAR(50),
                    target_asset_id  VARCHAR(200) REFERENCES assets(id) ON DELETE SET NULL,
                    vlan_id          INTEGER,
                    speed_bps        BIGINT,
                    link_type        VARCHAR(50)  DEFAULT 'physical',
                    observed_types   VARCHAR(100),
                    first_seen_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    last_seen_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """
                    )
                )
            )
        else:
            existing_cols = {col["name"] for col in inspector.get_columns(table)}
            for col_name, col_type, backfill in _ADDITIVE_COLUMNS:
                if col_name in existing_cols:
                    continue
                conn.execute(
                    text(
                        _sql(
                            f"ALTER TABLE network_links ADD COLUMN {col_name} {col_type}"
                        )
                    )
                )
                if backfill:
                    conn.execute(text(_sql(backfill)))

            # source_mac/target_mac originally required a value, which forced
            # callers to invent placeholders for endpoints with no known MAC.
            # Identity now lives in source_key/target_key, so the MAC columns
            # carry a MAC or nothing.
            not_nullable = {
                col["name"]
                for col in inspector.get_columns(table)
                if not col.get("nullable", True)
            }
            for col in ("source_mac", "target_mac"):
                if col in not_nullable:
                    conn.execute(
                        text(
                            _sql(
                                f"ALTER TABLE network_links ALTER COLUMN {col} "
                                "DROP NOT NULL"
                            )
                        )
                    )

        # Index names are global per schema, so a probe table gets its own.
        prefix = "ix_network_links" if table == "network_links" else f"ix_{table}"
        for name, columns in (
            ("org_id", "org_id"),
            ("scan_id", "scan_id"),
            ("org_last_seen", "org_id, last_seen_at"),
        ):
            conn.execute(
                text(
                    f"CREATE INDEX IF NOT EXISTS {prefix}_{name} "
                    f"ON {table}({columns})"
                )
            )
