"""
db/models/assets.py
──────────────────────────────────────────────────────────────────────────────
Asset Registry — the cornerstone of a production vulnerability management system.

Tables
──────
  assets          — One persistent row per discovered host (the "Asset Register")
  asset_tags      — Searchable string labels attached to assets
  asset_notes     — Free-text analyst notes attached to specific assets
  asset_change_log— Immutable changelog tracking what changed between scans
                    (enables Differential Scanning — "show me what's new since Monday")

Design philosophy
─────────────────
  In Nessus / Qualys, an "Asset" is a FIRST-CLASS entity with a persistent identity.
  When a scan discovers a host at 192.168.1.10, it either:
    a) Creates a new Asset record (first-ever detection)
    b) Updates last_seen + risk scores on the EXISTING Asset record

  This means you can ask questions like:
    "Show me all assets that had SSH open last week but not this week"
    "Which assets appeared on the network in the last 24 hours?"
    "How many assets still have CVE-2024-4577 unpatched?"

  — None of these are possible with the JSON-blob approach.

PostgreSQL-native types used
────────────────────────────
  INET    — Stores an IP address with built-in subnet operators (>> = "is in subnet")
  MACADDR — Stores a MAC address in canonical form (aa:bb:cc:dd:ee:ff)
  CIDR    — Stores a network range (192.168.1.0/24)
"""

from sqlalchemy import (
    BigInteger, Boolean, Column, ForeignKey, Integer,
    SmallInteger, String, Text, UniqueConstraint, Index,
)
from sqlalchemy.dialects.postgresql import (
    INET, JSONB, MACADDR, UUID,
)
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, gen_uuid, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Asset  (the persistent host identity record)
# ─────────────────────────────────────────────────────────────────────────────

class Asset(Base):
    """
    Represents one unique physical or virtual device on the network.

    Identity resolution priority (how we decide if a discovered host is "the same" asset):
      1. MAC address  — most stable identifier (survives IP changes from DHCP)
      2. IP address   — fallback if MAC is not available (e.g., routed subnets)
      3. FQDN/hostname — last resort

    Risk fields
    ────────────
      risk_score  — 0-100.  Calculated by the risk engine as:
                    Σ(severity_weight × n_vulns) capped at 100
      risk_level  — Derived bucket: critical (80+) | high (60-79) | medium (40-59)
                    | low (20-39) | info (<20)

    is_managed   — True = admin explicitly registered this asset (known device)
                   False = discovered by scanner unexpectedly (potential rogue device)

    custom_attributes JSONB examples:
      {"owner": "Network Team", "location": "Server Room B", "criticality": "high"}
    """
    __tablename__ = "assets"
    __table_args__ = (
        # Partial unique index: MAC uniqueness within an org (only when MAC is not NULL)
        # Uses Index with unique=True + postgresql_where for partial uniqueness.
        Index("uq_assets_org_mac",  "org_id", "mac_address", unique=True,
              postgresql_where="mac_address IS NOT NULL"),
        Index("ix_assets_org_ip",  "org_id", "ip_address"),
        Index("ix_assets_org_risk", "org_id", "risk_score"),
        Index("ix_assets_last_seen", "last_seen_at"),
        Index("ix_assets_category", "device_category"),
    )

    id          = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    org_id      = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    # ── Network Identity ──────────────────────────────────────────────────────
    ip_address  = Column(INET,    nullable=False)
    mac_address = Column(MACADDR, nullable=True)   # NULL if MAC not discoverable (routed L3)
    hostname    = Column(String(255), nullable=True)
    dns_name    = Column(String(512), nullable=True)
    fqdn        = Column(String(512), nullable=True)
    netbios_name= Column(String(255), nullable=True)
    discovery_method = Column(String(50), nullable=True)
    response_time_ms = Column(Integer, nullable=True)

    # ── Classification ────────────────────────────────────────────────────────
    # device_category: server | workstation | router | switch | firewall |
    #                  printer | phone | iot | unknown
    device_category = Column(String(100), nullable=True, index=True)
    os_family       = Column(String(100), nullable=True)   # Windows | Linux | macOS | FreeBSD
    os_name         = Column(String(255), nullable=True)   # "Windows Server 2022"
    os_version      = Column(String(100), nullable=True)   # "10.0.20348"
    os_confidence   = Column(SmallInteger, nullable=True)  # 0-100%

    # ── Vendor / Hardware ─────────────────────────────────────────────────────
    vendor          = Column(String(255), nullable=True)   # OUI vendor lookup
    manufacturer    = Column(String(255), nullable=True)   # From SNMP / banner

    # ── Network Context ───────────────────────────────────────────────────────
    subnet          = Column(String(50),  nullable=True)   # "192.168.1.0/24"
    vlan_id         = Column(Integer,     nullable=True)

    # ── Lifecycle Tracking ────────────────────────────────────────────────────
    first_seen_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    last_seen_at   = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)
    last_scan_id   = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"),
                            nullable=True)

    # ── Risk ─────────────────────────────────────────────────────────────────
    risk_score  = Column(SmallInteger, nullable=False, default=0)   # 0-100
    risk_level  = Column(String(20),   nullable=False, default="info") # critical|high|medium|low|info
    vuln_counts = Column(JSONB, nullable=False, default=dict)  # {"critical":2,"high":5,...}

    # ── Management ────────────────────────────────────────────────────────────
    is_active        = Column(Boolean, nullable=False, default=True)
    is_managed       = Column(Boolean, nullable=False, default=False)  # Known/registered asset
    owner            = Column(String(255), nullable=True)
    notes_summary    = Column(Text, nullable=True)
    custom_attributes = Column(JSONB, nullable=False, default=dict)

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization         = relationship("Organization", back_populates="assets")
    last_scan            = relationship("Scan", foreign_keys=[last_scan_id])
    tags                 = relationship("AssetTag",          back_populates="asset",
                                        cascade="all, delete-orphan")
    notes                = relationship("AssetNote",         back_populates="asset",
                                        cascade="all, delete-orphan")
    change_log           = relationship("AssetChangeLog",    back_populates="asset",
                                        order_by="AssetChangeLog.detected_at.desc()",
                                        cascade="all, delete-orphan")
    services             = relationship("Service",           back_populates="asset",
                                        cascade="all, delete-orphan")
    vulnerabilities      = relationship("AssetVulnerability", back_populates="asset",
                                        cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Asset {self.ip_address} mac={self.mac_address} risk={self.risk_level}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Tags
# ─────────────────────────────────────────────────────────────────────────────

class AssetTag(Base):
    """
    String labels applied to assets for grouping and filtering.

    Examples: "dmz", "critical-server", "pci-scope", "dev-env", "decommission-q3"

    Used in the UI via tag-based scan targeting:
      "Scan all assets tagged 'pci-scope'"
    """
    __tablename__ = "asset_tags"
    __table_args__ = (
        UniqueConstraint("asset_id", "tag", name="uq_asset_tags_asset_tag"),
    )

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id        = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    tag             = Column(String(100), nullable=False, index=True)
    created_by_id   = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                             nullable=True)
    created_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    asset           = relationship("Asset", back_populates="tags")
    created_by_user = relationship("User",  back_populates="asset_tags")

    def __repr__(self):
        return f"<AssetTag asset={self.asset_id} tag={self.tag!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Notes
# ─────────────────────────────────────────────────────────────────────────────

class AssetNote(Base):
    """
    Analyst-written notes attached to a specific asset.

    Content examples:
      "Confirmed with Network Team — this is the legacy ERP server, decom Q2 2025"
      "Risk accepted — CVE-2024-4577 mitigated by WAF rule #449"
    """
    __tablename__ = "asset_notes"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id    = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                         nullable=True)
    content     = Column(Text, nullable=False)
    created_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    asset = relationship("Asset", back_populates="notes")
    user  = relationship("User",  back_populates="asset_notes")

    def __repr__(self):
        return f"<AssetNote asset={self.asset_id} len={len(self.content or '')}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Change Log  (Differential Scanning engine)
# ─────────────────────────────────────────────────────────────────────────────

class AssetChangeLog(Base):
    """
    Immutable record of every detected change on an asset between scans.

    Powers the "What's New / Changed" differential view — a core feature of
    enterprise scanners like Nessus, Qualys, and Rapid7.

    change_type examples
    ────────────────────
      new_asset        — Host discovered for the first time
      asset_inactive   — Previously active host no longer responding
      ip_changed       — MAC stayed the same but IP changed (DHCP churn)
      port_opened      — A new port appeared (potential new service or attack surface)
      port_closed      — An open port is now closed (service decommissioned?)
      vuln_appeared    — A new CVE was detected on this host
      vuln_fixed       — A previously detected CVE is no longer present
      os_changed       — OS fingerprint changed (OS upgrade or abnormal?)
      service_changed  — Service banner / version changed on an existing port

    old_value / new_value
    ─────────────────────
      Stored as JSONB so any structured diff can be recorded.
      E.g. port_opened: {"port": 8443, "service": "HTTPS", "version": "Apache/2.4.55"}
    """
    __tablename__ = "asset_change_log"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id    = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    scan_id     = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"),
                         nullable=True, index=True)

    change_type = Column(String(50),  nullable=False, index=True)
    field_name  = Column(String(100), nullable=True)
    old_value   = Column(JSONB, nullable=True)
    new_value   = Column(JSONB, nullable=True)

    detected_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)

    asset = relationship("Asset", back_populates="change_log")

    def __repr__(self):
        return f"<AssetChangeLog {self.change_type!r} asset={self.asset_id}>"
