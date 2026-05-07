"""
db/models/assets.py
──────────────────────────────────────────────────────────────────────────────
Asset Registry — the cornerstone of a production vulnerability management system.

Tables
──────
  assets          — One persistent row per discovered host
  asset_tags      — Searchable string labels attached to assets
  asset_notes     — Free-text analyst notes attached to specific assets
  asset_change_log— Immutable changelog tracking what changed between scans

ID Convention (Stripe-Style)
─────────────────────────────
  Asset  →  ast_{org_3chars}_{ip_address}
            e.g.  ast_def_192.168.1.5
            Deterministic: the same host always gets the same ID in the same org.
            Reading it: "Asset discovered at 192.168.1.5 in the default org."

  AssetTag / AssetNote / AssetChangeLog → BigInteger (high-volume, no need for readable IDs)
"""

from sqlalchemy import (
    BigInteger, Boolean, Column, ForeignKey, Integer,
    SmallInteger, String, Text, UniqueConstraint, Index, CheckConstraint,
)
from sqlalchemy.dialects.postgresql import (
    INET, JSONB, MACADDR,
)
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Asset  (the persistent host identity record)
# ─────────────────────────────────────────────────────────────────────────────

class Asset(Base):
    """
    Represents one unique physical or virtual device on the network.

    ID: ast_{org_3chars}_{ip_address}
        e.g. ast_def_192.168.1.5
        Deterministic — same host = same ID = easy to trace in logs.

    ON UPDATE CASCADE on org_id: if org is renamed, all asset IDs update.
    """
    __tablename__ = "assets"
    __table_args__ = (
        # Partial unique index: IP uniqueness within an org
        Index("uq_assets_org_ip",   "org_id", "ip_address", unique=True),
        Index("ix_assets_org_mac",  "org_id", "mac_address"),
        Index("ix_assets_org_risk", "org_id", "risk_score"),
        Index("ix_assets_last_seen", "last_seen_at"),
        Index("ix_assets_category",  "device_category"),

        # ── Enterprise Enhancements ──────────────────────────────────────────
        # GIN index for deep JSONB searching (vuln counts)
        Index("idx_assets_vuln_counts_gin", "vuln_counts", postgresql_using="gin"),
        # Trigram index for fast partial hostname search (LIKE '%term%')
        Index("idx_assets_hostname_trgm", "hostname", postgresql_using="gin",
              postgresql_ops={"hostname": "gin_trgm_ops"}),
        # Integrity constraint for risk scores
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_assets_risk_score"),
    )

    # Stripe-style readable ID: "ast_def_192.168.1.5"
    id      = Column(String(200), primary_key=True)
    org_id  = Column(String(100), ForeignKey("organizations.id",
                     ondelete="CASCADE", onupdate="CASCADE"),
                     nullable=False, index=True)

    # ── Network Identity ──────────────────────────────────────────────────────
    ip_address       = Column(INET,       nullable=False)
    mac_address      = Column(MACADDR,    nullable=True)
    hostname         = Column(String(255), nullable=True)
    dns_name         = Column(String(512), nullable=True)
    fqdn             = Column(String(512), nullable=True)
    netbios_name     = Column(String(255), nullable=True)
    discovery_method = Column(String(50),  nullable=True)
    response_time_ms = Column(Integer,     nullable=True)

    # ── Classification ────────────────────────────────────────────────────────
    device_category = Column(String(100), nullable=True, index=True)
    os_family       = Column(String(100), nullable=True)
    os_name         = Column(String(255), nullable=True)
    os_version      = Column(String(100), nullable=True)
    os_confidence   = Column(SmallInteger, nullable=True)

    # ── Vendor / Hardware ─────────────────────────────────────────────────────
    vendor          = Column(String(255), nullable=True)
    manufacturer    = Column(String(255), nullable=True)

    # ── Network Context ───────────────────────────────────────────────────────
    subnet  = Column(String(50), nullable=True)
    vlan_id = Column(Integer,    nullable=True)

    # ── Lifecycle Tracking ────────────────────────────────────────────────────
    first_seen_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    last_seen_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)
    last_scan_id  = Column(String(100), ForeignKey("scans.id",
                            ondelete="SET NULL", onupdate="CASCADE"),
                            nullable=True)

    # ── Risk ──────────────────────────────────────────────────────────────────
    risk_score  = Column(SmallInteger, nullable=False, default=0)
    risk_level  = Column(String(20),   nullable=False, default="info")
    vuln_counts = Column(JSONB, nullable=False, default=dict)

    # ── Management ────────────────────────────────────────────────────────────
    is_active         = Column(Boolean, nullable=False, default=True)
    is_managed        = Column(Boolean, nullable=False, default=False)
    owner             = Column(String(255), nullable=True)
    notes_summary     = Column(Text, nullable=True)
    custom_attributes = Column(JSONB, nullable=False, default=dict)

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization    = relationship("Organization",    back_populates="assets")
    last_scan       = relationship("Scan",            foreign_keys=[last_scan_id])
    tags            = relationship("AssetTag",        back_populates="asset",
                                   cascade="all, delete-orphan")
    notes           = relationship("AssetNote",       back_populates="asset",
                                   cascade="all, delete-orphan")
    change_log      = relationship("AssetChangeLog",  back_populates="asset",
                                   order_by="AssetChangeLog.detected_at.desc()",
                                   cascade="all, delete-orphan")
    services        = relationship("Service",         back_populates="asset",
                                   cascade="all, delete-orphan")
    vulnerabilities = relationship("AssetVulnerability", back_populates="asset",
                                   cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Asset {self.id!r} risk={self.risk_level!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Tags
# ─────────────────────────────────────────────────────────────────────────────

class AssetTag(Base):
    """String labels applied to assets for grouping and filtering."""
    __tablename__ = "asset_tags"
    __table_args__ = (
        UniqueConstraint("asset_id", "tag", name="uq_asset_tags_asset_tag"),
    )

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id      = Column(String(200), ForeignKey("assets.id",
                            ondelete="CASCADE", onupdate="CASCADE"),
                            nullable=False, index=True)
    tag           = Column(String(100), nullable=False, index=True)
    created_by_id = Column(String(150), ForeignKey("users.id",
                            ondelete="SET NULL", onupdate="CASCADE"),
                            nullable=True)
    created_at    = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    asset           = relationship("Asset", back_populates="tags")
    created_by_user = relationship("User",  back_populates="asset_tags")

    def __repr__(self):
        return f"<AssetTag asset={self.asset_id!r} tag={self.tag!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Notes
# ─────────────────────────────────────────────────────────────────────────────

class AssetNote(Base):
    """Analyst-written notes attached to a specific asset."""
    __tablename__ = "asset_notes"

    id       = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(String(200), ForeignKey("assets.id",
                      ondelete="CASCADE", onupdate="CASCADE"),
                      nullable=False, index=True)
    user_id  = Column(String(150), ForeignKey("users.id",
                      ondelete="SET NULL", onupdate="CASCADE"),
                      nullable=True)
    content    = Column(Text, nullable=False)
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    asset = relationship("Asset", back_populates="notes")
    user  = relationship("User",  back_populates="asset_notes")

    def __repr__(self):
        return f"<AssetNote asset={self.asset_id!r} len={len(self.content or '')}>"


# ─────────────────────────────────────────────────────────────────────────────
# Asset Change Log  (Differential Scanning engine)
# ─────────────────────────────────────────────────────────────────────────────

class AssetChangeLog(Base):
    """
    Immutable record of every detected change on an asset between scans.
    Powers the "What's New / Changed" differential view.
    """
    __tablename__ = "asset_change_log"

    id       = Column(BigInteger, primary_key=True, autoincrement=True)
    asset_id = Column(String(200), ForeignKey("assets.id",
                      ondelete="CASCADE", onupdate="CASCADE"),
                      nullable=False, index=True)
    scan_id  = Column(String(100), ForeignKey("scans.id",
                      ondelete="SET NULL", onupdate="CASCADE"),
                      nullable=True, index=True)

    change_type = Column(String(50),  nullable=False, index=True)
    field_name  = Column(String(100), nullable=True)
    old_value   = Column(JSONB, nullable=True)
    new_value   = Column(JSONB, nullable=True)

    detected_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)

    asset = relationship("Asset", back_populates="change_log")

    def __repr__(self):
        return f"<AssetChangeLog {self.change_type!r} asset={self.asset_id!r}>"
