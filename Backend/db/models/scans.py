"""
db/models/scans.py
──────────────────────────────────────────────────────────────────────────────
Scan session and phase tracking.

Tables
──────
  scans       — One row per scan session (created when the user clicks "Start Scan")
  scan_phases — One row per phase within a scan (Host Discovery, Asset Discovery, etc.)

Production improvements over v1
────────────────────────────────
  - UUID primary key (prevents scan-ID enumeration)
  - org_id FK for tenant isolation
  - created_by FK (UUID) points to new production users table
  - PostgreSQL INET/CIDR for target network storage (supports subnet operators)
  - JSONB target_hosts for flexible multi-target storage
  - JSONB options for arbitrary scan parameters (no schema migration for new options)
  - Precise TIMESTAMPTZ timing: queued_at → started_at → completed_at
  - Detailed vulnerability counters (critical/high/medium/low/info) at scan level
  - ScanPhase replaces opaque "phase_key" with typed status + timing per phase
"""

from sqlalchemy import (
    BigInteger, Boolean, Column, Float, ForeignKey,
    Integer, SmallInteger, String, Text, UniqueConstraint, Index,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, gen_uuid, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Scan
# ─────────────────────────────────────────────────────────────────────────────

class Scan(Base):
    """
    One scan session — created when the user initiates any scan pipeline.

    pipeline_mode  — 'basic' | 'asset' | 'advanced'
                     Determines which phases run and which one marks it complete.

    status lifecycle
    ────────────────
      queued → running → complete
                       → failed
                       → cancelled

    target_network — CIDR type: allows SQL queries like:
       WHERE target_network >> '192.168.1.50'   (host is inside the scan range)

    target_hosts   — JSONB array for multi-target scans:
       ["192.168.1.0/24", "10.0.0.1", "172.16.5.10"]

    options JSONB examples:
       {"intensity": "deep", "rate_limit": 500, "max_concurrency": 8}

    Vulnerability counters are denormalized here for dashboard performance
    (avoids expensive COUNT(*) GROUP BY on findings table for the summary card).
    """
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_org_status",    "org_id", "status"),
        Index("ix_scans_org_created",   "org_id", "created_at"),
        Index("ix_scans_org_pipeline",  "org_id", "pipeline_mode"),
        Index("ix_scans_is_deleted",    "is_deleted"),
    )

    id              = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    org_id          = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    created_by      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                             nullable=True, index=True)

    # ── Target Definition ────────────────────────────────────────────────────
    scan_name       = Column(String(255), nullable=True)           # Optional human label
    target_network  = Column(CIDR,        nullable=True)           # "192.168.1.0/24"
    target_hosts    = Column(JSONB, nullable=False, default=list)  # ["ip1","ip2",...]
    target_str      = Column(String(512), nullable=False)          # Human-readable summary

    # ── Scan Configuration ───────────────────────────────────────────────────
    scan_type       = Column(String(50),  nullable=False, default="adaptive")
    pipeline_mode   = Column(String(50),  nullable=False, default="basic")    # basic|asset|advanced
    intensity       = Column(String(50),  nullable=True,  default="normal")   # light|normal|deep
    options         = Column(JSONB, nullable=False, default=dict)  # Arbitrary scan parameters

    # ── Status ───────────────────────────────────────────────────────────────
    status          = Column(String(50), nullable=False, default="queued", index=True)
    # queued | running | complete | failed | cancelled
    failure_reason  = Column(Text, nullable=True)

    # ── Timing ───────────────────────────────────────────────────────────────
    queued_at       = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    started_at      = Column(TIMESTAMPTZ, nullable=True)
    completed_at    = Column(TIMESTAMPTZ, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # ── Aggregate Stats (denormalized for dashboard speed) ───────────────────
    total_hosts     = Column(Integer, nullable=False, default=0)
    active_hosts    = Column(Integer, nullable=False, default=0)
    total_vulns     = Column(Integer, nullable=False, default=0)
    critical_count  = Column(Integer, nullable=False, default=0)
    high_count      = Column(Integer, nullable=False, default=0)
    medium_count    = Column(Integer, nullable=False, default=0)
    low_count       = Column(Integer, nullable=False, default=0)
    info_count      = Column(Integer, nullable=False, default=0)

    # ── Report Artifacts ─────────────────────────────────────────────────────
    report_pdf_path  = Column(String(512), nullable=True)
    report_xml_path  = Column(String(512), nullable=True)
    report_json_path = Column(String(512), nullable=True)

    # ── Soft Delete / Archive ────────────────────────────────────────────────
    is_archived     = Column(Boolean, nullable=False, default=False)
    archived_at     = Column(TIMESTAMPTZ, nullable=True)
    is_deleted      = Column(Boolean, nullable=False, default=False)
    deleted_at      = Column(TIMESTAMPTZ, nullable=True)

    created_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization    = relationship("Organization",   back_populates="scans")
    created_by_user = relationship("User",           back_populates="scans",
                                   foreign_keys=[created_by])
    phases          = relationship("ScanPhase",      back_populates="scan",
                                   cascade="all, delete-orphan",
                                   order_by="ScanPhase.phase_order.asc()")
    services        = relationship("Service",        back_populates="scan",
                                   cascade="all, delete-orphan")
    vulnerabilities = relationship("AssetVulnerability", back_populates="scan",
                                   cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.id} mode={self.pipeline_mode!r} status={self.status!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Scan Phase
# ─────────────────────────────────────────────────────────────────────────────

class ScanPhase(Base):
    """
    Tracks the execution status and timing of each individual phase within a scan.

    phase_key examples:
      'host_discovery'         — Phase 1: ICMP/ARP/TCP-SYN host detection
      'asset_discovery'        — Phase 2: Port scanning and service detection
      'vulnerability_assessment' — Phase 3: CVE matching and risk scoring
      'credentialed'           — Optional: SSH/WMI deep host inspection

    status lifecycle:  pending → running → complete | failed | skipped

    summary JSONB — phase-specific result statistics, e.g.:
      host_discovery:   {"total_scanned": 254, "active": 12, "method": "ADAPTIVE"}
      asset_discovery:  {"total_ports": 87, "open_ports": 34, "services": 28}
      vuln_assessment:  {"cves_found": 15, "critical": 2, "high": 5}

    NOTE: raw host/port/vuln data is NOT stored here.
          It lives in the normalized Service and AssetVulnerability tables.
          Only the lightweight summary dict goes into this column.
    """
    __tablename__ = "scan_phases"
    __table_args__ = (
        UniqueConstraint("scan_id", "phase_key", name="uq_scan_phases_scan_phase"),
    )

    id           = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id      = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"),
                          nullable=False, index=True)

    phase_key    = Column(String(50),      nullable=False)     # 'host_discovery' etc.
    phase_order  = Column(SmallInteger,    nullable=False)     # 1, 2, 3, 4
    status       = Column(String(50),      nullable=False, default="pending")

    started_at   = Column(TIMESTAMPTZ, nullable=True)
    completed_at = Column(TIMESTAMPTZ, nullable=True)
    duration_seconds = Column(Float,   nullable=True)

    hosts_processed = Column(Integer, nullable=False, default=0)
    summary         = Column(JSONB,   nullable=False, default=dict)

    error_message   = Column(Text, nullable=True)

    created_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    scan = relationship("Scan", back_populates="phases")

    def __repr__(self):
        return f"<ScanPhase {self.phase_key!r} status={self.status!r}>"
