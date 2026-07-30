"""
db/models/scans.py
──────────────────────────────────────────────────────────────────────────────
Scan session and phase tracking.

Tables
──────
  scans       — One row per scan session (created when the user clicks "Start Scan")
  scan_phases — One row per phase within a scan

ID Convention (Stripe-Style)
─────────────────────────────
  Scan       →  scn_{org_3chars}_{ddmonyy}_{4rand}
                e.g.  scn_def_07may25_x9v1

  ScanPhase  →  sph_{scan_id}_{phase_key}
                e.g.  sph_scn_def_07may25_x9v1_host_discovery

  ON UPDATE CASCADE on org_id and created_by so renaming either propagates.
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import CIDR, JSONB
from sqlalchemy.orm import relationship

# ─────────────────────────────────────────────────────────────────────────────
# Scan
# ─────────────────────────────────────────────────────────────────────────────


class Scan(Base):
    """
    One scan session — created when the user initiates any scan pipeline.

    ID: scn_{org_3chars}_{ddmonyy}_{4rand}
        e.g. scn_def_07may25_x9v1
        Reading this tells you: Scan for 'default' org, on 7-May-25.

    status lifecycle:  queued → running → complete | failed | cancelled
    """

    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint("org_id", "scan_no", name="uq_scans_org_scan_no"),
        Index("ix_scans_org_status", "org_id", "status"),
        Index("ix_scans_org_created", "org_id", "created_at"),
        Index("ix_scans_org_pipeline", "org_id", "pipeline_mode"),
        Index("ix_scans_is_deleted", "is_deleted"),
        Index("idx_scans_options_gin", "options", postgresql_using="gin"),
    )

    # Stripe-style readable ID: "scn_def_07may25_x9v1"
    id = Column(String(100), primary_key=True)

    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by = Column(
        String(150),
        ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
        index=True,
    )
    scan_no = Column(BigInteger, nullable=True)

    # ── Target Definition ─────────────────────────────────────────────────────
    scan_name = Column(String(255), nullable=True)
    target_network = Column(CIDR, nullable=True)
    target_hosts = Column(JSONB, nullable=False, default=list)
    target_str = Column(String(512), nullable=False)

    # ── Scan Configuration ────────────────────────────────────────────────────
    scan_type = Column(String(50), nullable=False, default="adaptive")
    pipeline_mode = Column(String(50), nullable=False, default="basic")
    intensity = Column(String(50), nullable=True, default="normal")
    options = Column(JSONB, nullable=False, default=dict)

    # ── Status ────────────────────────────────────────────────────────────────
    status = Column(String(50), nullable=False, default="queued", index=True)
    failure_reason = Column(Text, nullable=True)
    current_task_id = Column(String(100), nullable=True)  # Track active Celery task

    # ── Timing ────────────────────────────────────────────────────────────────
    queued_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    started_at = Column(TIMESTAMPTZ, nullable=True)
    completed_at = Column(TIMESTAMPTZ, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # ── Aggregate Stats (denormalized for dashboard speed) ────────────────────
    total_hosts = Column(Integer, nullable=False, default=0)
    active_hosts = Column(Integer, nullable=False, default=0)
    total_vulns = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)

    # ── Report Artifacts ──────────────────────────────────────────────────────
    # Named for the audience, not the payload format the report was built from.
    report_pdf_path = Column(String(512), nullable=True)
    report_technical_path = Column(String(512), nullable=True)
    report_executive_path = Column(String(512), nullable=True)

    # ── Soft Delete / Archive ─────────────────────────────────────────────────
    is_archived = Column(Boolean, nullable=False, default=False)
    archived_at = Column(TIMESTAMPTZ, nullable=True)
    is_deleted = Column(Boolean, nullable=False, default=False)
    deleted_at = Column(TIMESTAMPTZ, nullable=True)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    def __init__(self, **kwargs):
        if "id" not in kwargs:
            from db.base import gen_scan_id

            org_id = kwargs.get("org_id", "org_default")
            org_slug = org_id.replace("org_", "") if org_id else "default"
            kwargs["id"] = gen_scan_id(org_slug)
        super().__init__(**kwargs)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization = relationship("Organization", back_populates="scans")
    created_by_user = relationship(
        "User", back_populates="scans", foreign_keys=[created_by]
    )
    phases = relationship(
        "ScanPhase",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanPhase.phase_order.asc()",
    )
    services = relationship(
        "Service", back_populates="scan", cascade="all, delete-orphan"
    )
    vulnerabilities = relationship(
        "AssetVulnerability", back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Scan {self.id!r} mode={self.pipeline_mode!r} status={self.status!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Scan Phase
# ─────────────────────────────────────────────────────────────────────────────


class ScanPhase(Base):
    """
    Tracks the execution status and timing of each phase within a scan.

    ID: sph_{scan_id}_{phase_key}
        e.g. sph_scn_def_07may25_x9v1_host_discovery
        Reading this: Phase 'host_discovery' of scan scn_def_07may25_x9v1.

    status lifecycle:  pending → running → complete | failed | skipped
    """

    __tablename__ = "scan_phases"
    __table_args__ = (
        UniqueConstraint("scan_id", "phase_key", name="uq_scan_phases_scan_phase"),
    )

    # Stripe-style readable ID: "sph_scn_def_07may25_x9v1_host_discovery"
    id = Column(String(200), primary_key=True)
    scan_id = Column(
        String(100),
        ForeignKey("scans.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )

    phase_key = Column(String(50), nullable=False)
    phase_order = Column(SmallInteger, nullable=False)
    status = Column(String(50), nullable=False, default="pending")

    started_at = Column(TIMESTAMPTZ, nullable=True)
    completed_at = Column(TIMESTAMPTZ, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    hosts_processed = Column(Integer, nullable=False, default=0)
    summary = Column(JSONB, nullable=False, default=dict)
    error_message = Column(Text, nullable=True)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    scan = relationship("Scan", back_populates="phases")

    def __repr__(self):
        return f"<ScanPhase {self.id!r} status={self.status!r}>"
