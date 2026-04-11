"""
scans/models.py
---------------
Scan model — one row per scan session (spans up to 3 phases).

results column stores a JSON blob shaped like:
    {
        "phase1": { "data": [...], "summary": {...} },
        "phase2": { "data": [...], "summary": {...} },
        "phase3": { "data": [...], "summary": {...} }
    }

We reuse the same SQLite engine/Base/get_db from auth so every table
lives in a single ccure_users.db file.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean, Column, Integer, String, Float, Text,
    DateTime, ForeignKey, UniqueConstraint, inspect, text,
)
from sqlalchemy.orm import relationship

from auth.models import Base, get_db, engine  # shared DB


class Scan(Base):
    __tablename__ = "scans"

    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # What was scanned
    target        = Column(String,  nullable=False)   # comma-joined original targets
    targets_json  = Column(Text,    default="[]")     # original target array for exact reruns
    scan_type     = Column(String,  default="adaptive")

    # Progress tracking
    phase         = Column(Integer, default=1)         # highest phase completed (1/2/3)
    status        = Column(String,  default="running") # running | complete | failed

    # Cumulative results as JSON text
    results       = Column(Text,    default="{}")      # { phase1:{}, phase2:{}, phase3:{} }
    summary       = Column(Text,    default="{}")      # latest summary JSON
    report_json_path = Column(String, nullable=True)
    report_xml_path  = Column(String, nullable=True)
    failure_reason   = Column(Text, nullable=True)

    scan_duration = Column(Float,   default=0.0)       # seconds, cumulative
    is_archived   = Column(Boolean, default=False, nullable=False, index=True)
    archived_at   = Column(DateTime, nullable=True)
    is_deleted    = Column(Boolean, default=False, nullable=False, index=True)
    deleted_at    = Column(DateTime, nullable=True)

    created_at    = Column(DateTime, default=datetime.utcnow)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    phase_results = relationship(
        "ScanPhaseResult",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanPhaseResult.phase_order.asc()",
    )


class ScanPhaseResult(Base):
    __tablename__ = "scan_phase_results"
    __table_args__ = (
        UniqueConstraint("scan_id", "phase_key", name="uq_scan_phase_results_scan_phase_key"),
    )

    id          = Column(Integer, primary_key=True, index=True)
    scan_id     = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    phase_key   = Column(String, nullable=False, index=True)
    phase_order = Column(Integer, nullable=False, default=0)
    payload     = Column(Text, default="{}")
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan", back_populates="phase_results")


def ensure_scan_schema():
    """
    Backfill newer scan columns for existing databases.

    SQLAlchemy's create_all() will create missing tables, but it will not
    alter an existing scans table. We add the archive/recycle-bin columns here so
    current local databases keep working after the update.
    """
    inspector = inspect(engine)
    if "scans" not in inspector.get_table_names():
        return

    columns = {col["name"] for col in inspector.get_columns("scans")}
    with engine.begin() as conn:
        if "targets_json" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN targets_json TEXT NOT NULL DEFAULT '[]'"))
        if "report_json_path" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN report_json_path VARCHAR"))
        if "report_xml_path" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN report_xml_path VARCHAR"))
        if "failure_reason" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN failure_reason TEXT"))
        if "is_archived" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0"))
        if "archived_at" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN archived_at TIMESTAMP"))
        if "is_deleted" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0"))
        if "deleted_at" not in columns:
            conn.execute(text("ALTER TABLE scans ADD COLUMN deleted_at TIMESTAMP"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_is_archived ON scans (is_archived)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_is_deleted ON scans (is_deleted)"))
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS scan_phase_results ("
            "id INTEGER PRIMARY KEY, "
            "scan_id INTEGER NOT NULL, "
            "phase_key VARCHAR NOT NULL, "
            "phase_order INTEGER NOT NULL DEFAULT 0, "
            "payload TEXT DEFAULT '{}', "
            "created_at TIMESTAMP, "
            "updated_at TIMESTAMP, "
            "FOREIGN KEY(scan_id) REFERENCES scans (id)"
            ")"
        ))
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_phase_results_scan_phase_key "
            "ON scan_phase_results (scan_id, phase_key)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_scan_phase_results_scan_id "
            "ON scan_phase_results (scan_id)"
        ))
