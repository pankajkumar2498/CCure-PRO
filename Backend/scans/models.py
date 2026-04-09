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
    Column, Integer, String, Float, Text,
    DateTime, ForeignKey,
)

from auth.models import Base, get_db          # shared DB


class Scan(Base):
    __tablename__ = "scans"

    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # What was scanned
    target        = Column(String,  nullable=False)   # comma-joined original targets
    scan_type     = Column(String,  default="adaptive")

    # Progress tracking
    phase         = Column(Integer, default=1)         # highest phase completed (1/2/3)
    status        = Column(String,  default="running") # running | complete | failed

    # Cumulative results as JSON text
    results       = Column(Text,    default="{}")      # { phase1:{}, phase2:{}, phase3:{} }
    summary       = Column(Text,    default="{}")      # latest summary JSON

    scan_duration = Column(Float,   default=0.0)       # seconds, cumulative

    created_at    = Column(DateTime, default=datetime.utcnow)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
