"""
db/models/scan_reports.py
─────────────────────────────────────────────────────────────────────────────
ORM model for tracking generated report artifacts, cache files, formats,
severity filters, and execution metadata.
"""

import uuid
from datetime import datetime, timezone

from db.base import Base
from sqlalchemy import Column, DateTime, String


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    scan_type = Column(
        String(32), nullable=False, default="network"
    )  # "network" or "web"
    report_type = Column(
        String(32), nullable=False, default="executive"
    )  # "executive", "technical", "raw"
    report_format = Column(
        String(16), nullable=False, default="pdf"
    )  # "pdf", "csv", "json", "xml"
    min_severity = Column(
        String(16), nullable=False, default="Info"
    )  # "Critical", "High", "Medium", "Low", "Info"
    file_path = Column(String(512), nullable=False)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return f"<ScanReport(id='{self.id}', scan_id='{self.scan_id}', type='{self.report_type}', fmt='{self.report_format}')>"
