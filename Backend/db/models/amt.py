"""
Module: db/models/amt
Purpose: AMT Inventory reference records for optional reconciliation.
Author:  Pair Engineer
"""

from sqlalchemy import (
    BigInteger, Column, ForeignKey, Integer, String, Index,
)
from sqlalchemy.dialects.postgresql import MACADDR
from db.base import Base, TIMESTAMPTZ, utcnow


class AMTInventoryRecord(Base):
    """
    Stores imported inventory records from AMT (assets.json).
    Used as an offline reference table to calculate coverage gaps and enrich scanned assets.
    """
    __tablename__ = "amt_inventory_records"
    __table_args__ = (
        Index("ix_amt_org_mac1", "org_id", "mac_address_1", unique=True),
        Index("ix_amt_org_mac2", "org_id", "mac_address_2"),
    )

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    org_id        = Column(String(100), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    mac_address_1 = Column(MACADDR, nullable=False)
    mac_address_2 = Column(MACADDR, nullable=True)

    asset_tag     = Column(String(100), nullable=True)
    asset_name    = Column(String(255), nullable=True)
    serial        = Column(String(255), nullable=True)
    vendor        = Column(String(255), nullable=True)
    asset_type    = Column(String(255), nullable=True)
    asset_user    = Column(String(255), nullable=True)
    emp_id        = Column(String(100), nullable=True)
    status        = Column(String(100), nullable=True)
    location      = Column(String(255), nullable=True)
    location_id   = Column(Integer, nullable=True)
    company_name  = Column(String(255), nullable=True)

    created_at    = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at    = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)
