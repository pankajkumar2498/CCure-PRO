"""
Proxy to the central database models to avoid module import errors during transition.
"""

from db.models import Scan, ScanPhase
from db.base import Base, engine, get_db

def ensure_scan_schema():
    pass

# Map old ScanPhaseResult to the new ScanPhase just to satisfy imports
ScanPhaseResult = ScanPhase
