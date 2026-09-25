"""
Proxy to the central database models to avoid module import errors during transition.

``ensure_scan_schema`` moved to ``db/models/scans.py`` (Phase 3) and is
re-exported here unchanged.
"""

from db.models import ScanPhase
from db.models.scans import ensure_scan_schema  # noqa: F401  (re-export)

# Map old ScanPhaseResult to the new ScanPhase just to satisfy imports
ScanPhaseResult = ScanPhase
