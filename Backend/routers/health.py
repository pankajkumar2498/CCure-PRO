"""
routers/health.py
─────────────────────────────────────────────────────────────────────────────
The service root.

  GET /   → system health + info

Ownership: the body is the scanner runtime's own report
(``get_api().get_system_info()``: scapy, privileges, scan types), so the route
is Audit's today. There is no platform-owned health root yet; adding one would
change what ``/`` answers, which is a decision of its own. Scan progress and the
pipeline documentation routes that used to share this file are Audit's and live
in ``routers/scan_progress.py``.
"""

from fastapi import APIRouter
from scan_helpers import get_api

router = APIRouter()


# ── Health ────────────────────────────────────────────────────────────────────


@router.get("/", tags=["Health"])
async def root():
    return get_api().get_system_info()
