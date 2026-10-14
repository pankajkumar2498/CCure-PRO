"""
Whether the advisory that matched a finding says a fix has been released.

Decided once, from the finding the matcher produced, and stored on
``asset_vulnerabilities.fix_state``. Both writers of credentialed findings —
the pipeline's ``scans.asset_syncer`` and the standalone audit's
``core.tasks`` — call :func:`fix_state_for`, so the two cannot classify the
same record differently.

``no_fix_released`` is only ever a distribution's own statement. An OSV range
with no ``fixed`` event is how Ubuntu says "affected, no fix released" — but
``sync_osv`` also stores a ``last_affected`` range as an open window, because
``osv_ranges`` has no column for an inclusive bound. In a feed that uses
``last_affected`` an open range is therefore not that claim. An ecosystem joins
:data:`OPEN_RANGE_MEANS_NO_FIX` only once its feed has been measured to use no
``last_affected`` at all.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from db.models.findings import FIX_STATE_NOT_RELEASED, FIX_STATE_RELEASED

#: OSV ecosystem families in which an open range means "affected, no fix
#: released". Measured 14 Oct 2026 over the staged ``Ubuntu.zip`` (every
#: ``Ubuntu:*`` ecosystem, Ubuntu Pro included): 725,048 ranges end in
#: ``fixed``, 2,483,906 are open, none ends in ``last_affected``.
OPEN_RANGE_MEANS_NO_FIX = frozenset({"Ubuntu"})

_EMPTY_VERSIONS = {"", "none", "n/a", "unknown", "-"}


def _fixed_version(finding: Mapping[str, Any]) -> str:
    for key in ("fixed_ver", "fixed_version", "fixed_in"):
        value = str(finding.get(key) or "").strip()
        if value.lower() not in _EMPTY_VERSIONS:
            return value
    return ""


def fix_state_for(finding: Mapping[str, Any]) -> Optional[str]:
    """``fix_released``, ``no_fix_released`` or None (not established)."""
    if _fixed_version(finding):
        return FIX_STATE_RELEASED
    if str(finding.get("source") or "") != "osv_match":
        return None
    matched_by = str(finding.get("matched_by") or "")
    if not matched_by.startswith("osv:"):
        return None
    family = matched_by[len("osv:") :].split(":", 1)[0]
    if family in OPEN_RANGE_MEANS_NO_FIX:
        return FIX_STATE_NOT_RELEASED
    return None
