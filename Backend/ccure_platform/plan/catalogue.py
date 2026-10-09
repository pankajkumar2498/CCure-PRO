"""
The plans an organisation can be on.

A plan is a name; what it entitles an organisation to is declared by each
feature module next to that feature (``scan_limits._PLAN_SCAN_LIMITS``), so
removing a feature removes its per-plan figures with it.
"""

from __future__ import annotations

#: The plan an organisation without one — or an unknown organisation — is
#: treated as being on.
DEFAULT_PLAN = "community"


def plan_of(row) -> str:
    """The plan name recorded on an organisation row, or the default."""
    if row is None:
        return DEFAULT_PLAN
    return row.plan or DEFAULT_PLAN
