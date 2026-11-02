"""
core/scan_policy/scan_usage.py — how many scans ran under a policy, as the
scans capability answers.

``GET /scan-policies/{id}/usage`` reports a ``scan_count``: the scans whose
snapshot (``scans.options["scan_policy"]``) names the policy. The router used
to count them from the scan model, an upward edge from scan policy into the
scans capability, which depends on scan policy (it resolves and records the
snapshot). The scans capability answers here instead
(``scans.reads.scans_recorded_under``), registered by Audit's composition
root, ``ccure_audit/scan_directory.py``.

Nothing here imports the scan model. Without the registration the count
raises ``ScanUsageMissing``: a zero would claim no scan ran under the policy.
"""

from __future__ import annotations

from typing import Callable, Optional

from sqlalchemy.orm import Session

#: ``count(db, org_id, policy_id) -> int``: scans of the organisation whose
#: recorded snapshot names the policy id.
ScanUsageCounter = Callable[[Session, str, str], int]


class ScanUsageMissing(RuntimeError):
    """A policy's scan usage was read in a process that registered no answer."""


_counter: Optional[ScanUsageCounter] = None


def register_scan_usage(counter: ScanUsageCounter) -> None:
    """Register who answers; the same answer again is a no-op, another refused."""
    global _counter
    if _counter is counter:
        return
    if _counter is not None:
        raise ValueError("a scan usage counter is already registered")
    _counter = counter


def scans_recorded_under(db: Session, org_id: str, policy_id: str) -> int:
    """How many of the organisation's scans recorded this policy."""
    if _counter is None:
        raise ScanUsageMissing(
            "No scan usage counter is registered in this process. Audit's "
            "composition root, ccure_audit/scan_directory.py, registers the "
            "scans capability's: main.py and the worker load it."
        )
    return _counter(db, org_id, policy_id)
