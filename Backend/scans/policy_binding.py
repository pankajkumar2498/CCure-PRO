"""
scans/policy_binding.py
─────────────────────────────────────────────────────────────────────────────
Binding a scan policy to a scan, from an HTTP route.

Two helpers, shared by ``routers/phase_scans.py`` and
``routers/credentialed.py`` so the two dispatch paths cannot drift. The
credentialed route was the one that already carried ``transport``,
``auth_method`` and ``domain`` correctly while the enrichment path did not —
one helper, used by both, is the answer to that class of defect rather than
two careful call sites.

What ``resolve_scan_policy`` guarantees
───────────────────────────────────────
1. The policy exists for **this** tenant, is active and enabled, and is for
   this kind of scan. Anything else raises HTTP 400 with the reason, and the
   scan row created a moment earlier is removed first — a queued scan that
   never dispatched is a ghost in Scan History.
2. The resolved configuration is written into the scan's own ``options`` as
   an immutable snapshot **before** the task is dispatched, so the worker
   cannot read a scan whose configuration has not been settled.
3. The caller is told which of its own parameters the policy displaced.

Why the snapshot is written even with no policy
───────────────────────────────────────────────
A scan run without a policy still has an effective configuration — its own
request parameters — and recording it is what lets GAP-13 tell two such scans
apart when somebody changed the port range between them. Its ``source`` is
``"request"`` and its ``policy_name`` is empty, so nothing downstream can imply
a policy was chosen when none was.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Optional, Tuple

from core.scan_policy import (
    EffectivePolicy,
    ResolvedPolicyError,
    record_policy_snapshot,
    resolve_policy,
)
from fastapi import HTTPException

log = logging.getLogger("ccure.scans.policy_binding")

__all__ = ["reapply_policy_snapshot", "resolve_scan_policy"]


def resolve_scan_policy(
    db,
    *,
    scan,
    policy_id: Optional[str],
    org_id: str,
    scan_kind: str,
    has_credential: bool = False,
    request_options: Optional[Mapping[str, Any]] = None,
) -> Tuple[EffectivePolicy, Dict[str, Any]]:
    """
    Resolve the policy for *scan*, record it, and return it with any overrides.

    Raises ``HTTPException(400)`` when a named policy cannot be used. The 400
    rather than a 404 is deliberate even for "no such policy": the request
    itself is what is wrong — it named a policy this caller cannot use — and a
    404 on a POST that creates a scan reads as "the scan endpoint is missing".
    The tenant-scoped lookup inside ``resolve_policy`` is what stops the
    message distinguishing another tenant's policy from a nonexistent one.
    """
    try:
        resolution = resolve_policy(
            db,
            policy_id=policy_id,
            org_id=org_id,
            scan_kind=scan_kind,
            request_options=request_options,
            has_credential=has_credential,
        )
        if resolution.policy.custom_ports:
            from core.utils import InputValidator

            InputValidator.parse_custom_ports(resolution.policy.custom_ports)
    except (ResolvedPolicyError, ValueError) as exc:
        # Remove the scan row before answering. It was created to reserve the
        # scan number; a scan that never dispatched should
        # not appear in Scan History as permanently queued.
        try:
            db.delete(scan)
            db.commit()
        except Exception:  # noqa: BLE001 — the policy error is the answer
            db.rollback()
            log.warning(
                "Could not remove scan %s after a policy refusal",
                getattr(scan, "id", "?"),
                exc_info=True,
            )
        raise HTTPException(
            status_code=400,
            detail={"message": str(exc), "errors": getattr(exc, "errors", [str(exc)])},
        ) from exc

    effective = resolution.policy
    record_policy_snapshot(scan, effective)

    if effective.policy_id:
        _increment_use_count(db, effective.policy_id, org_id)

    if resolution.validation.warnings:
        log.info(
            "Scan %s policy %s: %s",
            getattr(scan, "id", "?"),
            effective.policy_name or effective.fingerprint()[:16],
            "; ".join(resolution.validation.warnings),
        )

    return effective, resolution.overrides


def reapply_policy_snapshot(scan, effective: EffectivePolicy) -> None:
    """
    Re-write the snapshot after a route has rebuilt ``scan.options`` wholesale.

    Both dispatch routes assemble ``options`` from a dict literal, which
    replaces the whole mapping and would silently drop a snapshot written
    before it. Calling this afterwards is cheap and idempotent; forgetting it
    loses the record of what the scan ran under, and the loss is invisible
    until somebody reads the report.

    ``overwrite=True`` because this is re-applying the *same* snapshot to a
    mapping that lost it, not changing a settled configuration.
    """
    record_policy_snapshot(scan, effective, overwrite=True)


def _increment_use_count(db, policy_id: str, org_id: str) -> None:
    """
    Count a scan against the policy that drove it.

    Best-effort and never fatal: the counter exists so an operator editing a
    policy is warned that it is in use, and failing a scan over a statistics
    column would be a poor trade. The authoritative count is
    ``GET /scan-policies/{id}/usage``, which counts snapshots.
    """
    from db.models.scan_policies import ScanPolicy

    try:
        row = (
            db.query(ScanPolicy)
            .filter(ScanPolicy.id == policy_id, ScanPolicy.org_id == org_id)
            .first()
        )
        if row is not None:
            row.use_count = int(row.use_count or 0) + 1
    except Exception:  # noqa: BLE001
        log.debug("Could not increment use_count for %s", policy_id, exc_info=True)
