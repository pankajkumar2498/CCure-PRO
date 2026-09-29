"""
core/remediation/reporting.py
─────────────────────────────────────────────────────────────────────────────
The remediation payload a report renders.

One function, and it exists so that the report, the API summary and the
dashboard cannot each compute "how many are overdue" a different way. The
figures come from the same two aggregate queries the summary endpoint runs.

**Aggregates, never a loop.** At the scale this product reaches — 4,633
findings on one Linux host — building this by iterating findings and calling
``sla_state`` on each would be the N+1 the materialised ``sla_due_at`` column
exists to prevent, on the path that runs at the end of every scan.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import case, func

from core.remediation.states import ACTIVE_STATES, REMEDIATION_STATES

log = logging.getLogger("ccure.remediation.reporting")

__all__ = ["remediation_report_payload"]

#: How many findings the technical report's detail table draws from. The table
#: itself prints 25; fetching a few more lets the ordering pick the ones worth
#: printing without pulling thousands of rows into memory for a PDF.
_DETAIL_LIMIT = 60


def remediation_report_payload(
    db,
    *,
    org_id: str,
    asset_ids: Optional[List[str]] = None,
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Everything the remediation section of a report needs.

    ``verification`` is this scan's own verification outcome, passed straight
    through. It is what lets the report distinguish "42 verified fixed" from
    "42 verified fixed, and 40 more that could not be checked because this scan
    did not assess them" — and the second is the honest sentence whenever the
    scan's reach was partial.

    Returns ``{}`` when the organisation has no findings, so a report for an
    empty estate renders no section rather than a page of zeroes.
    """
    from db.models.assets import Asset
    from db.models.findings import AssetVulnerability

    now = datetime.now(timezone.utc)

    base = (
        db.query(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .filter(Asset.org_id == org_id)
    )
    if asset_ids:
        base = base.filter(AssetVulnerability.asset_id.in_(list(asset_ids)))

    state_rows = (
        base.with_entities(
            AssetVulnerability.remediation_state, func.count(AssetVulnerability.id)
        )
        .group_by(AssetVulnerability.remediation_state)
        .all()
    )
    by_state = {state: 0 for state in REMEDIATION_STATES}
    total = 0
    for state, count in state_rows:
        by_state[str(state or "open")] = int(count)
        total += int(count)

    if not total:
        return {}

    sla_rows = (
        base.with_entities(
            case(
                (AssetVulnerability.sla_due_at.is_(None), "not_applicable"),
                (AssetVulnerability.sla_due_at < now, "overdue"),
                else_="within",
            ).label("bucket"),
            func.count(AssetVulnerability.id),
        )
        .filter(AssetVulnerability.remediation_state.in_(list(ACTIVE_STATES)))
        .group_by("bucket")
        .all()
    )
    buckets = {"within": 0, "overdue": 0, "not_applicable": 0}
    for bucket, count in sla_rows:
        buckets[str(bucket)] = int(count)

    payload: Dict[str, Any] = {
        "by_state": by_state,
        "total": total,
        "overdue": buckets["overdue"],
        "within_sla": buckets["within"],
        "no_sla": buckets["not_applicable"],
    }
    if verification:
        payload["verification"] = dict(verification)

    # Ownership, aggregated. `NULL` owner is reported as unassigned rather than
    # dropped: "nobody owns 4,000 findings" is the most actionable line in the
    # section and omitting it would hide it.
    try:
        owner_rows = (
            base.with_entities(
                AssetVulnerability.remediation_owner,
                func.count(AssetVulnerability.id),
                func.sum(
                    case(
                        (
                            (AssetVulnerability.sla_due_at.isnot(None))
                            & (AssetVulnerability.sla_due_at < now),
                            1,
                        ),
                        else_=0,
                    )
                ),
            )
            .filter(AssetVulnerability.remediation_state.in_(list(ACTIVE_STATES)))
            .group_by(AssetVulnerability.remediation_owner)
            .order_by(func.count(AssetVulnerability.id).desc())
            .limit(20)
            .all()
        )
        payload["by_owner"] = [
            {
                "owner": owner or "Unassigned",
                "open": int(count or 0),
                "overdue": int(overdue or 0),
            }
            for owner, count, overdue in owner_rows
        ]
    except Exception:  # noqa: BLE001
        log.warning("Could not aggregate remediation ownership", exc_info=True)

    # The detail table. Overdue first, then soonest-due — which is the order an
    # operator would work the list in, so the twenty-five rows that fit are the
    # twenty-five worth printing.
    try:
        from core.remediation.sla import sla_policy_for_org_id, sla_state

        policy = sla_policy_for_org_id(db, org_id)

        detail = (
            base.filter(
                AssetVulnerability.remediation_state.in_(list(ACTIVE_STATES)),
                AssetVulnerability.remediation_state != "open",
            )
            .order_by(AssetVulnerability.sla_due_at.asc().nullslast())
            .limit(_DETAIL_LIMIT)
            .all()
        )
        if not detail:
            # Nothing is under active remediation yet, so show the most urgent
            # untouched findings instead — an empty table under a heading
            # reading "Findings under remediation" tells a reader nothing.
            detail = (
                base.filter(
                    AssetVulnerability.remediation_state.in_(list(ACTIVE_STATES))
                )
                .order_by(AssetVulnerability.sla_due_at.asc().nullslast())
                .limit(_DETAIL_LIMIT)
                .all()
            )

        payload["findings"] = [
            {
                "finding_id": f.id,
                "vuln_id": f.vuln_id,
                "asset_id": f.asset_id,
                "severity": f.severity,
                "remediation": {
                    "state": f.remediation_state,
                    "owner": f.remediation_owner,
                },
                "sla": {
                    "due_at": f.sla_due_at.isoformat() if f.sla_due_at else None,
                    "state": sla_state(f, policy=policy, now=now),
                },
            }
            for f in detail
        ]
    except Exception:  # noqa: BLE001
        log.warning("Could not build the remediation detail table", exc_info=True)

    return payload
