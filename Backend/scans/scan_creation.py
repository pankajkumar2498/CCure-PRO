"""
scans/scan_creation.py
─────────────────────────────────────────────────────────────────────────────
Creating the scan record a request starts: its targets, its row and its policy
snapshot, settled before any task is dispatched.

G1 (C1, docs/architecture/MODULAR_REFACTORING_LOG.md §6). The credentialed
route used to assemble this itself, from the network orchestrator's target
expansion, the scan persistence helpers, the policy binding and the task hub's
target ceiling, which made the credentialed-audit capability depend on four
pieces of the scans capability's internals. It now asks this service, and
dispatches its task by registered name.

Behaviour is the route's, moved unchanged: the same expansion, the same row,
the same policy resolution in the same session, one commit.
"""

from dataclasses import dataclass
from typing import Any

#: A credentialed audit authenticates to one host at a time. Expanding a CIDR
#: is cheap; logging into every address in it is not, so an operator who pastes
#: a /16 by mistake gets an error rather than a scan that runs for days.
MAX_CREDENTIALED_TARGETS = 256


def expand_targets(requested: list[str]) -> list[str]:
    """
    Addresses, ranges and CIDRs expanded into the hosts a scan will touch.

    The network orchestrator's own expansion, so a credentialed scan and a
    network scan read a target list the same way. Imported when called: the
    orchestrator loads the scan engines, which a route need not.
    """
    from orchestrator.scan_orchestrator import ScanOrchestrator

    return ScanOrchestrator._expand_targets(requested)


@dataclass(frozen=True)
class CreatedScan:
    """A committed scan row and the configuration it will run with."""

    scan_id: str
    scan_no: Any
    #: The policy's section list where it names one, the request's otherwise.
    sections: list[str] | None
    #: What the API reports at acceptance: the policy and what it overrode.
    policy: dict


def create_credentialed_scan(
    db,
    *,
    user_id: str,
    hosts: list[str],
    org_id: str,
    policy_id: str | None,
    sections: list[str] | None,
) -> CreatedScan:
    """
    Create and commit the scan row for a standalone credentialed audit of
    *hosts*, with its policy snapshot.

    A named policy that cannot be used raises ``resolve_scan_policy``'s
    ``HTTPException(400)``, after it has deleted the row ``create_scan``
    committed.
    """
    from scans.db_helpers import create_scan
    from scans.policy_binding import resolve_scan_policy

    target_str = ", ".join(hosts)
    scan = create_scan(
        db=db,
        user_id=user_id,
        target=target_str,
        targets=hosts,
        scan_type="credentialed",
        # This audit runs no discovery and no port scan. Recording it as a
        # vulnerability_audit claimed three phases that never executed.
        pipeline_mode="credentialed",
        org_id=org_id,
    )
    # -- Policy gate (GAP-12) --------------------------------------------
    # Inside the same session that created the scan, so the snapshot and
    # the row it describes land in one commit, and before dispatch so the
    # worker can never read a scan whose configuration is unsettled.
    #
    # `has_credential` is True for every path that reaches here: the
    # request has either named a stored credential or supplied material,
    # both checked by the route. A policy with `require_credential`
    # therefore passes here and does its real work on the *scheduled* path
    # and on the main pipeline, where an unauthenticated fallback is
    # possible.
    effective, policy_overrides = resolve_scan_policy(
        db,
        scan=scan,
        policy_id=policy_id,
        org_id=org_id,
        scan_kind="credentialed",
        has_credential=True,
        request_options={"sections": sections},
    )
    db.commit()
    # Read out before the session closes: `effective` is a frozen
    # dataclass and safe to use afterwards, but the ORM row is not.
    return CreatedScan(
        scan_id=str(scan.id),
        scan_no=scan.scan_no,
        sections=list(effective.sections) or sections,
        policy={
            "policy_id": effective.policy_id,
            "policy_name": effective.policy_name,
            "fingerprint": effective.fingerprint(),
            "source": effective.source,
            "overrides": policy_overrides,
        },
    )
