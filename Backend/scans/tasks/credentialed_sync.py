"""
Writing a credentialed audit's results: the asset's identity, the services
the host reported listening, and the findings, package and configuration
alike.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Since G3 (C3) the findings writer, ``core.findings.writer``,
writes the services, catalogue rows and findings and sweeps the findings the
audit retired. Since 1 Nov 2026 the asset registry, ``core.asset_credentialed``,
finds or bootstraps the asset and writes its identity, risk and system
information. This module resolves the scan's organisation, calls the two
owners in the order it always did, and records what the scan assessed. Logs
under ``ccure.tasks``, as the hub did.
"""

import logging
from typing import Any

from db.models import Scan
from ccure_platform import api as platform_api
from core.asset_credentialed import (  # noqa: F401  the identity helpers, re-exported
    _clean_text,
    _extract_credentialed_identity_names,
    _normalize_mac,
    credentialed_asset,
    finish_credentialed_asset,
)
from core.findings.writer import (
    _sync_credentialed_vulnerabilities,
    risk_from_open_findings,
    sweep_credentialed_findings,
    upsert_credentialed_services,
)
from scans.asset_syncer import _record_asset_change
import core.findings as findings

log = logging.getLogger("ccure.tasks")


def _sync_credentialed_asset_identity(
    db,
    *,
    user_id: str,
    ip: str,
    scan_id: str,
    os_type: str,
    system_data: dict,
    stored_report: dict,
    cve_list: list[dict],
    severity_counts: dict[str, int],
) -> None:
    """
    Promote trusted credentialed scan identity into the Asset Registry.
    Phase 4: Adds forensic logging and provenance.
    """

    user = platform_api.user(db, user_id)
    if not user:
        log.warning("Credentialed asset sync skipped: user %s not found", user_id)
        return

    # Resolve scan's target org_id
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    org_id = str(scan.org_id) if scan else str(user.org_id)

    asset, identity = credentialed_asset(
        db,
        org_id=org_id,
        ip=ip,
        scan_id=scan_id,
        os_type=os_type,
        system_data=system_data,
    )

    _sync_credentialed_services(
        db,
        asset,
        scan_id,
        stored_report.get("open_ports_credentialed", []),
        stored_report.get("packages", []),
    )

    # 1. Sync Vulnerabilities (Marks as open/reopened)
    _sync_credentialed_vulnerabilities(db, asset, org_id, scan_id, cve_list)

    # 2. PHASE 4: VULNERABILITY STATUS HISTORY
    _config_summary, _assessed_checks, _packages_assessed = sweep_credentialed_findings(
        db,
        asset_id=asset.id,
        scan_id=scan_id,
        cve_list=cve_list,
        stored_report=stored_report,
        record_change=_record_asset_change,
    )

    # What this scan looked at, so a later comparison can tell "gone" from
    # "nobody looked". Smallest clean record: merged into `scans.options`,
    # which is JSONB and already carries `options.origin`. GAP-12's policy
    # engine is where this eventually belongs; it is deliberately not built here.
    try:
        from db.models.scans import Scan as _Scan

        _scan_row = db.query(_Scan).filter(_Scan.id == scan_id).first()
        if _scan_row is not None:
            findings.record_assessment_scope(
                _scan_row,
                assets=[asset.id],
                families=["credentialed_package"],
                detail={
                    "config_audit_assessed": bool(_config_summary.get("assessed")),
                    "packages_assessed": _packages_assessed,
                    "checks_assessed": len(_assessed_checks),
                    # The set itself, not only its size. The sweep above uses
                    # it to decide which absent configuration findings are
                    # genuinely gone; without it recorded, a later comparison
                    # has only the *family* to go on — and every credentialed
                    # finding shares one family, so a scan narrowed by a GAP-12
                    # policy reported the checks it stopped selecting as fixed.
                    # Measured on a real target: five controls reported
                    # remediated on a host where nothing had changed, while
                    # this same sweep had correctly left them open.
                    #
                    # Only checks that reached a verdict are in it, so it is
                    # tens of ids rather than the whole selected set.
                    "assessed_checks": sorted(_assessed_checks),
                },
            )
    except Exception as exc:  # never fail a scan over its own bookkeeping
        log.warning("Could not record assessment scope for scan %s: %s", scan_id, exc)

    db.flush()

    # Recalculate aggregate vuln_counts
    risk = risk_from_open_findings(db, asset.id)
    finish_credentialed_asset(
        db,
        asset,
        ip=ip,
        scan_id=scan_id,
        os_type=os_type,
        system_data=system_data,
        identity=identity,
        risk=risk,
    )


def _credentialed_sections_with_identity(
    sections: list[str] | None,
) -> list[str] | None:
    if sections is None:
        return None
    required = ["system_info", "network"]
    merged = list(sections)
    for section in required:
        if section not in merged:
            merged.append(section)
    return merged


def _port_int(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _sync_credentialed_services(
    db, asset: Any, scan_id: str, ports: list[dict], packages: list[dict] = None
) -> None:
    """Persist the host's listening sockets. See core.findings.writer for the semantics."""
    upsert_credentialed_services(db, asset.id, scan_id, ports or [], packages)
