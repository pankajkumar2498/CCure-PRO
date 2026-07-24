"""
scan_helpers.py
───────────────────────────────────────────────────────────────────────────────
Shared helpers, constants, and pipeline logic used by multiple router modules.

Located at the Backend root (not inside routers/) to avoid circular imports,
since the lifespan function in main.py also depends on these symbols.
"""

import json
import logging
from typing import Dict, List, Optional

from api.host_discovery_api import HostDiscoveryAPI
from config import AppConfig
from db.models import Scan
from scans.progress import (
    finish_progress as _db_finish_progress,
)
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.api")

# ─── Rate limiter (shared across routers) ────────────────────────────────────
# Uses the same Redis instance as Celery for persistence
limiter = Limiter(key_func=get_remote_address, storage_uri=AppConfig.CELERY_BROKER_URL)

# ─── Application state ──────────────────────────────────────────────────────
_api_instance: HostDiscoveryAPI | None = None


def set_api(api: HostDiscoveryAPI) -> None:
    """Called once from lifespan to register the singleton."""
    global _api_instance
    _api_instance = api


def get_api() -> HostDiscoveryAPI:
    """Return the HostDiscoveryAPI singleton or raise 503."""
    from fastapi import HTTPException

    if _api_instance is None:
        raise HTTPException(status_code=503, detail="API not initialised yet.")
    return _api_instance


# ─── Pipeline configuration (mirrors src/config/scanConfig.js) ───────────────
# Phase 4 (topology_mapping) is eligible to run at the end of any pipeline.
# It is only executed if SNMP credentials are provided in scan.options.
PIPELINE_PHASES: dict[str, list[int]] = {
    "basic": [1, 4],
    "asset": [1, 2, 4],
    "vulnerability_audit": [1, 2, 3, 4],
}

VALID_PIPELINE_MODES = set(PIPELINE_PHASES.keys()) | {"advanced"}
PIPELINE_MODE_ALIASES = {
    "advanced": "vulnerability_audit",
}


def _normalize_pipeline_mode(raw: str | None) -> str:
    token = str(raw or "").strip().lower()
    if not token:
        return "basic"
    return PIPELINE_MODE_ALIASES.get(token, token)


def get_terminal_phase(pipeline_mode: str) -> int:
    """Return the last *core* phase number for a given pipeline mode.
    Phase 4 (topology_mapping) is an optional bolt-on and does NOT
    count as the terminal phase for scan completion logic."""
    pipeline_mode = _normalize_pipeline_mode(pipeline_mode)
    phases = PIPELINE_PHASES.get(pipeline_mode, [1])
    # Exclude Phase 4 (topology) — it's an optional add-on, not core pipeline
    core_phases = [p for p in phases if p != 4]
    return max(core_phases) if core_phases else max(phases)


def is_phase_in_pipeline(pipeline_mode: str, phase: int) -> bool:
    """Return True if the given phase belongs to the declared pipeline."""
    pipeline_mode = _normalize_pipeline_mode(pipeline_mode)
    return phase in PIPELINE_PHASES.get(pipeline_mode, [1])


def resolve_pipeline_mode(raw: str | None) -> str:
    """
    Normalise and validate the pipeline_mode from a request.
    Falls back to 'basic' for unknown / missing values.
    """
    token = _normalize_pipeline_mode(raw)
    if token in VALID_PIPELINE_MODES:
        return token
    if raw:
        log.warning("Unknown pipeline_mode '%s' — defaulting to 'basic'.", raw)
    return "basic"


# ─── Misc helpers ────────────────────────────────────────────────────────────


def validate_total_targets(targets: list[str]) -> None:
    from core.utils import InputValidator
    from fastapi import HTTPException

    total = sum(len(InputValidator.expand_target(t)) for t in targets)
    if total > InputValidator.MAX_HOSTS:
        raise HTTPException(
            status_code=400,
            detail=f"Total requested hosts ({total}) exceeds the global limit of {InputValidator.MAX_HOSTS}.",
        )


def _safe_json_loads(text: str | None, default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


def _normalize_scan_method(value: str | None) -> str | None:
    token = str(value or "").strip().upper()
    if not token:
        return None
    if "ADAPTIVE" in token:
        return "ADAPTIVE"
    if "STEALTH" in token:
        return "STEALTH"
    if "FULL" in token:
        return "FULL"
    if "ARP" in token:
        return "ARP"
    if "PING" in token or "ICMP" in token:
        return "PING"
    if "TCP" in token:
        return "TCP"
    return None


def _extract_host_ip(host: dict) -> str | None:
    return host.get("ip_address") or host.get("ip")


def _target_from_hosts(hosts: list[dict]) -> str | None:
    ips = []
    for host in hosts or []:
        ip = _extract_host_ip(host)
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        return None
    return ", ".join(ips)


def _scan_method_from_hosts(hosts: list[dict]) -> str | None:
    for host in hosts or []:
        method = (
            host.get("scan_method")
            or host.get("discovery_method")
            or host.get("method")
        )
        normalized = _normalize_scan_method(method)
        if normalized:
            return normalized
    return None


# ─── Report context resolution ───────────────────────────────────────────────


def resolve_report_context(
    db: Session,
    user_id: str,
    *,
    scan_id: str | None = None,
    hosts: list[dict] | None = None,
    requested_targets: list[str] | None = None,
    requested_scan_type: str | None = None,
) -> dict:
    """
    Build report metadata with human-meaningful context:
      - target (prefer original user input)
      - scan_method/discovery_scan_method (discovery strategy)
    """
    context: dict = {}
    scan_row: Scan | None = None
    summary_blob: dict = {}

    if scan_id:
        scan_row = (
            db.query(Scan)
            .filter(Scan.id == scan_id, Scan.created_by == user_id)
            .first()
        )
    if scan_row:
        context["scan_no"] = scan_row.scan_no
        summary_blob = phase1_summary_from_scan(scan_row)

    # Target priority: request targets > scan row target/original_targets > host list
    if requested_targets:
        context["target"] = ", ".join(
            [str(t).strip() for t in requested_targets if str(t).strip()]
        )
        context["original_targets"] = requested_targets
    elif scan_row:
        target = (scan_row.target_str or "").strip()
        if target:
            context["target"] = target
        original_targets = summary_blob.get("original_targets") or (
            scan_row.target_hosts or []
        )
        if original_targets:
            context["original_targets"] = original_targets
            if "target" not in context:
                context["target"] = ", ".join(
                    [str(t).strip() for t in original_targets if str(t).strip()]
                )
    elif hosts:
        host_target = _target_from_hosts(hosts)
        if host_target:
            context["target"] = host_target

    # Scan strategy priority: request scan_type > stored scan_type > host-level method
    scan_method = _normalize_scan_method(requested_scan_type)
    if not scan_method and scan_row:
        scan_method = (
            _normalize_scan_method(scan_row.scan_type)
            or _normalize_scan_method(summary_blob.get("discovery_scan_method"))
            or _normalize_scan_method(summary_blob.get("scan_method"))
            or _normalize_scan_method(summary_blob.get("scan_type"))
        )
    if not scan_method and hosts:
        scan_method = _scan_method_from_hosts(hosts)

    if scan_method:
        context["scan_method"] = scan_method
        context["discovery_scan_method"] = scan_method

    return context


def phase1_summary_from_scan(scan_row: Scan) -> dict:
    for phase_row in getattr(scan_row, "phases", []) or []:
        if getattr(phase_row, "phase_key", "") not in ("host_discovery", "phase1"):
            continue
        summary = getattr(phase_row, "summary", {}) or {}
        if isinstance(summary, dict):
            return summary
    return {}


def apply_phase1_summary_hints(
    result: dict,
    db: Session,
    user_id: str,
    scan_id: str | None,
) -> None:
    if not scan_id:
        return
    scan_row = (
        db.query(Scan).filter(Scan.id == scan_id, Scan.created_by == user_id).first()
    )
    if not scan_row:
        return
    phase1_summary = phase1_summary_from_scan(scan_row)
    if not phase1_summary:
        return

    summary = result.setdefault("summary", {})
    for key in ("total_hosts", "active_hosts", "inactive_hosts"):
        if phase1_summary.get(key) is not None:
            summary[key] = phase1_summary[key]

    discovery_scan_method = _normalize_scan_method(
        phase1_summary.get("discovery_scan_method") or phase1_summary.get("scan_type")
    )
    if discovery_scan_method:
        summary["discovery_scan_method"] = discovery_scan_method
        metadata = result.setdefault("metadata", {})
        metadata.setdefault("scan_method", discovery_scan_method)
        metadata.setdefault("discovery_scan_method", discovery_scan_method)


def finish_progress(scan_id: str, db: Session = None):
    """Mark a scan as finished in the database (multi-worker safe)."""
    if db:
        _db_finish_progress(db, scan_id)
    else:
        from db.base import SessionLocal

        session = SessionLocal()
        try:
            _db_finish_progress(session, scan_id)
        finally:
            session.close()


def get_cve_redirection_url(cve_id: str) -> str:
    """Return the authoritative NIST NVD URL for a CVE ID."""
    clean_id = str(cve_id).strip()
    return f"https://nvd.nist.gov/vuln/detail/{clean_id.upper()}"


def make_pdf_cve_paragraph(cve_id: str, style) -> "Paragraph":
    """
    Constructs a ReportLab Paragraph containing a secure, clickable hyperlink
    directing the user to the NVD reference page for the specified CVE.
    """
    import html

    from reportlab.platypus import Paragraph

    clean_id = str(cve_id).strip()
    # Guard check: if it's not a valid CVE ID, return plain styled Paragraph
    if not clean_id.upper().startswith("CVE-"):
        return Paragraph(html.escape(clean_id), style)

    safe_id = html.escape(clean_id.upper())
    url = f"https://nvd.nist.gov/vuln/detail/{safe_id}"

    # Branded blue link markup
    link_html = f'<a href="{url}" color="#0066CC"><b>{safe_id}</b></a>'
    return Paragraph(link_html, style)
