"""
scan_helpers.py
───────────────────────────────────────────────────────────────────────────────
Shared helpers, constants, and pipeline logic used by multiple router modules.

Located at the Backend root (not inside routers/) to avoid circular imports,
since the lifespan function in main.py also depends on these symbols.
"""

import logging
from typing import Dict, List, Optional

from orchestrator.host_discovery_api import HostDiscoveryAPI

log = logging.getLogger("ccure.api")


# The limiter moved to core/rate_limiter.py (Phase 3). Re-exported here so
# every `from scan_helpers import limiter` gets the same instance. Application
# modules import it from core.rate_limiter (B1, 16 Oct 2026), which does not
# load the network orchestrator; tests and scripts still use this alias.
from core.rate_limiter import (  # noqa: F401  (re-export)
    _HeaderSafeLimiter,
    _rate_limit_key,
    limiter,
)

from scans.progress import (
    finish_progress as _db_finish_progress,
)
from sqlalchemy.orm import Session

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


# ─── Pipeline configuration ─────────────────────────────────────────────────
# Defined in scans/pipeline.py since C6, with the network phases and the one
# function that hands a phase its hosts. Re-exported here unchanged, as the
# same objects, for the routes and tests that read them from this module.
from scans.pipeline import (  # noqa: E402,F401  (re-export)
    PIPELINE_MODE_ALIASES,
    PIPELINE_PHASES,
    VALID_PIPELINE_MODES,
    _normalize_pipeline_mode,
    get_terminal_phase,
    is_phase_in_pipeline,
    resolve_pipeline_mode,
)


# ─── Misc helpers ────────────────────────────────────────────────────────────


# The target checks moved to core/scan_targets.py, in the scan kernel (G3).
from core.scan_targets import (  # noqa: E402,F401  (re-export)
    _is_scannable_address,
    _SCOPE_NOT_CHECKED,
    validate_custom_ports,
    validate_scan_targets,
)


# What a report says about its scan moved to scans/report_context.py (G2).
# Re-exported here for the scan tasks and anything else that imported it
# from this module.
from scans.report_context import (  # noqa: E402,F401  (re-export)
    _normalize_scan_method,
    _extract_host_ip,
    _target_from_hosts,
    _scan_method_from_hosts,
    resolve_report_context,
    SCAN_COVERAGE_KEYS,
    phase_summary_from_scan,
    carry_scan_coverage,
    phase1_summary_from_scan,
    apply_phase1_summary_hints,
)


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


def __getattr__(name: str):
    # make_pdf_cve_paragraph is a renderer's helper and lives in
    # reporting/report_helpers.py since G6. The old name stays, imported on
    # first use so that loading this module does not load ReportLab.
    if name == "make_pdf_cve_paragraph":
        from reporting.report_helpers import make_pdf_cve_paragraph

        return make_pdf_cve_paragraph
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
