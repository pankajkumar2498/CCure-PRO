"""
core/web/nuclei/profiles.py
────────────────────────────────────────────────────────────────────────────
Explicit nuclei scan profiles (Phase 10): FAST, STANDARD, DEEP.

Depth is a decision the operator makes, and each profile records what it did so
a short scan cannot be mistaken for a thorough one that found nothing.

  • **FAST**     — highest-confidence, high/critical templates selected from the
                   fingerprinted stack; higher concurrency, shorter timeout.
  • **STANDARD** — current production behaviour: all medium/high/critical
                   templates. Concurrency and timeout are the existing
                   NUCLEI_* values, so it must not regress.
  • **DEEP**     — every severity including low/informational; broader coverage
                   with a configurable timeout and concurrency.

The severity set and technology-tag narrowing continue to come from the
orchestrator's SCAN_DEPTHS (one source for those); a profile adds the execution
controls (concurrency, timeout) and — crucially — the safety exclusions.

**The dos / fuzz / intrusive / brute-force tags are excluded from every profile
by default.** This product scans production and OT hosts, where an audit that
causes an outage is worse than the finding it would have produced. The
exclusions are only dropped when an operator explicitly opts in
(NUCLEI_INCLUDE_DANGEROUS_TAGS, or an explicit override), never as a side effect
of choosing DEEP — DEEP widens *coverage of what is safe to run*, it does not
turn the safety rails off.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional

from config import WebScanConfig

#: Canonical profile names, in order of increasing coverage.
PROFILES = ("FAST", "STANDARD", "DEEP")

#: scan_depth value → canonical profile. "quick" is the historical name for the
#: fast pass and remains a valid alias.
_DEPTH_TO_PROFILE = {"quick": "FAST", "standard": "STANDARD", "deep": "DEEP"}

#: Accepted spellings for a directly-requested profile (options["nuclei_profile"]).
_PROFILE_ALIASES = {
    "fast": "FAST",
    "quick": "FAST",
    "standard": "STANDARD",
    "normal": "STANDARD",
    "deep": "DEEP",
    "full": "DEEP",
}

DEFAULT_PROFILE = "STANDARD"


def default_exclude_tags() -> List[str]:
    """The mandatory safety exclusions, from config (comma-separated)."""
    raw = getattr(
        WebScanConfig, "NUCLEI_EXCLUDE_TAGS", "dos,fuzz,intrusive,brute-force"
    )
    return [t.strip() for t in str(raw).split(",") if t.strip()]


def resolve_exclude_tags(
    override: Optional[List[str]] = None, include_dangerous: bool = False
) -> List[str]:
    """
    The exclude-tags for a run.

    An explicit override wins (that is the documented "unless explicitly
    configured otherwise"). Otherwise the safety set applies, unless dangerous
    tags are globally enabled. Returning ``[]`` means "exclude nothing", which
    only happens on a deliberate opt-in.
    """
    if override is not None:
        return list(override)
    if include_dangerous or getattr(
        WebScanConfig, "NUCLEI_INCLUDE_DANGEROUS_TAGS", False
    ):
        return []
    return default_exclude_tags()


def profile_for_depth(depth_name: str) -> str:
    """Canonical profile for a scan_depth value (quick/standard/deep)."""
    return _DEPTH_TO_PROFILE.get((depth_name or "").strip().lower(), DEFAULT_PROFILE)


def normalize_profile(name: str) -> Optional[str]:
    """Canonical profile for a requested name, or None if unrecognised."""
    return _PROFILE_ALIASES.get((name or "").strip().lower())


def resolve_profile(options: dict, depth_name: str) -> str:
    """
    The profile a scan runs at.

    An explicit ``nuclei_profile`` in the options wins; otherwise it follows the
    scan_depth the orchestrator already resolved (quick→FAST, standard→STANDARD,
    deep→DEEP), so the two knobs cannot disagree.
    """
    requested = normalize_profile((options or {}).get("nuclei_profile", ""))
    if requested:
        return requested
    return profile_for_depth(depth_name)


def profile_controls(profile: str) -> dict:
    """
    Execution controls for a profile, read from config so a deployment can
    tune them. STANDARD deliberately reuses the existing NUCLEI_* values so it
    does not regress; DEEP's timeout and concurrency are separately
    configurable, as the phase requires.
    """
    p = (profile or DEFAULT_PROFILE).upper()
    bulk = int(getattr(WebScanConfig, "NUCLEI_BULK_SIZE", 25))
    if p == "FAST":
        return {
            "concurrency": int(getattr(WebScanConfig, "NUCLEI_CONCURRENCY_FAST", 75)),
            "timeout": int(getattr(WebScanConfig, "NUCLEI_TIMEOUT_FAST", 1800)),
            "bulk_size": bulk,
            "rate_limit": int(getattr(WebScanConfig, "NUCLEI_RATE_FAST", 150)),
        }
    if p == "DEEP":
        return {
            "concurrency": int(getattr(WebScanConfig, "NUCLEI_CONCURRENCY_DEEP", 40)),
            "timeout": int(getattr(WebScanConfig, "NUCLEI_TIMEOUT_DEEP", 14400)),
            "bulk_size": bulk,
            "rate_limit": int(getattr(WebScanConfig, "NUCLEI_RATE_DEEP", 100)),
        }
    return {
        "concurrency": int(getattr(WebScanConfig, "NUCLEI_CONCURRENCY", 25)),
        "timeout": int(getattr(WebScanConfig, "NUCLEI_TIMEOUT", 7200)),
        "bulk_size": bulk,
        "rate_limit": int(getattr(WebScanConfig, "NUCLEI_RATE_STANDARD", 150)),
    }


def profile_label(profile: str) -> str:
    return {
        "FAST": "Fast — high/critical, high-confidence templates from the detected stack",
        "STANDARD": "Standard — all medium, high and critical templates",
        "DEEP": "Deep — every severity, including low and informational",
    }.get((profile or DEFAULT_PROFILE).upper(), profile)


# ── execution metrics from nuclei's own output ───────────────────────────────
_LOADED_RE = re.compile(r"[Tt]emplates?\s+loaded\s+for\s+current\s+scan:\s*(\d+)")
_EXCLUDED_RE = re.compile(r"[Tt]emplates?\s+excluded:\s*(\d+)")


def _as_int(v):
    """nuclei's -stats-json prints every value as a string ("percent":"45");
    coerce to int, returning None for anything that is not a whole number."""
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_run_metrics(stderr: str) -> dict:
    """
    Best-effort execution metrics from nuclei's stderr.

    Reads the "Templates loaded for current scan: N" line and the last
    ``-stats-json`` object. nuclei emits that object with **string** values
    (``{"percent":"45","requests":"494","rps":"151","templates":"956",…}``), so
    every field is coerced through ``_as_int``; a figure nuclei did not report is
    None, never a fabricated count.

    ``percent`` is the request-progress percentage from nuclei's own stats and
    is what tells a timeout apart from a completed run (Phase 19 PART C): a last
    stats line below 100 means the corpus was not finished. ``rps`` is the
    measured request rate.

    Returns: templates_total, templates_executed, templates_skipped, requests,
    requests_total, matched, percent, rps, errors.
    """
    total = executed = skipped = requests = matched = None
    requests_total = percent = rps = errors = None
    if stderr:
        m = _LOADED_RE.search(stderr)
        if m:
            total = int(m.group(1))
        me = _EXCLUDED_RE.search(stderr)
        if me:
            skipped = int(me.group(1))
        last = None
        for line in stderr.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if any(k in obj for k in ("templates", "matched", "requests")):
                    last = obj
        if last:
            # "templates" in the stats object is the number loaded for the scan;
            # it agrees with the "Templates loaded" line and is the total corpus.
            if total is None:
                total = _as_int(last.get("templates"))
            requests = _as_int(last.get("requests"))
            requests_total = _as_int(last.get("total"))
            matched = _as_int(last.get("matched"))
            percent = _as_int(last.get("percent"))
            rps = _as_int(last.get("rps"))
            errors = _as_int(last.get("errors"))
    # nuclei runs every template it loads. When it completed (percent is 100 or
    # unknown), executed == loaded; when it was cut off mid-run the executed
    # count is not directly reported, so it is left as the loaded total and the
    # partial state is carried by ``percent`` instead of a fabricated figure.
    if executed is None and total is not None:
        executed = total
    if skipped is None and total is not None and executed is not None:
        skipped = max(0, total - executed)
    return {
        "templates_total": total,
        "templates_executed": executed,
        "templates_skipped": skipped,
        "requests": requests,
        "requests_total": requests_total,
        "matched": matched,
        "percent": percent,
        "rps": rps,
        "errors": errors,
    }
