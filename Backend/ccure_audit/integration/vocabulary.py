"""
Audit's own values → the contract vocabulary (Phase 4 design document §5).

The adapter may not import ``core`` (layer rule ``integration-is-an-adapter``),
so the few tables it needs live here — and ``tests/audit_boundary`` pins every
one of them to Audit's own definitions (``CheckOutcome``, ``normalize_severity``,
``DetectionMethod``, ``REMEDIATION_STATES``, ``SLA_STATES``, the mapping and
parameter vocabularies). A value Audit gains that this module does not know
fails a test, rather than drifting silently.

Two kinds of translation, and the difference is deliberate:

* **Closed vocabularies** — remediation state, SLA state, detection status,
  definition type, mapping state, parameter handling. Each is CHECK-constrained
  or enumerated in Audit, so an unknown value means the two sides have drifted:
  :class:`MappingError`, never a guess.
* **Open vocabularies** — severity, detection method, confidence, stored check
  outcome. Audit already stores spellings outside its canonical set (raw
  plugin methods, capitalised confidence, a blank outcome), so each has a
  documented rule for the unknown case, and that rule never produces a better
  state than the data supports.
"""

from __future__ import annotations

from typing import Dict, Optional

from ccure_audit.integration.errors import MappingError

# ── Assessment state (stored CheckOutcome → contract AssessmentState) ─────────

_OUTCOME_TO_STATE: Dict[str, str] = {
    "pass": "PASS",
    "fail": "FAIL",
    "not_applicable": "NOT_APPLICABLE",
    "manual_review": "MANUAL_REVIEW",
    "error": "ERROR",
}


def assessment_state(outcome: str) -> str:
    """
    A stored check outcome as an assessment state.

    ``""`` — the record carries no outcome — is ``NOT_ASSESSED``, as the export
    labels it. An outcome this build does not define is ``ERROR``: it is not a
    verdict anyone can rely on, and reading it as either PASS or FAIL would
    assert something nothing established.
    """
    text = (outcome or "").strip().lower()
    if not text:
        return "NOT_ASSESSED"
    return _OUTCOME_TO_STATE.get(text, "ERROR")


def is_known_outcome(outcome: str) -> bool:
    text = (outcome or "").strip().lower()
    return not text or text in _OUTCOME_TO_STATE


# ── Severity ──────────────────────────────────────────────────────────────────

CANONICAL_SEVERITIES = ("critical", "high", "medium", "low", "none", "unscored")
_SEVERITY_ALIASES: Dict[str, str] = {
    "info": "none",
    "informational": "none",
    "unknown": "unscored",
    "": "unscored",
}


def severity(value: Optional[str]) -> str:
    """Same rule as ``core.checks.contract.normalize_severity``: unknown is
    ``unscored`` (no rating published), never ``none`` (a rating of zero)."""
    text = str(value or "").strip().lower()
    text = _SEVERITY_ALIASES.get(text, text)
    return text if text in CANONICAL_SEVERITIES else "unscored"


# ── Detection ─────────────────────────────────────────────────────────────────

CANONICAL_DETECTION_METHODS = (
    "version_match",
    "credentialed_package",
    "package_present",
    "banner_match",
    "version_imprecise",
    "service_product",
    "os_reported",
    "config_check",
    "engine_reported",
    "imported",
    "port_observation",
    "unverified",
)

#: Raw plugin spellings the asset syncer stores verbatim, mapped as the
#: finding normaliser's AUTHORITATIVE table maps them.
_DETECTION_ALIASES: Dict[str, str] = {
    "active_check": "config_check",
    "nessus": "imported",
}


def detection_method(value: Optional[str]) -> str:
    """
    A stored detection method in the contract vocabulary. An absent or
    unrecognised method is ``unverified`` — "Audit cannot say how this was
    established" — never a stronger claim.
    """
    text = str(value or "").strip().lower()
    text = _DETECTION_ALIASES.get(text, text)
    return text if text in CANONICAL_DETECTION_METHODS else "unverified"


_CONFIDENCES = ("confirmed", "potential", "informational", "unverified")


def confidence(value: Optional[str]) -> str:
    """Stored as ``Confirmed`` on one write path and ``confirmed`` on another;
    absent or unrecognised is ``unverified``."""
    text = str(value or "").strip().lower()
    return text if text in _CONFIDENCES else "unverified"


# ── Closed vocabularies ──────────────────────────────────────────────────────

REMEDIATION_STATES = (
    "open",
    "assigned",
    "in_remediation",
    "pending_verification",
    "verified_fixed",
    "reopened",
    "risk_accepted",
)
SLA_STATES = (
    "within_sla",
    "due_soon",
    "overdue",
    "resolved",
    "pending_verification",
    "not_applicable",
)
DETECTION_STATUSES = ("open", "fixed", "accepted")
DEFINITION_TYPES = ("cve", "config_check", "plugin_check", "privilege_check")

_MAPPING_STATES: Dict[str, str] = {
    "automated": "AUTOMATED",
    "partially_automated": "PARTIALLY_AUTOMATED",
    "attestation_required": "ATTESTATION_REQUIRED",
    "unknown_control": "UNKNOWN_CONTROL",
    "unsupported": "UNSUPPORTED",
}
_PARAMETER_HANDLINGS: Dict[str, str] = {
    "honoured": "HONOURED",
    "recorded_not_honoured": "RECORDED_NOT_HONOURED",
    "unknown_parameter": "UNKNOWN_PARAMETER",
    "invalid_value": "INVALID_VALUE",
}


def closed(value: Optional[str], allowed: tuple, what: str, where: str) -> str:
    """A value from a closed Audit vocabulary, or :class:`MappingError`."""
    text = str(value or "").strip()
    if text not in allowed:
        raise MappingError(
            f"{where}: {what} {value!r} is not in the contract vocabulary"
        )
    return text


def mapping_state(value: str, where: str) -> str:
    try:
        return _MAPPING_STATES[value]
    except KeyError:
        raise MappingError(f"{where}: unknown mapping state {value!r}") from None


def parameter_handling(value: str, where: str) -> str:
    try:
        return _PARAMETER_HANDLINGS[value]
    except KeyError:
        raise MappingError(f"{where}: unknown parameter handling {value!r}") from None


# ── Text limits ───────────────────────────────────────────────────────────────

SHORT_TEXT_MAX = 500
LONG_TEXT_MAX = 20000
_ELLIPSIS = " […]"


def short_text(value: Optional[str], fallback: Optional[str] = None) -> Optional[str]:
    """Fit a display string to the contract's ShortText; ``None`` for empty.
    Truncation is marked, so a cut value never reads as the whole value."""
    return _fit(value, SHORT_TEXT_MAX, fallback)


def long_text(value: Optional[str]) -> Optional[str]:
    return _fit(value, LONG_TEXT_MAX, None)


def _fit(value: Optional[str], limit: int, fallback: Optional[str]) -> Optional[str]:
    text = (value or "").strip()
    if not text:
        return fallback
    if len(text) <= limit:
        return text
    return text[: limit - len(_ELLIPSIS)].rstrip() + _ELLIPSIS
