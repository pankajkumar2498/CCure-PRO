"""
:class:`FindingView` → ``Finding``, and a :class:`FindingPageView` →
``AssessmentFindingsPage``.

Every field the view carries maps to its contract field; every field the
contract reserves and Audit does not implement is stated as such — never a
zero, a ``False`` or an empty string standing in for a value.

* **Risk.** Only the CVSS component exists. Criticality, exposure, the SRS
  weighted score and the residual score are ``not_implemented``; the composite
  is not computed from the one component Audit has. CVSS scores a CVE, so any
  other definition is ``not_applicable`` **whatever the row stores** — Audit
  writes ``cvss_score = 0.0`` with no vector on configuration and privilege
  findings (measured: every such row, critical ones included), and passing that
  through would report a critical finding's CVSS as zero. A CVE without a score
  was not published or not collected (``not_collected``). ``audit_priority`` is
  left null: it is computed by ``core.vuln_intel`` and not stored on the
  finding, and the adapter may not import ``core``.
* **Exploit intelligence** describes a CVE. For a check it is
  ``not_applicable`` and the KEV flag is null, not ``False``.
* **Remediation.** ``verified_fixed`` must name the scan that verified it, and
  a risk acceptance is emitted only in state ``risk_accepted`` — a withdrawn
  acceptance leaves reason and date behind, and the state, not the residue,
  decides (CLAUDE.md, WITHDRAWN ≠ ACCEPTED).
* **Evidence** is referenced, not embedded, and Audit has no evidence
  identifier or endpoint yet, so ``evidence_refs`` is null — the
  contract's "not implemented", never an empty list, which would state
  that no evidence exists.
"""

from __future__ import annotations

from typing import Optional

from ccure_audit.integration import vocabulary as vocab
from ccure_audit.integration.envelope import EnvelopeContext, envelope
from ccure_audit.integration.errors import MappingError
from ccure_audit.integration.mappers._common import build, measured, unavailable
from ccure_audit.services.finding_read import FindingPageView, FindingView
from ccure_contracts.assessment_result.v1.models import CcureAssessmentFindingsPageV1
from ccure_contracts.common.v1.assessment import CcureFindingV1
from ccure_contracts.common.v1.vocabulary import ValueStatus

FINDINGS_PAGE_CONTRACT = "ccure.audit.assessment_findings_page"

_NOT_IMPLEMENTED_CRITICALITY = (
    "Audit has no asset-criticality attribute yet (SRS 7.3.7.3)."
)
_NOT_IMPLEMENTED_EXPOSURE = "Audit does not compute network exposure yet (SRS 7.3.7.5)."
_NOT_IMPLEMENTED_SRS_SCORE = (
    "The SRS weighted score needs asset criticality and exposure, which Audit "
    "does not implement; it is not computed from the CVSS component alone."
)
_NOT_IMPLEMENTED_RESIDUAL = (
    "Residual risk needs compensating controls, which Audit does not record on "
    "vulnerability findings (SRS 7.3.7.8)."
)


def exploit_availability(view: FindingView) -> str:
    """
    The strongest exploit evidence known, from the flags the feeds set.

    CISA KEV, a VulnCheck canary observation and known ransomware use are all
    evidence of exploitation in the wild. ``verified_exploit`` is a working
    exploit confirmed reproducible; ``has_exploit`` a public one. None of them
    is a statement about this host.
    """
    if view.definition_type != "cve":
        return "not_applicable"
    if view.in_kev or view.canary_confirmed or view.ransomware_linked:
        return "actively_exploited"
    if view.verified_exploit:
        return "verified_exploit"
    if view.has_exploit:
        return "public_exploit"
    return "none_known"


def _cvss(view: FindingView) -> Optional[dict]:
    if view.definition_type != "cve":
        return None  # see the module docstring: a stored 0.0 is a placeholder
    if view.cvss_score is None and not view.cvss_vector and not view.cvss_version:
        return None
    return {
        "score": float(view.cvss_score) if view.cvss_score is not None else None,
        "vector": vocab.short_text(view.cvss_vector),
        "version": vocab.short_text(view.cvss_version),
    }


def _risk(view: FindingView) -> dict:
    if view.definition_type != "cve":
        cvss = unavailable(
            ValueStatus.NOT_APPLICABLE,
            "CVSS scores a CVE; a configuration, privilege or product check has none.",
        )
    elif view.cvss_score is not None:
        cvss = measured(view.cvss_score, "cvss_base_score")
    else:
        cvss = unavailable(
            ValueStatus.NOT_COLLECTED, "No CVSS base score is recorded for this CVE."
        )
    return {
        "cvss_component": cvss,
        "asset_criticality_component": unavailable(
            ValueStatus.NOT_IMPLEMENTED, _NOT_IMPLEMENTED_CRITICALITY
        ),
        "exposure_component": unavailable(
            ValueStatus.NOT_IMPLEMENTED, _NOT_IMPLEMENTED_EXPOSURE
        ),
        "srs_risk_score": unavailable(
            ValueStatus.NOT_IMPLEMENTED, _NOT_IMPLEMENTED_SRS_SCORE
        ),
        "risk_category": None,
        "residual_risk_score": unavailable(
            ValueStatus.NOT_IMPLEMENTED, _NOT_IMPLEMENTED_RESIDUAL
        ),
        "audit_priority": None,
    }


def _remediation(view: FindingView, where: str) -> dict:
    state = vocab.closed(
        view.remediation_state, vocab.REMEDIATION_STATES, "remediation state", where
    )
    if state == "verified_fixed" and not view.verified_scan_id:
        raise MappingError(
            f"{where}: verified_fixed names no verifying scan; only a scan can "
            "verify a fix, and the contract must say which"
        )
    acceptance = None
    if state == "risk_accepted":
        if view.accepted_at is None:
            raise MappingError(f"{where}: risk_accepted with no accepted_at")
        reason = vocab.long_text(view.accepted_risk_reason)
        if reason is None:
            raise MappingError(f"{where}: risk_accepted with no reason")
        acceptance = {
            "accepted_at": view.accepted_at,
            "expires_at": view.exception_expires_at,
            "reason": reason,
            "accepted_by_ref": view.accepted_by_id,
            "compensating_controls": None,
        }
    return {
        "state": state,
        "sla_state": vocab.closed(view.sla_state, vocab.SLA_STATES, "SLA state", where),
        "sla_due_at": view.sla_due_at,
        "verified_at": view.verified_at,
        "verified_by": (
            {"assessment_id": view.verified_scan_id} if view.verified_scan_id else None
        ),
        "reopened_count": view.reopened_count,
        "guidance": vocab.long_text(view.vendor_remediation),
        "risk_acceptance": acceptance,
    }


def _finding_data(view: FindingView) -> dict:
    where = f"finding {view.finding_id}"
    definition_type = vocab.closed(
        view.definition_type, vocab.DEFINITION_TYPES, "definition type", where
    )
    is_cve = definition_type == "cve"
    return {
        "finding": {"finding_id": view.finding_id},
        "definition": {
            "definition_id": view.definition_id,
            "definition_type": definition_type,
            "cve_id": view.definition_id if is_cve else None,
            "title": vocab.short_text(view.title, fallback=view.definition_id),
        },
        "asset": {
            "asset_id": view.asset_id,
            "ip_address": vocab.short_text(view.ip_address),
            "mac_address": vocab.short_text(view.mac_address),
            "hostname": vocab.short_text(view.hostname),
        },
        "severity": vocab.severity(view.severity),
        "cvss": _cvss(view),
        "detection": {
            "method": vocab.detection_method(view.detection_method),
            "confidence": vocab.confidence(view.confidence),
            "qod": view.qod,
            "detected_version": vocab.short_text(view.detected_version),
        },
        "exploit": {
            "availability": exploit_availability(view),
            "in_cisa_kev": view.in_kev if is_cve else None,
            "kev_due_date": view.kev_due_date if is_cve and view.in_kev else None,
            "epss_score": (
                float(view.epss_score)
                if is_cve and view.epss_score is not None
                else None
            ),
            "ransomware_linked": view.ransomware_linked if is_cve else None,
        },
        "status": vocab.closed(
            view.status, vocab.DETECTION_STATUSES, "detection status", where
        ),
        "first_found_at": view.first_found_at,
        "last_found_at": view.last_found_at,
        "fixed_at": view.fixed_at,
        "remediation": _remediation(view, where),
        "risk": _risk(view),
        "last_assessment": {"assessment_id": view.scan_id},
        "evidence_refs": None,
    }


def finding(view: FindingView) -> CcureFindingV1:
    return build(CcureFindingV1, _finding_data(view), f"finding {view.finding_id}")


def findings_page(
    page: FindingPageView, *, result_id: str, ctx: EnvelopeContext
) -> CcureAssessmentFindingsPageV1:
    """
    One page. The cursor is the service's ``after`` key; turning it into an
    opaque, signed cursor is the feed's job in the integration phase.
    """
    return build(
        CcureAssessmentFindingsPageV1,
        {
            **envelope(FINDINGS_PAGE_CONTRACT, ctx),
            "result_id": result_id,
            "items": [finding(v) for v in page.items],
            "position": {
                "next_cursor": page.next_after,
                "has_more": page.next_after is not None,
            },
        },
        f"findings page of {page.scan_id}",
    )
