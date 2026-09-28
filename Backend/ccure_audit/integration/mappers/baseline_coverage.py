"""
Contract 1, response: :class:`CoverageView` → ``BaselineCoverage``.

What Audit stores about a received baseline — when it arrived, its digest, the
mapping revision, whether an administrator has activated it — does not exist
until the integration phase adds the store. The mapper therefore takes those
as arguments and decides none of them; ``activation`` in particular has no
default, because only the store knows whether a baseline governs anything.

Three things the view knows that the contract has no field for, each carried
as honestly as the contract allows and listed as a pre-freeze clarification in
the Phase 5 document:

* the per-control **notes** (declared not applicable; framework not installed
  for this tenant) are appended to ``reason``, which is otherwise only
  required for a state other than AUTOMATED;
* a rejected scope entry's **reason** is dropped — ``rejected_entries`` is a
  list of strings;
* **unmatched asset tags** are not rejected entries (they lie inside the
  authorised scope; they match nothing yet) and are not reported at all.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from ccure_audit.integration import vocabulary as vocab
from ccure_audit.integration.envelope import EnvelopeContext, envelope
from ccure_audit.integration.errors import MappingError
from ccure_audit.integration.mappers._common import build, control_ref, required
from ccure_audit.services.baseline_mapping import ControlCoverageView, CoverageView
from ccure_audit.services.compliance_catalogue import CatalogueRuleView
from ccure_contracts.policy_baseline.v1.models import (
    BASELINE_COVERAGE_CONTRACT,
    CcureBaselineCoverageV1,
)


def _rule(rule: CatalogueRuleView, where: str) -> dict:
    return {
        "rule_id": rule.rule_id,
        # A title is display text; the identifier is the fact. An untitled
        # rule is shown by its id rather than refused.
        "title": vocab.short_text(rule.title, fallback=rule.rule_id),
        "check_type": required(rule.check_type, "rule check_type", where),
        "platforms": [rule.target_platform] if rule.target_platform else [],
    }


def _reason(control: ControlCoverageView) -> Optional[str]:
    parts: List[str] = []
    if control.mapping.reason:
        parts.append(control.mapping.reason.strip())
    parts.extend(n.strip() for n in control.notes if n and n.strip())
    return vocab.short_text(" ".join(parts)) if parts else None


def _control(control: ControlCoverageView) -> dict:
    where = f"baseline control {control.requirement_id}"
    key = control.mapping.key
    state = vocab.mapping_state(control.mapping.state, where)
    rules = [_rule(r, where) for r in control.assessing_rules]
    if state in ("AUTOMATED", "PARTIALLY_AUTOMATED") and not rules:
        raise MappingError(f"{where}: {state} with no assessing rule")
    return {
        "requirement_id": control.requirement_id,
        "control": control_ref(
            key.framework_code, key.framework_version, key.control_id, where
        ),
        "mapping_state": state,
        "audit_rules": rules,
        "reason": _reason(control),
    }


def baseline_coverage(
    view: CoverageView,
    *,
    ctx: EnvelopeContext,
    received_at: datetime,
    mapped_at: datetime,
    mapping_revision: int,
    activation: str,
    content_sha256: Optional[str] = None,
) -> CcureBaselineCoverageV1:
    where = f"baseline {view.baseline_id} v{view.baseline_version}"
    counts = view.counts
    data = {
        "baseline": {
            "baseline_id": view.baseline_id,
            "baseline_version": view.baseline_version,
            "content_sha256": content_sha256,
        },
        "received_at": received_at,
        "mapping_revision": mapping_revision,
        "mapped_at": mapped_at,
        "activation": activation,
        "summary": {
            "controls_total": counts.controls_total,
            "automated": counts.automated,
            "partially_automated": counts.partially_automated,
            "attestation_required": counts.attestation_required,
            "unknown_control": counts.unknown_control,
            "unsupported": counts.unsupported,
        },
        "controls": [_control(c) for c in view.controls],
        "parameters": [
            {
                "requirement_id": p.requirement_id,
                "name": p.name,
                "handling": vocab.parameter_handling(
                    p.handling, f"{where} parameter {p.name}"
                ),
                "reason": vocab.short_text(p.reason),
            }
            for p in view.parameters
        ],
        "scope": {
            "applied": view.scope.applied,
            "rejected_entries": [r.entry for r in view.scope.rejected_cidrs],
        },
    }
    return build(
        CcureBaselineCoverageV1,
        {**envelope(BASELINE_COVERAGE_CONTRACT, ctx), "data": data},
        where,
    )
