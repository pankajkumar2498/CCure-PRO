"""
Contract 1, inbound: ``PolicyBaseline`` → :class:`BaselineInput`.

The only mapper that runs contract → view. It carries across exactly what the
mapping service reads — the control keys, the declared applicability, the
parameters and the scope — and nothing else: the policy reference, approval
and effective dates are the integration phase's to store, and Audit derives no
behaviour from ``requirement_text`` (the model forbids executable content, and
this mapper does not read prose either).
"""

from __future__ import annotations

from ccure_audit.services.baseline_mapping import (
    BaselineControlInput,
    BaselineInput,
    BaselineParameterInput,
    BaselineScopeInput,
)
from ccure_audit.services.compliance_catalogue import ControlKey
from ccure_contracts.common.v1.vocabulary import Applicability
from ccure_contracts.policy_baseline.v1.models import CcurePolicyBaselineV1


def baseline_input(message: CcurePolicyBaselineV1) -> BaselineInput:
    data = message.data
    scope = data.scope
    return BaselineInput(
        baseline_id=data.baseline_id,
        baseline_version=data.baseline_version,
        controls=tuple(
            BaselineControlInput(
                requirement_id=c.requirement_id,
                control=ControlKey(
                    framework_code=c.control.framework.code,
                    framework_version=c.control.framework.version,
                    control_id=c.control.control_id,
                ),
                applicable=c.applicability is Applicability.APPLICABLE,
                parameters=tuple(
                    BaselineParameterInput(name=p.name, value=p.value, unit=p.unit)
                    for p in c.parameters
                ),
            )
            for c in data.controls
        ),
        scope=(
            BaselineScopeInput(
                cidrs=tuple(scope.cidrs), asset_tags=tuple(scope.asset_tags)
            )
            if scope is not None
            else None
        ),
    )
