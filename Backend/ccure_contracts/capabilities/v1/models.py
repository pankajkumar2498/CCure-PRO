"""
``GET /api/v1/integrations/capabilities`` — what this Audit deployment can do.

A vocabulary is fetched, not copied (CLAUDE.md, UI semantic integrity). Policy
Pro learns the frameworks Audit can assess and the parameter names Audit
understands from here, rather than keeping its own list that silently drifts
from what Audit gained or retired. Rank and IR learn which contract versions
Audit speaks and which methods it implements.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from ccure_contracts.common.v1.envelope import (
    CcureEnvelopeV1,
    CcureFrameworkRefV1,
    ContractModel,
    ShortText,
)
from ccure_contracts.common.v1.fields import owned
from ccure_contracts.common.v1.vocabulary import AssessmentMethod

CAPABILITIES_CONTRACT = "ccure.audit.capabilities"


class CcureContractSupportV1(ContractModel):
    contract: ShortText = owned("audit", "Contract name.")
    schema_versions: List[ShortText] = owned("audit", "Versions accepted or produced.")
    direction: Literal["inbound", "outbound"] = owned("audit", "Relative to Audit.")
    status: Literal["draft", "published", "deprecated"] = owned("audit", "Lifecycle.")


class CcureFrameworkCapabilityV1(ContractModel):
    framework: CcureFrameworkRefV1 = owned("platform", "The framework.")
    installed_for_tenant: bool = owned("audit", "Enabled for the caller's tenant.")
    controls_total: int = owned("audit", "Controls in Audit's catalogue.", ge=0)
    controls_automated: int = owned(
        "audit", "Controls with at least one automated rule.", ge=0
    )


class CcureParameterCapabilityV1(ContractModel):
    name: ShortText = owned("audit", "Parameter name a baseline may carry.")
    datatype: Literal["integer", "number", "boolean", "string"] = owned(
        "audit", "Type."
    )
    unit: Optional[ShortText] = owned("audit", "Unit.", default=None)
    honoured: bool = owned(
        "audit",
        "Whether Audit's rules use the value today. False until rule "
        "parameterisation (plan Phase 13) — a truthful false, not a missing value.",
    )
    description: ShortText = owned("audit", "Meaning.")


class CcureMethodCapabilityV1(ContractModel):
    method: AssessmentMethod = owned("audit", "Method.")
    implemented: bool = owned("audit", "Whether this build implements it.")
    note: Optional[ShortText] = owned("audit", "Limitation, if any.", default=None)


class CcureCapabilitiesDataV1(ContractModel):
    contracts: List[CcureContractSupportV1] = owned("audit", "Contracts spoken.")
    frameworks: List[CcureFrameworkCapabilityV1] = owned(
        "audit", "Assessable frameworks."
    )
    baseline_parameters: List[CcureParameterCapabilityV1] = owned(
        "audit", "Parameter vocabulary.", default_factory=list
    )
    methods: List[CcureMethodCapabilityV1] = owned("audit", "Assessment methods.")


class CcureCapabilitiesV1(CcureEnvelopeV1):
    contract: Literal["ccure.audit.capabilities"] = owned("producer", "Contract name.")
    data: CcureCapabilitiesDataV1 = owned("audit", "Capabilities.")
