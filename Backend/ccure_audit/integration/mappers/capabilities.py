"""
``Capabilities`` from :class:`FrameworkCapabilityView` and
:class:`ParameterDefinition`.

Frameworks and parameters come from Audit's own services. Two sections do not:

* **contracts** — which contract versions this deployment speaks, and in which
  lifecycle state, is a fact about the integration surface that does not exist
  until the integration phase wires it;
* **methods** — which assessment methods this build implements has no Audit
  service to read it from yet.

Both are therefore arguments, supplied by the caller as
:class:`ContractSupport` / :class:`MethodSupport`. The mapper neither
hardcodes a product fact nor emits an empty list that would read as "none":
an empty ``methods`` is refused, because the contract has no way to say "not
reported" for it.

**Only frameworks active in this installation are listed.** A parked catalogue
is seeded, crosswalk-reachable and deliberately not offered (CLAUDE.md, "Only
two frameworks are switched on"); offering it to Policy Pro would invite a
baseline Audit then answers with UNSUPPORTED on every control.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from ccure_audit.integration.envelope import EnvelopeContext, envelope
from ccure_audit.integration.errors import MappingError
from ccure_audit.integration.mappers._common import build, framework_ref
from ccure_audit.services.baseline_mapping import ParameterDefinition
from ccure_audit.services.compliance_catalogue import FrameworkCapabilityView
from ccure_contracts.capabilities.v1.models import (
    CAPABILITIES_CONTRACT,
    CcureCapabilitiesV1,
)


@dataclass(frozen=True)
class ContractSupport:
    contract: str
    schema_versions: Tuple[str, ...]
    direction: str  # inbound | outbound
    status: str  # draft | published | deprecated


@dataclass(frozen=True)
class MethodSupport:
    method: str  # an AssessmentMethod value
    implemented: bool
    note: Optional[str] = None


def _framework(view: FrameworkCapabilityView) -> dict:
    fw = view.framework
    where = f"framework {fw.framework_id}"
    return {
        "framework": framework_ref(fw.code, fw.version, where),
        "installed_for_tenant": fw.installed_for_tenant,
        "controls_total": view.controls_total,
        # "Controls with at least one automated rule": a partially automated
        # control has one, so it counts here.
        "controls_automated": view.controls_automated
        + view.controls_partially_automated,
    }


def capabilities(
    frameworks: Sequence[FrameworkCapabilityView],
    parameters: Sequence[ParameterDefinition],
    *,
    contracts: Sequence[ContractSupport],
    methods: Sequence[MethodSupport],
    ctx: EnvelopeContext,
) -> CcureCapabilitiesV1:
    if not methods:
        raise MappingError(
            "capabilities: no method support supplied; an empty list would "
            "state that Audit implements no assessment method"
        )
    data = {
        "contracts": [
            {
                "contract": c.contract,
                "schema_versions": list(c.schema_versions),
                "direction": c.direction,
                "status": c.status,
            }
            for c in contracts
        ],
        "frameworks": [
            _framework(f) for f in frameworks if f.framework.active_in_installation
        ],
        "baseline_parameters": [
            {
                "name": p.name,
                "datatype": p.datatype,
                "unit": p.unit,
                "honoured": p.honoured,
                "description": p.description,
            }
            for p in parameters
        ],
        "methods": [
            {"method": m.method, "implemented": m.implemented, "note": m.note}
            for m in methods
        ],
    }
    return build(
        CcureCapabilitiesV1,
        {**envelope(CAPABILITIES_CONTRACT, ctx), "data": data},
        "capabilities",
    )
