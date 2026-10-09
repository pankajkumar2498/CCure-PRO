"""
BaselineMappingService — how Audit can assess a received policy baseline.

Phase 5 step 5.3. **Stateless**: a baseline goes in, a coverage view comes out.
Nothing is stored and nothing is activated — storing a received baseline and
its ``pending_review`` → active workflow (Phase 4 review, Q1) belong to the
integration phase. This is the computation that phase will call.

Three independent answers, each from one function that is tested on its own:

* **Controls** — every baseline control is resolved through
  :class:`ComplianceCatalogueService` and classified by its ``classify_control``
  rule. This module never decides a mapping state itself.
* **Parameters** — :func:`parameter_handling`. Audit has **no parameter
  vocabulary yet**: its rules take no parameters until plan Phase 17. So every
  parameter is ``unknown_parameter`` today, with the value recorded and the
  reason given — never silently ignored and never reported as honoured.
* **Scope** — :func:`evaluate_scope_cidrs`. A baseline's scope may only
  **narrow** the organisation's authorised scan scope
  (``core.scan_scope.scope_for_org``, the same policy scan admission applies).
  An entry outside it is rejected and listed; Policy Pro is not a scan
  authorisation.

Takes and returns views only; imports no contract type.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from sqlalchemy.orm import Session

from ccure_audit.services.compliance_catalogue import (
    MAPPING_ATTESTATION_REQUIRED,
    MAPPING_AUTOMATED,
    MAPPING_PARTIALLY_AUTOMATED,
    MAPPING_STATES,
    MAPPING_UNKNOWN_CONTROL,
    MAPPING_UNSUPPORTED,
    CatalogueRuleView,
    ComplianceCatalogueService,
    ControlKey,
    ControlMappingView,
)
from ccure_audit.services.views import view
from core.scan_scope import org_scan_scope, scope_for_org
from db.models.assets import Asset, AssetTag

ParameterValue = Union[bool, int, float, str]

# ── Parameter vocabulary ──────────────────────────────────────────────────────

PARAM_HONOURED = "honoured"
PARAM_RECORDED_NOT_HONOURED = "recorded_not_honoured"
PARAM_UNKNOWN = "unknown_parameter"
PARAM_INVALID_VALUE = "invalid_value"

PARAMETER_HANDLINGS: Tuple[str, ...] = (
    PARAM_HONOURED,
    PARAM_RECORDED_NOT_HONOURED,
    PARAM_UNKNOWN,
    PARAM_INVALID_VALUE,
)


@view
class ParameterDefinition:
    """A parameter a baseline may set, and whether Audit's rules use it."""

    name: str
    datatype: str  # integer | number | boolean | string
    unit: Optional[str]
    description: str
    honoured: bool


#: The parameters Audit understands. **Empty, deliberately**: no Audit rule
#: takes a parameter yet (plan Phase 17). Adding an entry here is a promise
#: that the name means something to Audit; do not add one until a rule reads
#: it, or add it with ``honoured=False`` so it is reported as recorded.
PARAMETER_VOCABULARY: Tuple[ParameterDefinition, ...] = ()

_DATATYPE_CHECKS = {
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "string": lambda v: isinstance(v, str),
}


# ── Views ─────────────────────────────────────────────────────────────────────


@view
class BaselineParameterInput:
    name: str
    value: ParameterValue
    unit: Optional[str]


@view
class BaselineControlInput:
    requirement_id: str
    control: ControlKey
    #: False when the policy owner declared the control not applicable.
    applicable: bool
    parameters: Tuple[BaselineParameterInput, ...]


@view
class BaselineScopeInput:
    cidrs: Tuple[str, ...]
    asset_tags: Tuple[str, ...]


@view
class BaselineInput:
    """A received baseline, already translated out of the contract by the adapter."""

    baseline_id: str
    baseline_version: int
    controls: Tuple[BaselineControlInput, ...]
    scope: Optional[BaselineScopeInput]


@view
class ParameterOutcomeView:
    requirement_id: str
    name: str
    handling: str
    reason: Optional[str]


@view
class ControlCoverageView:
    requirement_id: str
    applicable: bool
    #: The catalogue's answer, unchanged: state, reason, framework, rules.
    mapping: ControlMappingView
    #: The rules that would assess the control automatically — the active,
    #: non-placeholder ones. Empty unless automated or partially automated.
    assessing_rules: Tuple[CatalogueRuleView, ...]
    #: Facts reported *beside* the state, never folded into it: a framework
    #: the tenant has not installed, a control declared not applicable.
    notes: Tuple[str, ...]


@view
class ScopeRejectionView:
    entry: str
    reason: str


@view
class ScopeOutcomeView:
    requested: bool
    #: False when the organisation has no scan scope configured (NULL) and
    #: REQUIRE_SCAN_SCOPE is off: the baseline then narrows an unrestricted
    #: scope, and the report says so rather than implying a check was made.
    org_scope_configured: bool
    accepted_cidrs: Tuple[str, ...]
    rejected_cidrs: Tuple[ScopeRejectionView, ...]
    asset_tags: Tuple[str, ...]
    #: Tags no asset of this tenant carries today. Not rejected — a tag can
    #: only narrow, and may be applied later — but reported, because a scope
    #: that matches nothing assesses nothing.
    unmatched_tags: Tuple[str, ...]

    @property
    def applied(self) -> bool:
        return bool(self.accepted_cidrs or self.asset_tags)


@view
class CoverageCountsView:
    controls_total: int
    automated: int
    partially_automated: int
    attestation_required: int
    unknown_control: int
    unsupported: int


@view
class CoverageView:
    baseline_id: str
    baseline_version: int
    counts: CoverageCountsView
    controls: Tuple[ControlCoverageView, ...]
    parameters: Tuple[ParameterOutcomeView, ...]
    scope: ScopeOutcomeView


# ── The rules ────────────────────────────────────────────────────────────────


def parameter_handling(
    name: str,
    value: ParameterValue,
    vocabulary: Sequence[ParameterDefinition],
) -> Tuple[str, Optional[str]]:
    """
    What Audit does with one parameter: ``(handling, reason)``.

    Unknown name → ``unknown_parameter``; known name, wrong type →
    ``invalid_value``; known and used by a rule → ``honoured``; known and not
    used → ``recorded_not_honoured``. Every outcome but ``honoured`` says why.
    """
    by_name = {d.name: d for d in vocabulary}
    definition = by_name.get(name)
    if definition is None:
        if not vocabulary:
            return (
                PARAM_UNKNOWN,
                "Audit has no parameter vocabulary yet: its rules take no "
                "parameters (plan Phase 17). The value is recorded, not applied.",
            )
        return (
            PARAM_UNKNOWN,
            f"Audit does not define a parameter named {name!r}. The value is "
            "recorded, not applied.",
        )
    check = _DATATYPE_CHECKS.get(definition.datatype)
    if check is None or not check(value):
        return (
            PARAM_INVALID_VALUE,
            f"{name!r} takes a {definition.datatype}; got {type(value).__name__}.",
        )
    if definition.honoured:
        return PARAM_HONOURED, None
    return (
        PARAM_RECORDED_NOT_HONOURED,
        f"Audit knows {name!r} but no rule uses it yet; the value is recorded "
        "and reported.",
    )


def evaluate_scope_cidrs(
    entries: Iterable[str],
    org_scope: Optional[Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]],
) -> Tuple[Tuple[str, ...], Tuple[ScopeRejectionView, ...]]:
    """
    Split baseline CIDRs into (accepted, rejected) against the organisation's
    authorised scope, as returned by ``core.scan_scope.scope_for_org``:

    * ``None`` — no scope configured, scanning unrestricted: every valid entry
      narrows it and is accepted;
    * ``[]`` — the organisation scans nothing: every entry is rejected;
    * networks — an entry is accepted only if it lies entirely inside one of
      them. Overlapping is not enough: the part outside would widen the scope.

    Accepted entries are returned in canonical form, first occurrence kept.
    """
    accepted: List[str] = []
    rejected: List[ScopeRejectionView] = []
    for raw in entries:
        text = str(raw).strip()
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            rejected.append(
                ScopeRejectionView(entry=text, reason="Not a valid CIDR block.")
            )
            continue
        canonical = str(network)
        if org_scope is None:
            accepted.append(canonical)
            continue
        if not org_scope:
            rejected.append(
                ScopeRejectionView(
                    entry=text,
                    reason="The organisation's scan scope denies all scanning.",
                )
            )
            continue
        inside = any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in org_scope
        )
        if inside:
            accepted.append(canonical)
        else:
            rejected.append(
                ScopeRejectionView(
                    entry=text,
                    reason="Outside the organisation's authorised scan scope; a "
                    "baseline may only narrow it.",
                )
            )
    return tuple(dict.fromkeys(accepted)), tuple(rejected)


# ── The service ───────────────────────────────────────────────────────────────


class BaselineMappingService:
    """Map a received baseline onto Audit's catalogue for one tenant."""

    def __init__(
        self,
        db: Session,
        *,
        catalogue: Optional[ComplianceCatalogueService] = None,
        parameter_vocabulary: Sequence[ParameterDefinition] = PARAMETER_VOCABULARY,
    ) -> None:
        self._db = db
        self._catalogue = catalogue or ComplianceCatalogueService(db)
        self._vocabulary = tuple(parameter_vocabulary)

    def map_baseline(self, *, org_id: str, baseline: BaselineInput) -> CoverageView:
        if not org_id:
            raise ValueError("org_id is required: a baseline belongs to one tenant")
        # None exactly when the organisation does not exist.
        org_scope = org_scan_scope(self._db, org_id)
        if org_scope is None:
            raise ValueError(f"unknown organisation {org_id!r}")

        seen: set = set()
        for control in baseline.controls:
            if control.requirement_id in seen:
                raise ValueError(f"duplicate requirement_id {control.requirement_id!r}")
            seen.add(control.requirement_id)

        mappings = self._catalogue.resolve_controls(
            org_id=org_id, keys=[c.control for c in baseline.controls]
        )

        controls: List[ControlCoverageView] = []
        parameters: List[ParameterOutcomeView] = []
        counts: Dict[str, int] = {state: 0 for state in MAPPING_STATES}
        for control, mapping in zip(baseline.controls, mappings):
            counts[mapping.state] += 1
            controls.append(
                ControlCoverageView(
                    requirement_id=control.requirement_id,
                    applicable=control.applicable,
                    mapping=mapping,
                    assessing_rules=_assessing_rules(mapping),
                    notes=_notes(control, mapping),
                )
            )
            for param in control.parameters:
                handling, reason = parameter_handling(
                    param.name, param.value, self._vocabulary
                )
                parameters.append(
                    ParameterOutcomeView(
                        requirement_id=control.requirement_id,
                        name=param.name,
                        handling=handling,
                        reason=reason,
                    )
                )

        return CoverageView(
            baseline_id=baseline.baseline_id,
            baseline_version=baseline.baseline_version,
            counts=CoverageCountsView(
                controls_total=len(controls),
                automated=counts[MAPPING_AUTOMATED],
                partially_automated=counts[MAPPING_PARTIALLY_AUTOMATED],
                attestation_required=counts[MAPPING_ATTESTATION_REQUIRED],
                unknown_control=counts[MAPPING_UNKNOWN_CONTROL],
                unsupported=counts[MAPPING_UNSUPPORTED],
            ),
            controls=tuple(controls),
            parameters=tuple(parameters),
            scope=self._scope(org_scope, baseline.scope),
        )

    def _scope(self, org_view, scope: Optional[BaselineScopeInput]) -> ScopeOutcomeView:
        org_scope = scope_for_org(org_view)
        configured = org_view.configured
        if scope is None:
            return ScopeOutcomeView(
                requested=False,
                org_scope_configured=configured,
                accepted_cidrs=(),
                rejected_cidrs=(),
                asset_tags=(),
                unmatched_tags=(),
            )
        accepted, rejected = evaluate_scope_cidrs(scope.cidrs, org_scope)
        tags = tuple(dict.fromkeys(t.strip() for t in scope.asset_tags if t.strip()))
        return ScopeOutcomeView(
            requested=True,
            org_scope_configured=configured,
            accepted_cidrs=accepted,
            rejected_cidrs=rejected,
            asset_tags=tags,
            unmatched_tags=self._unmatched_tags(org_view.org_id, tags),
        )

    def _unmatched_tags(self, org_id: str, tags: Tuple[str, ...]) -> Tuple[str, ...]:
        if not tags:
            return ()
        present = {
            t
            for (t,) in self._db.query(AssetTag.tag)
            .join(Asset, Asset.id == AssetTag.asset_id)
            .filter(Asset.org_id == org_id, AssetTag.tag.in_(list(tags)))
            .distinct()
            .all()
        }
        return tuple(t for t in tags if t not in present)


def _assessing_rules(mapping: ControlMappingView) -> Tuple[CatalogueRuleView, ...]:
    if mapping.state not in (MAPPING_AUTOMATED, MAPPING_PARTIALLY_AUTOMATED):
        return ()
    return tuple(r for r in mapping.rules if not r.is_attestation_placeholder)


def _notes(
    control: BaselineControlInput, mapping: ControlMappingView
) -> Tuple[str, ...]:
    notes: List[str] = []
    if not control.applicable:
        notes.append(
            "Declared not applicable by the baseline; Audit reports it as "
            "not applicable and does not assess it."
        )
    fw = mapping.framework
    if (
        fw is not None
        and fw.active_in_installation
        and not fw.installed_for_tenant
        and mapping.state != MAPPING_UNKNOWN_CONTROL
    ):
        notes.append(
            f"Framework {fw.code} {fw.version} is not installed for this "
            "tenant; Audit will not assess the control until it is."
        )
    return tuple(notes)


__all__ = [
    "PARAMETER_HANDLINGS",
    "PARAMETER_VOCABULARY",
    "PARAM_HONOURED",
    "PARAM_INVALID_VALUE",
    "PARAM_RECORDED_NOT_HONOURED",
    "PARAM_UNKNOWN",
    "BaselineControlInput",
    "BaselineInput",
    "BaselineMappingService",
    "BaselineParameterInput",
    "BaselineScopeInput",
    "ControlCoverageView",
    "CoverageCountsView",
    "CoverageView",
    "ParameterDefinition",
    "ParameterOutcomeView",
    "ScopeOutcomeView",
    "ScopeRejectionView",
    "evaluate_scope_cidrs",
    "parameter_handling",
]
