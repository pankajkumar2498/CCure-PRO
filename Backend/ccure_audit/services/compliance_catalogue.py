"""
ComplianceCatalogueService — what Audit's compliance catalogue can assess.

Phase 5 step 5.2. A **read** service over the existing catalogue tables
(``compliance_frameworks``, ``compliance_controls``, ``compliance_rule_controls``,
``compliance_rules``, ``compliance_tenant_frameworks``). It changes nothing in
the compliance engine and writes nothing.

It answers two questions, for one tenant:

* **How can Audit assess this control?** — :meth:`resolve_controls`, one
  :class:`ControlMappingView` per ``(framework code, framework version, control
  id)`` asked about. Serves contract 1 (``BaselineCoverage``).
* **Which frameworks can Audit assess for this tenant?** —
  :meth:`framework_capabilities`. Serves the ``Capabilities`` resource.

The mapping state is decided by one pure function, :func:`classify_control`,
over the control's catalogue facts and its rules. The service only gathers
those facts; it never decides a state itself, so the rule has exactly one
implementation and is tested on its own.

A mapping state describes Audit's **capability**, never a verdict. No state
here says a control passed, and the absence of a rule never makes a control
automated: a known control with no active rule is ``unsupported``.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ccure_audit.services.views import view
from core.compliance_frameworks import is_active as framework_is_active_here
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)

# ── Vocabulary ────────────────────────────────────────────────────────────────
# Audit's own spelling. The integration adapter maps these onto the contract's
# BaselineMappingState; this module never imports a contract type.

MAPPING_AUTOMATED = "automated"
MAPPING_PARTIALLY_AUTOMATED = "partially_automated"
MAPPING_ATTESTATION_REQUIRED = "attestation_required"
MAPPING_UNKNOWN_CONTROL = "unknown_control"
MAPPING_UNSUPPORTED = "unsupported"

MAPPING_STATES: Tuple[str, ...] = (
    MAPPING_AUTOMATED,
    MAPPING_PARTIALLY_AUTOMATED,
    MAPPING_ATTESTATION_REQUIRED,
    MAPPING_UNKNOWN_CONTROL,
    MAPPING_UNSUPPORTED,
)

#: The rule status that counts. ``archived`` and ``draft`` rules are not run by
#: the compliance scan (``run_scan_task`` evaluates ``active`` only), so they
#: cannot make a control assessable.
ACTIVE_RULE_STATUS = "active"

#: The evidence source that marks a manual attestation placeholder — the rule
#: ``seed_real_rules`` generates for a control with no automated check.
ATTESTATION_EVIDENCE_SOURCE = "manual"


# ── Views ─────────────────────────────────────────────────────────────────────


@view
class ControlKey:
    """A control as another module names it."""

    framework_code: str
    framework_version: str
    control_id: str


@view
class CatalogueRuleView:
    rule_id: str
    title: str
    check_type: str
    evidence_source: str
    target_platform: str
    severity: str
    status: str

    @property
    def is_active(self) -> bool:
        return self.status == ACTIVE_RULE_STATUS

    @property
    def is_attestation_placeholder(self) -> bool:
        return self.evidence_source == ATTESTATION_EVIDENCE_SOURCE


@view
class CatalogueFrameworkView:
    framework_id: str
    code: str
    version: str
    name: str
    #: Offered by this installation (``core.compliance_frameworks.is_active``).
    #: A parked catalogue is seeded but not assessed.
    active_in_installation: bool
    #: Installed and enabled by this tenant (``compliance_tenant_frameworks``).
    installed_for_tenant: bool


@view
class ControlClassification:
    state: str
    reason: Optional[str]


@view
class ControlMappingView:
    key: ControlKey
    state: str
    reason: Optional[str]
    framework: Optional[CatalogueFrameworkView]
    control_ref: Optional[str]
    control_title: Optional[str]
    #: The catalogue's own claim (``auto``/``semi_auto``/``manual``). Reported
    #: beside the state for review; the state is derived from rules, never
    #: from this field.
    scannability: Optional[str]
    #: Active rules only, in rule-id order.
    rules: Tuple[CatalogueRuleView, ...]


@view
class FrameworkCapabilityView:
    framework: CatalogueFrameworkView
    controls_total: int
    controls_automated: int
    controls_partially_automated: int
    controls_attestation_required: int
    controls_unsupported: int


# ── The classification rule ───────────────────────────────────────────────────


def classify_control(
    *,
    known: bool,
    framework_active: bool,
    rules: Iterable[CatalogueRuleView],
) -> ControlClassification:
    """
    How Audit can assess one control. The approved rule (Phase 5 review):

    * ``automated`` — at least one active rule whose evidence source is not
      ``manual``, and no active manual placeholder;
    * ``partially_automated`` — at least one such rule **and** an active manual
      placeholder;
    * ``attestation_required`` — every active rule is a manual placeholder.

    and the two states the Phase 4 contract defines for what is left:

    * ``unknown_control`` — the catalogue does not know the control;
    * ``unsupported`` — the control is known but Audit cannot assess it: its
      framework is parked in this installation, or it has no active rule of any
      kind, so Audit can neither check it nor record an attestation for it.

    Only active rules count. No rule never means automated.
    """
    if not known:
        return ControlClassification(
            state=MAPPING_UNKNOWN_CONTROL,
            reason="The control is not in Audit's compliance catalogue.",
        )
    if not framework_active:
        return ControlClassification(
            state=MAPPING_UNSUPPORTED,
            reason="The framework is parked in this installation; Audit does not "
            "assess it.",
        )

    active = [r for r in rules if r.is_active]
    automated = [r for r in active if not r.is_attestation_placeholder]
    placeholders = [r for r in active if r.is_attestation_placeholder]

    if automated and placeholders:
        return ControlClassification(
            state=MAPPING_PARTIALLY_AUTOMATED,
            reason=f"{len(automated)} automated rule(s); part of the control "
            "still needs a manual attestation.",
        )
    if automated:
        return ControlClassification(state=MAPPING_AUTOMATED, reason=None)
    if placeholders:
        return ControlClassification(
            state=MAPPING_ATTESTATION_REQUIRED,
            reason="No automated rule; the control is assessed by attestation.",
        )
    return ControlClassification(
        state=MAPPING_UNSUPPORTED,
        reason="The control has no active rule; Audit can neither check it nor "
        "record an attestation for it.",
    )


# ── The service ───────────────────────────────────────────────────────────────


def _rule_title(rule: ComplianceRule) -> str:
    """The configuration check's own title where it has one; otherwise the rule
    family code, which is what the compliance UI already shows."""
    definition = (
        rule.check_definition if isinstance(rule.check_definition, dict) else {}
    )
    title = definition.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    return str(rule.rule_family_code or rule.id)


def _rule_view(rule: ComplianceRule) -> CatalogueRuleView:
    return CatalogueRuleView(
        rule_id=str(rule.id),
        title=_rule_title(rule),
        check_type=str(rule.check_type or ""),
        evidence_source=str(rule.evidence_source or ""),
        target_platform=str(rule.target_platform or ""),
        severity=str(rule.severity or ""),
        status=str(rule.status or ""),
    )


class ComplianceCatalogueService:
    """Read-only questions about Audit's compliance catalogue, for one tenant."""

    def __init__(self, db: Session) -> None:
        self._db = db

    # ── frameworks ────────────────────────────────────────────────────────

    def _visible_frameworks(
        self, org_id: str, codes: Optional[Sequence[str]] = None
    ) -> List[ComplianceFramework]:
        """
        Frameworks this tenant can see: global ones and its own. The same
        filter the compliance marketplace applies. Another tenant's private
        framework is never visible, and is reported as unknown.
        """
        query = self._db.query(ComplianceFramework).filter(
            or_(
                ComplianceFramework.tenant_id.is_(None),
                ComplianceFramework.tenant_id == org_id,
            )
        )
        if codes is not None:
            if not codes:
                return []
            query = query.filter(ComplianceFramework.code.in_(list(codes)))
        return query.order_by(ComplianceFramework.id).all()

    def _installed(self, org_id: str, framework_ids: Sequence[str]) -> set:
        if not framework_ids:
            return set()
        rows = (
            self._db.query(ComplianceTenantFramework.framework_id)
            .filter(
                ComplianceTenantFramework.tenant_id == org_id,
                ComplianceTenantFramework.is_enabled.is_(True),
                ComplianceTenantFramework.framework_id.in_(list(framework_ids)),
            )
            .all()
        )
        return {r[0] for r in rows}

    @staticmethod
    def _framework_view(
        fw: ComplianceFramework, installed: set
    ) -> CatalogueFrameworkView:
        return CatalogueFrameworkView(
            framework_id=str(fw.id),
            code=str(fw.code),
            version=str(fw.version or ""),
            name=str(fw.name or fw.code),
            active_in_installation=bool(framework_is_active_here(fw.id)),
            installed_for_tenant=fw.id in installed,
        )

    def _rules_by_control(
        self, control_ids: Sequence[str]
    ) -> Dict[str, List[CatalogueRuleView]]:
        """Every rule linked to each control, whatever its status."""
        out: Dict[str, List[CatalogueRuleView]] = {cid: [] for cid in control_ids}
        if not control_ids:
            return out
        rows = (
            self._db.query(ComplianceRuleControl.control_id, ComplianceRule)
            .join(ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id)
            .filter(ComplianceRuleControl.control_id.in_(list(control_ids)))
            .all()
        )
        for control_id, rule in rows:
            out[control_id].append(_rule_view(rule))
        for rules in out.values():
            rules.sort(key=lambda r: r.rule_id)
        return out

    # ── questions ─────────────────────────────────────────────────────────

    def resolve_controls(
        self, *, org_id: str, keys: Sequence[ControlKey]
    ) -> Tuple[ControlMappingView, ...]:
        """
        One mapping per key, in the order asked. Four queries however many keys.

        Matching is exact on framework code, framework version and control id
        (surrounding whitespace ignored). Identifier normalisation across
        naming conventions is open decision D3 and is not guessed at here: a
        near miss is ``unknown_control``, never a silent match.
        """
        if not org_id:
            raise ValueError("org_id is required: the catalogue view is per tenant")
        keys = tuple(keys)
        codes = sorted({k.framework_code.strip() for k in keys})
        frameworks = self._visible_frameworks(org_id, codes)

        # (code, version) → framework. A tenant's own framework wins over a
        # global one of the same code and version, deterministically.
        by_code_version: Dict[Tuple[str, str], ComplianceFramework] = {}
        versions_by_code: Dict[str, List[str]] = {}
        for fw in sorted(frameworks, key=lambda f: (f.tenant_id is not None, f.id)):
            by_code_version[(fw.code, fw.version or "")] = fw
            versions_by_code.setdefault(fw.code, []).append(fw.version or "")

        wanted_fw_ids = sorted({fw.id for fw in by_code_version.values()})
        control_numbers = sorted({k.control_id.strip() for k in keys})
        controls: Dict[Tuple[str, str], ComplianceControl] = {}
        if wanted_fw_ids and control_numbers:
            for c in (
                self._db.query(ComplianceControl)
                .filter(
                    ComplianceControl.framework_id.in_(wanted_fw_ids),
                    ComplianceControl.control_number.in_(control_numbers),
                )
                .all()
            ):
                controls[(c.framework_id, c.control_number)] = c

        installed = self._installed(org_id, wanted_fw_ids)
        rules = self._rules_by_control(sorted(c.id for c in controls.values()))

        results: List[ControlMappingView] = []
        for key in keys:
            code, version, cid = (
                key.framework_code.strip(),
                key.framework_version.strip(),
                key.control_id.strip(),
            )
            fw = by_code_version.get((code, version))
            if fw is None:
                known_versions = sorted(set(versions_by_code.get(code, [])))
                reason = (
                    f"Framework {code} version {version} is not in Audit's "
                    f"catalogue (catalogue has: {', '.join(known_versions)})."
                    if known_versions
                    else f"Framework {code} is not in Audit's catalogue."
                )
                results.append(
                    ControlMappingView(
                        key=key,
                        state=MAPPING_UNKNOWN_CONTROL,
                        reason=reason,
                        framework=None,
                        control_ref=None,
                        control_title=None,
                        scannability=None,
                        rules=(),
                    )
                )
                continue

            fw_view = self._framework_view(fw, installed)
            control = controls.get((fw.id, cid))
            if control is None:
                results.append(
                    ControlMappingView(
                        key=key,
                        state=MAPPING_UNKNOWN_CONTROL,
                        reason=f"Control {cid} is not in {code} {version}.",
                        framework=fw_view,
                        control_ref=None,
                        control_title=None,
                        scannability=None,
                        rules=(),
                    )
                )
                continue

            linked = rules.get(control.id, [])
            decided = classify_control(
                known=True,
                framework_active=fw_view.active_in_installation,
                rules=linked,
            )
            results.append(
                ControlMappingView(
                    key=key,
                    state=decided.state,
                    reason=decided.reason,
                    framework=fw_view,
                    control_ref=str(control.id),
                    control_title=str(control.title or ""),
                    scannability=(
                        str(control.scannability) if control.scannability else None
                    ),
                    rules=tuple(r for r in linked if r.is_active),
                )
            )
        return tuple(results)

    def framework_capabilities(
        self, *, org_id: str
    ) -> Tuple[FrameworkCapabilityView, ...]:
        """
        Every framework this tenant can see, with how many of its controls Audit
        can assess and how. The counts come from :func:`classify_control` over
        every control, so they cannot disagree with :meth:`resolve_controls`.
        """
        if not org_id:
            raise ValueError("org_id is required: the catalogue view is per tenant")
        frameworks = self._visible_frameworks(org_id)
        fw_ids = [fw.id for fw in frameworks]
        installed = self._installed(org_id, fw_ids)

        controls_by_fw: Dict[str, List[str]] = {fid: [] for fid in fw_ids}
        if fw_ids:
            for control_id, framework_id in (
                self._db.query(ComplianceControl.id, ComplianceControl.framework_id)
                .filter(ComplianceControl.framework_id.in_(fw_ids))
                .all()
            ):
                controls_by_fw[framework_id].append(control_id)
        rules = self._rules_by_control(
            sorted(cid for ids in controls_by_fw.values() for cid in ids)
        )

        out: List[FrameworkCapabilityView] = []
        for fw in frameworks:
            fw_view = self._framework_view(fw, installed)
            tally: Dict[str, int] = {state: 0 for state in MAPPING_STATES}
            for control_id in controls_by_fw[fw.id]:
                decided = classify_control(
                    known=True,
                    framework_active=fw_view.active_in_installation,
                    rules=rules.get(control_id, []),
                )
                tally[decided.state] += 1
            out.append(
                FrameworkCapabilityView(
                    framework=fw_view,
                    controls_total=len(controls_by_fw[fw.id]),
                    controls_automated=tally[MAPPING_AUTOMATED],
                    controls_partially_automated=tally[MAPPING_PARTIALLY_AUTOMATED],
                    controls_attestation_required=tally[MAPPING_ATTESTATION_REQUIRED],
                    controls_unsupported=tally[MAPPING_UNSUPPORTED],
                )
            )
        return tuple(out)


__all__ = [
    "MAPPING_ATTESTATION_REQUIRED",
    "MAPPING_AUTOMATED",
    "MAPPING_PARTIALLY_AUTOMATED",
    "MAPPING_STATES",
    "MAPPING_UNKNOWN_CONTROL",
    "MAPPING_UNSUPPORTED",
    "CatalogueFrameworkView",
    "CatalogueRuleView",
    "ComplianceCatalogueService",
    "ControlClassification",
    "ControlKey",
    "ControlMappingView",
    "FrameworkCapabilityView",
    "classify_control",
]
