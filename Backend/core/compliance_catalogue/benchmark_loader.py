"""
core/compliance_catalogue/benchmark_loader.py
─────────────────────────────────────────────────────────────────────────────
Writes a benchmark pack into the tables the compliance engine already has.

Compliance's catalogue writer since G4, which moved it unchanged from
``core/benchmarks/loader.py``; that path is an alias of this module.

    BenchmarkPack ──> compliance_frameworks   (one row, the benchmark)
                 ├──> compliance_controls     (one row per recommendation)
                 ├──> compliance_rules        (one row per *automated* control)
                 └──> compliance_rule_controls(the junction, so a verdict lands
                                               on the control that asked for it)

No new table. A benchmark is a framework: it has controls, policies, scan runs,
scores, findings and a report already, and every one of those works the moment
the rows exist. That is the whole reason Phase 3 put configuration rules in
``compliance_rules`` rather than a table of their own.

The rule that keeps two engines from fighting
─────────────────────────────────────────────
``compliance_tasks.run_scan_task`` evaluates every active rule linked to a
control in the framework being scanned. Benchmark rules are *not* evaluated
there — they are evaluated by the configuration audit during a credentialed
scan, against a live host, and synced afterwards.

If the compliance scan also evaluated them it would find no ``key`` in the
check definition, treat the evidence as missing, and write ``manual_review``
**over the real verdict the host scan produced**. So ``run_scan_task`` skips
rules carrying ``check_definition.config_check`` and leaves those findings to
their owner. The marker is why Phase 3 put it there.

Idempotence, and why a partial load is refused
──────────────────────────────────────────────
Loading the same pack twice must converge, not duplicate: ids are derived from
the benchmark code and the control's own number, so the second run updates the
first run's rows. And the whole pack is written in one transaction — a pack
that fails halfway would otherwise leave a framework whose control count is
short, which scores better than the complete one and gives no sign of it.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from core.benchmarks.pack import (
    ASSESSMENT_UNIMPLEMENTED,
    BenchmarkControl,
    BenchmarkPack,
)
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceRuleControl,
)

log = logging.getLogger("ccure.benchmarks.loader")

__all__ = ["LoadResult", "load_pack_into_db", "BENCHMARK_EVIDENCE_SOURCE"]

#: ``compliance_rules.evidence_source`` for a benchmark rule.
#:
#: Deliberately not one of ``CREDENTIALED_EVIDENCE_SOURCES``: that set gates a
#: rule behind ``asset.custom_attributes['credentialed_status'] == 'success'``
#: in the *compliance* scan, and these rules never run there. It is also not an
#: evidence-adapter key, so nothing tries to look one up. It exists to say, in
#: the row itself, which engine owns the verdict.
BENCHMARK_EVIDENCE_SOURCE = "config_audit"

#: ``compliance_controls.theme`` for every benchmark control. See migration
#: c5d6e7f8a9b0 for why there is one value rather than one per section.
BENCHMARK_THEME = "BENCHMARK"

#: Severity → the numeric weight the compliance score multiplies by. Mirrors
#: the values ``scripts/seed_real_rules.py`` already uses so a benchmark rule
#: and a hand-seeded rule of the same severity weigh the same.
_SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}

_ID_SAFE = re.compile(r"[^a-z0-9]+")


def _slug(value: str) -> str:
    """
    Reduce a benchmark's own control number to something safe in an id.

    ``2.3.1.1`` becomes ``2_3_1_1``. Dots and dashes fold to the same
    character so that two spellings of one recommendation cannot become two
    control rows — the same rule ``definition_id_for_check`` applies to
    catalogue identifiers, and for the same reason.
    """
    return _ID_SAFE.sub("_", str(value).strip().lower()).strip("_")


def control_row_id(pack: BenchmarkPack, control_id: str) -> str:
    return f"cct_{pack.code.lower()}_{_slug(control_id)}"


def rule_row_id(pack: BenchmarkPack, control_id: str) -> str:
    return f"rule_{pack.code.lower()}_{_slug(control_id)}"


@dataclass
class LoadResult:
    """What one load did, for the operator and for the tracker's figures."""

    framework_id: str
    framework_created: bool = False
    controls_created: int = 0
    controls_updated: int = 0
    rules_created: int = 0
    rules_updated: int = 0
    rules_archived: int = 0
    links_created: int = 0
    counts: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "framework_id": self.framework_id,
            "framework_created": self.framework_created,
            "controls_created": self.controls_created,
            "controls_updated": self.controls_updated,
            "rules_created": self.rules_created,
            "rules_updated": self.rules_updated,
            "rules_archived": self.rules_archived,
            "links_created": self.links_created,
            "counts": dict(self.counts),
        }


def _control_tags(control: BenchmarkControl) -> List[str]:
    """
    Tags carry what the fixed columns cannot.

    ``assessment:unimplemented`` is the load-bearing one: ``scannability`` maps
    it to ``manual`` (nothing automated runs), which is correct but loses the
    difference between "a human must judge this" and "we have not built it
    yet". The coverage figures need that difference, so it is kept here.
    """
    tags = [f"assessment:{control.assessment}"]
    if control.section:
        tags.append(f"section:{control.section}")
    for profile in control.profiles:
        tags.append(f"profile:{profile}")
    return tags


def _upsert_framework(
    db: Session, pack: BenchmarkPack
) -> tuple[ComplianceFramework, bool]:
    framework = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == pack.framework_id)
        .first()
    )
    created = framework is None
    if created:
        framework = ComplianceFramework(
            id=pack.framework_id,
            tenant_id=None,  # a benchmark is a global standard, like the rest
            code=pack.code,
            name=pack.name,
            version=pack.version,
            is_active=True,
        )
        db.add(framework)
    else:
        # A benchmark republished at a new version keeps its framework row and
        # moves the version forward; the controls converge below.
        framework.name = pack.name
        framework.version = pack.version
    db.flush()
    return framework, created


def _upsert_control(
    db: Session, pack: BenchmarkPack, control: BenchmarkControl
) -> bool:
    row_id = control_row_id(pack, control.control_id)
    row = db.query(ComplianceControl).filter(ComplianceControl.id == row_id).first()
    created = row is None
    if created:
        row = ComplianceControl(id=row_id, framework_id=pack.framework_id)
        db.add(row)

    row.control_number = control.control_id
    row.theme = BENCHMARK_THEME
    row.title = control.title
    # A control with no description of its own falls back to its title rather
    # than to an empty string: the register renders this field, and a blank
    # cell reads as missing data rather than as "the title says it".
    row.description = control.description or control.title
    row.scannability = control.scannability
    row.scan_module_hint = "config_audit" if control.is_automated else None
    row.crosswalk = list(control.crosswalk)
    row.evidence_checklist = []
    row.tags = _control_tags(control)
    row.profiles = list(control.profiles)
    db.flush()
    return created


def _upsert_rule(
    db: Session, pack: BenchmarkPack, control: BenchmarkControl
) -> tuple[bool, bool]:
    """
    Write the rule for an automated control.

    Returns ``(created, archived)``. A control that *was* automated and is no
    longer — the pack changed, or the check was withdrawn — has its rule
    archived rather than deleted: ``run_scan_task`` evaluates ``active`` rules
    only, and the row is the record that the check once existed.
    """
    row_id = rule_row_id(pack, control.control_id)
    row = db.query(ComplianceRule).filter(ComplianceRule.id == row_id).first()

    if not control.is_automated:
        if row is not None and row.status == "active":
            row.status = "archived"
            db.flush()
            return False, True
        return False, False

    created = row is None
    if created:
        row = ComplianceRule(
            id=row_id,
            rule_family_code=f"{pack.code.lower()}_{_slug(control.control_id)}",
            version_number=1,
        )
        db.add(row)

    assert control.check is not None  # guaranteed by BenchmarkControl
    row.check_type = control.check.check_type
    row.evidence_source = BENCHMARK_EVIDENCE_SOURCE
    row.target_platform = pack.platform
    row.check_definition = control.check.to_check_definition()
    row.severity = control.severity
    row.severity_weight = _SEVERITY_WEIGHT[control.severity]
    row.tags = _control_tags(control)
    row.status = "active"
    db.flush()
    return created, False


def _link_rule_to_control(db: Session, pack: BenchmarkPack, control_id: str) -> bool:
    rule_id = rule_row_id(pack, control_id)
    control_row = control_row_id(pack, control_id)
    existing = (
        db.query(ComplianceRuleControl)
        .filter(
            ComplianceRuleControl.rule_id == rule_id,
            ComplianceRuleControl.control_id == control_row,
        )
        .first()
    )
    if existing:
        return False
    db.add(ComplianceRuleControl(rule_id=rule_id, control_id=control_row))
    db.flush()
    return True


def load_pack_into_db(
    db: Session, pack: BenchmarkPack, *, commit: bool = True
) -> LoadResult:
    """
    Write *pack* into the compliance tables, converging on re-run.

    The caller owns the transaction when ``commit`` is False, which is what
    lets a test load a pack inside its own rollback and what lets a script load
    several packs atomically.
    """
    result = LoadResult(framework_id=pack.framework_id, counts=pack.counts())

    _, result.framework_created = _upsert_framework(db, pack)

    for control in pack.controls:
        if _upsert_control(db, pack, control):
            result.controls_created += 1
        else:
            result.controls_updated += 1

        created, archived = _upsert_rule(db, pack, control)
        if created:
            result.rules_created += 1
        elif archived:
            result.rules_archived += 1
        elif control.is_automated:
            result.rules_updated += 1

        if control.is_automated and _link_rule_to_control(db, pack, control.control_id):
            result.links_created += 1

    if commit:
        db.commit()

    log.info(
        "Benchmark %s v%s loaded: %d controls (%d automated, %d manual, "
        "%d unimplemented), %d rules",
        pack.code,
        pack.version,
        result.counts.get("total", 0),
        result.counts.get("automated", 0),
        result.counts.get("manual", 0),
        result.counts.get(ASSESSMENT_UNIMPLEMENTED, 0),
        result.rules_created + result.rules_updated,
    )
    return result
