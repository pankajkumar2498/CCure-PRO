"""
core/benchmarks/pack.py
─────────────────────────────────────────────────────────────────────────────
The benchmark content format, and the parser that refuses to guess.

A *pack* is one hardening benchmark expressed as data: its identity, its
profiles, and its controls. Each control optionally carries a Phase 3
``ConfigCheck``. Nothing in this module knows what CIS is — a CIS benchmark, a
STIG, a vendor guide and an in-house baseline are the same shape, which is the
property that keeps Phase 5 from editing the engine.

Why content is a file and not code
──────────────────────────────────
Benchmark text — the recommendation wording, the rationale, the remediation —
is the publisher's, and for CIS it is licensed material. Expressing it as data
loaded from a file the operator supplies means this repository never has to
contain it, and means a customer with a CIS SecureSuite membership can load the
real thing without a code change. It also means the content can be *checked*:
see the assessment states below.

``assessment`` is declared, never inferred
──────────────────────────────────────────
The obvious design reads "has a check" as "is automated". That collapses two
facts that must stay apart, and CLAUDE.md records what it cost the last time:
eighteen ISO controls claimed ``semi_auto`` with no automated rule behind them,
and the register, the coverage figures and the SoA all read that as partial
automation.

So a control states which of three it is, and a mismatch is refused:

``automated``
    The benchmark automates it and this product implements it. A ``check`` is
    required.
``manual``
    The benchmark itself requires human judgement — a policy document, an
    interview, a physical inspection. A ``check`` is refused; there is nothing
    to automate and pretending otherwise invents a verdict.
``unimplemented``
    The benchmark automates it and **this product does not yet**. Loaded
    deliberately, so the control appears in the count and the gap is visible,
    and evaluated as not-assessed rather than quietly omitted. A benchmark that
    silently drops the controls it cannot do reports better coverage than it
    has.

That third state is the one that makes the coverage figures honest. Without it
the only way to represent an unimplemented control is to leave it out, and a
partial benchmark then looks complete.

Profiles
────────
Declared once on the pack and referenced by id from each control. A control
naming a profile the pack does not declare is refused rather than silently
creating one — a typo in ``"L1"`` would otherwise produce a profile with one
member and quietly remove that control from the real one.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from core.config_audit.spec import PLATFORMS, ConfigCheck, SpecError

__all__ = [
    "ASSESSMENT_STATES",
    "BenchmarkControl",
    "BenchmarkPack",
    "BenchmarkProfile",
    "PackError",
    "load_pack",
    "parse_pack",
]


class PackError(ValueError):
    """A benchmark pack is malformed, or claims something it cannot support."""


#: See the module docstring. The three are not interchangeable and no default
#: is provided — a control that does not declare one is refused.
ASSESSMENT_AUTOMATED = "automated"
ASSESSMENT_MANUAL = "manual"
ASSESSMENT_UNIMPLEMENTED = "unimplemented"

ASSESSMENT_STATES: Tuple[str, ...] = (
    ASSESSMENT_AUTOMATED,
    ASSESSMENT_MANUAL,
    ASSESSMENT_UNIMPLEMENTED,
)

#: ``compliance_rules.severity`` and ``compliance_controls`` are constrained to
#: these five. Deliberately not the six canonical finding severities: ``info``
#: is this table's spelling of ``none`` and ``unscored`` has no meaning for a
#: control someone deliberately rated.
PACK_SEVERITIES: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class BenchmarkProfile:
    """One selectable profile of a benchmark — CIS Level 1, Level 2, …"""

    id: str
    title: str = ""

    def __post_init__(self) -> None:
        if not str(self.id or "").strip():
            raise PackError("a profile needs an id")


@dataclass(frozen=True)
class BenchmarkControl:
    """One numbered recommendation from a benchmark."""

    #: The benchmark's own numbering, verbatim — "2.3.1.1". Never rewritten:
    #: it is how a reader cross-references the published document.
    control_id: str
    title: str
    assessment: str
    severity: str
    profiles: Tuple[str, ...] = ()
    section: str = ""
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    references: Tuple[str, ...] = ()
    #: Controls in *other* frameworks this one satisfies, "FRAMEWORK_CODE:id".
    crosswalk: Tuple[str, ...] = ()
    check: Optional[ConfigCheck] = None
    #: Why, when ``assessment`` is ``unimplemented``. Required in that state so
    #: the gap is explicable rather than merely counted.
    unimplemented_reason: str = ""

    def __post_init__(self) -> None:
        if not str(self.control_id or "").strip():
            raise PackError("a control needs a control_id")
        if not str(self.title or "").strip():
            raise PackError(f"control {self.control_id}: title is required")
        if self.assessment not in ASSESSMENT_STATES:
            raise PackError(
                f"control {self.control_id}: assessment must be one of "
                f"{ASSESSMENT_STATES}, got {self.assessment!r}. It is declared "
                f"rather than inferred so that 'the benchmark says a human must "
                f"judge this' and 'we have not written the check yet' stay "
                f"distinguishable."
            )
        if self.severity not in PACK_SEVERITIES:
            raise PackError(
                f"control {self.control_id}: severity {self.severity!r} is not "
                f"one of {PACK_SEVERITIES}"
            )

        if self.assessment == ASSESSMENT_AUTOMATED and self.check is None:
            raise PackError(
                f"control {self.control_id}: declared automated but carries no "
                f"check. Claiming automation that does not exist is how a "
                f"coverage figure comes to overstate what a scan does."
            )
        if self.assessment != ASSESSMENT_AUTOMATED and self.check is not None:
            raise PackError(
                f"control {self.control_id}: declared {self.assessment!r} but "
                f"carries a check. Use 'automated' if the check is real."
            )
        if (
            self.assessment == ASSESSMENT_UNIMPLEMENTED
            and not str(self.unimplemented_reason or "").strip()
        ):
            raise PackError(
                f"control {self.control_id}: an unimplemented control must say "
                f"why, so the gap is explicable rather than only counted."
            )

        # The control's narrative flows down into its check unless the check
        # states its own.
        #
        # Done here rather than in the JSON parser so both construction paths
        # agree: a pack built in Python behaved differently from the same pack
        # read from disk, and the field that went missing was `remediation` —
        # which is what the *security finding* renders. A benchmark control
        # would have carried remediation the finding it produced did not.
        if self.check is not None:
            inherited = {
                field: getattr(self, field)
                for field in ("description", "rationale", "remediation")
                if getattr(self, field) and not getattr(self.check, field)
            }
            if not self.check.references and self.references:
                inherited["references"] = self.references
            if inherited:
                object.__setattr__(
                    self, "check", dataclasses.replace(self.check, **inherited)
                )

    @property
    def is_automated(self) -> bool:
        return self.assessment == ASSESSMENT_AUTOMATED

    @property
    def scannability(self) -> str:
        """
        The ``compliance_controls.scannability`` value for this control.

        ``unimplemented`` maps to ``manual``, not ``auto``: nothing automated
        runs for it, and the register must not claim otherwise. The distinction
        between "manual by nature" and "not implemented yet" is kept in ``tags``
        rather than lost here.
        """
        return "auto" if self.is_automated else "manual"


@dataclass(frozen=True)
class BenchmarkPack:
    """One benchmark, at one version, for one platform."""

    code: str
    name: str
    version: str
    platform: str
    publisher: str
    #: The licence the content is supplied under. Required, and carried into
    #: the framework record so a report can attribute it. A pack that does not
    #: say is refused: content whose licence nobody recorded is content nobody
    #: can safely redistribute.
    licence: str
    profiles: Tuple[BenchmarkProfile, ...] = ()
    controls: Tuple[BenchmarkControl, ...] = ()
    source_url: str = ""
    notes: str = ""
    #: Operating-system constraints for the whole benchmark, flowed onto every
    #: check. ``platform`` says windows-or-linux; this says *which* Linux.
    #:
    #: Declared once here rather than repeated per control because a benchmark
    #: is published for one operating system — "CIS Ubuntu Linux 22.04 LTS
    #: Benchmark" — and repeating it six hundred times invites the one typo
    #: that quietly makes a control apply everywhere.
    applies_to: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("code", "name", "version", "publisher", "licence"):
            if not str(getattr(self, name) or "").strip():
                raise PackError(f"benchmark: {name} is required")
        if self.platform not in PLATFORMS:
            raise PackError(
                f"benchmark {self.code}: platform {self.platform!r} is not one "
                f"of {PLATFORMS}"
            )
        if not self.controls:
            raise PackError(f"benchmark {self.code}: contains no controls")

        if self.applies_to:
            unknown_keys = set(self.applies_to) - {
                "os_name_contains",
                "os_version_prefix",
            }
            if unknown_keys:
                raise PackError(
                    f"benchmark {self.code}: applies_to names unsupported "
                    f"key(s) {sorted(unknown_keys)}. A key nothing reads would "
                    f"look like targeting while constraining nothing."
                )
            # Flow it onto every check that does not state its own.
            object.__setattr__(
                self,
                "controls",
                tuple(
                    (
                        dataclasses.replace(
                            control,
                            check=dataclasses.replace(
                                control.check, os_match=dict(self.applies_to)
                            ),
                        )
                        if control.check is not None and not control.check.os_match
                        else control
                    )
                    for control in self.controls
                ),
            )

        seen: set[str] = set()
        for control in self.controls:
            if control.control_id in seen:
                raise PackError(
                    f"benchmark {self.code}: duplicate control_id "
                    f"{control.control_id!r}. Two rows for one recommendation "
                    f"would be scored twice."
                )
            seen.add(control.control_id)

        declared = {p.id for p in self.profiles}
        for control in self.controls:
            unknown = [p for p in control.profiles if p not in declared]
            if unknown:
                raise PackError(
                    f"benchmark {self.code}: control {control.control_id} names "
                    f"profile(s) {unknown} the benchmark does not declare "
                    f"{sorted(declared)}. A misspelled profile would remove the "
                    f"control from the real one without failing."
                )
            if control.check is not None and not control.check.applies_to_platform(
                self.platform
            ):
                raise PackError(
                    f"benchmark {self.code}: control {control.control_id} has a "
                    f"check targeting {control.check.platforms} on a "
                    f"{self.platform} benchmark; it would report not-applicable "
                    f"on every host."
                )

    # ── Derived counts, which are the coverage figures ───────────────────────

    @property
    def framework_id(self) -> str:
        """
        The ``compliance_frameworks.id`` this pack becomes.

        The ``cfw_bm_`` prefix is load-bearing: it is how
        ``core.compliance_frameworks.is_active`` tells loaded content from a
        catalogue that ships with the product, and therefore how a benchmark
        avoids being treated as a parked catalogue and scoring nothing.
        """
        from core.compliance_frameworks import BENCHMARK_FRAMEWORK_PREFIX

        return f"{BENCHMARK_FRAMEWORK_PREFIX}{self.code.lower()}"

    def controls_in_profile(self, profile: Optional[str]) -> List[BenchmarkControl]:
        """
        Controls in scope for *profile*.

        A control naming no profile is in scope for every one — the same
        reading migration c5d6e7f8a9b0 gives an empty ``profiles`` column, so
        the two cannot disagree.
        """
        if not profile:
            return list(self.controls)
        return [c for c in self.controls if not c.profiles or profile in c.profiles]

    def counts(self) -> Dict[str, int]:
        tally = {state: 0 for state in ASSESSMENT_STATES}
        for control in self.controls:
            tally[control.assessment] += 1
        tally["total"] = len(self.controls)
        return tally

    def automation_pct(self) -> float:
        """Share of controls this build actually assesses automatically."""
        if not self.controls:
            return 0.0
        automated = sum(1 for c in self.controls if c.is_automated)
        return round(100.0 * automated / len(self.controls), 1)


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────


def _tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def _parse_control(raw: Mapping[str, Any], index: int) -> BenchmarkControl:
    if not isinstance(raw, Mapping):
        raise PackError(f"controls[{index}] is {type(raw).__name__}, not an object")

    control_id = str(raw.get("control_id") or "").strip()
    assessment = str(raw.get("assessment") or "").strip().lower()

    check: Optional[ConfigCheck] = None
    raw_check = raw.get("check")
    if raw_check is not None:
        if not isinstance(raw_check, Mapping):
            raise PackError(f"control {control_id or index}: `check` must be an object")
        payload = dict(raw_check)
        payload.setdefault("check_id", control_id)
        payload.setdefault("title", raw.get("title"))
        payload.setdefault("description", raw.get("description", ""))
        payload.setdefault("rationale", raw.get("rationale", ""))
        payload.setdefault("remediation", raw.get("remediation", ""))
        payload.setdefault("references", list(_tuple(raw.get("references"))))
        try:
            check = ConfigCheck.from_check_definition(payload)
        except (SpecError, ValueError) as exc:
            # Surfaced with the control id attached: a pack of six hundred
            # controls otherwise reports a spec error with no way to find it.
            raise PackError(
                f"control {control_id or index}: check is not executable — {exc}"
            ) from exc

    return BenchmarkControl(
        control_id=control_id,
        title=str(raw.get("title") or "").strip(),
        assessment=assessment,
        severity=str(raw.get("severity") or "").strip().lower(),
        profiles=_tuple(raw.get("profiles")),
        section=str(raw.get("section") or ""),
        description=str(raw.get("description") or ""),
        rationale=str(raw.get("rationale") or ""),
        remediation=str(raw.get("remediation") or ""),
        references=_tuple(raw.get("references")),
        crosswalk=_tuple(raw.get("crosswalk")),
        check=check,
        unimplemented_reason=str(raw.get("unimplemented_reason") or ""),
    )


def parse_pack(data: Mapping[str, Any]) -> BenchmarkPack:
    """
    Build a :class:`BenchmarkPack` from decoded JSON.

    Raises :class:`PackError` on anything malformed rather than dropping it.
    A loader that skips the controls it cannot parse produces a benchmark that
    is quietly short, and a short benchmark scores better than a complete one.
    """
    if not isinstance(data, Mapping):
        raise PackError(f"pack is {type(data).__name__}, not an object")
    meta = data.get("benchmark")
    if not isinstance(meta, Mapping):
        raise PackError("pack has no `benchmark` object")
    raw_controls = data.get("controls")
    if not isinstance(raw_controls, list):
        raise PackError("pack has no `controls` array")

    profiles = tuple(
        BenchmarkProfile(
            id=str(p.get("id") or "").strip(), title=str(p.get("title") or "")
        )
        for p in (meta.get("profiles") or [])
        if isinstance(p, Mapping)
    )

    return BenchmarkPack(
        code=str(meta.get("code") or "").strip().upper(),
        name=str(meta.get("name") or "").strip(),
        version=str(meta.get("version") or "").strip(),
        platform=str(meta.get("platform") or "").strip().lower(),
        publisher=str(meta.get("publisher") or "").strip(),
        licence=str(meta.get("licence") or meta.get("license") or "").strip(),
        profiles=profiles,
        controls=tuple(_parse_control(c, i) for i, c in enumerate(raw_controls)),
        source_url=str(meta.get("source_url") or ""),
        notes=str(meta.get("notes") or ""),
        applies_to=meta.get("applies_to") or {},
    )


def load_pack(path: str | Path) -> BenchmarkPack:
    """Read and parse a pack from disk."""
    location = Path(path)
    try:
        data = json.loads(location.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PackError(f"benchmark pack not found: {location}") from exc
    except json.JSONDecodeError as exc:
        raise PackError(f"benchmark pack {location} is not valid JSON: {exc}") from exc
    try:
        return parse_pack(data)
    except PackError as exc:
        raise PackError(f"{location}: {exc}") from exc


def discover_packs(directory: str | Path) -> List[Path]:
    """Every ``*.benchmark.json`` in *directory*, sorted."""
    return sorted(Path(directory).glob("*.benchmark.json"))
