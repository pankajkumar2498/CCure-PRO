"""
core/scap/translate.py
─────────────────────────────────────────────────────────────────────────────
Turning SCAP content into a Phase 4 benchmark pack.

This is the whole join between GAP-05 and everything that already exists. A
benchmark *is* a framework (Phase 4), a rule *is* a ``ConfigCheck`` (Phase 3),
and a failed check *is* an ordinary finding (Phase 0). So once an XCCDF rule
and its OVAL definition have been turned into a :class:`BenchmarkControl`, the
register, the score, the findings queue, the risk model, the remediation text
and the reports all work with no further code.

The three assessment states carry the phase's honesty
─────────────────────────────────────────────────────
``automated``
    The rule has an OVAL definition this build compiled. It runs.
``manual``
    The benchmark itself wants a human — the rule's only check is OCIL, or it
    has no check at all. Nothing was lost.
``unimplemented``
    The benchmark automates it and **this build cannot**, with the reason
    attached. This is where every :class:`UnsupportedConstruct` lands.

The third state is the one that keeps the coverage figures honest, and it is
why a STIG loaded here reports fewer automated controls than ``oscap`` would
rather than silently reporting the same controls as passing. A benchmark that
drops what it cannot do looks complete.

Polarity is asserted, never assumed
───────────────────────────────────
A ``compliance``-class OVAL definition is TRUE when the host is in the state
the benchmark wants. A ``vulnerability``-class definition is TRUE when the host
is *affected*. Scoring the second with the first's polarity reports every
vulnerable host as compliant. The class is read and anything but ``compliance``
is refused, rather than negated on a guess about what the author meant.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from core.benchmarks.pack import (
    ASSESSMENT_AUTOMATED,
    ASSESSMENT_MANUAL,
    ASSESSMENT_UNIMPLEMENTED,
    BenchmarkControl,
    BenchmarkPack,
    BenchmarkProfile,
    PackError,
)
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation, SpecError
from core.scap.cci import crosswalk_entries
from core.scap.oval import OvalError, UnsupportedConstruct
from core.scap.xccdf import ScapContent, XccdfRule

log = logging.getLogger("ccure.scap.translate")

__all__ = [
    "ConversionReport",
    "applies_to_from_platforms",
    "to_pack",
]

#: The OVAL definition class a benchmark rule must carry. See the module
#: docstring: the other classes invert the meaning of TRUE.
_COMPLIANCE_CLASS = "compliance"

#: CPE product → the substrings an ``os_match`` should look for in a host's
#: reported OS name. Derived from the benchmark's own ``<platform>`` element,
#: and deliberately conservative: only the vendor's own product is named.
#: A rebuild such as Rocky or AlmaLinux carrying a RHEL benchmark is a decision
#: an operator makes explicitly through ``applies_to``, not one inferred here —
#: "these distributions are close enough" is a judgement with an audit
#: consequence, and it belongs to the person signing the report.
_CPE_OS_NAMES: Mapping[str, Tuple[str, ...]] = {
    "redhat:enterprise_linux": ("red hat",),
    "centos:centos": ("centos",),
    "canonical:ubuntu_linux": ("ubuntu",),
    "debian:debian_linux": ("debian",),
    "suse:linux_enterprise_server": ("suse",),
    "oracle:linux": ("oracle",),
    "fedoraproject:fedora": ("fedora",),
    "rocky:rocky_linux": ("rocky",),
    "almalinux:almalinux": ("alma",),
}

_CPE = re.compile(r"cpe:/?/?o:([a-z0-9_.-]+):([a-z0-9_.-]+)(?::([0-9][0-9.]*))?")

#: ``check_id`` must survive ``definition_id_for_check`` inside 120 characters.
#: A STIG control id is about fifteen; the cap is here because content is not
#: ours and a pathological id must be refused rather than truncated into a
#: collision with its sibling.
_MAX_CHECK_ID = 90


@dataclass
class ConversionReport:
    """What became of each rule, so a load can be explained rather than trusted."""

    automated: int = 0
    manual: int = 0
    unimplemented: int = 0
    skipped: int = 0
    #: ``reason → count``, the unimplemented tally grouped by cause. This is
    #: the phase's own gap list, produced from real content rather than
    #: guessed at.
    reasons: Dict[str, int] = field(default_factory=dict)
    #: ``area → count`` over the OVAL test types the automated rules use.
    test_types: Dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        key = reason.strip()
        self.reasons[key] = self.reasons.get(key, 0) + 1

    def as_dict(self) -> Dict[str, Any]:
        return {
            "automated": self.automated,
            "manual": self.manual,
            "unimplemented": self.unimplemented,
            "skipped": self.skipped,
            "reasons": dict(sorted(self.reasons.items(), key=lambda kv: -kv[1])),
            "test_types": dict(sorted(self.test_types.items())),
        }

    @property
    def total(self) -> int:
        return self.automated + self.manual + self.unimplemented


def applies_to_from_platforms(platforms: Sequence[str]) -> Dict[str, Any]:
    """
    Derive ``applies_to`` from the benchmark's own CPE platform declarations.

    Returns ``{}`` when nothing recognisable is declared, which the caller must
    treat as "the operator has to say" rather than "applies everywhere". A
    benchmark with no targeting runs its RHEL package names against Ubuntu and
    reads their absence as a verdict — the failure Phase 4 added ``applies_to``
    to prevent.
    """
    names: List[str] = []
    versions: List[str] = []
    for platform in platforms:
        match = _CPE.search(str(platform).lower())
        if not match:
            continue
        vendor, product, version = match.group(1), match.group(2), match.group(3)
        names.extend(_CPE_OS_NAMES.get(f"{vendor}:{product}", ()))
        if version:
            versions.append(version)
    result: Dict[str, Any] = {}
    if names:
        result["os_name_contains"] = sorted(set(names))
    if versions:
        result["os_version_prefix"] = sorted(set(versions))
    return result


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _control_id(rule: XccdfRule, used: set[str]) -> str:
    """
    The identifier an auditor cites, made unique.

    ``<version>`` — ``RHEL-09-211010`` — is preferred over the XCCDF rule id,
    which is a URI. Where two rules share a version (it happens in content that
    splits one requirement across profiles) the rule id disambiguates, because
    a duplicate control id is refused by the pack and would fail the whole
    load over one collision.
    """
    candidate = rule.stig_id.strip() or rule.short_name or rule.rule_id
    if candidate in used:
        candidate = rule.rule_id
    return candidate


def _profile_label(profile_id: str) -> str:
    """``xccdf_org.ssgproject.content_profile_stig`` → ``stig``."""
    tail = (
        profile_id.rsplit("_profile_", 1)[-1]
        if "_profile_" in profile_id
        else profile_id
    )
    return _slug(tail) or "default"


def _compile_applicability(
    content: ScapContent, rule: XccdfRule
) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Compile the CPE applicability tree a rule is conditional on.

    Returns ``(payload, unsupported_reason)``. ``payload`` is None when the
    rule names no platform this content defines, which is the normal case for
    the benchmark's own operating-system CPE — that one is answered by
    ``applies_to`` targeting, and evaluating it twice would give two answers
    that can disagree.

    **Why this is worth the machinery.** Measured against SCAP Security Guide's
    Ubuntu 24.04 STIG profile on a container: without applicability, 128 rules
    produce verdicts that ``oscap`` correctly skips, 102 of them failures. They
    are checks about a kernel, a display manager or a PAM stack that the target
    does not have, and every one would reach a customer as a finding. The
    agreement with ``oscap`` where both reach a verdict was already 100%; this
    is about the rules where only one of us should.
    """
    definitions: Dict[str, Any] = {}
    levels: List[Mapping[str, Any]] = []
    for level in rule.platform_levels:
        # A ref with no ``<cpe:platform>`` behind it is the benchmark's own
        # operating-system CPE, which ``applies_to`` targeting already answers.
        # Evaluating it a second way would give two answers that can disagree.
        refs = [ref for ref in level if ref in content.cpe_platforms]
        if not refs:
            continue
        alternatives: List[Mapping[str, Any]] = []
        for ref in refs:
            tree = content.cpe_platforms[ref]
            try:
                _collect_facts(content, tree, definitions)
            except UnsupportedConstruct as exc:
                return None, (
                    f"the rule is conditional on platform {ref!r}, whose "
                    f"applicability check this build cannot evaluate: {exc}"
                )
            alternatives.append(tree)
        # Siblings at one level are alternatives; see XccdfRule.platform_levels.
        levels.append(
            {
                "kind": "logical",
                "operator": "OR",
                "negate": False,
                "children": [dict(tree) for tree in alternatives],
            }
        )

    if not levels:
        return None, ""

    # Levels are cumulative.
    return {
        "operator": "AND",
        "platforms": levels,
        "definitions": definitions,
    }, ""


def _collect_facts(
    content: ScapContent, node: Mapping[str, Any], into: Dict[str, Any]
) -> None:
    """Compile every OVAL definition a CPE logical test references."""
    kind = str(node.get("kind") or "")
    if kind == "logical":
        for child in node.get("children") or []:
            _collect_facts(content, child, into)
        return
    if kind == "unknown":
        raise UnsupportedConstruct(
            "the platform names a bare CPE with no check behind it, so nothing "
            "can be established about whether it applies"
        )
    if kind != "fact":
        return
    definition_id = str(node.get("definition") or "")
    if definition_id in into:
        return
    document = content.oval_for(str(node.get("href") or ""))
    if document is None:
        raise UnsupportedConstruct(
            f"the CPE OVAL document {node.get('href')!r} was not supplied"
        )
    into[definition_id] = document.compile_definition(definition_id).as_dict()


def _check_for_rule(
    content: ScapContent,
    rule: XccdfRule,
    *,
    code: str,
    values: Mapping[str, str],
    severity: str,
    profile_label: str,
) -> Tuple[Optional[ConfigCheck], str, Tuple[str, ...]]:
    """
    Build the ``scap_rule`` check for *rule*.

    Returns ``(check, unsupported_reason, test_types)``. Exactly one of the
    first two is meaningful: a check, or the reason there is none.
    """
    document = content.oval_for(rule.check_href)
    if document is None:
        return (
            None,
            f"the OVAL document {rule.check_href or '(unnamed)'} this rule "
            f"checks through was not supplied with the benchmark",
            (),
        )

    definition_class = document.definition_class(rule.check_name)
    if definition_class and definition_class != _COMPLIANCE_CLASS:
        return (
            None,
            f"the OVAL definition is class {definition_class!r} rather than "
            f"'compliance'; TRUE would mean the host is affected rather than "
            f"hardened, and scoring it as written would invert the verdict",
            (),
        )

    # ``check-export`` names OVAL variables and the XCCDF Values that fill
    # them. This is how a STIG's own parameter — a minimum password length the
    # profile refines — reaches the check.
    bindings = {
        oval_var: values[value_id]
        for oval_var, value_id in rule.check_exports.items()
        if value_id in values
    }

    try:
        compiled = document.compile_definition(rule.check_name, values=bindings)
    except UnsupportedConstruct as exc:
        return None, str(exc), ()
    except OvalError as exc:
        return None, f"the OVAL definition could not be read: {exc}", ()

    applicability, unsupported = _compile_applicability(content, rule)
    if unsupported:
        return None, unsupported, ()

    check_id = f"stig.{code}.{_slug(rule.stig_id or rule.rule_id)}"
    if len(check_id) > _MAX_CHECK_ID:
        return (
            None,
            f"the rule's identifier renders to {len(check_id)} characters, "
            f"past the {_MAX_CHECK_ID} this build will mint a catalogue key "
            f"from; truncating it would merge it with a sibling rule",
            (),
        )

    tags = ["benchmark", "stig", profile_label]
    if rule.stig_id and rule.stig_id != rule.rule_id:
        tags.append(rule.stig_id)
    tags.extend(rule.cci_ids)
    if rule.group_path:
        tags.append(rule.group_path[-1][:60])

    try:
        check = ConfigCheck(
            check_id=check_id,
            title=rule.title or rule.stig_id,
            check_type="scap_rule",
            collect=(
                {"definition": compiled.as_dict(), "applicability": applicability}
                if applicability
                else {"definition": compiled.as_dict()}
            ),
            expect=Expectation(
                "equals",
                "compliant",
                description="the host is in the state the benchmark requires",
            ),
            # Unreachable: the collector reports COLLECTED for both outcomes
            # and UNAVAILABLE for everything else, so there is no absence to
            # have a policy about. Declared because the spec requires a
            # deliberate choice, and MANUAL_REVIEW is the value that could
            # never flatter a score if the collector ever changed.
            absent=AbsencePolicy.MANUAL_REVIEW,
            platforms=("linux",),
            severity=severity,
            description=rule.description,
            rationale=rule.rationale,
            remediation=rule.fixtext,
            references=rule.reference_labels,
            tags=tuple(dict.fromkeys(tags)),
            qod=95,
            metadata={
                "gap05": True,
                "benchmark": code,
                "stig_id": rule.stig_id,
                "xccdf_rule_id": rule.rule_id,
                "oval_definition": rule.check_name,
                "oval_test_types": list(compiled.test_types),
                "platforms": list(rule.platforms),
                "cci": list(rule.cci_ids),
            },
        )
    except SpecError as exc:
        return None, f"the converted check was refused: {exc}", ()
    return check, "", compiled.test_types


def to_pack(
    content: ScapContent,
    *,
    code: str,
    publisher: str,
    licence: str,
    profile_id: Optional[str] = None,
    applies_to: Optional[Mapping[str, Any]] = None,
    source_url: str = "",
    notes: str = "",
    cci_index: Optional[Mapping[str, Sequence[str]]] = None,
    max_controls: int = 5000,
) -> Tuple[BenchmarkPack, ConversionReport]:
    """
    Convert *content* into a benchmark pack for one profile.

    *publisher* and *licence* are required by the pack and are the caller's to
    supply, because they are a claim about provenance that this code cannot
    verify. SCAP Security Guide is BSD-3-Clause and renders the DISA STIG; DISA
    publishes its own SCAP benchmarks as US Government works. Those are
    different provenances for content that looks identical, and a report has to
    be able to say which one it ran.

    *applies_to* overrides the targeting derived from the benchmark's CPE
    platforms. An operator running the RHEL 9 STIG against a rebuild such as
    Rocky supplies it deliberately; nothing here infers that two distributions
    are interchangeable.
    """
    benchmark = content.benchmark
    report = ConversionReport()

    resolved_profile = profile_id or ""
    if resolved_profile and resolved_profile not in benchmark.profiles:
        # Accept the short label as well as the full id: nobody types
        # `xccdf_org.ssgproject.content_profile_stig` twice.
        matches = [
            pid
            for pid in benchmark.profiles
            if _profile_label(pid) == _slug(resolved_profile)
        ]
        if len(matches) == 1:
            resolved_profile = matches[0]
        elif len(matches) > 1:
            raise PackError(f"profile {profile_id!r} is ambiguous: {sorted(matches)}")
        else:
            raise PackError(
                f"the benchmark declares no profile {profile_id!r}. It has "
                f"{sorted(_profile_label(p) for p in benchmark.profiles)}"
            )

    label = _profile_label(resolved_profile) if resolved_profile else "default"
    rules = benchmark.rules_in_profile(resolved_profile or None)
    if not rules:
        raise PackError(
            f"profile {profile_id!r} selects no rules, so the pack would carry "
            f"no controls"
        )
    if len(rules) > max_controls:
        raise PackError(
            f"the profile selects {len(rules)} rules, past the {max_controls} "
            f"ceiling this converter will build in one pack"
        )
    values = benchmark.values_for_profile(resolved_profile or None)

    targeting = (
        dict(applies_to)
        if applies_to is not None
        else applies_to_from_platforms(benchmark.platforms)
    )

    controls: List[BenchmarkControl] = []
    used: set[str] = set()
    for rule in rules:
        control_id = _control_id(rule, used)
        if control_id in used:
            report.skipped += 1
            continue
        used.add(control_id)

        section = rule.group_path[-1] if rule.group_path else ""
        common = {
            "control_id": control_id,
            "title": rule.title or control_id,
            "severity": rule.severity,
            "profiles": (label,),
            "section": section,
            "description": rule.description,
            "rationale": rule.rationale,
            "remediation": rule.fixtext,
            "references": rule.reference_labels,
            "crosswalk": crosswalk_entries(
                rule.idents, rule.references, cci_index=cci_index
            ),
        }

        if not rule.check_name:
            reason = (
                f"the benchmark answers this rule through {rule.unsupported_check}"
                if rule.unsupported_check
                else ""
            )
            if rule.unsupported_check and "ocil" in rule.unsupported_check.lower():
                # OCIL is a questionnaire. The benchmark is asking a human, so
                # this is `manual` — a real state, not a gap in this build.
                controls.append(
                    BenchmarkControl(assessment=ASSESSMENT_MANUAL, **common)
                )
                report.manual += 1
                continue
            if not rule.unsupported_check:
                controls.append(
                    BenchmarkControl(assessment=ASSESSMENT_MANUAL, **common)
                )
                report.manual += 1
                continue
            controls.append(
                BenchmarkControl(
                    assessment=ASSESSMENT_UNIMPLEMENTED,
                    unimplemented_reason=reason,
                    **common,
                )
            )
            report.unimplemented += 1
            report.note(reason)
            continue

        check, unsupported, test_types = _check_for_rule(
            content,
            rule,
            code=code,
            values=values,
            severity=rule.severity,
            profile_label=label,
        )
        if check is None:
            controls.append(
                BenchmarkControl(
                    assessment=ASSESSMENT_UNIMPLEMENTED,
                    unimplemented_reason=unsupported
                    or "the rule's check could not be converted",
                    **common,
                )
            )
            report.unimplemented += 1
            report.note(_generalise(unsupported))
            continue

        controls.append(
            BenchmarkControl(assessment=ASSESSMENT_AUTOMATED, check=check, **common)
        )
        report.automated += 1
        for test_type in test_types:
            report.test_types[test_type] = report.test_types.get(test_type, 0) + 1

    pack = BenchmarkPack(
        # Upper-cased to match what ``parse_pack`` produces when the same pack
        # is read back from a file, so converting and round-tripping cannot
        # yield two packs that differ in one field.
        code=str(code).strip().upper(),
        name=benchmark.title or code,
        version=benchmark.version or "unversioned",
        platform="linux",
        publisher=publisher,
        licence=licence,
        profiles=(BenchmarkProfile(id=label, title=label.upper()),),
        controls=tuple(controls),
        source_url=source_url or content.source,
        notes=notes,
        applies_to=targeting,
    )
    return pack, report


_ID_IN_MESSAGE = re.compile(r"oval:[a-z0-9._-]+:(?:def|tst|obj|ste|var):\d+", re.I)


def _generalise(reason: str) -> str:
    """
    Strip the specific OVAL ids out of a reason so the tally groups.

    Without this, 400 rules produce 400 distinct "reasons" differing only by a
    definition id, and the one number that says what to build next — how many
    rules one missing construct costs — cannot be read at all.
    """
    return _ID_IN_MESSAGE.sub("<id>", reason).strip()
