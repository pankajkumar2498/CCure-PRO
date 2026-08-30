"""
core/scap/xccdf.py
─────────────────────────────────────────────────────────────────────────────
Reading XCCDF 1.2 benchmarks, and the SCAP source datastreams that wrap them.

Two shapes reach this module and both are real
──────────────────────────────────────────────
A **source datastream** — one file containing the XCCDF benchmark, the OVAL
definitions and a catalogue tying them together. This is what SCAP Security
Guide publishes and what ``oscap`` consumes.

A **bare XCCDF benchmark** beside its OVAL file, which is how DISA publishes
its own STIG SCAP packages inside a zip. The two are read by the same code
because the difference is only where the OVAL lives.

What a Rule has to carry for this to be worth doing
───────────────────────────────────────────────────
A STIG rule is not just a check. It is a V-ID an auditor cites, a severity a
programme reports on, a CCI that maps to NIST 800-53, and fix text somebody
has to act on. Dropping any of that leaves a verdict nobody can use: "rule
xccdf_org.ssgproject.content_rule_package_aide_installed failed" is not an
audit finding. Every one of them is preserved and carried onto the control.

Profiles and Values
───────────────────
A profile selects rules and *refines values*. The refinement is the mechanism
by which one benchmark expresses "STIG wants 15 characters, CIS wants 14" over
one shared rule, so a reader that ignores ``refine-value`` silently evaluates
every parameterised rule against the wrong number. Profile inheritance
(``extends``) is resolved here, parent first.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from xml.etree import ElementTree as ET

from core.scap.oval import OvalDocument, OvalError, local_name, parse_oval

__all__ = [
    "OVAL_CHECK_SYSTEM",
    "ScapContent",
    "XccdfBenchmark",
    "XccdfError",
    "XccdfProfile",
    "XccdfRule",
    "XccdfValue",
    "load_content",
    "parse_content",
]


class XccdfError(ValueError):
    """The document is not XCCDF this reader can make sense of."""


_DOCTYPE = re.compile(r"<!DOCTYPE", re.IGNORECASE)

#: The ``@system`` of a ``<check>`` whose content is OVAL. Matched by prefix
#: because the version suffix moves (…oval-definitions-5, …-5.11).
OVAL_CHECK_SYSTEM = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

#: XCCDF severities, and how they map onto this product's five. ``unknown`` is
#: deliberately ``medium`` rather than ``info``: a rule whose author did not
#: rate it is not thereby harmless, and rating it lowest is the reading that
#: quietly removes it from every report ordered by severity.
_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "medium",
}

#: A benchmark larger than this is refused. SSG's largest datastream is about
#: 80 MB; the cap is generous, and exists so a malformed or hostile file cannot
#: exhaust the loader's memory before anything has validated it.
MAX_CONTENT_BYTES = 256 * 1024 * 1024


# ─────────────────────────────────────────────────────────────────────────────
# Model
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class XccdfValue:
    """A benchmark parameter, with the selectors a profile may choose between."""

    value_id: str
    datatype: str = "string"
    title: str = ""
    #: selector → value. The empty-string key is the default.
    options: Mapping[str, str] = field(default_factory=dict)

    def resolve(self, selector: Optional[str] = None) -> Optional[str]:
        if selector and selector in self.options:
            return self.options[selector]
        if "" in self.options:
            return self.options[""]
        # A Value whose only entries are selector-qualified and none was
        # chosen has no defensible default; returning the first would pick one
        # by document order, which is not a decision anybody made.
        return None


@dataclass(frozen=True)
class XccdfRule:
    """One benchmark rule, with everything a finding needs to be actionable."""

    rule_id: str
    title: str
    severity: str = "medium"
    description: str = ""
    rationale: str = ""
    fixtext: str = ""
    version: str = ""
    group_path: Tuple[str, ...] = ()
    selected: bool = True
    #: ``(system, value)`` pairs — CCE identifiers, CCIs, STIG rule ids.
    idents: Tuple[Tuple[str, str], ...] = ()
    #: ``(href, text)`` pairs. **Both halves are kept, and that is not
    #: tidiness.** SSG writes ``<reference href="…/cci/">CCI-000366</reference>``
    #: — the href says which catalogue, the *text* is the identifier. A reader
    #: that keeps the href alone throws away every CCI, every NIST control and
    #: every STIG id in the benchmark, and what is left is a list of URLs that
    #: are identical across hundreds of rules.
    references: Tuple[Tuple[str, str], ...] = ()
    #: The OVAL definition this rule checks through, if it has one.
    check_href: str = ""
    check_name: str = ""
    #: ``oval variable id → xccdf value id``.
    check_exports: Mapping[str, str] = field(default_factory=dict)
    #: Set where the rule declares a check system this reader does not evaluate
    #: (OCIL, a vendor's own), so the converter can say why rather than
    #: silently dropping it.
    unsupported_check: str = ""
    #: CPE platform ids this rule is conditional on, in the order they were
    #: inherited. Flat, for metadata and tags; :attr:`platform_levels` carries
    #: the structure that decides applicability.
    #:
    #: Measured on SCAP Security Guide's Ubuntu 24.04 STIG profile: all 128 of
    #: the rules ``oscap`` reported as not applicable carry one of these, and
    #: none of the 15 it reached a verdict on without a platform did. Ignoring
    #: them is not a rounding error — it is 102 findings about rules that do
    #: not apply to the host at all.
    platforms: Tuple[str, ...] = ()
    #: The same ids grouped by the element that declared them: one tuple for
    #: the Benchmark, one per enclosing Group, one for the Rule.
    #:
    #: **The nesting is the semantics, and flattening it is wrong.** Platforms
    #: declared side by side on one element are alternatives — the item applies
    #: if any holds. Platforms inherited from *different* levels are
    #: cumulative: a Group that applies only to a system with a kernel does not
    #: stop applying because a Rule inside it also names a package that happens
    #: to be installed.
    #:
    #: Flattening them into one OR was measured against ``oscap`` and left 17
    #: rules applicable that it correctly skipped — every one a rule whose
    #: Group said "a real system with a kernel" and whose Rule said "and PAM
    #: is installed". In a container the first is false and the second true.
    platform_levels: Tuple[Tuple[str, ...], ...] = ()

    @property
    def cci_ids(self) -> Tuple[str, ...]:
        """
        Every CCI this rule cites, from its idents **and** its references.

        Both, because the two publishers put them in different places: DISA's
        own SCAP uses ``<ident system="…/cci">``, and SCAP Security Guide uses
        ``<reference href="…/cci/">CCI-000366</reference>``. Reading only
        idents finds zero CCIs in an SSG datastream — measured — which silently
        removes the entire NIST crosswalk from every rule.
        """
        found = [
            value
            for system, value in self.idents
            if "cci" in system.lower() or value.upper().startswith("CCI-")
        ]
        found.extend(
            text
            for href, text in self.references
            if text.upper().startswith("CCI-")
            or ("cci" in href.lower() and text.upper().startswith("CCI-"))
        )
        return tuple(dict.fromkeys(found))

    @property
    def reference_labels(self) -> Tuple[str, ...]:
        """References as a reader wants them: the identifier, then its source."""
        labels = []
        for href, text in self.references:
            if text and href:
                labels.append(f"{text} ({href})")
            else:
                labels.append(text or href)
        return tuple(dict.fromkeys(label for label in labels if label))

    @property
    def short_name(self) -> str:
        """
        The rule's own name, with the XCCDF 1.2 identifier scaffolding removed.

        XCCDF 1.2 requires a rule id of the form ``xccdf_<reverse-dns>_rule_
        <name>``, so stripping through the first ``_rule_`` is defined by the
        specification rather than a guess about one publisher's convention.

        This matters more than it looks. **No SSG rule carries a ``<version>``
        element** — all 488 in the RHEL 9 STIG profile lack one — so every
        control id falls back to the rule id, and the raw form is long enough
        that dozens of rules exceed the identifier ceiling and are dropped as
        unconvertible. That reads as a coverage limitation and is not one.
        """
        head, sep, tail = self.rule_id.partition("_rule_")
        return tail if sep and head.startswith("xccdf") else self.rule_id

    @property
    def stig_id(self) -> str:
        """
        The identifier an auditor cites.

        ``<version>`` is the STIG rule's own short id — ``RHEL-09-211010`` —
        and is preferred over the XCCDF rule id, which is a URI nobody reads
        out loud. DISA's own content carries it; SSG's does not, so this falls
        back to the rule's short name rather than to the full URI.
        """
        return self.version or self.short_name


@dataclass(frozen=True)
class XccdfProfile:
    """A selectable profile: which rules are in scope, and with what values."""

    profile_id: str
    title: str = ""
    description: str = ""
    extends: str = ""
    #: rule id → selected. Only rules the profile mentions appear.
    selections: Mapping[str, bool] = field(default_factory=dict)
    #: value id → selector.
    refine_values: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class XccdfBenchmark:
    """One ``<Benchmark>``."""

    benchmark_id: str
    title: str = ""
    version: str = ""
    description: str = ""
    platforms: Tuple[str, ...] = ()
    rules: Tuple[XccdfRule, ...] = ()
    values: Mapping[str, XccdfValue] = field(default_factory=dict)
    profiles: Mapping[str, XccdfProfile] = field(default_factory=dict)

    def resolved_profile(self, profile_id: str) -> XccdfProfile:
        """
        *profile_id* with its inherited selections and refinements folded in.

        Parent first, child second, so the child wins — which is what
        ``extends`` means and the opposite of what a naive dict merge in the
        other order would do.
        """
        chain: List[XccdfProfile] = []
        seen: set[str] = set()
        current = self.profiles.get(profile_id)
        if current is None:
            raise XccdfError(
                f"the benchmark declares no profile {profile_id!r}; it has "
                f"{sorted(self.profiles) or '(none)'}"
            )
        while current is not None:
            if current.profile_id in seen:
                raise XccdfError(
                    f"profile {current.profile_id!r} extends itself through a " f"cycle"
                )
            seen.add(current.profile_id)
            chain.append(current)
            current = self.profiles.get(current.extends) if current.extends else None

        selections: Dict[str, bool] = {}
        refinements: Dict[str, str] = {}
        for profile in reversed(chain):
            selections.update(profile.selections)
            refinements.update(profile.refine_values)
        head = chain[0]
        return XccdfProfile(
            profile_id=head.profile_id,
            title=head.title,
            description=head.description,
            extends="",
            selections=selections,
            refine_values=refinements,
        )

    def rules_in_profile(self, profile_id: Optional[str]) -> List[XccdfRule]:
        """
        The rules a profile puts in scope.

        With no profile, the benchmark's own default selection applies — which
        for SSG content is almost nothing, so a caller that means "everything"
        must say so rather than relying on this.
        """
        if not profile_id:
            return [rule for rule in self.rules if rule.selected]
        profile = self.resolved_profile(profile_id)
        return [
            rule
            for rule in self.rules
            if profile.selections.get(rule.rule_id, rule.selected)
        ]

    def values_for_profile(self, profile_id: Optional[str]) -> Dict[str, str]:
        """Every Value resolved against the profile's refinements."""
        refinements = (
            self.resolved_profile(profile_id).refine_values if profile_id else {}
        )
        resolved: Dict[str, str] = {}
        for value_id, value in self.values.items():
            picked = value.resolve(refinements.get(value_id))
            if picked is not None:
                resolved[value_id] = picked
        return resolved


@dataclass(frozen=True)
class ScapContent:
    """A benchmark and the OVAL documents its rules check through."""

    benchmark: XccdfBenchmark
    #: ``href`` → document. The empty-string key is the datastream's own OVAL
    #: component, which is what a ``check-content-ref`` inside a datastream
    #: resolves to when the catalogue does not name the href.
    oval: Mapping[str, OvalDocument] = field(default_factory=dict)
    source: str = ""
    #: SHA-256 of the bytes this was read from. Recorded so a loaded benchmark
    #: can be traced back to the exact file, and so a caller can pin it.
    digest: str = ""
    #: CPE 2.0 platform id → its logical test tree, as parsed from
    #: ``<cpe:platform>``. See :func:`parse_cpe_platforms`.
    cpe_platforms: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def oval_for(self, href: str) -> Optional[OvalDocument]:
        """
        The OVAL document a rule's ``check-content-ref`` names.

        Falls back to the sole document when the href does not match one. A
        datastream rewrites hrefs through its catalogue, and DISA's bare XCCDF
        names a filename that may have been renamed on the way here; with one
        OVAL document present there is no ambiguity to protect against, and
        refusing would fail every rule in the benchmark over a filename.
        """
        if href in self.oval:
            return self.oval[href]
        base = href.rsplit("/", 1)[-1]
        for key, doc in self.oval.items():
            if key.rsplit("/", 1)[-1] == base:
                return doc
        if len(self.oval) == 1:
            return next(iter(self.oval.values()))
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────


def _text(node: Optional[ET.Element]) -> str:
    """All text under *node*, tags flattened, whitespace collapsed."""
    if node is None:
        return ""
    parts = list(node.itertext())
    return re.sub(r"\s+", " ", "".join(parts)).strip()


def _child(node: ET.Element, name: str) -> Optional[ET.Element]:
    for child in node:
        if local_name(child.tag) == name:
            return child
    return None


def _children(node: ET.Element, name: str) -> List[ET.Element]:
    return [child for child in node if local_name(child.tag) == name]


def _reject_doctype(text: str) -> None:
    if _DOCTYPE.search(text):
        raise XccdfError(
            "the document declares a DOCTYPE, which this reader refuses: "
            "ElementTree expands internal entities, and benchmark content "
            "comes from outside the product"
        )


def _parse_value(node: ET.Element) -> XccdfValue:
    options: Dict[str, str] = {}
    for entry in _children(node, "value"):
        options[entry.get("selector") or ""] = (entry.text or "").strip()
    return XccdfValue(
        value_id=node.get("id") or "",
        datatype=(node.get("type") or "string").strip().lower(),
        title=_text(_child(node, "title")),
        options=options,
    )


def _parse_profile(node: ET.Element) -> XccdfProfile:
    selections: Dict[str, bool] = {}
    refinements: Dict[str, str] = {}
    for child in node:
        name = local_name(child.tag)
        if name == "select":
            idref = child.get("idref")
            if idref:
                selections[idref] = str(child.get("selected", "true")).lower() in (
                    "true",
                    "1",
                )
        elif name == "refine-value":
            idref = child.get("idref")
            selector = child.get("selector")
            if idref and selector is not None:
                refinements[idref] = selector
    return XccdfProfile(
        profile_id=node.get("id") or "",
        title=_text(_child(node, "title")),
        description=_text(_child(node, "description")),
        extends=node.get("extends") or "",
        selections=selections,
        refine_values=refinements,
    )


def _platform_refs(node: ET.Element) -> Tuple[str, ...]:
    """``<platform idref="#system_with_kernel"/>`` → ``system_with_kernel``."""
    return tuple(
        (child.get("idref") or "").lstrip("#")
        for child in _children(node, "platform")
        if (child.get("idref") or "").strip()
    )


def _parse_rule(
    node: ET.Element,
    group_path: Tuple[str, ...],
    levels: Tuple[Tuple[str, ...], ...] = (),
) -> XccdfRule:
    idents = tuple(
        (child.get("system") or "", (child.text or "").strip())
        for child in _children(node, "ident")
        if (child.text or "").strip()
    )
    references = tuple(
        ((child.get("href") or "").strip(), _text(child))
        for child in _children(node, "reference")
        if (child.get("href") or "").strip() or _text(child)
    )

    check_href = check_name = ""
    exports: Dict[str, str] = {}
    unsupported = ""
    for check in _children(node, "check"):
        system = (check.get("system") or "").strip()
        if not system.startswith(OVAL_CHECK_SYSTEM):
            # Recorded, not discarded: a rule whose only check is OCIL is a
            # rule the benchmark expects a human to answer, and that is a
            # different fact from a rule we failed to read.
            unsupported = unsupported or system
            continue
        ref = _child(check, "check-content-ref")
        if ref is None:
            continue
        check_href = ref.get("href") or ""
        check_name = ref.get("name") or ""
        for export in _children(check, "check-export"):
            var = export.get("export-name")
            value_id = export.get("value-id")
            if var and value_id:
                exports[var] = value_id
        unsupported = ""
        break

    complex_check = _child(node, "complex-check")
    if complex_check is not None and not check_name:
        unsupported = unsupported or "xccdf:complex-check"

    return XccdfRule(
        rule_id=node.get("id") or "",
        title=_text(_child(node, "title")),
        severity=_SEVERITY.get((node.get("severity") or "unknown").lower(), "medium"),
        description=_text(_child(node, "description")),
        rationale=_text(_child(node, "rationale")),
        fixtext=_text(_child(node, "fixtext")) or _text(_child(node, "fix")),
        version=_text(_child(node, "version")),
        group_path=group_path,
        platforms=tuple(
            dict.fromkeys(
                [ref for level in levels for ref in level] + list(_platform_refs(node))
            )
        ),
        platform_levels=tuple(
            level for level in levels + (_platform_refs(node),) if level
        ),
        selected=str(node.get("selected", "true")).lower() in ("true", "1"),
        idents=idents,
        references=references,
        check_href=check_href,
        check_name=check_name,
        check_exports=exports,
        unsupported_check=unsupported,
    )


def _walk_groups(
    node: ET.Element,
    path: Tuple[str, ...],
    rules: List[XccdfRule],
    values: Dict[str, XccdfValue],
    levels: Tuple[Tuple[str, ...], ...] = (),
) -> None:
    """
    Collect Rules *and* Values from the whole Group tree.

    Values are gathered here rather than from the Benchmark's direct children,
    and that is not a tidiness point. XCCDF 1.2 allows ``<Value>`` inside a
    ``<Group>``, and SCAP Security Guide puts nearly all of them there — so a
    reader that looks only at the top level finds **zero**, every
    ``refine-value`` resolves to nothing, every ``check-export`` binding goes
    missing, and every parameterised rule fails to compile with "could not
    resolve variable".

    The damage is that this does not look like a bug. Those rules land as
    ``unimplemented`` with a plausible reason attached, so the benchmark loads,
    the counts look sane, and the phase reports a coverage limitation it does
    not have. Measured against SSG's RHEL 9 datastream: 0 values found before
    this walked the tree.
    """
    for child in node:
        name = local_name(child.tag)
        if name == "Rule":
            rules.append(_parse_rule(child, path, levels))
        elif name == "Value":
            value = _parse_value(child)
            if value.value_id:
                values[value.value_id] = value
        elif name == "Group":
            title = _text(_child(child, "title")) or (child.get("id") or "")
            # Platform applicability is inherited down the Group tree, and SSG
            # relies on that: 103 of the Ubuntu STIG profile's rules get
            # ``system_with_kernel`` from an enclosing Group rather than
            # declaring it themselves. Reading only rule-level platforms finds
            # a third of what is really there.
            group_platforms = _platform_refs(child)
            _walk_groups(
                child,
                path + (title,),
                rules,
                values,
                levels + ((group_platforms,) if group_platforms else ()),
            )


def parse_benchmark(node: ET.Element) -> XccdfBenchmark:
    """Read one ``<Benchmark>`` element."""
    rules: List[XccdfRule] = []
    values: Dict[str, XccdfValue] = {}
    benchmark_platforms = _platform_refs(node)
    _walk_groups(
        node,
        (),
        rules,
        values,
        (benchmark_platforms,) if benchmark_platforms else (),
    )
    profiles = {
        profile.profile_id: profile
        for profile in (_parse_profile(child) for child in _children(node, "Profile"))
        if profile.profile_id
    }
    platforms = tuple(
        (child.get("idref") or "").strip()
        for child in _children(node, "platform")
        if (child.get("idref") or "").strip()
    )
    version_node = _child(node, "version")
    return XccdfBenchmark(
        benchmark_id=node.get("id") or "",
        title=_text(_child(node, "title")),
        version=(version_node.text or "").strip() if version_node is not None else "",
        description=_text(_child(node, "description")),
        platforms=platforms,
        rules=tuple(rules),
        values=values,
        profiles=profiles,
    )


def _find_all(root: ET.Element, name: str) -> List[ET.Element]:
    """Every descendant (and the root itself) whose local name is *name*."""
    found = [root] if local_name(root.tag) == name else []
    found.extend(node for node in root.iter() if local_name(node.tag) == name)
    # ``iter`` includes the root, so a root match would otherwise be duplicated.
    seen: List[ET.Element] = []
    for node in found:
        if not any(node is other for other in seen):
            seen.append(node)
    return seen


def _datastream_catalog(root: ET.Element) -> Dict[str, str]:
    """
    ``uri name`` → component-ref id, from the datastream's ``<cat:catalog>``.

    This is the indirection that makes a datastream self-contained: the XCCDF
    inside it names ``ssg-rhel9-oval.xml``, the catalogue maps that name to a
    ``component-ref``, and the ref points at an embedded component. Skipping it
    leaves every rule unable to find its OVAL, which presents as a benchmark
    where nothing is automated.
    """
    catalog: Dict[str, str] = {}
    for uri in _find_all(root, "uri"):
        name = uri.get("name")
        target = uri.get("uri") or ""
        if name and target:
            catalog[name] = target.lstrip("#")
    return catalog


def _parse_logical_test(node: ET.Element) -> Dict[str, Any]:
    """
    One ``<cpe:logical-test>`` subtree.

    CPE Language 2.0 nests logical tests over ``check-fact-ref`` elements, each
    naming an OVAL *inventory* definition — "is pam installed", "is this a real
    system with a kernel". The tree is the same shape as OVAL's own criteria,
    so it is evaluated by the same three-valued logic.
    """
    children: List[Dict[str, Any]] = []
    for child in node:
        name = local_name(child.tag)
        if name == "logical-test":
            children.append(_parse_logical_test(child))
        elif name == "check-fact-ref":
            children.append(
                {
                    "kind": "fact",
                    "system": child.get("system") or "",
                    "href": child.get("href") or "",
                    "definition": child.get("id-ref") or "",
                }
            )
        elif name == "fact-ref":
            # A bare CPE name with no check behind it. Nothing can be
            # established from it, and guessing "applicable" would put every
            # such rule back into the false-positive class this exists to
            # remove.
            children.append({"kind": "unknown", "name": child.get("name") or ""})
    return {
        "kind": "logical",
        "operator": (node.get("operator") or "AND").strip().upper(),
        "negate": str(node.get("negate") or "").lower() in ("true", "1"),
        "children": children,
    }


def parse_cpe_platforms(root: ET.Element) -> Dict[str, Dict[str, Any]]:
    """Every ``<cpe:platform id="...">`` in the content, by id."""
    platforms: Dict[str, Dict[str, Any]] = {}
    for node in root.iter():
        if local_name(node.tag) != "platform" or not node.get("id"):
            continue
        tests = [c for c in node if local_name(c.tag) == "logical-test"]
        if tests:
            platforms[node.get("id")] = _parse_logical_test(tests[0])
    return platforms


def parse_content(source: Any, *, origin: str = "") -> ScapContent:
    """
    Read a SCAP source datastream, or a bare XCCDF benchmark.

    *source* is XML text or bytes. Which of the two shapes it is is decided by
    the root element, not by the file name.
    """
    if isinstance(source, bytes):
        raw = source
        text = source.decode("utf-8", "replace")
    else:
        text = str(source)
        raw = text.encode("utf-8", "replace")
    if len(raw) > MAX_CONTENT_BYTES:
        raise XccdfError(
            f"the content is {len(raw)} bytes, past the {MAX_CONTENT_BYTES}-byte "
            f"ceiling this reader will parse"
        )
    _reject_doctype(text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise XccdfError(f"the content is not well-formed XML: {exc}") from exc

    digest = hashlib.sha256(raw).hexdigest()

    benchmarks = _find_all(root, "Benchmark")
    if not benchmarks:
        raise XccdfError(
            "the content contains no <Benchmark>; it is neither an XCCDF "
            "benchmark nor a datastream carrying one"
        )
    if len(benchmarks) > 1:
        raise XccdfError(
            f"the content carries {len(benchmarks)} benchmarks. Which one is "
            f"meant is a decision the caller has to make, not this reader."
        )
    benchmark = parse_benchmark(benchmarks[0])

    # OVAL components, indexed by every name that can reach them: the
    # component id, the component-ref id, and the catalogue's uri names.
    oval: Dict[str, OvalDocument] = {}
    components: Dict[str, ET.Element] = {}
    for component in _find_all(root, "component"):
        component_id = component.get("id") or ""
        for child in component:
            if local_name(child.tag) == "oval_definitions":
                components[component_id] = child

    refs: Dict[str, str] = {}
    for ref in _find_all(root, "component-ref"):
        ref_id = ref.get("id") or ""
        href = ""
        for key, value in ref.attrib.items():
            if local_name(key) == "href" or key.endswith("href"):
                href = value
                break
        if ref_id and href:
            refs[ref_id] = href.lstrip("#")

    catalog = _datastream_catalog(root)

    for component_id, element in components.items():
        try:
            document = parse_oval(element)
        except OvalError:
            continue
        oval[component_id] = document
        for ref_id, target in refs.items():
            if target == component_id:
                oval[ref_id] = document
        for name, ref_id in catalog.items():
            if refs.get(ref_id) == component_id or ref_id == component_id:
                oval[name] = document

    if not oval:
        # A bare XCCDF file: the OVAL is a sibling file the caller supplies.
        standalone = _find_all(root, "oval_definitions")
        for element in standalone:
            oval[""] = parse_oval(element)

    return ScapContent(
        benchmark=benchmark,
        oval=oval,
        source=origin,
        digest=digest,
        cpe_platforms=parse_cpe_platforms(root),
    )


def load_content(
    path: Any,
    *,
    oval_paths: Sequence[Any] = (),
    expected_digest: str = "",
) -> ScapContent:
    """
    Read content from disk.

    *oval_paths* supplies OVAL documents for a bare XCCDF benchmark; a
    datastream needs none. *expected_digest* is checked against the benchmark
    file's SHA-256 and a mismatch is refused — the content is somebody else's
    and travels over the network, so an operator who has recorded a digest
    should be able to hold this to it.
    """
    from pathlib import Path

    benchmark_path = Path(path)
    raw = benchmark_path.read_bytes()
    content = parse_content(raw, origin=str(benchmark_path))

    if expected_digest and content.digest.lower() != expected_digest.strip().lower():
        raise XccdfError(
            f"{benchmark_path.name} has SHA-256 {content.digest}, not the "
            f"expected {expected_digest}. Refusing to load content that is not "
            f"the file the operator pinned."
        )

    if oval_paths:
        merged = dict(content.oval)
        for oval_path in oval_paths:
            oval_file = Path(oval_path)
            merged[oval_file.name] = parse_oval(
                oval_file.read_text(encoding="utf-8", errors="replace")
            )
        content = ScapContent(
            benchmark=content.benchmark,
            oval=merged,
            source=content.source,
            digest=content.digest,
            cpe_platforms=content.cpe_platforms,
        )
    return content
