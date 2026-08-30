"""
core/scap/oval.py
─────────────────────────────────────────────────────────────────────────────
Reading OVAL 5.11 definition documents, and compiling one definition into a
self-contained, JSON-serialisable form.

Why compile rather than keep the document
─────────────────────────────────────────
A benchmark rule is stored as a row in ``compliance_rules`` and evaluated on a
Celery worker, possibly months later. The datastream it came from is a 60 MB
file on somebody's laptop. So a definition is **flattened at load time** into
the tests, objects, states and variable values it actually needs, and that
flattened form is what the rule carries. Nothing at scan time reads the
original content.

Namespaces are read, never stripped
───────────────────────────────────
Phase 8 strips XML namespaces because Tomcat's ``xmlns`` made every selection
return nothing. **Here the opposite is required.** ``file_test`` exists in the
OVAL ``unix`` schema *and* in the ``windows`` schema, and they are different
tests against different targets. Stripping would merge them, and a Windows
registry rule would be evaluated by a Unix probe. Every element is therefore
keyed ``schema:local_name`` — ``unix:file_test``, ``linux:rpminfo_test``,
``independent:textfilecontent54_test``.

Unsupported is a first-class answer
───────────────────────────────────
:class:`UnsupportedConstruct` is raised by the compiler, caught by the pack
converter, and turned into a control marked ``unimplemented`` with the reason
attached. It never becomes a passing check and never silently disappears. This
is the phase's central rule and every ``raise`` below is an instance of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from xml.etree import ElementTree as ET

__all__ = [
    "CRITERIA_OPERATORS",
    "CompiledDefinition",
    "OvalDocument",
    "OvalError",
    "SUPPORTED_OBJECT_TYPES",
    "SUPPORTED_TESTS",
    "UnsupportedConstruct",
    "literal_prefix",
    "local_name",
    "parse_oval",
    "schema_of",
]


class OvalError(ValueError):
    """The document is not OVAL this reader can make sense of."""


class UnsupportedConstruct(OvalError):
    """
    The document is valid OVAL and uses something this build cannot evaluate.

    Distinct from :class:`OvalError` on purpose. A malformed document is a
    problem with the content; this is a gap in *us*, and the two must reach a
    reader differently — one is "that file is broken", the other is "this
    product does not do that yet", and only the second belongs in a coverage
    figure.
    """


_DOCTYPE = re.compile(r"<!DOCTYPE", re.IGNORECASE)

#: OVAL schema namespace fragments → the short name used in test type keys.
#: Read from the namespace URI's last path segment, so a schema this table does
#: not name still produces a distinct key rather than colliding with another.
_SCHEMA_RE = re.compile(r"oval:def:(?:ind|unix|lin|win|sch)|#(?P<name>[a-z0-9_]+)$")

#: The criteria operators OVAL defines. All four are implemented; ONE and XOR
#: appear only three times in the measured corpus but cost nothing.
CRITERIA_OPERATORS: Tuple[str, ...] = ("AND", "OR", "ONE", "XOR")

#: ``test type`` → the GAP-05 area it satisfies. This mapping *is* the
#: capability claim: ``scripts/measure_scap_coverage.py`` reads it, so deleting
#: a probe removes the coverage credit rather than leaving a stale list saying
#: the area is still covered.
SUPPORTED_TESTS: Mapping[str, str] = {
    "independent:textfilecontent54_test": "scap.oval.textfilecontent54",
    "unix:file_test": "scap.oval.file",
    "linux:rpminfo_test": "scap.oval.rpminfo",
    "linux:dpkginfo_test": "scap.oval.dpkginfo",
    "independent:xmlfilecontent_test": "scap.oval.xmlfilecontent",
    "independent:yamlfilecontent_test": "scap.oval.yamlfilecontent",
    "linux:systemdunitproperty_test": "scap.oval.systemdunitproperty",
    "independent:family_test": "scap.oval.family",
    "unix:uname_test": "scap.oval.uname",
    "independent:variable_test": "scap.oval.variable_external",
}

SUPPORTED_OBJECT_TYPES: Tuple[str, ...] = tuple(
    key.replace("_test", "_object") for key in SUPPORTED_TESTS
)

#: Object entities each object type is allowed to carry. An entity outside this
#: set is refused rather than ignored: an ignored filter collects more items
#: than the content asked for, and "more items" changes the answer of every
#: ``check_existence`` value there is.
_OBJECT_ENTITIES: Mapping[str, Tuple[str, ...]] = {
    "independent:textfilecontent54_object": (
        "filepath",
        "path",
        "filename",
        "pattern",
        "instance",
        "behaviors",
        "filter",
    ),
    "unix:file_object": ("filepath", "path", "filename", "behaviors", "filter"),
    "linux:rpminfo_object": ("name", "behaviors", "filter"),
    "linux:dpkginfo_object": ("name", "behaviors", "filter"),
    "independent:xmlfilecontent_object": (
        "filepath",
        "path",
        "filename",
        "xpath",
        "behaviors",
        "filter",
    ),
    "independent:yamlfilecontent_object": (
        "filepath",
        "path",
        "filename",
        "yamlpath",
        "behaviors",
        "filter",
    ),
    "linux:systemdunitproperty_object": ("unit", "property", "behaviors", "filter"),
    "independent:family_object": (),
    "unix:uname_object": (),
    "independent:variable_object": ("var_ref",),
}

#: Which operations each object *entity* can be resolved by, per object type.
#: An entity selects **which items to collect**, so an operation this build
#: cannot resolve is not a comparison it gets wrong — it is a set of items it
#: never gathers, and every ``check_existence`` value is decided by how many
#: items there are.
#:
#: Validated here rather than in the probe, and that placement is the point.
#: The shape is knowable from the content alone, so refusing it at compile time
#: records the rule as ``unimplemented`` in the load tally — visible once, with
#: a reason, before anything is scanned. Refusing it in the probe produces an
#: ERROR on every host the benchmark ever runs against, which is the same
#: information delivered as noise.
_ENTITY_OPERATIONS: Mapping[str, Mapping[str, Tuple[str, ...]]] = {
    "independent:textfilecontent54_object": {
        "filepath": ("equals", "case insensitive equals", "pattern match"),
        "path": ("equals", "case insensitive equals", "pattern match"),
        "filename": ("equals", "case insensitive equals", "pattern match"),
    },
    "unix:file_object": {
        "filepath": ("equals", "case insensitive equals", "pattern match"),
        "path": ("equals", "case insensitive equals", "pattern match"),
        "filename": ("equals", "case insensitive equals", "pattern match"),
    },
    "independent:xmlfilecontent_object": {
        "filepath": ("equals", "case insensitive equals", "pattern match"),
        "path": ("equals", "case insensitive equals", "pattern match"),
        "filename": ("equals", "case insensitive equals", "pattern match"),
    },
    "independent:yamlfilecontent_object": {
        "filepath": ("equals", "case insensitive equals", "pattern match"),
        "path": ("equals", "case insensitive equals", "pattern match"),
        "filename": ("equals", "case insensitive equals", "pattern match"),
    },
    "linux:rpminfo_object": {
        "name": ("equals", "case insensitive equals", "pattern match"),
    },
    "linux:dpkginfo_object": {
        "name": ("equals", "case insensitive equals"),
    },
    "linux:systemdunitproperty_object": {
        "unit": ("equals", "case insensitive equals"),
        "property": ("equals", "case insensitive equals"),
    },
}

#: State operations this build compares with. ``bitwise and``/``bitwise or``
#: are deliberately absent — five uses in the measured corpus, and a wrong
#: bitmask comparison produces a confident verdict rather than a visible error.
_SUPPORTED_OPERATIONS: Tuple[str, ...] = (
    "equals",
    "not equal",
    "case insensitive equals",
    "case insensitive not equal",
    "pattern match",
    "greater than",
    "greater than or equal",
    "less than",
    "less than or equal",
)

_SUPPORTED_DATATYPES: Tuple[str, ...] = (
    "string",
    "int",
    "float",
    "boolean",
    "version",
    "evr_string",
    "ios_version",
    "debian_evr_string",
    "binary",
)

_CHECK_EXISTENCE: Tuple[str, ...] = (
    "all_exist",
    "any_exist",
    "at_least_one_exists",
    "none_exist",
    "only_one_exists",
)

_CHECK: Tuple[str, ...] = (
    "all",
    "at least one",
    "none satisfy",
    "only one",
)

#: A compiled definition may not exceed this many tests. A definition is a
#: hardening rule, not a program; anything past this is either a document this
#: reader has misunderstood or content that would make a JSONB row unreadable.
_MAX_TESTS_PER_DEFINITION = 64
_MAX_EXTEND_DEPTH = 12


# ─────────────────────────────────────────────────────────────────────────────
# Namespace-aware element helpers
# ─────────────────────────────────────────────────────────────────────────────


def local_name(tag: str) -> str:
    """``{uri}file_test`` → ``file_test``."""
    return tag.split("}", 1)[1] if isinstance(tag, str) and tag.startswith("{") else tag


def schema_of(tag: str) -> str:
    """
    ``{...oval:definitions:5#unix}file_test`` → ``unix``.

    The short schema name is the last ``#``-delimited segment of the namespace
    URI, which every OVAL component schema uses. A namespace that does not
    follow it yields its final path segment instead, so two unknown schemas
    still produce two distinct keys.
    """
    if not isinstance(tag, str) or not tag.startswith("{"):
        return ""
    uri = tag[1:].split("}", 1)[0]
    if "#" in uri:
        return uri.rsplit("#", 1)[1]
    return uri.rstrip("/").rsplit("/", 1)[-1]


def _key(element: ET.Element) -> str:
    """The ``schema:local_name`` key an element is addressed by."""
    schema = schema_of(element.tag)
    name = local_name(element.tag)
    return f"{schema}:{name}" if schema else name


_REGEX_META = set(".^$*+?{}[]|()\\")


def literal_prefix(pattern: str) -> str:
    """
    The longest literal directory prefix of a path regular expression.

    ``^\\/etc\\/(sudoers|sudoers\\.d\\/.*)$`` → ``/etc``. Everything from the
    first unescaped metacharacter onward is regex, so the last ``/`` before it
    bounds what a probe can search.

    ``""`` means the expression has no literal root — it opens with a group or
    a wildcard — and both callers refuse rather than walking from ``/``. A
    benchmark rule is not worth a filesystem crawl on a production host.

    Lives here rather than beside the probe because the *converter* consults it
    too: a rule whose path expression has no literal root can be recognised
    from the content alone, so it is recorded as unimplemented at load time
    instead of erroring on every host the benchmark is ever run against.
    """
    text = pattern.lstrip("^")
    literal: List[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            # An escape of a non-alphanumeric is a literal of that character —
            # PCRE permits ``\/`` and SSG writes paths that way. An escape of
            # an alphanumeric is a character class and ends the literal run.
            if not nxt.isalnum():
                literal.append(nxt)
                index += 2
                continue
            break
        if char in _REGEX_META:
            break
        literal.append(char)
        index += 1
    joined = "".join(literal)
    if "/" not in joined:
        return ""
    prefix = joined.rsplit("/", 1)[0]
    return prefix or "/"


def _reject_doctype(text: str) -> None:
    if _DOCTYPE.search(text):
        raise OvalError(
            "the OVAL document declares a DOCTYPE, which this reader refuses: "
            "ElementTree expands internal entities, and this content comes "
            "from outside the product"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Compiled form
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CompiledDefinition:
    """
    One OVAL definition, flattened to everything needed to evaluate it.

    Serialises to plain JSON so it can live in ``compliance_rules``'
    ``check_definition`` and be evaluated with no access to the original
    content.
    """

    definition_id: str
    criteria: Mapping[str, Any]
    tests: Mapping[str, Mapping[str, Any]]
    objects: Mapping[str, Mapping[str, Any]]
    states: Mapping[str, Mapping[str, Any]]
    #: Every ``schema:test`` name used, so a caller can report which areas a
    #: rule exercises without walking the tree again.
    test_types: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "definition_id": self.definition_id,
            "criteria": dict(self.criteria),
            "tests": {k: dict(v) for k, v in self.tests.items()},
            "objects": {k: dict(v) for k, v in self.objects.items()},
            "states": {k: dict(v) for k, v in self.states.items()},
            "test_types": list(self.test_types),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CompiledDefinition":
        return cls(
            definition_id=str(payload.get("definition_id") or ""),
            criteria=dict(payload.get("criteria") or {}),
            tests=dict(payload.get("tests") or {}),
            objects=dict(payload.get("objects") or {}),
            states=dict(payload.get("states") or {}),
            test_types=tuple(payload.get("test_types") or ()),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Document
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class OvalDocument:
    """An ``<oval_definitions>`` document, indexed by id."""

    definitions: Dict[str, ET.Element] = field(default_factory=dict)
    tests: Dict[str, ET.Element] = field(default_factory=dict)
    objects: Dict[str, ET.Element] = field(default_factory=dict)
    states: Dict[str, ET.Element] = field(default_factory=dict)
    variables: Dict[str, ET.Element] = field(default_factory=dict)

    # ── Metadata ─────────────────────────────────────────────────────────────

    def definition_class(self, definition_id: str) -> str:
        """
        The ``@class`` of a definition — ``compliance``, ``vulnerability``, …

        Load-bearing, not decoration. A ``compliance`` definition is written so
        that TRUE means the host is in the state the benchmark wants; a
        ``vulnerability`` definition is written so that TRUE means the host is
        *affected*. Scoring the second with the first's polarity reports every
        vulnerable host as compliant, which is the worst direction available.
        """
        node = self.definitions.get(definition_id)
        return (node.get("class") or "").strip().lower() if node is not None else ""

    def definition_title(self, definition_id: str) -> str:
        node = self.definitions.get(definition_id)
        if node is None:
            return ""
        for child in node.iter():
            if local_name(child.tag) == "title":
                return (child.text or "").strip()
        return ""

    # ── Compilation ──────────────────────────────────────────────────────────

    def compile_definition(
        self,
        definition_id: str,
        *,
        values: Optional[Mapping[str, Any]] = None,
    ) -> CompiledDefinition:
        """
        Flatten *definition_id* into a self-contained :class:`CompiledDefinition`.

        *values* binds XCCDF Values to OVAL ``external_variable`` ids — this is
        how a STIG's parameters ("minimum password length") reach the check.
        A variable with no binding and no default is refused: evaluating a rule
        against an unbound parameter would compare the host to nothing.

        Raises :class:`UnsupportedConstruct` for anything this build cannot
        evaluate, which the caller must record rather than swallow.
        """
        node = self.definitions.get(definition_id)
        if node is None:
            raise OvalError(f"no definition {definition_id!r} in this document")

        collected: Dict[str, Mapping[str, Any]] = {}
        objects: Dict[str, Mapping[str, Any]] = {}
        states: Dict[str, Mapping[str, Any]] = {}
        resolved = self._resolve_variables(values or {})

        criteria = self._compile_criteria(
            node,
            collected,
            objects,
            states,
            resolved,
            seen=set(),
            depth=0,
        )
        if not collected:
            raise UnsupportedConstruct(
                f"definition {definition_id!r} has no evaluable test; its "
                f"criteria reference nothing this build can collect"
            )
        types = tuple(sorted({str(t["type"]) for t in collected.values()}))
        return CompiledDefinition(
            definition_id=definition_id,
            criteria=criteria,
            tests=collected,
            objects=objects,
            states=states,
            test_types=types,
        )

    # ── Criteria ─────────────────────────────────────────────────────────────

    def _compile_criteria(
        self,
        parent: ET.Element,
        tests: Dict[str, Mapping[str, Any]],
        objects: Dict[str, Mapping[str, Any]],
        states: Dict[str, Mapping[str, Any]],
        values: Mapping[str, Any],
        *,
        seen: Set[str],
        depth: int,
    ) -> Dict[str, Any]:
        """Compile the single ``<criteria>`` child of *parent*."""
        node = None
        for child in parent:
            if local_name(child.tag) == "criteria":
                node = child
                break
        if node is None:
            raise UnsupportedConstruct(
                "the definition carries no <criteria> element, so there is "
                "nothing to evaluate"
            )
        return self._compile_criteria_node(
            node, tests, objects, states, values, seen=seen, depth=depth
        )

    def _compile_criteria_node(
        self,
        node: ET.Element,
        tests: Dict[str, Mapping[str, Any]],
        objects: Dict[str, Mapping[str, Any]],
        states: Dict[str, Mapping[str, Any]],
        values: Mapping[str, Any],
        *,
        seen: Set[str],
        depth: int,
    ) -> Dict[str, Any]:
        operator = (node.get("operator") or "AND").strip().upper()
        if operator not in CRITERIA_OPERATORS:
            raise UnsupportedConstruct(
                f"criteria operator {operator!r} is not one of "
                f"{', '.join(CRITERIA_OPERATORS)}"
            )
        children: List[Dict[str, Any]] = []
        for child in node:
            name = local_name(child.tag)
            if name == "criteria":
                children.append(
                    self._compile_criteria_node(
                        child, tests, objects, states, values, seen=seen, depth=depth
                    )
                )
            elif name == "criterion":
                test_id = child.get("test_ref") or ""
                self._compile_test(test_id, tests, objects, states, values)
                children.append(
                    {
                        "kind": "test",
                        "test": test_id,
                        "negate": _bool(child.get("negate")),
                    }
                )
            elif name == "extend_definition":
                children.append(
                    self._compile_extension(
                        child, tests, objects, states, values, seen=seen, depth=depth
                    )
                )
            # <oval:comment> and anything else carries no logic.
        if not children:
            raise UnsupportedConstruct(
                "a <criteria> element with no criterion, nested criteria or "
                "extended definition cannot produce a result"
            )
        return {
            "kind": "criteria",
            "operator": operator,
            "negate": _bool(node.get("negate")),
            "children": children,
        }

    def _compile_extension(
        self,
        child: ET.Element,
        tests: Dict[str, Mapping[str, Any]],
        objects: Dict[str, Mapping[str, Any]],
        states: Dict[str, Mapping[str, Any]],
        values: Mapping[str, Any],
        *,
        seen: Set[str],
        depth: int,
    ) -> Dict[str, Any]:
        """
        Inline an ``<extend_definition>`` reference.

        Inlined rather than left as a reference because the compiled form must
        be self-contained: at scan time there is no document to look the
        referenced definition up in. Cycles are refused rather than followed —
        OVAL permits a definition graph, and a cycle would compile forever.
        """
        ref = child.get("definition_ref") or ""
        if ref in seen:
            raise UnsupportedConstruct(
                f"definition {ref!r} extends itself through a cycle; this "
                f"reader will not follow one"
            )
        if depth >= _MAX_EXTEND_DEPTH:
            raise UnsupportedConstruct(
                f"extend_definition nesting exceeds {_MAX_EXTEND_DEPTH} levels"
            )
        target = self.definitions.get(ref)
        if target is None:
            raise UnsupportedConstruct(
                f"definition {ref!r} is referenced by extend_definition but is "
                f"not in this document"
            )
        inner = self._compile_criteria(
            target,
            tests,
            objects,
            states,
            values,
            seen=seen | {ref},
            depth=depth + 1,
        )
        if _bool(child.get("negate")):
            inner = dict(inner)
            inner["negate"] = not bool(inner.get("negate"))
        return inner

    # ── Tests, objects, states ───────────────────────────────────────────────

    def _compile_test(
        self,
        test_id: str,
        tests: Dict[str, Mapping[str, Any]],
        objects: Dict[str, Mapping[str, Any]],
        states: Dict[str, Mapping[str, Any]],
        values: Mapping[str, Any],
    ) -> None:
        if test_id in tests:
            return
        if len(tests) >= _MAX_TESTS_PER_DEFINITION:
            raise UnsupportedConstruct(
                f"the definition references more than "
                f"{_MAX_TESTS_PER_DEFINITION} tests"
            )
        node = self.tests.get(test_id)
        if node is None:
            raise UnsupportedConstruct(
                f"test {test_id!r} is referenced but not present in this document"
            )
        test_type = _key(node)
        if test_type not in SUPPORTED_TESTS:
            raise UnsupportedConstruct(
                f"OVAL test type {test_type!r} is not implemented by this build"
            )

        check = (node.get("check") or "all").strip().lower()
        if check not in _CHECK:
            raise UnsupportedConstruct(
                f"test {test_id!r} uses check={check!r}, which is not one of "
                f"{_CHECK}"
            )
        existence = (node.get("check_existence") or "at_least_one_exists").strip()
        if existence not in _CHECK_EXISTENCE:
            raise UnsupportedConstruct(
                f"test {test_id!r} uses check_existence={existence!r}, which is "
                f"not one of {_CHECK_EXISTENCE}"
            )

        object_ref = ""
        state_refs: List[str] = []
        for child in node:
            name = local_name(child.tag)
            if name == "object":
                object_ref = child.get("object_ref") or ""
            elif name == "state":
                state_refs.append(child.get("state_ref") or "")
        if not object_ref:
            raise UnsupportedConstruct(f"test {test_id!r} names no object")

        self._compile_object(object_ref, test_type, objects, states, values)
        for state_ref in state_refs:
            self._compile_state(state_ref, states, values)

        tests[test_id] = {
            "type": test_type,
            "object": object_ref,
            "states": state_refs,
            "check": check,
            "check_existence": existence,
        }

    def _compile_object(
        self,
        object_id: str,
        test_type: str,
        objects: Dict[str, Mapping[str, Any]],
        states: Dict[str, Mapping[str, Any]],
        values: Mapping[str, Any],
    ) -> None:
        if object_id in objects:
            return
        node = self.objects.get(object_id)
        if node is None:
            raise UnsupportedConstruct(
                f"object {object_id!r} is referenced but not present in this "
                f"document"
            )
        object_type = _key(node)
        allowed = _OBJECT_ENTITIES.get(object_type)
        if allowed is None:
            raise UnsupportedConstruct(
                f"OVAL object type {object_type!r} is not implemented by this " f"build"
            )

        entities: Dict[str, Any] = {}
        behaviors: Dict[str, str] = {}
        filters: List[Dict[str, str]] = []
        for child in node:
            name = local_name(child.tag)
            if name == "set":
                raise UnsupportedConstruct(
                    f"object {object_id!r} composes other objects with <set>, "
                    f"which needs a second collection pass this build does not "
                    f"make"
                )
            if name == "filter":
                # A filter narrows the collected item set by a state, *after*
                # collection — which is exactly the machinery the states
                # already provide. 613 of the RHEL 9 datastream's objects carry
                # one, so refusing them would put a fifth of the benchmark out
                # of reach for no reason beyond where the state is written.
                state_ref = (child.text or "").strip()
                if not state_ref:
                    raise UnsupportedConstruct(
                        f"object {object_id!r} declares a <filter> naming no " f"state"
                    )
                action = (child.get("action") or "exclude").strip().lower()
                if action not in ("include", "exclude"):
                    raise UnsupportedConstruct(
                        f"object {object_id!r} declares a filter with action "
                        f"{action!r}"
                    )
                self._compile_state(state_ref, states, values)
                filters.append({"state": state_ref, "action": action})
                continue
            if name == "behaviors":
                behaviors = {k: str(v) for k, v in child.attrib.items()}
                continue
            if name not in allowed:
                raise UnsupportedConstruct(
                    f"object {object_id!r} carries entity {name!r}, which is "
                    f"not one this build reads for {object_type}"
                )
            if object_type == "independent:variable_object" and name == "var_ref":
                # ``<var_ref>`` on a variable_object holds a variable *id* as
                # its text, not a value. Storing the text as if it were the
                # value makes the probe hand the comparison a string like
                # ``oval:ssg-…:var:1`` and call it the host's setting — a
                # verdict about a machine, derived from an identifier.
                #
                # Resolving it here also puts the failure where it belongs:
                # these almost always point at a local_variable, which is a
                # declared gap, so the rule loads as `unimplemented` with that
                # reason instead of erroring on every host it runs against.
                target = (child.text or "").strip()
                if target not in values:
                    kind = (
                        local_name(self.variables[target].tag)
                        if target in self.variables
                        else "unknown variable"
                    )
                    if kind == "local_variable":
                        raise UnsupportedConstruct(
                            f"object {object_id!r} tests a local_variable, "
                            f"which this build does not compute"
                        )
                    raise UnsupportedConstruct(
                        f"object {object_id!r} tests an unbound {kind}; the "
                        f"profile supplied no value for it"
                    )
                entities[name] = {
                    "values": [str(v) for v in values[target]],
                    "operation": "equals",
                    "from_variable": target,
                }
                continue
            entity = self._entity(child, values, where=object_id)
            allowed_ops = _ENTITY_OPERATIONS.get(object_type, {}).get(name)
            if allowed_ops is not None and entity["operation"] not in allowed_ops:
                raise UnsupportedConstruct(
                    f"object {object_id!r} selects {name} by "
                    f"{entity['operation']!r}; this build resolves "
                    f"{', '.join(allowed_ops)} for {object_type}"
                )
            if (
                name in ("filepath", "path")
                and entity["operation"] == "pattern match"
                and not all(literal_prefix(v) for v in entity["values"])
            ):
                raise UnsupportedConstruct(
                    f"object {object_id!r} selects {name} by a pattern with no "
                    f"literal directory to search from; resolving it would "
                    f"mean walking the filesystem"
                )
            entities[name] = entity

        objects[object_id] = {
            "type": object_type,
            "entities": entities,
            "behaviors": behaviors,
            "filters": filters,
        }

    def _compile_state(
        self,
        state_id: str,
        states: Dict[str, Mapping[str, Any]],
        values: Mapping[str, Any],
    ) -> None:
        if state_id in states:
            return
        node = self.states.get(state_id)
        if node is None:
            raise UnsupportedConstruct(
                f"state {state_id!r} is referenced but not present in this " f"document"
            )
        operator = (node.get("operator") or "AND").strip().upper()
        if operator not in ("AND", "OR"):
            raise UnsupportedConstruct(
                f"state {state_id!r} combines its fields with {operator!r}; "
                f"only AND and OR are implemented"
            )
        fields: List[Dict[str, Any]] = []
        for child in node:
            name = local_name(child.tag)
            entity = self._entity(child, values, where=state_id)
            operation = (child.get("operation") or "equals").strip().lower()
            if operation not in _SUPPORTED_OPERATIONS:
                raise UnsupportedConstruct(
                    f"state {state_id!r} field {name!r} uses operation "
                    f"{operation!r}, which this build does not compare with"
                )
            datatype = (child.get("datatype") or "string").strip().lower()
            if datatype not in _SUPPORTED_DATATYPES:
                raise UnsupportedConstruct(
                    f"state {state_id!r} field {name!r} declares datatype "
                    f"{datatype!r}, which this build does not compare"
                )
            entity_check = (child.get("entity_check") or "all").strip().lower()
            if entity_check not in ("all", "at least one", "none satisfy", "only one"):
                raise UnsupportedConstruct(
                    f"state {state_id!r} field {name!r} uses entity_check "
                    f"{entity_check!r}"
                )
            fields.append(
                {
                    "name": name,
                    "operation": operation,
                    "datatype": datatype,
                    "entity_check": entity_check,
                    "value": entity,
                }
            )
        if not fields:
            raise UnsupportedConstruct(
                f"state {state_id!r} constrains nothing, so it cannot decide "
                f"anything about an item"
            )
        states[state_id] = {"operator": operator, "fields": fields}

    # ── Entities and variables ───────────────────────────────────────────────

    def _entity(
        self, node: ET.Element, values: Mapping[str, Any], *, where: str
    ) -> Dict[str, Any]:
        """
        One entity's literal value or the value of the variable it names.

        ``var_ref`` is resolved **here, at compile time**, so the stored rule
        carries a number rather than a pointer into a document that will not be
        present at scan time.
        """
        var_ref = node.get("var_ref")
        if var_ref:
            if var_ref not in values:
                # Naming the *kind* is what makes the tally actionable: a
                # local_variable is a recorded, declared gap in this build,
                # while an unbound external variable is content whose profile
                # did not refine the value. Reporting both as "could not
                # resolve" hides which of the two a benchmark is losing rules
                # to, and therefore what to build next.
                kind = (
                    local_name(self.variables[var_ref].tag)
                    if var_ref in self.variables
                    else "unknown variable"
                )
                if kind == "local_variable":
                    raise UnsupportedConstruct(
                        f"{where} references a local_variable, which this "
                        f"build does not compute"
                    )
                raise UnsupportedConstruct(
                    f"{where} references an unbound {kind}; the profile "
                    f"supplied no value for it"
                )
            resolved = values[var_ref]
            return {
                "values": [str(v) for v in resolved],
                "operation": (node.get("operation") or "equals").strip().lower(),
                "from_variable": var_ref,
            }
        return {
            "values": [node.text if node.text is not None else ""],
            "operation": (node.get("operation") or "equals").strip().lower(),
        }

    def _resolve_variables(self, values: Mapping[str, Any]) -> Dict[str, List[str]]:
        """
        Every variable this document declares, resolved to literal values.

        ``external_variable`` takes the caller's binding, falling back to the
        variable's own ``<possible_value>``-adjacent default only where the
        content supplies one. ``constant_variable`` is read from the document.
        ``local_variable`` is **not** resolved — see the module docstring for
        why, and the coverage script for the recorded reason.
        """
        resolved: Dict[str, List[str]] = {}
        for var_id, node in self.variables.items():
            kind = local_name(node.tag)
            if kind == "constant_variable":
                literals = [
                    (child.text or "")
                    for child in node
                    if local_name(child.tag) == "value"
                ]
                if literals:
                    resolved[var_id] = literals
            elif kind == "external_variable":
                if var_id in values:
                    supplied = values[var_id]
                    resolved[var_id] = (
                        [str(v) for v in supplied]
                        if isinstance(supplied, (list, tuple))
                        else [str(supplied)]
                    )
            # local_variable is deliberately absent: a definition using one
            # fails to compile and is recorded as unimplemented.
        return resolved


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────


def _bool(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in ("true", "1")


def parse_oval(source: Any) -> OvalDocument:
    """
    Read an ``<oval_definitions>`` document.

    Accepts XML text or an already-parsed :class:`~xml.etree.ElementTree.Element`
    — a datastream embeds its OVAL components inline, so the caller usually has
    the element already and re-serialising it to hand back here would be pure
    waste on a 60 MB file.
    """
    if isinstance(source, (str, bytes)):
        text = (
            source.decode("utf-8", "replace") if isinstance(source, bytes) else source
        )
        _reject_doctype(text)
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise OvalError(f"the OVAL document is not well-formed XML: {exc}") from exc
    elif isinstance(source, ET.Element):
        root = source
    else:
        raise OvalError(f"cannot read OVAL from {type(source).__name__}")

    if local_name(root.tag) != "oval_definitions":
        found = None
        for child in root.iter():
            if local_name(child.tag) == "oval_definitions":
                found = child
                break
        if found is None:
            raise OvalError(
                f"expected an <oval_definitions> document, found "
                f"<{local_name(root.tag)}>"
            )
        root = found

    doc = OvalDocument()
    for section in root:
        name = local_name(section.tag)
        target = {
            "definitions": doc.definitions,
            "tests": doc.tests,
            "objects": doc.objects,
            "states": doc.states,
            "variables": doc.variables,
        }.get(name)
        if target is None:
            continue
        for item in section:
            item_id = item.get("id")
            if item_id:
                target[item_id] = item
    if not doc.definitions:
        raise OvalError("the OVAL document declares no definitions")
    return doc
