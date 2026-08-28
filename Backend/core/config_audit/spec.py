"""
core/config_audit/spec.py
─────────────────────────────────────────────────────────────────────────────
What a configuration check *is*, declaratively.

A ``ConfigCheck`` names a thing to read on a target and the state that thing is
required to be in. It contains no code and no benchmark. CIS, STIG, a vendor
hardening guide and an internal baseline are all just sets of these, which is
the property that lets Phases 4 and 5 add content without touching the engine.

Where these are stored
──────────────────────
In ``compliance_rules``. Not in a new table.

That table already carries ``check_type``, ``check_definition`` (JSONB),
``target_platform``, ``severity``, ``status``, versioning through
``rule_family_code``/``version_number``, a remediation link, and a junction to
every framework control the check satisfies. A second rule table would need all
of it again, and would immediately need a second finding table, a second score
and a second report — which is exactly the split CLAUDE.md records as the
reason ``vulnerability_definitions`` was widened rather than duplicated.

:meth:`ConfigCheck.to_check_definition` and :meth:`ConfigCheck.from_rule` are
the adapter between the dataclass the engine executes and the JSONB the
database holds. The round-trip is asserted in the test suite; a field added
here without a home in the JSON silently stops being persisted.

The three-way distinction this file exists to encode
────────────────────────────────────────────────────
The whole engine turns on separating three things that all look like "no
value came back":

* **Not collected** — the collector could not run. No credential, transport
  refused, command errored, output unparseable. This is never a verdict.
* **Absent** — the collector ran and the item genuinely is not there. A
  registry value that does not exist, a file that is not present, a service
  that is not installed. This *is* an observation, and its meaning depends
  entirely on the rule: for "SMBv1 feature must not be installed", absent is a
  PASS; for "auditd must be installed", absent is a FAIL; for "if IIS is
  present it must be configured thus", absent is NOT_APPLICABLE.
* **Present** — a value was read and is compared.

Because the second of those has no universal meaning, a rule must state it.
:class:`AbsencePolicy` is that statement, and it has no default that could
quietly turn a missing reading into a passing control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

from core.checks.contract import CHECK_DOMAINS, CheckOutcome, normalize_severity
from core.config_audit.operators import is_known_operator

__all__ = [
    "CHECK_TYPES",
    "PLATFORMS",
    "AbsencePolicy",
    "ConfigCheck",
    "Expectation",
    "SpecError",
]


class SpecError(ValueError):
    """A check was declared in a way that cannot be evaluated."""


#: The reusable check-type vocabulary. A check type names *how* something is
#: read, never *what* benchmark asked for it.
#:
#: Types with no collector on a given platform are not silently skipped — the
#: engine reports ERROR, because a rule that cannot be executed has not
#: established anything. ``api`` and ``database_query`` are declared here ahead
#: of their collectors (Phases 9, 10 and 16) so that adding those needs no
#: CHECK-constraint migration on a table holding customer rules, which is the
#: same reservation Phase 2 made for credential types.
CHECK_TYPES: Tuple[str, ...] = (
    "registry",
    "file",
    "directory",
    "permission",
    "service",
    "process",
    "package",
    "port",
    "config_file",
    "command",
    "security_policy",
    "api",
    "database_query",
)

#: Platform targeting values. ``any`` means the check is platform-independent,
#: not "run it everywhere and hope".
PLATFORMS: Tuple[str, ...] = (
    "windows",
    "linux",
    "network_device",
    "database",
    "container",
    "cloud",
    "any",
)


class AbsencePolicy(str, Enum):
    """
    What it means when the collector successfully established that the thing
    the rule names is not present on the target.

    There is deliberately no default. Every value below is correct for some
    real rule and wrong for others, so a rule author has to choose, and a rule
    that fails to choose is refused at construction rather than defaulting to
    whichever answer flatters the score.
    """

    #: Absence satisfies the rule. "SMBv1 must not be installed."
    PASS = "pass"
    #: Absence breaches the rule. "auditd must be installed."
    FAIL = "fail"
    #: The rule is conditional on the thing existing. "If IIS is installed, its
    #: request filtering must be on." A host without IIS is not in scope.
    NOT_APPLICABLE = "not_applicable"
    #: Absence is meaningful but cannot be judged mechanically.
    MANUAL_REVIEW = "manual_review"

    def to_outcome(self) -> CheckOutcome:
        return {
            AbsencePolicy.PASS: CheckOutcome.PASS,
            AbsencePolicy.FAIL: CheckOutcome.FAIL,
            AbsencePolicy.NOT_APPLICABLE: CheckOutcome.NOT_APPLICABLE,
            AbsencePolicy.MANUAL_REVIEW: CheckOutcome.MANUAL_REVIEW,
        }[self]


@dataclass(frozen=True)
class Expectation:
    """
    The state the collected value is required to be in.

    ``description`` is what a report prints as "Expected". It is optional
    because the operator and value usually read well enough on their own
    (``gte 14``), and mandatory in spirit for anything that does not.
    """

    operator: str
    value: Any = None
    description: str = ""

    def __post_init__(self) -> None:
        if not is_known_operator(self.operator):
            raise SpecError(
                f"Expectation: operator {self.operator!r} is not one of "
                f"the supported comparison operators. A misspelled operator "
                f"would otherwise evaluate to False and be recorded as a "
                f"failure against every host."
            )

    def render(self) -> str:
        if self.description:
            return self.description
        if self.value is None:
            return str(self.operator)
        if isinstance(self.value, (list, tuple)):
            return f"{self.operator} {', '.join(str(v) for v in self.value)}"
        return f"{self.operator} {self.value}"

    def as_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"operator": self.operator}
        if self.value is not None:
            payload["expected"] = self.value
        if self.description:
            payload["expected_description"] = self.description
        return payload


@dataclass(frozen=True)
class ConfigCheck:
    """
    One configuration requirement, independent of any host.

    Field groups map one-to-one onto the pipeline the engine runs:
    identity and metadata, platform targeting, collection parameters,
    expected state, and the reporting payload (severity, remediation,
    references) that the finding carries downstream.
    """

    # ── Identity and metadata ────────────────────────────────────────────────
    check_id: str
    title: str
    check_type: str
    #: Parameters for the collector, check-type specific. A ``registry`` check
    #: names hive/path/value; a ``file`` check names a path. Validated by the
    #: collector that consumes them, not here — this module must not grow a
    #: table of every collector's parameters.
    collect: Mapping[str, Any]
    expect: Expectation
    absent: AbsencePolicy

    platforms: Tuple[str, ...] = ("any",)
    domain: str = "host_configuration"
    severity: str = "medium"

    description: str = ""
    rationale: str = ""
    remediation: str = ""
    references: Tuple[str, ...] = ()

    #: Optional operating-system constraints, beyond the coarse ``platforms``.
    #:
    #: ``platforms`` distinguishes Windows from Linux and no further, which is
    #: not enough for benchmark content: a CIS Ubuntu 22.04 benchmark and a CIS
    #: RHEL 9 benchmark are both ``linux``, and dispatching one at the other's
    #: host produces confident, wrong findings — checking a path or a package
    #: name the distribution does not use and reading its absence as a verdict.
    #:
    #: Supported keys, all optional and all ANDed:
    #:   ``os_name_contains``   list of substrings, any of which may match
    #:   ``os_version_prefix``  list of version prefixes, any of which may match
    #:
    #: Empty means the check applies to every host of its platform, which is
    #: what every Phase 3 built-in is.
    os_match: Mapping[str, Any] = field(default_factory=dict)
    #: True where the check needs an account on the target. Dispatching one of
    #: these with no credential yields ERROR, never FAIL — see the engine.
    requires_credentials: bool = True
    #: True where evaluating the check could disrupt the target. This product
    #: scans production and OT hosts; intrusive checks are opt-in at policy
    #: level (Phase 12).
    intrusive: bool = False
    #: Quality of detection for findings this check produces. A check that read
    #: the actual setting is high; one inferring it from a related value is not.
    qod: int = 95
    tags: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.check_id or "").strip():
            raise SpecError("ConfigCheck.check_id is required")
        if not str(self.title or "").strip():
            raise SpecError(f"ConfigCheck {self.check_id}: title is required")
        if self.check_type not in CHECK_TYPES:
            raise SpecError(
                f"ConfigCheck {self.check_id}: check_type {self.check_type!r} "
                f"is not one of {CHECK_TYPES}"
            )
        if self.domain not in CHECK_DOMAINS:
            raise SpecError(
                f"ConfigCheck {self.check_id}: domain {self.domain!r} is not "
                f"one of {CHECK_DOMAINS}"
            )
        if not self.platforms:
            raise SpecError(
                f"ConfigCheck {self.check_id}: platforms must name at least "
                "one platform, or ('any',)"
            )
        unknown = [p for p in self.platforms if p not in PLATFORMS]
        if unknown:
            raise SpecError(
                f"ConfigCheck {self.check_id}: unknown platform(s) {unknown}. "
                f"Supported: {PLATFORMS}"
            )
        if not isinstance(self.absent, AbsencePolicy):
            object.__setattr__(self, "absent", AbsencePolicy(str(self.absent)))
        if not isinstance(self.expect, Expectation):
            raise SpecError(
                f"ConfigCheck {self.check_id}: expect must be an Expectation"
            )
        if not isinstance(self.collect, Mapping) or not self.collect:
            raise SpecError(
                f"ConfigCheck {self.check_id}: collect must name what to read "
                "on the target"
            )
        object.__setattr__(self, "severity", normalize_severity(self.severity))
        object.__setattr__(self, "platforms", tuple(self.platforms))
        object.__setattr__(self, "references", tuple(self.references))
        object.__setattr__(self, "tags", tuple(self.tags))
        if not 0 <= int(self.qod) <= 100:
            raise SpecError(f"ConfigCheck {self.check_id}: qod must be 0-100")

    # ── Platform targeting ───────────────────────────────────────────────────

    def applies_to_platform(self, platform: Optional[str]) -> bool:
        """
        Whether this check is in scope for a host of *platform*.

        An unknown or unfingerprinted platform is **not** treated as a match.
        Guessing here is how a Windows registry rule comes to be evaluated
        against a switch: the engine reports it unresolved instead, which is a
        gap in fingerprinting rather than a verdict about the host.
        """
        if "any" in self.platforms:
            return True
        if not platform:
            return False
        return str(platform).strip().lower() in self.platforms

    def os_applicability(
        self, os_name: Optional[str], os_version_id: Optional[str]
    ) -> Optional[str]:
        """
        Whether this check is in scope for a host running *os_name*.

        Returns None when it applies, or a human-readable reason when it does
        not. A check with no ``os_match`` always applies.

        **An unidentified OS does not match a check that demands one**, and the
        caller must render that as an error rather than as not-applicable: "we
        could not tell what this host runs" and "this host is not what the
        benchmark is for" are different facts, and only the second is a
        legitimate reason for a control to leave the score.
        """
        if not self.os_match:
            return None

        wanted_names = [
            str(v).lower() for v in self.os_match.get("os_name_contains", [])
        ]
        if wanted_names:
            haystack = str(os_name or "").lower()
            if not haystack:
                return "the host's operating system was not identified"
            if not any(token in haystack for token in wanted_names):
                return (
                    f"benchmark targets {', '.join(wanted_names)}; this host "
                    f"reports {os_name!r}"
                )

        wanted_versions = [
            str(v).lower() for v in self.os_match.get("os_version_prefix", [])
        ]
        if wanted_versions:
            version = str(os_version_id or "").lower()
            if not version:
                return "the host's operating system version was not identified"
            if not any(version.startswith(prefix) for prefix in wanted_versions):
                return (
                    f"benchmark targets version(s) {', '.join(wanted_versions)}; "
                    f"this host reports {os_version_id!r}"
                )

        return None

    # ── Persistence adapter (compliance_rules.check_definition) ──────────────

    def to_check_definition(self) -> Dict[str, Any]:
        """
        Render to the JSONB shape stored in ``compliance_rules``.

        ``operator``/``expected`` keep the names the pre-existing compliance
        rules already use, so a reviewer reading either kind of rule row sees
        one shape.
        """
        payload: Dict[str, Any] = {
            "config_check": True,
            "check_id": self.check_id,
            "title": self.title,
            "check_type": self.check_type,
            "collect": dict(self.collect),
            "absent": self.absent.value,
            "domain": self.domain,
            "platforms": list(self.platforms),
            "requires_credentials": self.requires_credentials,
            "intrusive": self.intrusive,
            "qod": self.qod,
        }
        if self.os_match:
            payload["os_match"] = dict(self.os_match)
        payload.update(self.expect.as_dict())
        if self.description:
            payload["description"] = self.description
        if self.rationale:
            payload["rationale"] = self.rationale
        if self.remediation:
            payload["remediation"] = self.remediation
        if self.references:
            payload["references"] = list(self.references)
        if self.tags:
            payload["tags"] = list(self.tags)
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload

    @classmethod
    def from_check_definition(
        cls,
        definition: Mapping[str, Any],
        *,
        check_id: str = "",
        check_type: str = "",
        severity: str = "medium",
        platforms: Optional[Tuple[str, ...]] = None,
    ) -> "ConfigCheck":
        """
        Rebuild a check from stored JSONB.

        The identity fields are accepted as arguments as well as read from the
        payload because they exist as real columns on ``compliance_rules``; the
        column wins where both are present, since that is what the database
        constraints and indexes actually enforce.
        """
        definition = dict(definition or {})
        resolved_id = check_id or definition.get("check_id") or ""
        resolved_type = check_type or definition.get("check_type") or ""
        absent = definition.get("absent")
        if absent is None:
            raise SpecError(
                f"ConfigCheck {resolved_id or '<unnamed>'}: stored definition "
                "has no `absent` policy. A rule that does not say what a "
                "missing reading means cannot be evaluated without inventing "
                "an answer."
            )
        raw_platforms = platforms or definition.get("platforms") or ("any",)
        return cls(
            check_id=resolved_id,
            title=definition.get("title") or resolved_id,
            check_type=resolved_type,
            collect=definition.get("collect") or {},
            expect=Expectation(
                operator=definition.get("operator", "equals"),
                value=definition.get("expected"),
                description=definition.get("expected_description", ""),
            ),
            absent=AbsencePolicy(str(absent)),
            platforms=tuple(raw_platforms),
            domain=definition.get("domain", "host_configuration"),
            severity=severity,
            description=definition.get("description", ""),
            rationale=definition.get("rationale", ""),
            remediation=definition.get("remediation", ""),
            references=tuple(definition.get("references") or ()),
            os_match=definition.get("os_match") or {},
            requires_credentials=bool(definition.get("requires_credentials", True)),
            intrusive=bool(definition.get("intrusive", False)),
            qod=int(definition.get("qod", 95)),
            tags=tuple(definition.get("tags") or ()),
            metadata=definition.get("metadata") or {},
        )

    @classmethod
    def from_rule(cls, rule: Any) -> "ConfigCheck":
        """
        Build from a ``ComplianceRule`` ORM row.

        Takes the row rather than the JSONB so the columns the database
        constrains — ``check_type``, ``target_platform``, ``severity`` — are
        the ones that reach the engine.
        """
        platform = str(getattr(rule, "target_platform", "") or "any").strip().lower()
        return cls.from_check_definition(
            getattr(rule, "check_definition", None) or {},
            check_id=str(getattr(rule, "id", "") or ""),
            check_type=str(getattr(rule, "check_type", "") or ""),
            severity=str(getattr(rule, "severity", "medium") or "medium"),
            platforms=(platform,),
        )

    @staticmethod
    def is_config_rule(rule: Any) -> bool:
        """
        Whether a ``ComplianceRule`` row is one of these rather than one of the
        pre-existing evidence-key rules.

        Read from the definition, not from ``check_type``: the two rule kinds
        share several type names (``registry``, ``command_output``), and the
        marker is what distinguishes a rule the configuration engine can
        execute from one the evidence adapter answers.
        """
        definition = getattr(rule, "check_definition", None) or {}
        return bool(definition.get("config_check"))
