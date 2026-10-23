"""
core/checks/contract.py
─────────────────────────────────────────────────────────────────────────────
The check contract: what an assessment may say, and what it must supply in
order to say it.

Vocabulary is reused, never reinvented
──────────────────────────────────────
Two vocabularies already exist in this product and both are load-bearing:

  * ``scans.cvss.CANONICAL_SEVERITIES`` — the six lowercase severity ratings
    that ``vulnerability_definitions.severity`` and
    ``asset_vulnerabilities.severity`` are CHECK-constrained to.
  * ``compliance_findings.status`` — pass, fail, not_applicable, manual_review,
    exception, remediation_applied, pending_reverify.

``CheckOutcome`` is a strict subset of the second, plus ``error``. The four
shared members carry the identical strings, so a check result can be written to
``compliance_findings.status`` without a translation table. The three omitted
members are *review* states rather than assessment outcomes — a check cannot
conclude "exception" or "pending_reverify" about a host; a person or a workflow
decides those afterwards.

The three rules this module enforces structurally
─────────────────────────────────────────────────
Each one is here because its absence has already produced a wrong answer in
this codebase, and each is enforced in ``CheckResult.__post_init__`` rather
than left to reviewer discipline:

1. **A FAIL must carry evidence.** ``core/compliance_evidence.py`` once wrote a
   hard-coded ``password_policy`` for every host, so every rule reading it
   passed unconditionally everywhere. The inverse — a fail asserted with
   nothing collected behind it — is the same defect pointed the other way, and
   it is the one that reaches a customer as a false positive. A ``FAIL`` with
   an empty ``evidence`` list is rejected at construction.

2. **Not-assessed is never a verdict.** A host the collector could not reach,
   a registry key that does not exist on this SKU, a constraint the matcher
   cannot order — none of these are passes and none are failures.
   ``CheckOutcome.is_verdict`` is True for exactly ``PASS`` and ``FAIL``, and
   every roll-up in this product is required to consult it. ISO A.8.2 was once
   reported as *failed* on hosts the scanner could not authenticate to, which
   is the same error.

3. **An ERROR must say what went wrong.** An error with no message is
   indistinguishable in a log from a check that did nothing, which is how an
   unregistered plugin looked like a registered one for a whole release.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.checks.cvss import CANONICAL_SEVERITIES, SEVERITY_RANK

__all__ = [
    "CHECK_DOMAINS",
    "CheckOutcome",
    "CheckResult",
    "CheckSpec",
    "Evidence",
    "SEVERITY_ORDER",
    "normalize_severity",
    "roll_up_outcomes",
    "severity_at_least",
]


# ─────────────────────────────────────────────────────────────────────────────
# Outcome
# ─────────────────────────────────────────────────────────────────────────────


class CheckOutcome(str, Enum):
    """
    What a check concluded about one target.

    The four non-error members are spelled exactly as
    ``compliance_findings.status`` spells them, so no mapping table stands
    between a check result and a stored compliance verdict.
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    MANUAL_REVIEW = "manual_review"
    #: The check could not be evaluated — unreachable target, refused
    #: authentication, unparseable output, missing collector. Deliberately not
    #: a member of the compliance status vocabulary: it is a scan-time
    #: condition, and storing it as a verdict would assert something about the
    #: host that nothing established.
    ERROR = "error"

    @property
    def is_verdict(self) -> bool:
        """
        True only where the check actually established something about the
        target. Every counter, score and roll-up in this product must gate on
        this rather than on ``!= FAIL``: treating NOT_APPLICABLE, MANUAL_REVIEW
        or ERROR as a pass inflates a compliance score, and treating any of
        them as a fail invents findings on hosts nobody could even reach.
        """
        return self in (CheckOutcome.PASS, CheckOutcome.FAIL)

    @property
    def is_assessed(self) -> bool:
        """
        True where the check ran to completion, including a deliberate
        "this does not apply here". Distinct from :attr:`is_verdict`: a
        NOT_APPLICABLE check was assessed and produced no verdict, which is a
        different fact from one that errored.
        """
        return self is not CheckOutcome.ERROR


#: The assessment domains a check may belong to. Used for reporting rollups,
#: policy selection (Phase 12) and for deciding which engine executes a check.
CHECK_DOMAINS: tuple[str, ...] = (
    "network_service",
    "host_configuration",
    "local_privilege",
    "application_configuration",
    "database",
    "network_device",
    "tls",
    "web_application",
    "cloud",
    "container",
    "virtualization",
)


# ─────────────────────────────────────────────────────────────────────────────
# Severity
# ─────────────────────────────────────────────────────────────────────────────

#: ``compliance_rules.severity`` is CHECK-constrained to a five-value set that
#: uses ``info`` where the finding tables use ``none``. Mapping it here keeps a
#: third spelling of the same idea from entering the product — two already
#: cost this codebase a silent split in every GROUP BY.
_RULE_SEVERITY_ALIASES: Dict[str, str] = {
    "info": "none",
    "informational": "none",
    "unknown": "unscored",
    "": "unscored",
}


def normalize_severity(value: Any) -> str:
    """
    Coerce any severity spelling this product uses into one of
    ``scans.cvss.CANONICAL_SEVERITIES``.

    Unrecognised input becomes ``unscored`` rather than ``none``: the two mean
    different things — no score was published, versus a published score of 0.0
    — and collapsing them hides which checks were never rated.
    """
    text = str(value or "").strip().lower()
    text = _RULE_SEVERITY_ALIASES.get(text, text)
    return text if text in CANONICAL_SEVERITIES else "unscored"


#: Severity vocabulary, weakest first. This is ``ConfigCheck.severity``'s own
#: vocabulary — read from the checks rather than restated — so a floor of
#: "high" means exactly what the check rows mean by it.
#:
#: A scan policy sets the floor and benchmark selection applies it, so both
#: read it from here (G4 moved it from ``core/scan_policy/spec.py``, which
#: re-exports it): compliance's selection must not import scan policy.
SEVERITY_ORDER: Tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def severity_at_least(severity: str, floor: Optional[str]) -> bool:
    """
    Whether *severity* clears *floor*.

    An unrecognised severity **passes** every floor. That direction is
    deliberate: a check whose severity this build does not recognise has not
    been established to be below the threshold, and dropping it would remove a
    check from a scan on the strength of a string nobody defined. The same
    reading ``core.checks.normalize_severity`` gives ``unscored``.
    """
    if not floor:
        return True
    try:
        floor_index = SEVERITY_ORDER.index(str(floor).strip().lower())
    except ValueError:
        return True
    try:
        value_index = SEVERITY_ORDER.index(str(severity).strip().lower())
    except ValueError:
        return True
    return value_index >= floor_index


# ─────────────────────────────────────────────────────────────────────────────
# Evidence
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Evidence:
    """
    One observation supporting a check result.

    ``expected`` and ``observed`` are what make a configuration finding
    actionable and auditable: a reviewer challenging a FAIL needs to see the
    value the benchmark requires beside the value the host actually held. A
    finding that can state only "non-compliant" cannot be defended in an audit
    and cannot be triaged by the person who has to fix it.

    ``raw`` is passed through ``redact_sensitive_data`` on construction.
    Collected configuration is exactly where credentials appear — a connection
    string in a config file, a password in an unattended-install answer file —
    and this object is written to the database and rendered into reports.
    """

    #: What gathered this — a collector name, not a transport.
    #: e.g. "windows_registry", "linux_file", "postgres_query".
    collector: str
    #: What was inspected, in the reviewer's language.
    description: str
    expected: Optional[str] = None
    observed: Optional[str] = None
    #: Verbatim collector output, redacted. None means nothing was captured,
    #: which is a different fact from an empty string ("captured, and empty").
    raw: Optional[str] = None
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not str(self.collector or "").strip():
            raise ValueError("Evidence.collector is required")
        if not str(self.description or "").strip():
            raise ValueError("Evidence.description is required")
        if self.raw is not None:
            # Imported inside the function rather than at module scope so this
            # package stays importable from contexts that load models without
            # the heavier scans dependencies already resolved.
            from core.checks.finding_normalizer import redact_sensitive_data

            object.__setattr__(self, "raw", redact_sensitive_data(str(self.raw)))
        if self.collected_at.tzinfo is None:
            raise ValueError(
                "Evidence.collected_at must be timezone-aware UTC — a naive "
                "datetime renders as local time beside UTC siblings."
            )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "collector": self.collector,
            "description": self.description,
            "expected": self.expected,
            "observed": self.observed,
            "raw": self.raw,
            "collected_at": self.collected_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Check specification (what a check *is*)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CheckSpec:
    """
    The declaration of a check, independent of any target it is run against.

    This is what a scan policy selects (Phase 12), what the check registry
    indexes, and what a report cites. It is deliberately separate from
    :class:`CheckResult`: one spec produces one result per target.
    """

    check_id: str
    title: str
    domain: str
    #: Platforms this check can be evaluated on. ``("any",)`` for checks that
    #: are platform-independent (a TLS handshake, an open-port observation).
    platforms: tuple[str, ...] = ("any",)
    severity: str = "medium"
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    #: True where the check cannot run without an account on the target. The
    #: scheduler and the policy engine both need this: dispatching a
    #: credentialed check with no credential produces ERROR, not FAIL, and a
    #: policy that selects only uncredentialed checks must be able to say so.
    requires_credentials: bool = False
    #: True where the check may disrupt the target — a brute-force attempt, a
    #: crash-triggering probe, a write. This product scans production and OT
    #: hosts; an audit that causes an outage is worse than the finding it would
    #: have produced. Intrusive checks are opt-in at policy level.
    intrusive: bool = False

    def __post_init__(self) -> None:
        if not str(self.check_id or "").strip():
            raise ValueError("CheckSpec.check_id is required")
        if not str(self.title or "").strip():
            raise ValueError(f"CheckSpec {self.check_id}: title is required")
        if self.domain not in CHECK_DOMAINS:
            raise ValueError(
                f"CheckSpec {self.check_id}: domain {self.domain!r} is not one "
                f"of {CHECK_DOMAINS}"
            )
        object.__setattr__(self, "severity", normalize_severity(self.severity))
        if not self.platforms:
            raise ValueError(
                f"CheckSpec {self.check_id}: platforms must name at least one "
                "platform, or ('any',)"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Check result (what a check *concluded*, for one target)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CheckResult:
    """
    One check's conclusion about one target.

    See the module docstring for the three invariants enforced below and why
    each exists.
    """

    check_id: str
    outcome: CheckOutcome
    title: str = ""
    severity: str = "medium"
    #: The thing assessed — an asset id, IP, hostname, or a
    #: "host:port"/"instance/database" locator for sub-target checks.
    target: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    #: One of ``scans.finding_normalizer.DetectionMethod``. Configuration
    #: checks are ``config_check``; this is the field the report uses to show
    #: a proven finding differently from an inferred one.
    detection_method: str = "config_check"
    #: One of ``scans.finding_normalizer.Confidence``.
    confidence: str = "Confirmed"
    #: Quality of detection, 0-100. A configuration check that read the actual
    #: setting is high; one that inferred it from a related value is not.
    qod: int = 95
    #: CVEs this result also establishes, where the check happens to prove one.
    #: Usually empty — the point of this contract is findings that have no CVE.
    cve_ids: List[str] = field(default_factory=list)
    #: Required when ``outcome is ERROR``; ignored otherwise.
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.check_id or "").strip():
            raise ValueError("CheckResult.check_id is required")
        if not isinstance(self.outcome, CheckOutcome):
            self.outcome = CheckOutcome(str(self.outcome))
        self.severity = normalize_severity(self.severity)

        # Invariant 1 — a FAIL must carry evidence.
        if self.outcome is CheckOutcome.FAIL and not self.evidence:
            raise ValueError(
                f"Check {self.check_id}: a FAIL must carry at least one "
                "Evidence entry. A finding asserted with nothing collected "
                "behind it cannot be defended in an audit and reaches the "
                "customer as a false positive."
            )

        # Invariant 3 — an ERROR must say what went wrong.
        if self.outcome is CheckOutcome.ERROR and not str(self.error or "").strip():
            raise ValueError(
                f"Check {self.check_id}: an ERROR outcome must set `error` to "
                "the reason it could not be evaluated."
            )

        if not 0 <= int(self.qod) <= 100:
            raise ValueError(f"Check {self.check_id}: qod must be 0-100")

    # ── Derived ──────────────────────────────────────────────────────────────

    @property
    def is_verdict(self) -> bool:
        return self.outcome.is_verdict

    @property
    def is_finding(self) -> bool:
        """
        True where this result should become a row in the finding model. Only
        a FAIL is a finding: a pass is a compliance verdict, not a
        vulnerability, and the other three are not verdicts at all.
        """
        return self.outcome is CheckOutcome.FAIL

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "outcome": self.outcome.value,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "evidence": [e.as_dict() for e in self.evidence],
            "remediation": self.remediation,
            "references": list(self.references),
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "qod": self.qod,
            "cve_ids": list(self.cve_ids),
            "error": self.error,
            "metadata": dict(self.metadata),
        }

    # ── Constructors that make the common cases hard to get wrong ────────────

    @classmethod
    def error_result(
        cls, check_id: str, target: str, reason: str, **kwargs: Any
    ) -> "CheckResult":
        """
        The outcome for "could not evaluate". Provided as a named constructor
        because the alternative every engine reaches for under time pressure is
        returning FAIL, which asserts a finding about a host nothing was
        collected from.
        """
        return cls(
            check_id=check_id,
            outcome=CheckOutcome.ERROR,
            target=target,
            error=reason,
            **kwargs,
        )

    @classmethod
    def not_applicable(
        cls, check_id: str, target: str, reason: str = "", **kwargs: Any
    ) -> "CheckResult":
        metadata = dict(kwargs.pop("metadata", {}) or {})
        if reason:
            metadata["not_applicable_reason"] = reason
        return cls(
            check_id=check_id,
            outcome=CheckOutcome.NOT_APPLICABLE,
            target=target,
            metadata=metadata,
            **kwargs,
        )


def roll_up_outcomes(outcomes: Sequence[CheckOutcome]) -> CheckOutcome:
    """
    Reduce several checks' outcomes to one.

    Precedence, strongest first: FAIL > ERROR > MANUAL_REVIEW > PASS >
    NOT_APPLICABLE.

    Two properties of that ordering are deliberate and were both wrong
    somewhere in this codebase before:

    * **ERROR outranks PASS.** A control with nine passing checks and one that
      could not be evaluated has not been established as compliant. Ranking
      PASS higher would report it as compliant on the strength of the checks
      that happened to run.
    * **FAIL outranks ERROR.** One check that positively established a problem
      is a finding regardless of how many of its siblings were unreachable.

    ``roll_up_statuses()`` in the compliance router does the equivalent job for
    stored compliance verdicts; this one is for in-flight check results. They
    must not disagree — see the compliance section of CLAUDE.md for what
    happened when four call sites each rolled up their own way.
    """
    if not outcomes:
        return CheckOutcome.NOT_APPLICABLE
    order = [
        CheckOutcome.FAIL,
        CheckOutcome.ERROR,
        CheckOutcome.MANUAL_REVIEW,
        CheckOutcome.PASS,
        CheckOutcome.NOT_APPLICABLE,
    ]
    present = set(outcomes)
    for candidate in order:
        if candidate in present:
            return candidate
    return CheckOutcome.NOT_APPLICABLE
