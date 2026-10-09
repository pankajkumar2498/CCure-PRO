"""
The shared vocabulary of the CCure integration contracts, version 1.

Each enumeration is the *contract* spelling. Where Audit already has the
concept, the design document gives the mapping from Audit's internal value;
the internal values are deliberately not imported here, because this package
may import no module's code.

The rule every enumeration below serves: **unknown is never reported as a
known state.** A check that could not run is not a pass, an asset nobody
assessed is not clean, a finding with no deadline is not within its deadline.
"""

from __future__ import annotations

from enum import Enum


class Module(str, Enum):
    """The four CCure modules, plus the shared platform."""

    POLICY_PRO = "policy_pro"
    AUDIT = "audit"
    RANK = "rank"
    IR = "ir"
    PLATFORM = "platform"


class AssessmentState(str, Enum):
    """
    The result of assessing one control or one check against one scope.

    ``PASS`` and ``FAIL`` are the only verdicts. The other four say why there
    is no verdict, and each needs a different action from the reader:

    * ``NOT_ASSESSED`` — nothing was run against it (out of the scan's policy,
      no credential in scope, no applicable asset reached).
    * ``NOT_APPLICABLE`` — it was considered and does not apply to the target.
    * ``MANUAL_REVIEW`` — it needs a human decision; automation cannot settle it.
    * ``ERROR`` — it was attempted and could not be evaluated.

    Absence of findings is never ``PASS``.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"


#: The two states that are verdicts. Every roll-up must gate on this.
VERDICT_STATES = frozenset({AssessmentState.PASS, AssessmentState.FAIL})


class CoverageState(str, Enum):
    """How completely one asset was assessed."""

    ASSESSED = "ASSESSED"
    PARTIALLY_ASSESSED = "PARTIALLY_ASSESSED"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


class AssessmentMethod(str, Enum):
    """The assessment methods Audit applies to an asset."""

    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    NETWORK_CHECKS = "network_checks"
    CREDENTIALED_ACCESS = "credentialed_access"
    PACKAGE_VULNERABILITY = "package_vulnerability"
    CONFIGURATION_AUDIT = "configuration_audit"
    WEB_APPLICATION = "web_application"
    MALWARE_SCAN = "malware_scan"


class MethodOutcome(str, Enum):
    """
    What happened to one method on one asset.

    ``unknown`` exists because Audit does not yet record a structured outcome
    for every method on every path. It is the honest answer where the record
    is missing, and it must never be read as ``completed``.
    """

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_RUN = "not_run"
    NOT_IMPLEMENTED = "not_implemented"
    UNKNOWN = "unknown"


class CredentialOutcome(str, Enum):
    """
    The result of the authenticated session a credentialed assessment needs.

    The four failure members are distinct because each sends the operator to a
    different fix: a wrong password, an account without rights, a host that
    did not answer, and anything else. ``FAILED_UNCLASSIFIED`` is used where
    the transport could not tell which.
    """

    SUCCEEDED = "SUCCEEDED"
    AUTHENTICATION_REJECTED = "AUTHENTICATION_REJECTED"
    INSUFFICIENT_PRIVILEGE = "INSUFFICIENT_PRIVILEGE"
    UNREACHABLE = "UNREACHABLE"
    FAILED_UNCLASSIFIED = "FAILED_UNCLASSIFIED"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


class Severity(str, Enum):
    """
    Technical severity. ``unscored`` (no rating published) is a different fact
    from ``none`` (a published rating of zero).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNSCORED = "unscored"


class DefinitionType(str, Enum):
    """What kind of catalogue entry a finding is an instance of."""

    CVE = "cve"
    CONFIG_CHECK = "config_check"
    PLUGIN_CHECK = "plugin_check"
    PRIVILEGE_CHECK = "privilege_check"


class DetectionMethod(str, Enum):
    """How Audit concluded that a finding applies to the host."""

    VERSION_MATCH = "version_match"
    CREDENTIALED_PACKAGE = "credentialed_package"
    PACKAGE_PRESENT = "package_present"
    BANNER_MATCH = "banner_match"
    VERSION_IMPRECISE = "version_imprecise"
    SERVICE_PRODUCT = "service_product"
    OS_REPORTED = "os_reported"
    CONFIG_CHECK = "config_check"
    ENGINE_REPORTED = "engine_reported"
    IMPORTED = "imported"
    PORT_OBSERVATION = "port_observation"
    UNVERIFIED = "unverified"


class DetectionConfidence(str, Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFORMATIONAL = "informational"
    UNVERIFIED = "unverified"


class DetectionStatus(str, Enum):
    """Whether the finding is present on the host (a detection question)."""

    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED = "accepted"


class RemediationState(str, Enum):
    """
    Where the work to fix a finding stands. ``verified_fixed`` is reached only
    by a scan, never by a person and never by another module.
    """

    OPEN = "open"
    ASSIGNED = "assigned"
    IN_REMEDIATION = "in_remediation"
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED_FIXED = "verified_fixed"
    REOPENED = "reopened"
    RISK_ACCEPTED = "risk_accepted"


class SlaState(str, Enum):
    """
    ``not_applicable`` — the finding carries no deadline. It is deliberately not
    ``within_sla``: "inside its deadline" and "has no deadline" are different.
    """

    WITHIN_SLA = "within_sla"
    DUE_SOON = "due_soon"
    OVERDUE = "overdue"
    RESOLVED = "resolved"
    PENDING_VERIFICATION = "pending_verification"
    NOT_APPLICABLE = "not_applicable"


class ExploitAvailability(str, Enum):
    """
    Threat-intelligence exploit evidence for a vulnerability (SRS 7.3.7.4).

    This describes the vulnerability, not the host: a public exploit existing
    does not mean this host is exploitable.
    """

    NONE_KNOWN = "none_known"
    PUBLIC_EXPLOIT = "public_exploit"
    VERIFIED_EXPLOIT = "verified_exploit"
    ACTIVELY_EXPLOITED = "actively_exploited"
    NOT_APPLICABLE = "not_applicable"


class ValueStatus(str, Enum):
    """Why a measured value is or is not present."""

    AVAILABLE = "available"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_COLLECTED = "not_collected"
    NOT_APPLICABLE = "not_applicable"


class BaselineMappingState(str, Enum):
    """How Audit can assess one control of a received policy baseline."""

    AUTOMATED = "AUTOMATED"
    PARTIALLY_AUTOMATED = "PARTIALLY_AUTOMATED"
    ATTESTATION_REQUIRED = "ATTESTATION_REQUIRED"
    UNKNOWN_CONTROL = "UNKNOWN_CONTROL"
    UNSUPPORTED = "UNSUPPORTED"


class ParameterHandling(str, Enum):
    """What Audit does with one organisation parameter of a baseline."""

    HONOURED = "HONOURED"
    RECORDED_NOT_HONOURED = "RECORDED_NOT_HONOURED"
    UNKNOWN_PARAMETER = "UNKNOWN_PARAMETER"
    INVALID_VALUE = "INVALID_VALUE"


class Applicability(str, Enum):
    """Whether the policy owner declares a control applicable to the organisation."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class ComplianceDisposition(str, Enum):
    """
    A human or workflow decision recorded on a control *alongside* its state.

    Audit's compliance register stores these in place of a verdict; the
    contract keeps them apart so a disposition can never masquerade as a pass.
    """

    NONE = "none"
    EXCEPTION_APPROVED = "exception_approved"
    REMEDIATION_APPLIED = "remediation_applied"
    PENDING_REVERIFICATION = "pending_reverification"
    ATTESTED = "attested"


class AssessmentKind(str, Enum):
    """The kind of Audit assessment a result describes."""

    NETWORK = "network"
    ASSET_DISCOVERY = "asset_discovery"
    VULNERABILITY_AUDIT = "vulnerability_audit"
    CREDENTIALED = "credentialed"
    COMPLIANCE = "compliance"
    WEB_APPLICATION = "web_application"


class AssessmentStatus(str, Enum):
    """How an assessment ended. Only terminal assessments produce a result."""

    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssessmentOrigin(str, Enum):
    MANUAL = "manual"
    SCHEDULE = "schedule"
    INTEGRATION_REQUEST = "integration_request"
