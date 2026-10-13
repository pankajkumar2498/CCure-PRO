"""
core/checks/finding_normalizer.py
─────────────────────────────────────────────────────────────────────────────
Normalizes raw scan telemetry from every scan engine (Nmap, credentialed
audits, DAST, host discovery, imported third-party results) into a
standardized, host-aware finding structure.

Design contract
───────────────
Everything this module emits must be traceable to observed data. Concretely:

  * CVSS scores and vectors come from the vulnerability feed and are
    independently recomputed by ``core.checks.cvss``. If a CVE carries no published
    vector the finding is marked "Unscored" — a score is never synthesized.

  * A finding is bound to a port/service only when the scan actually observed
    that binding (via ``service_id`` or an explicit port). Product names are
    never pattern-matched out of CVE prose to guess a port.

  * Titles and remediation text are taken from the feed record or derived from
    structured CPE version boundaries. When no remediation data exists the
    finding says so rather than emitting a plausible-sounding upgrade string.

  * Plugin output is reproduced verbatim from the scanner. When the scanner
    captured none, ``evidence_available`` is False and the report states that
    no output was captured instead of restating metadata as if it were proof.

  * Every finding carries a ``detection_method`` and ``confidence`` so that a
    version-confirmed match is visually distinguishable from a
    product-present-but-version-unknown match. Findings with no evidence tying
    them to the host are excluded from the report body and accounted for in
    ``ScanFindings.excluded``.

Where verification happens
──────────────────────────
``verify_host_findings`` is the single verification entry point and is called
by the vulnerability engine while the scan is still running, not at report
time. A host record therefore carries verified findings from the moment it
leaves the engine, and everything downstream — risk scoring, asset sync, the
API, the reports — reads the same verified set instead of re-deriving it or,
worse, working from raw candidates.

Candidates that fail verification are not discarded: they are handed back as
``ExcludedFinding`` entries, stored alongside the host, and reproduced in the
report's suppressed-candidates appendix, so the filtering stays auditable.

``build_scan_report`` still verifies any candidate it is handed, so payloads
written before this moved (and credentialed audits, which do not run the
vulnerability engine) normalize exactly as they always did.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.checks.cvss import (
    SEVERITY_RANK,
    CvssData,
    parse_cvss_vector,
    severity_from_score,
)
from core.checks.platform_scope import (
    PLATFORM_LABELS,
    declared_platforms,
    describe_scope,
    scope_excludes_host,
)

# ─────────────────────────────────────────────────────────────────────────────
# Secret redaction
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = [
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?header|bearer)"
            r'\s*[:=]\s*["\']?([^"\'\s;&]+)["\']?'
        ),
        r"\1=[REDACTED]",
    ),
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]+"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)Basic\s+[a-zA-Z0-9+/=]{8,}"), "Basic [REDACTED]"),
    (
        re.compile(
            r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)"
        ),
        r"\1 [REDACTED] \2",
    ),
]


def redact_sensitive_data(text: str) -> str:
    """Mask credentials, API keys, tokens, and private keys with [REDACTED]."""
    if not text:
        return ""
    result = str(text)
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Detection provenance
# ─────────────────────────────────────────────────────────────────────────────


class DetectionMethod(str, Enum):
    """How the scanner concluded this finding applies to this host."""

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


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    POTENTIAL = "Potential"
    INFORMATIONAL = "Informational"
    UNVERIFIED = "Unverified"


#: Quality of Detection, 0-100, modelled on the Greenbone/OpenVAS QoD scale.
#: It expresses how reliably the detection method establishes that the finding
#: actually applies to the host. The report shows findings at or above
#: ``QOD_REPORT_THRESHOLD`` in the body and relegates the rest to the
#: suppressed-candidates appendix, mirroring how OpenVAS defaults to qod>=70
#: and Nessus defaults to hiding "potential false alarms".
QOD_BY_METHOD: Dict["DetectionMethod", int] = {}

#: Findings scoring below this are withheld from the report body. Raise it for
#: a stricter report, lower it to surface more unverified candidates.
QOD_REPORT_THRESHOLD = 70


#: Detection method → (confidence, plain-English explanation printed in the report)
DETECTION_SEMANTICS: Dict[DetectionMethod, Tuple[Confidence, str]] = {
    DetectionMethod.VERSION_MATCH: (
        Confidence.CONFIRMED,
        "The detected service version falls inside the vulnerable version range "
        "published for this CVE.",
    ),
    DetectionMethod.CREDENTIALED_PACKAGE: (
        Confidence.CONFIRMED,
        "An authenticated query of the host's package manager returned an "
        "installed version inside the vulnerable range.",
    ),
    DetectionMethod.PACKAGE_PRESENT: (
        Confidence.POTENTIAL,
        "The affected package appears to be present on this host, but no "
        "version was recorded, so the finding could not be checked against the "
        "vulnerable range. Confirm the installed version before remediating.",
    ),
    DetectionMethod.BANNER_MATCH: (
        Confidence.CONFIRMED,
        "The service banner reported a product and version inside the "
        "vulnerable range.",
    ),
    DetectionMethod.VERSION_IMPRECISE: (
        Confidence.POTENTIAL,
        "The affected product is present and its version may fall inside the "
        "vulnerable range, but the version this scan could read is not precise "
        'enough to decide: an open-ended bound (for example "9.6.0 or '
        "later\"), a vendor's or distribution's own build that carries "
        "backported fixes without changing the version it reports (for example "
        "Microsoft's OpenSSH for Windows, or a Debian or Ubuntu package), or a "
        'release named without its update level (for example "V19" against a '
        "fix in V19 Update 2). Confirm the exact version or patch level before "
        "remediating.",
    ),
    DetectionMethod.SERVICE_PRODUCT: (
        Confidence.POTENTIAL,
        "The affected product is running on this port, but the scan could not "
        "determine its exact version. Confirm the version before remediating.",
    ),
    DetectionMethod.CONFIG_CHECK: (
        Confidence.CONFIRMED,
        "An active configuration check performed against the service returned "
        "a failing result.",
    ),
    DetectionMethod.ENGINE_REPORTED: (
        Confidence.POTENTIAL,
        "The scanning engine matched this vulnerability to the host, but the "
        "vulnerability feed holds no CPE version range for it, so the affected "
        "version could not be independently verified. Confirm before acting.",
    ),
    DetectionMethod.IMPORTED: (
        Confidence.POTENTIAL,
        "Imported from a third-party scanner result. Detection logic was "
        "supplied by the originating tool and has not been re-verified.",
    ),
    DetectionMethod.OS_REPORTED: (
        Confidence.POTENTIAL,
        "This CVE is published against the operating system rather than any "
        "listening service, and this host runs that operating system. An "
        "unauthenticated scan cannot read the exact patch level, so whether "
        "this specific host is still affected is unconfirmed. It is reported "
        "against the host, not against a port. Verify with an authenticated "
        "scan or the local package manager before remediating.",
    ),
    DetectionMethod.PORT_OBSERVATION: (
        Confidence.INFORMATIONAL,
        "Observed open port. Recorded for attack-surface inventory; this is "
        "not a vulnerability by itself.",
    ),
    DetectionMethod.UNVERIFIED: (
        Confidence.UNVERIFIED,
        "No observed evidence links this CVE to this host.",
    ),
}


QOD_BY_METHOD.update(
    {
        DetectionMethod.CONFIG_CHECK: 99,  # active probe returned a failing result
        DetectionMethod.CREDENTIALED_PACKAGE: 97,  # package manager version in range
        DetectionMethod.VERSION_MATCH: 95,  # fingerprinted version in range
        DetectionMethod.BANNER_MATCH: 75,  # banner version in range
        DetectionMethod.IMPORTED: 70,  # third-party tool asserted it
        DetectionMethod.PORT_OBSERVATION: 70,  # the port really is open
        # Deliberately at the reporting threshold, not below it.
        #
        # An open-ended fingerprint ("PostgreSQL 9.6.0 or later" — the server
        # discloses no version before authentication) admits every CVE fixed
        # above that floor, which on a real host produced 124 findings against
        # an install actually running 18.3, one of them a 2002 CVE at CVSS
        # 10.0. Dropping this to 30 would suppress them, and it is tempting.
        #
        # It is also wrong. On an *unauthenticated* scan the tool genuinely
        # cannot rule those out, and suppressing them would convert a visible
        # "confirm the version" prompt into a silent false negative — the
        # failure this codebase treats as the worst one. The 124 rows are a
        # readability problem, and readability is solved by grouping: they roll
        # up to a single "PostgreSQL DB · 124 findings · no published fix" row
        # in the component view. What fixes the *accuracy* is credentials, and
        # `_restate_findings_for_corrected_ports` already applies the
        # authenticated version when one exists — which is why the latest
        # credentialed scan of that host reports none of them.
        #
        # test_pipeline_contracts.py::test_service_precision_reaches_the_version_comparison
        # pins this behaviour.
        DetectionMethod.VERSION_IMPRECISE: 70,  # in range, but range-bounded fingerprint
        DetectionMethod.SERVICE_PRODUCT: 30,  # product present, version unknown
        DetectionMethod.OS_REPORTED: 30,  # right OS, patch level unknown
        DetectionMethod.PACKAGE_PRESENT: 30,  # package present, version unknown
        DetectionMethod.ENGINE_REPORTED: 30,  # asserted, nothing verifiable
        DetectionMethod.UNVERIFIED: 0,  # disproved
    }
)


class RemediationConfidence(str, Enum):
    VENDOR_PATCH = "vendor_patch"
    VERSION_BOUNDARY = "version_boundary"
    FEED_SUPPLIED = "feed_supplied"
    NONE_PUBLISHED = "none_published"
    #: The fix is a configuration change this product's own rule prescribes,
    #: not a patch anybody published. Distinct from NONE_PUBLISHED, which the
    #: report renders as "no published fix — compensating controls only": that
    #: is true of an unpatched CVE and false of a hardening control, where the
    #: fix is known, exact and available now.
    CONFIGURATION_GUIDANCE = "configuration_guidance"


# ─────────────────────────────────────────────────────────────────────────────
# Records
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ServiceRecord:
    """An open port observed on a host."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    banner: str = ""
    #: CPEs the scanner assigned to this service, as (vendor, product) pairs.
    #: Where the scan supplied these, product identity is a comparison rather
    #: than an interpretation of banner text.
    cpe_identities: Tuple[Tuple[str, str], ...] = ()
    #: What the version pins down: "exact", "floor", "ceiling" or "unknown",
    #: as recorded by the stage that measured it.
    version_precision: str = ""
    #: Whether the network can reach this service: "exposed", "host_only",
    #: "filtered" or "undetermined". Set when an authenticated session read the
    #: host's socket table, empty for an ordinary port scan — which observes
    #: reachability directly and has nothing extra to say about it.
    exposure: str = ""
    #: The socket's bind address class, when the host reported one.
    bind_scope: str = ""

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}"

    @property
    def is_reachable(self) -> bool:
        """
        Whether this service is reachable from the scanner.

        A loopback-bound listener is running but unreachable, and must not be
        counted as attack surface. Everything else is treated as reachable
        until something establishes otherwise — the conservative direction for
        an inventory whose purpose is to bound exposure.
        """
        if self.exposure == "host_only":
            return False
        state = (self.state or "open").lower()
        return state in ("open", "open|filtered", "listen", "listening")

    @property
    def product_label(self) -> str:
        """Human product string, or empty when the scan could not fingerprint it."""
        parts = [p for p in (self.product, self.version, self.extra) if p]
        return " ".join(parts)


@dataclass
class Remediation:
    summary: str
    confidence: RemediationConfidence
    fixed_version: Optional[str] = None
    patch_url: Optional[str] = None
    #: The component the upgrade applies to, kept separate from ``summary`` so
    #: the executive remediation plan can group findings by upgrade target.
    #: Grouping on the prose instead collapses nothing, because the summary
    #: names the CVE and is therefore unique per finding.
    product: Optional[str] = None
    #: The last release published as affected, when only an inclusive upper
    #: bound is known. Kept apart from ``fixed_version`` because the two ask
    #: for different upgrades: "8.0.42 or later" includes 8.0.42, "later than
    #: 8.0.44" does not. Folding this into ``fixed_version`` is how a report
    #: told an administrator to upgrade MySQL to 8.0.44, a release the same
    #: CVE names as vulnerable — the value was written back onto the record and
    #: read on the next verification pass as a first fixed release.
    last_affected_version: Optional[str] = None

    @property
    def upgrade_target(self) -> str:
        """The release to upgrade to, as a phrase; "" when none is known."""
        return upgrade_target(self.fixed_version, self.last_affected_version)

    @property
    def is_actionable(self) -> bool:
        return self.confidence in (
            RemediationConfidence.VENDOR_PATCH,
            RemediationConfidence.VERSION_BOUNDARY,
            RemediationConfidence.FEED_SUPPLIED,
            RemediationConfidence.CONFIGURATION_GUIDANCE,
        )


@dataclass
class StandardizedFinding:
    """One vulnerability (or observation) on one host."""

    # ── Identity ─────────────────────────────────────────────────────────────
    plugin_id: str
    plugin_name: str
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    plugin_family: str = "General"

    # ── Host / service binding ───────────────────────────────────────────────
    host: str = ""
    hostname: str = ""
    port: Optional[int] = None
    protocol: str = "tcp"
    service_name: str = ""
    service_product: str = ""
    detected_version: str = ""
    #: Why detection failed, when it did: "version_outside_range",
    #: "product_absent", or "platform_mismatch". Recorded by the check that
    #: made the call, so the suppression reason states what actually happened
    #: rather than inferring it from which fields happen to be populated.
    suppression_basis: str = ""
    #: When ``suppression_basis`` is "platform_mismatch" because the record
    #: names its platforms: those platforms, and the one this host runs. Kept so
    #: the appendix can say "published for Android only; this host runs
    #: Windows" rather than a sentence that fits every mismatch.
    applies_to_platforms: Tuple[str, ...] = ()
    host_platform: str = ""
    #: When ``suppression_basis`` is "countermeasure_observed": what the probe
    #: saw, completing the sentence "Ruled out: …".
    suppression_detail: str = ""

    # ── Scoring (never fabricated) ───────────────────────────────────────────
    cvss: Optional[CvssData] = None
    severity: str = "Unscored"
    severity_source: str = "unscored"

    # ── Narrative ────────────────────────────────────────────────────────────
    synopsis: str = ""
    description: str = ""

    # ── Evidence ─────────────────────────────────────────────────────────────
    evidence: str = ""
    evidence_available: bool = False
    detection_method: DetectionMethod = DetectionMethod.UNVERIFIED
    confidence: Confidence = Confidence.UNVERIFIED

    # ── Remediation ──────────────────────────────────────────────────────────
    remediation: Optional[Remediation] = None

    # ── Threat intelligence ──────────────────────────────────────────────────
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False
    kev_due_date: str = ""

    #: Whether a public exploit is known to exist for the CVE.
    #:
    #: **Three-valued, and the third value is the point.** ``True`` and
    #: ``False`` are what the exploit feeds established; ``None`` means this
    #: scan recorded nothing, which happens whenever the finding came from a
    #: path that does not consult them. Defaulting the absent case to ``False``
    #: would state that no exploit exists on the strength of never having
    #: looked, and a reader deciding what to patch first cannot tell that
    #: claim from a real one.
    #:
    #: It says a public exploit exists for the *vulnerability*. It says nothing
    #: about whether this host is exploitable, which depends on configuration
    #: and reachability the feed knows nothing about.
    has_exploit: Optional[bool] = None

    #: The remediation priority the backend computed (``P1``-``P4``), carried
    #: verbatim. Never re-derived here: ``core.vuln_intel.compute_priority``
    #: folds CVSS, EPSS, KEV membership and exploit availability together, and
    #: a second implementation in the report layer would drift from the one the
    #: dashboard and the findings queue show.
    priority_level: str = ""

    #: The vendor's own remediation wording, as the advisory published it.
    #:
    #: Distinct from ``remediation``, which is this product's normalised
    #: upgrade instruction. A CSAF advisory prefixes its text with the provider
    #: and advisory id, and that prefix is load-bearing: a Chrome CVE reaches a
    #: CISA ICS advisory because an ICS product embeds Chrome, and that
    #: advisory's mitigation is written for the ICS context. Rendered verbatim
    #: so it can never read as the desktop vendor's own advice.
    vendor_remediation: str = ""

    # ── Feed provenance / lifecycle ──────────────────────────────────────────
    references: List[str] = field(default_factory=list)
    published_at: str = ""
    last_modified_at: str = ""
    first_found_at: str = ""
    last_found_at: str = ""
    status: str = "open"
    mitigation_status: str = "Active"

    # ── Web-scan specific ────────────────────────────────────────────────────
    url: Optional[str] = None
    http_method: Optional[str] = None
    vulnerable_parameter: Optional[str] = None

    # ── Applicability ────────────────────────────────────────────────────────
    #: Which component of the affected package the flaw actually sits in.
    #: "remote"  — the listening service on this port is exploitable
    #: "client"  — the flaw is in a client/utility binary shipped alongside it,
    #:             so the open port is not the attack path
    #: "local"   — exploitation requires local access per the CVSS vector
    attack_surface: str = "remote"
    applicability_note: str = ""

    # ── Data-quality notes surfaced in the report ────────────────────────────
    integrity_warnings: List[str] = field(default_factory=list)

    # ── Derived helpers ──────────────────────────────────────────────────────

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    @property
    def cvss_score(self) -> Optional[float]:
        return self.cvss.score if self.cvss else None

    @property
    def cvss_vector(self) -> str:
        return self.cvss.vector_string if self.cvss else ""

    @property
    def cvss_version(self) -> str:
        return self.cvss.version if self.cvss else ""

    @property
    def port_label(self) -> str:
        if self.port is None:
            return "Host-level (not port-specific)"
        svc = self.service_name or "unknown"
        return f"{self.port}/{self.protocol} ({svc})"

    @property
    def primary_cve(self) -> str:
        return self.cve_ids[0] if self.cve_ids else ""

    @property
    def qod(self) -> int:
        """Quality of Detection (0-100) implied by how this was found."""
        return QOD_BY_METHOD.get(self.detection_method, 0)

    @property
    def is_reportable(self) -> bool:
        """
        Whether this finding belongs in the report body.

        Anything below the QoD threshold is withheld and accounted for in the
        suppressed-candidates appendix. KEV entries are exempt: the cost of
        omitting a vulnerability that is being exploited in the wild outweighs
        the cost of one unverified line, so those are surfaced and flagged.
        """
        if self.in_kev:
            return self.confidence != Confidence.UNVERIFIED
        return self.qod >= QOD_REPORT_THRESHOLD

    def sort_key(self) -> tuple:
        """
        Risk ordering: KEV first (known exploited in the wild), then whether the
        listening service is actually the attack path, then severity, then EPSS
        (probability of exploitation), then CVSS, then confidence.

        Attack surface ranks above severity because a Critical that can only be
        triggered against the *client* binary is a smaller operational risk than
        a High reachable from the network, and burying the latter under the
        former is how a prioritised report loses its value.
        """
        return (
            1 if self.in_kev else 0,
            1 if self.attack_surface == "remote" else 0,
            self.severity_rank,
            self.epss_score or 0.0,
            self.cvss_score or 0.0,
            1 if self.confidence == Confidence.CONFIRMED else 0,
        )


@dataclass
class HostReport:
    """All observations for a single host."""

    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_name: str = ""
    device_category: str = ""
    is_active: bool = True
    services: List[ServiceRecord] = field(default_factory=list)
    findings: List[StandardizedFinding] = field(default_factory=list)
    credentialed: bool = False
    auth_status: str = ""

    @property
    def display_name(self) -> str:
        """
        Hostname and IP, or just the IP when no name resolved.

        Never prints the IP twice — an unresolved name is simply absent.
        """
        if self.hostname and self.hostname.strip() and self.hostname.strip() != self.ip:
            return f"{self.hostname} ({self.ip})"
        return self.ip

    @property
    def os_label(self) -> str:
        """Reports the OS only when fingerprinting actually produced one."""
        value = (self.os_name or "").strip()
        if not value or value.lower() in ("unknown", "n/a", "none", "linux / windows"):
            return "Not determined"
        return value

    @property
    def reachable_services(self) -> List[ServiceRecord]:
        """
        The services that count as attack surface.

        Excludes loopback-bound listeners, matching the port inventory. Any
        headline figure must be drawn from here rather than from ``services``,
        or the report states one number and then lists a different one — an
        authenticated audit of a host running three host-only daemons reported
        "open ports inventoried: 4" above an inventory containing one.
        """
        return [svc for svc in self.services if svc.is_reachable]

    def severity_counts(self) -> Dict[str, int]:
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0,
            "Unscored": 0,
        }
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def vulnerability_findings(self) -> List[StandardizedFinding]:
        """Findings that represent actual vulnerabilities, excluding port inventory."""
        return [
            f
            for f in self.findings
            if f.detection_method != DetectionMethod.PORT_OBSERVATION
        ]

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "None"
        return max(self.findings, key=lambda f: f.severity_rank).severity


@dataclass
class ExcludedFinding:
    """A candidate suppressed before reaching the report, retained for audit."""

    identifier: str
    host: str
    reason: str


@dataclass
class ScanFindings:
    """Complete normalized result set for one scan."""

    hosts: List[HostReport] = field(default_factory=list)
    mitigated: List[StandardizedFinding] = field(default_factory=list)
    excluded: List[ExcludedFinding] = field(default_factory=list)
    integrity_warnings: List[str] = field(default_factory=list)

    @property
    def active(self) -> List[StandardizedFinding]:
        out: List[StandardizedFinding] = []
        for host in self.hosts:
            out.extend(host.findings)
        out.sort(key=lambda f: f.sort_key(), reverse=True)
        return out

    @property
    def reachable_hosts(self) -> List[HostReport]:
        """
        Hosts that actually answered.

        Reports must count these, not ``hosts``: a target that never responded
        is still carried in the result set so the scan can say it was probed,
        but presenting it as a reported or assessed host tells the reader a
        machine was discovered where none exists.
        """
        return [h for h in self.hosts if h.is_active]

    @property
    def unreachable_hosts(self) -> List[HostReport]:
        """Targets that were probed and did not respond."""
        return [h for h in self.hosts if not h.is_active]

    @property
    def vulnerabilities(self) -> List[StandardizedFinding]:
        return [
            f
            for f in self.active
            if f.detection_method != DetectionMethod.PORT_OBSERVATION
        ]

    def severity_counts(self) -> Dict[str, int]:
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0,
            "Unscored": 0,
        }
        for f in self.active:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def confirmed_count(self) -> int:
        return sum(
            1 for f in self.vulnerabilities if f.confidence == Confidence.CONFIRMED
        )

    @property
    def potential_count(self) -> int:
        return sum(
            1 for f in self.vulnerabilities if f.confidence == Confidence.POTENTIAL
        )

    @property
    def kev_findings(self) -> List[StandardizedFinding]:
        return [f for f in self.vulnerabilities if f.in_kev]


# ─────────────────────────────────────────────────────────────────────────────
# Field coercion helpers
# ─────────────────────────────────────────────────────────────────────────────


def _as_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


#: Values the scanners emit to mean "nothing was established". Printed verbatim
#: in a report they read as observations — a host page headed
#: "Host: Unknown (10.180.6.45)" states a name that was never resolved.
_PLACEHOLDER_VALUES = frozenset(
    {
        "unknown",
        "n/a",
        "na",
        "none",
        "null",
        "not determined",
        "not available",
        "-",
        "--",
        "",
    }
)


def _as_observed(value: Any) -> str:
    """Return the value as text, or "" when it is a scanner placeholder."""
    text = _as_str(value)
    return "" if text.lower() in _PLACEHOLDER_VALUES else text


def _as_bool_or_none(value: Any) -> Optional[bool]:
    """
    A tri-state boolean: the recorded answer, or ``None`` for "not recorded".

    ``bool(value)`` cannot express this. It maps a missing key, an explicit
    ``False`` and an empty string onto the same answer, and for exploit
    availability those are two different statements — "the feeds say there is
    no public exploit" and "nothing consulted the feeds".
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "t", "y"):
        return True
    if text in ("false", "no", "0", "f", "n"):
        return False
    # Anything else was never a boolean. Reading it either way would invent an
    # answer out of a value nobody meant as one.
    return None


def _first(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def extract_cve_list(raw_cve: Any) -> List[str]:
    """Extract well-formed CVE identifiers from strings, lists, or dicts."""
    if not raw_cve:
        return []
    if isinstance(raw_cve, list):
        items: List[str] = []
        for entry in raw_cve:
            items.extend(extract_cve_list(entry))
        return list(dict.fromkeys(items))
    if isinstance(raw_cve, dict):
        return extract_cve_list(_first(raw_cve, "cve_id", "cve", "id"))
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", str(raw_cve), re.IGNORECASE)
    return list(dict.fromkeys(m.upper() for m in matches))


def normalize_severity(severity_input: Any, cvss_score: Optional[float] = None) -> str:
    """
    Normalize a severity label.

    A published CVSS score always wins. A textual rating is honoured only when
    no score exists. Absent both, the result is "Unscored" — never a guess.
    """
    if cvss_score is not None:
        return severity_from_score(cvss_score)

    text = _as_str(severity_input).upper()
    mapping = {
        "CRITICAL": "Critical",
        "CRIT": "Critical",
        "4": "Critical",
        "HIGH": "High",
        "3": "High",
        "MEDIUM": "Medium",
        "MED": "Medium",
        "MODERATE": "Medium",
        "2": "Medium",
        "LOW": "Low",
        "1": "Low",
        "NONE": "None",
        "INFO": "None",
        "INFORMATIONAL": "None",
        "0": "None",
    }
    return mapping.get(text, "Unscored")


# ─────────────────────────────────────────────────────────────────────────────
# CPE version-range handling (the false-positive control)
# ─────────────────────────────────────────────────────────────────────────────

_VERSION_TOKEN = re.compile(r"(\d+(?:\.\d+)*)")


#: Words that appear in nmap service banners around the real version string.
#: A banner such as "VMware Authentication Daemon 1.10 Uses VNC, SOAP" contains
#: several numbers; picking the wrong one silently produces a bogus comparison.
_BANNER_NOISE = re.compile(
    r"\b(protocol|uses|or later|or higher|unauthorized|ssdp|upnp|soap|vnc)\b",
    re.IGNORECASE,
)


#: Qualifiers that make a fingerprinted version a *bound* rather than a value.
#: nmap emits these when a probe can only establish a floor or a ceiling — e.g.
#: "PostgreSQL DB 9.6.0 or later", where the host may actually be running 17.x.
#: Treating such a string as an exact version is the single largest source of
#: false positives in an unauthenticated scan, because every CVE whose range
#: happens to contain the floor gets reported as Confirmed.
_OPEN_ENDED_UP = re.compile(r"\b(or\s+(later|higher|newer|above))\b", re.IGNORECASE)
_OPEN_ENDED_DOWN = re.compile(r"\b(or\s+(earlier|older|below))\b", re.IGNORECASE)


#: Reverse-DNS zones. A name ending in one of these is the *question* asked
#: during a PTR lookup ("14.6.180.10.in-addr.arpa"), not the answer. Some
#: scanners echo the query back when the lookup returns nothing, and printing
#: it as the host's name makes a report look like it resolved a name it did not.
_PTR_ZONES = (".in-addr.arpa", ".ip6.arpa")


def clean_hostname(hostname: str, ip: str = "") -> str:
    """
    Return a hostname fit to print, or "" when the scanner gave us none.

    Rejects reverse-DNS query strings and names that merely restate the IP, so
    ``display_name`` falls back to the address instead of showing a synthetic
    name that no operator would recognise.
    """
    name = _as_str(hostname).strip().rstrip(".")
    if not name:
        return ""
    lowered = name.lower()
    # "Unknown" is the scanner saying it found no name. Treated as a hostname it
    # produced host pages headed "Host: Unknown (10.180.6.45)".
    if lowered in _PLACEHOLDER_VALUES:
        return ""
    if any(lowered.endswith(zone) for zone in _PTR_ZONES):
        return ""
    if ip and lowered == _as_str(ip).strip().lower():
        return ""
    return name


@dataclass(frozen=True)
class VendorBuild:
    """
    A vendor's own build of a product, serviced with backported fixes.

    Such a build keeps reporting the upstream release it was cut from, so its
    version is a *floor* on its patch level rather than the patch level — the
    same thing nmap's "9.6.0 or later" says, and judged the same way: a CVE
    fixed before the floor is ruled out, one fixed after it cannot be confirmed
    from the version and is reported as Potential. Measured on 10.180.6.30
    (12 Oct 2026): the banner said "OpenSSH_for_Windows_9.5" while the host
    read its sshd.exe as 9.5.6.3, and twenty upstream OpenSSH CVEs were
    reported as Confirmed against it.
    """

    #: Any one matching a version, product or banner string identifies the build.
    patterns: Tuple["re.Pattern[str]", ...]
    #: The product as the remediation names it; None keeps the CPE's name.
    label: Optional[str]
    #: Where the fix for this build comes from, appended to the remediation.
    guidance: str
    #: CVEs the build's own vendor has published as not affecting it, each with
    #: the statement and where it was published. Only a vendor statement about
    #: this build belongs here — never an inference about the code.
    not_affected: Dict[str, str] = field(default_factory=dict)

    def matches(self, text: str) -> bool:
        return any(pattern.search(text) for pattern in self.patterns)


VENDOR_BUILDS: Tuple[VendorBuild, ...] = (
    VendorBuild(
        patterns=(
            # nmap's version field for this service: "for_Windows_9.5".
            re.compile(r"^for[_ ]windows[_ ]\d", re.IGNORECASE),
            # The banner ("SSH-2.0-OpenSSH_for_Windows_9.5") and the product the
            # authenticated listener reports ("OpenSSH for Windows").
            re.compile(r"openssh[_ ]for[_ ]windows", re.IGNORECASE),
        ),
        label="OpenSSH for Windows",
        guidance=(
            "This is Microsoft's build of OpenSSH, which Microsoft services "
            "through Windows updates and its Win32-OpenSSH releases; a serviced "
            "build can carry this fix without reporting a later version. Apply "
            "the latest Windows cumulative update, or the current Win32-OpenSSH "
            "release for a standalone install, and confirm against Microsoft's "
            "guidance for this CVE."
        ),
        not_affected={
            # regreSSHion. MSRC's Security Update Guide entry, read 12 Oct 2026.
            "CVE-2024-6387": (
                "Microsoft states its OpenSSH for Windows build is not affected: "
                '"Although Windows contains an OpenSSH component, the vulnerable '
                'code cannot be exploited or controlled by an adversary", because '
                "win32-openssh handles the login grace timeout differently "
                "(https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6387)"
            ),
        },
    ),
    VendorBuild(
        # A distribution names itself in the service string nmap reports —
        # "8.9p1 Ubuntu 3ubuntu0.10", "9.2p1 Debian 2+deb12u3", Apache's
        # "(Rocky Linux)" — and patches the package with backported fixes while
        # it keeps reporting the upstream release. Matched as whole words only:
        # a package manager's own version ("1:9.6p1-3ubuntu13.5",
        # "2+deb12u3") never reaches this test as a service string, and the
        # credentialed path judges those against the distribution's advisories.
        # RHEL's OpenSSH banner names no distribution, so it is not covered.
        patterns=(
            re.compile(
                r"\b(?:ubuntu|debian|raspbian|red hat|rhel|centos|rocky linux|"
                r"almalinux|fedora|suse|opensuse|freebsd)\b",
                re.IGNORECASE,
            ),
        ),
        label=None,
        guidance=(
            "The service reports a distribution's build of the product, which the "
            "distribution patches with backported fixes without changing the "
            "upstream version it reports. Update the package through the "
            "system's package manager and check the distribution's security "
            "tracker for this CVE; a credentialed scan reads the package version "
            "and settles it."
        ),
    ),
)


def vendor_build_for(*texts: Any) -> Optional[VendorBuild]:
    """The vendor build any of these version/product/banner strings names."""
    for build in VENDOR_BUILDS:
        if any(build.matches(_as_str(text)) for text in texts if text):
            return build
    return None


@dataclass(frozen=True)
class ObservedCountermeasure:
    """
    A countermeasure a network probe sees on the wire, disproving one CVE.

    A version string cannot show a backported fix; an advertised countermeasure
    is the fix itself, observed on the service that carries it. So this is a
    disproof, not a downgrade, and the candidate is withheld with the reason.
    """

    #: The key in a port's observations (``host_observations``).
    observation: str
    #: The value whose presence is the countermeasure.
    marker: str
    #: Completes "Ruled out: …" in the suppressed-candidates appendix.
    reason: str


OBSERVED_COUNTERMEASURES: Dict[str, ObservedCountermeasure] = {
    # Terrapin. OpenSSH 9.6 closed the prefix-truncation attack with "strict
    # KEX", which a server signals by advertising this pseudo-algorithm in its
    # KEXINIT. On 10.180.6.30 the server advertised it while its banner still
    # read 9.5, and CVE-2023-48795 was reported as Confirmed.
    "CVE-2023-48795": ObservedCountermeasure(
        observation="ssh_kex",
        marker="kex-strict-s-v00@openssh.com",
        reason=(
            "the SSH server advertises strict key exchange "
            "(kex-strict-s-v00@openssh.com), the fix for this prefix-truncation "
            "attack, so it implements the countermeasure whatever version its "
            "banner reports"
        ),
    ),
}


def host_observations(
    host_dict: Dict[str, Any]
) -> Dict[int, Dict[str, Tuple[str, ...]]]:
    """What the network probes observed on each port of a host record."""
    observed: Dict[int, Dict[str, Tuple[str, ...]]] = {}
    ssh = host_dict.get("ssh_info") if isinstance(host_dict, dict) else None
    if isinstance(ssh, dict):
        kex = ssh.get("kex_algos")
        if isinstance(kex, list) and kex:
            # ssh_probe handshakes 22/tcp, and records no port of its own.
            port = _as_int(ssh.get("port")) or 22
            observed.setdefault(port, {})["ssh_kex"] = tuple(str(k) for k in kex)
    return observed


def observed_countermeasure(
    finding_dict: Dict[str, Any],
    service: Optional["ServiceRecord"],
    observations: Optional[Dict[int, Dict[str, Tuple[str, ...]]]],
) -> Optional[ObservedCountermeasure]:
    """The countermeasure observed on this finding's port, if one disproves it."""
    if not observations:
        return None
    cves = extract_cve_list(
        _first(finding_dict, "cves", "cve", "cve_list", "cve_id") or ""
    )
    countermeasure = OBSERVED_COUNTERMEASURES.get(cves[0]) if cves else None
    if countermeasure is None:
        return None
    port = service.port if service else _as_int(finding_dict.get("port"))
    seen = (observations.get(port) or {}).get(countermeasure.observation) or ()
    return countermeasure if countermeasure.marker in seen else None


def vendor_not_affected(
    finding_dict: Dict[str, Any], service: Optional["ServiceRecord"]
) -> str:
    """The vendor's statement that its build is not affected by this CVE, or ""."""
    vendor = vendor_build_for(
        *(
            (service.product, service.version, service.banner, service.extra)
            if service
            else ()
        ),
        _first(finding_dict, "detected_version", "installed_version"),
    )
    if vendor is None:
        return ""
    cves = extract_cve_list(
        _first(finding_dict, "cves", "cve", "cve_list", "cve_id") or ""
    )
    return vendor.not_affected.get(cves[0], "") if cves else ""


def version_precision(value: str) -> str:
    """
    Classify how precisely a detected version string pins the real version.

    Returns "exact", "floor" (true version is >= the stated one) or "ceiling"
    (true version is <= the stated one).
    """
    if not value:
        return "exact"
    text = str(value)
    if _OPEN_ENDED_UP.search(text) or vendor_build_for(text):
        return "floor"
    if _OPEN_ENDED_DOWN.search(text):
        return "ceiling"
    return "exact"


def _comparable_version(value: str) -> Optional[Tuple[int, ...]]:
    """
    Reduce a version string to a comparable numeric tuple.

    Returns ``None`` when no numeric component exists, which forces the caller
    to treat the comparison as indeterminate rather than assume a match.
    """
    if not value:
        return None
    text = str(value)
    # Trim trailing banner commentary so the version is taken from the product
    # string rather than from whatever number happens to appear first.
    noise = _BANNER_NOISE.search(text)
    if noise:
        text = text[: noise.start()]
    match = _VERSION_TOKEN.search(text)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _version_compare(left: str, right: str) -> Optional[int]:
    """Return -1/0/1, or None when either side is not numerically comparable."""
    a, b = _comparable_version(left), _comparable_version(right)
    if a is None or b is None:
        return None
    length = max(len(a), len(b))
    a_padded = a + (0,) * (length - len(a))
    b_padded = b + (0,) * (length - len(b))
    if a_padded < b_padded:
        return -1
    if a_padded > b_padded:
        return 1
    return 0


def effective_precision(version: str, recorded: str = "") -> str:
    """
    What a version string actually pins down.

    Prefers the precision recorded by the stage that measured the version;
    falls back to re-deriving it from the string. Recording it at measurement
    is the reliable path — by the time a version reaches here it may have been
    copied between fields, and "9.6.0 or later" only reads as a lower bound
    while the words are still attached to it.
    """
    # A vendor build is a floor whatever the measuring stage recorded: nmap
    # records "for_Windows_9.5" as exact, because as a string it is.
    if vendor_build_for(version):
        return "floor"
    if recorded in ("exact", "floor", "ceiling"):
        return recorded
    return version_precision(version)


def _publishes_version(cpe: Dict[str, Any]) -> bool:
    """Whether a CPE entry states any version: a bound, or a pinned release."""
    if any(
        cpe.get(camel) or cpe.get(snake)
        for camel, snake in (
            ("versionStartIncluding", "version_start_including"),
            ("versionStartExcluding", "version_start_excluding"),
            ("versionEndIncluding", "version_end_including"),
            ("versionEndExcluding", "version_end_excluding"),
        )
    ):
        return True
    uri = _as_str(
        cpe.get("cpe23Uri")
        or cpe.get("cpe23_uri")
        or cpe.get("cpe_uri")
        or cpe.get("criteria")
    )
    parts = uri.split(":")
    return len(parts) > 5 and parts[5] not in ("*", "-", "")


def version_in_cpe_range(
    detected: str, cpe: Dict[str, Any], recorded_precision: str = ""
) -> Optional[bool]:
    """
    Test a detected version against a CPE 2.3 version range.

    Returns True/False when a determination is possible, or ``None`` when the
    range or the detected version cannot be compared — the caller must then
    downgrade confidence rather than assume vulnerability.
    """
    if not detected:
        return None

    precision = effective_precision(detected, recorded_precision)

    bounds = [
        ("versionStartIncluding", "version_start_including", lambda c: c >= 0, "lower"),
        ("versionStartExcluding", "version_start_excluding", lambda c: c > 0, "lower"),
        ("versionEndIncluding", "version_end_including", lambda c: c <= 0, "upper"),
        ("versionEndExcluding", "version_end_excluding", lambda c: c < 0, "upper"),
    ]

    saw_bound = False
    indeterminate = False
    for camel, snake, predicate, side in bounds:
        boundary = cpe.get(camel) or cpe.get(snake)
        if not boundary:
            continue
        saw_bound = True
        comparison = _version_compare(detected, str(boundary))
        if comparison is None:
            return None
        if not predicate(comparison):
            # Disproved even at the stated bound. For an open-ended fingerprint
            # this still holds: a floor of 9.6.0 that already exceeds a "< 9.0"
            # ceiling rules the host out no matter how much higher it really is.
            return False
        # The bound passed — but for an open-ended fingerprint, passing on the
        # *open* side proves nothing, because the true version may lie beyond
        # it. "9.6.0 or later" clears a "<= 11.2" ceiling only if the host is
        # not actually running 17.x, which the scan cannot tell us.
        if (precision == "floor" and side == "upper") or (
            precision == "ceiling" and side == "lower"
        ):
            indeterminate = True

    if indeterminate:
        return None

    if saw_bound:
        return True

    # No range published. Fall back to an exact version pinned in the CPE URI.
    uri = _as_str(
        cpe.get("cpe23Uri")
        or cpe.get("cpe23_uri")
        or cpe.get("cpe_uri")
        or cpe.get("criteria")
    )
    if uri:
        parts = uri.split(":")
        if len(parts) > 5:
            pinned = parts[5]
            if pinned not in ("*", "-", ""):
                comparison = _version_compare(detected, pinned)
                if comparison is None:
                    return None
                if precision == "exact":
                    return comparison == 0
                # An open-ended fingerprint cannot establish *equality*: a CVE
                # that publishes one pinned CPE per released version carries
                # dozens of them, and "9.6.0 or later" matched the entry pinned
                # to exactly 9.6.0 — reporting eight PostgreSQL CVEs as
                # Confirmed against a server actually running 18.3.
                #
                # It can still disprove one, in the direction the bound is
                # closed. A host that is at least 9.6.0 is definitively not
                # running the pinned 8.4.1, and saying so keeps those candidates
                # suppressed instead of promoting them to "potential".
                if precision == "floor":
                    return False if comparison > 0 else None
                if precision == "ceiling":
                    return False if comparison < 0 else None
                return None

    return None


def _cpe_from_uri(uri: str) -> Dict[str, str]:
    """
    Split a CPE 2.3 URI into its vendor, product, and pinned version.

    Format: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:...
    """
    parts = str(uri).split(":")
    return {
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4] if len(parts) > 4 else "",
        "pinned_version": parts[5] if len(parts) > 5 else "",
    }


def _cpe_products(affected_software: Any) -> List[Dict[str, Any]]:
    """
    Flatten a stored affected_software blob into a list of flat CPE dicts.

    Three shapes occur in practice and all must be handled, otherwise version
    matching silently does nothing and every finding degrades to unverified:

      1. Raw NVD ``configurations`` — a list of ``{"nodes": [{"cpeMatch": [...]}]}``
         with arbitrarily nested ``children``. This is what the CVE database
         stores for the overwhelming majority of records.
      2. Already-flat dicts with vendor/product and version-bound keys, as
         emitted by the structured CVE detail query.
      3. Bare CPE URI strings.

    Only entries marked ``vulnerable`` are returned; NVD uses non-vulnerable
    entries to express platform context ("running on OS X"), and treating those
    as affected would manufacture false positives.
    """
    if not affected_software:
        return []
    if isinstance(affected_software, dict):
        affected_software = [affected_software]
    if not isinstance(affected_software, list):
        return []

    out: List[Dict[str, Any]] = []

    def add_match(match: Dict[str, Any]) -> None:
        if not isinstance(match, dict):
            return
        if match.get("vulnerable") is False:
            return
        uri = _as_str(
            match.get("criteria")
            or match.get("cpe23Uri")
            or match.get("cpe23_uri")
            or match.get("cpe_uri")
        )
        parsed = (
            _cpe_from_uri(uri)
            if uri
            else {"vendor": "", "product": "", "pinned_version": ""}
        )
        vendor = _as_str(match.get("vendor")) or parsed["vendor"]
        product = _as_str(match.get("product")) or parsed["product"]

        # A record is usable if it names a product, whether that arrived as a
        # CPE URI or as separate vendor/product columns.
        if not product and not uri:
            return

        out.append(
            {
                "cpe23Uri": uri,
                "vendor": vendor,
                "product": product,
                "versionStartIncluding": match.get("versionStartIncluding")
                or match.get("version_start_including"),
                "versionStartExcluding": match.get("versionStartExcluding")
                or match.get("version_start_excluding"),
                "versionEndIncluding": match.get("versionEndIncluding")
                or match.get("version_end_including"),
                "versionEndExcluding": match.get("versionEndExcluding")
                or match.get("version_end_excluding"),
            }
        )

    def visit_node(node: Any, depth: int = 0) -> None:
        if depth > 8 or not isinstance(node, dict):
            return
        for match in node.get("cpeMatch") or node.get("cpe_match") or []:
            add_match(match)
        for child in node.get("children") or []:
            visit_node(child, depth + 1)

    for entry in affected_software:
        if isinstance(entry, str):
            if entry.startswith("cpe:"):
                add_match({"criteria": entry})
            continue
        if not isinstance(entry, dict):
            continue

        nodes = entry.get("nodes")
        if nodes:
            for node in nodes:
                visit_node(node)
            continue

        if entry.get("cpeMatch") or entry.get("cpe_match") or entry.get("children"):
            visit_node(entry)
            continue

        # Already-flat record from the structured detail query.
        if (
            entry.get("product")
            or entry.get("vendor")
            or entry.get("criteria")
            or entry.get("cpe_uri")
        ):
            add_match(entry)

    return out


#: Tokens that denote an edition or packaging of the same product rather than a
#: different product. "nginx_open_source" is nginx; "nginx_ui" is a separate
#: application that merely manages nginx and must not inherit nginx's CVEs.
_EDITION_TOKENS = frozenset(
    {
        "open",
        "source",
        "oss",
        "plus",
        "server",
        "daemon",
        "community",
        "enterprise",
        "standard",
        "edition",
        "core",
        "project",
        "software",
    }
)


def _name_tokens(value: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", str(value).lower()) if t]


#: Platform families and the tokens that identify them in an OS fingerprint or
#: a product banner. Used to test a CPE's target_sw field against the host.
_PLATFORM_TOKENS: Dict[str, Tuple[str, ...]] = {
    "windows": ("windows", "win32", "win64", "microsoft"),
    "linux": ("linux", "ubuntu", "debian", "red hat", "redhat", "centos", "suse"),
    "macos": ("mac os", "macos", "os x", "darwin"),
    "freebsd": ("freebsd",),
    "solaris": ("solaris", "sunos"),
    "android": ("android",),
}


def cpe_platform_conflicts(cpe: Dict[str, Any], host_os: str, product: str) -> bool:
    """
    True when a CPE is scoped to a platform the host demonstrably is not.

    CPE 2.3 field 10 (``target_sw``) pins the software environment a vulnerable
    configuration applies to. When NVD sets it and the host's OS fingerprint
    names a different family, the record does not apply here — that is a
    disproof, not an uncertainty, so the caller may suppress on it.

    Returns False whenever target_sw is unset, unrecognised, or the host OS is
    unknown, because absence of evidence must not become evidence of absence.
    """
    uri = _as_str(
        cpe.get("cpe23Uri")
        or cpe.get("cpe23_uri")
        or cpe.get("cpe_uri")
        or cpe.get("criteria")
    )
    parts = uri.split(":")
    if len(parts) <= 10:
        return False
    target_sw = parts[10].strip().lower()
    if target_sw in ("*", "-", ""):
        return False

    family = next(
        (name for name in _PLATFORM_TOKENS if name in target_sw or target_sw in name),
        "",
    )
    if not family:
        return False

    haystack = f"{host_os} {product}".lower()
    if not haystack.strip():
        return False

    # The host matches the CPE's platform — no conflict.
    if any(token in haystack for token in _PLATFORM_TOKENS[family]):
        return False

    # Only call it a conflict when the host positively identifies as some
    # *other* known family. An unrecognised OS string proves nothing.
    return any(
        any(token in haystack for token in tokens)
        for name, tokens in _PLATFORM_TOKENS.items()
        if name != family
    )


def _cpe_identities_from(value: Any) -> List[Tuple[str, str]]:
    """Parse ``(vendor, product)`` pairs out of scanner-assigned CPE strings."""
    identities: List[Tuple[str, str]] = []
    raw_values = value if isinstance(value, (list, tuple)) else [value]
    for raw in raw_values:
        text = _as_str(raw).lower()
        if not text.startswith("cpe:"):
            continue
        parts = text.split(":")
        if len(parts) > 2 and parts[1] == "2.3":
            pair = (parts[3], parts[4]) if len(parts) > 4 else ("", "")
        else:
            pair = (parts[2], parts[3]) if len(parts) > 3 else ("", "")
        vendor, product = pair[0].strip(), pair[1].strip()
        if vendor and product and product not in ("*", "-"):
            if (vendor, product) not in identities:
                identities.append((vendor, product))
    return identities


def cpe_part(cpe: Dict[str, Any]) -> str:
    """
    The CPE 2.3 part indicator: "a" application, "o" operating system, "h" hardware.

    ``cpe:2.3:o:canonical:ubuntu_linux:*`` describes the platform the host runs,
    not something listening on a port. The distinction is load-bearing — see
    ``_cpe_matches_product``.
    """
    uri = _as_str(
        cpe.get("cpe23Uri")
        or cpe.get("cpe23_uri")
        or cpe.get("cpe_uri")
        or cpe.get("criteria")
    )
    if uri:
        parts = uri.split(":")
        if len(parts) > 2 and parts[2] in ("a", "o", "h"):
            return parts[2]
    return _as_str(cpe.get("part")).lower() or ""


def is_platform_cpe(cpe: Dict[str, Any]) -> bool:
    """True when a CPE names an operating system or hardware, not an application."""
    return cpe_part(cpe) in ("o", "h")


def _cpe_matches_product(cpe: Dict[str, Any], service: ServiceRecord) -> bool:
    """
    Check whether a CPE entry refers to the product observed on this port.

    When the scan recorded CPEs for the service, identity is decided by
    comparing them — the scanner already established what this is, so there is
    nothing to interpret. Token matching below is the fallback for services the
    scanner could not identify that precisely.

    Matching is token-based rather than substring-based, because both
    directions of a substring test are wrong in practice:

      * ``"nginx_open_source" in "nginx 1.26.3"`` is False, yet that CPE *is*
        nginx - a plain containment test loses real findings.
      * ``"nginx" in "nginx_ui"`` is True, yet Nginx UI is a different
        application - the reverse test manufactures false positives.

    So the CPE's leading token must appear in the observed product string, and
    every remaining token must either also appear there or be a recognised
    edition qualifier. ``nginx_open_source`` matches nginx; ``nginx_ui``,
    ``nginx_proxy_manager`` and ``spring_framework`` do not.

    The service *name* (``http``, ``ssh``) is deliberately excluded from the
    comparison. It is a protocol label, not a product: including it let
    ``apache:http_server`` match every HTTP port on the network.
    """
    # An operating-system or hardware CPE never describes a listening service,
    # so it is not eligible to be matched against one.
    #
    # Without this, ``cpe:2.3:o:canonical:ubuntu_linux`` matched the SSH service
    # on an Ubuntu host — the banner "OpenSSH 9.6p1 Ubuntu 3ubuntu13.18"
    # contains the token "ubuntu" — and the *service's* version was then tested
    # against the *operating system's* published range: 9.6 < 20.10, so
    # CVE-2021-3493 was reported Confirmed at QoD 95 against a host running
    # Ubuntu 24.04, with the remediation "upgrade Ubuntu to 20.10 or later".
    # The same path put a Google Chrome CVE on port 22 via its linux_kernel
    # platform entry. Platform CPEs are evaluated against the host OS instead,
    # in ``_classify_platform_finding``.
    if is_platform_cpe(cpe):
        return False

    uri = _as_str(
        cpe.get("cpe23Uri")
        or cpe.get("cpe23_uri")
        or cpe.get("cpe_uri")
        or cpe.get("criteria")
    )
    product = _as_str(cpe.get("product"))
    vendor = _as_str(cpe.get("vendor"))
    if uri:
        parts = uri.split(":")
        if len(parts) > 4:
            vendor = vendor or parts[3]
            product = product or parts[4]
    if not product:
        return False

    if service.cpe_identities:
        # Decided by identifier where possible: the scanner already established
        # what this service is. Product only — Nmap and NVD disagree on vendor
        # often enough (nginx is igor_sysoev to one and f5 to the other) that
        # requiring both to agree would reject genuine matches.
        if any(product.lower() == known for _v, known in service.cpe_identities):
            return True
        # No identity match is not a disproof: the scanner's CPE list is not
        # exhaustive, and NVD names products more specifically than Nmap does
        # ("nginx_open_source" against "nginx"). Fall through to token
        # matching, so the identity check can only ever add matches.

    product_tokens = _name_tokens(product)
    if not product_tokens:
        return False

    observed = set()
    for observed_field in (service.product, service.extra, service.banner):
        if observed_field:
            observed.update(_name_tokens(observed_field))
    if not observed:
        return False

    if product_tokens[0] not in observed:
        return False

    return all(
        token in observed or token in _EDITION_TOKENS for token in product_tokens[1:]
    )


# ─────────────────────────────────────────────────────────────────────────────
# Attack-surface applicability
# ─────────────────────────────────────────────────────────────────────────────

#: An explicit statement in the CVE text that the flaw is client-side. NVD
#: writes these as parentheticals, and they are the strongest signal available.
_CLIENT_SIDE_PHRASE = re.compile(
    r"(only on the client side|on the client side|client[- ]side only)", re.IGNORECASE
)

#: Client and utility binaries that ship inside a server package. A flaw in one
#: of these is real and still needs the upgrade, but it is not reachable
#: through the listening port the finding is bound to.
_CLIENT_COMPONENTS = frozenset(
    {
        "ssh",
        "scp",
        "sftp",
        "ssh-agent",
        "ssh-add",
        "ssh-keygen",
        "ssh-keyscan",
        "ssh-copy-id",
        "ssh_config",
        "psql",
        "libpq",
        "pg_dump",
        "pg_dumpall",
        "pg_restore",
        "pg_basebackup",
        "pg_rewind",
        "pg_upgrade",
        "pgbench",
        "mysqldump",
        "mysqladmin",
        "curl",
        "wget",
        "git",
    }
)

#: Daemon names. If one of these appears anywhere in the text the flaw touches
#: the server side, which overrides any client component also mentioned.
_SERVER_COMPONENTS = frozenset(
    {
        "sshd",
        "sshd_config",
        "httpd",
        "nginx",
        "postmaster",
        "mysqld",
        "postgres",
        "named",
        "smbd",
        "vsftpd",
        "dovecot",
        "postfix",
    }
)

#: "<component> in <Product>" or "In <component> in <Product>" — the shape NVD
#: uses to name the affected binary at the start of a description.
_LEADING_COMPONENT = re.compile(
    r"^(?:in\s+)?([a-z][a-z0-9_\-]{1,20})\s+in\s+", re.IGNORECASE
)

_WORD_SPLIT = re.compile(r"[^a-z0-9_\-]+")


def classify_attack_surface(text: str, has_open_port: bool) -> Tuple[str, str]:
    """
    Decide whether a listening service is really the attack path for this CVE.

    Returns ``(surface, note)`` where surface is "remote" or "client".

    A vulnerability report that lists a client-side use-after-free as a Critical
    finding "on 22/tcp" invites the reader to conclude the SSH *server* is
    remotely exploitable, which is not what the CVE says. The package is still
    affected and still needs upgrading, so this never suppresses the finding —
    it relabels the attack path and lets the ordering put genuinely remote
    issues first.

    Defaults to "remote" whenever the text is ambiguous: under-reporting reach
    is the more dangerous error.
    """
    if not text or not has_open_port:
        return "remote", ""

    body = str(text)
    words = {w for w in _WORD_SPLIT.split(body.lower()) if w}

    names_server = bool(words & _SERVER_COMPONENTS)

    explicit = bool(_CLIENT_SIDE_PHRASE.search(body))
    if explicit and not names_server:
        return "client", (
            "The CVE text states this outcome occurs on the client side. The "
            "listening service on this port is not the attack path; the package "
            "still requires the upgrade below."
        )

    leading = _LEADING_COMPONENT.match(body.strip())
    component = leading.group(1).lower() if leading else ""

    if names_server:
        return "remote", ""

    candidate = component if component in _CLIENT_COMPONENTS else ""
    if not candidate:
        overlap = words & _CLIENT_COMPONENTS
        # A bare "ssh"/"git" mention is too weak on its own; require the
        # description to lead with the component, or to name a specific utility.
        strong = {w for w in overlap if len(w) > 3 and w not in ("curl", "wget")}
        candidate = sorted(strong)[0] if strong else ""

    if candidate:
        return "client", (
            f"This flaw is in <b>{candidate}</b>, a client/utility component of "
            f"the affected package, not in the service listening on this port. "
            f"The upgrade below still applies, but the open port is not the "
            f"attack path for this CVE."
        )

    return "remote", ""


#: Version token inside an OS description, e.g. "Ubuntu Linux (kernel 6.8.0-137)"
#: or "Microsoft Windows 10 1607". Used only to test an OS CPE range against the
#: platform the host actually runs.
_OS_VERSION_TOKEN = re.compile(r"(\d+(?:\.\d+){1,3})")


def _os_version_from(host_os: str) -> str:
    """Best-effort version for the host's operating system, or "" if none."""
    match = _OS_VERSION_TOKEN.search(_as_str(host_os))
    return match.group(1) if match else ""


def _classify_platform_finding(
    platform_cpes: List[Dict[str, Any]], host_os: str, fixed_hint: str
) -> Tuple[DetectionMethod, str, str, str]:
    """
    Judge an OS-level CVE against the host's operating system.

    A record published only against operating systems (a kernel flaw, a
    distribution advisory) is genuinely about the host, so it is reported — but
    the version it is tested against must be the OS's, never a service's, and
    the product must be the OS the host is actually running.

    An unauthenticated scan rarely establishes a distribution's release number,
    so most of these end as UNVERIFIED rather than confirmed. That is the honest
    answer: the alternative was CVE-2021-3493 asserted "Confirmed, QoD 95"
    against a host two major releases past the fix.
    """
    os_text = _as_str(host_os)
    if not os_text:
        return DetectionMethod.UNVERIFIED, "", fixed_hint, "os_unknown"

    os_tokens = set(_name_tokens(os_text))
    os_version = _os_version_from(os_text)
    named_this_os = False
    any_in_range = False

    for cpe in platform_cpes:
        product = _as_str(cpe.get("product")) or ""
        if not product:
            uri = _as_str(
                cpe.get("cpe23Uri") or cpe.get("cpe_uri") or cpe.get("criteria")
            )
            parts = uri.split(":")
            product = parts[4] if len(parts) > 4 else ""
        tokens = [t for t in _name_tokens(product) if t not in ("linux",)]
        # "linux_kernel" against a Windows host names a different platform.
        if tokens and not any(t in os_tokens for t in tokens):
            continue
        named_this_os = True

        if os_version and version_in_cpe_range(os_version, cpe) is True:
            any_in_range = True

    if not named_this_os:
        return DetectionMethod.UNVERIFIED, "", fixed_hint, "platform_mismatch"

    if os_version and not any_in_range:
        # Disproof is safe in this direction: a kernel newer than every
        # published range is genuinely not affected.
        return (
            DetectionMethod.UNVERIFIED,
            os_version,
            fixed_hint,
            "version_outside_range",
        )

    # In range — but that is not a confirmation, and must never be reported as
    # one.
    #
    # Distributions backport security fixes without changing the version a
    # banner reports: Ubuntu's "6.8.0-137-generic" carries hundreds of patches
    # that upstream 6.8.0 does not, and the CPE ranges published against
    # linux_kernel describe upstream releases only. Treating the two as the same
    # number reported 480 kernel CVEs as "Confirmed, QoD 95" against this host,
    # every one of them bound to whichever port happened to be open.
    #
    # An unauthenticated scan cannot read a distribution's patch level, so the
    # honest verdict is "this host runs the affected platform and the exposure
    # is unconfirmed". At QoD 30 these sit below the reporting threshold and are
    # recorded as suppressed candidates with that reason — which is where an
    # unauthenticated scanner should leave them. A credentialed scan resolves
    # them properly from the package manager.
    return DetectionMethod.OS_REPORTED, os_version, fixed_hint, ""


def record_platform_scope(
    finding_dict: Dict[str, Any], cpes: Optional[List[Dict[str, Any]]] = None
) -> Tuple[str, ...]:
    """The platforms a candidate's record says it applies to; () for any."""
    if cpes is None:
        cpes = _cpe_products(
            _first(finding_dict, "affected_software", "affected", "cpe_ids", "cpes")
            or []
        )
    configured = finding_dict.get("affected_platforms")
    return declared_platforms(
        _first(finding_dict, "description", "desc", "details", "summary"),
        configured if isinstance(configured, (list, tuple)) else None,
        [c.get("cpe23Uri") for c in cpes],
    )


def classify_detection(
    finding_dict: Dict[str, Any],
    service: Optional[ServiceRecord],
    affected_software: Any,
    host_services: Optional[List[ServiceRecord]] = None,
    host_os: str = "",
    observations: Optional[Dict[int, Dict[str, Tuple[str, ...]]]] = None,
) -> Tuple[DetectionMethod, str, str, str]:
    """
    Decide how a CVE was tied to this host.

    Returns ``(method, detected_version, fixed_version_hint, suppression_basis)``
    where the basis names *why* a suppression happened — the check that made
    the call is the only place that knows, and a reader of the report should
    not be told "the version ruled this out" when the product was never found.

    Returns ``(method, detected_version, fixed_version_hint)``.

    This is the control that separates a defensible finding from a port-open
    guess. The governing rule is: **suppress only on disproof, downgrade on
    unverifiability.**

      * Version inside the published vulnerable range      → Confirmed
      * Version outside that range                         → suppressed
      * CPE pinned to a platform this host is not          → suppressed
      * Affected product absent from a known inventory     → suppressed
      * Version is an open-ended bound, not an exact value → Potential
      * No CPE range published, so nothing can be checked   → Potential
      * No service inventory to check against              → Potential

    Suppressing an unverifiable finding would trade false positives for false
    negatives, which is the worse failure for a security report. Such findings
    are therefore reported and visibly marked as unverified instead.
    """
    explicit = _as_str(
        _first(finding_dict, "detection_method", "evidence_source")
    ).lower()

    # Only methods that carry their own independent evidence may bypass the
    # CPE range check. A scanner asserting "version_match" is a claim, not a
    # verification: honouring it here would let a patched host keep a finding
    # that the published version range disproves.
    AUTHORITATIVE = {
        "config_check": DetectionMethod.CONFIG_CHECK,
        "active_check": DetectionMethod.CONFIG_CHECK,
        "imported": DetectionMethod.IMPORTED,
        "nessus": DetectionMethod.IMPORTED,
    }

    detected_version = _as_str(
        _first(finding_dict, "detected_version", "installed_version", "package_version")
    )
    if not detected_version and service:
        detected_version = service.version

    fixed_hint = _as_str(_first(finding_dict, "fixed_version", "fixed_in"))

    if explicit in AUTHORITATIVE:
        return AUTHORITATIVE[explicit], detected_version, fixed_hint, ""

    cpes = _cpe_products(affected_software)

    # A credentialed package finding carries its own installed version from the
    # host's package manager and does not depend on a network service being
    # fingerprinted, so it may skip the product-match test below.
    #
    # This branch is deliberately narrow. A network scan attaches a *package
    # hint* guessed from a service banner, which is not a package-manager
    # result. Letting that hint enter here bypassed product verification
    # entirely: any CVE whose version range happened to contain a number
    # scraped out of a banner was reported as Confirmed, which is how Spring
    # Framework, Dropbear and Dahua camera CVEs ended up attached to a VMware
    # daemon, OpenSSH and PostgreSQL respectively.
    # Credentialed origin must be asserted by the record, never inferred from
    # the absence of a service inventory. The old fallback — "has a package name
    # and this payload has no services" — treated an ordinary network finding as
    # a package-manager result whenever the host record it travelled in had been
    # stripped of its ports, which is exactly what the stored phase-3 payload is
    # (`to_phase3_dict` drops `open_ports` because phase 2 already reported
    # them). Every such finding came out Confirmed at QoD 97 on the strength of
    # a package name guessed from a banner.
    # The origin is also kept apart from the verdict: the first verification
    # pass writes its verdict back into ``detection_method``, so a finding it
    # judged "version_imprecise" or "package_present" no longer read as
    # credentialed on the second pass and fell into the network path — where a
    # CSAF finding with no CPE range scored QoD 30 and vanished into the
    # appendix (10.180.6.30, scan #11, 12 Oct 2026).
    is_credentialed_package = (
        explicit
        in (
            "credentialed",
            "credentialed_package",
            "package",
        )
        or _as_str(finding_dict.get("finding_origin")) == "credentialed"
    )
    if is_credentialed_package:
        # A package matched by name and version is still not affected when the
        # record is about another platform's build of it. The matcher reads
        # NVD's "running on" nodes into affected_platforms; the description
        # and the CPE's target_sw are read here as well, so payloads stored
        # before the matcher did so are judged the same way.
        if scope_excludes_host(record_platform_scope(finding_dict, cpes), host_os):
            return (
                DetectionMethod.UNVERIFIED,
                detected_version,
                fixed_hint,
                "platform_mismatch",
            )
        if not detected_version:
            # The package is installed but the audit did not capture a version,
            # so vulnerability cannot be asserted — only that the package which
            # would be affected is present.
            return DetectionMethod.PACKAGE_PRESENT, "", fixed_hint, ""

        # The matcher found the version in range only by reading a release line
        # ("V19") as its first update; whether the installed update is below the
        # fix is unknown. It said so rather than confirming.
        if _as_str(finding_dict.get("installed_version_precision")) == "coarse":
            return (
                DetectionMethod.VERSION_IMPRECISE,
                detected_version,
                fixed_hint
                or next(
                    (
                        _as_str(
                            c.get("versionEndExcluding")
                            or c.get("version_end_excluding")
                        )
                        for c in cpes
                        if c.get("versionEndExcluding")
                        or c.get("version_end_excluding")
                    ),
                    "",
                ),
                "",
            )

        disproved = False
        for cpe in cpes:
            verdict = version_in_cpe_range(detected_version, cpe)
            if verdict is True:
                return (
                    DetectionMethod.CREDENTIALED_PACKAGE,
                    detected_version,
                    fixed_hint
                    or _as_str(
                        cpe.get("versionEndExcluding")
                        or cpe.get("version_end_excluding")
                    ),
                    "",
                )
            if verdict is False:
                # As in the network path below: a single non-matching entry does
                # not disprove a record whose affected list holds one entry per
                # released version, so the whole list is evaluated first.
                disproved = True
        if disproved:
            return (
                DetectionMethod.UNVERIFIED,
                detected_version,
                fixed_hint,
                "version_outside_range",
            )
        return (
            DetectionMethod.CREDENTIALED_PACKAGE,
            detected_version,
            fixed_hint,
            "",
        )

    # A countermeasure seen on the wire outranks any version comparison, and so
    # does the build's own vendor saying the build is not affected.
    if observed_countermeasure(finding_dict, service, observations):
        return (
            DetectionMethod.UNVERIFIED,
            detected_version,
            fixed_hint,
            "countermeasure_observed",
        )
    if vendor_not_affected(finding_dict, service):
        return (
            DetectionMethod.UNVERIFIED,
            detected_version,
            fixed_hint,
            "vendor_not_affected",
        )

    # Without CPE data nothing can be verified either way. The engine still
    # asserted this finding against the host, so it is reported rather than
    # dropped — visibly flagged as unverified.
    if not cpes:
        return DetectionMethod.ENGINE_REPORTED, detected_version, fixed_hint, ""

    inventory = (
        host_services if host_services is not None else ([service] if service else [])
    )

    # Check the bound service first, then the rest of the host's inventory, so
    # a finding still confirms when the port binding was not recorded.
    candidates: List[ServiceRecord] = []
    if service is not None:
        candidates.append(service)
    candidates.extend(s for s in inventory if s is not service)

    product_matched = False
    imprecise_version = ""
    imprecise_hint = ""
    disproved_version = ""
    platform_conflict = False
    for cpe in cpes:
        for candidate in candidates:
            if not _cpe_matches_product(cpe, candidate):
                continue
            # The CPE names the right product but pins it to a platform this
            # host is not running, so this configuration does not apply here.
            if cpe_platform_conflicts(
                cpe, host_os, candidate.product or candidate.banner
            ):
                platform_conflict = True
                continue
            product_matched = True
            version = detected_version or candidate.version
            # Precision recorded by the stage that measured this version, when
            # the version is the one that stage measured.
            precision = effective_precision(
                version,
                candidate.version_precision if version == candidate.version else "",
            )
            # The service may name the vendor build where the version does not,
            # e.g. once an authenticated reading has replaced "for_Windows_9.5"
            # with the file version 9.5.6.3 — which is no more an upstream
            # release than the banner was.
            if vendor_build_for(candidate.product, candidate.banner, candidate.extra):
                precision = "floor"
            verdict = version_in_cpe_range(version, cpe, precision)
            if (
                verdict is None
                and version
                and precision != "exact"
                and _publishes_version(cpe)
            ):
                # The fingerprint is a bound, not a value: it lands inside the
                # published range but cannot rule out a fixed release beyond
                # the open end. Remember it in case no CPE gives a firm answer.
                #
                # Only where the record publishes a version. One that names the
                # product and nothing else ("openssh:*", "openssh:-") is not
                # undecided by an imprecise version — no version could decide
                # it — and stays a product-present candidate, as it is for an
                # exact one. Without this, seven unversioned OpenSSH records
                # (a 2008 Red Hat package trojan among them) went from withheld
                # to reported as soon as OpenSSH for Windows read as a floor
                # (10.180.6.30, scan #12).
                imprecise_version = version
                imprecise_hint = imprecise_hint or _as_str(
                    cpe.get("versionEndExcluding") or cpe.get("version_end_excluding")
                )
                continue
            if verdict is True:
                method = (
                    DetectionMethod.BANNER_MATCH
                    if candidate.banner and not candidate.product
                    else DetectionMethod.VERSION_MATCH
                )
                return (
                    method,
                    version,
                    fixed_hint
                    or _as_str(
                        cpe.get("versionEndExcluding")
                        or cpe.get("version_end_excluding")
                    ),
                    "",
                )
            if verdict is False:
                # This configuration does not cover the detected version. Note
                # it, but keep going: one CVE routinely carries many affected
                # entries for the same product — Oracle publishes one pinned
                # version per release, and F5 publishes one range per supported
                # nginx branch. Concluding "disproved" from the first
                # non-matching entry threw away every finding whose matching
                # entry happened to be listed later, and the feed does not
                # guarantee any order.
                disproved_version = disproved_version or version
                continue

    if imprecise_version:
        return (
            DetectionMethod.VERSION_IMPRECISE,
            imprecise_version,
            fixed_hint or imprecise_hint,
            "",
        )

    if disproved_version:
        # Every affected entry naming this product excluded the detected
        # version, so the record really is disproved for this host.
        return (
            DetectionMethod.UNVERIFIED,
            disproved_version,
            fixed_hint,
            "version_outside_range",
        )

    if product_matched:
        return DetectionMethod.SERVICE_PRODUCT, detected_version, fixed_hint, ""

    # No application CPE matched a service. If the record is published purely
    # against operating systems, it is a host-level finding and is judged
    # against the host's own OS version rather than discarded — a real kernel
    # or distribution vulnerability must still be reported, just not attributed
    # to whichever port happened to be open.
    platform_cpes = [c for c in cpes if is_platform_cpe(c)]
    if platform_cpes and len(platform_cpes) == len(cpes):
        return _classify_platform_finding(platform_cpes, host_os, fixed_hint)

    if platform_conflict:
        # Every CPE that named this product was scoped to a different platform.
        return (
            DetectionMethod.UNVERIFIED,
            detected_version,
            fixed_hint,
            "platform_mismatch",
        )

    if inventory:
        # The host's services were enumerated and none of them is the affected
        # product, so the finding is disproved by absence.
        return (
            DetectionMethod.UNVERIFIED,
            detected_version,
            fixed_hint,
            "product_absent",
        )

    # Nothing was enumerated on this host, so applicability cannot be tested.
    return DetectionMethod.ENGINE_REPORTED, detected_version, fixed_hint, ""


# ─────────────────────────────────────────────────────────────────────────────
# Remediation resolution
# ─────────────────────────────────────────────────────────────────────────────

_PATCH_HOST_HINTS = (
    "security",
    "advisory",
    "advisories",
    "patch",
    "bulletin",
    "errata",
    "download",
    "support",
    "release",
    "update",
)


def resolve_remediation(
    finding_dict: Dict[str, Any],
    cve_id: str,
    affected_software: Any,
    references: List[str],
    service: Optional[ServiceRecord],
    fixed_version_hint: str = "",
    detected_version: str = "",
) -> Remediation:
    """
    Build remediation guidance from structured data only.

    Order of preference:
      1. Text the feed supplied for this specific CVE.
      2. A fixed version derived from the CPE ``versionEndExcluding`` boundary.
      3. A vendor advisory / patch reference URL.
      4. An explicit statement that no fix is published.
    """
    feed_text = _as_str(
        _first(finding_dict, "solution", "remediation", "remediation_notes", "fix")
    )
    if feed_text and len(feed_text) > 12:
        return Remediation(
            summary=feed_text, confidence=RemediationConfidence.FEED_SUPPLIED
        )

    product_label = ""
    fixed_version = fixed_version_hint
    last_affected = ""

    cpes = [
        cpe
        for cpe in _cpe_products(affected_software)
        if not (service and not _cpe_matches_product(cpe, service))
    ]
    # A record often publishes one range per supported branch — PostgreSQL's
    # run < 14.23, 15.0–15.18, … 18.0–18.4. The boundary that applies is the
    # one from the range this host's version falls in; taking the first range
    # listed told an 18.3 server to upgrade to 14.23.
    if detected_version:
        containing = [
            cpe for cpe in cpes if version_in_cpe_range(detected_version, cpe) is True
        ]
        if containing:
            cpes = containing

    for cpe in cpes:
        vendor = _as_str(cpe.get("vendor")).replace("_", " ").title()
        product = _as_str(cpe.get("product")).replace("_", " ").title()
        if product:
            product_label = f"{vendor} {product}".strip()
        if not fixed_version and not last_affected:
            # versionEndExcluding names the first fixed release. When only an
            # inclusive upper bound is published, the last vulnerable release
            # is known instead, so the guidance is worded accordingly.
            exclusive = _as_str(
                cpe.get("versionEndExcluding") or cpe.get("version_end_excluding")
            )
            if exclusive:
                fixed_version = exclusive
            else:
                last_affected = _as_str(
                    cpe.get("versionEndIncluding") or cpe.get("version_end_including")
                )
        if (fixed_version or last_affected) and product_label:
            break

    if not product_label and service:
        product_label = service.product or service.service_name

    # The upstream boundary still says how far the fix had to go, but for a
    # vendor build the vendor ships it: "Upgrade OpenBSD OpenSSH to 10.4" is not
    # an action anyone can take on Windows' own OpenSSH.
    vendor = vendor_build_for(
        *(
            (service.product, service.version, service.banner, service.extra)
            if service
            else ()
        ),
        detected_version,
    )
    if vendor and vendor.label:
        product_label = vendor.label

    if fixed_version or last_affected:
        target = product_label or "the affected component"
        if fixed_version:
            action = f"Upgrade {target} to version {fixed_version} or later."
        else:
            action = (
                f"Upgrade {target} to a release later than {last_affected}; that "
                f"version is the last one published as affected."
            )
        return Remediation(
            summary=(
                f"{action} This boundary is taken from the CPE version range "
                f"published for {cve_id or 'this finding'}."
                + (f" {vendor.guidance}" if vendor else "")
            ),
            confidence=RemediationConfidence.VERSION_BOUNDARY,
            fixed_version=fixed_version or None,
            last_affected_version=last_affected or None,
            product=product_label or None,
        )

    patch_url = ""
    for url in references:
        lowered = url.lower()
        if (
            any(hint in lowered for hint in _PATCH_HOST_HINTS)
            and "nvd.nist.gov" not in lowered
        ):
            patch_url = url
            break

    if patch_url:
        target = product_label or "the affected component"
        return Remediation(
            summary=(
                f"Apply the vendor advisory for {cve_id or 'this finding'} to "
                f"{target}. Refer to the linked advisory for the exact fixed "
                f"release and any interim mitigation."
            ),
            confidence=RemediationConfidence.VENDOR_PATCH,
            patch_url=patch_url,
        )

    return Remediation(
        summary=(
            f"No fixed version or vendor advisory is published in the "
            f"vulnerability feed for {cve_id or 'this finding'}. Apply "
            f"compensating controls — restrict network exposure to the affected "
            f"service, apply IPS/WAF signatures where available — and re-check "
            f"the vendor advisory page for an official fix."
        ),
        confidence=RemediationConfidence.NONE_PUBLISHED,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Finding construction
# ─────────────────────────────────────────────────────────────────────────────


def _build_synopsis(description: str, title: str) -> str:
    """
    Use the first sentence of the published description.

    No sentence is generated. If the description is empty the synopsis is
    empty, and the report omits the field rather than printing filler.
    """
    text = _as_str(description)
    if not text:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    first = sentences[0].strip() if sentences else text
    if len(first) > 260:
        first = first[:257].rstrip() + "..."
    return first


def _build_evidence(
    finding_dict: Dict[str, Any],
    service: Optional[ServiceRecord],
    detected_version: str,
    method: DetectionMethod,
    cve_id: str,
) -> Tuple[str, bool]:
    """
    Return ``(evidence_text, is_real_scanner_output)``.

    Real plugin output is always preferred. When the scanner captured none, a
    factual observation block is produced from data the scan actually recorded
    (banner, detected version, matched range) and flagged as derived, so it is
    never presented as captured tool output.
    """
    if finding_dict.get("evidence_captured") is False:
        # Derived on an earlier pass: rebuild it from what is recorded now.
        raw = _as_str(
            _first(finding_dict, "plugin_output", "proof", "output", "detail")
        )
    else:
        raw = _as_str(
            _first(
                finding_dict, "plugin_output", "evidence", "proof", "output", "detail"
            )
        )
    if raw:
        return redact_sensitive_data(raw), True

    if method == DetectionMethod.UNVERIFIED or service is None:
        return "", False

    lines: List[str] = []
    lines.append(f"Port/Protocol     : {service.port}/{service.protocol}")
    if service.service_name:
        lines.append(f"Service           : {service.service_name}")
    if service.product:
        lines.append(f"Product           : {service.product}")
    if detected_version:
        lines.append(f"Detected version  : {detected_version}")
    else:
        lines.append("Detected version  : not determined by this scan")
    if service.banner:
        banner = redact_sensitive_data(service.banner).strip()
        if len(banner) > 300:
            banner = banner[:297] + "..."
        lines.append(f"Service banner    : {banner}")

    if not lines:
        return "", False

    return "\n".join(lines), False


def parse_raw_finding(
    finding_dict: Dict[str, Any],
    host: str = "",
    hostname: str = "",
    service: Optional[ServiceRecord] = None,
    host_services: Optional[List[ServiceRecord]] = None,
    host_os: str = "",
    observations: Optional[Dict[int, Dict[str, Tuple[str, ...]]]] = None,
) -> StandardizedFinding:
    """Convert one raw vulnerability record into a StandardizedFinding."""

    cve_ids = extract_cve_list(
        _first(finding_dict, "cves", "cve", "cve_list", "cve_id") or ""
    )
    primary_cve = cve_ids[0] if cve_ids else ""

    description = redact_sensitive_data(
        _as_str(_first(finding_dict, "description", "details", "summary"))
    )

    # ── Scoring: parse and independently recompute; never invent ─────────────
    vector = _as_str(_first(finding_dict, "cvss_vector", "vector", "cvss_v3_vector"))
    feed_score = _as_float(
        _first(finding_dict, "cvss_v3_score", "cvss_score", "cvss", "base_score")
    )
    v2_score = _as_float(finding_dict.get("cvss_v2_score"))

    # A score of 0.0 with no vector is what the pipeline produces when no score
    # was published — not a genuine assessment that the issue carries zero risk.
    # Treating it as real produced reports where every finding read "0.0 / NONE"
    # and the severity columns were all zero.
    if not vector:
        if feed_score == 0.0:
            feed_score = None
        if v2_score == 0.0:
            v2_score = None

    cvss = parse_cvss_vector(vector, feed_score if feed_score else v2_score)

    if cvss is not None and cvss.score is not None:
        severity = cvss.severity
        source = f"CVSS v{cvss.version} base score"
        if cvss.computed_score is not None:
            source += " (recomputed from published vector)"
    elif feed_score is not None:
        severity = severity_from_score(feed_score)
        source = "CVSS base score supplied by feed (no vector published)"
        cvss = CvssData(
            version=_as_str(finding_dict.get("cvss_version")) or "3.1",
            vector_string="",
            feed_score=feed_score,
            integrity_warnings=[
                "No CVSS vector is published for this record, so the base score "
                "could not be independently recomputed."
            ],
        )
    elif v2_score is not None:
        severity = severity_from_score(v2_score)
        source = "CVSS v2 base score supplied by feed"
        cvss = CvssData(version="2.0", vector_string="", feed_score=v2_score)
    else:
        raw_sev = _as_str(_first(finding_dict, "severity", "risk_factor", "risk"))
        severity = normalize_severity(raw_sev, None)
        source = (
            "Vendor severity rating (no CVSS score published)"
            if severity != "Unscored"
            else "unscored"
        )

    # "affected" is the key the CVE database search returns; "affected_software"
    # is the column name on the stored vulnerability definition. Both occur.
    affected_software = (
        _first(finding_dict, "affected_software", "affected", "cpe_ids", "cpes") or []
    )

    method, detected_version, fixed_hint, suppression_basis = classify_detection(
        finding_dict, service, affected_software, host_services, host_os, observations
    )
    confidence, _ = DETECTION_SEMANTICS[method]

    # Which component of the affected package the flaw actually sits in. This
    # never changes whether the finding is reported — only how it is labelled
    # and where it ranks, so a client-side Critical cannot outrank a genuinely
    # network-reachable High.
    attack_surface, applicability_note = classify_attack_surface(
        description, has_open_port=service is not None
    )
    if attack_surface == "remote" and cvss is not None and cvss.is_local_only:
        attack_surface = "local"
        applicability_note = (
            "The published CVSS vector marks this as locally exploitable, so "
            "the open port is not the attack path. Exploitation requires "
            "existing access to the host."
        )

    references_raw = _first(finding_dict, "references", "see_also", "refs") or []
    if isinstance(references_raw, str):
        references_raw = [references_raw]
    references = [_as_str(r) for r in references_raw if _as_str(r)]
    if primary_cve:
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{primary_cve}"
        if nvd_url not in references:
            references.append(nvd_url)

    remediation = resolve_remediation(
        finding_dict,
        primary_cve,
        affected_software,
        references,
        service,
        fixed_hint,
        detected_version=detected_version,
    )

    countermeasure = (
        observed_countermeasure(finding_dict, service, observations)
        if suppression_basis == "countermeasure_observed"
        else None
    )

    applies_to: Tuple[str, ...] = ()
    host_family = ""
    if suppression_basis == "platform_mismatch":
        applies_to = record_platform_scope(finding_dict)
        host_family = scope_excludes_host(applies_to, host_os)
        if not host_family:
            applies_to = ()

    evidence, evidence_real = _build_evidence(
        finding_dict, service, detected_version, method, primary_cve
    )

    title = _as_str(_first(finding_dict, "title", "plugin_name", "name"))
    if not title:
        title = (
            primary_cve or _as_str(finding_dict.get("plugin_id")) or "Unnamed finding"
        )

    plugin_id = (
        _as_str(_first(finding_dict, "plugin_id", "id", "rule_id"))
        or primary_cve
        or title
    )

    cwe_raw = _first(finding_dict, "cwe_ids", "cwe", "cwes", "cwe_id") or []
    if isinstance(cwe_raw, str):
        cwe_raw = [cwe_raw]
    cwe_ids = [_as_str(c) for c in cwe_raw if _as_str(c)]

    status = _as_str(finding_dict.get("status")) or "open"
    mitigation_status = _as_str(finding_dict.get("mitigation_status"))
    if not mitigation_status:
        status_map = {
            "false_positive": "False Positive",
            "accepted_risk": "Accepted Risk",
            "risk_accepted": "Accepted Risk",
            "mitigated": "Mitigated",
            "fixed": "Remediated",
            "resolved": "Remediated",
        }
        mitigation_status = status_map.get(status.lower(), "Active")

    finding = StandardizedFinding(
        plugin_id=plugin_id,
        plugin_name=title,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        plugin_family=_as_str(_first(finding_dict, "plugin_family", "source", "family"))
        or "General",
        host=host,
        hostname=hostname,
        port=service.port if service else _as_int(finding_dict.get("port")),
        protocol=(
            service.protocol
            if service
            else (_as_str(finding_dict.get("protocol")) or "tcp")
        ),
        service_name=(
            service.service_name
            if service
            else _as_str(finding_dict.get("service_name"))
        ),
        service_product=service.product if service else "",
        detected_version=detected_version,
        suppression_basis=suppression_basis,
        applies_to_platforms=applies_to,
        host_platform=host_family,
        suppression_detail=(
            countermeasure.reason
            if countermeasure
            else (
                vendor_not_affected(finding_dict, service)
                if suppression_basis == "vendor_not_affected"
                else ""
            )
        ),
        cvss=cvss,
        severity=severity,
        severity_source=source,
        synopsis=_build_synopsis(description, title),
        description=description,
        evidence=evidence,
        evidence_available=evidence_real,
        detection_method=method,
        confidence=confidence,
        remediation=remediation,
        epss_score=_as_float(_first(finding_dict, "epss_score", "epss")),
        epss_percentile=_as_float(finding_dict.get("epss_percentile")),
        in_kev=bool(finding_dict.get("in_kev") or finding_dict.get("kev")),
        kev_due_date=_as_str(finding_dict.get("kev_due_date")),
        has_exploit=_as_bool_or_none(
            _first(finding_dict, "has_exploit", "exploit_available")
        ),
        priority_level=_as_observed(finding_dict.get("priority_level")).upper(),
        vendor_remediation=_as_str(finding_dict.get("vendor_remediation")),
        references=references,
        # The CVE feed names these "published"/"updated_at"; only the report's
        # own vocabulary was being read, so "CVE Published" and "CVE Age" came
        # out empty for every row of the CSV export.
        published_at=_as_str(_first(finding_dict, "published_at", "published")),
        last_modified_at=_as_str(
            _first(finding_dict, "last_modified_at", "last_modified", "updated_at")
        ),
        first_found_at=_as_str(_first(finding_dict, "first_found_at", "first_seen_at")),
        last_found_at=_as_str(_first(finding_dict, "last_found_at", "last_seen_at")),
        status=status,
        mitigation_status=mitigation_status,
        url=_first(finding_dict, "url", "target_url"),
        http_method=finding_dict.get("http_method"),
        vulnerable_parameter=finding_dict.get("vulnerable_parameter"),
        attack_surface=attack_surface,
        applicability_note=applicability_note,
        integrity_warnings=list(cvss.integrity_warnings) if cvss else [],
    )

    return finding


def _build_port_observation(
    service: ServiceRecord, host: str, hostname: str
) -> StandardizedFinding:
    """Record an open port as an informational inventory item, not a vulnerability."""
    # An authenticated session can report a service the network cannot reach.
    # Describing that as "open" would overstate the attack surface, so the
    # observation states what was actually established.
    opening = {
        "exposed": f"Port {service.port}/{service.protocol} is open and reachable.",
        "filtered": (
            f"Port {service.port}/{service.protocol} is listening on the host "
            f"but was not reachable from the scanner."
        ),
        "undetermined": (
            f"Port {service.port}/{service.protocol} is listening on the host; "
            f"reachability was not tested."
        ),
    }.get(service.exposure, f"Port {service.port}/{service.protocol} is open.")
    detail = [opening]
    if service.product_label:
        detail.append(f"Service fingerprint: {service.product_label}.")
    elif service.service_name:
        detail.append(f"Service reported as '{service.service_name}'.")

    evidence_lines = [
        f"Port/Protocol     : {service.port}/{service.protocol}",
        f"State             : {service.state}",
    ]
    if service.exposure:
        evidence_lines.append(f"Exposure          : {service.exposure}")
    if service.bind_scope:
        evidence_lines.append(f"Bind scope        : {service.bind_scope}")
    if service.service_name:
        evidence_lines.append(f"Service           : {service.service_name}")
    if service.product:
        evidence_lines.append(f"Product           : {service.product}")
    if service.version:
        evidence_lines.append(f"Version           : {service.version}")
    if service.banner:
        banner = redact_sensitive_data(service.banner).strip()
        evidence_lines.append(f"Banner            : {banner[:300]}")

    return StandardizedFinding(
        plugin_id=f"PORT-{service.port}-{service.protocol.upper()}",
        plugin_name=f"Open Port: {service.service_name or 'unidentified service'} ({service.port}/{service.protocol})",
        plugin_family="Port Inventory",
        host=host,
        hostname=hostname,
        port=service.port,
        protocol=service.protocol,
        service_name=service.service_name,
        service_product=service.product,
        detected_version=service.version,
        cvss=None,
        severity="None",
        severity_source="Informational observation — not a scored vulnerability",
        synopsis=" ".join(detail),
        description=(
            "This entry documents an open network port discovered during the "
            "scan. It is included for attack-surface inventory and is not, by "
            "itself, evidence of a vulnerability. Review whether this service "
            "needs to be reachable from the scanned network segment."
        ),
        evidence="\n".join(evidence_lines),
        evidence_available=True,
        detection_method=DetectionMethod.PORT_OBSERVATION,
        confidence=Confidence.INFORMATIONAL,
        remediation=Remediation(
            summary=(
                "If this service does not need to be reachable from this "
                "network segment, restrict it with a host or perimeter firewall "
                "rule. Otherwise ensure it is patched and access-controlled."
            ),
            confidence=RemediationConfidence.FEED_SUPPLIED,
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Host extraction
# ─────────────────────────────────────────────────────────────────────────────


def _parse_services(host_dict: Dict[str, Any]) -> List[ServiceRecord]:
    services: List[ServiceRecord] = []
    raw_ports = (
        host_dict.get("open_ports")
        or host_dict.get("ports")
        or host_dict.get("services")
        or []
    )
    if not isinstance(raw_ports, list):
        return services

    for entry in raw_ports:
        if not isinstance(entry, dict):
            continue
        port = _as_int(_first(entry, "port", "portid"))
        if port is None:
            continue
        services.append(
            ServiceRecord(
                port=port,
                protocol=_as_str(_first(entry, "protocol", "proto")) or "tcp",
                state=_as_str(entry.get("state")) or "open",
                service_name=_as_str(_first(entry, "service", "service_name", "name")),
                product=_as_str(_first(entry, "product", "service_product")),
                version=_as_str(_first(entry, "version", "service_version")),
                extra=_as_str(_first(entry, "extra", "service_extra", "extrainfo")),
                banner=_as_str(entry.get("banner")),
                cpe_identities=tuple(
                    _cpe_identities_from(_first(entry, "cpe", "cpes", "service_cpe"))
                ),
                version_precision=_as_str(entry.get("version_precision")),
                exposure=_as_str(entry.get("exposure")),
                bind_scope=_as_str(entry.get("bind_scope")),
            )
        )
    return services


def _match_service(
    finding_dict: Dict[str, Any], services: List[ServiceRecord]
) -> Optional[ServiceRecord]:
    """
    Bind a finding to the service the scan actually associated it with.

    Resolution order: explicit service_id, then explicit port, then nothing.
    A product name is never pattern-matched out of CVE text to pick a port.
    """
    service_id = _as_str(finding_dict.get("service_id"))
    if service_id:
        # Service IDs are formatted "svc_{asset}_{port}_{proto}".
        tail = re.search(r"_(\d{1,5})_(tcp|udp)$", service_id, re.IGNORECASE)
        if tail:
            port, proto = int(tail.group(1)), tail.group(2).lower()
            for svc in services:
                if svc.port == port and svc.protocol.lower() == proto:
                    return svc

    port = _as_int(_first(finding_dict, "port", "service_port"))
    if port is not None:
        proto = _as_str(_first(finding_dict, "protocol", "proto")).lower() or "tcp"
        for svc in services:
            if svc.port == port and svc.protocol.lower() == proto:
                return svc
        for svc in services:
            if svc.port == port:
                return svc

    return None


def _iter_host_dicts(payload: Any) -> List[Dict[str, Any]]:
    """Locate per-host records inside any of the payload shapes in use."""
    hosts: List[Dict[str, Any]] = []

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 6 or node is None:
            return
        if isinstance(node, list):
            for item in node:
                visit(item, depth + 1)
            return
        if not isinstance(node, dict):
            return

        looks_like_host = any(
            key in node for key in ("ip", "ip_address", "host", "target")
        ) and any(
            key in node
            for key in (
                "open_ports",
                "ports",
                "cves",
                "vulnerabilities",
                "services",
                "hostname",
                "mac",
                "mac_address",
            )
        )
        if looks_like_host:
            hosts.append(node)
            return

        for key in ("data", "hosts", "results", "assets", "findings"):
            if key in node:
                visit(node[key], depth + 1)

    visit(payload)
    return hosts


def _extract_credentialed_host(report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Reshape a credentialed audit report into the common host structure."""
    if not isinstance(report, dict):
        return None

    system_info = report.get("system_info") or {}
    target = _as_str(_first(report, "target", "host", "ip"))
    if not target:
        return None

    host: Dict[str, Any] = {
        "ip_address": target,
        "hostname": _as_str(system_info.get("hostname")),
        "os_guess": _as_str(
            _first(system_info, "os_name", "os_version_id", "pretty_name")
        ),
        "open_ports": report.get("open_ports_credentialed") or [],
        "credentialed": True,
        # Candidates the audit already ruled out. They are no longer among its
        # findings, so the report can only account for them if they travel with
        # the host record — without this the methodology appendix reported zero
        # suppressions for every credentialed scan, whatever it had withheld.
        "suppressed_cves": report.get("suppressed_cves") or [],
        "candidates_evaluated": report.get("candidates_evaluated") or 0,
    }

    packages = {
        _as_str(p.get("name")): _as_str(p.get("version"))
        for p in (report.get("packages") or [])
        if isinstance(p, dict) and p.get("name")
    }

    cves: List[Dict[str, Any]] = []
    for entry in report.get("cves") or []:
        if not isinstance(entry, dict):
            continue
        record = dict(entry)
        package = _as_str(_first(entry, "package", "package_name"))
        if package:
            record.setdefault("package", package)
            # A package finding is a package finding whether or not the host
            # also has listening services. Without this the credentialed audit
            # of a host with a port inventory fell through to the network
            # matching path, where a package that is not exposed on any port
            # looks like a product the host does not run — and every finding
            # the audit had already version-matched was suppressed.
            record.setdefault("detection_method", "credentialed")
            # Recover the installed version from the package inventory when the
            # CVE record itself did not carry one. Detection confidence is then
            # decided by classify_detection: a known version can be range-checked
            # and confirmed, an unknown one can only be reported as potential.
            if package in packages and not record.get("installed_version"):
                record["installed_version"] = packages[package]
        cves.append(record)

    host["cves"] = cves
    return host


# ─────────────────────────────────────────────────────────────────────────────
# Public entry points
# ─────────────────────────────────────────────────────────────────────────────


def upgrade_target(
    fixed_version: Optional[str], last_affected_version: Optional[str] = None
) -> str:
    """
    The release an upgrade must reach, as a phrase for "Upgrade X to …".

    "8.0.42 or later" when the first fixed release is known; "a release later
    than 8.0.44" when only the last affected one is. "" when neither is.
    """
    if fixed_version:
        return f"{fixed_version} or later"
    if last_affected_version:
        return f"a release later than {last_affected_version}"
    return ""


def boundary_key(version: str, is_last_affected: bool) -> Tuple[Tuple[int, ...], int]:
    """
    Order upgrade boundaries by how far they require the upgrade to go.

    A last-affected release outranks a fixed release with the same number:
    "later than 8.0.44" asks for more than "8.0.44 or later".
    """
    return (_comparable_version(version or "") or (), 1 if is_last_affected else 0)


@dataclass
class FindingGroup:
    """
    Findings that one upgrade resolves, presented as a single item.

    A host twelve Chrome versions behind is genuinely affected by ~1,700
    published CVEs, and listing them individually is accurate and useless: the
    reader cannot see that four products need updating, the remediation is one
    action repeated 1,700 times, and — because a report can only print so many
    findings — an ICS component with a Critical was pushed out of the document
    by a browser. Grouping is how every established scanner presents this, and
    it changes presentation only: the per-CVE findings remain the record.
    """

    product: str
    #: The boundary the group's upgrade must reach. A first fixed release,
    #: unless ``boundary_is_last_affected`` says it is the last vulnerable one.
    fixed_version: str
    findings: List[StandardizedFinding] = field(default_factory=list)
    boundary_is_last_affected: bool = False

    @property
    def upgrade_target(self) -> str:
        """The release to upgrade to, as a phrase ("… or later")."""
        if self.boundary_is_last_affected:
            return upgrade_target(None, self.fixed_version)
        return upgrade_target(self.fixed_version)

    @property
    def representative(self) -> StandardizedFinding:
        """The finding whose detail stands for the group — the worst of them."""
        return self.findings[0]

    @property
    def is_group(self) -> bool:
        return len(self.findings) > 1

    @property
    def severity(self) -> str:
        return self.representative.severity

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def cve_ids(self) -> List[str]:
        return sorted({f.primary_cve for f in self.findings if f.primary_cve})

    @property
    def kev_findings(self) -> List[StandardizedFinding]:
        return [f for f in self.findings if f.in_kev]

    @property
    def max_epss(self) -> Optional[StandardizedFinding]:
        scored = [f for f in self.findings if f.epss_score]
        return max(scored, key=lambda f: f.epss_score) if scored else None


#: Below this many findings, an upgrade target is shown as individual findings.
#: Two CVEs read better as two entries than as a group of two.
GROUPABLE_MINIMUM = 3


def group_findings_for_report(
    findings: List[StandardizedFinding],
    minimum: int = GROUPABLE_MINIMUM,
) -> List[FindingGroup]:
    """
    Collapse findings that a single upgrade resolves into one item each.

    Grouped on the upgrade target — the same key the executive remediation plan
    uses, so the two documents cannot disagree about how much work there is.
    Findings with no published fix, or too few to be worth grouping, come back
    as single-finding groups and render exactly as before.

    Ordering is preserved by severity: groups are ranked by their worst finding,
    so an ICS Critical still leads a browser's thousand Highs.
    """
    grouped: Dict[Any, FindingGroup] = {}
    singles: List[FindingGroup] = []

    for finding in findings:
        remediation = finding.remediation
        product = (remediation.product or "").strip() if remediation else ""
        fixed = (remediation.fixed_version or "").strip() if remediation else ""
        last = (remediation.last_affected_version or "").strip() if remediation else ""
        boundary, is_last = (fixed, False) if fixed else (last, bool(last))
        if not product or not boundary:
            singles.append(
                FindingGroup(product="", fixed_version="", findings=[finding])
            )
            continue
        # Keyed on the product, not on the fixed version. An administrator
        # performs one upgrade: splitting Chrome into a card per fixed version
        # produced 76 cards for what is a single action. The group therefore
        # tracks the highest boundary any of its findings requires — the same
        # rule the executive remediation plan applies, so the two documents
        # cannot disagree about how much work there is.
        key = (finding.host, product.lower())
        entry = grouped.setdefault(
            key,
            FindingGroup(
                product=product,
                fixed_version=boundary,
                boundary_is_last_affected=is_last,
            ),
        )
        entry.findings.append(finding)
        if boundary_key(boundary, is_last) > boundary_key(
            entry.fixed_version, entry.boundary_is_last_affected
        ):
            entry.fixed_version = boundary
            entry.boundary_is_last_affected = is_last

    result: List[FindingGroup] = []
    for entry in grouped.values():
        entry.findings.sort(key=lambda f: f.sort_key(), reverse=True)
        if len(entry.findings) >= minimum:
            result.append(entry)
        else:
            result.extend(
                FindingGroup(product="", fixed_version="", findings=[f])
                for f in entry.findings
            )
    result.extend(singles)

    result.sort(key=lambda g: g.representative.sort_key(), reverse=True)
    return result


def suppression_reason(finding: StandardizedFinding) -> str:
    """
    Plain-English account of why a candidate was withheld.

    Written once and used by both verification paths, so the wording a user
    reads in the report appendix is the same wording recorded on the host
    during the scan.
    """
    if finding.confidence == Confidence.UNVERIFIED:
        # Stated from the basis the check recorded, not inferred from which
        # fields are populated: a finding can carry a detected version and
        # still have been ruled out because the product was never found.
        if finding.suppression_basis == "version_outside_range":
            return (
                f"Ruled out: the version detected on this host "
                f"({finding.detected_version}) falls outside the vulnerable "
                f"range published for this record."
            )
        if (
            finding.suppression_basis
            in ("countermeasure_observed", "vendor_not_affected")
            and finding.suppression_detail
        ):
            return f"Ruled out: {finding.suppression_detail}."
        if finding.suppression_basis == "platform_mismatch":
            if finding.applies_to_platforms and finding.host_platform:
                return (
                    f"Ruled out: this record is published for "
                    f"{describe_scope(finding.applies_to_platforms)} only, and "
                    f"this host runs "
                    f"{PLATFORM_LABELS.get(finding.host_platform, finding.host_platform)}."
                )
            return (
                "Ruled out: every published configuration for this record is "
                "scoped to a platform this host is not running."
            )
        return (
            "Ruled out: the host's enumerated services do not include the "
            "affected product."
        )
    _, explanation = DETECTION_SEMANTICS[finding.detection_method]
    return (
        f"Below the reporting confidence threshold "
        f"(quality of detection {finding.qod}%, "
        f"threshold {QOD_REPORT_THRESHOLD}%). {explanation}"
    )


@dataclass
class HostVerification:
    """The verified/withheld split for one host's candidate findings."""

    #: Candidate records, in their original shape, that survived verification.
    #: Kept raw rather than normalized so the report remains the single place
    #: that decides how a finding is presented.
    verified: List[Any] = field(default_factory=list)
    #: Withheld candidates with the reason, for the audit trail.
    suppressed: List[ExcludedFinding] = field(default_factory=list)
    #: Severity breakdown of the verified set.
    severity_counts: Dict[str, int] = field(
        default_factory=lambda: {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0,
            "Unscored": 0,
        }
    )

    @property
    def evaluated(self) -> int:
        return len(self.verified) + len(self.suppressed)

    def as_host_fields(self) -> Dict[str, Any]:
        """The fields to write onto a host record after verification."""
        return {
            "cves": self.verified,
            "suppressed_cves": [
                {
                    "identifier": item.identifier,
                    "host": item.host,
                    "reason": item.reason,
                }
                for item in self.suppressed
            ],
            "vulnerability_counts": dict(self.severity_counts),
            "candidates_evaluated": self.evaluated,
        }


def verify_host_findings(host_dict: Dict[str, Any]) -> HostVerification:
    """
    Split one host's candidate findings into verified and withheld.

    This is the verification step itself, exposed so the vulnerability engine
    can run it during the scan. A candidate survives only when the host's own
    enumerated services place the affected product on this machine and the
    detected version falls inside the published vulnerable range — the same
    test the report applies, run once, at the point the data is produced.

    The input host record is not modified; the caller decides what to store.
    """
    verification = HostVerification()
    if not isinstance(host_dict, dict):
        return verification

    ip = _as_str(_first(host_dict, "ip_address", "ip", "host", "target"))
    hostname = clean_hostname(
        _as_str(_first(host_dict, "hostname", "netbios_name", "fqdn")), ip
    )
    services = _parse_services(host_dict)
    host_os = _as_str(_first(host_dict, "os_guess", "os_name", "os"))
    observations = host_observations(host_dict)

    candidates = _first(host_dict, "cves", "vulnerabilities", "findings") or []
    if not isinstance(candidates, list):
        return verification

    for raw in candidates:
        candidate = {"cve_id": raw} if isinstance(raw, str) else raw
        if not isinstance(candidate, dict):
            continue

        finding = parse_raw_finding(
            candidate,
            host=ip,
            hostname=hostname,
            service=_match_service(candidate, services),
            host_services=services,
            host_os=host_os,
            observations=observations,
        )

        is_credentialed_origin = _as_str(
            _first(candidate, "detection_method", "evidence_source")
        ).lower() in ("credentialed", "credentialed_package", "package") or (
            _as_str(candidate.get("finding_origin")) == "credentialed"
        )

        if finding.is_reportable:
            # Carry the verdict back onto the record the rest of the pipeline
            # stores. Everything below was computed here and then thrown away:
            # the database kept only severity and score, so the API had to
            # answer with hardcoded zeros and the UI could not distinguish a
            # version-confirmed finding from an unverified guess. The reports
            # re-derived it independently, which is why they were right while
            # every other surface was not.
            if isinstance(raw, dict):
                raw.update(
                    {
                        "confidence": finding.confidence.value,
                        "qod": finding.qod,
                        "detection_method": finding.detection_method.value,
                        "detected_version": finding.detected_version,
                        "attack_surface": finding.attack_surface,
                        "cvss_vector": finding.cvss_vector,
                        "cvss_version": finding.cvss_version,
                        "severity": finding.severity,
                        "epss_score": finding.epss_score,
                        "epss_percentile": finding.epss_percentile,
                        "in_kev": finding.in_kev,
                        "kev_due_date": finding.kev_due_date or None,
                        # A first fixed release only. The last affected one
                        # travels under its own key: written here as
                        # fixed_version, the next verification pass read it
                        # back as a fixed release and advised upgrading to a
                        # version the CVE names as vulnerable.
                        "fixed_version": getattr(
                            finding.remediation, "fixed_version", ""
                        ),
                        "last_affected_version": getattr(
                            finding.remediation, "last_affected_version", None
                        ),
                        "evidence": finding.evidence,
                        # Whether that evidence is scanner output or a block
                        # this module derived. Without it, the next pass found
                        # derived text under "evidence" and presented it as
                        # captured output — and kept a "Detected version" line
                        # an authenticated correction had since superseded.
                        "evidence_captured": finding.evidence_available,
                    }
                )
                # Where the finding came from, which the verdict just written
                # over detection_method no longer says.
                if is_credentialed_origin:
                    raw["finding_origin"] = "credentialed"
                # An OS-level finding is about the host, not about whatever
                # port the candidate happened to be generated from. Leaving the
                # port attached is how a Google Chrome CVE came to be filed
                # against 22/tcp ssh.
                if finding.detection_method is DetectionMethod.OS_REPORTED:
                    raw.pop("port", None)
                    raw.pop("protocol", None)

            verification.verified.append(raw)
            verification.severity_counts[finding.severity] = (
                verification.severity_counts.get(finding.severity, 0) + 1
            )
        else:
            verification.suppressed.append(
                ExcludedFinding(
                    identifier=finding.primary_cve or finding.plugin_id,
                    host=ip,
                    reason=suppression_reason(finding),
                )
            )

    return verification


def verify_credentialed_report(report: Dict[str, Any]) -> HostVerification:
    """
    Verify a credentialed audit's findings at the point the audit produces them.

    A credentialed audit matches installed package versions against published
    ranges, so its findings arrive with real evidence — but the audit still
    emits candidates its own matcher could not settle, and until now those were
    only filtered when the report was rendered. Everything in between (the
    severity summary, the vulnerability rows written to the database, the
    dashboard counts) was reading the unfiltered list.

    The report is reshaped into the common host structure first, so the exact
    same verification runs here as at report time — one implementation, one
    result, wherever it is called from.
    """
    host = _extract_credentialed_host(report)
    if not host:
        return HostVerification()
    return verify_host_findings(host)


def build_scan_report(
    result_dict: Dict[str, Any],
    include_port_inventory: bool = True,
) -> ScanFindings:
    """
    Normalize a full scan result payload into a host-aware ScanFindings object.

    Findings whose detection method resolves to UNVERIFIED are withheld from
    the report body and recorded in ``ScanFindings.excluded`` with the reason,
    so the suppression is auditable rather than silent.
    """
    report = ScanFindings()
    if not isinstance(result_dict, dict):
        return report

    payload = result_dict.get("data", result_dict)

    host_dicts = _iter_host_dicts(payload)

    # Credentialed audits store their payload under a distinct key. A scan may
    # cover several hosts, in which case `reports` holds all of them and
    # `report` repeats the first for consumers that predate multi-host audits;
    # reading both would double-count that host.
    if isinstance(payload, dict) and "credentialed" in payload:
        cred = payload["credentialed"]
        cred_reports: List[Any] = []
        if isinstance(cred, dict):
            if isinstance(cred.get("reports"), list) and cred["reports"]:
                cred_reports = cred["reports"]
            elif cred.get("report"):
                cred_reports = [cred["report"]]
        for cred_report in cred_reports:
            converted = _extract_credentialed_host(cred_report or {})
            if converted:
                host_dicts.append(converted)

    if not host_dicts and isinstance(result_dict.get("metadata"), dict):
        # Single-target scan with no per-host breakdown available.
        target = _as_str(result_dict["metadata"].get("target"))
        if target and ("," not in target):
            host_dicts = [
                {
                    "ip_address": target,
                    **({"cves": payload} if isinstance(payload, list) else {}),
                }
            ]

    seen_global: set = set()

    for host_dict in host_dicts:
        ip = _as_str(_first(host_dict, "ip_address", "ip", "host", "target"))
        if not ip:
            continue

        hostname = clean_hostname(
            _as_str(_first(host_dict, "hostname", "netbios_name", "fqdn")), ip
        )
        services = _parse_services(host_dict)
        os_name = _as_observed(_first(host_dict, "os_guess", "os_name", "os"))

        host_report = HostReport(
            ip=ip,
            hostname=hostname,
            # MAC casing is normalised so a report never shows the same kind of
            # identifier two different ways on consecutive pages.
            mac=_as_observed(_first(host_dict, "mac_address", "mac")).lower(),
            vendor=_as_observed(host_dict.get("vendor")),
            os_name=os_name,
            device_category=_as_observed(host_dict.get("device_category")),
            is_active=bool(host_dict.get("is_active", True)),
            services=services,
            credentialed=bool(host_dict.get("credentialed")),
        )

        raw_vulns = _first(host_dict, "cves", "vulnerabilities", "findings") or []
        if not isinstance(raw_vulns, list):
            raw_vulns = []

        seen_host: set = set()
        withheld_here: set = set()

        # Candidates the vulnerability engine already ruled out while the scan
        # was running. They are replayed from the host record rather than
        # re-derived, because the host no longer carries them among its
        # findings and the methodology appendix must still account for every
        # candidate the scan evaluated.
        for entry in host_dict.get("suppressed_cves") or []:
            if not isinstance(entry, dict):
                continue
            identifier = _as_str(_first(entry, "identifier", "cve_id", "id"))
            reason = _as_str(entry.get("reason"))
            if not identifier or identifier in withheld_here:
                continue
            withheld_here.add(identifier)
            report.excluded.append(
                ExcludedFinding(
                    identifier=identifier,
                    host=_as_str(entry.get("host")) or ip,
                    reason=reason or "Withheld during scan-time verification.",
                )
            )

        for raw in raw_vulns:
            if isinstance(raw, str):
                raw = {"cve_id": raw}
            if not isinstance(raw, dict):
                continue

            service = _match_service(raw, services)
            finding = parse_raw_finding(
                raw,
                host=ip,
                hostname=hostname,
                service=service,
                host_services=services,
                host_os=os_name,
                observations=host_observations(host_dict),
            )

            # Payloads written before verification moved into the scan still
            # arrive unfiltered, so the same test runs here. On a verified
            # payload this rejects nothing — it is the identical check against
            # the identical data.
            if not finding.is_reportable:
                identifier = finding.primary_cve or finding.plugin_id
                if identifier in withheld_here:
                    continue
                withheld_here.add(identifier)
                report.excluded.append(
                    ExcludedFinding(
                        identifier=identifier,
                        host=ip,
                        reason=suppression_reason(finding),
                    )
                )
                continue

            # Records lacking a CVE or plugin id (config checks, vendor
            # advisories) would otherwise all collapse to the same key and be
            # silently merged, so the package and title are included as
            # discriminators.
            dedup = (
                finding.plugin_id,
                finding.primary_cve,
                finding.port,
                finding.protocol,
                _as_str(_first(raw, "package", "package_name")),
                finding.plugin_name,
            )
            if dedup in seen_host:
                continue
            seen_host.add(dedup)

            if finding.mitigation_status in (
                "False Positive",
                "Accepted Risk",
                "Mitigated",
                "Remediated",
            ):
                report.mitigated.append(finding)
            else:
                host_report.findings.append(finding)

            for warning in finding.integrity_warnings:
                message = (
                    f"{ip} / {finding.primary_cve or finding.plugin_id}: {warning}"
                )
                if message not in seen_global:
                    seen_global.add(message)
                    report.integrity_warnings.append(message)

        if include_port_inventory:
            covered = {(f.port, f.protocol) for f in host_report.findings}
            for svc in services:
                # Listening sockets read from inside the host belong in the
                # inventory too; only a loopback bind is excluded, because it is
                # positively not attack surface rather than merely unconfirmed.
                if not svc.is_reachable:
                    continue
                if (svc.port, svc.protocol) in covered:
                    continue
                host_report.findings.append(_build_port_observation(svc, ip, hostname))

        host_report.findings.sort(key=lambda f: f.sort_key(), reverse=True)
        report.hosts.append(host_report)

    report.hosts.sort(
        key=lambda h: (
            max((f.severity_rank for f in h.findings), default=0),
            len(h.vulnerability_findings),
        ),
        reverse=True,
    )
    return report
