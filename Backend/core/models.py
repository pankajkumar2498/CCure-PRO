"""
core/models.py
--------------
Shared enums and dataclasses.
No logic here - just typed containers.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional

# =============================================================================
# Enums
# =============================================================================


class DiscoveryScanType(Enum):
    PING = "ping"
    ARP = "arp"
    TCP = "tcp"
    FULL = "full"
    ADAPTIVE = "adaptive"
    STEALTH = "stealth"  # fragmented / low-TTL evasion


class ScanIntensity(Enum):
    LIGHT = "light"  # quick ports only
    NORMAL = "normal"  # standard ports
    DEEP = "deep"  # all ports + deep banner grab


# =============================================================================
# Result Dataclasses
# =============================================================================


#: How strongly a port record's service identification is evidenced. Higher
#: wins when two observations of the same port disagree — see
#: ``PortResult.evidence_rank``. Ordering, not arrival, decides which
#: fingerprint a host keeps: a discovery-time connect-and-read must never
#: displace a service-detection result, because the version it failed to
#: capture is what every downstream version check depends on.
FINGERPRINT_SOURCES: tuple[str, ...] = (
    "port_state",  # the port answered; nothing else established
    "connect_probe",  # discovery-time banner grab
    "banner",  # a banner was captured and parsed
    "service_detection",  # scanner identified the product
    "version_detection",  # scanner identified product *and* version
)


@dataclass
class PortResult:
    """
    One observed open port.

    This is the pipeline's source of truth for what is running on a port, and
    the input every later version comparison depends on. Identification is kept
    **structured**: ``product``, ``version`` and ``extra`` stay in separate
    fields exactly as the scanner reported them, rather than being concatenated
    into a display string that consumers have to parse back apart.
    """

    port: int
    service: str = "unknown"
    protocol: str = "tcp"
    state: str = "open"
    banner: str = ""
    #: The version alone, e.g. "9.5" — never the product name, never the extra
    #: info. Empty means the scan did not establish a version.
    version: str = ""
    #: Product name as identified by the scanner, e.g. "OpenSSH".
    product: str = ""
    #: Scanner-supplied extra info, e.g. "protocol 2.0", "Ubuntu".
    extra: str = ""
    #: CPEs the scanner itself assigned to this service. This is authoritative
    #: product identity — with it, matching a CVE to this service is a
    #: comparison rather than a guess at what the banner text means.
    cpe: list = field(default_factory=list)
    #: What the version string actually pins down: "exact", "floor" (the real
    #: version is at least this), "ceiling", or "unknown". Recorded where the
    #: measurement happens so no consumer has to infer it from prose.
    version_precision: str = "unknown"
    #: Which observation produced this identification. See FINGERPRINT_SOURCES.
    fingerprint_source: str = "port_state"
    risk: str = "Info"
    cves: list = field(default_factory=list)

    @property
    def evidence_rank(self) -> int:
        try:
            return FINGERPRINT_SOURCES.index(self.fingerprint_source)
        except ValueError:
            return 0

    @property
    def product_label(self) -> str:
        """Display string, composed on demand from the structured fields."""
        return " ".join(p for p in (self.product, self.version, self.extra) if p)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TLSInfo:
    enabled: bool = False
    version: str = ""
    cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    cert_expired: bool = False
    cert_self_signed: bool = False
    san_domains: list = field(default_factory=list)
    weak_cipher: bool = False
    score: str = "N/A"  # A / B / C / F

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HTTPAudit:
    status_code: int = 0
    server_header: str = ""
    hsts: bool = False
    x_frame: str = ""
    csp: bool = False
    x_content_type: bool = False
    x_xss: bool = False
    redirect_http: bool = False  # HTTP -> HTTPS redirect?
    issues: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostResult:
    ip_address: str
    hostname: str = "Unknown"
    mac_address: str = "N/A"
    vendor: str = "N/A"
    is_active: bool = False
    status: str = "Inactive"
    scan_method: str = "N/A"
    response_time_ms: float | None = None
    open_ports: list = field(default_factory=list)
    os_guess: str = "Unknown"
    os_confidence: str = "Low"
    confidence: str = "Low"
    #: Exact build where a probe established one (e.g. an SNMP sysDescr naming
    #: the running kernel), as opposed to the range os_guess carries.
    os_version: str | None = None
    #: What established the OS — "snmp_sysdescr" outranks an Nmap fingerprint,
    #: which is why later phases need to be able to see where it came from.
    os_evidence: str | None = None
    # Timezone-aware UTC. This used to be a naive local-time stamp sitting
    # beside UTC fields in the same payload, so an export showed a host scanned
    # at "16:18" next to a scan that completed at "10:48" — same moment, no
    # offset on either to say so.
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Priority-1 & 2 & 3 Additions
    device_category: str = "unknown"
    snmp_device_type: str | None = None
    mdns_name: str | None = None
    netbios_names: list = field(default_factory=list)
    os_fingerprint_full: dict = field(default_factory=dict)
    tcp_fingerprint: dict = field(default_factory=dict)
    port_states: dict = field(default_factory=dict)

    # v2 enrichment
    tls_info: dict = field(default_factory=dict)
    http_audit: dict = field(default_factory=dict)
    snmp_info: dict = field(default_factory=dict)
    smb_info: dict = field(default_factory=dict)
    ssh_info: dict = field(default_factory=dict)
    udp_services: list = field(default_factory=list)
    #: Verified findings only. The vulnerability engine tests every candidate
    #: against this host's own services and versions before it lands here.
    cves: list = field(default_factory=list)
    #: Candidates ruled out during that verification, with the reason each was
    #: withheld. Carried through to the report's suppressed-candidates
    #: appendix and the CSV export, so the filtering stays auditable.
    suppressed_cves: list = field(default_factory=list)
    #: Severity breakdown of ``cves``, computed from recomputed CVSS vectors.
    vulnerability_counts: dict = field(default_factory=dict)
    #: How many candidates verification examined (verified + suppressed).
    candidates_evaluated: int = 0
    #: How many candidate searches ran, and which stopped at their row cap.
    #: A truncated search leaves candidates that were never evaluated; recorded
    #: here so the report can say so instead of the worker log alone.
    candidate_enumeration: dict = field(default_factory=dict)
    host_risk_score: int = 0  # 0-100
    host_risk_level: str = "Info"  # Critical / High / Medium / Low / Info
    _ot_probed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def to_phase1_dict(self) -> dict:
        """Returns fields for Phase 1 (Host Discovery) with proper field mapping for frontend."""
        d = {
            "ip_address": self.ip_address,
            "is_active": self.is_active,
            "status": self.status,
            "scan_method": self.scan_method,
            "discovery_method": self.scan_method,  # Frontend alias
            "scan_timestamp": self.scan_timestamp,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "response_time_ms": self.response_time_ms,
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            "os_version": self.os_version,
            "os_evidence": self.os_evidence,
            "confidence": self.confidence,
            "device_category": self.device_category,
            "snmp_device_type": self.snmp_device_type,
            "mdns_name": self.mdns_name,
            "netbios_names": self.netbios_names,
            "os_fingerprint_full": self.os_fingerprint_full,
            "tcp_fingerprint": self.tcp_fingerprint,
            "port_states": self.port_states,
            "_ot_probed": self._ot_probed,
        }
        return d

    def to_basic_dict(self) -> dict:
        """Returns essential fields for Basic Network Scan (FAST profile) - excludes redundant and enrichment fields."""
        return {
            "ip_address": self.ip_address,
            "is_active": self.is_active,
            "scan_method": self.scan_method,
            "discovery_method": self.scan_method,
            "scan_timestamp": self.scan_timestamp,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "response_time_ms": self.response_time_ms,
            "confidence": self.confidence,
            "device_category": self.device_category,
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            # Carried even in the "basic" projection: these are two small scalars
            # and they are what stops a later phase from replacing a kernel the
            # host reported about itself with a fingerprint's guessed range.
            "os_version": self.os_version,
            "os_evidence": self.os_evidence,
            "_ot_probed": self._ot_probed,
        }

    def to_phase3_dict(self) -> dict:
        """Returns fields for Phase 3 (Vulnerability Scan) - excludes open_ports (shown in Phase 2)."""
        d = self.to_clean_dict()
        # Remove open_ports from Phase 3 to avoid redundancy with Phase 2 port scan results
        d.pop("open_ports", None)
        return d

    def to_clean_dict(self) -> dict:
        """Like to_dict() but drops fields that have no meaningful value."""
        d = asdict(self)

        # Fields that should be hidden when they carry no real info
        HIDE_IF_NA = {"N/A", "Unknown", ""}
        HIDE_IF_EMPTY = {None, False}

        # Keys that are always safe to drop when empty/falsy
        # NOTE: "vendor" is now ALWAYS included if it has any value
        OPTIONAL_KEYS = {
            "mac_address",
            "os_guess",
            "os_confidence",
            "response_time_ms",
            "tls_info",
            "http_audit",
            "snmp_info",
            "smb_info",
            "ssh_info",
            "udp_services",
            "cves",
            "suppressed_cves",
            "vulnerability_counts",
            "candidates_evaluated",
            "candidate_enumeration",
            "host_risk_score",
            "host_risk_level",
            "device_category",
            "snmp_device_type",
            "mdns_name",
            "netbios_names",
            "os_fingerprint_full",
            "tcp_fingerprint",
            "port_states",
        }

        cleaned = {}
        for key, value in d.items():
            # SPECIAL CASE: Always include vendor if it's not N/A or Unknown
            if key == "vendor":
                if value not in HIDE_IF_NA:
                    cleaned[key] = value
                continue

            if key in OPTIONAL_KEYS:
                # Handle unhashable types (dict, list) first
                if isinstance(value, (list, dict)):
                    if not value:
                        continue
                    # Drop dicts where ALL values are falsy
                    if isinstance(value, dict) and not any(value.values()):
                        continue
                else:
                    # Drop if N/A / Unknown / empty string
                    if value in HIDE_IF_NA:
                        continue
                    # Drop if None, False, 0
                    if value in HIDE_IF_EMPTY:
                        continue

            cleaned[key] = value

        # Add discovery_method as alias for scan_method (Phase 1 frontend compatibility)
        if "scan_method" in cleaned:
            cleaned["discovery_method"] = cleaned["scan_method"]

        # Clean open_ports — remove per-port fields that are empty
        if "open_ports" in cleaned:
            clean_ports = []
            for port in cleaned["open_ports"]:
                clean_port = {
                    k: v
                    for k, v in port.items()
                    if v not in (None, "", "unknown", "Unknown", [], {}, 0)
                    and not (k == "risk" and v == "Info")  # hide trivial risk
                    and not (k == "cves" and not v)  # hide empty CVE list
                }
                clean_ports.append(clean_port)
            cleaned["open_ports"] = clean_ports

        return cleaned


@dataclass
class DiscoverySummary:
    total_hosts: int
    active_hosts: int
    inactive_hosts: int
    scan_type: str
    scan_duration: float
    target: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    critical_hosts: int = 0
    high_risk_hosts: int = 0

    def to_dict(self) -> dict:
        return asdict(self)
