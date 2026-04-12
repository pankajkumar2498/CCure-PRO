"""
core/models.py
--------------
Shared enums and dataclasses.
No logic here - just typed containers.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict


# =============================================================================
# Enums
# =============================================================================

class DiscoveryScanType(Enum):
    PING     = "ping"
    ARP      = "arp"
    TCP      = "tcp"
    FULL     = "full"
    ADAPTIVE = "adaptive"
    STEALTH  = "stealth"   # fragmented / low-TTL evasion


class ScanIntensity(Enum):
    LIGHT  = "light"    # quick ports only
    NORMAL = "normal"   # standard ports
    DEEP   = "deep"     # all ports + deep banner grab


# =============================================================================
# Result Dataclasses
# =============================================================================

@dataclass
class PortResult:
    port:    int
    service: str  = "unknown"
    state:   str  = "open"
    banner:  str  = ""
    version: str  = ""
    risk:    str  = "Info"
    cves:    list = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TLSInfo:
    enabled:          bool  = False
    version:          str   = ""
    cipher:           str   = ""
    cert_subject:     str   = ""
    cert_issuer:      str   = ""
    cert_expiry:      str   = ""
    cert_expired:     bool  = False
    cert_self_signed: bool  = False
    san_domains:      list  = field(default_factory=list)
    weak_cipher:      bool  = False
    score:            str   = "N/A"   # A / B / C / F

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class HTTPAudit:
    status_code:    int   = 0
    server_header:  str   = ""
    hsts:           bool  = False
    x_frame:        str   = ""
    csp:            bool  = False
    x_content_type: bool  = False
    x_xss:          bool  = False
    redirect_http:  bool  = False   # HTTP -> HTTPS redirect?
    issues:         list  = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class HostResult:
    ip_address:       str
    hostname:         str            = "Unknown"
    mac_address:      str            = "N/A"
    vendor:           str            = "N/A"
    is_active:        bool           = False
    status:           str            = "Inactive"
    scan_method:      str            = "N/A"
    response_time_ms: Optional[float] = None
    open_ports:       list           = field(default_factory=list)
    os_guess:         str            = "Unknown"
    os_confidence:    str            = "Low"
    confidence:       str            = "Low"
    scan_timestamp:   str            = field(default_factory=lambda: datetime.now().isoformat())
    # v2 enrichment
    tls_info:         dict           = field(default_factory=dict)
    http_audit:       dict           = field(default_factory=dict)
    snmp_info:        dict           = field(default_factory=dict)
    smb_info:         dict           = field(default_factory=dict)
    ssh_info:         dict           = field(default_factory=dict)
    udp_services:     list           = field(default_factory=list)
    cves:             list           = field(default_factory=list)
    host_risk_score:  int            = 0        # 0-100
    host_risk_level:  str            = "Info"   # Critical / High / Medium / Low / Info

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_phase1_dict(self) -> Dict:
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
            "confidence": self.confidence,
        }
        return d

    def to_clean_dict(self) -> Dict:
        """Like to_dict() but drops fields that have no meaningful value."""
        d = asdict(self)

        # Fields that should be hidden when they carry no real info
        HIDE_IF_NA      = {"N/A", "Unknown", ""}
        HIDE_IF_EMPTY   = {None, False, 0}

        # Keys that are always safe to drop when empty/falsy
        OPTIONAL_KEYS = {
            "vendor", "mac_address", "os_guess", "os_confidence",
            "response_time_ms", "tls_info", "http_audit", "snmp_info",
            "smb_info", "ssh_info", "udp_services", "cves",
            "host_risk_score", "host_risk_level",
        }

        cleaned = {}
        for key, value in d.items():
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
                    k: v for k, v in port.items()
                    if v not in (None, "", "unknown", "Unknown", [], {}, 0)
                    and not (k == "risk" and v == "Info")    # hide trivial risk
                    and not (k == "cves" and not v)          # hide empty CVE list
                }
                clean_ports.append(clean_port)
            cleaned["open_ports"] = clean_ports

        return cleaned


@dataclass
class DiscoverySummary:
    total_hosts:     int
    active_hosts:    int
    inactive_hosts:  int
    scan_type:       str
    scan_duration:   float
    target:          str
    timestamp:       str = field(default_factory=lambda: datetime.now().isoformat())
    critical_hosts:  int = 0
    high_risk_hosts: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)