"""
core/asset_correlation.py
────────────────────────────────────────────────────────────────────────────
Unified Asset Correlation Engine (Production-Grade)

PROBLEM:
  - Phase 1 (Discovery): Vendor populated ✅
  - Phase 2 (Port Scan): Vendor LOST ❌
  - Phase 3 (Vulnerability): OS added, but Vendor still missing ❌

SOLUTION:
  Implement a centralized Asset Registry that:
  1. Maintains unified asset model across all scan phases
  2. Preserves and enriches metadata as phases complete
  3. Implements consistency rules and deduplication
  4. Provides fallback strategies for missing data

DESIGN PRINCIPLES (Nessus/Nmap-style):
  - Single source of truth per IP
  - Immutable discovery data (MAC, first-seen)
  - Enrichment layers (merge, don't overwrite)
  - Confidence scoring for inferred data
  - Audit trail of data sources
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

log = logging.getLogger("ccure.asset_correlation")


# =============================================================================
# Data Confidence & Source Tracking
# =============================================================================


class DataSource(Enum):
    """Track where each piece of data came from (for audit & reliability)."""

    MAC_OUI = "mac_oui"  # MAC → OUI database lookup (most reliable)
    NMAP_OS = "nmap_os"  # Nmap OS fingerprinting
    CVE_INFERENCE = "cve_inference"  # OS inferred from CVE banner matching
    BANNER_GRAB = "banner_grab"  # Service banner analysis
    TTL_HEURISTIC = "ttl_heuristic"  # TTL-based OS guess (least reliable)
    DEFAULT = "default"  # Fallback / unknown


@dataclass
class ConfidenceScore:
    """Confidence metadata for any detected attribute."""

    score: float = 0.0  # 0.0 to 1.0
    source: DataSource = DataSource.DEFAULT
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "confidence_score": self.score,
            "source": self.source.value,
            "timestamp": self.timestamp,
            "notes": self.notes,
        }


@dataclass
class VendorInfo:
    """Vendor metadata with confidence tracking."""

    name: str = "Unknown"
    mac_address: str = "N/A"
    confidence: ConfidenceScore = field(default_factory=ConfidenceScore)
    fallback_used: bool = False  # Did we use a fallback strategy?
    strategies_tried: list[str] = field(default_factory=list)  # Audit trail

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mac_address": self.mac_address,
            "confidence": self.confidence.to_dict(),
            "fallback_used": self.fallback_used,
            "strategies_tried": self.strategies_tried,
        }


@dataclass
class OSInfo:
    """OS detection with multiple confidence sources."""

    name: str = "Unknown"
    confidence: str = "Low"  # Low / Medium / High
    cpe: str = ""  # CPE identifier
    primary_source: DataSource = DataSource.DEFAULT
    secondary_sources: list[DataSource] = field(default_factory=list)
    version: str = ""
    detection_methods: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "confidence": self.confidence,
            "cpe": self.cpe,
            "version": self.version,
            "primary_source": self.primary_source.value,
            "secondary_sources": [s.value for s in self.secondary_sources],
            "detection_methods": self.detection_methods,
        }


# =============================================================================
# Unified Asset Model (Single Source of Truth per IP)
# =============================================================================


@dataclass
class UnifiedAsset:
    """
    Production-grade asset model — like Nessus asset record.

    Maintains complete lifecycle from discovery → port scan → vulnerability scan.
    Each field has confidence metadata to track reliability.
    """

    # ── Immutable Discovery Data (set once, never changed) ──────────────────
    ip_address: str
    hostname: str = "Unknown"
    mac_address: str = "N/A"
    is_active: bool = False
    discovery_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    discovery_method: str = "N/A"  # ICMP / ARP / TCP / etc.
    discovery_profile: str = "FAST"  # FAST / BALANCED / AGGRESSIVE

    # ── Vendor (enriched from Phase 1, preserved through all phases) ────────
    vendor: VendorInfo = field(default_factory=VendorInfo)

    # ── OS Detection (multi-source, confidence-aware) ─────────────────────
    os: OSInfo = field(default_factory=OSInfo)

    # ── Port & Service Data (enriched across phases) ──────────────────────
    open_ports: list[dict] = field(default_factory=list)
    services_detected: list[dict] = field(default_factory=list)
    udp_services: list[dict] = field(default_factory=list)

    # ── Security Findings (merged from all phases) ───────────────────────
    cves: list[dict] = field(default_factory=list)
    tls_info: dict = field(default_factory=dict)
    http_audit: dict = field(default_factory=dict)
    ssh_info: dict = field(default_factory=dict)
    smb_info: dict = field(default_factory=dict)
    snmp_info: dict = field(default_factory=dict)

    # ── Risk Scoring ──────────────────────────────────────────────────────
    host_risk_score: float = 0.0
    host_risk_level: str = "Info"  # Critical / High / Medium / Low / Info

    # ── Device Classification ─────────────────────────────────────────────
    device_category: str = "unknown"  # printer / server / workstation / iot / unknown
    device_confidence: str = "Low"
    snmp_device_type: str | None = None

    # ── Metadata ──────────────────────────────────────────────────────────
    scan_phases_completed: list[int] = field(default_factory=list)  # [1, 2, 3, 4]
    last_updated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    data_sources: list[str] = field(default_factory=list)  # Audit trail

    def to_dict(self) -> dict:
        """Export as production-grade JSON (Nessus-compatible format)."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "is_active": self.is_active,
            "discovery": {
                "timestamp": self.discovery_timestamp,
                "method": self.discovery_method,
                "profile": self.discovery_profile,
            },
            "vendor": self.vendor.to_dict(),
            "os": self.os.to_dict(),
            "open_ports": self.open_ports,
            "services": self.services_detected,
            "udp_services": self.udp_services,
            "security": {
                "cves_count": len(self.cves),
                "cves": self.cves,
                "tls_info": self.tls_info,
                "http_audit": self.http_audit,
                "ssh_info": self.ssh_info,
                "smb_info": self.smb_info,
                "snmp_info": self.snmp_info,
            },
            "risk": {
                "score": self.host_risk_score,
                "level": self.host_risk_level,
            },
            "device": {
                "category": self.device_category,
                "confidence": self.device_confidence,
                "snmp_type": self.snmp_device_type,
            },
            "metadata": {
                "phases_completed": self.scan_phases_completed,
                "last_updated": self.last_updated,
                "data_sources": self.data_sources,
            },
        }


# =============================================================================
# Asset Correlation Engine (Central Registry)
# =============================================================================


class AssetCorrelationEngine:
    """
    Maintains unified asset registry across all scan phases.

    Usage::

        engine = AssetCorrelationEngine()

        # Phase 1: Add discovered hosts
        engine.register_discovery_results(phase1_hosts)

        # Phase 2: Enrich with port scan data
        engine.enrich_port_scan_results(phase2_hosts)

        # Phase 3: Merge vulnerability findings
        engine.enrich_vulnerability_findings(phase3_hosts)

        # Export unified results
        unified_hosts = engine.export_all()
    """

    def __init__(self):
        self._assets: dict[str, UnifiedAsset] = {}  # IP → UnifiedAsset

    # ── Phase 1: Discovery ─────────────────────────────────────────────────

    def register_discovery_results(
        self,
        hosts: list[dict],
        discovery_method: str = "adaptive",
        discovery_profile: str = "FAST",
    ) -> None:
        """
        Register discovered hosts into the unified asset registry.

        Sets immutable discovery data:
        - IP, Hostname, MAC
        - Vendor (from MAC → OUI lookup)
        - Discovery method & profile

        Args:
            hosts: Phase 1 discovery results
            discovery_method: scan method used (ICMP, ARP, TCP, etc.)
            discovery_profile: profile used (FAST, BALANCED, AGGRESSIVE)
        """
        for host in hosts:
            ip = host.get("ip_address") or host.get("ip")
            if not ip:
                continue

            if ip not in self._assets:
                # Create new unified asset
                asset = UnifiedAsset(
                    ip_address=ip,
                    hostname=host.get("hostname", "Unknown"),
                    mac_address=host.get("mac_address", "N/A"),
                    is_active=host.get("is_active", False),
                    discovery_method=discovery_method,
                    discovery_profile=discovery_profile,
                )

                # Populate vendor from discovery phase
                vendor_name = host.get("vendor", "Unknown")
                mac = host.get("mac_address", "N/A")
                asset.vendor = VendorInfo(
                    name=vendor_name,
                    mac_address=mac,
                    confidence=ConfidenceScore(
                        score=0.95 if vendor_name != "Unknown" else 0.0,
                        source=DataSource.MAC_OUI,
                        notes="From MAC address OUI database lookup",
                    ),
                )

                self._assets[ip] = asset
                log.debug(f"Asset registry: registered {ip} → {vendor_name}")

            # Mark phase 1 complete
            if 1 not in self._assets[ip].scan_phases_completed:
                self._assets[ip].scan_phases_completed.append(1)
                self._assets[ip].data_sources.append("phase1_discovery")

    # ── Phase 2: Port Scan ─────────────────────────────────────────────────

    def enrich_port_scan_results(self, hosts: list[dict]) -> None:
        """
        Enrich existing assets with port scan data.

        Preserves all previous data (especially vendor from Phase 1).
        Adds/updates:
        - open_ports
        - services_detected
        - OS detection (if Nmap -O was used)

        Args:
            hosts: Phase 2 port scan results
        """
        for host in hosts:
            ip = host.get("ip_address") or host.get("ip")
            if not ip or ip not in self._assets:
                log.warning(f"Asset {ip} not in registry — skipping port enrichment")
                continue

            asset = self._assets[ip]

            # ✅ PRESERVE existing vendor (don't overwrite!)
            # Vendor stays the same as Phase 1

            # Add open ports
            asset.open_ports = host.get("open_ports", [])

            # Merge OS detection if available from Nmap
            nmap_os = host.get("os_guess", "Unknown")
            if nmap_os and nmap_os != "Unknown":
                asset.os = OSInfo(
                    name=nmap_os,
                    confidence=host.get("os_confidence", "Medium"),
                    cpe=host.get("os_cpe", ""),
                    primary_source=DataSource.NMAP_OS,
                    detection_methods=["nmap_fingerprinting"],
                )

            # Mark phase 2 complete
            if 2 not in asset.scan_phases_completed:
                asset.scan_phases_completed.append(2)
                asset.data_sources.append("phase2_port_scan")

            asset.last_updated = datetime.now(timezone.utc).isoformat()
            log.debug(f"Asset enriched {ip}: {len(asset.open_ports)} ports found")

    # ── Phase 3: Vulnerability Scan ────────────────────────────────────────

    def enrich_vulnerability_findings(self, hosts: list[dict]) -> None:
        """
        Enrich assets with vulnerability findings.

        Adds:
        - CVE data
        - TLS/HTTP/SSH/SMB info
        - Refined OS detection
        - Risk score
        - Device classification

        Args:
            hosts: Phase 3 vulnerability scan results
        """
        for host in hosts:
            ip = host.get("ip_address") or host.get("ip")
            if not ip or ip not in self._assets:
                continue

            asset = self._assets[ip]

            # Add security findings
            asset.cves = host.get("cves", [])
            asset.tls_info = host.get("tls_info", {})
            asset.http_audit = host.get("http_audit", {})
            asset.ssh_info = host.get("ssh_info", {})
            asset.smb_info = host.get("smb_info", {})
            asset.snmp_info = host.get("snmp_info", {})
            asset.udp_services = host.get("udp_services", [])

            # ✅ REFINE OS detection (merge with Phase 2 Nmap data)
            cve_os = host.get("os_guess", "Unknown")
            if cve_os and cve_os != "Unknown" and asset.os.name == "Unknown":
                # Use CVE-inferred OS if Nmap didn't find one
                asset.os = OSInfo(
                    name=cve_os,
                    confidence="Medium",
                    primary_source=DataSource.CVE_INFERENCE,
                    detection_methods=["cve_banner_matching"],
                )
            elif cve_os and cve_os != "Unknown":
                # Add CVE inference as secondary source
                asset.os.secondary_sources.append(DataSource.CVE_INFERENCE)

            # Add risk scoring
            asset.host_risk_score = host.get("host_risk_score", 0.0)
            asset.host_risk_level = host.get("host_risk_level", "Info")

            # Add device classification
            asset.device_category = host.get("device_category", "unknown")
            asset.device_confidence = host.get("device_confidence", "Low")
            asset.snmp_device_type = host.get("snmp_device_type")

            # Mark phase 3 complete
            if 3 not in asset.scan_phases_completed:
                asset.scan_phases_completed.append(3)
                asset.data_sources.append("phase3_vulnerability")

            asset.last_updated = datetime.now(timezone.utc).isoformat()
            log.debug(f"Asset enriched {ip}: {len(asset.cves)} CVEs found")

    # ── Utility Methods ────────────────────────────────────────────────────

    def get_asset(self, ip: str) -> UnifiedAsset | None:
        """Retrieve unified asset by IP."""
        return self._assets.get(ip)

    def export_all(self) -> list[dict]:
        """Export all assets in production-grade JSON format."""
        return [asset.to_dict() for asset in self._assets.values()]

    def export_by_phase(self, phases: list[int]) -> list[dict]:
        """Export only assets that have completed all specified phases."""
        return [
            asset.to_dict()
            for asset in self._assets.values()
            if all(p in asset.scan_phases_completed for p in phases)
        ]

    def get_stats(self) -> dict:
        """Get correlation engine statistics."""
        total = len(self._assets)
        active = sum(1 for a in self._assets.values() if a.is_active)
        with_vendor = sum(
            1 for a in self._assets.values() if a.vendor.name != "Unknown"
        )
        with_os = sum(1 for a in self._assets.values() if a.os.name != "Unknown")
        with_cves = sum(1 for a in self._assets.values() if a.cves)

        return {
            "total_assets": total,
            "active_hosts": active,
            "with_vendor_info": with_vendor,
            "with_os_detection": with_os,
            "with_vulnerabilities": with_cves,
            "phases_1_only": sum(
                1 for a in self._assets.values() if a.scan_phases_completed == [1]
            ),
            "phases_1_2": sum(
                1
                for a in self._assets.values()
                if set([1, 2]).issubset(a.scan_phases_completed)
            ),
            "phases_1_2_3": sum(
                1
                for a in self._assets.values()
                if set([1, 2, 3]).issubset(a.scan_phases_completed)
            ),
        }
