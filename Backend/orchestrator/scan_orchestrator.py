"""
orchestrator/scan_orchestrator.py  (REFACTORED — key methods only)
────────────────────────────────────────────────────────────────────────────
Changes from original:
  1. run_host_discovery_only() now resolves a DiscoveryProfile from pipeline_mode
     and passes it to core.discovery.engine.DiscoveryEngine
  2. run_asset_discovery_only() delegates to PortEngine which uses NmapScanner
  3. run_advanced_scan_only() passes open_port data to NmapScanner.full_scan()
     for OS fingerprinting before handing to VulnerabilityEngine

All other methods (scan_single_host, scan_ip_range, scan_subnet,
scan_subnets_of_subnet, generate_phase_report, _format_host, etc.)
are UNCHANGED from the original orchestrator.

The public API surface (method names + return format) is preserved.
"""

import asyncio
import ipaddress
import logging
import platform
import socket
import time
import uuid
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional

from core.models import DiscoveryScanType, ScanIntensity, HostResult, DiscoverySummary
from core.utils import InputValidator, PrivilegeManager, get_local_ips, get_local_mac
from core.risk import infer_os_from_host
from core.constants import PDF_AVAILABLE
from core.oui_lookup import lookup_vendor
from core.asset_correlation import AssetCorrelationEngine

# ── NEW imports for refactored architecture ───────────────────────────────────
from core.discovery.engine import DiscoveryEngine
from core.discovery.profiles import FAST, BALANCED, AGGRESSIVE, profile_for_pipeline

# ── Existing engine imports (unchanged) ───────────────────────────────────────
from engines.port.port_engine import PortEngine
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine

if PDF_AVAILABLE:
    from pdf_generator import ScanReportGenerator

log = logging.getLogger("ccure.orchestrator")


class ScanOrchestrator:
    """
    Single entry-point for all scan types.

    REFACTORED changes:
      - Phase 1 uses DiscoveryEngine with explicit DiscoveryProfile
      - Phase 2 uses PortEngine which internally routes to NmapScanner
      - Phase 3 unchanged (VulnerabilityEngine / plugin system)
    """

    def __init__(
        self,
        silent:       bool  = True,
        reports_dir:  str   = "reports",
        intensity:    str   = "normal",
        rate_limit:   float = 200.0,
        stealth_mode: bool  = False,
    ):
        self.silent       = silent
        self.rate_limit   = rate_limit
        self.stealth_mode = stealth_mode
        self.platform     = PrivilegeManager.get_platform()
        self.has_priv     = PrivilegeManager.is_admin()
        
        # ── NEW: Unified asset correlation engine for data consistency ────────
        self.asset_engine = AssetCorrelationEngine()

        try:
            self.intensity = ScanIntensity(intensity.lower())
        except ValueError:
            self.intensity = ScanIntensity.NORMAL

        self._pdf = (
            ScanReportGenerator(output_dir=reports_dir) if PDF_AVAILABLE else None
        )
        self._log(
            f"ScanOrchestrator ready — platform={self.platform}, "
            f"priv={self.has_priv}, intensity={self.intensity.value}"
        )

    # ── PHASE 1: Host Discovery ───────────────────────────────────────────────

    async def run_host_discovery_only(
        self,
        targets: List[str],
        scan_type: str = "adaptive",
        pipeline_mode: str = "basic",
    ) -> Dict:
        """
        Phase 1 — Host Discovery.

        REFACTORED:
          Previously called DiscoveryScanType enum to pick a scan type.
          Now maps pipeline_mode → DiscoveryProfile for explicit technique control.

          pipeline_mode → Profile mapping:
            "basic"    → FAST       (ARP + TCP connect only — no fallback chains)
            "asset"    → BALANCED   (ARP + ICMP + TCP SYN + UDP)
            "advanced" → AGGRESSIVE (all techniques + enrichment)

          scan_type is still accepted for backward compatibility with the
          traditional scan endpoints (/scan/host, /scan/subnet, etc.).
        """
        self._log(f"run_host_discovery_only → targets={targets}, mode={pipeline_mode}")

        # Map pipeline_mode to a discovery profile
        # scan_type="fast" (Light Mode) always forces FAST profile
        if scan_type == "fast":
            profile = FAST
        else:
            profile = profile_for_pipeline(pipeline_mode)

        # Expand all targets into a flat de-duplicated IP list
        all_ips = self._expand_targets(targets)
        if not all_ips:
            return self._err("No valid targets to scan.")

        t0 = time.time()

        # ── Run Phase 1 with profile-driven engine ────────────────────────
        discovery = DiscoveryEngine(
            profile=profile,
            has_privileges=self.has_priv,
            stealth_mode=self.stealth_mode,
        )
        disc_results: List[Dict] = await discovery.run(all_ips)
        duration = time.time() - t0

        # Format results (hostname, MAC, vendor enrichment)
        if pipeline_mode in ("basic", "asset"):
            formatted = [
                self._format_host(r.get("ip"), r).to_basic_dict()
                for r in disc_results
            ]
        else:
            formatted = [
                self._format_host(r.get("ip"), r).to_phase1_dict()
                for r in disc_results
            ]

        # ── Register in unified asset correlation engine (ONLY for Advanced Scan) ───────────────────
        if pipeline_mode == "advanced":
            self.asset_engine.register_discovery_results(
                formatted,
                discovery_method=scan_type,
                discovery_profile=profile.name,
            )

        active = sum(1 for h in formatted if h["is_active"])
        
        if pipeline_mode == "advanced":
            # Full summary for Advanced Scan (enrichment fields populated)
            summary = {
                "total_hosts":         len(formatted),
                "active_hosts":        active,
                "inactive_hosts":      len(formatted) - active,
                "scan_duration":       duration,
                "phase":               1,
                "scan_type":           scan_type.upper(),
                "discovery_scan_method": scan_type.upper(),
                "discovery_profile":   profile.name,
            }
            metadata = {
                "target":                 ", ".join(targets),
                "original_targets":       targets,
                "scan_method":            scan_type.upper(),
                "discovery_scan_method":  scan_type.upper(),
                "discovery_profile":      profile.name,
            }
        else:
            # Simplified summary for Basic/Asset scans (enrichment fields empty)
            summary = {
                "total_hosts":    len(formatted),
                "active_hosts":   active,
                "inactive_hosts": len(formatted) - active,
                "scan_duration":  duration,
                "phase":          1,
                "scan_type":      scan_type.upper(),
                "discovery_profile": profile.name,
            }
            metadata = {
                "target":           ", ".join(targets),
                "original_targets": targets,
                "scan_type":        scan_type.upper(),
                "discovery_profile": profile.name,
            }

        return {
            "success":  True,
            "data":     formatted,
            "summary":  summary,
            "metadata": metadata,
        }

    async def run_asset_discovery_only(
        self,
        hosts: List[Dict],
        intensity: str = "normal",
        pipeline_mode: str = "asset",
    ) -> Dict:
        """
        Phase 2 — Port Scanning.

        REFACTORED:
          PortEngine now routes to NmapScanner when nmap is available,
          falling back to async TCP connect when not.
          The return format is IDENTICAL to the original.
        """
        self._log(f"run_asset_discovery_only → {len(hosts)} hosts, intensity={intensity}")

        try:
            intensity_enum = ScanIntensity(intensity.lower())
        except ValueError:
            intensity_enum = ScanIntensity.NORMAL

        hosts = [self._normalize_host_record(h) for h in hosts]
        discovery_scan_method = self._infer_discovery_method(hosts)
        target_str = self._hosts_target_string(hosts)

        active_hosts = [h for h in hosts if h.get("is_active", False)]
        active_count = len(active_hosts)
        inactive_count = len(hosts) - active_count

        if not active_hosts:
            return self._make_empty_phase2(
                hosts, active_count, inactive_count,
                intensity_enum, discovery_scan_method, target_str,
            )

        t0 = time.time()

        # ── SAVE vendor/mac data BEFORE PortEngine modifies hosts ──────────────
        vendor_backup = {}
        for host in active_hosts:
            ip = self._get_host_ip(host)
            if ip:
                vendor_backup[ip] = {
                    "vendor": host.get("vendor", "N/A"),
                    "mac_address": host.get("mac_address", "N/A"),
                }

        # ── PortEngine now uses NmapScanner internally ────────────────────
        port_engine = PortEngine(intensity=intensity_enum)
        await port_engine.run(active_hosts)   # mutates in-place
        self._apply_os_inference(active_hosts)
        
        # ── RESTORE vendor/mac data from backup ────────────────────────────────
        # This ensures vendor is NEVER lost, regardless of PortEngine behavior
        for host in active_hosts:
            ip = self._get_host_ip(host)
            if ip and ip in vendor_backup:
                backup = vendor_backup[ip]
                # Always restore vendor/mac if they were present in Phase 1
                if backup["vendor"] != "N/A":
                    host["vendor"] = backup["vendor"]
                if backup["mac_address"] != "N/A":
                    host["mac_address"] = backup["mac_address"]
                    host["mac"] = backup["mac_address"]
        
        # ── Also try to get vendor from asset registry (ONLY for Advanced Scan) ────
        # ONLY for Advanced Scan pipeline (phases 1+2+3)
        if pipeline_mode == "advanced":
            self._preserve_vendor_from_registry(active_hosts)
            self.asset_engine.enrich_port_scan_results(active_hosts)

        duration = time.time() - t0

        formatted = [
            self._format_host(self._get_host_ip(h), h).to_clean_dict()
            for h in hosts
        ]
        hosts_with_ports = sum(1 for h in formatted if h.get("open_ports"))

        summary = {
            "total_hosts":            len(formatted),
            "active_hosts":           active_count,
            "inactive_hosts":         inactive_count,
            "hosts_with_ports":       hosts_with_ports,
            "scan_duration":          duration,
            "phase":                  2,
            "scan_type":              intensity_enum.value.upper(),
            "discovery_scan_method":  discovery_scan_method or "N/A",
        }
        return {
            "success":  True,
            "data":     formatted,
            "summary":  summary,
            "metadata": self._phase2_meta(
                target_str, intensity_enum, discovery_scan_method
            ),
        }

    # ── PHASE 3: Advanced Scan / Vulnerability + Risk ─────────────────────────

    def run_advanced_scan_only(self, hosts: List[Dict]) -> Dict:
        """
        Phase 3+4 — Vulnerability Scanning + Risk Scoring.

        REFACTORED:
          Before calling VulnerabilityEngine, optionally run NmapScanner.full_scan()
          on each host to upgrade OS detection and service versions.
          This gives plugins (tls_scanner, ssh_probe, etc.) exact version strings
          which dramatically improves CVE matching accuracy.

          The VulnerabilityEngine itself is UNCHANGED.
        """
        self._log(f"run_advanced_scan_only → {len(hosts)} hosts")

        hosts = [self._normalize_host_record(h) for h in hosts]
        discovery_scan_method = self._infer_discovery_method(hosts)
        target_str = self._hosts_target_string(hosts)

        active_hosts = [h for h in hosts if h.get("is_active", False)]
        active_count = len(active_hosts)
        inactive_count = len(hosts) - active_count

        if not active_hosts:
            return self._make_empty_phase3(
                hosts, active_count, inactive_count,
                discovery_scan_method, target_str,
            )

        t0 = time.time()

        # ── Optional: Nmap OS fingerprint upgrade before vuln plugins ─────
        # This runs nmap -sV -O on the known open ports for each host.
        # If nmap is unavailable, this is a no-op (VulnEngine runs as-before).
        self._nmap_pre_enrich(active_hosts)

        # ── VulnerabilityEngine (UNCHANGED) ───────────────────────────────
        vuln_engine = VulnerabilityEngine(rate_limit=self.rate_limit)
        vuln_engine.run(active_hosts)
        self._apply_os_inference(active_hosts)
        
        # ── Enrich asset registry with vulnerability findings ───────────────
        self.asset_engine.enrich_vulnerability_findings(active_hosts)

        duration = time.time() - t0

        formatted = [
            self._format_host(self._get_host_ip(h), h).to_clean_dict()
            for h in hosts
        ]
        critical = sum(1 for h in formatted if h.get("host_risk_level") == "Critical")
        high     = sum(1 for h in formatted if h.get("host_risk_level") == "High")

        summary = {
            "total_hosts":           len(formatted),
            "active_hosts":          active_count,
            "inactive_hosts":        inactive_count,
            "critical_hosts":        critical,
            "high_risk_hosts":       high,
            "scan_duration":         duration,
            "phase":                 3,
            "scan_type":             "advanced",
            "discovery_scan_method": discovery_scan_method or "N/A",
        }
        return {
            "success":  True,
            "data":     formatted,
            "summary":  summary,
            "metadata": {
                **({} if not target_str else {"target": target_str}),
                "scan_type":             "advanced",
                **({} if not discovery_scan_method else {"discovery_scan_method": discovery_scan_method}),
            },
        }

    # ── Nmap pre-enrichment for Phase 3 ──────────────────────────────────────

    @staticmethod
    def _nmap_pre_enrich(hosts: List[Dict]) -> None:
        """
        Run Nmap OS detection + service version upgrade on each active host.
        Uses known open ports from Phase 2 to limit scan scope.

        This is a best-effort step — if Nmap fails or is unavailable,
        the host data from Phase 2 is used as-is.
        """
        from core.nmap.wrapper import NmapScanner, NMAP_AVAILABLE
        if not NMAP_AVAILABLE:
            return

        # On Windows, sudo doesn't work — disable it. On Linux/Mac, enable it for SYN scan.
        use_sudo = platform.system() != "Windows"
        scanner = NmapScanner(sudo=use_sudo)
        for host in hosts:
            ip = host.get("ip_address") or host.get("ip")
            if not ip:
                continue
            open_port_nums = [p["port"] for p in host.get("open_ports", [])]
            if not open_port_nums:
                continue
            try:
                result = scanner.full_scan(ip, ports=open_port_nums)
                # Upgrade service versions with Nmap's more accurate data
                for nmap_port in result.open_ports:
                    for existing in host.get("open_ports", []):
                        if existing["port"] == nmap_port.port:
                            if nmap_port.full_version:
                                existing["version"] = nmap_port.full_version[:200]
                            if nmap_port.product and not existing.get("service"):
                                existing["service"] = nmap_port.product
                            # Copy NSE script output into banner if empty
                            if nmap_port.scripts and not existing.get("banner"):
                                existing["banner"] = nmap_port.scripts.get("banner", "")
                # Upgrade OS if Nmap got a better match
                best_os = result.best_os
                if best_os and best_os.accuracy >= 75:
                    host["os_guess"]      = best_os.name
                    host["os_confidence"] = "High" if best_os.accuracy >= 90 else "Medium"
            except Exception as exc:
                log.debug("_nmap_pre_enrich(%s) error: %s", ip, exc)

    # ── Preserve vendor from unified asset registry ─────────────────────────

    def _preserve_vendor_from_registry(self, hosts: List[Dict]) -> None:
        """
        Retrieve vendor information from the asset registry (Phase 1 data)
        and apply it to Phase 2 results.
        
        This ensures vendor data is NOT lost when PortEngine overwrites the host dict.
        """
        for host in hosts:
            ip = host.get("ip_address") or host.get("ip")
            if not ip:
                continue
            
            # Get unified asset from registry
            asset = self.asset_engine.get_asset(ip)
            if not asset:
                continue
            
            # Restore vendor info from Phase 1
            if asset.vendor and asset.vendor.name != "Unknown":
                host["vendor"] = asset.vendor.name
                host["mac_address"] = asset.vendor.mac_address
                host["mac"] = asset.vendor.mac_address

    # ── Target expansion ──────────────────────────────────────────────────────

    @staticmethod
    def _expand_targets(targets: List[str]) -> List[str]:
        """Expand a list of IPs/ranges/subnets into a flat de-duplicated IP list."""
        all_ips = []
        for target in targets:
            res = InputValidator.resolve_target(target)
            if "error" in res:
                continue
            resolved = res["resolved"]
            if "/" in resolved:
                network = ipaddress.ip_network(resolved, strict=False)
                all_ips.extend(str(ip) for ip in network.hosts())
            elif "-" in resolved:
                all_ips.extend(InputValidator.expand_ip_range(resolved))
            else:
                all_ips.append(resolved)
        return list(dict.fromkeys(all_ips))  # deduplicate, preserve order

    # ── Helpers (unchanged from original) ────────────────────────────────────

    def _format_host(self, ip: str, data: Dict, input_hostname: str = None) -> HostResult:
        """Unchanged from original orchestrator."""
        ip = ip or self._get_host_ip(data)
        is_active = data.get("is_active", False)
        hostname = "Unknown"
        if is_active and ip:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = input_hostname or "Unknown"
        else:
            hostname = input_hostname or "Unknown"

        mac = data.get("mac")
        if not mac or mac == "N/A":
            mac = data.get("mac_address", "N/A")
        if ip and ip in get_local_ips():
            if hostname == "Unknown":
                hostname = socket.gethostname()
            if mac == "N/A":
                mac = get_local_mac()

        vendor = "N/A"
        if mac and mac != "N/A":
            vendor = lookup_vendor(mac) or "N/A"

        confs = data.get("confirmations", [])
        confidence = (
            "High"   if len(confs) >= 2 or "ARP" in confs else
            "Medium" if len(confs) == 1 else "Low"
        )
        if not is_active:
            confidence = "N/A"

        return HostResult(
            ip_address       = ip or "",
            hostname         = hostname,
            mac_address      = mac,
            vendor           = vendor,
            is_active        = is_active,
            status           = "Active" if is_active else "Inactive",
            scan_method      = data.get("method") or data.get("scan_method") or "N/A",
            response_time_ms = data.get("elapsed_ms") or data.get("response_time_ms"),
            open_ports       = data.get("open_ports", []),
            os_guess         = data.get("os_guess", "Unknown"),
            os_confidence    = data.get("os_confidence", "Low"),
            confidence       = confidence,
            device_category  = data.get("device_category", "unknown"),
            snmp_device_type = data.get("snmp_device_type"),
            mdns_name        = data.get("mdns_name"),
            netbios_names    = data.get("netbios_names", []),
            os_fingerprint_full = data.get("os_fingerprint_full", {}),
            tcp_fingerprint  = data.get("tcp_fingerprint", {}),
            port_states      = data.get("port_states", {}),
            tls_info         = data.get("tls_info", {}),
            http_audit       = data.get("http_audit", {}),
            snmp_info        = data.get("snmp_info", {}),
            smb_info         = data.get("smb_info", {}),
            ssh_info         = data.get("ssh_info", {}),
            udp_services     = data.get("udp_services", []),
            cves             = data.get("cves", []),
            host_risk_score  = data.get("host_risk_score", 0),
            host_risk_level  = data.get("host_risk_level", "Info"),
        )

    @staticmethod
    def _get_host_ip(host: Dict) -> Optional[str]:
        return host.get("ip_address") or host.get("ip")

    def _normalize_host_record(self, host: Dict) -> Dict:
        norm = dict(host)
        ip = self._get_host_ip(norm)
        if ip:
            norm["ip"] = ip
            norm["ip_address"] = ip
        if "mac" not in norm and "mac_address" in norm:
            norm["mac"] = norm["mac_address"]
        if "mac_address" not in norm and "mac" in norm:
            norm["mac_address"] = norm["mac"]
        if "method" not in norm:
            norm["method"] = (
                norm.get("scan_method") or norm.get("discovery_method") or "N/A"
            )
        return norm

    @staticmethod
    def _normalize_scan_method(value) -> Optional[str]:
        if not value:
            return None
        token = str(value).strip().upper()
        if not token or token in {"N/A", "UNKNOWN", "NONE"}:
            return None
        for key, label in [
            ("ADAPTIVE", "ADAPTIVE"), ("STEALTH", "STEALTH"),
            ("FULL", "FULL"), ("ARP", "ARP"),
            ("PING", "PING"), ("ICMP", "PING"), ("TCP", "TCP"),
        ]:
            if key in token:
                return label
        return None

    def _infer_discovery_method(self, hosts: List[Dict]) -> Optional[str]:
        methods = []
        for host in hosts:
            raw = host.get("method") or host.get("scan_method") or host.get("discovery_method")
            m = self._normalize_scan_method(raw)
            if m:
                methods.append(m)
        if not methods:
            return None
        return Counter(methods).most_common(1)[0][0]

    def _hosts_target_string(self, hosts: List[Dict]) -> Optional[str]:
        ips = []
        for h in hosts:
            ip = self._get_host_ip(h)
            if ip and ip not in ips:
                ips.append(ip)
        return ", ".join(ips) if ips else None

    @staticmethod
    def _apply_os_inference(hosts: List[Dict]) -> None:
        from core.risk import infer_os_from_host
        from core.device_classifier import classify_device
        for host in hosts:
            guess, conf = infer_os_from_host(host)
            if host.get("os_guess", "Unknown") == "Unknown":
                host["os_guess"]      = guess
                host["os_confidence"] = conf
            classify_device(host)

    def _log(self, msg: str) -> None:
        if not self.silent:
            log.info(msg)

    def generate_phase_report(self, resp: Dict, scan_type: str) -> Dict[str, str]:
        if not self._pdf:
            return {}
        try:
            return self._pdf.generate(resp, scan_type)
        except Exception as exc:
            self._log(f"[WARN] PDF generation failed: {exc}")
            return {}

    # ── Empty result builders ─────────────────────────────────────────────────

    def _make_empty_phase2(self, hosts, active, inactive, intensity, dsm, target):
        formatted = [self._format_host(self._get_host_ip(h), h).to_clean_dict() for h in hosts]
        return {
            "success": True, "data": formatted,
            "summary": {
                "total_hosts": len(formatted), "active_hosts": active,
                "inactive_hosts": inactive, "hosts_with_ports": 0,
                "scan_duration": 0, "phase": 2,
                "scan_type": intensity.value.upper(),
                "discovery_scan_method": dsm or "N/A",
            },
            "metadata": self._phase2_meta(target, intensity, dsm),
        }

    def _make_empty_phase3(self, hosts, active, inactive, dsm, target):
        formatted = [self._format_host(self._get_host_ip(h), h).to_clean_dict() for h in hosts]
        return {
            "success": True, "data": formatted,
            "summary": {
                "total_hosts": len(formatted), "active_hosts": active,
                "inactive_hosts": inactive, "critical_hosts": 0,
                "high_risk_hosts": 0, "scan_duration": 0,
                "phase": 3, "scan_type": "advanced",
                "discovery_scan_method": dsm or "N/A",
            },
            "metadata": {
                **({} if not target else {"target": target}),
                "scan_type": "advanced",
            },
        }

    @staticmethod
    def _phase2_meta(target, intensity, dsm) -> Dict:
        d = {"scan_intensity": intensity.value.upper()}
        if target:
            d["target"] = target
        if dsm:
            d["discovery_scan_method"] = dsm
            d["scan_method"] = dsm
        return d
