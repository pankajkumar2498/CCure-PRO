"""
orchestrator/scan_orchestrator.py
-------------------------------------------
ScanOrchestrator - controls the full 4-phase pipeline with phase-selective support.

NEW: Phase-selective methods for frontend-driven orchestration (Option 1).

Pipeline
--------
Phase 1  DiscoveryEngine  ->  list of host dicts (is_active, mac, os_guess ...)
Phase 2  PortEngine       ->  enriches active hosts with open_ports + banners
Phase 3  VulnEngine       ->  enriches active hosts with plugin findings
Phase 4  (inside VulnEngine) ->  risk scores each host

Supported scan modes (via scan_mode param)
------------------------------------------
  'discovery'  -> Phase 1 only
  'port'       -> Phase 1 + 2
  'full'       -> Phase 1 + 2 + 3 + 4  (default)

NEW PHASE-SELECTIVE METHODS (Frontend-driven):
----------------------------------------------
  run_host_discovery_only()  -> Discovery on IPs
  run_asset_discovery_only()  -> Port scan on already-discovered hosts
  run_advanced_scan_only()  -> Vulnerability + risk on hosts with ports
  run_phases()       -> Flexible: "1", "1+2", "1+2+3+4"
"""

import ipaddress
import logging
import socket
import time
import uuid
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional

from core.models import (
    DiscoveryScanType, ScanIntensity,
    HostResult, DiscoverySummary,
)
from core.utils import (
    InputValidator, PrivilegeManager,
    get_local_ips, get_local_mac, get_mac_from_arp_cache,
)
from core.risk import infer_os_from_host
from core.constants import PDF_AVAILABLE

from engines.discovery.discovery_engine import DiscoveryEngine
from engines.port.port_engine import PortEngine
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine

if PDF_AVAILABLE:
    from pdf_generator import ScanReportGenerator

log = logging.getLogger("ccure.orchestrator")


class ScanOrchestrator:
    """
    Single entry-point for all scan types.
    
    NOW SUPPORTS:
      - Traditional flow (scan_subnet -> all phases)
      - Phase-selective flow (run_phase1 -> run_phase2 -> run_phase3)

    Usage (Traditional)::

        orch = ScanOrchestrator(silent=False, intensity="normal")
        result = orch.scan_subnet("192.168.1.0/24", scan_type="adaptive")

    Usage (Phase-Selective - NEW)::

        orch = ScanOrchestrator(silent=False, intensity="normal")
        
        # Step 1: Quick discovery
        discovery_result = orch.run_host_discovery_only(["192.168.1.0/24"], "adaptive")
        active_hosts = discovery_result["data"]  # 45 hosts found in 30s
        
        # Step 2: User selects 5 hosts, run port scan
        selected = active_hosts[:5]
        ports_result = orch.run_asset_discovery_only(selected, intensity="normal")
        
        # Step 3: User clicks "deep audit", run vuln
        vuln_result = orch.run_advanced_scan_only(ports_result["data"])
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

        try:
            self.intensity = ScanIntensity(intensity.lower())
        except ValueError:
            self.intensity = ScanIntensity.NORMAL

        self._pdf = (
            ScanReportGenerator(output_dir=reports_dir)
            if PDF_AVAILABLE else None
        )
        self._log(
            f"ScanOrchestrator ready - platform={self.platform}, "
            f"privileges={self.has_priv}, intensity={self.intensity.value}"
        )

    # ------------------------------------------------------------------
    # BACKWARD COMPATIBLE: Traditional scan methods (unchanged)
    # ------------------------------------------------------------------

    async def scan_single_host(self, target: str, scan_type: str = "adaptive") -> Dict:
        res = self._resolve(target, scan_type)
        if "error" in res:
            return self._err(res["error"])
        ip, st, meta = res["ip"], res["st"], res["meta"]

        self._log(f"scan_single_host -> {ip}")
        t0    = time.time()
        hosts = await self._run_pipeline([ip], st, scan_type, meta)
        host  = self._format_host(ip, hosts.get(ip, {}), meta.get("original"))

        summary = self._summary(1, [host.to_clean_dict()], st, time.time() - t0, target)
        result  = self._ok(host.to_clean_dict(), summary, meta)
        self._attach_pdf(result, "scan_single_host")
        return result

    async def scan_ip_range(self, target: str, scan_type: str = "adaptive") -> Dict:
        res = self._resolve(target, scan_type)
        if "error" in res:
            return self._err(res["error"])
        st, meta = res["st"], res["meta"]

        ips = InputValidator.expand_ip_range(target)
        meta["ips_in_range"] = len(ips)
        self._log(f"scan_ip_range -> {target} ({len(ips)} IPs)")

        t0    = time.time()
        hosts = await self._run_pipeline(ips, st, "discovery", meta)
        data  = [self._format_host(ip, hosts.get(ip, {})).to_clean_dict() for ip in ips]
        result = self._ok(data, self._summary(len(data), data, st, time.time() - t0, target), meta)
        self._attach_pdf(result, "scan_ip_range")
        return result

    async def scan_subnet(self, target: str, scan_type: str = "adaptive") -> Dict:
        # Allow a bare IP - auto-expand to /24
        if "/" not in target and "-" not in target:
            r2 = InputValidator.resolve_target(target)
            if "error" not in r2 and r2["type"] == "ip":
                target = str(ipaddress.ip_network(r2["resolved"] + "/24", strict=False))

        res = self._resolve(target, scan_type)
        if "error" in res:
            return self._err(res["error"])
        st, meta = res["st"], res["meta"]

        network = ipaddress.ip_network(target, strict=False)
        ips     = [str(ip) for ip in network.hosts()]
        meta["total_in_subnet"] = len(ips)
        self._log(f"scan_subnet -> {target} ({len(ips)} hosts)")

        t0    = time.time()
        hosts = await self._run_pipeline(ips, st, "discovery", meta)
        data  = [self._format_host(ip, hosts.get(ip, {})).to_clean_dict() for ip in ips]
        result = self._ok(data, self._summary(len(data), data, st, time.time() - t0, target), meta)
        self._attach_pdf(result, "scan_subnet")
        return result

    async def scan_subnets_of_subnet(
        self,
        target:        str,
        subnet_prefix: int = 24,
        scan_type:     str = "adaptive",
    ) -> Dict:
        res = self._resolve(target, scan_type)
        if "error" in res:
            return self._err(res["error"])
        st, meta = res["st"], res["meta"]

        network = ipaddress.ip_network(target, strict=False)
        if subnet_prefix <= network.prefixlen:
            return self._err(f"subnet_prefix must be > {network.prefixlen}.")
        if subnet_prefix > 30:
            return self._err("subnet_prefix must be <= 30.")

        subnets = list(network.subnets(new_prefix=subnet_prefix))
        if len(subnets) > 64:
            return self._err("Too many sub-networks. Max 64 per call.")

        meta.update(
            parent_network=target, subnet_prefix=subnet_prefix,
            subnets_scanned=len(subnets),
        )
        self._log(f"scan_subnets_of_subnet -> {target} -> {len(subnets)} blocks")

        all_ips = [str(ip) for sn in subnets for ip in sn.hosts()]
        t0      = time.time()
        raw     = await self._run_pipeline(all_ips, st, "discovery", meta)

        subnet_info, all_results = [], []
        for sn in subnets:
            sn_ips = [str(ip) for ip in sn.hosts()]
            hosts  = [self._format_host(ip, raw.get(ip, {})).to_clean_dict() for ip in sn_ips]
            all_results.extend(hosts)
            active = sum(1 for h in hosts if h["is_active"])
            subnet_info.append({
                "subnet": str(sn), "total_found": len(hosts),
                "active_hosts": active, "inactive_hosts": len(hosts) - active,
                "hosts": hosts,
            })

        summary = self._summary(len(all_results), all_results, st, time.time() - t0, target)
        resp = {
            "success": True, "data": subnet_info, "all_hosts": all_results,
            "summary": summary.to_dict(), "metadata": meta,
        }
        self._attach_pdf(resp, "scan_subnets")
        return resp

    # ------------------------------------------------------------------
    # NEW: PHASE-SELECTIVE METHODS (Frontend-driven orchestration)
    # ------------------------------------------------------------------

    async def run_host_discovery_only(
        self,
        targets: List[str],
        scan_type: str = "adaptive",
    ) -> Dict:
        """
        HOST DISCOVERY ONLY: Run discovery on one or more targets.
        
        Args:
            targets: List of IPs, ranges, or subnets
                    e.g., ["192.168.1.10", "192.168.1.0/24", "10.0.0.1-50"]
            scan_type: "ping" | "arp" | "tcp" | "full" | "adaptive" | "stealth"
        
        Returns:
            {
                "success": True,
                "data": [
                    {
                        "ip": "192.168.1.10",
                        "is_active": True,
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "method": "ARP",
                        ...
                    },
                    ...
                ],
                "summary": {
                    "total_hosts": 254,
                    "active_hosts": 45,
                    "duration": 30.5
                }
            }
        """
        self._log(f"run_host_discovery_only -> targets={targets}, scan_type={scan_type}")
        
        # Resolve scan type
        try:
            st = DiscoveryScanType(scan_type.lower())
        except ValueError:
            return self._err(f"Invalid scan_type '{scan_type}'.")
        
        # Expand all targets into a flat IP list (preserve order, drop duplicates)
        all_ips = []
        for target in targets:
            res = InputValidator.resolve_target(target)
            if "error" in res:
                continue
            
            resolved = res["resolved"]
            if "/" in resolved:
                network = ipaddress.ip_network(resolved, strict=False)
                all_ips.extend([str(ip) for ip in network.hosts()])
            elif "-" in resolved:
                all_ips.extend(InputValidator.expand_ip_range(resolved))
            else:
                all_ips.append(resolved)
        all_ips = list(dict.fromkeys(all_ips))
        
        if not all_ips:
            return self._err("No valid targets to scan.")
        
        t0 = time.time()
        
        # Run only Phase 1
        discovery = DiscoveryEngine(
            has_privileges=self.has_priv,
            stealth_mode=self.stealth_mode,
        )
        disc_results: List[Dict] = await discovery.run(all_ips, st)
        duration = time.time() - t0
        
        # Format results
        formatted_hosts = []
        for ip_data in disc_results:
            ip = ip_data.get("ip")
            formatted = self._format_host(ip, ip_data).to_phase1_dict()
            formatted_hosts.append(formatted)
        
        active = sum(1 for h in formatted_hosts if h["is_active"])
        summary = {
            "total_hosts": len(formatted_hosts),
            "active_hosts": active,
            "inactive_hosts": len(formatted_hosts) - active,
            "scan_duration": duration,
            "phase": 1,
            "scan_type": st.value.upper(),
            "discovery_scan_method": st.value.upper(),
        }
        
        return {
            "success": True,
            "data": formatted_hosts,
            "summary": summary,
            "metadata": {
                "target": ", ".join(targets),
                "original_targets": targets,
                "scan_method": st.value.upper(),
                "discovery_scan_method": st.value.upper(),
            },
        }

    async def run_asset_discovery_only(
        self,
        hosts: List[Dict],
        intensity: str = "normal",
    ) -> Dict:
        """
        ASSET DISCOVERY ONLY: Run port scanning on already-discovered hosts.
        
        Args:
            hosts: List of host dicts with at least "ip" and "is_active" fields.
                   Typically output from run_host_discovery_only().
            intensity: "light" | "normal" | "deep"
        
        Returns:
            {
                "success": True,
                "data": [
                    {
                        "ip": "192.168.1.10",
                        "is_active": True,
                        "open_ports": [
                            {"port": 22, "service": "ssh", "banner": "OpenSSH ..."},
                            {"port": 80, "service": "http", ...},
                        ],
                        ...
                    },
                    ...
                ],
                "summary": {
                    "total_hosts": 5,
                    "hosts_with_ports": 5,
                    "duration": 8.5,
                    "phase": 2,
                }
            }
        """
        self._log(f"run_asset_discovery_only -> {len(hosts)} hosts, intensity={intensity}")
        
        try:
            intensity_enum = ScanIntensity(intensity.lower())
        except ValueError:
            intensity_enum = ScanIntensity.NORMAL

        hosts = [self._normalize_host_record(h) for h in hosts]
        discovery_scan_method = self._infer_discovery_method(hosts)
        target_from_hosts = self._hosts_target_string(hosts)
        
        # Filter to active hosts only
        active_hosts = [h for h in hosts if h.get("is_active", False)]
        active_count = len(active_hosts)
        inactive_count = len(hosts) - active_count
        
        if not active_hosts:
            formatted_hosts = [
                self._format_host(self._get_host_ip(host), host).to_clean_dict()
                for host in hosts
            ]
            return {
                "success": True,
                "data": formatted_hosts,
                "summary": {
                    "total_hosts": len(formatted_hosts),
                    "active_hosts": active_count,
                    "inactive_hosts": inactive_count,
                    "hosts_with_ports": 0,
                    "scan_duration": 0,
                    "phase": 2,
                    "scan_type": intensity_enum.value.upper(),
                    "discovery_scan_method": discovery_scan_method or "N/A",
                },
                "metadata": {
                    **({"target": target_from_hosts} if target_from_hosts else {}),
                    "scan_intensity": intensity_enum.value.upper(),
                    **({"scan_method": discovery_scan_method} if discovery_scan_method else {}),
                    **({"discovery_scan_method": discovery_scan_method} if discovery_scan_method else {}),
                },
            }
        
        t0 = time.time()
        
        # Run Phase 2: Port Scanning
        port_engine = PortEngine(intensity=intensity_enum)
        await port_engine.run(active_hosts)  # mutates in-place
        self._apply_os_inference(active_hosts)
        
        duration = time.time() - t0
        
        # Format all hosts (active + inactive)
        formatted_hosts = []
        for host in hosts:
            formatted = self._format_host(self._get_host_ip(host), host).to_clean_dict()
            formatted_hosts.append(formatted)
        
        hosts_with_ports = sum(1 for h in formatted_hosts if h.get("open_ports"))
        
        summary = {
            "total_hosts": len(formatted_hosts),
            "active_hosts": active_count,
            "inactive_hosts": inactive_count,
            "hosts_with_ports": hosts_with_ports,
            "scan_duration": duration,
            "phase": 2,
            "scan_type": intensity_enum.value.upper(),
            "discovery_scan_method": discovery_scan_method or "N/A",
        }
        
        return {
            "success": True,
            "data": formatted_hosts,
            "summary": summary,
            "metadata": {
                **({"target": target_from_hosts} if target_from_hosts else {}),
                "scan_intensity": intensity_enum.value.upper(),
                **({"scan_method": discovery_scan_method} if discovery_scan_method else {}),
                **({"discovery_scan_method": discovery_scan_method} if discovery_scan_method else {}),
            },
        }

    def run_advanced_scan_only(
        self,
        hosts: List[Dict],
    ) -> Dict:
        """
        ADVANCED SCAN ONLY: Run vulnerability scanning + risk scoring on hosts with ports.
        
        Args:
            hosts: List of host dicts with "ip", "open_ports", etc.
                   Typically output from run_asset_discovery_only().
        
        Returns:
            {
                "success": True,
                "data": [
                    {
                        "ip": "192.168.1.10",
                        "open_ports": [...],
                        "tls_info": {...},
                        "ssh_info": {...},
                        "cves": [...],
                        "host_risk_score": 85,
                        "host_risk_level": "High",
                        ...
                    },
                    ...
                ],
                "summary": {
                    "total_hosts": 5,
                    "critical_hosts": 1,
                    "duration": 45.2,
                    "phase": 3,
                }
            }
        """
        self._log(f"run_advanced_scan_only -> {len(hosts)} hosts")

        hosts = [self._normalize_host_record(h) for h in hosts]
        discovery_scan_method = self._infer_discovery_method(hosts)
        target_from_hosts = self._hosts_target_string(hosts)
        
        # Filter to active hosts
        active_hosts = [h for h in hosts if h.get("is_active", False)]
        active_count = len(active_hosts)
        inactive_count = len(hosts) - active_count
        
        if not active_hosts:
            formatted_hosts = [
                self._format_host(self._get_host_ip(host), host).to_clean_dict()
                for host in hosts
            ]
            return {
                "success": True,
                "data": formatted_hosts,
                "summary": {
                    "total_hosts": len(formatted_hosts),
                    "active_hosts": active_count,
                    "inactive_hosts": inactive_count,
                    "critical_hosts": 0,
                    "high_risk_hosts": 0,
                    "scan_duration": 0,
                    "phase": 3,
                    "scan_type": "advanced",
                    "discovery_scan_method": discovery_scan_method or "N/A",
                },
                "metadata": {
                    **({"target": target_from_hosts} if target_from_hosts else {}),
                    "scan_type": "advanced",
                    **({"scan_method": discovery_scan_method} if discovery_scan_method else {}),
                    **({"discovery_scan_method": discovery_scan_method} if discovery_scan_method else {}),
                },
            }
        
        t0 = time.time()
        
        # Run Phase 3+4: Vulnerability + Risk Scoring
        vuln_engine = VulnerabilityEngine(rate_limit=self.rate_limit)
        vuln_engine.run(active_hosts)  # mutates in-place
        self._apply_os_inference(active_hosts)
        
        duration = time.time() - t0
        
        # Format all hosts
        formatted_hosts = []
        for host in hosts:
            formatted = self._format_host(self._get_host_ip(host), host).to_clean_dict()
            formatted_hosts.append(formatted)
        
        critical = sum(1 for h in formatted_hosts if h.get("host_risk_level") == "Critical")
        high = sum(1 for h in formatted_hosts if h.get("host_risk_level") == "High")
        
        summary = {
            "total_hosts": len(formatted_hosts),
            "active_hosts": active_count,
            "inactive_hosts": inactive_count,
            "critical_hosts": critical,
            "high_risk_hosts": high,
            "scan_duration": duration,
            "phase": 3,
            "scan_type": "advanced",
            "discovery_scan_method": discovery_scan_method or "N/A",
        }
        
        return {
            "success": True,
            "data": formatted_hosts,
            "summary": summary,
            "metadata": {
                **({"target": target_from_hosts} if target_from_hosts else {}),
                "scan_type": "advanced",
                **({"scan_method": discovery_scan_method} if discovery_scan_method else {}),
                **({"discovery_scan_method": discovery_scan_method} if discovery_scan_method else {}),
            },
        }

    async def run_phases(
        self,
        targets: List[str],
        phases: str = "1",
        scan_type: str = "adaptive",
        intensity: str = "normal",
    ) -> Dict:
        """
        Flexible phase selection: run any combination of phases.
        
        Args:
            targets: List of IPs, ranges, or subnets
            phases: "1" | "1+2" | "1+2+3+4" | "2" | "3" etc.
                   (if phase 2 without 1, will still run phase 1 as prerequisite)
            scan_type: "ping" | "arp" | "tcp" | "full" | "adaptive" | "stealth"
            intensity: "light" | "normal" | "deep"
        
        Returns:
            Combined result from all phases requested
        """
        self._log(f"run_phases -> targets={targets}, phases={phases}")
        
        # Parse phases string
        phase_list = [int(p.strip()) for p in phases.split("+")]
        phase_set = set(phase_list)
        
        if not phase_set or not phase_set.issubset({1, 2, 3, 4}):
            return self._err(f"Invalid phases: {phases}. Use '1', '1+2', '1+2+3+4', etc.")
        
        # Phase 1 is always prerequisite
        min_phase = min(phase_set)
        if min_phase > 1:
            phase_set.add(1)
        
        result = None
        
        # Phase 1
        if 1 in phase_set:
            result = await self.run_host_discovery_only(targets, scan_type)
            if not result["success"]:
                return result
        
        # Phase 2
        if 2 in phase_set:
            result = await self.run_asset_discovery_only(result["data"], intensity)
            if not result["success"]:
                return result
        
        # Phase 3+4
        if 3 in phase_set or 4 in phase_set:
            result = self.run_advanced_scan_only(result["data"])
            if not result["success"]:
                return result
        
        return result

    # ------------------------------------------------------------------
    # Pipeline execution (internal - unchanged)
    # ------------------------------------------------------------------

    async def _run_pipeline(
        self,
        ips:       List[str],
        st:        DiscoveryScanType,
        scan_mode: str,
        meta:      Dict,
    ) -> Dict[str, Dict]:
        """
        Runs phases 1-4 depending on scan_mode.
        Returns a dict keyed by IP -> raw host dict.
        """
        # -- Phase 1: Discovery -------------------------------------------
        discovery = DiscoveryEngine(
            has_privileges=self.has_priv,
            stealth_mode=self.stealth_mode,
        )
        disc_results: List[Dict] = await discovery.run(ips, st)

        # Convert to keyed dict for O(1) lookup
        host_map: Dict[str, Dict] = {h["ip"]: h for h in disc_results}

        if scan_mode == "discovery":
            return host_map

        # -- Phase 2: Port Scan -------------------------------------------
        active_hosts = [h for h in disc_results if h["is_active"]]
        port_engine  = PortEngine(intensity=self.intensity)
        await port_engine.run(active_hosts)   # mutates active_hosts in-place
        self._apply_os_inference(active_hosts)

        if scan_mode == "port":
            return host_map

        # -- Phase 3+4: Vulnerability + Risk Scoring -------------------
        vuln_engine = VulnerabilityEngine(rate_limit=self.rate_limit)
        vuln_engine.run(active_hosts)   # mutates in-place
        self._apply_os_inference(active_hosts)

        return host_map

    # ------------------------------------------------------------------
    # Host formatting
    # ------------------------------------------------------------------

    def _format_host(self, ip: str, data: Dict, input_hostname: str = None) -> HostResult:
        ip = ip or self._get_host_ip(data)
        is_active = data.get("is_active", False)

        # Reverse-DNS lookup for active hosts
        hostname = "Unknown"
        if is_active and ip:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = input_hostname or "Unknown"
        else:
            hostname = input_hostname or "Unknown"

        # Enrich local-machine entries
        mac = data.get("mac", "N/A")
        if ip and ip in get_local_ips():
            if hostname == "Unknown":
                hostname = socket.gethostname()
            if mac == "N/A":
                mac = get_local_mac()

        # ── ARP cache fallback for same-subnet hosts ──
        if ip and mac == "N/A" and is_active:
            from core.utils import get_mac_from_arp_cache
            mac = get_mac_from_arp_cache(ip)
        # ──────────────────────────────────────────────

        # ── OUI / Vendor lookup from MAC address ─────
        vendor = "N/A"
        if mac and mac != "N/A":
            from core.oui_lookup import lookup_vendor
            vendor = lookup_vendor(mac) or "N/A"
        # ──────────────────────────────────────────────

        confs      = data.get("confirmations", [])
        n          = len(confs)
        confidence = (
            "High"   if n >= 2 or "ARP" in confs else
            "Medium" if n == 1 else "Low"
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
            scan_method      = (
                data.get("method")
                or data.get("scan_method")
                or data.get("discovery_method")
                or "N/A"
            ),
            response_time_ms = data.get("elapsed_ms", data.get("response_time_ms")),
            open_ports       = data.get("open_ports", []),
            os_guess         = data.get("os_guess", "Unknown"),
            os_confidence    = data.get("os_confidence", "Low"),
            confidence       = confidence,
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
        normalized = dict(host)
        ip = self._get_host_ip(normalized)
        if ip:
            normalized["ip"] = ip
            normalized["ip_address"] = ip
        if "method" not in normalized:
            normalized["method"] = (
                normalized.get("scan_method")
                or normalized.get("discovery_method")
                or "N/A"
            )
        if "elapsed_ms" not in normalized and "response_time_ms" in normalized:
            normalized["elapsed_ms"] = normalized.get("response_time_ms")
        return normalized

    @staticmethod
    def _normalize_scan_method(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        token = str(value).strip().upper()
        if not token or token in {"N/A", "UNKNOWN", "NONE"}:
            return None
        if "ADAPTIVE" in token:
            return "ADAPTIVE"
        if "STEALTH" in token:
            return "STEALTH"
        if "FULL" in token:
            return "FULL"
        if "ARP" in token:
            return "ARP"
        if "PING" in token or "ICMP" in token:
            return "PING"
        if "TCP" in token:
            return "TCP"
        return None

    def _infer_discovery_method(self, hosts: List[Dict]) -> Optional[str]:
        methods: List[str] = []
        for host in hosts:
            raw = host.get("method") or host.get("scan_method") or host.get("discovery_method")
            normalized = self._normalize_scan_method(raw)
            if normalized:
                methods.append(normalized)
        if not methods:
            return None
        return Counter(methods).most_common(1)[0][0]

    def _hosts_target_string(self, hosts: List[Dict]) -> Optional[str]:
        ips: List[str] = []
        for host in hosts:
            ip = self._get_host_ip(host)
            if ip and ip not in ips:
                ips.append(ip)
        if not ips:
            return None
        return ", ".join(ips)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_os_inference(hosts: List[Dict]):
        for host in hosts:
            guess, conf = infer_os_from_host(host)
            host["os_guess"] = guess
            host["os_confidence"] = conf

    def _resolve(self, target: str, scan_type: str) -> Dict:
        try:
            st = DiscoveryScanType(scan_type.lower())
        except ValueError:
            return {"error": f"Invalid scan_type '{scan_type}'."}

        res = InputValidator.resolve_target(target)
        if "error" in res:
            return {"error": res["error"]}

        meta: Dict = {
            "target": target, "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
        }
        if res.get("resolved_ip"):
            meta["resolved_ip"] = res["resolved_ip"]
            meta["original"]    = res.get("original", target)

        # Downgrade scan if not privileged
        if not self.has_priv and st in (
            DiscoveryScanType.ARP, DiscoveryScanType.FULL,
            DiscoveryScanType.PING, DiscoveryScanType.STEALTH,
        ):
            msg = f"Root/Admin required for '{st.value}'. Auto-switching to TCP."
            self._log(f"[WARN] {msg}")
            meta["privilege_warning"] = msg
            st = DiscoveryScanType.TCP

        meta["scan_method"] = st.value.upper()
        meta["discovery_scan_method"] = st.value.upper()

        return {"ip": res["resolved"], "st": st, "meta": meta}

    @staticmethod
    def _summary(
        total: int, data: List[Dict],
        st: DiscoveryScanType, duration: float, target: str,
    ) -> DiscoverySummary:
        active = sum(1 for h in data if h.get("is_active"))
        crits  = sum(1 for h in data if h.get("host_risk_level") == "Critical")
        highs  = sum(1 for h in data if h.get("host_risk_level") in ("Critical", "High"))
        return DiscoverySummary(
            total_hosts=total, active_hosts=active, inactive_hosts=total - active,
            scan_type=st.value.upper(), scan_duration=duration, target=target,
            critical_hosts=crits, high_risk_hosts=highs,
        )

    @staticmethod
    def _ok(data, summary: DiscoverySummary, meta: Dict) -> Dict:
        return {"success": True, "data": data, "summary": summary.to_dict(), "metadata": meta}

    @staticmethod
    def _err(message: str, **extra) -> Dict:
        return {"success": False, "error": message, **extra}

    def _log(self, msg: str):
        if not self.silent:
            log.info(msg)

    def generate_phase_report(self, resp: Dict, scan_type: str) -> Dict[str, str]:
        if not self._pdf:
            return {}

        try:
            return self._pdf.generate(resp, scan_type)
        except Exception as exc:
            self._log(f"[WARN] PDF generation failed for {scan_type}: {exc}")
            return {}

    def _attach_pdf(self, resp: Dict, scan_type: str):
        paths = self.generate_phase_report(resp, scan_type)
        if paths:
            resp["reports"] = paths
