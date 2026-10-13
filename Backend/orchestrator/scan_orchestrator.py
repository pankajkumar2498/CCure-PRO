"""
orchestrator/scan_orchestrator.py  (REFACTORED — key methods only)
────────────────────────────────────────────────────────────────────────────
Changes from original:
  1. run_host_discovery_only() now resolves a DiscoveryProfile from pipeline_mode
     and passes it to core.discovery.engine.DiscoveryEngine
  2. run_asset_discovery_only() delegates to PortEngine which uses NmapScanner
  3. run_vulnerability_audit_only() passes open_port data to NmapScanner.full_scan()
     for OS fingerprinting before handing to VulnerabilityEngine

All other methods (scan_single_host, scan_ip_range, scan_subnet,
scan_subnets_of_subnet, generate_phase_report, _format_host, etc.)
are UNCHANGED from the original orchestrator.

The public API surface (method names + return format) is preserved.
"""

import asyncio
import ipaddress
import logging
import os
import platform
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from core.asset_correlation import AssetCorrelationEngine
from reporting.availability import PDF_AVAILABLE

# ── NEW imports for refactored architecture ───────────────────────────────────
from core.discovery.engine import DiscoveryEngine
from core.discovery.profiles import BALANCED, FAST, profile_for_pipeline
from core.models import HostResult, PortResult, ScanIntensity
from core.oui_lookup import lookup_vendor
from core.risk import infer_os_from_host
from core.utils import InputValidator, PrivilegeManager, get_local_ips, get_local_mac

# ── Existing engine imports (unchanged) ───────────────────────────────────────
from engines.port.port_engine import (
    PortEngine,
    _record_port,
    fingerprint_os_confidence,
)
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine
from scans.finding_normalizer import version_precision

if PDF_AVAILABLE:
    from reporting.pdf_generator import ScanReportGenerator

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
        silent: bool = True,
        reports_dir: str | None = None,
        intensity: str = "normal",
        rate_limit: float = 200.0,
        stealth_mode: bool = False,
    ):
        self.silent = silent
        self.rate_limit = rate_limit
        self.stealth_mode = stealth_mode
        self.platform = PrivilegeManager.get_platform()
        self.has_priv = PrivilegeManager.is_admin()

        # Authorised scan scope for the organisation this run belongs to, as a
        # list of ip_network objects, or None for unrestricted. Set by the
        # Celery task via apply_scan_scope() once the scan row is loaded.
        #
        # The API already refuses out-of-scope targets at admission. This is the
        # second layer, and the load-bearing one: it applies to the addresses a
        # hostname actually resolved to at scan time, which admission could not
        # know. Without it a name that resolved in-scope during admission could
        # point somewhere else by the time the scanner connects.
        self.scan_scope = None

        # ── NEW: Unified asset correlation engine for data consistency ────────
        self.asset_engine = AssetCorrelationEngine()

        try:
            self.intensity = ScanIntensity(intensity.lower())
        except ValueError:
            self.intensity = ScanIntensity.NORMAL

        if reports_dir is None or reports_dir == "reports":
            backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            reports_dir = os.path.join(backend_dir, "reports")

        self._pdf = (
            ScanReportGenerator(output_dir=reports_dir) if PDF_AVAILABLE else None
        )
        self._log(
            f"ScanOrchestrator ready — platform={self.platform}, "
            f"priv={self.has_priv}, intensity={self.intensity.value}"
        )

    # ── TRADITIONAL SCAN METHODS (backward-compat with /scan/host, /scan/range, etc.) ─────
    #
    # These methods are called by main.py traditional endpoints (POST /scan/host,
    # /scan/range, /scan/subnet, /scan/subnets, /scan/phases) via HostDiscoveryAPI.
    # They delegate to run_host_discovery_only() which drives the new Scapy pipeline.
    # The "vulnerability_audit" pipeline_mode is used so all discovery techniques are active.

    async def scan_single_host(self, target: str, scan_type: str = "adaptive") -> dict:
        """Backward-compat: scan a single host using the full discovery pipeline."""
        return await self.run_host_discovery_only(
            targets=[target],
            scan_type=scan_type,
            pipeline_mode="vulnerability_audit",
        )

    async def scan_ip_range(self, target: str, scan_type: str = "adaptive") -> dict:
        """Backward-compat: scan an IP range (e.g. '10.180.6.14-50')."""
        return await self.run_host_discovery_only(
            targets=[target],
            scan_type=scan_type,
            pipeline_mode="vulnerability_audit",
        )

    async def scan_subnet(self, target: str, scan_type: str = "adaptive") -> dict:
        """Backward-compat: scan a CIDR subnet (e.g. '10.180.6.0/24')."""
        return await self.run_host_discovery_only(
            targets=[target],
            scan_type=scan_type,
            pipeline_mode="vulnerability_audit",
        )

    async def scan_subnets_of_subnet(
        self,
        target: str,
        subnet_prefix: int = 24,
        scan_type: str = "adaptive",
    ) -> dict:
        """Backward-compat: scan all sub-subnets of a parent CIDR."""
        import ipaddress

        results: list[dict] = []
        try:
            parent = ipaddress.ip_network(target, strict=False)
            subnets = [str(s) for s in parent.subnets(new_prefix=subnet_prefix)]
        except ValueError as exc:
            return self._err(f"Invalid target '{target}': {exc}")

        for subnet in subnets:
            r = await self.run_host_discovery_only(
                targets=[subnet],
                scan_type=scan_type,
                pipeline_mode="vulnerability_audit",
            )
            results.extend(r.get("data", []))

        active = sum(1 for h in results if h.get("is_active"))
        return {
            "success": True,
            "data": results,
            "summary": {
                "total_subnets": len(subnets),
                "total_hosts": len(results),
                "active_hosts": active,
                "inactive_hosts": len(results) - active,
                "scan_type": scan_type.upper(),
            },
        }

    async def run_phases(
        self,
        targets: list[str],
        phases: str,
        scan_type: str = "adaptive",
        intensity: str = "normal",
        scan_id: str | None = None,
        passive_first: bool = False,
        exclude_ot_from_nmap: bool = True,
        exclude_ips: str | None = None,
    ) -> dict:
        """
        Backward-compat: run any combination of phases in one call.
        phases: '1' | '1+2' | '1+2+3+4'
        """
        phase_nums = {int(p) for p in phases.split("+") if p.strip().isdigit()}

        if 3 in phase_nums or 4 in phase_nums:
            pipeline_mode = "vulnerability_audit"
        elif 2 in phase_nums:
            pipeline_mode = "asset"
        else:
            pipeline_mode = "basic"

        # Phase 1: Host Discovery
        result = await self.run_host_discovery_only(
            targets=targets,
            scan_type=scan_type,
            pipeline_mode=pipeline_mode,
            scan_id=scan_id,
            exclude_ips=exclude_ips,
        )
        if not result.get("success") or pipeline_mode == "basic":
            return result

        # Phase 2: Port Scan
        hosts = result.get("data", [])
        result = await self.run_asset_discovery_only(
            hosts=hosts,
            intensity=intensity,
            pipeline_mode=pipeline_mode,
            scan_id=scan_id,
            exclude_ot_from_nmap=exclude_ot_from_nmap,
            passive_first=passive_first,
            exclude_ips=exclude_ips,
        )
        if not result.get("success") or pipeline_mode == "asset":
            return result

        # Phase 3: Vulnerability
        hosts = result.get("data", [])
        return await asyncio.to_thread(
            self.run_vulnerability_audit_only,
            hosts=hosts,
            scan_id=scan_id,
            exclude_ot_from_nmap=exclude_ot_from_nmap,
            exclude_ips=exclude_ips,
        )

    @staticmethod
    def _err(msg: str) -> dict:
        return {"success": False, "error": msg}

    # ── PHASE 1: Host Discovery ───────────────────────────────────────────────

    async def run_host_discovery_only(
        self,
        targets: list[str],
        scan_type: str = "adaptive",
        pipeline_mode: str = "basic",
        discovery_intensity: str = "normal",
        scan_id: str | None = None,
        rate_limit: float | None = None,
        max_concurrency: int | None = None,
        exclude_ips: str | None = None,
    ) -> dict:
        """
        Phase 1 — Host Discovery.

        pipeline_mode → Profile mapping (unchanged):
          "basic"    → FAST       (ARP + TCP connect only — no fallback chains)
          "vulnerability_audit" → AGGRESSIVE (all techniques + enrichment)

        Asset Discovery (pipeline_mode="asset") is now intensity-aware:
          "light"  → FAST only
          "normal" → FAST first, then BALANCED only for IPs still inactive/unresolved
          "deep"   → BALANCED (original Asset Discovery behaviour)

        Basic and Vulnerability Audit scan behaviour is COMPLETELY UNCHANGED.
        scan_type is still accepted for backward-compat with traditional endpoints.
        """
        self._log(
            f"run_host_discovery_only → targets={targets}, "
            f"mode={pipeline_mode}, intensity={discovery_intensity}"
        )

        # ── Non-asset pipelines: preserve existing behaviour exactly ──────────
        custom_exclude = self._parse_exclude_ips(exclude_ips)
        if pipeline_mode != "asset":
            # scan_type="fast" (Light Mode toggle on Basic Scan) → always FAST
            if scan_type == "fast":
                profile = FAST
            else:
                profile = profile_for_pipeline(pipeline_mode)

            all_ips = self._drop_out_of_scope(
                self._expand_targets(targets, custom_exclude)
            )
            if not all_ips:
                return self._err("No valid targets to scan.")

            t0 = time.time()
            discovery = DiscoveryEngine(
                profile=profile,
                has_privileges=self.has_priv,
                stealth_mode=self.stealth_mode,
                rate_limit=rate_limit,
                concurrency_override=max_concurrency,
            )
            disc_results: list[dict] = await discovery.run(all_ips, scan_id=scan_id)
            duration = time.time() - t0

            # Trigger classification and OS inference on the discovered hosts
            self._apply_os_inference(
                disc_results, ot_enrichment=(pipeline_mode == "vulnerability_audit")
            )

            if pipeline_mode == "basic":
                formatted = [
                    self._format_host(r.get("ip"), r).to_basic_dict()
                    for r in disc_results
                ]
            else:  # vulnerability_audit
                formatted = [
                    self._format_host(r.get("ip"), r).to_phase1_dict()
                    for r in disc_results
                ]

            if pipeline_mode == "vulnerability_audit":
                self.asset_engine.register_discovery_results(
                    formatted,
                    discovery_method=scan_type,
                    discovery_profile=profile.name,
                )

            active = sum(1 for h in formatted if h["is_active"])

            if pipeline_mode == "vulnerability_audit":
                summary = {
                    "total_hosts": len(formatted),
                    "active_hosts": active,
                    "inactive_hosts": len(formatted) - active,
                    "scan_duration": duration,
                    "phase": 1,
                    "scan_type": scan_type.upper(),
                    "discovery_scan_method": scan_type.upper(),
                    "discovery_profile": profile.name,
                }
                metadata = {
                    "target": ", ".join(targets),
                    "original_targets": targets,
                    "scan_method": scan_type.upper(),
                    "discovery_scan_method": scan_type.upper(),
                    "discovery_profile": profile.name,
                }
            else:  # basic
                summary = {
                    "total_hosts": len(formatted),
                    "active_hosts": active,
                    "inactive_hosts": len(formatted) - active,
                    "scan_duration": duration,
                    "phase": 1,
                    "scan_type": scan_type.upper(),
                    "discovery_profile": profile.name,
                }
                metadata = {
                    "target": ", ".join(targets),
                    "original_targets": targets,
                    "scan_type": scan_type.upper(),
                    "discovery_profile": profile.name,
                }

            # Host discovery does not scan ports or fingerprint services. Saying
            # so explicitly matters more than it looks: a report whose coverage
            # reads "not recorded" invites the reader to assume those checks ran
            # and found nothing, when this policy never performed them.
            discovery_coverage = {
                "port_range": "Not scanned — host discovery policy does not scan ports",
                "service_detection": "Not performed",
                "os_detection": (
                    "Passive inference from discovery responses"
                    if any(
                        h.get("os_guess") not in (None, "", "Unknown")
                        for h in formatted
                    )
                    else "Not performed"
                ),
                "scanner": f"Built-in host discovery ({profile.name} profile)",
                "timing_template": f"{profile.name} discovery profile",
            }
            summary.update(discovery_coverage)
            metadata.update(discovery_coverage)

            return {
                "success": True,
                "data": formatted,
                "summary": summary,
                "metadata": metadata,
            }

        # ── Asset Discovery — intensity-aware orchestration ───────────────────
        all_ips = self._drop_out_of_scope(self._expand_targets(targets, custom_exclude))
        if not all_ips:
            return self._err("No valid targets to scan.")

        return await self._run_asset_phase1(
            all_ips=all_ips,
            targets=targets,
            scan_type=scan_type,
            discovery_intensity=discovery_intensity,
            scan_id=scan_id,
            rate_limit=rate_limit,
            max_concurrency=max_concurrency,
        )

    # ── Asset Discovery — Phase 1 orchestrator ───────────────────────────────

    async def _run_asset_phase1(
        self,
        all_ips: list[str],
        targets: list[str],
        scan_type: str,
        discovery_intensity: str,
        scan_id: str | None = None,
        rate_limit: float | None = None,
        max_concurrency: int | None = None,
    ) -> dict:
        """
        Asset-specific Phase 1 orchestration.

        Implements the three discovery intensities:

          light  — Run FAST only.  Fastest, may miss firewalled hosts.
          normal — Run FAST first; run BALANCED only on IPs still inactive.
                   Merges results preserving original IP order.
          deep   — Run full BALANCED (original Asset Discovery behaviour).
        """
        intensity = (discovery_intensity or "normal").strip().lower()
        if intensity not in ("light", "normal", "deep"):
            log.warning(
                "Unknown discovery_intensity '%s' — defaulting to 'normal'.",
                discovery_intensity,
            )
            intensity = "normal"

        self._log(f"_run_asset_phase1 → {len(all_ips)} IPs, intensity={intensity}")

        t0 = time.time()
        fallback_targets_count = 0
        fallback_active_hosts = 0

        if intensity == "light":
            # ── LIGHT: FAST only ─────────────────────────────────────────────
            engine = DiscoveryEngine(
                profile=FAST,
                has_privileges=self.has_priv,
                stealth_mode=self.stealth_mode,
                rate_limit=rate_limit,
                concurrency_override=max_concurrency,
            )
            raw_results: list[dict] = await engine.run(all_ips, scan_id=scan_id)
            discovery_profile_label = "FAST"

        elif intensity == "normal":
            # ── NORMAL: FAST first, BALANCED fallback for inactive ────────────
            fast_engine = DiscoveryEngine(
                profile=FAST,
                has_privileges=self.has_priv,
                stealth_mode=self.stealth_mode,
                rate_limit=rate_limit,
                concurrency_override=max_concurrency,
            )
            fast_raw: list[dict] = await fast_engine.run(all_ips, scan_id=scan_id)

            # Determine which IPs are still inactive after FAST pass
            fast_by_ip: dict[str, dict] = {r["ip"]: r for r in fast_raw}
            unresolved_ips = [
                ip
                for ip in all_ips
                if not fast_by_ip.get(ip, {}).get("is_active", False)
            ]
            fallback_targets_count = len(unresolved_ips)

            if unresolved_ips:
                balanced_engine = DiscoveryEngine(
                    profile=BALANCED,
                    has_privileges=self.has_priv,
                    stealth_mode=self.stealth_mode,
                    rate_limit=rate_limit,
                )
                balanced_raw: list[dict] = await balanced_engine.run(
                    unresolved_ips, scan_id=scan_id
                )
                balanced_by_ip: dict[str, dict] = {r["ip"]: r for r in balanced_raw}
                fallback_active_hosts = sum(
                    1 for r in balanced_raw if r.get("is_active", False)
                )
            else:
                balanced_by_ip = {}

            # Merge: preserve original IP order
            raw_results = self._merge_fast_balanced_results(
                all_ips, fast_by_ip, balanced_by_ip
            )
            discovery_profile_label = "FAST+BALANCED_FALLBACK"

        else:  # deep
            # ── DEEP: full BALANCED (original behaviour) ──────────────────────
            engine = DiscoveryEngine(
                profile=BALANCED,
                has_privileges=self.has_priv,
                stealth_mode=self.stealth_mode,
                rate_limit=rate_limit,
                concurrency_override=max_concurrency,
            )
            raw_results = await engine.run(all_ips, scan_id=scan_id)
            discovery_profile_label = "BALANCED"

        duration = time.time() - t0

        # Trigger classification and OS inference on the discovered hosts
        self._apply_os_inference(raw_results, ot_enrichment=False)

        # Format using the same to_basic_dict() path as the original asset flow
        formatted = [
            self._format_host(r.get("ip"), r).to_basic_dict() for r in raw_results
        ]

        active = sum(1 for h in formatted if h["is_active"])

        summary = {
            "total_hosts": len(formatted),
            "active_hosts": active,
            "inactive_hosts": len(formatted) - active,
            "scan_duration": duration,
            "phase": 1,
            "scan_type": scan_type.upper(),
            "discovery_profile": discovery_profile_label,
            "discovery_intensity": intensity,
        }
        if intensity == "normal":
            summary["fallback_targets_count"] = fallback_targets_count
            summary["fallback_active_hosts"] = fallback_active_hosts

        metadata = {
            "target": ", ".join(targets),
            "original_targets": targets,
            "scan_type": scan_type.upper(),
            "discovery_profile": discovery_profile_label,
            "discovery_intensity": intensity,
        }

        return {
            "success": True,
            "data": formatted,
            "summary": summary,
            "metadata": metadata,
        }

    @staticmethod
    def _merge_fast_balanced_results(
        ordered_ips: list[str],
        fast_by_ip: dict[str, dict],
        balanced_by_ip: dict[str, dict],
    ) -> list[dict]:
        """
        Merge FAST and BALANCED discovery results for Normal intensity.

        Rules (in priority order):
          1. If FAST found the host active → keep FAST result (no wasted bandwidth).
          2. If FAST did not find it but BALANCED did → use BALANCED result.
          3. If both are inactive → prefer the result with more populated fields;
             always preserve any MAC/vendor data that's available.
        """
        merged: list[dict] = []
        for ip in ordered_ips:
            fast_r = fast_by_ip.get(
                ip,
                {
                    "ip": ip,
                    "ip_address": ip,
                    "is_active": False,
                    "method": "N/A",
                    "confirmations": [],
                    "mac": "N/A",
                },
            )
            balanced_r = balanced_by_ip.get(ip)

            if fast_r.get("is_active"):
                # Rule 1: FAST success → keep FAST result
                merged.append(fast_r)
            elif balanced_r and balanced_r.get("is_active"):
                # Rule 2: BALANCED found it → use BALANCED, stitch in any MAC from FAST
                result = dict(balanced_r)
                if fast_r.get("mac") and fast_r["mac"] != "N/A":
                    # Override only if balanced result has no useful MAC
                    if result.get("mac", "N/A") in ("N/A", None, ""):
                        result["mac"] = fast_r["mac"]
                if fast_r.get("mac_address") and fast_r["mac_address"] != "N/A":
                    if result.get("mac_address", "N/A") in ("N/A", None, ""):
                        result["mac_address"] = fast_r["mac_address"]
                merged.append(result)
            else:
                # Rule 3: both inactive → pick whichever has more populated fields
                if balanced_r:
                    fast_pop = sum(1 for v in fast_r.values() if v and v != "N/A")
                    balanced_pop = sum(
                        1 for v in balanced_r.values() if v and v != "N/A"
                    )
                    base = balanced_r if balanced_pop >= fast_pop else fast_r
                    result = dict(base)
                    # Preserve MAC from either side
                    for src in (fast_r, balanced_r):
                        if result.get("mac", "N/A") in ("N/A", None, ""):
                            if src.get("mac") and src["mac"] != "N/A":
                                result["mac"] = src["mac"]
                        if result.get("mac_address", "N/A") in ("N/A", None, ""):
                            if src.get("mac_address") and src["mac_address"] != "N/A":
                                result["mac_address"] = src["mac_address"]
                    merged.append(result)
                else:
                    merged.append(fast_r)

        return merged

    async def run_asset_discovery_only(
        self,
        hosts: list[dict],
        intensity: str = "normal",
        scan_id: str | None = None,
        pipeline_mode: str = "asset",
        os_detection: bool = True,
        custom_ports: str | None = None,
        exclude_ports: str | None = None,
        exclude_ot_from_nmap: bool = True,
        passive_first: bool = False,
        exclude_ips: str | None = None,
    ) -> dict:
        """
        Phase 2 — Port Scanning.

        REFACTORED:
          PortEngine now routes to NmapScanner when nmap is available,
          falling back to async TCP connect when not.
          The return format is IDENTICAL to the original.

        Args:
            hosts:         Host dicts from Phase 1.
            intensity:     Scan intensity (light/normal/deep).
            scan_id:       Optional scan ID for progress tracking.
            pipeline_mode: Pipeline context (basic/asset/vulnerability_audit).
            os_detection:  When True (default), passes -O to Nmap for active
                           OS fingerprinting during port scan.
            custom_ports:  Optional custom ports or ranges to scan (e.g. '22,80,443').
            exclude_ports: Optional ports or ranges to exclude from scan (e.g. '2375,6443').
        """
        self._log(
            f"run_asset_discovery_only → {len(hosts)} hosts, intensity={intensity}, os_detection={os_detection}, custom_ports={custom_ports}, exclude_ports={exclude_ports}"
        )

        try:
            intensity_enum = ScanIntensity(intensity.lower())
        except ValueError:
            intensity_enum = ScanIntensity.NORMAL

        parsed_custom_ports = None
        if custom_ports:
            try:
                from core.utils import InputValidator

                parsed_custom_ports = InputValidator.parse_custom_ports(custom_ports)
            except ValueError as e:
                log.warning("Failed parsing custom ports in orchestrator: %s", e)

        parsed_exclude_ports = None
        if exclude_ports:
            try:
                from core.utils import InputValidator

                parsed_exclude_ports = InputValidator.parse_exclude_ports(exclude_ports)
            except ValueError as e:
                log.warning("Failed parsing exclude ports in orchestrator: %s", e)

        hosts = [self._normalize_host_record(h) for h in hosts]
        custom_exclude = self._parse_exclude_ips(exclude_ips)
        hosts = [
            h
            for h in hosts
            if not self._is_blacklisted(self._get_host_ip(h), custom_exclude)
        ]

        discovery_scan_method = self._infer_discovery_method(hosts)
        target_str = self._hosts_target_string(hosts)
        self.asset_engine.register_discovery_results(
            hosts,
            discovery_method=discovery_scan_method or "adaptive",
            discovery_profile=intensity_enum.value.upper(),
        )
        active_hosts = [h for h in hosts if h.get("is_active", False)]
        # Passive-First filter
        skipped_hosts = []
        if passive_first:
            active_for_scan = []
            for h in active_hosts:
                is_resolved = h.get("device_category") not in (
                    "unknown",
                    None,
                    "",
                ) or h.get("vendor") not in ("N/A", "Unknown", "", None)
                if is_resolved:
                    skipped_hosts.append(h)
                else:
                    active_for_scan.append(h)
            log.info(
                "Passive-first: skipping active port scan for %d hosts: %s",
                len(skipped_hosts),
                [self._get_host_ip(h) for h in skipped_hosts],
            )
        else:
            active_for_scan = active_hosts

        active_count = len(active_for_scan)
        inactive_count = len(hosts) - len(
            active_hosts
        )  # keep total inactive count correct

        if not active_hosts:
            return self._make_empty_phase2(
                hosts,
                len(active_hosts),
                inactive_count,
                intensity_enum,
                discovery_scan_method,
                target_str,
            )

        t0 = time.time()

        # ── SAVE vendor/mac and Phase 1 open_ports BEFORE PortEngine modifies hosts ──────────────
        host_backup = {}
        for host in active_hosts:
            ip = self._get_host_ip(host)
            if ip:
                host_backup[ip] = {
                    "vendor": host.get("vendor", "N/A"),
                    "mac_address": host.get("mac_address", "N/A"),
                    "open_ports": list(host.get("open_ports") or []),
                }

        # ── PortEngine now uses NmapScanner internally ────────────────────
        port_engine = PortEngine(
            intensity=intensity_enum,
            os_detection=os_detection,
            custom_ports=parsed_custom_ports,
            exclude_ports=parsed_exclude_ports,
            exclude_ot_from_nmap=exclude_ot_from_nmap,
        )
        if active_for_scan:
            await port_engine.run(active_for_scan, scan_id=scan_id)  # mutates in-place
            self._apply_os_inference(active_for_scan, ot_enrichment=True)
        if skipped_hosts:
            self._apply_os_inference(skipped_hosts, ot_enrichment=False)

        # ── RESTORE and MERGE vendor, mac, and open_ports from backup ──────────
        # This ensures vendor and Phase 1 enrichment ports are NEVER lost, regardless of PortEngine behavior
        for host in active_hosts:
            ip = self._get_host_ip(host)
            if ip and ip in host_backup:
                backup = host_backup[ip]
                # Always restore vendor/mac if they were present in Phase 1
                if backup["vendor"] != "N/A":
                    host["vendor"] = backup["vendor"]
                if backup["mac_address"] != "N/A":
                    host["mac_address"] = backup["mac_address"]
                    host["mac"] = backup["mac_address"]

                # Merge Phase 1 ports into Phase 2 open_ports
                p1_ports = backup["open_ports"]
                if p1_ports:
                    p2_ports = host.setdefault("open_ports", [])
                    p2_port_nums = {p["port"] for p in p2_ports if p.get("port")}
                    for port_dict in p1_ports:
                        p_num = port_dict.get("port")
                        if p_num and p_num not in p2_port_nums:
                            p2_ports.append(port_dict)
                            # Also ensure registered in port_states dict if present
                            if "port_states" in host:
                                host["port_states"][p_num] = "open"
                                host["port_states"][str(p_num)] = "open"

        # ── Also try to get vendor from asset registry (ONLY for Vulnerability Audit) ────
        # ONLY for Vulnerability Audit pipeline (phases 1+2+3)
        if pipeline_mode == "vulnerability_audit":
            self._preserve_vendor_from_registry(active_hosts)
            self.asset_engine.enrich_port_scan_results(active_hosts)

        duration = time.time() - t0

        formatted = [
            self._format_host(self._get_host_ip(h), h).to_clean_dict() for h in hosts
        ]
        hosts_with_ports = sum(1 for h in formatted if h.get("open_ports"))

        scan_config = port_engine.scan_configuration()
        summary = {
            "total_hosts": len(formatted),
            "active_hosts": active_count,
            "inactive_hosts": inactive_count,
            "hosts_with_ports": hosts_with_ports,
            "scan_duration": duration,
            "phase": 2,
            "scan_type": intensity_enum.value.upper(),
            "discovery_scan_method": discovery_scan_method or "N/A",
            # Recorded on the summary as well as the metadata because only the
            # summary is persisted with the phase: a report regenerated later
            # must still be able to state what the scan covered.
            **scan_config,
        }
        if custom_ports:
            summary["custom_ports"] = custom_ports

        return {
            "success": True,
            "data": formatted,
            "summary": summary,
            "metadata": self._phase2_meta(
                target_str,
                intensity_enum,
                discovery_scan_method,
                scan_config,
            ),
        }

    # ── PHASE 3: Vulnerability Audit / Vulnerability + Risk ─────────────────

    def run_vulnerability_audit_only(
        self,
        hosts: list[dict],
        scan_id: str | None = None,
        exclude_ot_from_nmap: bool = True,
        exclude_ips: str | None = None,
    ) -> dict:
        """
        Phase 3+4 — Vulnerability Scanning + Risk Scoring.

        REFACTORED:
          Before calling VulnerabilityEngine, optionally run NmapScanner.full_scan()
          on each host to upgrade OS detection and service versions.
          This gives plugins (tls_scanner, ssh_probe, etc.) exact version strings
          which dramatically improves CVE matching accuracy.

          The VulnerabilityEngine itself is UNCHANGED.
        """
        self._log(f"run_vulnerability_audit_only → {len(hosts)} hosts")

        hosts = [self._normalize_host_record(h) for h in hosts]
        custom_exclude = self._parse_exclude_ips(exclude_ips)
        hosts = [
            h
            for h in hosts
            if not self._is_blacklisted(self._get_host_ip(h), custom_exclude)
        ]

        discovery_scan_method = self._infer_discovery_method(hosts)
        target_str = self._hosts_target_string(hosts)

        # Register hosts in the unified asset registry and enrich them with Phase 2 port scan results
        self.asset_engine.register_discovery_results(
            hosts,
            discovery_method=discovery_scan_method or "adaptive",
        )
        self.asset_engine.enrich_port_scan_results(hosts)

        active_hosts = [h for h in hosts if h.get("is_active", False)]
        active_count = len(active_hosts)
        inactive_count = len(hosts) - active_count

        if not active_hosts:
            return self._make_empty_phase3(
                hosts,
                active_count,
                inactive_count,
                discovery_scan_method,
                target_str,
            )

        t0 = time.time()

        # ── FIX: Run Nmap enrichment SEQUENTIALLY BEFORE vulnerability scanning ─────
        # Previously these ran in parallel (ThreadPoolExecutor), creating a race
        # condition where vulnerability plugins would probe ports before Nmap had
        # finished writing service/version/banner data — causing empty Product,
        # Version, and Banner fields in results.
        #
        # Nmap runs first to populate host["open_ports"] with accurate service
        # metadata; then VulnerabilityEngine reads that enriched data for
        # reliable CVE correlation.
        self._nmap_pre_enrich(active_hosts, exclude_ot_from_nmap=exclude_ot_from_nmap)
        vuln_engine = VulnerabilityEngine(rate_limit=self.rate_limit)
        vuln_engine.run(active_hosts, scan_id=scan_id)
        self._apply_os_inference(active_hosts, ot_enrichment=True)

        # ── Enrich asset registry with vulnerability findings ───────────────
        self.asset_engine.enrich_vulnerability_findings(active_hosts)

        duration = time.time() - t0

        formatted = [
            self._format_host(self._get_host_ip(h), h).to_phase3_dict() for h in hosts
        ]
        critical = sum(1 for h in formatted if h.get("host_risk_level") == "Critical")
        high = sum(1 for h in formatted if h.get("host_risk_level") == "High")

        summary = {
            "total_hosts": len(formatted),
            "active_hosts": active_count,
            "inactive_hosts": inactive_count,
            "critical_hosts": critical,
            "high_risk_hosts": high,
            "scan_duration": duration,
            "phase": 3,
            "scan_type": "vulnerability_audit",
            "discovery_scan_method": discovery_scan_method or "N/A",
            # Verification totals are recorded on the scan itself. A report
            # rebuilt later from the database reads back only the findings that
            # were kept, so without these it could not state how many
            # candidates were examined to arrive at them.
            "candidates_evaluated": sum(
                int(h.get("candidates_evaluated") or 0) for h in formatted
            ),
            "candidates_suppressed": sum(
                len(h.get("suppressed_cves") or []) for h in formatted
            ),
        }
        return {
            "success": True,
            "data": formatted,
            "summary": summary,
            "metadata": {
                **({} if not target_str else {"target": target_str}),
                "scan_type": "vulnerability_audit",
                **(
                    {}
                    if not discovery_scan_method
                    else {"discovery_scan_method": discovery_scan_method}
                ),
            },
        }

    # ── Nmap pre-enrichment for Phase 3 ──────────────────────────────────────

    @staticmethod
    def _nmap_pre_enrich(hosts: list[dict], exclude_ot_from_nmap: bool = True) -> None:
        """
        Run Nmap OS fingerprinting + service/version upgrade on each active host.
        Uses known open ports from Phase 2 to limit scan scope.

        This is a critical step for the Advanced module — it provides accurate OS
        detection (active fingerprinting) and service version enrichment that feeds
        the SNMP-based device classification.

        If Nmap fails or is unavailable, the host data from Phase 2 is used as-is.
        """
        from core.nmap.wrapper import NMAP_AVAILABLE, NmapScanner

        if not NMAP_AVAILABLE:
            return

        # On Windows, sudo doesn't work — disable it. On Linux/Mac, enable it for SYN scan.
        use_sudo = platform.system() != "Windows"
        scanner = NmapScanner(sudo=use_sudo)

        def _enrich_one_host(host: dict) -> None:
            ip = host.get("ip_address") or host.get("ip")
            if not ip:
                return
            open_port_nums = [p["port"] for p in host.get("open_ports", [])]
            if exclude_ot_from_nmap:
                ot_ports = {
                    502,
                    102,
                    44818,
                    47808,
                    20000,
                    4840,
                    2404,
                    18245,
                    9600,
                    5007,
                    2455,
                }
                open_port_nums = [p for p in open_port_nums if p not in ot_ports]
            if not open_port_nums:
                return
            try:
                result = scanner.full_scan(ip, ports=open_port_nums)
                # Enrich service/version info through the same contract the port
                # engine uses. This wrote `full_version` — the product, version
                # and extra concatenated — straight into the `version` field,
                # which put prose back where a comparable version belongs and
                # bypassed the evidence-ranked merge, so a deeper scan here
                # could silently overwrite a better fingerprint with a worse
                # one and drop the CPE entirely.
                for nmap_port in result.open_ports:
                    version = nmap_port.version or ""
                    record = PortResult(
                        port=nmap_port.port,
                        protocol=nmap_port.protocol or "tcp",
                        state=nmap_port.state or "open",
                        service=nmap_port.service or "",
                        product=nmap_port.product[:255] if nmap_port.product else "",
                        version=version[:200],
                        extra=nmap_port.extra[:255] if nmap_port.extra else "",
                        cpe=list(nmap_port.cpe or []),
                        version_precision=(
                            version_precision(version) if version else "unknown"
                        ),
                        fingerprint_source=(
                            "version_detection"
                            if nmap_port.version
                            else (
                                "service_detection" if nmap_port.product else "banner"
                            )
                        ),
                        banner=(nmap_port.scripts or {}).get("banner", ""),
                    ).to_dict()
                    _record_port(host, record)
                # CRITICAL: Add accurate OS fingerprinting results
                best_os = result.best_os
                if best_os and best_os.accuracy >= 75:
                    # An Nmap TCP/IP fingerprint infers a kernel *range* from
                    # packet behaviour. SNMP sysDescr is the device stating its
                    # exact build. Where the host has told us directly, that
                    # wins — overwriting it reported "Linux 5.0 - 5.14" for a
                    # machine whose own agent said 6.8.0-137-generic.
                    if host.get("os_evidence") == "snmp_sysdescr":
                        host.setdefault("os_guess_nmap", best_os.name)
                    else:
                        host["os_guess"] = best_os.name
                        host["os_confidence"] = fingerprint_os_confidence(
                            best_os.accuracy
                        )
                        host.setdefault("os_evidence", "nmap_fingerprint")
            except Exception as exc:
                log.debug("_nmap_pre_enrich(%s) error: %s", ip, exc)

        if not hosts:
            return

        # We cap workers to avoid memory or network exhaustion
        with ThreadPoolExecutor(max_workers=min(len(hosts), 20)) as pool:
            futures = [pool.submit(_enrich_one_host, h) for h in hosts]
            for f in futures:
                try:
                    f.result()
                except Exception as exc:
                    log.debug("_nmap_pre_enrich error: %s", exc)

    # _run_nmap_and_vuln_parallel removed — replaced by sequential execution
    # in run_vulnerability_audit_only() to eliminate the race condition
    # where vulnerability plugins read empty open_ports before Nmap enrichment completes.

    # ── Preserve vendor from unified asset registry ─────────────────────────

    def _preserve_vendor_from_registry(self, hosts: list[dict]) -> None:
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
    def _parse_exclude_ips(exclude_ips_str: str | None) -> list:
        if not exclude_ips_str:
            return []
        networks = []
        import ipaddress

        for item in exclude_ips_str.split(","):
            item = item.strip()
            if item:
                try:
                    networks.append(ipaddress.ip_network(item, strict=False))
                except ValueError:
                    pass
        return networks

    def apply_scan_scope(self, scope) -> None:
        """Bind this run to an organisation's authorised scan scope (a
        ``ScanScopeView`` from core.scan_scope.org_scan_scope, or None)."""
        from core.scan_scope import scope_for_org

        self.scan_scope = scope_for_org(scope)

    def _drop_out_of_scope(self, ips: list[str]) -> list[str]:
        """
        Remove addresses outside the bound scope.

        Silent trimming is correct *here* and wrong at the API: admission
        rejected the request outright so the operator saw an error, whereas by
        this point the only alternative to trimming is failing a scan that is
        mostly legitimate because one name resolved somewhere unexpected. The
        drop is logged so it is visible after the fact.
        """
        if self.scan_scope is None:
            return ips
        from core.scan_scope import filter_to_scope

        allowed, denied = filter_to_scope(ips, self.scan_scope)
        if denied:
            self._log(
                f"Dropped {len(denied)} address(es) outside the organisation's "
                f"authorised scan scope: {', '.join(denied[:10])}"
                + (" …" if len(denied) > 10 else "")
            )
        return allowed

    @staticmethod
    def _is_blacklisted(ip: str, custom_exclude_list: list | None = None) -> bool:
        import ipaddress

        from config import AppConfig

        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in AppConfig.SCAN_IP_BLACKLIST:
                if ip_obj in network:
                    return True
            if custom_exclude_list:
                for network in custom_exclude_list:
                    if ip_obj in network:
                        return True
        except ValueError:
            pass
        return False

    @staticmethod
    def _expand_targets(
        targets: list[str], custom_exclude_list: list | None = None
    ) -> list[str]:
        """Expand a list of IPs/ranges/subnets into a flat de-duplicated IP list."""
        all_ips = []
        for target in targets:
            res = InputValidator.resolve_target(target)
            if "error" in res:
                continue
            resolved = res["resolved"]
            if "/" in resolved:
                network = ipaddress.ip_network(resolved, strict=False)
                for ip in network.hosts():
                    ip_str = str(ip)
                    if not ScanOrchestrator._is_blacklisted(
                        ip_str, custom_exclude_list
                    ):
                        all_ips.append(ip_str)
            elif "-" in resolved:
                for ip_str in InputValidator.expand_ip_range(resolved):
                    if not ScanOrchestrator._is_blacklisted(
                        ip_str, custom_exclude_list
                    ):
                        all_ips.append(ip_str)
            else:
                if not ScanOrchestrator._is_blacklisted(resolved, custom_exclude_list):
                    all_ips.append(resolved)
        return list(dict.fromkeys(all_ips))  # deduplicate, preserve order

    # ── Helpers (unchanged from original) ────────────────────────────────────

    def _format_host(
        self, ip: str, data: dict, input_hostname: str = None
    ) -> HostResult:
        """
        Resolve hostname with live-source priority over stale DNS.

        Priority order (highest → lowest):
          1. NetBIOS computer name   — from nbns.py / enrichment._netbios_query()
          2. mDNS local name         — from enrichment._mdns_query()
          3. hostname already in data — set by nbns technique during discovery
          4. DNS PTR (last resort)   — socket.gethostbyaddr() — may be stale
          5. input_hostname argument
          6. "Unknown"
        """
        ip = ip or self._get_host_ip(data)
        is_active = data.get("is_active", False)
        hostname = "Unknown"

        if is_active and ip:
            # ── 1. NetBIOS computer name (live UDP-137 response from target) ──
            netbios_name = data.get("netbios_computer") or ""
            if not netbios_name:
                # Also scan netbios_names list for the workstation entry
                for entry in data.get("netbios_names", []):
                    if isinstance(entry, dict) and not (
                        entry.get("flags", 0xFFFF) & 0x8000
                    ):
                        netbios_name = entry.get("name", "")
                        break

            if netbios_name and netbios_name not in ("Unknown", ""):
                hostname = netbios_name

            # ── 2. mDNS local name (unicast .local PTR response from target) ──
            elif data.get("mdns_name") and data["mdns_name"] not in ("Unknown", ""):
                hostname = data["mdns_name"]

            # ── 3. hostname already set by discovery engine ───────────────────
            elif data.get("hostname") and data["hostname"] not in (
                "Unknown",
                "",
                "N/A",
            ):
                hostname = data["hostname"]

            # ── 4. DNS PTR — last resort (may be stale) ───────────────────────
            else:
                try:
                    dns_name = socket.gethostbyaddr(ip)[0]
                    if dns_name and dns_name != ip:
                        hostname = dns_name
                        log.debug(
                            "_format_host(%s): DNS PTR used as fallback → %s "
                            "(NetBIOS/mDNS returned nothing — result may be stale)",
                            ip,
                            dns_name,
                        )
                    else:
                        hostname = input_hostname or "Unknown"
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

        vendor = data.get("vendor", "N/A")
        if vendor in ("", "Unknown", "N/A", None) and mac and mac != "N/A":
            vendor = lookup_vendor(mac) or "N/A"

        confs = data.get("confirmations", [])
        confidence = (
            "High"
            if len(confs) >= 2 or "ARP" in confs
            else "Medium" if len(confs) == 1 else "Low"
        )
        if not is_active:
            confidence = "N/A"

        return HostResult(
            ip_address=ip or "",
            hostname=hostname,
            mac_address=mac,
            vendor=vendor,
            is_active=is_active,
            status="Active" if is_active else "Inactive",
            scan_method=data.get("method") or data.get("scan_method") or "N/A",
            response_time_ms=data.get("elapsed_ms") or data.get("response_time_ms"),
            open_ports=data.get("open_ports", []),
            os_guess=data.get("os_guess", "Unknown"),
            os_confidence=data.get("os_confidence", "Low"),
            os_version=data.get("os_version"),
            os_evidence=data.get("os_evidence"),
            confidence=confidence,
            device_category=data.get("device_category", "unknown"),
            snmp_device_type=data.get("snmp_device_type"),
            mdns_name=data.get("mdns_name"),
            netbios_names=data.get("netbios_names", []),
            os_fingerprint_full=data.get("os_fingerprint_full", {}),
            tcp_fingerprint=data.get("tcp_fingerprint", {}),
            port_states=data.get("port_states", {}),
            tls_info=data.get("tls_info", {}),
            http_audit=data.get("http_audit", {}),
            snmp_info=data.get("snmp_info", {}),
            smb_info=data.get("smb_info", {}),
            ssh_info=data.get("ssh_info", {}),
            udp_services=data.get("udp_services", []),
            cves=data.get("cves", []),
            # Verification metadata travels with the host record. Dropping it
            # here would leave the stored scan with verified findings and no
            # account of what was ruled out, which is the one thing the
            # report's methodology appendix cannot reconstruct on its own.
            suppressed_cves=data.get("suppressed_cves", []),
            vulnerability_counts=data.get("vulnerability_counts", {}),
            candidates_evaluated=data.get("candidates_evaluated", 0),
            host_risk_score=data.get("host_risk_score", 0),
            host_risk_level=data.get("host_risk_level", "Info"),
            _ot_probed=data.get("_ot_probed", False),
        )

    @staticmethod
    def _get_host_ip(host: dict) -> str | None:
        return host.get("ip_address") or host.get("ip")

    @staticmethod
    def _normalize_mac(value) -> str | None:
        """
        Render a MAC in one canonical form: lowercase, colon-separated.

        Different probes returned different casing, so the same table could
        show '2c:58:b9:15:74:70' next to '2C:58:B9:87:0B:B3' — and any caller
        matching MACs as strings saw two devices where there was one.
        """
        if not value:
            return value
        text = str(value).strip()
        if text.upper() in ("N/A", "UNKNOWN", "NONE", ""):
            return text
        return text.replace("-", ":").lower()

    def _normalize_host_record(self, host: dict) -> dict:
        norm = dict(host)
        ip = self._get_host_ip(norm)
        if ip:
            norm["ip"] = ip
            norm["ip_address"] = ip
        if "mac" not in norm and "mac_address" in norm:
            norm["mac"] = norm["mac_address"]
        if "mac_address" not in norm and "mac" in norm:
            norm["mac_address"] = norm["mac"]
        for key in ("mac", "mac_address"):
            if norm.get(key):
                norm[key] = self._normalize_mac(norm[key])
        if "method" not in norm:
            norm["method"] = (
                norm.get("scan_method") or norm.get("discovery_method") or "N/A"
            )
        return norm

    @staticmethod
    def _normalize_scan_method(value) -> str | None:
        if not value:
            return None
        token = str(value).strip().upper()
        if not token or token in {"N/A", "UNKNOWN", "NONE"}:
            return None
        for key, label in [
            ("ADAPTIVE", "ADAPTIVE"),
            ("STEALTH", "STEALTH"),
            ("FULL", "FULL"),
            ("ARP", "ARP"),
            ("PING", "PING"),
            ("ICMP", "PING"),
            ("TCP", "TCP"),
        ]:
            if key in token:
                return label
        return None

    def _infer_discovery_method(self, hosts: list[dict]) -> str | None:
        methods = []
        for host in hosts:
            raw = (
                host.get("method")
                or host.get("scan_method")
                or host.get("discovery_method")
            )
            m = self._normalize_scan_method(raw)
            if m:
                methods.append(m)
        if not methods:
            return None
        return Counter(methods).most_common(1)[0][0]

    def _hosts_target_string(self, hosts: list[dict]) -> str | None:
        ips = []
        for h in hosts:
            ip = self._get_host_ip(h)
            if ip and ip not in ips:
                ips.append(ip)
        return ", ".join(ips) if ips else None

    @staticmethod
    def _apply_os_inference(hosts: list[dict], ot_enrichment: bool = False) -> None:
        from concurrent.futures import ThreadPoolExecutor

        from core.device_classifier import classify_device
        from core.discovery.enrichment import _ot_protocol_probes

        active_hosts = [h for h in hosts if h.get("is_active")]
        if active_hosts and ot_enrichment:

            def _probe_host(host: dict) -> None:
                ip = host.get("ip_address") or host.get("ip")
                if ip:
                    try:
                        _ot_protocol_probes(ip, host)
                    except Exception:
                        pass

            with ThreadPoolExecutor(max_workers=min(len(active_hosts), 20)) as pool:
                pool.map(_probe_host, active_hosts)

        for host in hosts:
            guess, conf = infer_os_from_host(host)
            if host.get("os_guess", "Unknown") == "Unknown":
                host["os_guess"] = guess
                host["os_confidence"] = conf
            classify_device(host)

    def _log(self, msg: str) -> None:
        if not self.silent:
            log.info(msg)

    def generate_phase_report(self, resp: dict, scan_type: str) -> dict[str, str]:
        if not self._pdf:
            return {}
        try:
            return self._pdf.generate(resp, scan_type)
        except Exception as exc:
            self._log(f"[WARN] PDF generation failed: {exc}")
            return {}

    # ── Empty result builders ─────────────────────────────────────────────────

    def _make_empty_phase2(self, hosts, active, inactive, intensity, dsm, target):
        formatted = [
            self._format_host(self._get_host_ip(h), h).to_clean_dict() for h in hosts
        ]
        return {
            "success": True,
            "data": formatted,
            "summary": {
                "total_hosts": len(formatted),
                "active_hosts": active,
                "inactive_hosts": inactive,
                "hosts_with_ports": 0,
                "scan_duration": 0,
                "phase": 2,
                "scan_type": intensity.value.upper(),
                "discovery_scan_method": dsm or "N/A",
            },
            "metadata": self._phase2_meta(target, intensity, dsm),
        }

    def _make_empty_phase3(self, hosts, active, inactive, dsm, target):
        formatted = [
            self._format_host(self._get_host_ip(h), h).to_clean_dict() for h in hosts
        ]
        return {
            "success": True,
            "data": formatted,
            "summary": {
                "total_hosts": len(formatted),
                "active_hosts": active,
                "inactive_hosts": inactive,
                "critical_hosts": 0,
                "high_risk_hosts": 0,
                "scan_duration": 0,
                "phase": 3,
                "scan_type": "vulnerability_audit",
                "discovery_scan_method": dsm or "N/A",
            },
            "metadata": {
                **({} if not target else {"target": target}),
                "scan_type": "vulnerability_audit",
            },
        }

    @staticmethod
    def _phase2_meta(target, intensity, dsm, scan_config: dict | None = None) -> dict:
        d = {"scan_intensity": intensity.value.upper()}
        if target:
            d["target"] = target
        if dsm:
            d["discovery_scan_method"] = dsm
            d["scan_method"] = dsm
        # What the scan actually examined. Recorded from the engine that ran it
        # so the report can bound its own coverage instead of stating "not
        # recorded" against every parameter — or defaulting to a claim.
        if scan_config:
            d.update(scan_config)
        return d
