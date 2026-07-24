"""
api/host_discovery_api.py
--------------------------
HostDiscoveryAPI - public interface.

Exactly mirrors the interface from host_discovery_api.py so callers
require zero changes.  All heavy lifting lives in ScanOrchestrator.
"""

import logging
import os
from typing import Optional

from core.constants import PDF_AVAILABLE, SCAPY_AVAILABLE
from core.models import DiscoveryScanType, ScanIntensity
from core.utils import PrivilegeManager
from orchestrator.scan_orchestrator import ScanOrchestrator

log = logging.getLogger("ccure")


class HostDiscoveryAPI:
    """
    High-level scan API.

    Examples::

        api = HostDiscoveryAPI(silent=False, intensity="deep")
        result = api.scan_single_host("10.180.1.1", scan_type="adaptive")
        result = api.scan_subnet("10.180.5.0/24")
    """

    def __init__(
        self,
        silent: bool = True,
        reports_dir: str | None = None,
        intensity: str = "normal",
        rate_limit: float = 200.0,
        stealth_mode: bool = False,
    ):
        if not SCAPY_AVAILABLE:
            log.warning("Scapy not found. Raw-socket scans disabled. TCP-only mode.")

        if reports_dir is None or reports_dir == "reports":
            backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            reports_dir = os.path.join(backend_dir, "reports")

        self._orch = ScanOrchestrator(
            silent=silent,
            reports_dir=reports_dir,
            intensity=intensity,
            rate_limit=rate_limit,
            stealth_mode=stealth_mode,
        )
        # Expose for callers that read these directly
        self.platform = self._orch.platform
        self.has_privileges = self._orch.has_priv
        self.intensity = self._orch.intensity
        self.silent = silent

    # ------------------------------------------------------------------
    # System info
    # ------------------------------------------------------------------

    def get_system_info(self) -> dict:
        return {
            "platform": self.platform,
            "privileges": PrivilegeManager.info(),
            "scanner_runtime": os.getenv("SCANNER_RUNTIME", "unknown"),
            "scapy": {"installed": SCAPY_AVAILABLE},
            "pdf": {"installed": PDF_AVAILABLE},
            "scan_types": [s.value for s in DiscoveryScanType],
            "intensities": [s.value for s in ScanIntensity],
            "version": "1.0",
            # "pro_features": [
            #     "TLS/SSL Certificate Inspector",
            #     "HTTP Security Header Audit",
            #     "SSH Algorithm Negotiation Parser",
            #     "SMB/NetBIOS Probe (no smb lib)",
            #     "SNMP Community String Check (no pysnmp)",
            #     "UDP Service Discovery (DNS/NTP/TFTP)",
            #     "ICMP Timestamp Probe",
            #     "Enhanced OS Fingerprinting (TTL + Window)",
            #     "CVE Hint Intelligence (local DB, 30+ entries)",
            #     "Port Risk Scoring (Critical -> Info)",
            #     "Host Risk Score (0-100, CVSS-weighted)",
            #     "Rate-Limiting / Token Bucket",
            #     "Stealth Mode (packet fragmentation)",
            #     "Service Version Extraction (regex)",
            #     "Plugin architecture (drop-in new probes)",
            # ],
        }

    # ------------------------------------------------------------------
    # Scan methods (thin wrappers - all logic in orchestrator)
    # ------------------------------------------------------------------

    async def scan_single_host(self, target: str, scan_type: str = "adaptive") -> dict:
        return await self._orch.scan_single_host(target, scan_type)

    async def scan_ip_range(self, target: str, scan_type: str = "adaptive") -> dict:
        return await self._orch.scan_ip_range(target, scan_type)

    async def scan_subnet(self, target: str, scan_type: str = "adaptive") -> dict:
        return await self._orch.scan_subnet(target, scan_type)

    async def scan_subnets_of_subnet(
        self,
        target: str,
        subnet_prefix: int = 24,
        scan_type: str = "adaptive",
    ) -> dict:
        return await self._orch.scan_subnets_of_subnet(target, subnet_prefix, scan_type)
