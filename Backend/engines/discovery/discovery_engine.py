"""
engines/discovery/discovery_engine.py  — Backward-Compatibility Shim
────────────────────────────────────────────────────────────────────────────
MIGRATION SHIM — do not modify the logic here.

The original DiscoveryEngine class has been split across:
  core/discovery/engine.py        ← new orchestrating engine
  core/discovery/profiles.py      ← FAST / BALANCED / AGGRESSIVE profiles
  core/discovery/techniques/      ← one module per technique

This shim wraps the new engine to preserve all existing import paths:

  # All of these still work — zero changes required in callers:
  from engines.discovery.discovery_engine import DiscoveryEngine
  from engines.discovery.discovery_engine import DiscoveryEngine as DE

The shim translates the original DiscoveryScanType enum → DiscoveryProfile
mapping so the ScanOrchestrator's backward-compatible scan_single_host()
and scan_subnet() methods continue to work without modification.

You may remove this shim once you have fully migrated all callers to use:
  from core.discovery.engine import DiscoveryEngine
  from core.discovery.profiles import BALANCED, get_profile
"""

import logging
from typing import Dict, List, Optional

# ── New implementation ────────────────────────────────────────────────────────
from core.discovery.engine import DiscoveryEngine as _NewDiscoveryEngine
from core.discovery.profiles import (
    FAST, BALANCED, AGGRESSIVE, DiscoveryProfile, get_profile
)
from core.models import DiscoveryScanType

log = logging.getLogger("ccure.discovery.shim")

# ── scan_type string → DiscoveryProfile ──────────────────────────────────────
_SCAN_TYPE_TO_PROFILE: Dict[str, DiscoveryProfile] = {
    # New pipeline modes
    "fast":       FAST,
    "basic":      FAST,
    "balanced":   BALANCED,
    "asset":      BALANCED,
    "aggressive": AGGRESSIVE,
    "advanced":   AGGRESSIVE,
    "vulnerability_audit": AGGRESSIVE,
    # Legacy DiscoveryScanType values
    "ping":       BALANCED,    # ICMP → BALANCED covers it
    "arp":        FAST,        # ARP only → FAST is appropriate
    "tcp":        BALANCED,    # TCP SYN → BALANCED
    "full":       AGGRESSIVE,  # All techniques → AGGRESSIVE
    "adaptive":   BALANCED,    # Adaptive heuristic → BALANCED
    "stealth":    AGGRESSIVE,  # Stealth → AGGRESSIVE (includes stealth escalation)
}


class DiscoveryEngine:
    """
    Backward-compatible shim around the new core.discovery.engine.DiscoveryEngine.

    Accepts all original constructor parameters but routes to the new
    profile-driven implementation. New code should import directly from
    core.discovery.engine and core.discovery.profiles instead.

    Original constructor signature (preserved):
        DiscoveryEngine(
            has_privileges=False,
            stealth_mode=False,
            timing_level=3,
            scan_technique="syn",
            decoy_count=0,
            source_port=None,
            fragment_mtu=None,
            randomize_ports=False,
            enable_l2_sniffer=False,
        )

    Original run() signature (preserved):
        async def run(ip_list, scan_type=DiscoveryScanType.ADAPTIVE) -> List[Dict]
    """

    def __init__(
        self,
        has_privileges:    bool = False,
        stealth_mode:      bool = False,
        timing_level:      int  = 3,
        scan_technique:    str  = "syn",
        decoy_count:       int  = 0,
        source_port:       Optional[int] = None,
        fragment_mtu:      Optional[int] = None,
        randomize_ports:   bool = False,
        enable_l2_sniffer: bool = False,
        # New optional parameter — callers can pass profile directly
        profile:           Optional[DiscoveryProfile] = None,
    ):
        self._has_privileges = has_privileges
        self._stealth_mode   = stealth_mode
        self._profile        = profile  # kept None until run() selects per scan_type

        if stealth_mode:
            log.debug(
                "DiscoveryEngine shim: stealth_mode=True → AGGRESSIVE profile "
                "with auto-escalation enabled."
            )

    async def run(
        self,
        ip_list:   List[str],
        scan_type: "DiscoveryScanType | str" = DiscoveryScanType.ADAPTIVE,
    ) -> List[Dict]:
        """
        Drop-in replacement for the original DiscoveryEngine.run().

        Translates scan_type (DiscoveryScanType enum or string) → DiscoveryProfile
        and delegates to the new implementation.
        """
        # Resolve scan_type to a profile
        if self._profile is not None:
            profile = self._profile
        else:
            scan_type_str = (
                scan_type.value if isinstance(scan_type, DiscoveryScanType)
                else str(scan_type).lower()
            )
            # Stealth mode always escalates to AGGRESSIVE
            if self._stealth_mode:
                profile = AGGRESSIVE
            else:
                profile = _SCAN_TYPE_TO_PROFILE.get(scan_type_str, BALANCED)

        log.debug(
            "DiscoveryEngine shim: scan_type=%s → profile=%s (%d IPs)",
            scan_type, profile.name, len(ip_list),
        )

        engine = _NewDiscoveryEngine(
            profile        = profile,
            has_privileges = self._has_privileges,
            stealth_mode   = self._stealth_mode,
        )
        return await engine.run(ip_list)
