"""
core/discovery/profiles.py
────────────────────────────────────────────────────────────────────────────
Discovery Profile Definitions

Maps the three named profiles required by the architecture spec to
the concrete technique combinations used by DiscoveryEngine.

  Profile     | Used By            | Scan Type (internal)
  ─────────────────────────────────────────────────────────
  FAST        | Basic Network Scan | ARP (LAN) + TCP fallback only
  BALANCED    | Asset Discovery    | ARP + ICMP + TCP SYN + UDP probes
  AGGRESSIVE  | Advanced Scan      | All techniques + retry logic + NetBIOS

Each profile specifies:
  - techniques: ordered list of Technique enum values
  - timeout: per-probe timeout in seconds
  - retries: how many times to retry failed probes
  - concurrency: semaphore size for async probes
  - enrichment: whether to run SNMP/mDNS/NetBIOS after discovery
  - stealth_auto: whether to auto-escalate to stealth on hostile networks

Design constraint:
  Host discovery MUST use Scapy only (not Nmap).
  Nmap is only used in Phase 2 (port scanning) and Phase 3 (vuln scan).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Technique(Enum):
    """Available discovery techniques (maps to technique modules)."""
    ARP       = "arp"        # L2 broadcast — fastest LAN probe
    ICMP      = "icmp"       # ICMP echo + timestamp — TTL for OS hint
    TCP_SYN   = "tcp_syn"    # Raw TCP SYN — Scapy, needs root
    TCP_CONN  = "tcp_conn"   # Async TCP connect — no root needed
    UDP_PROBE = "udp_probe"  # DNS/SNMP/NTP/DHCP UDP probes
    NBNS      = "nbns"       # NetBIOS Name Service (UDP 137)


@dataclass
class DiscoveryProfile:
    """
    A complete host-discovery configuration used by DiscoveryEngine.

    Attributes:
        name:           Human-readable profile name.
        techniques:     Ordered list of Technique values to apply per host.
                        Techniques run in order; earlier techniques that
                        confirm a host skip remaining techniques for that IP.
        timeout:        Per-probe network timeout in seconds.
        retries:        Number of retries for unanswered probes.
        concurrency:    Async semaphore / thread pool size.
        enrichment:     Run SNMP / mDNS / NetBIOS after discovery.
        stealth_auto:   Auto-escalate to stealth mode when hostile net detected.
        description:    What this profile is for.
    """
    name:         str
    techniques:   List[Technique]
    timeout:      float
    retries:      int
    concurrency:  int
    enrichment:   bool
    stealth_auto: bool
    description:  str = ""

    # LAN-only zone separation: some profiles probe LAN vs routed/WAN differently
    separate_lan_wan: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Profile definitions
# ─────────────────────────────────────────────────────────────────────────────

FAST = DiscoveryProfile(
    name        = "FAST",
    description = (
        "Basic Network Scan — Phase 1 only pipeline. "
        "Uses a single probe per host zone with no fallback chains. "
        "LAN: ARP broadcast. Non-LAN: TCP connect on ports 80/443/22. "
        "Ideal for quick /24 sweeps. May miss hosts behind strict firewalls."
    ),
    techniques  = [Technique.ARP, Technique.TCP_CONN],
    timeout     = 0.8,
    retries     = 0,     # no retries — speed first
    concurrency = 256,   # high for async TCP connect
    enrichment  = False, # skip SNMP/mDNS/NetBIOS — speed priority
    stealth_auto = False,
    separate_lan_wan = True,
)

BALANCED = DiscoveryProfile(
    name        = "BALANCED",
    description = (
        "Asset Discovery — Phase 1+2 pipeline. "
        "Combines ARP + ICMP + TCP SYN + UDP to maximize host detection "
        "while keeping scan time reasonable. "
        "LAN: ARP → ICMP fallback → UDP broadcast. "
        "Routed: ICMP → TCP SYN on enterprise ports. "
        "Internet: TCP SYN on web ports only. "
        "Enrichment: PTR/mDNS/NetBIOS disabled (Phase 2 Nmap covers this)."
    ),
    techniques  = [Technique.ARP, Technique.ICMP, Technique.TCP_SYN, Technique.UDP_PROBE],
    timeout     = 1.5,
    retries     = 1,
    concurrency = 100,
    enrichment  = False,   # Phase 2 Nmap handles service detection
    stealth_auto = False,
    separate_lan_wan = True,
)

AGGRESSIVE = DiscoveryProfile(
    name        = "AGGRESSIVE",
    description = (
        "Advanced Scan — Phase 1+2+3 pipeline. "
        "Runs all techniques including NetBIOS name resolution and SNMP. "
        "LAN: ARP + ICMP + TCP SYN + UDP + NetBIOS. "
        "Routed: ICMP + TCP SYN (all management ports) + UDP. "
        "Internet: TCP SYN (full web + management range). "
        "Includes enrichment (SNMP/mDNS/NetBIOS) for device classification. "
        "Hostile-environment auto-escalation to stealth is enabled."
    ),
    techniques  = [
        Technique.ARP,
        Technique.ICMP,
        Technique.TCP_SYN,
        Technique.UDP_PROBE,
        Technique.NBNS,
    ],
    timeout     = 2.0,
    retries     = 2,
    concurrency = 50,    # lower: more thorough per-host, less blast radius
    enrichment  = True,  # run SNMP/mDNS/NetBIOS on active hosts
    stealth_auto = True, # auto-escalate when IDS detected
    separate_lan_wan = True,
)


# ── Registry ─────────────────────────────────────────────────────────────────

_PROFILES = {
    "fast":       FAST,
    "balanced":   BALANCED,
    "aggressive": AGGRESSIVE,
    # Pipeline mode aliases
    "basic":      FAST,
    "asset":      BALANCED,
    "advanced":   AGGRESSIVE,
}


def get_profile(name: str) -> DiscoveryProfile:
    """
    Return the DiscoveryProfile for a given name.

    Accepts both profile names and pipeline mode aliases:
      "fast" | "basic"     → FAST
      "balanced" | "asset" → BALANCED
      "aggressive" | "advanced" → AGGRESSIVE

    Falls back to BALANCED for unknown names.
    """
    key = name.lower().strip() if name else "balanced"
    profile = _PROFILES.get(key)
    if profile is None:
        import logging
        logging.getLogger("ccure.profiles").warning(
            "Unknown discovery profile '%s' — defaulting to BALANCED.", name
        )
        profile = BALANCED
    return profile


def profile_for_pipeline(pipeline_mode: str) -> DiscoveryProfile:
    """
    Map a pipeline_mode string (from the API) to a DiscoveryProfile.

      "basic"    → FAST       (Host Discovery only)
      "asset"    → BALANCED   (Host Discovery + Asset Discovery)
      "advanced" → AGGRESSIVE (Full pipeline)
    """
    mapping = {
        "basic":    FAST,
        "asset":    BALANCED,
        "advanced": AGGRESSIVE,
    }
    return mapping.get(pipeline_mode.lower(), BALANCED)
