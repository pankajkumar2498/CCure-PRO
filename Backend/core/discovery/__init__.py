"""
core/discovery — Profile-driven Scapy host discovery.

Primary entry points:
  from core.discovery.engine   import DiscoveryEngine
  from core.discovery.profiles import FAST, BALANCED, AGGRESSIVE, get_profile
"""

from core.discovery.engine import DiscoveryEngine
from core.discovery.profiles import (
    AGGRESSIVE,
    BALANCED,
    FAST,
    DiscoveryProfile,
    get_profile,
    profile_for_pipeline,
)

__all__ = [
    "AGGRESSIVE",
    "BALANCED",
    "FAST",
    "DiscoveryEngine",
    "DiscoveryProfile",
    "get_profile",
    "profile_for_pipeline",
]
