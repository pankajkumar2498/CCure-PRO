"""
core/discovery — Profile-driven Scapy host discovery.

Primary entry points:
  from core.discovery.engine   import DiscoveryEngine
  from core.discovery.profiles import FAST, BALANCED, AGGRESSIVE, get_profile
"""
from core.discovery.engine   import DiscoveryEngine
from core.discovery.profiles import (
    FAST, BALANCED, AGGRESSIVE,
    DiscoveryProfile, get_profile, profile_for_pipeline,
)

__all__ = [
    "DiscoveryEngine",
    "DiscoveryProfile",
    "FAST", "BALANCED", "AGGRESSIVE",
    "get_profile", "profile_for_pipeline",
]
