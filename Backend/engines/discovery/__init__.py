"""
engines/discovery — Backward-compatibility shim package.

Primary entry point for callers that still use the old import path:
    from engines.discovery.discovery_engine import DiscoveryEngine

New code should import directly from core:
    from core.discovery.engine import DiscoveryEngine
    from core.discovery.profiles import FAST, BALANCED, AGGRESSIVE
"""

from engines.discovery.discovery_engine import DiscoveryEngine

__all__ = ["DiscoveryEngine"]
