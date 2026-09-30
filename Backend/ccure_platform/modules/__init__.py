"""
The CCure module registry (Phase 11): which modules the core service hosts and
what each contributes. A leaf — see ``registry.py``.
"""

from ccure_platform.modules.manifest import TILE_STATES, ManifestError, ModuleManifest
from ccure_platform.modules.registry import (
    enabled_modules,
    get,
    modules,
    mount_module_routers,
    queues,
    task_modules,
)

__all__ = [
    "TILE_STATES",
    "ManifestError",
    "ModuleManifest",
    "enabled_modules",
    "get",
    "modules",
    "mount_module_routers",
    "queues",
    "task_modules",
]
