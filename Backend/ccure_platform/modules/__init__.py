"""
The CCure module registry (Phase 11): which modules the core service hosts and
what each contributes. A leaf — see ``registry.py``.
"""

from ccure_platform.modules.manifest import (
    PRODUCT_KINDS,
    TILE_STATES,
    ManifestError,
    ModuleManifest,
    Product,
    ServiceProduct,
)
from ccure_platform.modules.registry import (
    enabled_modules,
    get,
    modules,
    mount_module_routers,
    products,
    queues,
    services,
    task_modules,
)

__all__ = [
    "PRODUCT_KINDS",
    "TILE_STATES",
    "ManifestError",
    "ModuleManifest",
    "Product",
    "ServiceProduct",
    "enabled_modules",
    "get",
    "modules",
    "mount_module_routers",
    "products",
    "queues",
    "services",
    "task_modules",
]
