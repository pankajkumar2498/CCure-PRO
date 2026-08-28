"""
core/config_audit/collectors
─────────────────────────────────────────────────────────────────────────────
Platform collectors, and the one place they are registered.

Registration happens here rather than at each class definition so that
importing a collector module for inspection — a test, a REPL, the API process
listing supported check types — cannot have the side effect of half-populating
a global registry. :func:`register_builtin_collectors` is idempotent, so the
package can be imported from several worker threads during lazy loading
without either racing to register the same pair or raising the duplicate error
that guards against two collectors claiming one check type.
"""

from __future__ import annotations

import threading

from core.config_audit.collectors.base import (
    Collector,
    CollectorRegistry,
    ShellOutput,
    ShellRunner,
    collector_registry,
)
from core.config_audit.collectors.linux import register_linux_collectors
from core.config_audit.collectors.privilege_linux import (
    register_linux_privilege_collector,
)
from core.config_audit.collectors.privilege_windows import (
    register_windows_privilege_collector,
)
from core.config_audit.collectors.windows import register_windows_collectors

__all__ = [
    "Collector",
    "CollectorRegistry",
    "ShellOutput",
    "ShellRunner",
    "collector_registry",
    "register_builtin_collectors",
    "register_linux_collectors",
    "register_linux_privilege_collector",
    "register_windows_collectors",
    "register_windows_privilege_collector",
]

_REGISTRATION_LOCK = threading.Lock()
_registered = False


def register_builtin_collectors(registry: CollectorRegistry | None = None) -> None:
    """
    Populate *registry* with the Windows and Linux collectors.

    Against the process-wide registry this runs exactly once. Against a
    caller-supplied registry it runs every time, which is what lets a test
    build an isolated registry without disturbing the shared one.
    """
    global _registered
    if registry is not None and registry is not collector_registry:
        register_windows_collectors(registry)
        register_linux_collectors(registry)
        register_windows_privilege_collector(registry)
        register_linux_privilege_collector(registry)
        return
    with _REGISTRATION_LOCK:
        if _registered:
            return
        register_windows_collectors(collector_registry)
        register_linux_collectors(collector_registry)
        register_windows_privilege_collector(collector_registry)
        register_linux_privilege_collector(collector_registry)
        _registered = True
