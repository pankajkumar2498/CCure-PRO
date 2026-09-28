"""
Legacy path of identity's code, which moved to ``ccure_platform.identity``
and ``ccure_platform.rbac`` in Phase 8.2. Every ``auth.<module>`` is an alias
of the moved module (``ccure_platform/_legacy.py``). New code imports
``ccure_platform.api``.
"""


def __getattr__(name):
    """A submodule moved to ``ccure_platform`` and imported under its new name
    first is in ``sys.modules`` but not yet an attribute here (Phase 8.2)."""
    import sys

    module = sys.modules.get(f"{__name__}.{name}")
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return module
