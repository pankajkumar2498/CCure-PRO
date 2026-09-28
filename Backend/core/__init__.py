"""Shared capabilities. Some modules here are aliases of code that moved to
``ccure_platform`` (``ccure_platform/_legacy.py``)."""


def __getattr__(name):
    """A submodule moved to ``ccure_platform`` and imported under its new name
    first is in ``sys.modules`` but not yet an attribute here (Phase 8.3)."""
    import sys

    module = sys.modules.get(f"{__name__}.{name}")
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return module
