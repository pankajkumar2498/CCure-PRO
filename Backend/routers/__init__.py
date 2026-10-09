# routers/__init__.py — Package marker for FastAPI router modules.


def __getattr__(name):
    """A submodule moved to ``ccure_platform`` and imported under its new name
    first is in ``sys.modules`` but not yet an attribute here (backend
    alignment, step 2; see ``ccure_platform/_legacy.py``)."""
    import sys

    module = sys.modules.get(f"{__name__}.{name}")
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return module
