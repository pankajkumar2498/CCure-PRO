"""
Report generators.

Four modules that turn scan and web-scan results into deliverables: the
executive and technical PDFs, the host-inventory CSV, and the shared ReportLab
helpers both PDF generators use.

They used to sit loose at the ``Backend/`` root beside ``main.py`` and
``config.py``, which put four presentation modules in the package's entry-point
directory and left no way to tell at a glance which top-level files were
application wiring and which were reporting.

Note the deliberate name. ``Backend/reports/`` already exists and is the
*runtime output directory* for generated PDFs — it is bind-mounted into the API
container by ``docker-compose.yml``. Code lives in ``reporting/``; artefacts land
in ``reports/``.

Compliance's DOCX/PDF documents are rendered by ``reporting/compliance/`` (G6),
from the controls and verdicts the compliance routes read.
"""


def __getattr__(name):
    """A submodule moved to ``ccure_platform`` and imported under its new name
    first is in ``sys.modules`` but not yet an attribute here (backend
    alignment, step 2; see ``ccure_platform/_legacy.py``)."""
    import sys

    module = sys.modules.get(f"{__name__}.{name}")
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return module
