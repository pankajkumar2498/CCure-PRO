"""
Whether PDF report generation is available in this runtime.

Moved here from ``core/constants.py`` (Phase 3 of the modular-platform
programme). The check imports ``reporting.pdf_generator``, and making it at
import time of the shared constants module meant *every* importer of a port
list or a lookup table also loaded the PDF generator — and through it the
scans and credentialed-engine packages. Importing the discovery engine loaded
the report renderer.

The value is unchanged: True exactly when ``reporting.pdf_generator`` imports.
"""

try:
    from reporting.pdf_generator import ScanReportGenerator  # noqa: F401

    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
