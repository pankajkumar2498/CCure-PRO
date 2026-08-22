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

Compliance has its own DOCX/PDF generators inside ``routers/compliance.py`` and
is not part of this package.
"""
