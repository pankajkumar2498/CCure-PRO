"""
core/vuln_intel_repository.py
─────────────────────────────────────────────────────────────────────────────
The vulnerability-intelligence database, as the credentialed version matcher
reads it (G3, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md): the engine to
connect with, the SQL construct its queries are written in, and the errors a
failed query raises.

The matcher used to build the engine itself and import SQLAlchemy for the
other two, so a library that matches package versions loaded the database
layer. It is handed this now; Audit's composition root registers it
(``ccure_audit/engine_ports.py``).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


class VulnIntelRepository:
    #: What a failed query raises.
    errors = (SQLAlchemyError,)

    def __init__(self, engine: Any = None):
        self._engine = engine

    @property
    def engine(self) -> Any:
        """The engine, built at the first use, as ``get_vuln_engine`` always
        has been: it is a process-wide singleton."""
        if self._engine is None:
            from core.vuln_intel import get_vuln_engine

            self._engine = get_vuln_engine()
        return self._engine

    @staticmethod
    def sql(statement: str) -> Any:
        return text(statement)


REPOSITORY = VulnIntelRepository()
