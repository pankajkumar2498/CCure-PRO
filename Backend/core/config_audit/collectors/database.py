"""
core/config_audit/collectors/database.py
─────────────────────────────────────────────────────────────────────────────
The ``database_query`` collector — reads configuration and catalogue state from
an authenticated database session. Phase 7 of the gap-closure programme,
closing GAP-10.

Phase 3 declared ``database_query`` as a check type and ``database`` as a
platform with no collector behind either, so a rule using them reported ERROR:
"this product cannot perform that check". This module is that collector. The
engine, the operator vocabulary, the four collection states, ``AbsencePolicy``,
the evidence record and the finding path are all unchanged — a database check
is an ordinary :class:`ConfigCheck`, and its failure becomes an ordinary
``StandardizedFinding`` in the same ``cve_list`` as everything else.

Two result shapes, and the second is why this is not just "run a query"
──────────────────────────────────────────────────────────────────────
``scalar``
    One row, one value, compared against the expectation. ``SHOW ssl`` →
    ``'off'``. **No row** is ABSENT, not an empty reading: a setting a given
    engine version does not have and a setting whose value is the empty string
    are different facts, and the rule's :class:`AbsencePolicy` is what decides
    what the first one means.

``rows``
    An *enumeration of offending items* — "which accounts have an empty
    password", "which roles hold superuser". The rule asserts the list is
    empty, so a clean instance produces ABSENT and ``AbsencePolicy.PASS`` makes
    it a pass, while a breached one produces the offenders as the evidence a
    person needs to fix it. This is the shape Phase 5 established for
    ``privilege`` checks, reused deliberately: a count on its own ("4
    superusers") says nothing, and the finding has to name what to change.

``count``
    The number of rows, as a value. For rules that legitimately allow some —
    "no more than two accounts hold sysadmin". Never ABSENT: zero is a reading.

Why a failed query can never become a verdict
─────────────────────────────────────────────
Every non-success path here returns UNAVAILABLE, which the engine turns into
ERROR. A catalogue view that does not exist on this engine version, a
credential without the privilege to read ``pg_authid``, a dropped connection —
none of them establish anything about the instance's configuration, and a
scanner that reads a refused query's empty result set as "no offending
accounts" reports a hardened database for one it was never allowed to inspect.
That is the single failure this whole collection vocabulary exists to prevent,
and it is easier to write by accident here than anywhere else in the engine,
because an empty result set is *exactly* what a compliant instance returns.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.base import Collector, CollectorRegistry
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.collectors.database")

__all__ = ["DatabaseQueryCollector", "register_database_collector"]

#: How a rule may ask for its result to be shaped.
_RESULT_SHAPES: Tuple[str, ...] = ("scalar", "rows", "count")


class DatabaseQueryCollector(Collector):
    """
    Reads one configuration item from a database instance.

    ``check.collect`` keys:

    ``sql``           required — one read-only statement
    ``params``        optional — bound parameters, never interpolated
    ``engine``        optional — restrict to one engine; a mismatch is
                      UNSUPPORTED, because a PostgreSQL catalogue read against
                      MySQL was never in scope for that instance
    ``result``        ``scalar`` (default) | ``rows`` | ``count``
    ``value_index``   optional — which column carries the value in ``scalar``
                      mode. ``SHOW VARIABLES LIKE 'x'`` answers ``(name,
                      value)``, so the value is at index 1 and reading index 0
                      would compare the setting's *name* against the expected
                      value and fail on every host.
    ``value_column``  optional — the same, by column name
    """

    check_type = "database_query"
    platforms = ("database",)
    name = "database_query"

    def collect(self, check: ConfigCheck, ctx: CollectionContext) -> CollectedState:
        params, failure = self._require(check, "sql")
        if failure is not None:
            return failure
        # `_require` returns exactly one of the pair, so this cannot be None
        # here. Written as a fallback rather than an assert because asserts are
        # stripped under `python -O`, and the line after this would then raise
        # AttributeError instead of reporting a rule defect.
        params = params or {}

        session = ctx.executor
        if session is None:
            return CollectedState.unavailable(
                "no authenticated database session was established for this "
                "instance",
                collector=self.name,
            )

        shape = str(params.get("result") or "scalar").strip().lower()
        if shape not in _RESULT_SHAPES:
            return CollectedState.unavailable(
                f"rule asks for result shape {shape!r}; supported shapes are "
                f"{', '.join(_RESULT_SHAPES)}",
                collector=self.name,
            )

        mismatch = self._engine_mismatch(params, session)
        if mismatch is not None:
            return mismatch

        statement = str(params["sql"])
        bound = params.get("params")
        if bound is not None and not isinstance(bound, (list, tuple)):
            return CollectedState.unavailable(
                "rule's 'params' must be a list of bound values; a statement "
                "built by string interpolation is refused",
                collector=self.name,
            )

        try:
            result = session.query(statement, params=bound, timeout=ctx.timeout)
        except Exception as exc:  # noqa: BLE001 — never propagate to the engine
            # The session is not supposed to raise, but a driver can. Reported
            # as a failed collection rather than allowed out, so one unlucky
            # statement does not abort the audit of every other check.
            log.debug("Database query raised for %s: %s", check.check_id, exc)
            return CollectedState.unavailable(
                f"the database driver raised {type(exc).__name__}: {exc}",
                collector=self.name,
            )

        if not result.ok:
            return CollectedState.unavailable(
                result.failure_detail(),
                raw=statement,
                collector=self.name,
            )

        raw = self._raw_evidence(statement, result)

        if shape == "count":
            # Zero is a reading, not an absence — a rule saying "at most two
            # sysadmins" must be able to pass on an instance with none.
            return CollectedState.collected(
                result.row_count, raw=raw, collector=self.name
            )

        if shape == "rows":
            if not result.rows:
                return CollectedState.absent(
                    "the query matched no rows",
                    raw=raw,
                    collector=self.name,
                )
            return CollectedState.collected(
                result.rendered_rows(), raw=raw, collector=self.name
            )

        # scalar
        if not result.rows:
            return CollectedState.absent(
                "the query returned no row, so the setting is not present on "
                "this instance",
                raw=raw,
                collector=self.name,
            )

        value, error = self._scalar_value(params, result)
        if error is not None:
            return CollectedState.unavailable(error, raw=raw, collector=self.name)
        return CollectedState.collected(value, raw=raw, collector=self.name)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _engine_mismatch(
        self, params: Dict[str, Any], session: Any
    ) -> Optional[CollectedState]:
        """
        UNSUPPORTED where the rule names a different engine.

        NOT_APPLICABLE is the right outcome and UNSUPPORTED is how a collector
        says so: a PostgreSQL catalogue read dispatched at MySQL was never in
        scope for that instance, and reporting it as an error would fill the
        report with product gaps that are really targeting decisions.

        ``ConfigCheck.os_match`` covers the same ground at the engine level and
        is the primary mechanism — the session's product string is passed as
        ``os_name``. This is the backstop for a rule that forgot to declare it,
        which would otherwise run a MySQL ``SHOW VARIABLES`` against PostgreSQL
        and record the syntax error as an unassessed check.

        The session folds the engine names: it is the executor the context was
        handed, and the vocabulary of engine names is the executor's
        (``DatabaseSession.normalize_engine``). Importing the executor module
        for it put the configuration audit on top of the credentialed engine
        (B10). A session that cannot fold names gets no backstop, as when that
        import failed; the query then runs, and a statement in the wrong
        dialect comes back as an error, never a verdict.
        """
        wanted = params.get("engine")
        if not wanted:
            return None
        normalize_engine = getattr(session, "normalize_engine", None)
        if not callable(normalize_engine):
            return None

        names = wanted if isinstance(wanted, (list, tuple)) else [wanted]
        accepted = {normalize_engine(n) for n in names} - {""}
        actual = normalize_engine(getattr(session, "engine", ""))
        if not accepted or not actual or actual in accepted:
            return None
        return CollectedState.unsupported(
            f"check targets {', '.join(sorted(accepted))}; this instance is "
            f"{actual}",
            collector=self.name,
        )

    def _scalar_value(
        self, params: Dict[str, Any], result: Any
    ) -> Tuple[Any, Optional[str]]:
        """
        Pull the value out of the first row.

        Returns ``(value, None)`` or ``(None, reason)``. A rule naming a column
        the query did not return is a defect in the rule, so it is UNAVAILABLE
        — not a comparison against None, which would evaluate and record a
        verdict about the instance.
        """
        row = result.rows[0]
        column = params.get("value_column")
        if column:
            try:
                index = [c.lower() for c in result.columns].index(str(column).lower())
            except ValueError:
                return None, (
                    f"rule names value_column {column!r}, which the query did "
                    f"not return (columns: "
                    f"{', '.join(result.columns) or 'none reported'})"
                )
            return row[index], None

        index_param = params.get("value_index")
        index = 0 if index_param is None else int(index_param)
        if index >= len(row) or index < -len(row):
            return None, (
                f"rule reads column {index} but the query returned "
                f"{len(row)} column(s)"
            )
        return row[index], None

    @staticmethod
    def _raw_evidence(statement: str, result: Any) -> str:
        """
        The statement and what it returned, for the evidence record.

        The statement is included because a reader assessing a database finding
        needs to know what was asked as well as what came back — a verdict on
        "which accounts have an empty password" is only as good as the query
        that produced it, and an auditor is entitled to check it.
        """
        lines: List[str] = [f"SQL: {' '.join(str(statement).split())}"]
        if result.columns:
            lines.append("columns: " + ", ".join(result.columns))
        lines.append(f"rows: {result.row_count}")
        lines.extend(result.rendered_rows(limit=20))
        return "\n".join(lines)


def register_database_collector(registry: CollectorRegistry) -> None:
    """
    Register the database collector on *registry*.

    Registration lives here rather than at class definition so that importing
    this module for inspection cannot half-populate a global registry — the
    same reason every other collector in this package is registered from
    ``collectors/__init__``.
    """
    registry.register(DatabaseQueryCollector())
