"""
core/web/coverage.py
────────────────────────────────────────────────────────────────────────────
Coverage ledger (Phase 22, Codex P0 item 3).

The property that separates a mature DAST from "a collection of checks around a
URL" is that it can answer, per parameter: *was this tested, by which engine,
and if not — why not?* Without it, "0 findings" is indistinguishable from
"never looked", which is the single most dangerous ambiguity in a scanner
result (a clean-looking report over an unassessed surface).

This module records the discovered attack surface at parameter granularity and
what each active engine did with it, then produces an auditable summary:

    total parameters | tested (by ≥1 engine) | untested | per-engine coverage
    | skipped-with-reason

It stores no request/response bodies and no secrets — only URL, parameter name,
location, the engine, a status and a reason. It is persisted alongside the
existing tool_coverage in ``scans.options`` (no new table), so a scan can prove
its own coverage in the report and API.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

#: parameter locations the ledger understands.
LOCATIONS = ("query", "form", "json", "path", "cookie", "header", "soap")

STATUS_TESTED = "tested"
STATUS_SKIPPED = "skipped"


def _base(url: str) -> str:
    """URL without query/fragment — the stable identity of an endpoint."""
    try:
        p = urlparse(url or "")
        return p._replace(query="", fragment="").geturl()
    except Exception:
        return (url or "").split("?")[0]


class CoverageLedger:
    """A per-(endpoint, location, parameter) record of what was tested."""

    def __init__(self) -> None:
        # key: (base_url, location, param) -> node
        self._nodes: Dict[tuple, Dict[str, Any]] = {}

    # ── surface registration ────────────────────────────────────────────────
    def discover(self, url: str, location: str, param: str) -> None:
        """Register a parameter as part of the discovered attack surface."""
        if not param or location not in LOCATIONS:
            return
        key = (_base(url), location, str(param))
        self._nodes.setdefault(
            key,
            {
                "url": _base(url),
                "location": location,
                "param": str(param),
                "engines": {},  # engine -> {"status", "reason"}
            },
        )

    def seed_from_surface(
        self,
        endpoints: Optional[List[dict]] = None,
        forms: Optional[List[dict]] = None,
    ) -> None:
        """
        Enumerate every parameter of the discovered surface as a ledger node,
        using the same parameter model the engines consume (surface.describe_*),
        so the ledger's denominator is the real surface, not a guess.
        """
        from core.web.surface import describe_parameters

        for ep in endpoints or []:
            if not isinstance(ep, dict) or not ep.get("url"):
                continue
            model = ep.get("parameters") or describe_parameters(ep)
            for loc, names in (model or {}).items():
                if loc not in LOCATIONS:
                    continue
                for name in names or []:
                    self.discover(ep["url"], loc, name)
        for form in forms or []:
            if not isinstance(form, dict) or not form.get("url"):
                continue
            for inp in form.get("inputs") or []:
                if isinstance(inp, dict) and inp.get("name"):
                    self.discover(form["url"], "form", inp["name"])

    # ── outcomes ────────────────────────────────────────────────────────────
    def mark(
        self,
        url: str,
        location: str,
        param: str,
        engine: str,
        status: str = STATUS_TESTED,
        reason: str = "",
    ) -> None:
        """Record that ``engine`` tested (or skipped) one parameter."""
        if not param:
            return
        key = (_base(url), location, str(param))
        node = self._nodes.get(key)
        if node is None:
            # An engine tested something the surface seed did not enumerate
            # (e.g. a target-supplied path param) — register it so it counts.
            self.discover(url, location, param)
            node = self._nodes[key]
        # "tested" always wins over a prior "skipped" for the same engine.
        prev = node["engines"].get(engine, {})
        if prev.get("status") == STATUS_TESTED and status != STATUS_TESTED:
            return
        node["engines"][engine] = {"status": status, "reason": reason}

    def mark_tested_params(self, engine: str, tested: List[dict]) -> None:
        """Bulk-mark the ``tested_params`` list an engine returns in its stats."""
        for t in tested or []:
            if isinstance(t, dict) and t.get("param"):
                self.mark(
                    t.get("url", ""),
                    t.get("location", "query"),
                    t["param"],
                    engine,
                    STATUS_TESTED,
                )

    def mark_endpoint(
        self, url: str, engine: str, status: str = STATUS_TESTED, reason: str = ""
    ) -> None:
        """Mark every parameter of one endpoint (a tool like sqlmap tests them
        all in a single run against the target)."""
        b = _base(url)
        for node in list(self._nodes.values()):
            if node["url"] == b:
                self.mark(
                    node["url"], node["location"], node["param"], engine, status, reason
                )

    def mark_skipped(self, engine: str, reason: str, predicate=None) -> None:
        """Mark surface parameters this engine did not reach, with a reason."""
        for node in self._nodes.values():
            if engine in node["engines"]:
                continue  # already tested/recorded by this engine
            if predicate is None or predicate(node):
                node["engines"][engine] = {
                    "status": STATUS_SKIPPED,
                    "reason": reason,
                }

    # ── summary ─────────────────────────────────────────────────────────────
    def summary(self, active_engines: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        A durable, honest coverage summary. ``active_engines`` is the set of
        engines that ran, so per-engine coverage is only reported for them.
        """
        nodes = list(self._nodes.values())
        total = len(nodes)
        tested_nodes = [
            n
            for n in nodes
            if any(e.get("status") == STATUS_TESTED for e in n["engines"].values())
        ]
        untested = [
            {"url": n["url"], "location": n["location"], "param": n["param"]}
            for n in nodes
            if not any(e.get("status") == STATUS_TESTED for e in n["engines"].values())
        ]
        per_engine: Dict[str, int] = {}
        for eng in active_engines or self._engine_names():
            per_engine[eng] = sum(
                1
                for n in nodes
                if n["engines"].get(eng, {}).get("status") == STATUS_TESTED
            )
        # Collapse skip reasons for the report.
        skip_reasons: Dict[str, int] = {}
        for n in nodes:
            for eng, e in n["engines"].items():
                if e.get("status") == STATUS_SKIPPED and e.get("reason"):
                    skip_reasons[e["reason"]] = skip_reasons.get(e["reason"], 0) + 1
        return {
            "total_parameters": total,
            "tested_parameters": len(tested_nodes),
            "untested_parameters": len(untested),
            "coverage_pct": (
                round(100.0 * len(tested_nodes) / total, 1) if total else 0.0
            ),
            "per_engine_tested": per_engine,
            "untested": untested[:200],  # bounded for the report
            "skip_reasons": skip_reasons,
        }

    def _engine_names(self) -> List[str]:
        names: set = set()
        for n in self._nodes.values():
            names.update(n["engines"].keys())
        return sorted(names)

    # ── relational export ─────────────────────────────────────────────────────
    def export_parameters(self, max_params: int = 20000) -> List[Dict[str, Any]]:
        """
        Full per-parameter coverage, for persistence as first-class relational
        rows (WebParameter). Unlike ``summary`` — which is bounded counts and a
        truncated untested sample for the report — this is every node with the
        engines that tested it and, when untested, the reason it was skipped, so
        the durable attack-surface table records the real surface at parameter
        granularity.
        """
        out: List[Dict[str, Any]] = []
        for node in self._nodes.values():
            engines = node.get("engines", {})
            tested_by = sorted(
                eng for eng, e in engines.items() if e.get("status") == STATUS_TESTED
            )
            skipped_reason = ""
            if not tested_by:
                # Surface the first recorded skip reason, if any.
                for e in engines.values():
                    if e.get("status") == STATUS_SKIPPED and e.get("reason"):
                        skipped_reason = e["reason"]
                        break
            out.append(
                {
                    "url": node["url"],
                    "location": node["location"],
                    "param": node["param"],
                    "tested": bool(tested_by),
                    "tested_by": tested_by,
                    "skipped_reason": skipped_reason,
                }
            )
            if len(out) >= max_params:
                break
        return out
