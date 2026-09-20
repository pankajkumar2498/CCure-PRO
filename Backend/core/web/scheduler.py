"""
core/web/scheduler.py
────────────────────────────────────────────────────────────────────────────
Coverage scheduler / queue engine (Codex P2 item 12).

Industry scanners do not let each tool decide independently what to do with a
target. A scheduler sits between discovery and the engines: every discovered
request is classified, passive checks are enqueued, then active checks, results
are recorded, findings deduplicated, and coverage updated. That single flow is
what makes coverage answerable and duplicate work avoidable.

This is that component. It does not re-implement the engines — it *organises*
them: it turns the discovered surface into an ordered, classified plan (passive
before active), records each task's outcome, rolls the outcomes into the coverage
ledger, and deduplicates the findings through the existing correlation engine. It
is deliberately pure and synchronous so it is testable in isolation; the
orchestrator drives it and the engines do the I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

#: Passive checks observe a response and never inject — safe on every request.
PASSIVE_CHECKS = ("security_headers", "cookies", "cors", "tls")
#: Active checks inject and only apply to a request that carries a parameter.
ACTIVE_CHECKS = ("sqli", "xss", "injection", "access_control")

# Task lifecycle.
QUEUED = "queued"
RUNNING = "running"
DONE = "done"
SKIPPED = "skipped"


@dataclass
class Task:
    kind: str  # a check name from PASSIVE_CHECKS / ACTIVE_CHECKS
    phase: str  # "passive" | "active"
    url: str
    method: str = "GET"
    param_count: int = 0
    status: str = QUEUED
    outcome: str = ""  # "vulnerable" | "clean" | "error" | "skipped"
    reason: str = ""


def classify_request(req: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Classify one discovered request into the checks it warrants. Every request
    gets the passive checks; a request that carries at least one parameter also
    gets the active checks (there is nothing for an injector to test otherwise).
    """
    params = req.get("parameters") or {}
    has_params = any(params.get(loc) for loc in params) or bool(req.get("inputs"))
    active = list(ACTIVE_CHECKS) if has_params else []
    return {"passive": list(PASSIVE_CHECKS), "active": active}


class CoverageScheduler:
    """Plans, records and deduplicates the DETECT work for a discovered surface."""

    def __init__(self, ledger: Optional[Any] = None) -> None:
        self._tasks: List[Task] = []
        self._ledger = ledger  # optional CoverageLedger to roll outcomes into
        self._findings: List[dict] = []

    # ── planning ──────────────────────────────────────────────────────────────
    def enqueue_surface(
        self,
        endpoints: Optional[List[dict]] = None,
        forms: Optional[List[dict]] = None,
    ) -> None:
        """Turn the discovered surface into a classified, ordered task queue."""
        for req in list(endpoints or []) + list(forms or []):
            if not isinstance(req, dict) or not req.get("url"):
                continue
            params = req.get("parameters") or {}
            pcount = sum(len(v or []) for v in params.values()) or (
                len(req.get("inputs") or [])
            )
            plan = classify_request(req)
            for kind in plan["passive"]:
                self._tasks.append(
                    Task(
                        kind=kind,
                        phase="passive",
                        url=req["url"],
                        method=str(req.get("method") or "GET").upper(),
                    )
                )
            for kind in plan["active"]:
                self._tasks.append(
                    Task(
                        kind=kind,
                        phase="active",
                        url=req["url"],
                        method=str(req.get("method") or "GET").upper(),
                        param_count=pcount,
                    )
                )

    def plan(self) -> List[Task]:
        """The queue in execution order: all passive tasks before any active one
        (a passive observation is cheap and can inform the active phase)."""
        return sorted(self._tasks, key=lambda t: 0 if t.phase == "passive" else 1)

    # ── recording ─────────────────────────────────────────────────────────────
    def record(self, kind: str, url: str, outcome: str, reason: str = "") -> None:
        """Record an engine's outcome for a check, updating the matching tasks and
        the coverage ledger."""
        matched = False
        for t in self._tasks:
            if t.kind == kind and (not url or t.url == url):
                t.status = DONE if outcome != SKIPPED else SKIPPED
                t.outcome = outcome
                t.reason = reason
                matched = True
        if self._ledger is not None and outcome != SKIPPED:
            try:
                self._ledger.mark_endpoint(url, kind)
            except Exception:
                pass
        return matched

    def add_findings(self, findings: List[dict]) -> None:
        self._findings.extend(findings or [])

    def deduplicate(self, findings: Optional[List[dict]] = None) -> List[dict]:
        """Deduplicate findings through the existing correlation engine — one flow
        for correlation, not each engine's own."""
        from core.web.correlation import deduplicate_findings

        return deduplicate_findings(self._findings if findings is None else findings)

    # ── summary ─────────────────────────────────────────────────────────────────
    def summary(self) -> Dict[str, Any]:
        passive = [t for t in self._tasks if t.phase == "passive"]
        active = [t for t in self._tasks if t.phase == "active"]
        by_status: Dict[str, int] = {}
        for t in self._tasks:
            by_status[t.status] = by_status.get(t.status, 0) + 1
        return {
            "total_tasks": len(self._tasks),
            "passive_tasks": len(passive),
            "active_tasks": len(active),
            "by_status": by_status,
            "active_check_kinds": sorted({t.kind for t in active}),
        }
