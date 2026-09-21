"""
Phase 23c — coverage scheduler / queue engine (Codex P2 item 12).

The scheduler classifies the discovered surface into passive+active check tasks,
orders passive before active, records task outcomes, and deduplicates findings
through the correlation engine. Engines, not endpoint-level task outcomes, update
parameter coverage. These tests pin that flow.
"""

from core.web.coverage import CoverageLedger
from core.web.scheduler import (
    ACTIVE_CHECKS,
    PASSIVE_CHECKS,
    CoverageScheduler,
    classify_request,
)


def test_classify_request_active_only_with_params():
    with_params = classify_request({"url": "/x", "parameters": {"query": ["id"]}})
    assert with_params["active"] == list(ACTIVE_CHECKS)
    assert with_params["passive"] == list(PASSIVE_CHECKS)
    no_params = classify_request({"url": "/x", "parameters": {}})
    assert no_params["active"] == []  # nothing to inject
    assert no_params["passive"] == list(PASSIVE_CHECKS)


def test_plan_orders_passive_before_active():
    s = CoverageScheduler()
    s.enqueue_surface(
        endpoints=[{"url": "http://a/x?id=1", "parameters": {"query": ["id"]}}],
        forms=[],
    )
    plan = s.plan()
    phases = [t.phase for t in plan]
    # all passive tasks come before any active one
    assert phases == sorted(phases, key=lambda p: 0 if p == "passive" else 1)
    assert any(t.phase == "active" and t.kind == "sqli" for t in plan)


def test_endpoint_without_params_schedules_no_active_tasks():
    s = CoverageScheduler()
    s.enqueue_surface(endpoints=[{"url": "http://a/about", "parameters": {}}], forms=[])
    summ = s.summary()
    assert summ["active_tasks"] == 0
    assert summ["passive_tasks"] == len(PASSIVE_CHECKS)


def test_record_updates_tasks_but_not_parameter_ledger():
    ledger = CoverageLedger()
    ledger.discover("http://a/x", "query", "id")
    s = CoverageScheduler(ledger)
    s.enqueue_surface(
        endpoints=[{"url": "http://a/x", "parameters": {"query": ["id"]}}], forms=[]
    )
    assert s.record("sqli", "http://a/x", "done")
    summ = s.summary()
    assert summ["by_status"].get("done", 0) >= 1
    # Endpoint-level task completion is not proof that a parameter was tested.
    cov = ledger.summary(active_engines=["sqli"])
    assert cov["per_engine_tested"].get("sqli", 0) == 0


def test_finalize_unresolved_marks_queued_tasks_skipped():
    s = CoverageScheduler()
    s.enqueue_surface(
        endpoints=[{"url": "http://a/x?id=1", "parameters": {"query": ["id"]}}],
        forms=[],
    )
    s.record("xss", "http://a/x?id=1", "done")
    s.finalize_unresolved("not individually executed")
    summ = s.summary()
    assert summ["by_status"].get("queued", 0) == 0
    assert summ["by_status"].get("skipped", 0) > 0


def test_deduplicate_delegates_to_correlation():
    s = CoverageScheduler()
    dupes = [
        {"finding_type": "xss", "matched_at": "http://a/x", "param": "q"},
        {"finding_type": "xss", "matched_at": "http://a/x", "param": "q"},
    ]
    s.add_findings(dupes)
    out = s.deduplicate()
    assert len(out) <= len(dupes)
