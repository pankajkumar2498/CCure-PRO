"""
Phase 22 — coverage ledger (Codex P0 item 3).

The property that separates a mature DAST from a checks-around-a-URL tool is
that it can prove, per parameter, whether it was tested and by which engine —
so "0 findings" is never confused with "never looked". These tests pin the
ledger's surface enumeration, per-engine marking, endpoint-level marking
(sqlmap) and the tested/untested summary.
"""

from core.web.coverage import CoverageLedger


def test_seed_enumerates_all_parameter_locations():
    endpoints = [
        {
            "url": "http://t/api/users/42?sort=asc",
            "parameters": {"query": ["sort"], "path": ["3"], "json": ["name"]},
        }
    ]
    forms = [{"url": "http://t/login", "inputs": [{"name": "user"}, {"name": "pass"}]}]
    led = CoverageLedger()
    led.seed_from_surface(endpoints, forms)
    s = led.summary()
    # sort(query) + path(3) + name(json) + user + pass = 5
    assert s["total_parameters"] == 5
    assert s["tested_parameters"] == 0
    assert s["untested_parameters"] == 5
    assert s["coverage_pct"] == 0.0


def test_mark_tested_and_summary_distinguishes_tested_from_untested():
    led = CoverageLedger()
    led.seed_from_surface(
        [{"url": "http://t/s?q=1&r=2"}], []
    )  # q, r discovered via describe_parameters
    led.mark("http://t/s", "query", "q", "xss")
    s = led.summary(active_engines=["xss"])
    assert s["total_parameters"] == 2
    assert s["tested_parameters"] == 1
    assert s["untested_parameters"] == 1
    assert s["per_engine_tested"]["xss"] == 1
    assert s["untested"][0]["param"] == "r"


def test_mark_tested_params_bulk():
    led = CoverageLedger()
    led.seed_from_surface([{"url": "http://t/a?x=1&y=2"}], [])
    led.mark_tested_params(
        "injection",
        [
            {"url": "http://t/a", "param": "x", "location": "query"},
            {"url": "http://t/a", "param": "y", "location": "query"},
        ],
    )
    s = led.summary(active_engines=["injection"])
    assert s["tested_parameters"] == 2
    assert s["coverage_pct"] == 100.0


def test_mark_endpoint_covers_every_param_of_that_url():
    led = CoverageLedger()
    led.seed_from_surface([{"url": "http://t/a?x=1&y=2"}], [])
    led.mark_endpoint("http://t/a?x=1&y=2", "sqlmap")  # sqlmap tests the whole target
    s = led.summary(active_engines=["sqlmap"])
    assert s["per_engine_tested"]["sqlmap"] == 2
    assert s["untested_parameters"] == 0


def test_tested_wins_over_skipped_for_same_engine():
    led = CoverageLedger()
    led.discover("http://t/a", "query", "x")
    led.mark("http://t/a", "query", "x", "sqlmap", status="skipped", reason="cap")
    led.mark("http://t/a", "query", "x", "sqlmap", status="tested")
    s = led.summary(active_engines=["sqlmap"])
    assert s["per_engine_tested"]["sqlmap"] == 1


def test_marking_unknown_param_registers_it():
    # An engine that tests something the seed missed (a target-supplied path id)
    # still gets counted, so coverage never undercounts what was actually done.
    led = CoverageLedger()
    led.mark("http://t/api/users/9", "path", "3", "sqlmap")
    s = led.summary(active_engines=["sqlmap"])
    assert s["total_parameters"] == 1
    assert s["tested_parameters"] == 1


def test_skip_reasons_are_recorded():
    led = CoverageLedger()
    led.seed_from_surface([{"url": "http://t/a?x=1"}], [])
    led.mark_skipped("sqlmap", "target cap reached")
    s = led.summary(active_engines=["sqlmap"])
    assert s["skip_reasons"].get("target cap reached") == 1
    assert s["untested_parameters"] == 1  # skipped is not tested
