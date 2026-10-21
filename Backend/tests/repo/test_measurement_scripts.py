"""
The two probes every Phase B step is measured with
(docs/architecture/MODULAR_REFACTORING_LOG.md §6):

* ``scripts/architecture/interface_snapshot.py`` — routes, route limits, the
  limiter's identity, Celery tasks, beat and the OpenAPI digest;
* ``scripts/architecture/import_cost.py`` — what importing a module loads.

A refactoring step's record is only as good as the measurement behind it, so
these pin that each probe measures what it says, that a comparison names a
change and reports none where there is none, and that a probe never raises on
the module it is asked about.
"""

import json
import re

from scripts.architecture import import_cost, interface_snapshot


# ── interface_snapshot ───────────────────────────────────────────────────────


def test_the_snapshot_records_the_application_it_loaded():
    from core.rate_limiter import limiter

    import main

    snap = interface_snapshot.snapshot()
    served = {route.path for route in main.app.routes if hasattr(route, "endpoint")}
    assert {path for _, path, _ in snap["routes"]} == served
    assert snap["route_count"] == len(snap["routes"])
    assert set(snap["route_limits"]) == set(limiter._route_limits)
    assert snap["app_state_limiter_is_canonical"] is True
    assert snap["scan_helpers_limiter_is_canonical"] is True
    assert all(snap["limiter_holders_are_canonical"].values())
    # Tasks the worker serves and a beat entry, by the names they are
    # dispatched under; a snapshot that missed the task modules would lack them.
    assert "ccure.tasks.run_host_discovery" in snap["celery_tasks"]
    assert "purge-expired-audit-logs-daily" in snap["beat"]
    assert re.fullmatch(r"[0-9a-f]{64}", snap["openapi_sha256"])


def test_the_snapshot_is_deterministic():
    first = json.dumps(interface_snapshot.snapshot(), sort_keys=True)
    second = json.dumps(interface_snapshot.snapshot(), sort_keys=True)
    assert first == second


def test_compare_names_what_moved_and_nothing_else():
    before = {
        "routes": [[["GET"], "/a", "routers.x.a"], [["GET"], "/b", "routers.x.b"]],
        "route_count": 2,
        "beat": {"nightly": {"task": "t", "schedule": "1"}},
        "openapi_sha256": "0" * 64,
    }
    assert interface_snapshot.compare(before, json.loads(json.dumps(before))) == []

    after = json.loads(json.dumps(before))
    after["routes"][1][2] = "routers.y.b"  # the handler moved module
    after["beat"]["nightly"]["schedule"] = "2"
    lines = interface_snapshot.compare(before, after)
    assert 'routes: removed [["GET"], "/b", "routers.x.b"]' in lines
    assert 'routes: added [["GET"], "/b", "routers.y.b"]' in lines
    assert any(line.startswith("beat[nightly]:") for line in lines)
    assert not any("route_count" in line or "openapi" in line for line in lines)


def test_compare_exits_nonzero_on_a_difference(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({"route_count": 1}))
    b.write_text(json.dumps({"route_count": 2}))
    assert interface_snapshot.cli(["--compare", str(a), str(a)]) == 0
    assert interface_snapshot.cli(["--compare", str(a), str(b)]) == 1
    assert "route_count: 1 -> 2" in capsys.readouterr().out


# ── import_cost ──────────────────────────────────────────────────────────────


def test_import_cost_counts_what_a_fresh_import_loads():
    result = import_cost.measure(
        ["json", "core.rate_limiter"], watch=["slowapi", "scan_helpers"]
    )
    stdlib, limiter = result["modules"]["json"], result["modules"]["core.rate_limiter"]

    assert stdlib["first_party"] == 0
    assert stdlib["heavy"] == []
    # The limiter is first-party and needs slowapi; since B1 it is reached
    # without scan_helpers, and so without the network scan stack.
    assert limiter["first_party"] >= 2
    assert limiter["watched"] == {"slowapi": True, "scan_helpers": False}
    assert not {"scapy", "nmap", "reportlab"} & set(limiter["heavy"])
    assert result["python"] and result["heavy_list"] == list(import_cost.HEAVY)


def test_import_cost_lists_first_party_modules_on_request():
    row = import_cost.measure(["core.rate_limiter"], list_modules=True)["modules"][
        "core.rate_limiter"
    ]
    assert "core.rate_limiter" in row["first_party_modules"]
    assert len(row["first_party_modules"]) == row["first_party"]


def test_import_cost_reports_a_failed_import_instead_of_raising():
    row = import_cost.measure(["no_such_module_xyz"])["modules"]["no_such_module_xyz"]
    assert "ModuleNotFoundError" in row["error"]


def test_import_cost_compare_names_heavy_packages_gained_and_lost():
    def run(first_party, heavy, watched):
        return {
            "python": "3.11",
            "modules": {
                "m": {
                    "first_party": first_party,
                    "all": first_party * 10,
                    "heavy": heavy,
                    "watched": watched,
                }
            },
        }

    lines = import_cost.compare(
        run(125, ["nmap", "scapy"], {"scan_helpers": True}),
        run(70, ["redis"], {"scan_helpers": False}),
    )
    assert lines == [
        "m: first-party 125 -> 70, all 1250 -> 700; no longer loads nmap, scapy;"
        " now loads redis; watched scan_helpers True -> False"
    ]
