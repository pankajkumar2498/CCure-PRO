"""
B3: the discovery engine no longer loads the vulnerability-intelligence
database layer.

It came in through ``core.risk``, which needs ``compute_priority`` and
``merge_alias_fields`` to merge duplicate findings, and imported them from
``core.vuln_intel`` — the module that holds the queries against the
``vuln_intel`` database and opens SQLAlchemy and the configuration at import.
The four pure helpers moved unchanged to ``core/vuln_scoring.py``;
``core.vuln_intel`` re-exports them.

These pin the move (the same functions, under both names), its purpose (the
discovery engine imports and runs without the database layer) and the
behaviour every caller relies on (the priority ladder and the normalised
record), so the next move cannot change any of them quietly.
"""

import ast
import json
import subprocess
import sys
from datetime import date, datetime
from decimal import Decimal

import pytest

import core.vuln_intel as vuln_intel
import core.vuln_scoring as vuln_scoring
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

HELPERS = (
    "compute_priority",
    "merge_alias_fields",
    "title_case_severity",
    "_json_safe",
)
DATABASE_LAYER = (
    "sqlalchemy",
    "config",
    "core.vuln_intel",
    "core.cve_database",
    "db.fork_safety",
    "db.base",
)


def test_vuln_intel_reexports_the_same_functions():
    for name in HELPERS:
        assert getattr(vuln_intel, name) is getattr(vuln_scoring, name), name


def test_the_scoring_module_imports_only_the_standard_library():
    tree = ast.parse((BACKEND_ROOT / "core" / "vuln_scoring.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "datetime", "decimal", "typing"}


def test_core_risk_does_not_import_the_vuln_intel_database_modules():
    """Lazy imports count; they are how the codebase hid its couplings."""
    _, edges = collect_edges()
    found = sorted(
        e.dst
        for e in edges
        if e.src == "core.risk" and e.dst in ("core.vuln_intel", "core.cve_database")
    )
    assert found == []


_IMPORT_AND_RUN = r"""
import asyncio, json, sys
import core.discovery.engine as de
watched = %r
after_import = {m: m in sys.modules for m in watched}

async def probe(self, batch, results):
    for ip in batch:
        results[ip]["is_active"] = True

async def nothing(self, *args, **kwargs):
    return None

de.DiscoveryEngine._probe_batch = probe
de.DiscoveryEngine._enrich_active = nothing
hosts = asyncio.run(de.DiscoveryEngine().run(["198.51.100.1"]))
after_run = {m: m in sys.modules for m in watched}
print(json.dumps({"after_import": after_import, "after_run": after_run,
                  "active": [h["is_active"] for h in hosts]}))
"""


def test_the_discovery_engine_imports_and_runs_without_the_database_layer():
    done = subprocess.run(
        [sys.executable, "-c", _IMPORT_AND_RUN % (DATABASE_LAYER,)],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result["active"] == [True]
    for stage in ("after_import", "after_run"):
        loaded = sorted(m for m, seen in result[stage].items() if seen)
        assert loaded == [], f"{stage}: {loaded}"


# ── The behaviour every caller relies on ─────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        (dict(cvss_score=9.8, in_kev=True), (100.0, "P0")),
        (dict(cvss_score=5.0, epss_score=0.8), (52.0, "P1")),
        (dict(cvss_score=7.5, has_exploit=True), (45.0, "P1")),
        (dict(cvss_score=9.1), (36.4, "P2")),
        (dict(cvss_score=7.0), (28.0, "P3")),
        (dict(cvss_score=2.0, epss_score=0.35), (22.0, "P3")),
        (dict(cvss_score=3.1, epss_score=0.01), (12.8, "P4")),
        (dict(cvss_score="not a number", epss_score=None), (0.0, "P4")),
    ],
)
def test_the_priority_ladder(kwargs, expected):
    assert vuln_scoring.compute_priority(**kwargs) == expected


def test_a_record_is_normalised_with_its_aliases_and_priority():
    record = {
        "cve": "CVE-2024-6387",
        "desc": "regreSSHion",
        "cvss": Decimal("8.1"),
        "severity": "high",
        "epss_score": 0.5,
        "published": date(2024, 7, 1),
        "seen": [datetime(2024, 7, 2, 3, 4, 5)],
    }
    out = vuln_scoring.merge_alias_fields(record)
    assert out["cve_id"] == out["cve"] == "CVE-2024-6387"
    assert out["description"] == out["desc"] == "regreSSHion"
    assert out["cvss_score"] == out["cvss"] == 8.1
    assert out["severity"] == "High"
    assert (out["priority_score"], out["priority_level"]) == (52.4, "P3")
    assert out["published"] == "2024-07-01"
    assert out["seen"] == ["2024-07-02T03:04:05"]
    assert record["cvss"] == Decimal("8.1")  # the input is not modified


def test_an_existing_priority_is_kept_and_severity_falls_back_to_the_score():
    out = vuln_scoring.merge_alias_fields(
        {"cve_id": "CVE-X", "cvss_score": 4.2, "priority_level": "P0"}
    )
    assert out["priority_level"] == "P0"
    assert out["severity"] == "Medium"
    assert vuln_scoring.title_case_severity("none") == "Info"
    assert vuln_scoring.title_case_severity("", 0.0) == "Info"
