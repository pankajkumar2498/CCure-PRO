"""
B5: the check kernel no longer reaches into the network checks.

``core.checks.legacy_plugins`` verifies that every plugin the network checks
can dispatch is callable the way the engine calls it. It used to import
``engines.vulnerability.plugin_selector`` for the dispatch tables and import
each plugin by its ``engines.vulnerability.plugins`` path, so the kernel every
capability imports depended on one engine. Now the selector registers a
``PluginSource`` (its own dispatch table and a strict loader) when it is
imported, and the kernel answers from what is registered.

These pin the purpose (no ``core.checks`` module imports above the kernel), the
refusal when nothing is registered (an empty answer would read as "every plugin
is callable"), and that the registered answers are the selector's own.
``test_plugin_contract.py`` still checks every plugin through the kernel.
"""

import ast
import json
import subprocess
import sys

import pytest

import core.checks.legacy_plugins as lp
import engines.vulnerability.plugin_selector as selector
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT


def test_the_kernel_module_imports_no_engine_and_imports_nothing_by_name():
    tree = ast.parse(
        (BACKEND_ROOT / "core" / "checks" / "legacy_plugins.py").read_text()
    )
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Call):
            called = getattr(node.func, "attr", getattr(node.func, "id", ""))
            assert called not in ("import_module", "__import__"), called
    assert imported == {"__future__", "dataclasses", "typing", "core.checks.registry"}


def test_no_check_kernel_module_imports_above_the_kernel():
    """Lazy imports count; they are how the codebase hid its couplings."""
    _, edges = collect_edges()
    above = sorted(
        (e.src, e.dst)
        for e in edges
        if capability_map.capability_of(e.src) == "check_kernel"
        and capability_map.capability_of(e.dst) not in ("check_kernel", "infra")
    )
    assert above == []


_UNREGISTERED = r"""
import json, sys
import core.checks.legacy_plugins as lp
refused = {}
for name, call in (
    ("all_dispatchable_plugin_names", lambda: lp.all_dispatchable_plugin_names()),
    ("validate_all_plugins", lambda: lp.validate_all_plugins()),
    ("describe_plugin", lambda: lp.describe_plugin("snmp_probe", ("parallel",))),
    ("validate_plugin_module", lambda: lp.validate_plugin_module("snmp_probe", ("parallel",))),
):
    try:
        call()
        refused[name] = None
    except lp.NoPluginSource as exc:
        refused[name] = type(exc).__name__
print(json.dumps({
    "refused": refused,
    "sources": list(lp.registered_plugin_sources()),
    "engine_loaded": sorted(m for m in sys.modules if m.startswith("engines")),
}))
"""


def test_with_nothing_registered_the_kernel_refuses_and_loads_no_engine():
    done = subprocess.run(
        [sys.executable, "-c", _UNREGISTERED],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result["sources"] == []
    assert set(result["refused"].values()) == {"NoPluginSource"}
    assert result["engine_loaded"] == []


def test_the_selector_registers_its_own_tables():
    assert "network_checks" in lp.registered_plugin_sources()
    table = selector.dispatch_table()
    assert lp.all_dispatchable_plugin_names() == table
    expected = set(selector._ALWAYS_RUN) | set(selector._SERIAL_LAST)
    for names in selector._PORT_MAP.values():
        expected |= set(names)
    assert set(table) == expected
    assert {n for n, kinds in table.items() if "serial" in kinds} == set(
        selector._SERIAL_LAST
    )


def test_the_strict_loader_reports_the_error_the_selector_would_skip():
    contract = lp.describe_plugin("no_such_plugin_b5", ("parallel",))
    assert not contract.imported
    assert contract.error == (
        "ModuleNotFoundError: No module named "
        "'engines.vulnerability.plugins.no_such_plugin_b5'"
    )


class _Plugin:
    @staticmethod
    def run(ip, open_ports, port_details=None):
        return {}


def _fake_source(name="fake", table=None):
    table = table or {"fake_probe": ("parallel",)}
    return lp.PluginSource(
        name=name,
        dispatch_table=lambda: dict(table),
        load=lambda plugin: _Plugin,
    )


@pytest.fixture()
def isolated_sources(monkeypatch):
    """The registered sources, restored after the test."""
    monkeypatch.setattr(lp, "_SOURCES", dict(lp._SOURCES))
    return lp._SOURCES


def test_several_sources_merge_and_each_answers_for_its_own(isolated_sources):
    lp.register_plugin_source(_fake_source())
    names = lp.all_dispatchable_plugin_names()
    assert names["fake_probe"] == ("parallel",)
    assert set(selector.dispatch_table()) < set(names)
    assert lp.describe_plugin("fake_probe", ("parallel",)).ok
    assert lp.describe_plugin("cve_engine", ("serial",)).ok


def test_an_ambiguous_plugin_is_refused(isolated_sources):
    lp.register_plugin_source(_fake_source(table={"cve_engine": ("serial",)}))
    with pytest.raises(LookupError, match="cve_engine"):
        lp.all_dispatchable_plugin_names()
    with pytest.raises(LookupError, match="several sources"):
        lp.describe_plugin("cve_engine", ("serial",))
    with pytest.raises(LookupError, match="no source's dispatch table"):
        lp.describe_plugin("listed_nowhere", ("parallel",))


def test_registering_again_replaces_and_a_non_source_is_refused(isolated_sources):
    lp.register_plugin_source(_fake_source(table={"first": ("parallel",)}))
    lp.register_plugin_source(_fake_source(table={"second": ("parallel",)}))
    names = lp.all_dispatchable_plugin_names()
    assert "second" in names and "first" not in names
    with pytest.raises(TypeError):
        lp.register_plugin_source({"name": "fake"})
