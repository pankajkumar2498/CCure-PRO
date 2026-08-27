"""
tests/scans/test_plugin_contract.py
─────────────────────────────────────────────────────────────────────────────
Every vulnerability plugin the selector can dispatch must be callable the way
the engine dispatches it.

The defect this guards
──────────────────────
``VulnerabilityEngine`` calls serial plugins with three positional arguments
and parallel plugins with two, and catches every plugin exception at DEBUG
level. A plugin whose ``run`` accepts the wrong arity therefore:

  * raises ``TypeError`` on every host,
  * is swallowed by the engine's ``except Exception``,
  * still appears in ``plugin_names()`` and in ``select_plugins()``,
  * and produces **zero findings, indefinitely, with nothing in the logs**.

CLAUDE.md records this as one of four defects that each produced no findings
until someone scanned a target they already knew was vulnerable and noticed the
silence. Nothing structural stops it recurring — the next plugin added with a
two-argument ``run`` and a ``_SERIAL_LAST`` entry reproduces it exactly.

This test is that structural stop. It is deliberately static: it inspects
signatures rather than running plugins, so it needs no network, no target and
no Nmap, and it runs in CI in milliseconds.

Why it reads the selector's tables rather than ``plugins.__all__``
─────────────────────────────────────────────────────────────────
``__all__`` is the import list. ``_PORT_MAP`` / ``_ALWAYS_RUN`` /
``_SERIAL_LAST`` are what actually decide whether a plugin ever runs, and with
which arity. Validating the import list would pass a plugin that is imported
and dispatched nowhere, and would say nothing at all about arity.
"""

import pytest
from core.checks.legacy_plugins import (
    PARALLEL_ARITY,
    SERIAL_ARITY,
    all_dispatchable_plugin_names,
    describe_plugin,
    validate_all_plugins,
)

DISPATCHABLE = all_dispatchable_plugin_names()


def test_the_selector_dispatches_a_plausible_number_of_plugins():
    """
    A guard on the guard. If the selector's tables were renamed or emptied,
    ``all_dispatchable_plugin_names()`` would return nothing and every
    parametrised case below would silently vanish — a green suite proving
    nothing, which is the failure mode this whole file exists to prevent.
    """
    assert len(DISPATCHABLE) >= 15, (
        f"only {len(DISPATCHABLE)} dispatchable plugins found: {sorted(DISPATCHABLE)}. "
        "If plugins were genuinely removed, lower this floor deliberately; if "
        "plugin_selector's tables were renamed, this test is now inspecting "
        "nothing."
    )


@pytest.mark.parametrize("name", sorted(DISPATCHABLE))
def test_plugin_is_callable_as_dispatched(name):
    contract = describe_plugin(name, DISPATCHABLE[name])
    assert contract.ok, (
        f"plugin '{name}' (dispatched as {', '.join(contract.dispatch)}) cannot "
        f"run as the engine calls it:\n  - " + "\n  - ".join(contract.problems)
    )


def test_no_dispatchable_plugin_is_broken():
    """The aggregate form, so a failure names every broken plugin at once
    rather than one per parametrised case."""
    broken = validate_all_plugins()
    assert not broken, f"plugins that cannot run as dispatched: {broken}"


def test_serial_plugins_accept_the_three_argument_form():
    """
    The specific arity mismatch that shipped. Serial plugins receive
    ``(ip, open_ports, port_details)``; a two-argument ``run`` is the exact
    shape that failed silently.
    """
    serial = [n for n, kinds in DISPATCHABLE.items() if "serial" in kinds]
    assert serial, "no serial plugins found — _SERIAL_LAST is empty or renamed"
    for name in serial:
        contract = describe_plugin(name, DISPATCHABLE[name])
        assert contract.accepts_serial, (
            f"serial plugin '{name}' does not accept {SERIAL_ARITY} positional "
            f"arguments. The engine calls run(ip, open_ports, port_details); "
            f"this plugin would raise TypeError on every host and be swallowed."
        )


def test_parallel_plugins_accept_the_two_argument_form():
    parallel = [n for n, kinds in DISPATCHABLE.items() if "parallel" in kinds]
    assert parallel, "no parallel plugins found — _PORT_MAP/_ALWAYS_RUN empty"
    for name in parallel:
        contract = describe_plugin(name, DISPATCHABLE[name])
        assert contract.accepts_parallel, (
            f"parallel plugin '{name}' does not accept {PARALLEL_ARITY} "
            f"positional arguments. The engine calls run(ip, open_ports)."
        )


def test_every_dispatchable_plugin_actually_imports():
    """
    ``plugin_selector`` imports lazily and logs an ImportError at WARNING, then
    carries on without the plugin. That is the right runtime behaviour — one
    broken plugin must not stop a scan — but it means a plugin can be broken
    for a whole release with only a log line to show for it.
    """
    failed = {
        name: describe_plugin(name, kinds).error
        for name, kinds in DISPATCHABLE.items()
        if not describe_plugin(name, kinds).imported
    }
    assert not failed, f"plugins that fail to import: {failed}"


def test_every_dispatchable_plugin_exposes_run():
    missing = [
        name
        for name, kinds in DISPATCHABLE.items()
        if describe_plugin(name, kinds).imported
        and not describe_plugin(name, kinds).has_run
    ]
    assert not missing, (
        f"plugins with no callable `run`: {missing}. plugin_selector will "
        "return these and the engine will raise AttributeError on every host."
    )


def test_registry_and_selector_agree_on_which_plugins_exist():
    """
    ``plugins/__init__.py`` is the explicit import registry and the selector's
    tables are the dispatch list. A plugin in the dispatch tables but missing
    from the registry still works (the selector imports lazily by name), but
    the divergence means one of the two is stale — and the registry is what a
    reader consults to learn what exists.
    """
    from engines.vulnerability import plugins as plugin_registry

    registered = set(plugin_registry.__all__)
    dispatched = set(DISPATCHABLE)
    assert dispatched <= registered, (
        "dispatched but not listed in plugins.__all__: "
        f"{sorted(dispatched - registered)}"
    )
