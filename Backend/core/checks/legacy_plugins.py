"""
core/checks/legacy_plugins.py
─────────────────────────────────────────────────────────────────────────────
The contract the existing vulnerability plugins already speak, written down so
it can be verified instead of assumed.

Why this is a separate module from ``registry.py``
──────────────────────────────────────────────────
The fifteen plugins under ``engines/vulnerability/plugins/`` are stable, in
production, and produce real findings. Rewriting them onto the new
:class:`~core.checks.contract.CheckResult` contract would be a large refactor
with no capability gained, and this project's Phase 0 brief says not to
refactor stable functionality for its own sake. What the plugins are missing is
not a better shape — it is any enforcement of the shape they already have.

So the legacy contract is described here in a form a test can execute, and the
plugins stay exactly as they are. New capabilities use ``core.checks.registry``;
existing ones get the guard they never had.

The contract, as ``VulnerabilityEngine`` actually calls it
──────────────────────────────────────────────────────────
Two conventions, and the difference between them is the whole point:

    parallel   plugin.run(ip, open_ports)                 → dict
    serial     plugin.run(ip, open_ports, port_details)   → dict

``vulnerability_engine._run_single_plugin`` calls the first form inside a
``ThreadPoolExecutor`` and swallows every exception; ``_run_plugins`` calls the
second form in a loop and logs failures at DEBUG. Either way, a plugin whose
``run`` does not accept the arity it will be called with raises ``TypeError``
on every host and is never heard from again — while ``plugin_names()`` keeps
listing it and ``select_plugins()`` keeps returning it.

CLAUDE.md records this as one of four defects that each produced zero findings
in production. :func:`validate_plugin_module` is the executable form of that
paragraph.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.checks.registry import _accepts_arity

__all__ = [
    "PARALLEL_ARITY",
    "SERIAL_ARITY",
    "PluginContract",
    "all_dispatchable_plugin_names",
    "describe_plugin",
    "validate_plugin_module",
    "validate_all_plugins",
]

#: ``VulnerabilityEngine._run_single_plugin`` → ``plugin.run(ip, open_ports)``
PARALLEL_ARITY: int = 2
#: ``VulnerabilityEngine._run_plugins`` serial loop →
#: ``plugin.run(ip, open_ports, port_dets)``
SERIAL_ARITY: int = 3


@dataclass(frozen=True)
class PluginContract:
    """What one plugin module offers, and whether the engine can call it."""

    name: str
    imported: bool
    #: How the engine dispatches this plugin. A plugin can be reachable both
    #: ways if it is named in ``_SERIAL_LAST`` and in ``_PORT_MAP``; both
    #: arities are then required of it.
    dispatch: Tuple[str, ...]
    has_run: bool
    accepts_parallel: bool
    accepts_serial: bool
    error: Optional[str] = None

    @property
    def problems(self) -> List[str]:
        """Every reason this plugin cannot run as dispatched. Empty is good."""
        issues: List[str] = []
        if not self.imported:
            issues.append(f"module failed to import: {self.error}")
            return issues
        if not self.has_run:
            issues.append(
                "module has no callable `run` — plugin_selector will return it "
                "and the engine will raise AttributeError on every host"
            )
            return issues
        if "parallel" in self.dispatch and not self.accepts_parallel:
            issues.append(
                f"run() does not accept {PARALLEL_ARITY} positional arguments, "
                "but the plugin is reachable from _PORT_MAP/_ALWAYS_RUN, where "
                "the engine calls run(ip, open_ports)"
            )
        if "serial" in self.dispatch and not self.accepts_serial:
            issues.append(
                f"run() does not accept {SERIAL_ARITY} positional arguments, "
                "but the plugin is named in _SERIAL_LAST, where the engine "
                "calls run(ip, open_ports, port_details)"
            )
        return issues

    @property
    def ok(self) -> bool:
        return not self.problems


def all_dispatchable_plugin_names() -> Dict[str, Tuple[str, ...]]:
    """
    Every plugin the selector can hand to the engine, mapped to how it is
    dispatched.

    Read from ``plugin_selector``'s own tables rather than from
    ``plugins/__all__``. The two disagree in a way that matters: ``__all__`` is
    the import list, while ``_PORT_MAP``/``_ALWAYS_RUN``/``_SERIAL_LAST`` are
    what actually decides whether a plugin ever runs. Validating the import
    list would pass a plugin that is imported and dispatched nowhere, and would
    say nothing about the arity it is dispatched with.
    """
    from engines.vulnerability import plugin_selector as selector

    dispatch: Dict[str, set] = {}
    for name in selector._ALWAYS_RUN:
        dispatch.setdefault(name, set()).add("parallel")
    for names in selector._PORT_MAP.values():
        for name in names:
            dispatch.setdefault(name, set()).add("parallel")
    for name in selector._SERIAL_LAST:
        dispatch.setdefault(name, set()).add("serial")
    return {name: tuple(sorted(kinds)) for name, kinds in sorted(dispatch.items())}


def describe_plugin(name: str, dispatch: Tuple[str, ...]) -> PluginContract:
    """Import one plugin by short name and report what it offers."""
    module: Any
    try:
        module = importlib.import_module(f"engines.vulnerability.plugins.{name}")
    except Exception as exc:  # noqa: BLE001 — an import error is a finding here
        return PluginContract(
            name=name,
            imported=False,
            dispatch=dispatch,
            has_run=False,
            accepts_parallel=False,
            accepts_serial=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    run = getattr(module, "run", None)
    if not callable(run):
        return PluginContract(
            name=name,
            imported=True,
            dispatch=dispatch,
            has_run=False,
            accepts_parallel=False,
            accepts_serial=False,
        )

    return PluginContract(
        name=name,
        imported=True,
        dispatch=dispatch,
        has_run=True,
        accepts_parallel=_accepts_arity(run, PARALLEL_ARITY),
        accepts_serial=_accepts_arity(run, SERIAL_ARITY),
    )


def validate_plugin_module(name: str, dispatch: Tuple[str, ...]) -> List[str]:
    """Problems with one plugin. Empty list means it can run as dispatched."""
    return describe_plugin(name, dispatch).problems


def validate_all_plugins() -> Dict[str, List[str]]:
    """
    Validate every dispatchable plugin.

    Returns a mapping of plugin name → problems, containing only the plugins
    that have problems. An empty mapping means every plugin the selector can
    dispatch is callable the way the engine dispatches it.
    """
    broken: Dict[str, List[str]] = {}
    for name, dispatch in all_dispatchable_plugin_names().items():
        problems = validate_plugin_module(name, dispatch)
        if problems:
            broken[name] = problems
    return broken
