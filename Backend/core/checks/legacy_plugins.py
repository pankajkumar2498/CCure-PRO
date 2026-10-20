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

Where the plugins come from
───────────────────────────
This module is the check kernel, which every capability imports, so it imports
no engine. The engine that owns plugins registers them instead: a
:class:`PluginSource` says how the engine dispatches its plugins and how to
import one, and ``engines.vulnerability.plugin_selector`` registers the network
checks' source when it is imported (B5, docs/architecture/
MODULAR_REFACTORING_LOG.md §6). Until B5 this module imported the selector and
the plugin package itself.

With no source registered, every function below raises :class:`NoPluginSource`.
It never answers with an empty mapping, which would read as "every plugin is
callable" about plugins nobody looked at.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from core.checks.registry import _accepts_arity

__all__ = [
    "PARALLEL_ARITY",
    "SERIAL_ARITY",
    "NoPluginSource",
    "PluginContract",
    "PluginSource",
    "all_dispatchable_plugin_names",
    "describe_plugin",
    "register_plugin_source",
    "registered_plugin_sources",
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


class NoPluginSource(LookupError):
    """No engine has registered its plugins, so there is nothing to verify."""


@dataclass(frozen=True)
class PluginSource:
    """
    An engine's plugins, as the engine dispatches them.

    ``dispatch_table`` maps every plugin the engine can call to how it calls it
    (``"parallel"``, ``"serial"`` or both). It must be read from what decides
    dispatch, never from an import list. ``load`` imports one plugin module by
    short name and raises whatever its import raises: an import error is a
    finding here, so a loader that logs and skips would hide it.
    """

    name: str
    dispatch_table: Callable[[], Mapping[str, Tuple[str, ...]]]
    load: Callable[[str], Any]


_SOURCES: Dict[str, PluginSource] = {}


def register_plugin_source(source: PluginSource) -> None:
    """
    Register an engine's plugins. Called by the engine when it is imported.

    A source registered again under the same name replaces the earlier one, so
    reloading the engine's module does not leave a stale copy behind.
    """
    if not isinstance(source, PluginSource):
        raise TypeError(f"expected a PluginSource, got {type(source).__name__}")
    if not callable(source.dispatch_table) or not callable(source.load):
        raise TypeError(
            f"plugin source {source.name!r} needs a callable table and loader"
        )
    _SOURCES[source.name] = source


def registered_plugin_sources() -> Tuple[str, ...]:
    """The names of the registered sources, sorted."""
    return tuple(sorted(_SOURCES))


def _sources() -> List[PluginSource]:
    if not _SOURCES:
        raise NoPluginSource(
            "no plugin source is registered. The network checks register theirs "
            "when engines.vulnerability.plugin_selector is imported; import it "
            "first."
        )
    return [_SOURCES[name] for name in sorted(_SOURCES)]


def _source_for(name: str) -> PluginSource:
    """The source that dispatches *name*, or the only source when none lists it."""
    sources = _sources()
    owners = [s for s in sources if name in s.dispatch_table()]
    if len(owners) > 1:
        raise LookupError(
            f"plugin {name!r} is dispatched by several sources: "
            f"{[s.name for s in owners]}"
        )
    if owners:
        return owners[0]
    if len(sources) == 1:
        return sources[0]
    raise LookupError(
        f"plugin {name!r} is in no source's dispatch table, and there are "
        f"several sources to ask: {[s.name for s in sources]}"
    )


def all_dispatchable_plugin_names() -> Dict[str, Tuple[str, ...]]:
    """
    Every plugin a registered engine can dispatch, mapped to how it is
    dispatched.

    Each source reads its own dispatch tables rather than its import list. For
    the network checks that is ``plugin_selector``'s ``_PORT_MAP``,
    ``_ALWAYS_RUN`` and ``_SERIAL_LAST``, not ``plugins/__all__``. The two
    disagree in a way that matters: ``__all__`` is the import list, while the
    tables decide whether a plugin ever runs. Validating the import list would
    pass a plugin that is imported and dispatched nowhere, and would say
    nothing about the arity it is dispatched with.
    """
    merged: Dict[str, Tuple[str, ...]] = {}
    owner: Dict[str, str] = {}
    for source in _sources():
        for name, kinds in source.dispatch_table().items():
            if name in owner:
                raise LookupError(
                    f"plugin {name!r} is dispatched by both {owner[name]!r} "
                    f"and {source.name!r}"
                )
            owner[name] = source.name
            merged[name] = tuple(kinds)
    return dict(sorted(merged.items()))


def describe_plugin(name: str, dispatch: Tuple[str, ...]) -> PluginContract:
    """Import one plugin by short name and report what it offers."""
    module: Any
    # Outside the try: no registered source is a refusal, not a plugin's import error.
    source = _source_for(name)
    try:
        module = source.load(name)
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
