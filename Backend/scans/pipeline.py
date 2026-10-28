"""
scans/pipeline.py
─────────────────────────────────────────────────────────────────────────────
The network scan pipeline, defined once (C6 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md): which phases each
pipeline mode runs, which registered task runs each phase, what each hands the
next, and the one function that hands it over.

    phase 1 host discovery ──HostRecord──▶ phase 2 asset discovery
                           ──ServiceInventory──▶ phase 3 vulnerability audit

    basic                1                (then topology, phase 4, if SNMP is configured)
    asset                1 → 2            (then topology)
    vulnerability_audit  1 → 2 → 3        (then topology)
    credentialed                     3    (the standalone credentialed task)

Until C6 each phase task dispatched the next by importing it
(``run_asset_discovery_task.delay(...)``), and the browser's continuation
dispatched them again by name. Both go through :func:`hand_over` now, by
registered name, with the typed hand-off of ``core.phase_handoff``. The task
names, queues, limits and signatures are unchanged (pinned in
``scripts/architecture/task_registry.json``), and so is what a task receives.

Where a phase stops is unchanged too: a phase continues to the next unless it
is its pipeline mode's terminal phase, or the scan runs interactively, where
the person continues it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from core import task_names
from core.phase_handoff import HostRecord

#: The logger these helpers wrote to in scan_helpers.py, where they were
#: defined until C6; kept so a log line an operator looks for is unchanged.
log = logging.getLogger("ccure.api")

__all__ = [
    "ASSET_DISCOVERY",
    "HOST_DISCOVERY",
    "NETWORK_PHASES",
    "PIPELINE_MODE_ALIASES",
    "PIPELINE_PHASES",
    "VALID_PIPELINE_MODES",
    "VULNERABILITY_AUDIT",
    "Phase",
    "get_terminal_phase",
    "hand_over",
    "is_phase_in_pipeline",
    "next_phase",
    "resolve_pipeline_mode",
]


# ─── Pipeline configuration (mirrors Frontend/src/modules/audit/config/scanConfig.js)
# Phase 4 (topology_mapping) is eligible to run at the end of any pipeline.
# It is only executed if SNMP credentials are provided in scan.options.
PIPELINE_PHASES: dict[str, list[int]] = {
    "basic": [1, 4],
    "asset": [1, 2, 4],
    "vulnerability_audit": [1, 2, 3, 4],
    # A standalone credentialed audit runs no discovery and no port scan. It
    # was previously recorded as "vulnerability_audit", which claimed three
    # phases it never executed — the scan record has to describe what ran.
    "credentialed": [3],
}

VALID_PIPELINE_MODES = set(PIPELINE_PHASES.keys()) | {"advanced"}
PIPELINE_MODE_ALIASES = {
    "advanced": "vulnerability_audit",
}


def _normalize_pipeline_mode(raw: str | None) -> str:
    token = str(raw or "").strip().lower()
    if not token:
        return "basic"
    return PIPELINE_MODE_ALIASES.get(token, token)


def get_terminal_phase(pipeline_mode: str) -> int:
    """Return the last *core* phase number for a given pipeline mode.
    Phase 4 (topology_mapping) is an optional bolt-on and does NOT
    count as the terminal phase for scan completion logic."""
    pipeline_mode = _normalize_pipeline_mode(pipeline_mode)
    phases = PIPELINE_PHASES.get(pipeline_mode, [1])
    # Exclude Phase 4 (topology) — it's an optional add-on, not core pipeline
    core_phases = [p for p in phases if p != 4]
    return max(core_phases) if core_phases else max(phases)


def is_phase_in_pipeline(pipeline_mode: str, phase: int) -> bool:
    """Return True if the given phase belongs to the declared pipeline."""
    pipeline_mode = _normalize_pipeline_mode(pipeline_mode)
    return phase in PIPELINE_PHASES.get(pipeline_mode, [1])


def resolve_pipeline_mode(raw: str | None) -> str:
    """
    Normalise and validate the pipeline_mode from a request.
    Falls back to 'basic' for unknown / missing values.
    """
    token = _normalize_pipeline_mode(raw)
    if token in VALID_PIPELINE_MODES:
        return token
    if raw:
        log.warning("Unknown pipeline_mode '%s' — defaulting to 'basic'.", raw)
    return "basic"


# ─── The network phases, in order ────────────────────────────────────────────


@dataclass(frozen=True)
class Phase:
    """A core phase of the network pipeline and the registered task that runs it."""

    number: int
    key: str
    task: str


HOST_DISCOVERY = Phase(1, "host_discovery", task_names.RUN_HOST_DISCOVERY)
ASSET_DISCOVERY = Phase(2, "asset_discovery", task_names.RUN_ASSET_DISCOVERY)
VULNERABILITY_AUDIT = Phase(
    3, "vulnerability_audit", task_names.RUN_VULNERABILITY_AUDIT
)

#: The order the phases run in. Phase 4, topology, is not a step of this
#: sequence: each phase that ends a pipeline offers it (``scans.tasks.topology``).
NETWORK_PHASES: tuple[Phase, ...] = (
    HOST_DISCOVERY,
    ASSET_DISCOVERY,
    VULNERABILITY_AUDIT,
)


def next_phase(
    pipeline_mode: str, after: Phase, *, interactive: bool = False
) -> Optional[Phase]:
    """
    The phase that follows *after* in this scan, or None where the scan stops.

    A phase stops the pipeline when it is the mode's terminal phase
    (``get_terminal_phase``), or when the scan runs interactively and the
    person continues it. Otherwise the next phase in ``NETWORK_PHASES``
    follows, which is the rule each phase task applied before C6.
    """
    if interactive or get_terminal_phase(pipeline_mode) == after.number:
        return None
    position = NETWORK_PHASES.index(after)
    if position + 1 >= len(NETWORK_PHASES):
        return None
    return NETWORK_PHASES[position + 1]


def hand_over(phase: Phase, hosts: Sequence[HostRecord], **settings: Any):
    """
    Start *phase* with *hosts*, by its registered name.

    The records cross as their own dicts (``HostRecord.wire``), so the task
    receives exactly what its producer wrote. *settings* are the task's other
    arguments. Returns the dispatched task's result handle; a broker that
    refuses the dispatch raises, and the caller settles the scan as failed.
    """
    from core.celery_app import registered_task

    return registered_task(phase.task).delay(
        hosts=[host.wire() for host in hosts], **settings
    )
