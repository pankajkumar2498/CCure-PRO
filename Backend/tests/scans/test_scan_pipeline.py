"""
The network scan pipeline's one definition (C6, ``scans/pipeline.py``).

Which phase follows which is decided here now, not in each phase task, so
these pin that the decision is the one every task made before C6, for every
pipeline mode, phase and interactive setting; that a phase is handed its hosts
by registered name, as the records' own dicts; and that the pipeline table
``scan_helpers`` used to define is the same object there.
"""

import pytest

import scan_helpers
from core import task_names
from core.celery_app import registered_task
from core.phase_handoff import host_records
from scans import pipeline
from scans.pipeline import (
    ASSET_DISCOVERY,
    HOST_DISCOVERY,
    NETWORK_PHASES,
    PIPELINE_PHASES,
    VULNERABILITY_AUDIT,
    get_terminal_phase,
    hand_over,
    next_phase,
)

MODES = sorted(PIPELINE_PHASES) + ["advanced", "unknown", "", None]


def _pre_c6_next(mode, phase_number, interactive):
    """What each phase task chained to before C6: the next phase unless this
    one was the mode's terminal phase or the scan was interactive; phase 3
    chained nothing."""
    if phase_number == 3:
        return None
    is_final = (get_terminal_phase(mode) == phase_number) or interactive
    return None if is_final else phase_number + 1


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("phase", NETWORK_PHASES, ids=lambda p: p.key)
@pytest.mark.parametrize("interactive", [False, True])
def test_the_next_phase_is_the_one_each_task_chose(mode, phase, interactive):
    following = next_phase(
        pipeline.resolve_pipeline_mode(mode), phase, interactive=interactive
    )
    expected = _pre_c6_next(
        pipeline.resolve_pipeline_mode(mode), phase.number, interactive
    )
    assert (following.number if following else None) == expected


def test_the_phases_run_in_order_under_their_registered_names():
    assert [(p.number, p.task) for p in NETWORK_PHASES] == [
        (1, task_names.RUN_HOST_DISCOVERY),
        (2, task_names.RUN_ASSET_DISCOVERY),
        (3, task_names.RUN_VULNERABILITY_AUDIT),
    ]
    for phase in NETWORK_PHASES:
        assert registered_task(phase.task).name == phase.task


def test_the_pipeline_table_is_the_one_scan_helpers_offers():
    for name in (
        "PIPELINE_PHASES",
        "VALID_PIPELINE_MODES",
        "PIPELINE_MODE_ALIASES",
        "get_terminal_phase",
        "is_phase_in_pipeline",
        "resolve_pipeline_mode",
    ):
        assert getattr(scan_helpers, name) is getattr(pipeline, name), name


@pytest.mark.parametrize("phase", [ASSET_DISCOVERY, VULNERABILITY_AUDIT])
def test_a_phase_is_handed_its_hosts_by_name_as_their_own_dicts(monkeypatch, phase):
    sent = {}

    class _Result:
        id = "task-1"

    def _delay(**kwargs):
        sent.update(kwargs)
        return _Result()

    monkeypatch.setattr(registered_task(phase.task), "delay", _delay)
    wires = [{"ip_address": "10.0.0.1", "is_active": True, "x": 1}]
    result = hand_over(phase, host_records(wires), user_id="u", scan_id="s")
    assert result.id == "task-1"
    assert sent["hosts"] == wires
    assert sent["hosts"][0] is wires[0]
    assert {k: v for k, v in sent.items() if k != "hosts"} == {
        "user_id": "u",
        "scan_id": "s",
    }


def test_a_refused_dispatch_is_raised_to_the_phase(monkeypatch):
    def _refuse(**kwargs):
        raise ConnectionError("broker down")

    monkeypatch.setattr(registered_task(ASSET_DISCOVERY.task), "delay", _refuse)
    with pytest.raises(ConnectionError):
        hand_over(ASSET_DISCOVERY, host_records([{"ip_address": "10.0.0.1"}]))


def test_host_discovery_is_not_handed_hosts():
    # The pipeline starts with a request, not a hand-off.
    assert next_phase("vulnerability_audit", HOST_DISCOVERY) is ASSET_DISCOVERY
    assert HOST_DISCOVERY not in [
        next_phase(m, p) for m in PIPELINE_PHASES for p in NETWORK_PHASES
    ]
