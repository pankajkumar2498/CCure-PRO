"""
Every Celery task's declared interface, and the beat schedule, pinned.

A task's name is what a message, the beat schedule and every by-name dispatch
carry, but the name is not all of a task's interface:

* its queue decides which worker runs it (``test_worker_queue_mapping.py``
  pins that too, with the workers that consume each queue);
* its soft and hard time limits bound it;
* its retry and acknowledgement options decide what happens when it fails;
* its signature is the set of arguments a message already in the broker was
  built with, and for a ``bind=True`` task it starts with ``self``.

G1 moves every scan task out of ``core/tasks.py``
(docs/architecture/MODULAR_REFACTORING_LOG.md §6). A move that kept a task's
name and changed any of the above would pass every by-name check and change
how the task behaves. ``scripts/architecture/task_registry.json`` was written
from the code before the move; regenerate it only for an intended change to a
task's interface, and say which in review:

    python -m scripts.architecture.interface_snapshot --registry \\
        > scripts/architecture/task_registry.json        # from Backend/
"""

import json

from scripts.architecture import interface_snapshot
from testpaths import BACKEND_ROOT

PINNED = BACKEND_ROOT / "scripts" / "architecture" / "task_registry.json"


def _pinned() -> dict:
    return json.loads(PINNED.read_text(encoding="utf-8"))


def _differences(section: str) -> list[str]:
    current = interface_snapshot.task_registry()
    return interface_snapshot.compare(
        {section: _pinned()[section]}, {section: current[section]}
    )


def test_every_task_is_registered_with_what_it_declared():
    problems = _differences("tasks")
    assert not problems, (
        "a task's registered interface changed:\n  "
        + "\n  ".join(problems)
        + "\nIf the change is intended, regenerate the pin (this module's docstring)."
    )


def test_the_beat_schedule_is_unchanged():
    problems = _differences("beat")
    assert not problems, "the beat schedule changed:\n  " + "\n  ".join(problems)


def test_the_pin_records_the_scan_tasks_with_their_limits():
    # A pin generated from a process that had not loaded the task modules
    # would hold nothing worth comparing against.
    tasks = _pinned()["tasks"]
    scan = tasks["ccure.tasks.run_credentialed_scan"]
    assert scan["queue"] == "scanner"
    assert scan["soft_time_limit"] and scan["time_limit"] > scan["soft_time_limit"]
    assert tasks["ccure.tasks.run_host_discovery"]["signature"].startswith("(self, ")
    assert len(tasks) == len(set(tasks)) >= 36
