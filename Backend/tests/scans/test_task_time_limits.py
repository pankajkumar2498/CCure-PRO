"""Every scan task must declare its own time limits, and the soft one must be
catchable by the task's own error handling.

The defect this guards against shipped for nine months and was invisible the
whole time. `core/celery_app.py` set one global
``task_time_limit = NMAP_TIMEOUT + 60`` — 360 seconds — for every task in the
application. That is a unit error: ``NMAP_TIMEOUT`` is the lease on a *single*
nmap invocation, while a scan task spawns many and can wait
``NMAP_PROCESS_WAIT_TIMEOUT`` (900s) just to acquire one slot.

It did no damage on the Windows host worker, which ran ``--pool=threads``,
where Celery's hard limit cannot fire at all. The Linux VM worker runs prefork,
where it does: measured 22 Sep 2026, a task was killed at exactly 360s. Against
the deployment's own scan history that would have killed 11 of 48 completed
scans.

Two properties are defended here, and the second is the subtle one:

  1. every scan task carries explicit ``soft_time_limit`` and ``time_limit``,
     so nothing silently inherits a number meant for something else; and
  2. the soft limit comes *first*, because only the soft limit can be caught.

``SoftTimeLimitExceeded`` subclasses ``Exception``, so each task's own
``except Exception -> _settle_failure`` records an honest failure. A hard limit
raises ``SystemExit`` in the child, which is a ``BaseException`` and is **not**
caught by those handlers — so a scan killed by the hard limit is never settled
and sits ``running`` until ``reap_stalled_scans`` finds it. The hard limit is a
backstop for a task wedged in uninterruptible code, never the working deadline.

These are read off the registered task objects rather than the decorator
source, so a limit removed anywhere in the chain fails the test.
"""

from __future__ import annotations

import pytest
from celery.exceptions import SoftTimeLimitExceeded, TimeLimitExceeded

from core.celery_app import celery_app

#: Every task that performs a scan. A new one belongs here *and* needs its own
#: budget in ``config.py`` — nothing inherits a limit now that the global is
#: gone, so a task missing from this list would run unbounded.
SCAN_TASKS = [
    "ccure.tasks.run_host_discovery",
    "ccure.tasks.run_asset_discovery",
    "ccure.tasks.run_vulnerability_audit",
    "ccure.tasks.run_topology_mapping",
    "ccure.tasks.run_traditional_scan",
    "ccure.tasks.run_credentialed_scan",
    "ccure.tasks.sync_host_discovery_task",
    "ccure.tasks.sync_asset_discovery_task",
    "ccure.tasks.sync_vulnerability_audit_task",
    "ccure.web.run_recon",
    "ccure.web.run_crawl",
    "ccure.web.run_detect",
    "ccure.web.run_audit",
]

#: The old global. Any task whose budget lands back on this number is almost
#: certainly inheriting ``NMAP_TIMEOUT + 60`` again rather than stating its own.
_OLD_GLOBAL_LIMIT = 360


@pytest.fixture(scope="module", autouse=True)
def _import_tasks():
    """Celery registers tasks lazily; the names are absent until imported."""
    celery_app.loader.import_default_modules()


def _task(name):
    task = celery_app.tasks.get(name)
    assert task is not None, (
        f"{name} is not registered. If it was renamed, rename it here too — "
        "a stale entry makes this test pass while guarding nothing."
    )
    return task


def test_no_global_task_time_limit():
    """A global limit has to be sized for the longest task, at which point it
    bounds nothing — and the failure it produces is the uncatchable kind."""
    assert celery_app.conf.task_time_limit is None, (
        "A global task_time_limit is set again. It applies to every task in the "
        "application, including tasks it was never sized for. Give the task its "
        "own soft_time_limit/time_limit from config.SCAN_TIME_LIMIT_* instead."
    )


@pytest.mark.parametrize("name", SCAN_TASKS)
def test_scan_task_declares_both_limits(name):
    task = _task(name)
    assert task.soft_time_limit, (
        f"{name} has no soft_time_limit. Only the soft limit routes through the "
        "task's own `except Exception -> _settle_failure`; without it a timeout "
        "leaves the scan 'running' until reap_stalled_scans settles it."
    )
    assert task.time_limit, f"{name} has no time_limit (hard backstop)."


@pytest.mark.parametrize("name", SCAN_TASKS)
def test_soft_limit_precedes_hard_limit(name):
    """The hard limit must never be reached first, or the catchable failure
    path is dead code."""
    task = _task(name)
    assert task.soft_time_limit < task.time_limit, (
        f"{name}: soft_time_limit ({task.soft_time_limit}) must be strictly "
        f"below time_limit ({task.time_limit}). Reached the other way round, "
        "the task is SIGKILLed before its own handler can settle the scan."
    )


@pytest.mark.parametrize("name", SCAN_TASKS)
def test_limit_is_not_the_old_global(name):
    task = _task(name)
    assert task.soft_time_limit != _OLD_GLOBAL_LIMIT, (
        f"{name} is bounded at {_OLD_GLOBAL_LIMIT}s, the old "
        "NMAP_TIMEOUT + 60 global. That is one nmap invocation's lease, not a "
        "budget for a task that spawns many of them."
    )


def test_soft_limit_is_catchable_and_hard_limit_is_not():
    """The whole reason the soft limit is the working deadline.

    Pinned as a property of Celery's own exception hierarchy rather than left
    as a comment, because the distinction is invisible at the call site: both
    handlers read `except Exception`, and only one of the two ever runs.
    """
    assert issubclass(SoftTimeLimitExceeded, Exception)
    assert issubclass(TimeLimitExceeded, Exception)
    # What a prefork child actually receives when the hard limit fires.
    assert not issubclass(SystemExit, Exception)
    assert issubclass(SystemExit, BaseException)


def test_vulnerability_audit_budget_clears_the_longest_recorded_scan():
    """11,714s (3h15m) is the longest scan in this deployment's history.

    A budget below it would reintroduce the same defect with a bigger number.
    """
    task = _task("ccure.tasks.run_vulnerability_audit")
    assert task.soft_time_limit >= 14400, (
        "The vulnerability audit budget must clear the longest scan on record "
        f"(11,714s); it is {task.soft_time_limit}s."
    )
