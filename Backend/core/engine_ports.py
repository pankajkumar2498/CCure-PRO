"""
What a scan engine needs from whoever runs it: somewhere to report progress,
and a way to learn that it should stop.

The discovery, port and network-check engines used to do both themselves. They
imported ``core.redis_client`` to publish progress frames, and the discovery
engine imported ``core.scan_control`` to persist its counters and to read the
scan's status from the ``scans`` table. An engine that has to reach the scan
record and the message broker cannot run, or be tested, without them.

They now receive both as arguments. The orchestrator builds them for a scan
(``core.scan_control.engine_ports``), and the Redis channel, the
``scans.options`` counters and the ``scans.status`` read stay there. An engine
that is given neither reports nothing and is never cancelled, which is what it
did before when it was given no scan id.

Both interfaces are structural (``typing.Protocol``): an implementation needs
the methods, not this module. This module imports nothing from the application.
"""

from __future__ import annotations

from typing import Protocol


class ProgressSink(Protocol):
    """Where an engine reports how far it has got.

    ``publish`` is for engines running on an event loop and ``publish_sync`` for
    those running in threads; both send one progress frame for a phase. ``start``
    and ``record`` keep the counters a progress endpoint reads back (targets in
    total, targets done so far). None of them may raise into the engine: a
    progress report that fails must never fail a scan.
    """

    def start(self, total: int) -> None: ...

    async def publish(self, phase: int, progress: dict) -> None: ...

    def publish_sync(self, phase: int, progress: dict) -> None: ...

    def record(self, done: int, active: int | None = None) -> None: ...


class CancelToken(Protocol):
    """How an engine learns that the scan it serves has been cancelled.

    ``is_cancelled`` answers without raising, so an engine can poll it between
    batches. ``raise_if_cancelled`` raises the runner's own cancellation
    exception, which the runner then handles; the engine does not need to know
    its type. Cancellation is cooperative: an engine checks between units of
    work, never inside one.
    """

    def is_cancelled(self) -> bool: ...

    def raise_if_cancelled(self) -> None: ...


class _NeverCancelled:
    """The token for a run nobody can cancel: an ad-hoc scan with no scan record."""

    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    def __repr__(self) -> str:
        return "uncancellable run"


NEVER_CANCELLED: CancelToken = _NeverCancelled()
