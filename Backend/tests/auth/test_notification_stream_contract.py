"""
The notification SSE stream (``GET /notifications/stream``) — its contract, and
what its "closed before its first heartbeat" warning does and does not mean.

The stream had no test. It was investigated on 3 Oct 2026 after a production
log line, and found to be working as designed:

* the first frame is ``connected`` and carries the unread summary, so a client
  that reconnects after a gap gets the correct count from the durable inbox
  (PostgreSQL) — the stream is a live push, not the record of notifications;
* a Redis message is relayed under its own event name; a quiet connection gets a
  ``heartbeat``;
* the "closed after N s, before its first heartbeat" WARNING is the connection
  ending early on the **client's** side (a page load or layout remount aborts the
  request). It is not a failure of the stream, and it is emitted only when
  cleanup runs to the end — a client abort cancelled mid-cleanup logs nothing —
  so its absence proves nothing and its presence is not an incident.

These tests drive the endpoint's generator directly with a fake Redis pub/sub.
"""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace

import ccure_platform.notifications.router as nr


class FakePubSub:
    def __init__(self, messages):
        self._messages = list(messages)
        self.subscribed = None
        self.unsubscribed = None
        self.closed = False

    async def subscribe(self, channel):
        self.subscribed = channel

    async def get_message(self, ignore_subscribe_messages=True, timeout=0):
        if self._messages:
            return self._messages.pop(0)
        return None  # a quiet interval: the stream sends a heartbeat

    async def unsubscribe(self, channel):
        self.unsubscribed = channel

    async def close(self):
        self.closed = True


def _stream(monkeypatch, pubsub):
    monkeypatch.setattr(nr, "redis_client", SimpleNamespace(pubsub=lambda: pubsub))
    monkeypatch.setattr(nr, "SessionLocal", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(
        nr, "summary_payload", lambda db, uid: {"total_unread": 3, "by_category": {}}
    )
    response = asyncio.run(
        nr.stream_notifications(request=None, current_user=SimpleNamespace(id="u-1"))
    )
    return response


def _parse(frame: str):
    lines = frame.strip().split("\n")
    return lines[0].removeprefix("event: "), json.loads(lines[1].removeprefix("data: "))


def test_first_frame_is_connected_with_the_durable_unread_summary(monkeypatch):
    pubsub = FakePubSub([])
    response = _stream(monkeypatch, pubsub)
    assert response.headers["x-accel-buffering"] == "no"

    async def first():
        it = response.body_iterator
        frame = await it.__anext__()
        await it.aclose()
        return frame

    event, data = _parse(asyncio.run(first()))
    assert event == "connected"
    assert data["ok"] is True and data["summary"]["total_unread"] == 3


def test_a_published_message_is_relayed_under_its_own_event_then_heartbeats(
    monkeypatch,
):
    message = {
        "data": json.dumps(
            {"event": "notification.created", "notification": {"id": "n1"}}
        )
    }
    pubsub = FakePubSub([message])
    response = _stream(monkeypatch, pubsub)

    async def frames():
        it = response.body_iterator
        got = [await it.__anext__() for _ in range(3)]
        await it.aclose()
        return got

    got = asyncio.run(frames())
    assert [_parse(f)[0] for f in got] == [
        "connected",
        "notification.created",
        "heartbeat",
    ]
    assert _parse(got[1])[1]["notification"]["id"] == "n1"
    assert pubsub.subscribed == "notifications:user:u-1"


def test_closing_cleans_up_the_subscription(monkeypatch):
    pubsub = FakePubSub([])
    response = _stream(monkeypatch, pubsub)

    async def drive():
        it = response.body_iterator
        await it.__anext__()  # connected
        await it.__anext__()  # heartbeat: the subscription is live
        await it.aclose()

    asyncio.run(drive())
    assert pubsub.unsubscribed == "notifications:user:u-1"
    assert pubsub.closed is True


def test_an_early_close_that_completes_cleanup_logs_the_known_warning(
    monkeypatch, caplog
):
    """The warning is a client-side early close, not a stream fault."""
    pubsub = FakePubSub([])
    response = _stream(monkeypatch, pubsub)

    async def drive():
        it = response.body_iterator
        await it.__anext__()
        await it.__anext__()
        await it.aclose()

    with caplog.at_level(logging.WARNING, logger=nr.logger.name):
        asyncio.run(drive())
    warned = [r for r in caplog.records if "before its first heartbeat" in r.message]
    assert len(warned) == 1
    assert warned[0].name == "routers.notifications"  # the legacy logger name
