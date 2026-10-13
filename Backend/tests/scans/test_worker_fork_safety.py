"""
A Celery prefork child gets its own database connections.

13 Oct 2026: one ``vuln_intel`` connection, opened by the worker's parent
process at import, was open in all 19 scanner-worker processes. Two scans
looking up packages at once interleaved their queries on it, and a
credentialed audit of an Ubuntu host reported 0 package CVEs from 2,699
packages. See ``db/fork_safety.py``.

The unguarded engine is the control: it shows the child really does inherit
its parent's backend session, so the guarded case is proving something.
"""

from __future__ import annotations

import os

import pytest
from db.base import engine as app_engine
from db.fork_safety import release_pool_after_fork
from sqlalchemy import create_engine, text


def _backend_pid(engine) -> int:
    with engine.connect() as conn:
        return conn.execute(text("SELECT pg_backend_pid()")).scalar_one()


def _backend_pid_in_child(engine) -> int:
    read_end, write_end = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - runs in the forked child
        try:
            os.write(write_end, str(_backend_pid(engine)).encode())
        finally:
            os._exit(0)
    os.close(write_end)
    try:
        raw = os.read(read_end, 64)
    finally:
        os.close(read_end)
        os.waitpid(child, 0)
    return int(raw)


@pytest.fixture()
def fresh_engine():
    engines = []

    def make(guarded: bool):
        engine = create_engine(app_engine.url, pool_size=1, max_overflow=0)
        engines.append(engine)
        return release_pool_after_fork(engine) if guarded else engine

    yield make
    for engine in engines:
        engine.dispose()


def test_an_unguarded_child_reuses_its_parents_session(fresh_engine):
    engine = fresh_engine(guarded=False)
    parent = _backend_pid(engine)  # returned to the pool, socket still open
    assert _backend_pid_in_child(engine) == parent


def test_a_guarded_child_opens_its_own_session(fresh_engine):
    engine = fresh_engine(guarded=True)
    parent = _backend_pid(engine)
    assert _backend_pid_in_child(engine) != parent
    # And the child left the parent's connection alone: dispose(close=False)
    # must not send a Terminate down the shared socket.
    assert _backend_pid(engine) == parent


def test_both_production_engines_are_guarded():
    import inspect

    from core import vuln_intel
    from db import base

    assert "release_pool_after_fork(" in inspect.getsource(base)
    assert "release_pool_after_fork(" in inspect.getsource(vuln_intel.get_vuln_engine)
