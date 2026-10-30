"""
The Nmap wrapper's Redis clients are handed to it (Group 3): Audit's
composition root registers the global limiter's lease connection and the result
cache's client (``ccure_audit/engine_ports.py``), and the wrapper loads no
Redis client. A process that registers nothing behaves as one whose Redis could
not be reached always did: the limiter falls back to its local semaphore and
the cache is off, each with its warning.
"""

import logging

import pytest
from core.nmap import wrapper


class _Redis:
    def __init__(self):
        self.keys = {}
        self.released = []

    def ping(self):
        return True

    def set(self, key, owner, nx=False, ex=None):
        if nx and key in self.keys:
            return False
        self.keys[key] = owner
        return True

    def eval(self, script, numkeys, key, owner):
        self.released.append(key)
        self.keys.pop(key, None)
        return 1


@pytest.fixture
def unregistered(monkeypatch):
    monkeypatch.setattr(wrapper, "_lease_client", None)
    monkeypatch.setattr(wrapper, "_cache_client", None)


def test_the_wrapper_imports_no_redis_client():
    import ast

    tree = ast.parse(open(wrapper.__file__, encoding="utf-8").read())
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not {m for m in imported if m and m.split(".")[0] == "redis"}
    assert "core.redis_client" not in imported


def test_without_a_lease_the_limiter_is_local(unregistered, caplog):
    limiter = wrapper._NmapProcessLimiter(
        max_processes=1, wait_timeout=1, lease_seconds=60
    )
    with caplog.at_level(logging.WARNING, logger="ccure.nmap"):
        token = limiter.acquire()
    assert token[0] == "local"
    limiter.release(token)
    assert "using local process limiter only" in caplog.text


def test_a_registered_lease_is_the_global_limiter(monkeypatch):
    redis = _Redis()
    monkeypatch.setattr(wrapper, "_lease_client", lambda: redis)
    limiter = wrapper._NmapProcessLimiter(
        max_processes=2, wait_timeout=1, lease_seconds=60
    )
    token = limiter.acquire()
    assert token[0] == "redis" and token[1] == "ccure:nmap:slot:0"
    limiter.release(token)
    assert redis.released == ["ccure:nmap:slot:0"]


def test_without_a_cache_client_the_cache_is_off(unregistered, monkeypatch, caplog):
    monkeypatch.setattr(wrapper.AppConfig, "NMAP_CACHE_ENABLED", True)
    with caplog.at_level(logging.WARNING, logger="ccure.nmap"):
        scanner = wrapper.NmapScanner(sudo=False)
    assert scanner._cache_enabled is False
    assert "Redis unavailable for Nmap cache" in caplog.text


def test_a_registered_cache_client_enables_the_cache(monkeypatch):
    redis = _Redis()
    monkeypatch.setattr(wrapper, "_cache_client", lambda: redis)
    monkeypatch.setattr(wrapper.AppConfig, "NMAP_CACHE_ENABLED", True)
    scanner = wrapper.NmapScanner(sudo=False)
    assert scanner._cache_enabled is True and scanner._redis is redis


def test_a_different_pair_is_refused(unregistered):
    def lease():
        return None

    def cache():
        return None

    wrapper.register_shared_state(lease_client=lease, cache_client=cache)
    wrapper.register_shared_state(lease_client=lease, cache_client=cache)
    with pytest.raises(ValueError):
        wrapper.register_shared_state(lease_client=cache, cache_client=lease)
