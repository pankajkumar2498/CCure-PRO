"""
test_cve_database_fallback.py
─────────────────────────────────────────────────────────────────────────────
The vulnerability-intelligence database stays authoritative, and a transient
outage does not silently convert the process into a stale-CVE one.

`CVEDatabase.__init__` probed `can_connect_vuln_db()` exactly once and fixed
`backend` from the answer. `get_cve_database()` caches the instance for the life
of the process, and `core/constants.py` builds it at *import* — on a worker or
an API container, the moment the database is least likely to be up. The probe
gives up after two seconds, so one slow start pinned every CVE lookup in that
process to a bundled SQLite snapshot months behind the feed, and said so in a
single warning line nobody would see again.
"""

from __future__ import annotations

import core.cve_database as cve_database
from core.cve_database import CVEDatabase, _BACKEND_PROBE_TTL_SECONDS


def _snapshot(tmp_path):
    path = tmp_path / "cves.db"
    path.write_bytes(b"")  # presence is all `sqlite_available` tests
    return path


def test_healthy_probe_selects_postgres(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_database, "can_connect_vuln_db", lambda: True)

    db = CVEDatabase(db_path=str(_snapshot(tmp_path)))

    assert db.backend == "postgresql"
    assert db.db_available is True


def test_failed_probe_falls_back_but_does_not_pin(tmp_path, monkeypatch):
    """The fix: the demotion lasts as long as the outage, not as long as the process."""
    calls = {"n": 0}

    def _probe():
        calls["n"] += 1
        return calls["n"] > 1  # first probe fails, later ones succeed

    monkeypatch.setattr(cve_database, "can_connect_vuln_db", _probe)

    db = CVEDatabase(db_path=str(_snapshot(tmp_path)))
    assert db.backend == "sqlite", "A failed probe still falls back"

    # Inside the TTL the answer is cached, so a hot path costs nothing.
    assert db.backend == "sqlite"
    assert calls["n"] == 1

    # Once it goes stale the probe is retried, and recovery needs no restart.
    db._probed_at -= _BACKEND_PROBE_TTL_SECONDS + 1
    assert db.backend == "postgresql"
    assert calls["n"] == 2


def test_healthy_backend_is_never_re_probed(tmp_path, monkeypatch):
    """
    A live query that fails is already handled per query. Re-probing a working
    backend would put a connection attempt in front of every CVE lookup.
    """
    calls = {"n": 0}

    def _probe():
        calls["n"] += 1
        return True

    monkeypatch.setattr(cve_database, "can_connect_vuln_db", _probe)

    db = CVEDatabase(db_path=str(_snapshot(tmp_path)))
    db._probed_at -= _BACKEND_PROBE_TTL_SECONDS + 1
    for _ in range(5):
        assert db.backend == "postgresql"

    assert calls["n"] == 1


def test_sqlite_remains_available_for_offline_use(tmp_path, monkeypatch):
    """The snapshot is a legitimate offline and test fallback; it is not removed."""
    monkeypatch.setattr(cve_database, "can_connect_vuln_db", lambda: False)

    db = CVEDatabase(db_path=str(_snapshot(tmp_path)))

    assert db.sqlite_available is True
    assert db.backend == "sqlite"
    assert db.db_available is True


def test_no_database_at_all_reports_the_hint_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_database, "can_connect_vuln_db", lambda: False)

    db = CVEDatabase(db_path=str(tmp_path / "absent.db"))

    assert db.sqlite_available is False
    assert db.backend == "fallback"
    assert db.db_available is False
