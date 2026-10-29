"""
The CVE database client is made at the first CVE lookup, never at import
(Group 3: B3's second half; engines/vulnerability/cve_lookup.py).

It used to be built when ``core.utils`` was imported, so every engine that
imported ``core.utils`` for an unrelated helper loaded SQLAlchemy and opened the
vulnerability database before it had scanned anything. These pin the new
behaviour: importing contacts nothing; the first lookup builds the client once
and every later one reuses it; a build without the database module falls back
to the hint table, as the import-time client did.
"""

import subprocess
import sys

import pytest
from engines.vulnerability import cve_lookup
from testpaths import BACKEND_ROOT


def _loaded_after(statement: str) -> set[str]:
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import sys; {statement}; "
            "print(' '.join(m for m in ('core.cve_database', 'sqlalchemy') "
            "if m in sys.modules))",
        ],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return set(out.stdout.split())


@pytest.mark.parametrize(
    "statement",
    [
        "import engines.vulnerability.cve_lookup",
        "import core.utils",
        "import engines.vulnerability.vulnerability_engine",
        "import engines.port.port_engine",
    ],
)
def test_importing_contacts_no_database(statement):
    assert _loaded_after(statement) == set()


class _FakeDatabase:
    db_available = True

    def __init__(self):
        self.searches = []

    def search_cves_for_service(self, banner, version, cpes):
        self.searches.append((banner, version, cpes))
        return [{"cve_id": "CVE-2026-0001", "banner": banner}]


@pytest.fixture
def fresh(monkeypatch):
    """A process in which no lookup has happened yet."""
    monkeypatch.setattr(cve_lookup, "_cve_db", cve_lookup._UNSET)
    cve_lookup.lookup_cve.cache_clear()
    yield
    cve_lookup.lookup_cve.cache_clear()


def test_the_first_lookup_builds_the_client_once(fresh, monkeypatch):
    import core.cve_database

    built = []
    fake = _FakeDatabase()

    def get_cve_database():
        built.append(1)
        return fake

    monkeypatch.setattr(core.cve_database, "get_cve_database", get_cve_database)
    assert built == []  # nothing yet: the fixture reset the client, nothing asked

    first = cve_lookup.lookup_cve("OpenSSH 9.6p1", "9.6p1")
    second = cve_lookup.lookup_cve("nginx 1.27", "1.27")

    assert built == [1]
    assert first == [{"cve_id": "CVE-2026-0001", "banner": "OpenSSH 9.6p1"}]
    assert second == [{"cve_id": "CVE-2026-0001", "banner": "nginx 1.27"}]
    assert [s[0] for s in fake.searches] == ["OpenSSH 9.6p1", "nginx 1.27"]
    assert cve_lookup.cve_database() is fake


def test_an_empty_query_builds_nothing(fresh, monkeypatch):
    import core.cve_database

    monkeypatch.setattr(
        core.cve_database,
        "get_cve_database",
        lambda: pytest.fail("an empty query must not build the client"),
    )
    assert cve_lookup.lookup_cve("", "") == []
    assert cve_lookup._cve_db is cve_lookup._UNSET


def test_without_the_database_module_the_hint_table_answers(fresh, monkeypatch):
    from core.constants import CVE_HINTS

    monkeypatch.setitem(sys.modules, "core.cve_database", None)  # ImportError
    key = next(iter(CVE_HINTS))

    found = cve_lookup.lookup_cve(f"{key} banner", "")

    assert cve_lookup.cve_database() is None
    assert found and all(f.get("detection_source") == "hint_table" for f in found)


def test_core_utils_no_longer_offers_the_lookup():
    import core.utils

    assert not hasattr(core.utils, "lookup_cve")
    assert not hasattr(core.utils, "CVE_DB")
