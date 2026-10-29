"""
The OUI lookup reads the shared MAC-vendor cache through a port (Group 3):
``core.oui_lookup`` is part of the scan kernel and names no table, and the
asset registry answers (``core/mac_vendor_cache.py``, registered by
``ccure_audit/vendor_cache.py``).

A process with no cache registered behaves as one whose database could not be
reached always did: the shared tier is skipped, with the same warning, and the
local registry still answers.
"""

import logging

import pytest
from core import oui_lookup
from core.oui_lookup import OUIDatabase


class _Cache:
    def __init__(self, entries=None):
        self.entries = dict(entries or {})
        self.puts = []

    def get(self, oui):
        return self.entries.get(oui)

    def put(self, oui, vendor):
        self.puts.append((oui, vendor))
        self.entries[oui] = vendor


@pytest.fixture
def database(tmp_path):
    manuf = tmp_path / "manuf.txt"
    manuf.write_text("00:1A:2B\tLocal\tLocal Vendor Inc\n", encoding="utf-8")
    db = OUIDatabase(db_path=str(manuf), api_url="")
    yield db
    db._executor.shutdown(wait=True)


def test_the_kernel_module_names_no_table():
    source = oui_lookup.__file__
    text = open(source, encoding="utf-8").read()
    assert "MacVendorCache" not in text and "SessionLocal" not in text


def test_a_registered_cache_answers_after_the_local_registry(database, monkeypatch):
    cache = _Cache({"aabbcc": "Cached Vendor"})
    monkeypatch.setattr(oui_lookup, "_vendor_cache", cache)
    assert database.lookup("00:1A:2B:00:00:01") == "Local Vendor Inc"
    assert database.lookup("aa:bb:cc:00:00:01") == "Cached Vendor"


def test_a_synchronous_lookup_writes_what_the_api_answers(database, monkeypatch):
    cache = _Cache()
    monkeypatch.setattr(oui_lookup, "_vendor_cache", cache)
    monkeypatch.setattr(database, "_query_vendor_api", lambda mac: "Api Vendor")
    # lookup() would also schedule the background fetch, which writes too.
    monkeypatch.setattr(database, "_schedule_api_fetch", lambda mac: None)
    assert database.lookup_sync("de:ad:be:ef:00:01") == "Api Vendor"
    assert cache.puts == [("deadbe", "Api Vendor")]


def test_without_a_cache_the_shared_tier_is_skipped(database, monkeypatch, caplog):
    monkeypatch.setattr(oui_lookup, "_vendor_cache", None)
    scheduled = []
    monkeypatch.setattr(database, "_schedule_api_fetch", scheduled.append)
    with caplog.at_level(logging.WARNING, logger="ccure.oui"):
        assert database.lookup("aa:bb:cc:00:00:01") is None
        assert database.lookup("00:1A:2B:00:00:01") == "Local Vendor Inc"
    assert scheduled == ["aabbcc000001"]
    assert "Database OUI cache lookup failed" in caplog.text
    assert "no vendor cache is registered" in caplog.text


def test_a_second_cache_is_refused(monkeypatch):
    monkeypatch.setattr(oui_lookup, "_vendor_cache", None)
    first = _Cache()
    oui_lookup.register_vendor_cache(first)
    oui_lookup.register_vendor_cache(first)  # the same one again: nothing
    with pytest.raises(ValueError):
        oui_lookup.register_vendor_cache(_Cache())
