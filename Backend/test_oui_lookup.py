import json
from pathlib import Path

from core.oui_lookup import OUIDatabase


def test_local_oui_lookup(tmp_path):
    manuf_file = tmp_path / "manuf.txt"
    manuf_file.write_text("00-1A-2B\tTest Vendor\n", encoding="utf-8")

    db = OUIDatabase(db_path=str(manuf_file), cache_path=str(tmp_path / "vendor_cache.json"), api_url="")
    assert db.lookup("00:1A:2B:00:00:00") == "Test Vendor"


def test_vendor_cache_loads_and_returns(tmp_path):
    cache_path = tmp_path / "vendor_cache.json"
    cache_path.write_text(json.dumps({"1234567890ab": "Cached Corp"}), encoding="utf-8")

    db = OUIDatabase(db_path=str(tmp_path / "manuf.txt"), cache_path=str(cache_path), api_url="")
    assert db.lookup("00:1A:2B:4C:5D:6E") == "Cached Corp"


def test_api_fallback_sync_caches_result(tmp_path, monkeypatch):
    cache_path = tmp_path / "vendor_cache.json"

    class DummyResponse:
        status_code = 200
        text = "API Vendor"

    def fake_get(url, timeout):
        assert url.endswith("/1234567890ab")
        assert timeout == 5
        return DummyResponse()

    monkeypatch.setattr("core.oui_lookup.requests.get", fake_get)

    db = OUIDatabase(db_path=str(tmp_path / "manuf.txt"), cache_path=str(cache_path), api_url="https://api.macvendors.com/")
    vendor = db.lookup_sync("12:34:56:78:90:ab")

    assert vendor == "API Vendor"
    data = json.loads(Path(cache_path).read_text(encoding="utf-8"))
    assert data["1234567890ab"] == "API Vendor"
