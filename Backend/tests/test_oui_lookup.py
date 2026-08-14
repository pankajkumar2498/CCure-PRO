import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from core.oui_lookup import OUIDatabase


@pytest.fixture
def temp_manuf_file():
    """Create a temporary manuf file with standard tab-delimited formatting."""
    content = (
        "# Wireshark OUI database test file\n"
        "00:00:0C\tCisco\tCisco Systems, Inc\n"
        "28-6F-B9\tNokiaShanghai\tNokia Shanghai Bell Co., Ltd.\n"
        "00 1A 2B\tCiscoSPA\tCisco SPA Phone\n"
        "00:01:05\tBeckhoff\tBeckhoff Automation GmbH\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as temp:
        temp.write(content)
        temp_path = temp.name

    yield temp_path

    if os.path.exists(temp_path):
        os.remove(temp_path)


def test_oui_database_load(temp_manuf_file):
    """Verify that OUIDatabase correctly parses prefix names, colons, hyphens, and tabs."""
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)
    db._load()

    # 00:00:0C -> should normalize to 00000c and prefer full name "Cisco Systems, Inc"
    assert db._database.get("00000c") == "Cisco Systems, Inc"

    # 28-6F-B9 -> should normalize to 286fb9 and prefer full name
    assert db._database.get("286fb9") == "Nokia Shanghai Bell Co., Ltd."

    # 00 1A 2B -> should normalize to 001a2b and prefer full name
    assert db._database.get("001a2b") == "Cisco SPA Phone"

    # 00:01:05 -> should normalize to 000105
    assert db._database.get("000105") == "Beckhoff Automation GmbH"


def test_oui_database_local_lookup_only(temp_manuf_file):
    """Verify that lookup resolves MAC address via local memory cache without DB/API queries."""
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)

    # Test lookup of offline values
    assert db.lookup("00:00:0C:11:22:33") == "Cisco Systems, Inc"
    assert db.lookup("28-6F-B9-AA-BB-CC") == "Nokia Shanghai Bell Co., Ltd."
    assert db.lookup("001a2b3c4d5e") == "Cisco SPA Phone"
    assert db.lookup("INVALID_MAC") is None


@patch("db.base.SessionLocal")
def test_oui_database_db_cache_lookup(mock_session_maker, temp_manuf_file):
    """Verify that lookup falls back to checking the PostgreSQL cache table."""
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)

    # Setup mock session and DB return
    mock_db = MagicMock()
    mock_session_maker.return_value = mock_db

    mock_cached = MagicMock()
    mock_cached.vendor_name = "Mocked Cached Vendor"
    mock_db.query().filter().first.return_value = mock_cached

    # Query a MAC that is not in the local registry (00:99:99)
    result = db.lookup("00:99:99:11:22:33")

    assert result == "Mocked Cached Vendor"
    mock_db.query.assert_called()
    mock_db.close.assert_called()


@patch("db.base.SessionLocal")
@patch("requests.get")
def test_oui_database_lookup_sync_fallback(
    mock_get, mock_session_maker, temp_manuf_file
):
    """Verify that lookup_sync queries requests API fallback and saves to DB cache."""
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)
    db._executor = MagicMock()

    # Setup request mock
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "API Resolved Vendor"
    mock_get.return_value = mock_response

    # Setup DB mock
    mock_db = MagicMock()
    mock_session_maker.return_value = mock_db
    mock_db.query().filter().first.return_value = None  # Mock DB cache miss

    # Perform synchronous lookup of unknown OUI
    result = db.lookup_sync("00:11:22:33:44:55")

    assert result == "API Resolved Vendor"
    mock_get.assert_any_call("https://api.macvendors.com/001122334455", timeout=2.0)
    mock_db.execute.assert_called_once()
    mock_db.commit.assert_called_once()
    mock_db.close.assert_called()


@patch("requests.get")
def test_update_mac_vendor_registry_task_success(mock_get, temp_manuf_file):
    """Verify that update_mac_vendor_registry_task downloads registry and refreshes memory."""
    from core.tasks import update_mac_vendor_registry_task

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = (
        "# New Wireshark OUI file\n"
        "00:00:00\tXerox\tXerox Corporation\n"
        "00:11:22\tNewVendor\tNew Vendor Corp\n"
    )
    mock_get.return_value = mock_response

    # Patch OUIDatabase db_path to point to our temp_manuf_file
    with patch("core.oui_lookup.get_oui_db") as mock_get_db:
        mock_db_instance = OUIDatabase(db_path=temp_manuf_file, cache_path=None)
        mock_get_db.return_value = mock_db_instance

        # Execute task
        result = update_mac_vendor_registry_task()

        assert result["success"] is True
        assert result["entries"] == 2
        assert mock_db_instance._database.get("001122") == "New Vendor Corp"

        # Verify file is updated
        with open(temp_manuf_file, "r", encoding="utf-8") as f:
            written_content = f.read()
        assert "New Vendor Corp" in written_content
