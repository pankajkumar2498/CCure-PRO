import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pytest
from core.oui_lookup import OUIDatabase, _normalize_mac_address


@pytest.fixture(autouse=True)
def drain_oui_executors():
    """
    Shut down every OUIDatabase background executor before the next test starts.

    ``OUIDatabase.__init__`` opens a real ``ThreadPoolExecutor`` and nothing ever
    closes it, so a fetch scheduled by one test can still be running inside the
    next one. ``test_oui_database_local_lookup_only`` used to reach that path: it
    looks up "INVALID_MAC", which is not a MAC, but ``_normalize_mac`` checked
    only length rather than that the characters were hexadecimal — so it fell
    through to ``_schedule_api_fetch`` and submitted a real job against the real
    ``api.macvendors.com`` with a 2s timeout. ``_normalize_mac_address`` refuses
    that input now, so no such job is scheduled; the tests at the end of this
    file pin that.

    Note what this fixture is *not*. It was written while chasing this module's
    one-in-three failure, on the theory that the stray thread was landing on the
    next test's ``db.base.SessionLocal`` mock and adding a second ``commit()``.
    That theory was wrong. Capturing a thread name and stack for every mock
    ``commit`` showed the second call coming from ``main.py``'s ``cleanup_loop``,
    an application background task that had no ``asyncio.sleep`` and therefore
    ran continuously for the whole session, picking up whatever ``SessionLocal``
    happened to be patched at the time. The fix for the flakiness is the sleep
    added to that loop.

    This fixture is kept anyway, on its own merits: a test suite should not leave
    threads running past the test that started them, and combined with the mocks
    added below it also stops this module making real network calls, which is
    what made it the slowest file of its size in the suite.
    """
    created = []
    original_init = OUIDatabase.__init__

    def tracking_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        created.append(self)

    with patch.object(OUIDatabase, "__init__", tracking_init):
        yield

    for db in created:
        executor = getattr(db, "_executor", None)
        # A test may have replaced _executor with a MagicMock; only a real pool
        # needs draining.
        if isinstance(executor, ThreadPoolExecutor):
            executor.shutdown(wait=True)


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


@patch("db.base.SessionLocal")
@patch("requests.get")
def test_oui_database_local_lookup_only(mock_get, mock_session_maker, temp_manuf_file):
    """Verify that lookup resolves MAC address via local memory cache without DB/API queries."""
    # These two patches are what make the claim in the docstring true. Without
    # them this test issued a real query against whatever DATABASE_URL pointed
    # at and a real HTTPS request to api.macvendors.com — see drain_oui_executors
    # above for what that cost the rest of the module.
    #
    # The session must model a cache *miss*. A bare MagicMock returns a truthy
    # mock from .first(), which lookup() would hand back as the vendor name.
    mock_session_maker.return_value.query.return_value.filter.return_value.first.return_value = (
        None
    )

    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)

    # Test lookup of offline values
    assert db.lookup("00:00:0C:11:22:33") == "Cisco Systems, Inc"
    assert db.lookup("28-6F-B9-AA-BB-CC") == "Nokia Shanghai Bell Co., Ltd."
    assert db.lookup("001a2b3c4d5e") == "Cisco SPA Phone"

    # The point of the test: a prefix present in the local registry is answered
    # from memory. Assert it rather than trusting the title.
    mock_session_maker.assert_not_called()
    mock_get.assert_not_called()

    # "INVALID_MAC" is not a MAC. It used to normalize to "invalid_mac" — the
    # old rule asked only whether six characters were present, never whether
    # they were hexadecimal — and fell through to the DB-cache and API-fallback
    # paths, which is why this assertion held while still costing a round trip.
    # It is refused up front now, and the two mocks prove it: neither is called
    # anywhere in this test.
    assert db.lookup("INVALID_MAC") is None
    mock_session_maker.assert_not_called()
    mock_get.assert_not_called()


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


# =============================================================================
# MAC syntax validation
# -----------------------------------------------------------------------------
# `_normalize_mac` used to ask only whether six characters survived separator
# stripping. It never asked whether they were hexadecimal, so any word of six
# or more letters was treated as an address and was handed to the vendor API as
# a URL path segment.
#
# That was reachable in production rather than only from this file.
# `orchestrator/scan_orchestrator.py::_normalize_mac` returns "Unknown" and
# "None" unchanged, and the vendor-resolution branch beside it guards on
# `mac != "N/A"` only — so a host discovered without a MAC produced a live
# request to https://api.macvendors.com/unknown on every scan.
#
# The tests below pin both halves of the fix: every address form the module
# accepted before is still accepted and still normalizes to the same value, and
# nothing that is not an address reaches the network.
# =============================================================================


#: Every form this module is documented or known to accept, with the compact
#: value it must produce. Verified against the previous implementation: all of
#: these normalized to exactly the same string before the validation was added,
#: so this list is a preservation contract, not a new capability.
SUPPORTED_MAC_FORMATS = [
    ("00:1a:2b:3c:4d:5e", "001a2b3c4d5e", "colon separated, lower case"),
    ("00:1A:2B:3C:4D:5E", "001a2b3c4d5e", "colon separated, upper case"),
    ("00-1A-2B-3C-4D-5E", "001a2b3c4d5e", "hyphen separated (Windows getmac)"),
    ("001a2b3c4d5e", "001a2b3c4d5e", "bare hex"),
    ("001A2B3C4D5E", "001a2b3c4d5e", "bare hex, upper case"),
    ("001a.2b3c.4d5e", "001a2b3c4d5e", "Cisco three-group dotted form"),
    ("Aa-Bb:Cc-Dd:Ee-Ff", "aabbccddeeff", "mixed separators and case"),
    ("00:1A:2B", "001a2b", "24-bit OUI prefix (OUIDatabase docstring)"),
    ("001a2b", "001a2b", "24-bit OUI prefix, bare"),
    ("00-1A-2B", "001a2b", "24-bit OUI prefix, hyphenated"),
    ("00:1a:2b:3c:4d:5e:6f:70", "001a2b3c4d5e6f70", "EUI-64"),
    # Syntactically valid and must stay accepted here. Whether an address is
    # *useful* is a different question, asked by core.topology.identity's
    # is_usable_mac; this module only asks whether it is an address. 00:00:00
    # is a real assignment (Xerox), and the shipped manuf.txt carries it.
    ("00:00:00:00:00:00", "000000000000", "all-zero address"),
    ("ff:ff:ff:ff:ff:ff", "ffffffffffff", "broadcast address"),
]


@pytest.mark.parametrize(
    "raw,expected",
    [(raw, expected) for raw, expected, _ in SUPPORTED_MAC_FORMATS],
    ids=[label for _, _, label in SUPPORTED_MAC_FORMATS],
)
def test_normalize_mac_preserves_every_supported_format(raw, expected):
    """Each accepted form still normalizes to the value it produced before."""
    assert _normalize_mac_address(raw) == expected


#: Values that are not addresses. Each one was accepted by the previous rule
#: unless marked otherwise, and each therefore became a URL path segment.
NON_ADDRESSES = [
    ("INVALID_MAC", "the placeholder this module's own test used"),
    ("Unknown", "scan_orchestrator passes this through verbatim"),
    ("unknown", "same, lower case"),
    ("core-sw-01", "LLDP chassis subtype 7, a locally assigned name"),
    ("edge-sw.corp.local", "CDP device id"),
    ("10.180.4.1", "LLDP chassis subtype 5, a network address"),
    ("aabbccddeef", "11 hex digits: one short of an address"),
    ("aabbccddeeffgg", "12 hex digits with trailing junk"),
    ("00:1a:2b:3c:4d:5ez", "a valid address plus one stray character"),
    ("deadbeefcafebabe0", "17 hex digits"),
    # Not hypothetical: separators are removed but "/" and "?" are not, so
    # before the hex check these reached requests.get as a crafted path.
    ("aabbcc/../../etc/passwd", "path traversal through the API URL"),
    ("aabbcc?callback=x", "query-string injection through the API URL"),
    ("N/A", "already refused before, on length"),
    ("None", "already refused before, on length"),
    ("", "empty string"),
    (None, "None"),
    (0, "a non-string falsy value"),
]


@pytest.mark.parametrize(
    "raw",
    [raw for raw, _ in NON_ADDRESSES],
    ids=[label for _, label in NON_ADDRESSES],
)
def test_normalize_mac_rejects_non_addresses(raw):
    """Anything that is not an address normalizes to None, not to a URL."""
    assert _normalize_mac_address(raw) is None


@pytest.mark.parametrize("length", range(1, 21))
def test_normalize_mac_accepts_only_address_lengths(length):
    """Only 24-bit, 48-bit and 64-bit addresses are accepted, whatever the digits.

    The old rule was ``len >= 6``, which admitted every length above five. This
    walks all-hex strings of length 1 through 20 so the boundary is stated
    explicitly rather than inferred from the examples above.
    """
    candidate = "a" * length
    expected = candidate if length in (6, 12, 16) else None
    assert _normalize_mac_address(candidate) == expected


def test_normalize_mac_method_delegates_to_module_function(temp_manuf_file):
    """The bound method and the module function cannot drift apart."""
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)
    for raw, _, _ in SUPPORTED_MAC_FORMATS:
        assert db._normalize_mac(raw) == _normalize_mac_address(raw)
    for raw, _ in NON_ADDRESSES:
        assert db._normalize_mac(raw) is None


@pytest.mark.parametrize(
    "raw",
    ["INVALID_MAC", "Unknown", "core-sw-01", "10.180.4.1", "aabbcc/../../etc/passwd"],
)
@patch("db.base.SessionLocal")
@patch("requests.get")
def test_lookup_refuses_non_address_without_db_or_network(
    mock_get, mock_session_maker, raw, temp_manuf_file
):
    """lookup() answers None for a non-address and touches nothing to do it.

    The return value is what it always was. What changed is that reaching it no
    longer costs a database round trip and an HTTPS request.
    """
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)

    assert db.lookup(raw) is None

    mock_session_maker.assert_not_called()
    mock_get.assert_not_called()


@pytest.mark.parametrize("raw", ["INVALID_MAC", "Unknown", "10.180.4.1"])
@patch("db.base.SessionLocal")
@patch("requests.get")
def test_lookup_sync_refuses_non_address_without_db_or_network(
    mock_get, mock_session_maker, raw, temp_manuf_file
):
    """lookup_sync() has its own call into the API and is gated the same way."""
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)
    db._executor = MagicMock()

    assert db.lookup_sync(raw) is None

    mock_session_maker.assert_not_called()
    mock_get.assert_not_called()


@patch("requests.get")
def test_query_vendor_api_revalidates_its_own_argument(mock_get, temp_manuf_file):
    """The URL boundary refuses a non-address even when called directly.

    Every current caller normalizes first, so this is redundant today. It is a
    property of the call graph rather than of the function, though, and this is
    the one place a scanned value becomes an outbound request — so the check
    lives here too, and this test is what stops it being removed as dead.
    """
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)

    assert db._query_vendor_api("Unknown") is None
    assert db._query_vendor_api("aabbcc/../../etc/passwd") is None

    mock_get.assert_not_called()


@patch("requests.get")
def test_query_vendor_api_requests_the_normalized_address(mock_get, temp_manuf_file):
    """A separator-bearing address is requested in compact form, once."""
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Some Vendor"
    mock_get.return_value = mock_response

    assert db._query_vendor_api("00-11-22-33-44-55") == "Some Vendor"

    mock_get.assert_called_once_with(
        "https://api.macvendors.com/001122334455", timeout=2.0
    )


@patch("db.base.SessionLocal")
@patch("requests.get")
def test_valid_address_still_resolves_from_local_registry(
    mock_get, mock_session_maker, temp_manuf_file
):
    """Regression guard: validation must not cost the offline path.

    Includes the bare 24-bit prefix form, which the class docstring documents
    and which no other test in this file exercises — it is the format most at
    risk from a length check written for 48-bit addresses.
    """
    db = OUIDatabase(db_path=temp_manuf_file, cache_path=None)

    assert db.lookup("00:00:0C:11:22:33") == "Cisco Systems, Inc"
    assert db.lookup("00:00:0C") == "Cisco Systems, Inc"
    assert db.lookup("00000c") == "Cisco Systems, Inc"
    assert db.lookup("28-6F-B9-AA-BB-CC") == "Nokia Shanghai Bell Co., Ltd."
    assert db.lookup("001a2b3c4d5e") == "Cisco SPA Phone"
    assert db.lookup("0000.0c11.2233") == "Cisco Systems, Inc"

    mock_session_maker.assert_not_called()
    mock_get.assert_not_called()
