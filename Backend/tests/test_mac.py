"""
tests/test_mac.py
─────────────────────────────────────────────────────────────────────────────
`core.mac` is the one place that answers "is this a MAC address?".

Two of the five functions that used to answer it separately got it wrong, in
the same way: they validated by shape rather than by content. `core.oui_lookup`
accepted anything six characters or longer, and `core.tasks` accepted anything
with six colon-separated groups. This file pins the shared rule, and pins the
two properties that stop the old sprawl growing back — that the deduplicated
collector function still behaves exactly like the copies it replaced, and that
both collectors still point at it.
"""

import itertools
import re

import pytest
from core.mac import RESERVED_MACS, collector_mac, mac_colon, mac_hex
from core.tasks import _normalize_mac as tasks_mac
from db.base import gen_asset_id
from db.models.assets import Asset
from engines.credentialed import linux_collector, windows_collector
from sqlalchemy import text

# =============================================================================
# mac_hex — the shared predicate
# =============================================================================

EUI48_FORMS = [
    ("00:1a:2b:3c:4d:5e", "colon separated"),
    ("00:1A:2B:3C:4D:5E", "colon separated, upper case"),
    ("00-1A-2B-3C-4D-5E", "hyphen separated (Windows getmac)"),
    ("001a2b3c4d5e", "bare hex"),
    ("001a.2b3c.4d5e", "Cisco three-group dotted form"),
    ("00-1a:2B-3c:4D-5e", "mixed separators and case"),
    ("  00:1a:2b:3c:4d:5e  ", "whitespace padded"),
]


@pytest.mark.parametrize(
    "raw", [raw for raw, _ in EUI48_FORMS], ids=[label for _, label in EUI48_FORMS]
)
def test_mac_hex_accepts_every_eui48_dialect(raw):
    assert mac_hex(raw) == "001a2b3c4d5e"


@pytest.mark.parametrize(
    "raw",
    [
        "Unknown",
        "core-sw-01",
        "edge-sw.corp.local",
        "10.180.4.1",
        "aabbccddeef",
        "aabbccddeeffgg",
        "00:1a:2b:3c:4d:5ez",
        "aabbcc/../../etc/passwd",
        "N/A",
        "",
        None,
        0,
    ],
)
def test_mac_hex_rejects_non_addresses(raw):
    assert mac_hex(raw) is None


def test_mac_hex_defaults_to_eui48_only():
    """The default is 12 digits. A 24-bit prefix is opt-in, not free."""
    assert mac_hex("001a2b") is None
    assert mac_hex("001a2b", (6,)) == "001a2b"
    assert mac_hex("001a2b3c4d5e", (6,)) is None
    assert mac_hex("001a2b", (6, 12, 16)) == "001a2b"


def test_mac_hex_removes_only_known_separators():
    """A stray character is refused, not silently discarded.

    ``core.topology.identity.normalize_mac`` strips every non-hex character,
    which is right for deciding what may be compared against a MACADDR column
    and wrong here: it would repair this input into a valid-looking address.
    """
    assert mac_hex("00:1a:2b:3c:4d:5ezz") is None
    assert mac_hex("zz001a2b3c4d5e") is None


# =============================================================================
# mac_colon — canonical form, including the unpadded dialect
# =============================================================================


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("001a2b3c4d5e", "00:1a:2b:3c:4d:5e"),
        ("001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"),
        ("00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"),
        # Unpadded octets. PostgreSQL accepts these and normalizes them the
        # same way, and macOS ifconfig emits them, so they are a real dialect.
        ("0:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("0:1:2:3:4:5", "00:01:02:03:04:05"),
    ],
)
def test_mac_colon_canonicalizes_every_accepted_dialect(raw, expected):
    assert mac_colon(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "zz:zz:zz:zz:zz:zz",  # six groups, none of them hex
        "q1:q2:q3:q4:q5:q6",
        "000:1a:2b:3c:4d:5e",  # a group that is not an octet
        "00:1a:2b:3c:4d",  # five groups
        "Unknown",
        "10.180.4.1",
        "",
        None,
    ],
)
def test_mac_colon_rejects_non_addresses(raw):
    assert mac_colon(raw) is None


# =============================================================================
# collector_mac — the deduplicated copy must not have drifted
# =============================================================================


def _original_collector_mac(value):
    """The body that existed, character for character, in both collectors.

    Kept here so the deduplication is checked rather than asserted. If someone
    changes ``core.mac.collector_mac``, this test says so, and they can decide
    deliberately whether the collectors should change with it.
    """
    text = str(value or "").strip().lower().replace("-", ":")
    if not text or text in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return ""
    if re.fullmatch(r"[0-9a-f]{12}", text):
        text = ":".join(text[i : i + 2] for i in range(0, 12, 2))
    return text if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", text) else ""


@pytest.mark.parametrize(
    "raw",
    [
        "00:1a:2b:3c:4d:5e",
        "00-1A-2B-3C-4D-5E",
        "001a2b3c4d5e",
        "001a.2b3c.4d5e",
        "0:1a:2b:3c:4d:5e",
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "FF:FF:FF:FF:FF:FF",
        "zz:zz:zz:zz:zz:zz",
        "Unknown",
        "N/A",
        "",
        None,
        0,
        "  00:1a:2b:3c:4d:5e  ",
        "000000000000",
    ],
)
def test_collector_mac_matches_the_body_it_replaced(raw):
    assert collector_mac(raw) == _original_collector_mac(raw)


def test_collector_mac_matches_the_body_it_replaced_under_fuzz():
    """Every string up to four characters over a MAC-ish alphabet."""
    alphabet = "0af:z-. "
    mismatches = [
        candidate
        for length in range(5)
        for candidate in (
            "".join(t) for t in itertools.product(alphabet, repeat=length)
        )
        if collector_mac(candidate) != _original_collector_mac(candidate)
    ]
    assert mismatches == []


def test_collector_mac_returns_empty_string_not_none():
    """Both call sites branch on ``""``; None would read as a valid falsy MAC."""
    assert collector_mac("Unknown") == ""
    assert collector_mac(None) == ""


def test_both_collectors_share_one_implementation():
    """The duplication cannot come back without this failing."""
    assert linux_collector._normalize_mac is collector_mac
    assert windows_collector._normalize_mac is collector_mac


# =============================================================================
# core.tasks._normalize_mac — the colon-counting fall-through
# =============================================================================


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"),
        ("001a2b3c4d5e", "00:1a:2b:3c:4d:5e"),
        ("001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"),
        ("Aa-Bb:Cc-Dd:Ee-Ff", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_tasks_normalize_mac_preserves_valid_addresses(raw, expected):
    assert tasks_mac(raw) == expected


@pytest.mark.parametrize(
    "raw", ["zz:zz:zz:zz:zz:zz", "q1:q2:q3:q4:q5:q6", "000:1a:2b:3c:4d:5e"]
)
def test_tasks_normalize_mac_refuses_groups_that_are_not_hex(raw):
    """The fix.

    These have six colon-separated groups, which is all the previous rule
    checked. ``Asset.mac_address`` is a PostgreSQL MACADDR column, so passing
    one along raises DataError and aborts the credentialed asset sync.
    """
    assert tasks_mac(raw) == ""


@pytest.mark.parametrize("raw", ["Unknown", "N/A", "core-sw-01", "", None])
def test_tasks_normalize_mac_refuses_non_addresses(raw):
    assert tasks_mac(raw) == ""


@pytest.mark.parametrize("raw", ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"])
def test_tasks_normalize_mac_drops_non_unique_addresses(raw):
    """Policy that stays with this caller: these identify no interface."""
    assert tasks_mac(raw) == ""


def test_tasks_normalize_mac_pads_unpadded_octets():
    """Unpadded input now returns the same string as its padded equivalent.

    It previously passed the raw text through, so the value only became
    canonical once PostgreSQL rewrote it on the way into the column — and
    looked different to anything comparing it in Python beforehand.
    """
    assert tasks_mac("0:1a:2b:3c:4d:5e") == tasks_mac("00:1a:2b:3c:4d:5e")


# =============================================================================
# Reserved addresses, in every representation
# -----------------------------------------------------------------------------
# `core.tasks._normalize_mac` applied its reserved-address filter to the raw
# text, so it only recognised the two addresses spelled exactly as they appear
# in RESERVED_MACS. `000000000000`, `0:0:0:0:0:0` and `0000.0000.0000` are the
# same all-zero address written differently and every one of them got through,
# to be returned as the canonical `00:00:00:00:00:00`.
#
# `assets` is keyed on `(org_id, mac_address)`, so each host that got through
# claimed the same row. An all-zero MAC is not rare — a NIC with no hardware
# address, some hypervisor interfaces and a failed read all produce one — so
# the hosts collapsed onto one asset that appeared to change identity on every
# scan.
#
# The filter now runs on the value `mac_colon` returns, which is the only form
# in which two spellings of one address are comparable.
# =============================================================================

ALL_ZERO_REPRESENTATIONS = [
    ("00:00:00:00:00:00", "canonical"),
    ("00-00-00-00-00-00", "hyphen separated"),
    ("000000000000", "bare hex"),
    ("0000.0000.0000", "Cisco dotted form"),
    ("0:0:0:0:0:0", "unpadded octets"),
    ("00:00:00:00:00:0", "mixed padding"),
    ("  000000000000  ", "bare hex, whitespace padded"),
]

BROADCAST_REPRESENTATIONS = [
    ("ff:ff:ff:ff:ff:ff", "canonical"),
    ("FF:FF:FF:FF:FF:FF", "upper case"),
    ("FF-FF-FF-FF-FF-FF", "hyphen separated, upper case"),
    ("ffffffffffff", "bare hex"),
    ("FFFFFFFFFFFF", "bare hex, upper case"),
    ("ffff.ffff.ffff", "Cisco dotted form"),
    ("Ff-fF:Ff-fF:Ff-fF", "mixed separators and case"),
]


@pytest.mark.parametrize(
    "raw",
    [raw for raw, _ in ALL_ZERO_REPRESENTATIONS],
    ids=[label for _, label in ALL_ZERO_REPRESENTATIONS],
)
def test_every_all_zero_representation_is_refused(raw):
    assert tasks_mac(raw) == ""


@pytest.mark.parametrize(
    "raw",
    [raw for raw, _ in BROADCAST_REPRESENTATIONS],
    ids=[label for _, label in BROADCAST_REPRESENTATIONS],
)
def test_every_broadcast_representation_is_refused(raw):
    assert tasks_mac(raw) == ""


def test_reserved_addresses_are_compared_after_normalization():
    """Stated directly, because it is the whole substance of the change.

    Every spelling above normalizes to a member of RESERVED_MACS. Checking the
    raw text could only ever have caught the two canonical spellings.
    """
    for raw, _ in ALL_ZERO_REPRESENTATIONS + BROADCAST_REPRESENTATIONS:
        assert mac_colon(raw) in RESERVED_MACS


# ── the near misses, which must survive ──────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        # One bit from a reserved address is an ordinary address.
        ("00:00:00:00:00:01", "00:00:00:00:00:01"),
        ("01:00:00:00:00:00", "01:00:00:00:00:00"),
        ("ff:ff:ff:ff:ff:fe", "ff:ff:ff:ff:ff:fe"),
        ("fe:ff:ff:ff:ff:ff", "fe:ff:ff:ff:ff:ff"),
        # `f` unpadded is the octet 0f, not ff — this is 0f:0f:… and is not the
        # broadcast address, however much it looks like one written in haste.
        ("f:f:f:f:f:f", "0f:0f:0f:0f:0f:0f"),
        ("0f:0f:0f:0f:0f:0f", "0f:0f:0f:0f:0f:0f"),
        # A 24-bit prefix is not an EUI-48, reserved or otherwise.
        ("00:00:00", ""),
        ("ff:ff:ff", ""),
    ],
)
def test_near_miss_addresses_are_not_treated_as_reserved(raw, expected):
    assert tasks_mac(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("00:1A:2B:3C:4D:5E", "00:1a:2b:3c:4d:5e"),
        ("00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"),
        ("001a2b3c4d5e", "00:1a:2b:3c:4d:5e"),
        ("001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"),
        ("0:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("  00:1a:2b:3c:4d:5e  ", "00:1a:2b:3c:4d:5e"),
        ("Aa-Bb:Cc-Dd:Ee-Ff", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_valid_formats_survive_the_reserved_filter(raw, expected):
    """Every supported dialect, re-checked after the filter moved.

    Moving a check earlier in a function is exactly the kind of edit that
    quietly narrows what the function accepts, so the full format list is
    asserted here rather than assumed from the section above.
    """
    assert tasks_mac(raw) == expected


# =============================================================================
# Asset identity
# =============================================================================


def test_postgres_stores_every_all_zero_spelling_as_one_value(db_session):
    """Why the filter has to run on the normalized value.

    The column does not preserve the spelling it was given. Two hosts sending
    ``000000000000`` and ``0:0:0:0:0:0`` are writing the same row key, so a
    filter that compares raw text cannot see that they collide.
    """
    stored = {
        db_session.execute(text("SELECT CAST(:v AS macaddr)"), {"v": raw}).scalar()
        for raw, _ in ALL_ZERO_REPRESENTATIONS
    }
    db_session.rollback()
    assert stored == {"00:00:00:00:00:00"}


def test_a_reserved_mac_never_reaches_the_asset_lookup(db_session, test_org):
    """The guard in _sync_credentialed_asset_identity is ``if mac_address:``.

    A legacy row holding the all-zero address is seeded deliberately: this
    change does not migrate existing data, so such a row can still exist. The
    property being pinned is that no incoming host can be matched to it any
    more, whichever way it spells the address.
    """
    legacy = Asset(
        id=gen_asset_id(str(test_org.id), "legacy-all-zero"),
        org_id=str(test_org.id),
        ip_address="10.0.0.1",
        mac_address="00:00:00:00:00:00",
    )
    db_session.add(legacy)
    db_session.commit()

    try:
        for raw, _ in ALL_ZERO_REPRESENTATIONS + BROADCAST_REPRESENTATIONS:
            mac_address = tasks_mac(raw)

            # Falsy, so the caller skips the MAC branch entirely and identifies
            # the host by IP instead.
            assert mac_address == ""

            # And had it not been skipped, this is the row it would have hit.
            matched = (
                db_session.query(Asset)
                .filter(
                    Asset.org_id == str(test_org.id),
                    Asset.mac_address == "00:00:00:00:00:00",
                )
                .first()
            )
            assert matched is not None, "the collision target really is present"
    finally:
        db_session.delete(legacy)
        db_session.commit()


def test_a_real_mac_still_keys_an_asset(db_session, test_org):
    """The positive control: ordinary addresses still resolve to their asset."""
    asset = Asset(
        id=gen_asset_id(str(test_org.id), "10.0.0.2"),
        org_id=str(test_org.id),
        ip_address="10.0.0.2",
        mac_address="00:1a:2b:3c:4d:5e",
    )
    db_session.add(asset)
    db_session.commit()

    try:
        for spelling in ("00:1A:2B:3C:4D:5E", "001a2b3c4d5e", "0:1a:2b:3c:4d:5e"):
            mac_address = tasks_mac(spelling)
            assert mac_address == "00:1a:2b:3c:4d:5e"

            matched = (
                db_session.query(Asset)
                .filter(
                    Asset.org_id == str(test_org.id),
                    Asset.mac_address == mac_address,
                )
                .first()
            )
            assert matched is not None and matched.id == asset.id
    finally:
        db_session.delete(asset)
        db_session.commit()
