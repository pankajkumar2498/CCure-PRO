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
from core.mac import RESERVED_MACS, collector_mac, mac_colon, mac_hex, mac_identity
from scans.tasks.credentialed_sync import _normalize_mac as tasks_mac
from db.base import gen_asset_id
from db.models.assets import Asset
from engines.credentialed import linux_collector, windows_collector
from scans.asset_syncer import _existing_assets_for_hosts, _resolve_mac
from sqlalchemy import text
from sqlalchemy.exc import DataError

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


#: Every input on which ``collector_mac`` deliberately departs from the body it
#: replaced, with the value it produces now. Two kinds, and both were accidents
#: of the original rather than decisions:
#:
#: * dialects it discarded. ``linux_collector`` feeds it from a regex whose
#:   character class is ``[0-9a-fA-F:.-]{12,17}`` — dots included — so it
#:   captured Cisco dotted addresses and then threw them away.
#: * reserved addresses it let through, because it compared the compact
#:   spelling against the canonical one.
#:
#: Widening cannot lose a correct result: every input it used to refuse produced
#: ``""``, and both call sites read that as "skip this interface".
COLLECTOR_INTENTIONAL_CHANGES = {
    "001a.2b3c.4d5e": ("", "00:1a:2b:3c:4d:5e"),
    "001A.2B3C.4D5E": ("", "00:1a:2b:3c:4d:5e"),
    "0:1a:2b:3c:4d:5e": ("", "00:1a:2b:3c:4d:5e"),
    "0:1:2:3:4:5": ("", "00:01:02:03:04:05"),
    "f:f:f:f:f:f": ("", "0f:0f:0f:0f:0f:0f"),
    "0000.0000.0000": ("", ""),
    "000000000000": ("00:00:00:00:00:00", ""),
    "ffffffffffff": ("ff:ff:ff:ff:ff:ff", ""),
    "FFFFFFFFFFFF": ("ff:ff:ff:ff:ff:ff", ""),
    "ffff.ffff.ffff": ("", ""),
}


@pytest.mark.parametrize(
    "raw,expected",
    [(raw, after) for raw, (_, after) in COLLECTOR_INTENTIONAL_CHANGES.items()],
)
def test_collector_mac_intended_changes(raw, expected):
    """The departures are asserted individually, not just tolerated in bulk."""
    assert collector_mac(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "00:1a:2b:3c:4d:5e",
        "00-1A-2B-3C-4D-5E",
        "001a2b3c4d5e",
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
        "00:00:00:00:00:01",
        "ff:ff:ff:ff:ff:fe",
        "0f:0f:0f:0f:0f:0f",
    ],
)
def test_collector_mac_is_otherwise_unchanged(raw):
    """Everything outside the documented set behaves as it always did."""
    assert raw not in COLLECTOR_INTENTIONAL_CHANGES
    assert collector_mac(raw) == _original_collector_mac(raw)


def test_collector_mac_has_no_undocumented_changes_under_fuzz():
    """Every string up to four characters over a MAC-ish alphabet.

    The original body is still kept, and still compared against — what changed
    is that a difference is now allowed only where this file says so. An edit
    that alters any other input fails here.
    """
    alphabet = "0af:z-. "
    undocumented = [
        candidate
        for length in range(5)
        for candidate in (
            "".join(t) for t in itertools.product(alphabet, repeat=length)
        )
        if collector_mac(candidate) != _original_collector_mac(candidate)
        and candidate not in COLLECTOR_INTENTIONAL_CHANGES
    ]
    assert undocumented == []


def test_collector_mac_returns_empty_string_not_none():
    """Both call sites branch on ``""``; None would read as a valid falsy MAC."""
    assert collector_mac("Unknown") == ""
    assert collector_mac(None) == ""


def test_both_collectors_share_one_implementation():
    """The duplication cannot come back without this failing."""
    assert linux_collector._normalize_mac is collector_mac
    assert windows_collector._normalize_mac is collector_mac


# =============================================================================
# scans.tasks.credentialed_sync._normalize_mac (core.tasks until G1) — the colon-counting fall-through
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


# =============================================================================
# EUI-64: supported on one path, refused on the other, and both are right
# =============================================================================


@pytest.mark.parametrize("raw", ["00:1a:2b:3c:4d:5e:6f:70", "001a2b3c4d5e6f70"])
def test_eui64_is_accepted_for_vendor_lookup_and_refused_for_asset_identity(raw):
    """The two paths want different things and the difference is deliberate.

    ``core.oui_lookup`` resolves a vendor from the leading 24 bits, which an
    EUI-64 has like any other address, so ``mac_hex`` accepts one. Asset
    identity ends at ``Asset.mac_address``, a PostgreSQL ``MACADDR`` — six
    bytes, not ``MACADDR8`` — which refuses an EUI-64 outright. Passing one
    through only moves the failure to the INSERT.
    """
    assert mac_hex(raw, (6, 12, 16)) is not None
    assert mac_colon(raw) is None
    assert mac_identity(raw) is None
    assert _resolve_mac({"mac_address": raw}) is None
    assert tasks_mac(raw) == ""


def test_postgres_macaddr_refuses_eui64(db_session):
    """The reason the line above is drawn where it is."""
    assert (
        db_session.execute(
            text("SELECT CAST(:v AS macaddr)"), {"v": "00:1a:2b:3c:4d:5e"}
        ).scalar()
        == "00:1a:2b:3c:4d:5e"
    )
    db_session.rollback()

    with pytest.raises(DataError):
        db_session.execute(
            text("SELECT CAST(:v AS macaddr)"), {"v": "00:1a:2b:3c:4d:5e:6f:70"}
        )
    db_session.rollback()


# =============================================================================
# scans.asset_syncer._resolve_mac
# -----------------------------------------------------------------------------
# This lowercased its input and swapped hyphens for colons, and did nothing
# else. It applied no hex check, filtered the all-zero address by spelling
# alone, and did not filter broadcast at all — so hostnames, IP literals and
# path-injection strings were all returned as though they were addresses, on
# their way to a PostgreSQL MACADDR column.
#
# The normalization matters as much as the rejection.
# `_existing_assets_for_hosts` keys `existing_by_mac` off the value PostgreSQL
# stored, so a scanner emitting `001a2b3c4d5e` or `001a.2b3c.4d5e` produced a
# key that could never match and the host was re-identified by IP, or created
# a second time.
# =============================================================================


def _resolved(raw):
    return _resolve_mac({"mac_address": raw})


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("00:1A:2B:3C:4D:5E", "00:1a:2b:3c:4d:5e"),
        ("00-1a-2b-3c-4d-5e", "00:1a:2b:3c:4d:5e"),
        ("00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"),
        ("001a2b3c4d5e", "00:1a:2b:3c:4d:5e"),
        ("001A2B3C4D5E", "00:1a:2b:3c:4d:5e"),
        ("001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"),
        ("00-1a:2B-3c:4D-5e", "00:1a:2b:3c:4d:5e"),
        ("0:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("0:1:2:3:4:5", "00:01:02:03:04:05"),
        ("  00:1a:2b:3c:4d:5e  ", "00:1a:2b:3c:4d:5e"),
    ],
)
def test_resolve_mac_normalizes_every_supported_format(raw, expected):
    assert _resolved(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [raw for raw, _ in ALL_ZERO_REPRESENTATIONS]
    + [raw for raw, _ in BROADCAST_REPRESENTATIONS],
)
def test_resolve_mac_refuses_reserved_addresses(raw):
    """Broadcast was not filtered here at all before, in any spelling."""
    assert _resolved(raw) is None


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("00:00:00:00:00:01", "00:00:00:00:00:01"),
        ("01:00:00:00:00:00", "01:00:00:00:00:00"),
        ("ff:ff:ff:ff:ff:fe", "ff:ff:ff:ff:ff:fe"),
        ("fe:ff:ff:ff:ff:ff", "fe:ff:ff:ff:ff:ff"),
        ("f:f:f:f:f:f", "0f:0f:0f:0f:0f:0f"),
        ("0f:0f:0f:0f:0f:0f", "0f:0f:0f:0f:0f:0f"),
    ],
)
def test_resolve_mac_keeps_near_miss_addresses(raw, expected):
    assert _resolved(raw) == expected


@pytest.mark.parametrize(
    "raw,kind",
    [
        ("zz:zz:zz:zz:zz:zz", "non-hex"),
        ("q1:q2:q3:q4:q5:q6", "non-hex"),
        ("00:1a:2b:3c:4d:5ez", "valid address plus a stray character"),
        ("core-sw-01", "hostname"),
        ("edge-sw.corp.local", "FQDN"),
        ("Unknown", "scanner placeholder"),
        ("N/A", "scanner placeholder"),
        ("10.180.4.1", "IPv4 literal"),
        ("192.168.1.1", "IPv4 literal"),
        ("aabbcc/../../etc/passwd", "path injection"),
        ("aabbcc?callback=x", "query injection"),
        ("001a2b3c4d5e/../x", "valid address with a path appended"),
        ("", "empty"),
        (None, "None"),
        (0, "non-string"),
    ],
)
def test_resolve_mac_refuses_values_that_are_not_addresses(raw, kind):
    """Each of these was previously returned verbatim, bound for a MACADDR."""
    assert _resolved(raw) is None


def test_resolve_mac_reads_either_host_key():
    """Contract preserved: ``mac_address`` first, then ``mac``."""
    assert _resolve_mac({"mac_address": "001a2b3c4d5e"}) == "00:1a:2b:3c:4d:5e"
    assert _resolve_mac({"mac": "001a2b3c4d5e"}) == "00:1a:2b:3c:4d:5e"
    assert (
        _resolve_mac({"mac_address": "00:1a:2b:3c:4d:5e", "mac": "aa:bb:cc:dd:ee:ff"})
        == "00:1a:2b:3c:4d:5e"
    )
    assert _resolve_mac({}) is None


def test_resolve_mac_output_is_what_postgres_stores(db_session):
    """The property the reconciliation lookups depend on.

    ``_existing_assets_for_hosts`` builds ``existing_by_mac`` from the stored
    value. Unless ``_resolve_mac`` returns that same string, the lookup cannot
    hit — which is what happened for every scanner that did not emit colons.
    """
    for raw in (
        "001a2b3c4d5e",
        "001a.2b3c.4d5e",
        "0:1a:2b:3c:4d:5e",
        "00-1A-2B-3C-4D-5E",
    ):
        stored = db_session.execute(
            text("SELECT CAST(:v AS macaddr)"), {"v": raw}
        ).scalar()
        db_session.rollback()
        assert _resolved(raw) == str(stored)


# =============================================================================
# Asset synchronisation behaviour
# =============================================================================


def test_existing_asset_is_found_whatever_spelling_the_scanner_emits(
    db_session, test_org
):
    """The reconciliation fix, exercised through the real lookup helper."""
    asset = Asset(
        id=gen_asset_id(str(test_org.id), "10.0.0.7"),
        org_id=str(test_org.id),
        ip_address="10.0.0.7",
        mac_address="00:1a:2b:3c:4d:5e",
    )
    db_session.add(asset)
    db_session.commit()

    try:
        for spelling in (
            "00:1a:2b:3c:4d:5e",
            "00:1A:2B:3C:4D:5E",
            "00-1a-2b-3c-4d-5e",
            "001a2b3c4d5e",
            "001a.2b3c.4d5e",
            "0:1a:2b:3c:4d:5e",
        ):
            host = {"ip": "10.0.0.99", "mac_address": spelling}
            _, _, existing_by_mac = _existing_assets_for_hosts(
                db_session, str(test_org.id), [host]
            )
            mac = _resolve_mac(host)
            assert mac is not None
            assert existing_by_mac.get(mac) is not None, spelling
            assert existing_by_mac[mac].id == asset.id
    finally:
        db_session.delete(asset)
        db_session.commit()


def test_a_reserved_mac_never_becomes_an_asset_key(db_session, test_org):
    """A host reporting a reserved address is identified by IP, not by MAC.

    Several hosts can report an all-zero MAC at once — a NIC with no hardware
    address, some hypervisor interfaces, a failed read — and before this they
    all resolved to the same key.
    """
    for raw, _ in ALL_ZERO_REPRESENTATIONS + BROADCAST_REPRESENTATIONS:
        host = {"ip": "10.0.0.8", "mac_address": raw}
        assert _resolve_mac(host) is None

        _, _, existing_by_mac = _existing_assets_for_hosts(
            db_session, str(test_org.id), [host]
        )
        # Nothing to look up with, so the caller falls through to IP identity.
        assert "00:00:00:00:00:00" not in existing_by_mac
        assert "ff:ff:ff:ff:ff:ff" not in existing_by_mac


def test_asset_id_falls_back_to_unknown_without_a_usable_mac(test_org):
    """The ``_resolve_mac(h) or "unknown"`` branch in _existing_assets_for_hosts.

    A host with no routable IP is keyed on its MAC instead. With a reserved or
    malformed address that key is now the literal "unknown" rather than a
    fabricated one, so two such hosts no longer collide on a MAC-shaped id.
    """
    assert _resolve_mac({"mac_address": "000000000000"}) is None
    assert _resolve_mac({"mac_address": "zz:zz:zz:zz:zz:zz"}) is None
    assert _resolve_mac({"mac_address": "001a2b3c4d5e"}) == "00:1a:2b:3c:4d:5e"
