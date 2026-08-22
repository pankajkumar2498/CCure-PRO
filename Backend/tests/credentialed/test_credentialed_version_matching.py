"""
tests/test_credentialed_version_matching.py
─────────────────────────────────────────────────────────────────────────────
Version comparison for credentialed package findings.

Every string below was taken from a live Windows inventory. Real inventories do
not hand you bare semver: Windows DisplayVersion values carry vendor prose
("ad 9.0.14"), Siemens ships service-pack notation ("V2.12 Sp0 Upd0"), and some
products register no version at all.

The parser that dropped unreadable components produced both failure modes at
once on that host — it invented ten AnyDesk findings against a patched 9.x
install, and it missed eight real Siemens findings including a Critical.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))

from engines.credentialed.vuln_matcher import (  # noqa: E402
    _parse_version,
    _version_gte,
    _version_lt,
)


def test_version_is_read_from_inside_vendor_prose():
    assert _parse_version("ad 9.0.14") == (9, 0, 14)  # AnyDesk, Windows registry
    assert _parse_version("V2.12 Sp0 Upd0") == (2, 12)  # Siemens UMC
    assert _parse_version("v2.1") == (2, 1)
    assert _parse_version("Release 4.3") == (4, 3)
    assert _parse_version("1:2.3.4-1ubuntu1") == (2, 3, 4)  # Debian epoch
    assert _parse_version("1.0.2k") == (1, 0, 2, 11)  # OpenSSL patch letter


def test_an_unreadable_version_yields_nothing_rather_than_zero():
    """
    ``(0,)`` compares as lower than every fixed release, so an unreadable
    version silently satisfied every "affected below X" test. Returning nothing
    is recoverable; returning a wrong number that compares cleanly is not.
    """
    assert _parse_version("") == ()
    assert _parse_version("not-a-version") == ()
    assert _parse_version(None) == ()


def test_a_patched_product_is_not_reported_as_vulnerable():
    """AnyDesk 9.0.14 against CVE-2020-13160, which affects before 5.5.3."""
    assert _version_lt("ad 9.0.14", "5.5.3") is False
    assert _version_gte("ad 9.0.14", "5.5.3") is True


def test_a_genuinely_affected_version_still_matches():
    assert _version_lt("4.0.1", "5.5.3") is True
    # Siemens UMC V2.12 against fixed 2.15.1.1 — a real finding the old parser
    # missed, because it read the version as (12,) and 12 > 2.
    assert _version_lt("V2.12 Sp0 Upd0", "2.15.1.1") is True


def test_no_ordering_is_asserted_when_a_version_cannot_be_read():
    """A claim needs evidence in both directions, not just the absence of it."""
    for op in (_version_lt, _version_gte):
        assert op("", "5.5.3") is False
        assert op("unknown", "5.5.3") is False
        assert op("5.5.3", "") is False
