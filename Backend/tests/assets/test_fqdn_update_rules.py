"""
Which DNS name is allowed to replace which.

Two defects, both of which let a wrong value become permanent:

  * `_looks_like_fqdn` accepted anything dotted, so the reverse-lookup string
    "14.6.180.10.in-addr.arpa" qualified as a DNS name — and at six labels it
    then won the length tiebreak against every real name, so no later scan
    could ever correct it. Measured on the live registry before the fix.
  * The length tiebreak applied even when the incoming value came from a
    *better* source, so a deeper name from a weaker scan held off a
    better-sourced one indefinitely.
"""

import pytest
from db.models.assets import Asset
from scans.asset_syncer import _can_update_field, _fqdn_label_count, _looks_like_fqdn


def _asset(**kw):
    """An Asset carrying a stored value and its provenance."""
    field = kw.pop("field", "fqdn")
    value = kw.pop("value", None)
    source = kw.pop("source", "discovery")
    asset = Asset()
    setattr(asset, field, value)
    asset.custom_attributes = {"provenance": {field: {"source": source}}}
    return asset


# ── What counts as a DNS name ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        "14.6.180.10.in-addr.arpa",
        "160.7.180.10.in-addr.arpa",
        "1.0.0.0.0.0.0.0.ip6.arpa",
        "14.6.180.10.IN-ADDR.ARPA",
    ],
)
def test_a_reverse_lookup_string_is_not_a_dns_name(value):
    assert _looks_like_fqdn(value) is False
    assert _fqdn_label_count(value) == 0


def test_an_mdns_name_is_not_a_dns_name():
    """ "host.local" is link-local — it resolves on that segment and nowhere else."""
    assert _looks_like_fqdn("PankajM-HPNew.local") is False


def test_active_directory_dot_local_domains_are_still_dns_names():
    """
    Plenty of AD estates use .local as a real internal domain. The label count
    is what separates them from the mDNS shape; rejecting the suffix outright
    would break every one of those deployments.
    """
    assert _looks_like_fqdn("pc1.corp.local") is True
    assert _looks_like_fqdn("host.ad.contoso.local") is True


@pytest.mark.parametrize(
    "value,expected",
    [
        ("ccurepro.cdacb.in", True),
        ("atharv-desktop.blr.cdac.in", True),
        ("singlelabel", False),
        ("10.180.6.14", False),
        ("", False),
        (None, False),
    ],
)
def test_ordinary_cases(value, expected):
    assert _looks_like_fqdn(value) is expected


# ── The stickiness this fixes ────────────────────────────────────────────────


def test_a_real_name_can_replace_a_stored_reverse_lookup_string():
    """
    The regression that made cleanup mandatory: the stored junk had more
    labels than any real name, so every future scan's correct answer lost.
    """
    asset = _asset(value="14.6.180.10.in-addr.arpa", source="discovery")

    assert _can_update_field(asset, "fqdn", "ccurepro.cdacb.in", "discovery") is True


def test_a_reverse_lookup_string_can_never_be_written():
    asset = _asset(value="ccurepro.cdacb.in", source="discovery")

    assert (
        _can_update_field(asset, "fqdn", "14.6.180.10.in-addr.arpa", "discovery")
        is False
    )


# ── Authority beats length ───────────────────────────────────────────────────


def test_a_better_source_wins_even_with_a_shorter_name():
    asset = _asset(value="host.a.b.example.com", source="discovery")

    assert (
        _can_update_field(asset, "fqdn", "host.example.com", "vulnerability_audit")
        is True
    )


def test_a_weaker_source_never_wins_even_with_a_longer_name():
    asset = _asset(value="host.example.com", source="vulnerability_audit")

    assert (
        _can_update_field(asset, "fqdn", "host.a.b.example.com", "discovery") is False
    )


# ── Length is the tiebreak at equal authority ────────────────────────────────


def test_at_equal_authority_the_more_qualified_name_wins():
    asset = _asset(value="host.example.com", source="discovery")

    assert (
        _can_update_field(asset, "fqdn", "host.corp.example.com", "discovery") is True
    )


def test_at_equal_authority_a_less_qualified_name_does_not_replace():
    asset = _asset(value="host.corp.example.com", source="discovery")

    assert _can_update_field(asset, "fqdn", "host.example.com", "discovery") is False


def test_an_absent_stored_value_is_always_replaceable():
    """NULL is how the cleanup script leaves a field for the next scan to fill."""
    asset = _asset(value=None, source="discovery")

    assert _can_update_field(asset, "fqdn", "ccurepro.cdacb.in", "discovery") is True


def test_credentialed_still_does_not_write_dns_names():
    """
    Unchanged and deliberate: an authenticated session knows what the machine
    calls itself, which is the hostname question, not what DNS calls it.
    """
    asset = _asset(value=None, source="discovery")

    assert _can_update_field(asset, "fqdn", "host.example.com", "credentialed") is False
