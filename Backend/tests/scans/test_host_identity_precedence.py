"""
Host identity resolution: one declared precedence, applied in one place.

Six probes used to write ``result["hostname"]``, each guarded by "only if
nothing is there yet", so the winner was whichever ran first. NBNS runs as a
discovery *technique* — before enrichment — so on a host answering NetBIOS the
NetBIOS name won and PTR never overwrote it, which is the opposite of what the
probe list in ``enrich_host`` suggests. These tests pin the order as a
property of the table rather than of the call sequence.
"""

from unittest.mock import patch

import pytest
from core.discovery.host_identity import (
    HOSTNAME_PRECEDENCE,
    forward_confirm,
    resolve_identity,
)

IP = "10.180.6.14"


# ── The declared order ───────────────────────────────────────────────────────


def test_a_machines_own_name_beats_what_dns_calls_its_address():
    """The defect this module exists for: PTR ran first and took the field."""
    result = {
        "ptr_hostname": "ccurepro.cdacb.in",
        "mdns_name": "PankajM-HPNew.local",
    }
    resolve_identity(result)

    assert result["hostname"] == "PankajM-HPNew"
    assert result["hostname_source"] == "mdns"
    # and the DNS name is not lost — it is reported as what it is
    assert result["fqdn"] == "ccurepro.cdacb.in"
    assert result["dns_name"] == "ccurepro.cdacb.in"


@pytest.mark.parametrize(
    "fields,expected_name,expected_source",
    [
        (
            {"snmp_sys_name": "sw-core-01", "netbios_computer": "NB"},
            "sw-core-01",
            "snmp",
        ),
        (
            {"netbios_computer": "WKS-042", "mdns_name": "other.local"},
            "WKS-042",
            "netbios",
        ),
        ({"mdns_name": "printer.local", "lldp_hostname": "sw"}, "printer", "mdns"),
        (
            {"lldp_hostname": "sw-edge-7", "ptr_hostname": "a.example.com"},
            "sw-edge-7",
            "lldp",
        ),
        (
            {"ptr_hostname": "a.example.com", "ot_model": "S7-1500"},
            "a.example.com",
            "ptr",
        ),
        ({"ot_model": "S7-1500"}, "S7-1500", "ot_probe"),
    ],
)
def test_each_source_beats_the_one_below_it(fields, expected_name, expected_source):
    result = dict(fields)
    resolve_identity(result)

    assert result["hostname"] == expected_name
    assert result["hostname_source"] == expected_source


def test_precedence_table_is_ordered_most_authoritative_first():
    """A reordering of the table is a behaviour change and must be deliberate."""
    assert [source for _field, source in HOSTNAME_PRECEDENCE] == [
        "snmp",
        "netbios",
        "mdns",
        "lldp",
        "ptr",
        "ot_probe",
    ]


# ── Absence, placeholders and junk ───────────────────────────────────────────


def test_an_unnamed_host_has_no_hostname_key_rather_than_a_placeholder():
    """ "We did not establish a name" is not "its name is Unknown"."""
    result = {"ip": IP}
    resolve_identity(result)

    assert "hostname" not in result
    assert "hostname_source" not in result


@pytest.mark.parametrize("junk", ["Unknown", "N/A", "", "  ", "none", "-"])
def test_placeholders_never_win(junk):
    result = {"netbios_computer": junk, "ptr_hostname": "real.example.com"}
    resolve_identity(result)

    assert result["hostname"] == "real.example.com"
    assert result["hostname_source"] == "ptr"


def test_a_reverse_lookup_string_is_never_a_name():
    """The last gate before publication — see test_mdns_hostname_parse."""
    result = {
        "mdns_name": "14.6.180.10.in-addr.arpa",
        "ptr_hostname": "real.example.com",
    }
    resolve_identity(result)

    assert result["hostname"] == "real.example.com"
    assert result["fqdn"] == "real.example.com"


# ── hostname is not fqdn ─────────────────────────────────────────────────────


def test_a_link_local_mdns_name_never_becomes_a_dns_name():
    """An mDNS name resolves nowhere outside the segment that answered."""
    result = {"mdns_name": "PankajM-HPNew.local"}
    resolve_identity(result)

    assert result["hostname"] == "PankajM-HPNew"
    assert "fqdn" not in result
    assert "dns_name" not in result


def test_a_netbios_name_never_becomes_a_dns_name():
    result = {"netbios_computer": "WKS-042"}
    resolve_identity(result)

    assert result["hostname"] == "WKS-042"
    assert "fqdn" not in result


def test_ptr_is_the_only_thing_that_answers_a_dns_question():
    result = {"snmp_sys_name": "sw-core-01", "ptr_hostname": "sw1.corp.example.com"}
    resolve_identity(result)

    assert result["hostname"] == "sw-core-01"
    assert result["fqdn"] == "sw1.corp.example.com"
    assert result["fqdn_source"] == "ptr"


# ── Idempotence ──────────────────────────────────────────────────────────────


def test_resolving_twice_changes_nothing():
    """It runs in enrich_host and again in engine.run; both must be safe."""
    result = {"ptr_hostname": "ccurepro.cdacb.in", "mdns_name": "PankajM-HPNew.local"}
    resolve_identity(result)
    first = dict(result)
    resolve_identity(result)

    assert result == first


# ── Forward-confirmed reverse DNS ────────────────────────────────────────────


def test_forward_confirmation_true_when_the_name_resolves_back():
    with patch("socket.gethostbyname_ex", return_value=("ccurepro.cdacb.in", [], [IP])):
        assert forward_confirm(IP, "ccurepro.cdacb.in") is True


def test_forward_confirmation_false_when_the_name_resolves_elsewhere():
    with patch(
        "socket.gethostbyname_ex", return_value=("stale.example.com", [], ["10.0.0.9"])
    ):
        assert forward_confirm(IP, "stale.example.com") is False


@pytest.mark.parametrize("boom", [OSError, __import__("socket").gaierror])
def test_an_unanswerable_lookup_is_none_and_never_false(boom):
    """
    The third state is load-bearing. Reading "could not ask" as "not
    confirmed" brands every host in an internal-only or split-horizon zone as
    suspect, which is most of an enterprise estate.
    """
    with patch("socket.gethostbyname_ex", side_effect=boom):
        assert forward_confirm(IP, "internal.example.com") is None


def test_no_forward_record_is_none_not_false():
    with patch("socket.gethostbyname_ex", return_value=("x", [], [])):
        assert forward_confirm(IP, "x") is None
