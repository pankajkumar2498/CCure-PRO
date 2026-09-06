"""
The mDNS probe must read the *answer*, not the question.

`_mdns_query` asks for the PTR of "<reversed-ip>.in-addr.arpa" and used to
store `resp[DNS].an.rrname` — the record's owner name, which for this query is
always the string just sent. So `mdns_name` held the question rather than the
host's own name, and that reached two places: the UI falls back to `mdns_name`
when PTR and NetBIOS are both empty, and `_extract_dns_identity` fed it into
`assets.fqdn`, where `_looks_like_fqdn` accepts anything dotted.

Measured against a real host, the answer's `rdata` carried "PankajM-HPNew.local"
the whole time.
"""

from unittest.mock import patch

import pytest
from core.discovery.enrichment import _mdns_query
from scans.asset_syncer import _extract_dns_identity

pytest.importorskip("scapy")

IP = "10.180.6.14"
QUERY_NAME = b"14.6.180.10.in-addr.arpa."
ANSWER_NAME = b"PankajM-HPNew.local."


def _fake_response(rrname, rdata, as_list=True):
    """Build a stand-in for the scapy DNS response the probe reads."""

    class _Answer:
        pass

    answer = _Answer()
    answer.rrname = rrname
    answer.rdata = rdata

    class _DNSLayer:
        ancount = 1
        # Scapy 2.7 makes 'an' a PacketListField; older builds hand back the
        # bare packet. The probe must cope with both.
        an = [answer] if as_list else answer

    class _Response:
        def haslayer(self, _layer):
            return True

        def __getitem__(self, _layer):
            return _DNSLayer()

    return _Response()


@pytest.mark.parametrize(
    "as_list", [True, False], ids=["scapy_2_7_list", "legacy_bare"]
)
def test_mdns_stores_the_answer_not_the_question(as_list):
    result = {}
    with patch(
        "scapy.all.sr1", return_value=_fake_response(QUERY_NAME, ANSWER_NAME, as_list)
    ):
        _mdns_query(IP, result)

    assert result.get("mdns_name") == "PankajM-HPNew.local"


def test_mdns_refuses_a_responder_that_echoes_the_question():
    """An echoed question establishes no name, so nothing may be recorded."""
    result = {}
    with patch("scapy.all.sr1", return_value=_fake_response(QUERY_NAME, QUERY_NAME)):
        _mdns_query(IP, result)

    assert "mdns_name" not in result


def test_reverse_lookup_string_never_becomes_an_asset_identity():
    """
    Belt and braces for the persistence half: even if some future probe puts a
    reverse-lookup string in `mdns_name`, it must not reach fqdn or dns_name.
    An mDNS name is link-local and is not a DNS name in any case.
    """
    host = {
        "ip_address": IP,
        "hostname": "",
        "ptr_hostname": None,
        "mdns_name": "14.6.180.10.in-addr.arpa",
    }
    dns_name, fqdn = _extract_dns_identity(host)

    assert dns_name is None
    assert fqdn is None


def test_mdns_name_is_not_promoted_to_fqdn():
    """A genuine .local name is still not a DNS name."""
    host = {
        "ip_address": IP,
        "hostname": "",
        "ptr_hostname": None,
        "mdns_name": "PankajM-HPNew.local",
    }
    dns_name, fqdn = _extract_dns_identity(host)

    assert dns_name is None
    assert fqdn is None
