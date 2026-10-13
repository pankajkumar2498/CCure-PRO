"""
SNMP responses are decoded by structure, never by searching for a tag byte.

Every value used to be read with ``rfind(b"\\x04")`` or a backwards scan for
``0x02``. Against a real Ubuntu agent (10.180.6.45, 13 Oct 2026) that produced:
``eth0`` reported as ``th0``; eleven phantom interfaces named ``public`` whose
"MAC" was the ASCII of the community string; every ifSpeed as 5 bps; every
SNMP agent reported as a bridge; and an IP address table of raw octets with NUL
bytes, which reached a finding's evidence and aborted the whole finding sync.

These tests build byte-exact responses with the module's own encoder and drive
``_probe_snmp`` against a fake agent shaped like that host.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from engines.vulnerability.plugins import snmp_probe as sp


def _response(
    oid, tag, value=b"", *, request_id=1, error_status=0, community=b"public"
):
    varbind = sp._tlv(0x30, sp._tlv(0x06, sp._encode_oid(oid)) + sp._tlv(tag, value))
    pdu = sp._tlv(
        0xA2,
        sp._tlv(0x02, sp._encode_integer(request_id))
        + sp._tlv(0x02, bytes([error_status]))
        + sp._tlv(0x02, b"\x00")
        + sp._tlv(0x30, varbind),
    )
    return sp._tlv(0x30, sp._tlv(0x02, b"\x01") + sp._tlv(0x04, community) + pdu)


IF_DESCR_2 = "1.3.6.1.2.1.2.2.1.2.2"


# ── single values ────────────────────────────────────────────────────────────


def test_a_length_byte_equal_to_the_string_tag_is_not_mistaken_for_it():
    """``04 04 65 74 68 30`` is the string "eth0", not a tag at the length byte."""
    assert sp._extract_string(_response(IF_DESCR_2, 0x04, b"eth0")) == "eth0"


@pytest.mark.parametrize("exception_tag", [0x80, 0x81, 0x82])
def test_an_snmp_exception_is_absence_not_the_community_string(exception_tag):
    data = _response(IF_DESCR_2, exception_tag)
    assert sp._extract_string(data) == ""
    assert sp._extract_mac(data) == ""  # "public" is six bytes long
    assert sp._extract_integer(data) is None


def test_v1_no_such_name_is_absence():
    assert sp._extract_string(_response(IF_DESCR_2, 0x05, error_status=2)) == ""


def test_an_ip_address_is_decoded_and_never_returned_as_text():
    data = _response("1.3.6.1.2.1.4.20.1.1.127.0.0.1", 0x40, bytes([127, 0, 0, 1]))
    assert sp._extract_ip_address(data) == "127.0.0.1"
    # Read as an OctetString it would carry NUL bytes into the evidence.
    assert sp._extract_string(data) == ""


@pytest.mark.parametrize(
    "tag,value,expected",
    [
        (0x02, (0).to_bytes(1, "big"), 0),
        (0x02, (-5).to_bytes(1, "big", signed=True), -5),
        (0x42, (1_000_000_000).to_bytes(4, "big"), 1_000_000_000),  # Gauge32 ifSpeed
        (
            0x43,
            (4_294_967_295).to_bytes(4, "big"),
            4_294_967_295,
        ),  # TimeTicks, high bit set
        (0x41, (7).to_bytes(1, "big"), 7),  # Counter32
    ],
)
def test_numbers_are_read_by_their_own_type(tag, value, expected):
    assert (
        sp._extract_integer(_response("1.3.6.1.2.1.2.2.1.5.2", tag, value)) == expected
    )


def test_a_long_form_length_is_followed():
    descr = "Linux superusr-HP3 6.8.0-146-generic #146-Ubuntu SMP " * 4
    data = _response("1.3.6.1.2.1.1.1.0", 0x04, descr.encode())
    assert sp._extract_string(data) == descr.strip()


def test_an_object_identifier_value_is_decoded():
    data = _response(
        "1.3.6.1.2.1.1.2.0", 0x06, sp._encode_oid("1.3.6.1.4.1.8072.3.2.10")
    )
    assert sp._extract_oid_value(data) == "1.3.6.1.4.1.8072.3.2.10"


def test_an_answer_to_a_different_request_is_rejected():
    data = _response(IF_DESCR_2, 0x04, b"eth0", request_id=41)
    assert sp._decode_response(data, request_id=41) is not None
    assert sp._decode_response(data, request_id=42) is None


@pytest.mark.parametrize("junk", [b"", b"\x30", b"\x30\x05\x02\x01", b"garbage" * 3])
def test_malformed_datagrams_decode_to_nothing(junk):
    assert sp._decode_response(junk) is None
    assert sp._extract_string(junk) == ""


def test_control_bytes_in_an_octet_string_are_removed():
    assert (
        sp._extract_string(_response("1.3.6.1.2.1.1.5.0", 0x04, b"host\x00\x01"))
        == "host"
    )


# ── a whole probe against a fake agent ───────────────────────────────────────


def _oid_key(oid: str):
    return tuple(int(x) for x in oid.split("."))


def _agent(mib: dict, community: str = "public"):
    """A GET/GETNEXT responder over *mib*: {oid: (tag, value)}."""
    ordered = sorted(mib, key=_oid_key)

    def request(ip, comm, oid, timeout, pdu_tag):
        if comm != community:
            return None  # a v1/v2c agent stays silent for a wrong community
        if pdu_tag == sp._PDU_GET:
            tag, value = mib.get(oid, (0x81, b""))
            return _response(oid, tag, value)
        following = [o for o in ordered if _oid_key(o) > _oid_key(oid)]
        if not following:
            return _response(oid, 0x82, b"")
        nxt = following[0]
        return _response(nxt, *mib[nxt])

    return request


def _ubuntu_mib() -> dict:
    s = lambda text: (0x04, text.encode())  # noqa: E731
    i = lambda n: (0x02, n.to_bytes(1, "big"))  # noqa: E731
    g = lambda n: (0x42, n.to_bytes(4, "big"))  # noqa: E731
    ip = lambda a: (0x40, bytes(int(x) for x in a.split(".")))  # noqa: E731
    mib = {
        "1.3.6.1.2.1.1.1.0": s(
            "Linux superusr-HP3 6.8.0-146-generic #146-Ubuntu SMP x86_64"
        ),
        "1.3.6.1.2.1.1.2.0": (0x06, sp._encode_oid("1.3.6.1.4.1.8072.3.2.10")),
        "1.3.6.1.2.1.1.3.0": (0x43, (123_456).to_bytes(4, "big")),
        "1.3.6.1.2.1.1.5.0": s("superusr-HP3"),
        "1.3.6.1.2.1.2.1.0": i(3),
        "1.3.6.1.2.1.4.1.0": i(2),
    }
    # Sparse ifIndex: 1, 2 and 7.
    for idx, name, mac, speed, itype in (
        (1, "lo", b"", 10_000_000, 24),
        (2, "eth0", bytes.fromhex("2c58b9870bb3"), 1_000_000_000, 6),
        (7, "docker0", bytes.fromhex("f60bd73e2295"), 0, 6),
    ):
        mib[f"1.3.6.1.2.1.2.2.1.2.{idx}"] = s(name)
        mib[f"1.3.6.1.2.1.2.2.1.3.{idx}"] = i(itype)
        mib[f"1.3.6.1.2.1.2.2.1.5.{idx}"] = g(speed)
        mib[f"1.3.6.1.2.1.2.2.1.6.{idx}"] = (0x04, mac)
        mib[f"1.3.6.1.2.1.2.2.1.7.{idx}"] = i(1)
        mib[f"1.3.6.1.2.1.2.2.1.8.{idx}"] = i(1 if idx != 7 else 2)
    # ipAddrTable is indexed by the address itself.
    for addr, mask in (("10.180.6.45", "255.255.255.0"), ("127.0.0.1", "255.0.0.0")):
        mib[f"1.3.6.1.2.1.4.20.1.1.{addr}"] = ip(addr)
        mib[f"1.3.6.1.2.1.4.20.1.3.{addr}"] = ip(mask)
    return mib


@pytest.fixture()
def probed():
    with patch.object(sp, "_snmp_request", side_effect=_agent(_ubuntu_mib())):
        return sp._probe_snmp("10.180.6.45")


def test_the_interface_table_is_walked_by_its_real_indices(probed):
    names = [(i["index"], i["description"]) for i in probed["interfaces"]]
    assert names == [(1, "lo"), (2, "eth0"), (7, "docker0")]
    eth0 = probed["interfaces"][1]
    assert eth0["mac"] == "2C:58:B9:87:0B:B3"
    assert eth0["speed_bps"] == 1_000_000_000
    assert eth0["type"] == "ethernetCsmacd"
    assert probed["interfaces"][2]["oper_up"] is False
    assert not any(i["description"] == "public" for i in probed["interfaces"])


def test_the_ip_address_table_is_read_as_addresses(probed):
    assert probed["ip_addresses"] == [
        {"address": "10.180.6.45", "netmask": "255.255.255.0"},
        {"address": "127.0.0.1", "netmask": "255.0.0.0"},
    ]


def test_system_group_and_device_type_values(probed):
    assert probed["community"] == "public"
    assert probed["sys_name"] == "superusr-HP3"
    assert probed["sys_uptime_s"] == 1234
    assert probed["enterprise_id"] == 8072
    assert probed["if_count"] == 3
    assert probed["ip_forwarding"] == 2
    # dot1dBaseBridgeAddress is absent on this agent.
    assert probed["bridge_mib"] is False


def test_a_bridge_is_reported_only_when_the_agent_has_a_bridge_address():
    mib = _ubuntu_mib()
    mib["1.3.6.1.2.1.17.1.1.0"] = (0x04, bytes.fromhex("525400530893"))
    with patch.object(sp, "_snmp_request", side_effect=_agent(mib)):
        assert sp._probe_snmp("10.0.0.1")["bridge_mib"] is True


def test_nothing_the_probe_returns_carries_a_nul_byte(probed):
    assert "\\u0000" not in json.dumps(probed)
    with patch.object(sp, "_snmp_request", side_effect=_agent(_ubuntu_mib())):
        result = sp.run("10.180.6.45", [])
    blob = json.dumps(result)
    assert "\\u0000" not in blob
    disclosure = [f for f in result["cves"] if "INFORMATION-DISCLOSURE" in f["cve_id"]]
    assert disclosure and "10.180.6.45" in disclosure[0]["evidence"]


def test_a_silent_agent_is_reported_closed():
    with patch.object(sp, "_snmp_request", side_effect=_agent({}, community="nope")):
        info = sp._probe_snmp("10.0.0.2")
    assert info["open"] is False and info["community"] == ""
