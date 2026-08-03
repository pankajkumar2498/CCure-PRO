"""
Endpoint-identity and schema-migration tests.

`core.topology.identity` is the boundary that decides what may be compared
against `Asset.mac_address` (a PostgreSQL MACADDR column) and what may not, so
its edge cases are worth pinning directly rather than only through the engine.
"""

import pytest
from core.topology.identity import (
    canonical_pair,
    is_usable_mac,
    is_valid_ip,
    make_endpoint,
    normalize_mac,
)
from db.base import gen_network_link_id


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("00-1A-2B-3C-4D-5E", "00:1a:2b:3c:4d:5e"),
        ("001a2b3c4d5e", "00:1a:2b:3c:4d:5e"),
        ("001a.2b3c.4d5e", "00:1a:2b:3c:4d:5e"),  # Cisco dotted form
        ("core-sw-01", None),  # LLDP chassis subtype 7 (locally assigned)
        ("edge-sw.corp.local", None),  # CDP device ID
        ("10.180.4.1", None),  # LLDP chassis subtype 5 (network address)
        ("", None),
        (None, None),
    ],
)
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize(
    "mac,usable",
    [
        ("00:1a:2b:3c:4d:5e", True),
        ("ff:ff:ff:ff:ff:ff", False),  # broadcast
        ("00:00:00:00:00:00", False),  # null
        ("01:00:5e:00:00:fb", False),  # IPv4 multicast (mDNS)
        ("33:33:00:00:00:01", False),  # IPv6 all-nodes multicast
        ("01:80:c2:00:00:0e", False),  # LLDP reserved group address
        ("02:1a:2b:3c:4d:5e", True),  # locally administered but unicast
    ],
)
def test_is_usable_mac(mac, usable):
    assert is_usable_mac(mac) is usable


def test_is_valid_ip():
    assert is_valid_ip("10.180.4.1")
    assert is_valid_ip("::1")
    assert not is_valid_ip("0.0.0.0")
    assert not is_valid_ip("not-an-ip")
    assert not is_valid_ip(None)


def test_make_endpoint_classifies_by_available_identity():
    mac_ep = make_endpoint(raw_id="00:1a:2b:3c:4d:5e", ip="10.1.1.5")
    assert (mac_ep.kind, mac_ep.key, mac_ep.ip) == (
        "mac",
        "00:1a:2b:3c:4d:5e",
        "10.1.1.5",
    )

    ip_ep = make_endpoint(raw_id=None, ip="10.1.1.6")
    assert (ip_ep.kind, ip_ep.key) == ("ip", "ip:10.1.1.6")

    name_ep = make_endpoint(raw_id="core-sw-01")
    assert (name_ep.kind, name_ep.key, name_ep.name) == (
        "name",
        "name:core-sw-01",
        "core-sw-01",
    )

    # A CDP device ID with a management address prefers the address, which is
    # the identity inventory can actually join on.
    cdp_ep = make_endpoint(raw_id="edge-sw", ip="10.1.1.7", name="edge-sw")
    assert cdp_ep.key == "ip:10.1.1.7"
    assert cdp_ep.name == "edge-sw"

    assert make_endpoint(raw_id="ff:ff:ff:ff:ff:ff") is None
    assert make_endpoint(raw_id="", ip="0.0.0.0") is None


def test_make_endpoint_decodes_legacy_placeholders():
    """Links recorded before endpoint identity existed still have to resolve."""
    assert make_endpoint(raw_id="sw:10:180:4:1").key == "ip:10.180.4.1"
    assert make_endpoint(raw_id="cdp:10.180.4.2").key == "ip:10.180.4.2"


def test_canonical_pair_is_order_independent():
    a = make_endpoint(raw_id="00:aa:aa:aa:aa:aa")
    b = make_endpoint(raw_id="00:bb:bb:bb:bb:bb")

    first_ab, second_ab, swapped_ab = canonical_pair(a, b)
    first_ba, second_ba, swapped_ba = canonical_pair(b, a)

    assert (first_ab.key, second_ab.key) == (first_ba.key, second_ba.key)
    assert swapped_ab is False and swapped_ba is True


def test_link_id_does_not_collide_across_distinct_endpoints():
    """
    Stripping separators from identifiers merged distinct devices: 10.1.4.11 and
    1.0.14.11 both reduce to '1014 11'. Two different switches sharing one link
    row is a silent topology error, so non-MAC keys are hashed instead.
    """
    peer = "00:11:22:33:44:55"
    a = gen_network_link_id("acme", "ip:10.1.4.11", peer)
    b = gen_network_link_id("acme", "ip:1.0.14.11", peer)
    assert a != b

    # MAC-keyed links stay readable, and remain undirected.
    mac_link = gen_network_link_id("acme", "00:aa:bb:cc:dd:ee", peer)
    assert "001122334455" in mac_link and "00aabbccddee" in mac_link
    assert mac_link == gen_network_link_id("acme", peer, "00:aa:bb:cc:dd:ee")


def test_ensure_topology_schema_upgrades_a_pre_existing_table():
    """
    Deployed installs already have the first-release table. The startup
    migration has to add the identity, evidence and ageing columns, backfill
    them, and relax the NOT NULL on the MAC columns — otherwise the first scan
    after an upgrade fails on an endpoint with no known MAC.
    """
    from db.base import engine
    from db.models.topology import ensure_topology_schema
    from sqlalchemy import inspect, text

    # A throwaway replica of the first-release table. Migrating the live one
    # would take an ACCESS EXCLUSIVE lock and block on any other open session.
    probe = "network_links_legacy_probe"

    with engine.begin() as conn:
        conn.execute(text(f"DROP TABLE IF EXISTS {probe}"))
        conn.execute(
            text(
                f"""
                CREATE TABLE {probe} (
                    id          VARCHAR(200) PRIMARY KEY,
                    org_id      VARCHAR(100) NOT NULL,
                    scan_id     VARCHAR(100) NOT NULL,
                    source_mac  VARCHAR(50)  NOT NULL,
                    source_port VARCHAR(100),
                    target_mac  VARCHAR(50)  NOT NULL,
                    target_port VARCHAR(100),
                    target_ip   VARCHAR(50),
                    link_type   VARCHAR(50) DEFAULT 'physical',
                    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
                """
            )
        )
        conn.execute(
            text(
                f"INSERT INTO {probe} "
                "(id, org_id, scan_id, source_mac, target_mac, link_type) VALUES "
                "('lnk_legacy', 'org1', 'scan1', 'sw:10:180:4:1', "
                "'00:11:22:33:44:55', 'arp')"
            )
        )

    try:
        ensure_topology_schema(engine=engine, table=probe)

        columns = {c["name"]: c for c in inspect(engine).get_columns(probe)}
        for expected in (
            "source_key",
            "target_key",
            "observed_types",
            "first_seen_at",
            "last_seen_at",
            "source_ip",
            "vlan_id",
            "speed_bps",
        ):
            assert expected in columns, f"{expected} missing after migration"

        # The MAC columns must no longer be mandatory — a switch whose MAC is
        # unknown is the case that used to have no representable row.
        assert columns["source_mac"]["nullable"] is True
        assert columns["target_mac"]["nullable"] is True

        with engine.begin() as conn:
            row = conn.execute(
                text(
                    "SELECT source_key, target_key, observed_types, first_seen_at, "
                    f"last_seen_at FROM {probe} WHERE id = 'lnk_legacy'"
                )
            ).one()
        # Existing rows are backfilled rather than left half-populated.
        assert row[0] == "sw:10:180:4:1"
        assert row[1] == "00:11:22:33:44:55"
        assert row[2] == "arp"
        assert row[3] is not None and row[4] is not None

        # Re-running must be a no-op, since it runs on every startup.
        ensure_topology_schema(engine=engine, table=probe)
        assert set(columns) == {c["name"] for c in inspect(engine).get_columns(probe)}
    finally:
        with engine.begin() as conn:
            conn.execute(text(f"DROP TABLE IF EXISTS {probe}"))
