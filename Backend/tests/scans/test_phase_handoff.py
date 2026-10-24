"""
What one network-scan phase hands the next (C6, ``core/phase_handoff.py``).

These pin the two properties the hand-off rests on: a record crosses as its
producer's own dict, every key and its order kept and no copy made (the
receiving phase's engines edit it in place, and phase 3 reads the edits back);
and the decisions the pipeline makes from it — which hosts are active, which
identity is restored — are the ones the phase tasks made before C6.
"""

import pytest

from core.phase_handoff import (
    HOST_IDENTITY_FIELDS,
    HandoffError,
    HostRecord,
    ServiceInventory,
    active,
    host_records,
    merge_host_identity,
)


def _record(**fields):
    base = {"ip_address": "10.0.0.1", "is_active": True, "hostname": "h1"}
    base.update(fields)
    return base


def test_a_record_crosses_as_its_own_dict():
    wire = _record(extra_key="kept", open_ports=[{"port": 22}])
    record = HostRecord.from_wire(wire)
    assert record.wire() is wire
    assert list(record.wire()) == [
        "ip_address",
        "is_active",
        "hostname",
        "extra_key",
        "open_ports",
    ]


def test_an_edit_made_downstream_reaches_the_record():
    wire = _record(open_ports=[{"port": 22, "service": "ssh"}])
    inventory = ServiceInventory.from_wire([wire])
    inventory.wire()[0]["open_ports"][0]["version"] = "9.6"
    assert wire["open_ports"][0]["version"] == "9.6"


def test_the_typed_fields_are_read_from_the_record():
    record = HostRecord.from_wire(
        _record(
            open_ports=[
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6",
                },
                {"port": "443"},
                "not a port",
            ]
        )
    )
    assert record.ip_address == "10.0.0.1"
    assert record.is_active is True
    assert [s.port for s in record.services] == [22, 443]
    assert record.services[0].product == "OpenSSH"


def test_an_address_written_under_ip_is_read():
    assert HostRecord.from_wire({"ip": "10.0.0.9"}).ip_address == "10.0.0.9"
    assert HostRecord.from_wire({"is_active": True}).ip_address is None


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, True),
        (False, False),
        (None, False),
        (1, True),
        (0, False),
        ("true", True),
        ("", False),
    ],
)
def test_is_active_is_read_for_truth_as_the_pipeline_always_read_it(value, expected):
    assert HostRecord.from_wire({"is_active": value}).is_active is expected
    assert bool({"is_active": value}.get("is_active")) is expected


def test_a_record_that_is_not_a_mapping_is_refused():
    with pytest.raises(HandoffError):
        HostRecord.from_wire(["10.0.0.1"])
    with pytest.raises(HandoffError):
        host_records([_record(), "10.0.0.2"])
    with pytest.raises(HandoffError):
        host_records(None)


def test_active_keeps_order_and_the_same_dicts():
    wires = [
        _record(ip_address="10.0.0.1"),
        _record(ip_address="10.0.0.2", is_active=False),
        _record(ip_address="10.0.0.3"),
    ]
    chosen = active(host_records(wires))
    assert [r.wire() for r in chosen] == [wires[0], wires[2]]
    assert all(r.wire() is w for r, w in zip(chosen, (wires[0], wires[2])))
    # The pre-C6 selection, for comparison.
    assert [h for h in wires if h.get("is_active")] == [r.wire() for r in chosen]


def test_an_inventory_hands_on_its_active_hosts():
    wires = [
        _record(open_ports=[{"port": 22}]),
        _record(ip_address="10.0.0.2", is_active=0),
    ]
    inventory = ServiceInventory.from_wire(wires).active()
    assert inventory.wire() == [wires[0]]
    assert inventory.wire()[0] is wires[0]
    assert inventory.service_count == 1


# The merge as the vulnerability audit task defined it before C6, verbatim.
def _pre_c6_merge(enriched_hosts, source_hosts):
    by_ip = {}
    for host in source_hosts or []:
        ip = host.get("ip_address") or host.get("ip")
        if ip:
            by_ip[ip] = host
    merged = []
    for idx, host in enumerate(enriched_hosts or []):
        base = {}
        ip = host.get("ip_address") or host.get("ip")
        if ip and ip in by_ip:
            base = dict(by_ip[ip])
        elif idx < len(source_hosts or []):
            base = dict(source_hosts[idx])
        combined = dict(base)
        combined.update(host or {})
        for key in (
            "ip",
            "ip_address",
            "hostname",
            "mac",
            "mac_address",
            "vendor",
            "is_active",
            "status",
            "open_ports",
            "os_guess",
            "os_confidence",
            "device_category",
            "snmp_device_type",
            "mdns_name",
            "netbios_names",
            "os_fingerprint_full",
            "tcp_fingerprint",
            "port_states",
        ):
            if combined.get(key) in (None, "", [], {}):
                if key in base:
                    combined[key] = base.get(key)
        merged.append(combined)
    return merged


MERGE_CASES = [
    # identity restored by address
    (
        [{"ip_address": "10.0.0.1", "cves": [1]}],
        [_record(vendor="Acme", open_ports=[{"port": 22}])],
    ),
    # emptied fields restored, filled ones kept
    (
        [{"ip_address": "10.0.0.1", "hostname": "", "vendor": "New", "os_guess": None}],
        [_record(vendor="Old", os_guess="Linux")],
    ),
    # no address on the output: matched by position
    (
        [{"cves": []}, {"cves": [2]}],
        [_record(ip_address="10.0.0.5"), _record(ip_address="10.0.0.6")],
    ),
    # more outputs than inputs, and an address under ip
    (
        [{"ip": "10.0.0.7"}, {"ip_address": "10.0.0.8"}],
        [{"ip": "10.0.0.7", "hostname": "seven", "mac": "aa"}],
    ),
    # nothing handed over
    ([{"ip_address": "10.0.0.9"}], []),
    ([], [_record()]),
]


@pytest.mark.parametrize("enriched, source", MERGE_CASES)
def test_identity_is_restored_exactly_as_before(enriched, source):
    import copy

    expected = _pre_c6_merge(copy.deepcopy(enriched), copy.deepcopy(source))
    assert (
        merge_host_identity(copy.deepcopy(enriched), copy.deepcopy(source)) == expected
    )
    inventory = ServiceInventory.from_wire(copy.deepcopy(source))
    restored = inventory.restore_identity(copy.deepcopy(enriched))
    assert restored == expected
    assert [list(h) for h in restored] == [list(h) for h in expected]


def test_the_identity_fields_are_the_ones_the_task_restored():
    assert HOST_IDENTITY_FIELDS == (
        "ip",
        "ip_address",
        "hostname",
        "mac",
        "mac_address",
        "vendor",
        "is_active",
        "status",
        "open_ports",
        "os_guess",
        "os_confidence",
        "device_category",
        "snmp_device_type",
        "mdns_name",
        "netbios_names",
        "os_fingerprint_full",
        "tcp_fingerprint",
        "port_states",
    )
