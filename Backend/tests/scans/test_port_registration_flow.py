from unittest.mock import MagicMock, patch

import pytest
from core.discovery.enrichment import _register_open_port, enrich_host
from orchestrator.scan_orchestrator import ScanOrchestrator


def test_register_open_port_honors_register_ports_flag():
    # Scenario 1: register_ports is True (default)
    result_with_ports = {"port_states": {}, "open_ports": [], "confirmations": []}
    _register_open_port(result_with_ports, port=137, service="netbios-ns")
    assert 137 in result_with_ports["port_states"]
    assert len(result_with_ports["open_ports"]) == 1
    assert result_with_ports["open_ports"][0]["port"] == 137

    # Scenario 2: register_ports is False (as in FAST profile / Basic Scan)
    result_no_ports = {
        "port_states": {},
        "open_ports": [],
        "confirmations": [],
        "_register_ports": False,
    }
    _register_open_port(result_no_ports, port=137, service="netbios-ns")
    assert 137 not in result_no_ports["port_states"]
    assert len(result_no_ports["open_ports"]) == 0


@patch("core.discovery.enrichment._netbios_query")
@patch("core.discovery.enrichment._mdns_query")
@patch("core.discovery.enrichment._ptr_lookup")
def test_enrich_host_sets_and_pops_internal_flag(mock_ptr, mock_mdns, mock_netbios):
    # Mocking basic query functions to simulate discovery enrichment behavior
    def mock_nb_query(ip, result):
        _register_open_port(result, port=137, service="netbios-ns")
        result["netbios_computer"] = "TEST-PC"

    mock_netbios.side_effect = mock_nb_query

    # Test under FAST profile (register_ports=False)
    result_fast = {"port_states": {}, "open_ports": []}
    enrich_host("10.180.12.104", result_fast, ot_enrichment=False, register_ports=False)

    # Internal key should be popped
    assert "_register_ports" not in result_fast
    # Hostname/NetBIOS name details are resolved
    assert result_fast.get("netbios_computer") == "TEST-PC"
    # Port 137 should NOT be registered as open
    assert 137 not in result_fast["port_states"]
    assert len(result_fast["open_ports"]) == 0

    # Test under AGGRESSIVE profile (register_ports=True)
    result_aggressive = {"port_states": {}, "open_ports": []}
    enrich_host(
        "10.180.12.104", result_aggressive, ot_enrichment=False, register_ports=True
    )

    assert "_register_ports" not in result_aggressive
    assert result_aggressive.get("netbios_computer") == "TEST-PC"
    # Port 137 SHOULD be registered as open
    assert 137 in result_aggressive["port_states"]
    assert len(result_aggressive["open_ports"]) == 1


@pytest.mark.asyncio
@patch("orchestrator.scan_orchestrator.PortEngine")
async def test_orchestrator_merges_phase1_ports_into_phase2(mock_port_engine_cls):
    # Mock PortEngine to run without modifying open_ports (simulating a scan that misses port 502)
    mock_port_engine = MagicMock()

    async def mock_run(hosts, progress=None):
        for h in hosts:
            # Overwrite open_ports to represent a scan that did not cover port 502
            h["open_ports"] = []
            h["port_states"] = {}
        return hosts

    mock_port_engine.run = mock_run
    mock_port_engine_cls.return_value = mock_port_engine

    # Setup hosts list with Phase 1 enrichment details
    hosts_input = [
        {
            "ip": "10.180.12.104",
            "ip_address": "10.180.12.104",
            "is_active": True,
            "vendor": "Modbus Device",
            "open_ports": [
                {
                    "port": 502,
                    "service": "MODBUS",
                    "state": "open",
                    "banner": "Protocol: MODBUS, Vendor: Modbus Device",
                }
            ],
            "port_states": {502: "open", "502": "open"},
        }
    ]

    orch = ScanOrchestrator()

    # Mocking helpers on orchestrator that we are not testing
    orch._expand_targets = MagicMock(return_value=["10.180.12.104"])
    orch._apply_os_inference = MagicMock()

    res = await orch.run_asset_discovery_only(
        hosts=hosts_input,
        intensity="normal",
        pipeline_mode="vulnerability_audit",
        os_detection=False,
    )

    assert res["success"] is True
    hosts_output = res["data"]
    assert len(hosts_output) == 1

    host = hosts_output[0]
    # Verify port 502 from Phase 1 is merged back into Phase 2 output
    assert len(host["open_ports"]) == 1
    assert host["open_ports"][0]["port"] == 502
    assert host["port_states"]["502"] == "open"
    assert host["port_states"][502] == "open"


def test_port_engine_port_list_curated_hybrid_ranges():
    from core.constants import SCAN_PORTS_OT, SCAN_PORTS_QUICK
    from core.models import ScanIntensity
    from engines.port.port_engine import PortEngine

    # Scenario 1: LIGHT intensity
    # Pass exclude_ot_from_nmap=False so OT ports are not stripped from the list
    pe_light = PortEngine(intensity=ScanIntensity.LIGHT, exclude_ot_from_nmap=False)
    ports_light = pe_light._port_list()
    # Check that it contains all OT ports (like 502, 102, 2404)
    for ot_port in SCAN_PORTS_OT:
        assert ot_port in ports_light
    # Check that it contains SCAN_PORTS_QUICK
    for quick_port in SCAN_PORTS_QUICK:
        assert quick_port in ports_light

    # Scenario 2: NORMAL intensity
    pe_normal = PortEngine(intensity=ScanIntensity.NORMAL, exclude_ot_from_nmap=False)
    ports_normal = pe_normal._port_list()
    # Check that it contains all system ports 1-1024
    for p in range(1, 1025):
        assert p in ports_normal
    # Check that it contains curated ports above 1024 like OPC-UA (4840), BACnet (47808), EtherNet/IP (44818)
    assert 4840 in ports_normal
    assert 47808 in ports_normal
    assert 44818 in ports_normal
    assert 20000 in ports_normal
    # Check database/IT ports above 1024
    assert 1433 in ports_normal
    assert 3306 in ports_normal
    assert 5432 in ports_normal
    assert 3389 in ports_normal  # RDP
