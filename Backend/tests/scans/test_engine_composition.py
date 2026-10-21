"""
B8a: the port and discovery engines import no sibling engine.

The port engine ended every run with a lightweight SNMP query and the OT
identity probes (discovery enrichment's) and device classification (the asset
registry's); discovery's SNMP probe imported the network checks' SNMP client.
The orchestrator now composes both (``orchestrator/host_enrichment.py``): it
runs the post-scan enrichment after the port engine, and hands every discovery
engine it builds the SNMP read (``snmp_query``).

These pin the purpose (no such import, statically or at run time), that the
orchestrator does the composing everywhere it builds an engine, and the moved
behaviour itself. The byte-identical golden capture of the orchestrator's port
and discovery phases is recorded in the refactoring log (§6).
"""

import ast
import asyncio
import json
import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock

import core.discovery.enrichment as enrichment
import orchestrator.host_enrichment as host_enrichment
import orchestrator.scan_orchestrator as orchestrator_module
import pytest
from core.discovery.engine import DiscoveryEngine
from core.discovery.profiles import AGGRESSIVE
from engines.vulnerability.plugins import snmp_probe as sp
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges, discover_modules
from testpaths import BACKEND_ROOT

# ── An SNMP agent and OT probes with no network ──────────────────────────────


def _response(oid, tag, value=b""):
    varbind = sp._tlv(0x30, sp._tlv(0x06, sp._encode_oid(oid)) + sp._tlv(tag, value))
    pdu = sp._tlv(
        0xA2,
        sp._tlv(0x02, sp._encode_integer(1))
        + sp._tlv(0x02, b"\x00")
        + sp._tlv(0x02, b"\x00")
        + sp._tlv(0x30, varbind),
    )
    return sp._tlv(0x30, sp._tlv(0x02, b"\x01") + sp._tlv(0x04, b"public") + pdu)


LINUX_AGENT = {
    sp._OID_SYS_OBJ_ID: (0x06, sp._encode_oid("1.3.6.1.4.1.8072.3.2.10")),
    sp._OID_SYS_DESCR: (0x04, b"Linux web01 6.8.0-137-generic #147-Ubuntu SMP x86_64"),
    sp._OID_SYS_NAME: (0x04, b"web01"),
    sp._OID_IP_FORWARD: (0x02, sp._encode_integer(2)),
    sp._OID_IF_NUMBER: (0x02, sp._encode_integer(3)),
}


@pytest.fixture
def network(monkeypatch):
    """Agents keyed by address; every SNMP request and OT probe is recorded."""
    world = {"agents": {}, "snmp": [], "ot": [], "ot_answers": {}}

    def snmp_get(ip, community, oid, timeout=2.0):
        world["snmp"].append((ip, oid))
        agent = world["agents"].get(ip, {})
        if oid not in agent:
            return None
        tag, value = agent[oid]
        return _response(oid, tag, value)

    def ot_probes(ip, result):
        world["ot"].append(ip)
        if ip in world["ot_answers"]:
            result["ot_info"] = dict(world["ot_answers"][ip])

    monkeypatch.setattr(sp, "_snmp_get_raw", snmp_get)
    monkeypatch.setattr(enrichment, "_ot_protocol_probes", ot_probes)
    for name in (
        "_ptr_lookup",
        "_netbios_query",
        "_mdns_query",
        "_mdns_service_query",
        "_os_probe_full",
    ):
        monkeypatch.setattr(enrichment, name, lambda ip, result: None)
    return world


# ── The purpose ──────────────────────────────────────────────────────────────


def test_the_port_and_discovery_engines_import_no_sibling_engine():
    """Lazy imports count; they are how the codebase hid its couplings."""
    _, edges = collect_edges()
    cap = capability_map.capability_of
    layer = {name: spec[0] for name, spec in capability_map.CAPABILITIES.items()}
    sideways = sorted(
        (e.src, e.dst)
        for e in edges
        if cap(e.src) in ("port_inventory", "discovery")
        and cap(e.dst) != cap(e.src)
        and layer[cap(e.dst)] == layer[cap(e.src)]
    )
    assert sideways == []
    # The port engine also reached up into the asset registry's classifier.
    upward = sorted(
        (e.src, e.dst)
        for e in edges
        if cap(e.src) == "port_inventory"
        and layer[cap(e.dst)] > layer["port_inventory"]
    )
    assert upward == []


_RUN = r"""
import asyncio, json, sys
import engines.port.port_engine as pe

class Sink:
    def start(self, total): pass
    async def publish(self, phase, progress): pass
    def publish_sync(self, phase, progress): pass
    def record(self, done, active=None): pass

pe.NMAP_AVAILABLE = True
pe.NmapScanner.scan_hosts = lambda self, ips, **kw: {}
hosts = [{"ip": "198.51.100.1", "ip_address": "198.51.100.1", "is_active": True,
          "open_ports": [{"port": 502}], "port_states": {161: "open"}}]
asyncio.run(pe.PortEngine(exclude_ot_from_nmap=False).run(hosts, progress=Sink()))
print(json.dumps(sorted(
    m for m in sys.modules
    if m.startswith("core.discovery") or m.startswith("engines.vulnerability")
    or m == "core.device_classifier"
)))
"""


def test_running_the_port_engine_loads_no_discovery_classifier_or_snmp_client():
    """Measured by running it on a host with SNMP and an OT port open."""
    done = subprocess.run(
        [sys.executable, "-c", _RUN],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={"SKIP_DOTENV_LOAD": "1", "PATH": "/usr/bin:/bin"},
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == []


# ── The orchestrator composes, everywhere it builds an engine ────────────────


def _calls_named(tree, name):
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == name)
            or (isinstance(node.func, ast.Attribute) and node.func.attr == name)
        )
    ]


def test_every_discovery_engine_in_production_code_gets_the_snmp_read():
    """A discovery engine built without one makes no SNMP request at all."""
    sites = []
    for module, path in discover_modules().items():
        if module.split(".")[0] in ("tests", "scripts", "alembic"):
            continue
        for call in _calls_named(ast.parse(path.read_text()), "DiscoveryEngine"):
            given = {k.arg: k.value for k in call.keywords}
            value = given.get("snmp_query")
            sites.append(
                (
                    module,
                    call.lineno,
                    getattr(value, "id", None) if value is not None else None,
                )
            )
    assert sites, "no production code builds a DiscoveryEngine any more"
    assert {name for _, _, name in sites} == {"snmp_system_query"}, sites
    assert {module for module, _, _ in sites} == {"orchestrator.scan_orchestrator"}


@pytest.mark.parametrize("exclude_ot", [True, False])
def test_the_orchestrator_enriches_after_the_port_engine_on_its_hosts(
    monkeypatch, exclude_ot
):
    order = []

    engine = MagicMock()

    async def run(hosts, progress=None):
        order.append(("ports", [h["ip_address"] for h in hosts]))

    engine.run = run
    monkeypatch.setattr(orchestrator_module, "PortEngine", lambda **kw: engine)

    async def enrich(hosts, *, exclude_ot_from_nmap):
        order.append(("enrich", [h["ip_address"] for h in hosts], exclude_ot_from_nmap))

    monkeypatch.setattr(orchestrator_module, "enrich_after_port_scan", enrich)
    monkeypatch.setattr(
        orchestrator_module.ScanOrchestrator,
        "_apply_os_inference",
        staticmethod(
            lambda hosts, ot_enrichment=False: order.append(
                ("inference", [h["ip_address"] for h in hosts], ot_enrichment)
            )
        ),
    )
    hosts = [
        {"ip": ip, "ip_address": ip, "is_active": active, "open_ports": []}
        for ip, active in (("198.51.100.1", True), ("198.51.100.2", False))
    ]
    asyncio.run(
        orchestrator_module.ScanOrchestrator().run_asset_discovery_only(
            hosts=hosts, os_detection=False, exclude_ot_from_nmap=exclude_ot
        )
    )
    assert order == [
        ("ports", ["198.51.100.1"]),
        ("enrich", ["198.51.100.1"], exclude_ot),
        ("inference", ["198.51.100.1"], True),
    ]


# ── Discovery uses the read it is given, and only that ───────────────────────


def _aggressive_results(ip):
    return {ip: {"ip": ip, "is_active": True, "port_states": {}, "open_ports": []}}


def test_discovery_asks_through_the_read_it_was_given(network):
    network["agents"]["10.0.0.1"] = LINUX_AGENT
    results = _aggressive_results("10.0.0.1")
    engine = DiscoveryEngine(
        profile=AGGRESSIVE, snmp_query=host_enrichment.snmp_system_query
    )
    asyncio.run(engine._enrich_active(["10.0.0.1"], results))

    host = results["10.0.0.1"]
    assert host["snmp_info"]["sys_name"] == "web01"
    assert host["snmp_info"]["enterprise_id"] == 8072
    assert host["os_evidence"] == "snmp_sysdescr"
    assert host["snmp_sys_name"] == "web01"
    assert [p["port"] for p in host["open_ports"]] == [161]
    assert network["snmp"][0] == ("10.0.0.1", sp._OID_SYS_OBJ_ID)


def test_a_discovery_engine_given_no_read_makes_no_snmp_request(network):
    network["agents"]["10.0.0.1"] = LINUX_AGENT
    results = _aggressive_results("10.0.0.1")
    asyncio.run(
        DiscoveryEngine(profile=AGGRESSIVE)._enrich_active(["10.0.0.1"], results)
    )
    assert network["snmp"] == []
    assert "snmp_info" not in results["10.0.0.1"]
    assert network["ot"] == ["10.0.0.1"]  # the other deep probes still ran


def test_a_read_that_raises_or_finds_no_agent_leaves_the_host_alone(network):
    def broken(ip):
        raise OSError("agent went away")

    for query in (broken, host_enrichment.snmp_system_query):
        result = {"port_states": {}, "open_ports": []}
        enrichment._snmp_lightweight_probe("10.0.0.2", result, query)
        assert result == {"port_states": {}, "open_ports": []}


def test_the_read_asks_for_nothing_more_once_sysobjectid_is_silent(network):
    assert host_enrichment.snmp_system_query("10.0.0.3") is None
    assert network["snmp"] == [("10.0.0.3", sp._OID_SYS_OBJ_ID)]


# ── The enrichment after the port scan, as the port engine ran it ────────────


def _host(ip, **fields):
    return {"ip": ip, "ip_address": ip, "is_active": True, "open_ports": [], **fields}


def test_the_snmp_query_after_the_port_scan_skips_only_a_closed_161(network):
    network["agents"]["10.0.0.1"] = LINUX_AGENT
    hosts = [
        _host("10.0.0.1", open_ports=[{"port": 161}]),
        _host("10.0.0.2", port_states={161: "closed"}),
        _host("10.0.0.3", port_states={"161": "closed"}),
        _host("10.0.0.4"),
        _host("10.0.0.5", is_active=False),
    ]
    asyncio.run(
        host_enrichment.enrich_after_port_scan(hosts, exclude_ot_from_nmap=False)
    )
    asked = sorted({ip for ip, _ in network["snmp"]})
    assert asked == ["10.0.0.1", "10.0.0.4"]
    assert hosts[0]["snmp_info"]["sys_descr"].startswith("Linux web01")
    assert "snmp_info" not in hosts[3]


@pytest.mark.parametrize(
    "exclude_ot, probed",
    [
        (True, ["10.0.0.1", "10.0.0.2"]),  # nmap kept off the OT ports: probe all
        (False, ["10.0.0.2"]),  # nmap scanned them: only where one is open
    ],
)
def test_the_ot_probes_after_the_port_scan(network, exclude_ot, probed):
    network["ot_answers"]["10.0.0.2"] = {
        "protocol": "Modbus/TCP",
        "vendor": "Schneider Electric",
        "model": "BMX P34 2020",
    }
    hosts = [
        _host("10.0.0.1", port_states={161: "closed"}),
        _host("10.0.0.2", open_ports=[{"port": 502}], port_states={161: "closed"}),
        _host("10.0.0.3", ot_info={"protocol": "already"}, port_states={161: "closed"}),
    ]
    asyncio.run(
        host_enrichment.enrich_after_port_scan(hosts, exclude_ot_from_nmap=exclude_ot)
    )
    assert sorted(network["ot"]) == probed
    assert hosts[1]["port_states"][502] == "open"
    assert hosts[1]["device_category"] == "scada_ics"  # classified after the probe
    assert hosts[1]["vendor"] == "Schneider Electric"
    assert "device_category" not in hosts[2]  # already identified: left alone


def test_an_ot_probe_failure_is_contained_to_its_host(network, monkeypatch):
    def failing(ip, result):
        network["ot"].append(ip)
        if ip == "10.0.0.1":
            raise RuntimeError("probe failed")
        result["ot_info"] = {"protocol": "BACnet/IP"}

    monkeypatch.setattr(enrichment, "_ot_protocol_probes", failing)
    hosts = [_host(ip, port_states={161: "closed"}) for ip in ("10.0.0.1", "10.0.0.2")]
    asyncio.run(
        host_enrichment.enrich_after_port_scan(hosts, exclude_ot_from_nmap=True)
    )
    assert "ot_info" not in hosts[0]
    assert hosts[1]["device_category"] == "scada_ics"


def test_nothing_is_asked_of_an_empty_or_inactive_host_list(network):
    for hosts in ([], [_host("10.0.0.1", is_active=False)]):
        asyncio.run(
            host_enrichment.enrich_after_port_scan(hosts, exclude_ot_from_nmap=True)
        )
    assert network["snmp"] == [] and network["ot"] == []
