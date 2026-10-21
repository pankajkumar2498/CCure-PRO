"""
B2: the scan engines take a ProgressSink and a CancelToken (core.engine_ports)
instead of reaching the scan record and the message broker themselves.

``test_engine_progress_and_cancellation.py`` holds the behaviour at the
orchestrator boundary and passed unchanged before and after the change. This
file holds what changed: the engines run with any sink and token a caller hands
them, raise the caller's own cancellation, and do not import or load the
orchestration modules; and the scans capability's implementations do exactly
what the functions they wrap did.
"""

import asyncio
import json
import subprocess
import sys

import pytest

import core.scan_control as scan_control
from core.engine_ports import NEVER_CANCELLED
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

ENGINES = (
    "core.discovery.engine",
    "engines.port.port_engine",
    "engines.vulnerability.vulnerability_engine",
)
ORCHESTRATION = ("core.scan_control", "core.redis_client")


class RecordingSink:
    def __init__(self):
        self.events = []

    def start(self, total):
        self.events.append(("start", total))

    async def publish(self, phase, progress):
        self.events.append(("publish", phase, progress))

    def publish_sync(self, phase, progress):
        self.events.append(("publish_sync", phase, progress))

    def record(self, done, active=None):
        self.events.append(("record", done, active))


class StopAfter:
    """A token that reports cancellation from its nth check on, with its own exception."""

    class Stopped(Exception):
        pass

    def __init__(self, checks_before_stop):
        self.remaining = checks_before_stop
        self.checks = 0

    def _cancelled(self):
        self.checks += 1
        return self.checks > self.remaining

    def is_cancelled(self):
        return self._cancelled()

    def raise_if_cancelled(self):
        if self._cancelled():
            raise StopAfter.Stopped()


# ── The engines' own dependencies ────────────────────────────────────────────


def test_no_engine_imports_the_scan_record_or_the_broker():
    """Lazy imports count: they are how this codebase hid its couplings."""
    _, edges = collect_edges()
    found = sorted(
        (e.src, e.dst) for e in edges if e.src in ENGINES and e.dst in ORCHESTRATION
    )
    assert found == []


def test_the_web_scanner_does_not_import_the_network_scan_control():
    _, edges = collect_edges()
    found = sorted(
        (e.src, e.dst)
        for e in edges
        if e.src.startswith("core.web.") and e.dst == "core.scan_control"
    )
    assert found == []


_RUN_ENGINES = r"""
import asyncio, json, sys
import core.discovery.engine as de
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine

class Sink:
    def start(self, total): pass
    async def publish(self, phase, progress): pass
    def publish_sync(self, phase, progress): pass
    def record(self, done, active=None): pass

async def probe(self, batch, results):
    for ip in batch:
        results[ip]["is_active"] = True

async def nothing(self, *args, **kwargs):
    return None

de.DiscoveryEngine._probe_batch = probe
de.DiscoveryEngine._enrich_active = nothing
for name in ("_run_plugins", "_verify_host", "_score_host"):
    setattr(VulnerabilityEngine, name, lambda self, host: None)

watched = ("core.scan_control", "core.redis_client", "db.models.scans")
loaded = {}
hosts = asyncio.run(de.DiscoveryEngine().run(["198.51.100.1"], progress=Sink()))
loaded["discovery"] = {m: m in sys.modules for m in watched}
VulnerabilityEngine().run(hosts, progress=Sink())
loaded["discovery+checks"] = {m: m in sys.modules for m in watched}

# Imported last: its module loads core.redis_client through core.nmap.wrapper.
import engines.port.port_engine as pe
pe.NMAP_AVAILABLE = True
pe.NmapScanner.scan_hosts = lambda self, ips, **kw: {}
asyncio.run(pe.PortEngine().run(hosts, progress=Sink()))
loaded["all three"] = {m: m in sys.modules for m in watched}
print(json.dumps(loaded))
"""


def test_running_the_engines_loads_neither_the_scan_record_nor_its_control():
    """
    Measured by running them, not by reading imports: a fresh interpreter runs
    discovery, the network checks and the port scan with a sink of its own and
    no orchestrator. Before B2 discovery imported core.scan_control (and through
    it the Scan model) the moment it ran.
    """
    done = subprocess.run(
        [sys.executable, "-c", _RUN_ENGINES],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    loaded = json.loads(done.stdout.strip().splitlines()[-1])
    for stage in loaded.values():
        assert stage["core.scan_control"] is False
        assert stage["db.models.scans"] is False
    # Discovery and the network checks need no broker. The port scan does,
    # through the nmap process lease (core.nmap.wrapper) — the Lease port,
    # which is not B2's.
    assert loaded["discovery+checks"]["core.redis_client"] is False


# ── The engines with a caller's own sink and token ───────────────────────────


@pytest.fixture
def quiet_discovery(monkeypatch):
    import core.discovery.engine as de

    probed = []

    async def probe(self, batch, results):
        probed.append(list(batch))
        for ip in batch:
            if ip.endswith(".1"):
                results[ip]["is_active"] = True

    async def nothing(self, *args, **kwargs):
        return None

    monkeypatch.setattr(de.DiscoveryEngine, "_probe_batch", probe)
    monkeypatch.setattr(de.DiscoveryEngine, "_enrich_active", nothing)
    return de.DiscoveryEngine, probed


def test_discovery_reports_through_the_sink_it_is_given(quiet_discovery):
    engine_cls, probed = quiet_discovery
    sink = RecordingSink()
    asyncio.run(engine_cls().run(["198.51.100.1", "198.51.100.2"], progress=sink))

    kinds = [event[0] for event in sink.events]
    assert kinds == ["start", "publish", "record", "publish"]
    assert sink.events[0] == ("start", 2)
    assert sink.events[2] == ("record", 2, 1)
    assert [e[2]["status"] for e in sink.events if e[0] == "publish"] == [
        "running",
        "enriching",
    ]


def test_discovery_raises_the_callers_own_cancellation(quiet_discovery):
    """The engine does not know the runner's exception type; the token raises it."""
    engine_cls, probed = quiet_discovery
    token = StopAfter(checks_before_stop=1)  # passes the start, stops at the batch

    with pytest.raises(StopAfter.Stopped):
        asyncio.run(engine_cls().run(["198.51.100.1"], cancel=token))
    assert probed == []


def test_discovery_without_a_sink_or_token_still_runs(quiet_discovery):
    engine_cls, probed = quiet_discovery
    hosts = asyncio.run(engine_cls().run(["198.51.100.1", "198.51.100.2"]))
    assert [h["is_active"] for h in hosts] == [True, False]
    assert len(probed) == 1


def test_the_port_engine_reports_through_the_sink_it_is_given(monkeypatch):
    import engines.port.port_engine as pe

    monkeypatch.setattr(pe, "NMAP_AVAILABLE", True)
    monkeypatch.setattr(pe.NmapScanner, "scan_hosts", lambda self, ips, **kw: {})

    sink = RecordingSink()
    hosts = [{"ip": "198.51.100.1", "ip_address": "198.51.100.1", "is_active": True}]
    asyncio.run(pe.PortEngine().run(hosts, progress=sink))
    assert sink.events == [
        ("publish", 2, {"total_hosts": 1, "status": "running"}),
        ("publish", 2, {"scanned_hosts": 1, "total_hosts": 1, "status": "running"}),
    ]


def test_the_check_engine_reports_from_its_threads_through_the_sink(monkeypatch):
    from engines.vulnerability.vulnerability_engine import VulnerabilityEngine

    for name in ("_run_plugins", "_verify_host", "_score_host"):
        monkeypatch.setattr(VulnerabilityEngine, name, lambda self, host: None)
    sink = RecordingSink()
    hosts = [
        {"ip": f"198.51.100.{n}", "ip_address": f"198.51.100.{n}", "is_active": True}
        for n in (1, 2)
    ]
    VulnerabilityEngine().run(hosts, progress=sink)
    assert [e[0] for e in sink.events] == ["publish_sync"] * 3
    assert sorted(e[2]["scanned_hosts"] for e in sink.events) == [0, 1, 2]


# ── The scans capability's implementations ───────────────────────────────────


def test_no_scan_record_means_no_ports():
    assert scan_control.engine_ports(None) == (None, None)
    assert scan_control.engine_ports("") == (None, None)


def test_the_never_cancelled_token():
    assert NEVER_CANCELLED.is_cancelled() is False
    assert NEVER_CANCELLED.raise_if_cancelled() is None


def test_the_scan_token_reads_the_status_and_raises_scan_cancelled(monkeypatch):
    statuses = iter(["running", "cancelling", "cancelled"])
    monkeypatch.setattr(scan_control, "read_status", lambda scan_id: next(statuses))
    _, token = scan_control.engine_ports("scan-1")

    assert token.is_cancelled() is False
    assert token.is_cancelled() is True  # "cancelling" asks the scan to stop too
    with pytest.raises(scan_control.ScanCancelled) as raised:
        token.raise_if_cancelled()
    assert raised.value.scan_id == "scan-1"
    assert repr(token) == "scan scan-1"


def test_the_scan_token_never_raises_on_a_failed_read(monkeypatch):
    def broken(scan_id):
        raise RuntimeError("database gone")

    monkeypatch.setattr(scan_control, "is_cancelled", broken)
    _, token = scan_control.engine_ports("scan-1")
    assert token.is_cancelled() is False


def test_the_scan_sink_writes_where_the_engines_used_to(monkeypatch):
    import core.redis_client as redis_client
    import scans.progress as scans_progress

    seen = []

    async def publish_progress(scan_id, phase, progress):
        seen.append(("redis", scan_id, phase, progress))

    def publish_progress_sync(scan_id, phase, progress):
        seen.append(("redis-sync", scan_id, phase, progress))

    monkeypatch.setattr(redis_client, "publish_progress", publish_progress)
    monkeypatch.setattr(redis_client, "publish_progress_sync", publish_progress_sync)
    monkeypatch.setattr(
        scans_progress,
        "init_progress",
        lambda db, scan_id, total_ips: seen.append(("init", scan_id, total_ips)),
    )
    monkeypatch.setattr(
        scans_progress,
        "update_progress",
        lambda db, scan_id, discovered, active=None: seen.append(
            ("update", scan_id, discovered, active)
        ),
    )

    sink, _ = scan_control.engine_ports("scan-1")
    sink.start(10)
    asyncio.run(sink.publish(1, {"status": "running"}))
    sink.publish_sync(3, {"scanned_hosts": 1})
    sink.record(5, 2)

    assert seen == [
        ("init", "scan-1", 10),
        ("redis", "scan-1", 1, {"status": "running"}),
        ("redis-sync", "scan-1", 3, {"scanned_hosts": 1}),
        ("update", "scan-1", 5, 2),
    ]
