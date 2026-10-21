"""
Progress and cancellation, observed at the orchestrator boundary.

The scan engines report progress (Redis frames for the live view, counters in
``scans.options`` for the REST endpoint) and stop when the user cancels. Until
B2 they did both themselves, through ``core.redis_client`` and
``core.scan_control``; since B2 the orchestrator hands them a ``ProgressSink``
and a ``CancelToken`` (``core.engine_ports``) and keeps those implementations.

These tests drive the orchestrator's three phase methods with a scan id and
record what reaches the outside world: every Redis progress frame, every write
to the progress counters and every read of the scan's status. They use only the
orchestrator's own interface and the lowest-level functions it ends up calling,
so they hold the same behaviour before and after the change — they were run
against the parent commit first (docs/architecture/MODULAR_REFACTORING_LOG.md).

Nothing here touches the network or a database: the probes, nmap and the
plugins are replaced, and so are the status read and the progress writes.
"""

import pytest

import core.discovery.engine as discovery_engine_module
import engines.port.port_engine as port_engine_module
import orchestrator.scan_orchestrator as orchestrator_module
from core.scan_control import ScanCancelled
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine

SCAN_ID = "scan-characterisation-0001"
ACTIVE = {"198.51.100.1"}


@pytest.fixture
def world(monkeypatch):
    """Replace every edge the scan path has to the outside, and record it."""
    record = {
        "frames": [],  # (scan_id, phase, progress) as published to Redis
        "init": [],  # (scan_id, total_ips) written to scans.options
        "update": [],  # (scan_id, discovered, active)
        "status_reads": 0,
        "probed_batches": [],
        "statuses": [],  # what read_status answers, in order; then "running"
    }

    async def publish_progress(scan_id, phase, progress):
        record["frames"].append((scan_id, phase, progress))

    def publish_progress_sync(scan_id, phase, progress):
        record["frames"].append((scan_id, phase, progress))

    def read_status(scan_id):
        record["status_reads"] += 1
        return record["statuses"].pop(0) if record["statuses"] else "running"

    def init_progress(db, scan_id, total_ips):
        record["init"].append((scan_id, total_ips))

    def update_progress(db, scan_id, discovered, active=None):
        record["update"].append((scan_id, discovered, active))

    async def probe_batch(self, batch, results):
        record["probed_batches"].append(list(batch))
        for ip in batch:
            if ip in ACTIVE:
                results[ip].update(
                    is_active=True, method="ARP", mac="02:00:00:00:00:01"
                )

    async def no_enrichment(self, active_ips, results):
        return None

    import core.redis_client as redis_client
    import core.scan_control as scan_control
    import scans.progress as scans_progress

    monkeypatch.setattr(redis_client, "publish_progress", publish_progress)
    monkeypatch.setattr(redis_client, "publish_progress_sync", publish_progress_sync)
    monkeypatch.setattr(scan_control, "read_status", read_status)
    monkeypatch.setattr(scans_progress, "init_progress", init_progress)
    monkeypatch.setattr(scans_progress, "update_progress", update_progress)
    monkeypatch.setattr(
        discovery_engine_module.DiscoveryEngine, "_probe_batch", probe_batch
    )
    monkeypatch.setattr(
        discovery_engine_module.DiscoveryEngine, "_enrich_active", no_enrichment
    )
    monkeypatch.setattr(
        orchestrator_module.PrivilegeManager, "is_admin", staticmethod(lambda: False)
    )
    return record


@pytest.fixture
def orch(world):
    return orchestrator_module.ScanOrchestrator()


def _phase(record, phase):
    return [progress for _, p, progress in record["frames"] if p == phase]


# ── Phase 1: discovery ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_discovery_publishes_and_persists_progress_for_a_scan(orch, world):
    result = await orch.run_host_discovery_only(
        ["198.51.100.1", "198.51.100.2"], pipeline_mode="basic", scan_id=SCAN_ID
    )

    assert result["success"] is True
    assert {scan_id for scan_id, _, _ in world["frames"]} == {SCAN_ID}
    frames = _phase(world, 1)
    # One frame when the batch completes, one after enrichment.
    assert [f["status"] for f in frames] == ["running", "enriching"]
    for frame in frames:
        assert (frame["discovered"], frame["active"], frame["total_ips"]) == (2, 1, 2)
        assert [h["ip_address"] for h in frame["hosts"]] == ["198.51.100.1"]
        assert frame["hosts"][0]["mac_address"] == "02:00:00:00:00:01"
    # The REST progress endpoint's counters: the total at the start, then the
    # count after each batch.
    assert world["init"] == [(SCAN_ID, 2)]
    assert world["update"] == [(SCAN_ID, 2, 1)]
    # Status read once before probing, once before and once after the batch,
    # and once before enrichment.
    assert world["status_reads"] == 4


@pytest.mark.asyncio
async def test_discovery_without_a_scan_reports_nothing_and_reads_no_status(
    orch, world
):
    result = await orch.run_host_discovery_only(
        ["198.51.100.1", "198.51.100.2"], pipeline_mode="basic", scan_id=None
    )

    assert result["success"] is True
    assert world["frames"] == []
    assert world["init"] == [] and world["update"] == []
    assert world["status_reads"] == 0


@pytest.mark.asyncio
async def test_a_scan_cancelled_before_discovery_probes_nothing(orch, world):
    world["statuses"] = ["cancelled"]

    with pytest.raises(ScanCancelled) as raised:
        await orch.run_host_discovery_only(
            ["198.51.100.1", "198.51.100.2"], pipeline_mode="basic", scan_id=SCAN_ID
        )

    assert raised.value.scan_id == SCAN_ID
    assert world["probed_batches"] == []
    assert world["frames"] == [] and world["init"] == []


@pytest.mark.asyncio
async def test_a_cancel_during_the_batch_stops_before_its_results_are_reported(
    orch, world
):
    # Read 1 before probing, read 2 before the batch, read 3 after it.
    world["statuses"] = ["running", "running", "cancelled"]

    with pytest.raises(ScanCancelled):
        await orch.run_host_discovery_only(
            ["198.51.100.1", "198.51.100.2"], pipeline_mode="basic", scan_id=SCAN_ID
        )

    assert len(world["probed_batches"]) == 1
    assert world["init"] == [(SCAN_ID, 2)]
    assert world["frames"] == [] and world["update"] == []


@pytest.mark.asyncio
async def test_a_cancel_between_batches_stops_before_the_next_one(orch, world):
    # 254 addresses run as two batches of 128 and 126. Reads 1-3 cover the
    # start and the first batch; the check before the second batch sees the
    # cancellation and confirms it.
    world["statuses"] = ["running"] * 3 + ["cancelled"] * 2

    with pytest.raises(ScanCancelled):
        await orch.run_host_discovery_only(
            ["198.51.100.0/24"], pipeline_mode="basic", scan_id=SCAN_ID
        )

    assert [len(batch) for batch in world["probed_batches"]] == [128]
    assert world["init"] == [(SCAN_ID, 254)]
    assert world["update"] == [(SCAN_ID, 128, 1)]
    assert [f["status"] for f in _phase(world, 1)] == ["running"]
    assert world["status_reads"] == 5


@pytest.mark.asyncio
async def test_a_status_that_cannot_be_read_never_cancels_a_scan(
    orch, world, monkeypatch
):
    import core.scan_control as scan_control

    def unreadable(scan_id):
        world["status_reads"] += 1
        return None  # what read_status returns when the database is unreachable

    monkeypatch.setattr(scan_control, "read_status", unreadable)

    result = await orch.run_host_discovery_only(
        ["198.51.100.1"], pipeline_mode="basic", scan_id=SCAN_ID
    )

    assert result["success"] is True
    assert len(world["probed_batches"]) == 1


# ── Phase 2: ports ───────────────────────────────────────────────────────────


@pytest.fixture
def no_nmap(monkeypatch):
    def scan_hosts(self, ips, **kwargs):
        return {}

    async def nothing(hosts, **kwargs):
        return None

    monkeypatch.setattr(port_engine_module, "NMAP_AVAILABLE", True)
    monkeypatch.setattr(port_engine_module.NmapScanner, "scan_hosts", scan_hosts)
    # The SNMP and OT enrichment after the port scan (the orchestrator's since B8).
    monkeypatch.setattr(orchestrator_module, "enrich_after_port_scan", nothing)
    monkeypatch.setattr(
        orchestrator_module.ScanOrchestrator,
        "_apply_os_inference",
        staticmethod(lambda hosts, ot_enrichment=False: None),
    )


def _active_host(ip="198.51.100.1"):
    return {"ip": ip, "ip_address": ip, "is_active": True, "open_ports": []}


@pytest.mark.asyncio
async def test_the_port_phase_publishes_its_start_and_its_end(orch, world, no_nmap):
    await orch.run_asset_discovery_only(
        [_active_host(), _active_host("198.51.100.2")],
        intensity="normal",
        scan_id=SCAN_ID,
    )

    assert _phase(world, 2) == [
        {"total_hosts": 2, "status": "running"},
        {"scanned_hosts": 2, "total_hosts": 2, "status": "running"},
    ]
    assert world["status_reads"] == 0  # the port phase does not poll for cancellation


@pytest.mark.asyncio
async def test_the_port_phase_without_a_scan_publishes_nothing(orch, world, no_nmap):
    await orch.run_asset_discovery_only([_active_host()], scan_id=None)
    assert world["frames"] == []


# ── Phase 3: network checks ──────────────────────────────────────────────────


@pytest.fixture
def no_plugins(monkeypatch):
    monkeypatch.setattr(
        orchestrator_module.ScanOrchestrator,
        "_nmap_pre_enrich",
        staticmethod(lambda hosts, exclude_ot_from_nmap=True: None),
    )
    monkeypatch.setattr(
        orchestrator_module.ScanOrchestrator,
        "_apply_os_inference",
        staticmethod(lambda hosts, ot_enrichment=False: None),
    )
    for name in ("_run_plugins", "_verify_host", "_score_host"):
        monkeypatch.setattr(VulnerabilityEngine, name, lambda self, host: None)


def test_the_check_phase_publishes_once_per_host(orch, world, no_plugins):
    hosts = [_active_host(f"198.51.100.{n}") for n in (1, 2, 3)]
    orch.run_vulnerability_audit_only(hosts, scan_id=SCAN_ID)

    frames = _phase(world, 3)
    assert frames[0] == {"scanned_hosts": 0, "total_hosts": 3, "status": "running"}
    # The hosts are checked in parallel, so the per-host frames can arrive in
    # any order; there is exactly one per host.
    assert sorted(f["scanned_hosts"] for f in frames[1:]) == [1, 2, 3]
    assert all(f == {**f, "total_hosts": 3, "status": "running"} for f in frames)
    assert world["status_reads"] == 0


def test_the_check_phase_without_a_scan_publishes_nothing(orch, world, no_plugins):
    orch.run_vulnerability_audit_only([_active_host()], scan_id=None)
    assert world["frames"] == []
