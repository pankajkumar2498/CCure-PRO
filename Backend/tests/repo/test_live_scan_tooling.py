"""
The live scan validation tooling in scripts/validation/
(docs/ci/LIVE_SCAN_VALIDATION.md).

Phase B steps on a scan path are validated by scanning disposable targets with
the code before and after the change and comparing what the scans stored. The
scans themselves need Docker and raw sockets and are run by hand; these tests
hold the parts that can be checked without them, and that would otherwise
drift silently:

* the target definition stays isolated: an internal private subnet that
  overlaps nothing this installation uses, the host's own bridge address never
  a target, every image pinned by digest;
* every target keeps the same MAC address however often it is re-created, and
  ``targets.sh up`` replaces a target holding any other;
* the harness dispatches a scan with exactly the keyword arguments the
  host-discovery route uses, and stops one the way the stop route does;
* the harness's queries run against the real schema (B2's first run queried a
  column that does not exist);
* the comparison names every difference except time.
"""

import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
import uuid

import pytest
from testpaths import BACKEND_ROOT, REPO_ROOT

VALIDATION = REPO_ROOT / "scripts" / "validation"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, VALIDATION / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _targets_env() -> dict:
    values = {}
    for raw in (VALIDATION / "targets.env").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, rest = line.partition("=")
        match = re.match(r'"([^"]*)"', rest)
        values[key] = match.group(1) if match else rest.split("#")[0].strip()
    return values


# ── The targets ──────────────────────────────────────────────────────────────

#: Networks this installation already uses (docs: CLAUDE.md "Deployment: Linux
#: VM"): Docker's default bridge, the compose network, the gateway network, and
#: the VM's own LAN. A validation network overlapping any of them could route a
#: scan somewhere real.
IN_USE = ("172.17.0.0/16", "172.18.0.0/16", "172.31.254.0/24", "10.180.20.0/22")


def test_the_target_network_is_private_and_overlaps_nothing_in_use():
    env = _targets_env()
    subnet = ipaddress.ip_network(env["VALIDATION_SUBNET"])
    assert subnet.is_private and subnet.prefixlen == 24
    for used in IN_USE:
        assert not subnet.overlaps(ipaddress.ip_network(used)), used


def test_every_target_is_inside_it_and_none_is_the_host():
    env = _targets_env()
    subnet = ipaddress.ip_network(env["VALIDATION_SUBNET"])
    host = ipaddress.ip_address(env["VALIDATION_HOST_ADDRESS"])
    # Docker gives the host the first address on the bridge.
    assert host == next(subnet.hosts())
    addresses = [
        env[k]
        for k in (
            "VALIDATION_SCANNER_ADDRESS",
            "VALIDATION_PROBE_ADDRESS",
            "SSH_TARGET",
            "WEB_TARGET",
            "REDIS_TARGET",
            "PG_TARGET",
        )
    ] + env["EMPTY_ADDRESSES"].split()
    assert len(addresses) == len(set(addresses))
    for address in map(ipaddress.ip_address, addresses):
        assert address in subnet and address != host


def test_every_image_is_pinned_by_digest():
    env = _targets_env()
    for key in (
        "SSH_BASE_IMAGE",
        "WEB_IMAGE",
        "REDIS_IMAGE",
        "PG_IMAGE",
        "PROBE_IMAGE",
    ):
        assert re.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", env[key]), key


TARGETS = ("SSH", "WEB", "REDIS", "PG")


def _registry_prefixes() -> set[str]:
    """The OUI prefixes the bundled registry (core/oui_lookup.py) knows."""
    prefixes = set()
    for line in (
        (BACKEND_ROOT / "data" / "manuf.txt")
        .read_text(encoding="utf-8", errors="ignore")
        .splitlines()
    ):
        if line and not line.startswith("#"):
            first = line.split("\t", 1)[0].strip()
            prefixes.add(re.sub(r"[^0-9a-f]", "", first.lower())[:6])
    return prefixes


def test_every_target_has_a_fixed_mac_that_is_nobodys():
    """
    Docker picks a random MAC whenever a container is created, so before the
    MACs were fixed every asset's MAC changed with each down and up. A fixed
    MAC must be locally administered and unicast (no vendor's), and absent from
    the bundled registry, so discovery looks it up as it did the random ones.
    """
    env = _targets_env()
    macs = [env[f"{t}_MAC"] for t in TARGETS]
    assert len(set(macs)) == len(macs)
    registry = _registry_prefixes()
    for target in TARGETS:
        mac = env[f"{target}_MAC"]
        assert re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac), mac
        first = int(mac[:2], 16)
        assert first & 0b10 and not first & 0b01, f"{mac} is not local unicast"
        assert mac.replace(":", "")[:6] not in registry, mac
        # Docker's classic form, so the address reads back to its target.
        octets = ipaddress.ip_address(env[f"{target}_TARGET"]).packed
        assert mac == "02:42:" + ":".join(f"{b:02x}" for b in octets), mac


#: A stand-in for the docker CLI: records each call and answers the queries
#: targets.sh makes from a JSON state file of containers.
_FAKE_DOCKER = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
path = os.environ["FAKE_DOCKER_STATE"]
state = json.load(open(path))
def save():
    json.dump(state, open(path, "w"))
def opt(name):
    return args[args.index(name) + 1] if name in args else None
if args[:2] == ["network", "inspect"]:
    print("true" if "-f" in args else "[]")
elif args[0] in ("network", "image", "build", "exec"):
    pass
elif args[:2] == ["container", "inspect"]:
    box = state.get(args[-1])
    if box is None:
        sys.exit(1)
    template = opt("-f") or ""
    if "State.Running" in template:
        print("true")
    elif "State.Status" in template:
        print("running")
    elif "MacAddress" in template:
        print(box["address"])
elif args[0] == "rm":
    state.pop(args[-1], None)
    save()
elif args[0] == "run" and "--rm" not in args:
    state[opt("--name")] = {"address": f"{opt('--ip')} {opt('--mac-address')}"}
    save()
"""


def _run_up(tmp_path, containers: dict) -> tuple[list[list[str]], str, dict]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(_FAKE_DOCKER)
    (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
    for tool in ("docker", "sleep"):
        (bin_dir / tool).chmod(0o755)
    log, state = tmp_path / "calls.jsonl", tmp_path / "state.json"
    log.write_text("")
    state.write_text(json.dumps(containers))
    done = subprocess.run(
        ["bash", str(VALIDATION / "targets.sh"), "up"],
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_DOCKER_LOG": str(log),
            "FAKE_DOCKER_STATE": str(state),
        },
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    return calls, done.stdout, json.loads(state.read_text())


def _defined() -> dict:
    env = _targets_env()
    return {
        env[f"{t}_CONTAINER"]: {"address": f"{env[f'{t}_TARGET']} {env[f'{t}_MAC']}"}
        for t in TARGETS
    }


def test_up_starts_every_target_at_its_address_and_mac(tmp_path):
    calls, _, state = _run_up(tmp_path, {})
    started = [c for c in calls if c[0] == "run" and "--rm" not in c]
    assert len(started) == len(TARGETS)
    assert state == _defined()


def test_up_leaves_targets_holding_their_address_alone(tmp_path):
    calls, out, state = _run_up(tmp_path, _defined())
    assert not [c for c in calls if c[0] == "rm" or (c[0] == "run" and "--rm" not in c)]
    assert "started" not in out and "replacing" not in out
    assert state == _defined()


def test_up_replaces_a_target_holding_another_mac(tmp_path):
    """A target created by hand, or before the MACs were fixed, is replaced."""
    env = _targets_env()
    containers = _defined()
    web = env["WEB_CONTAINER"]
    containers[web] = {"address": f"{env['WEB_TARGET']} 3a:2e:0d:74:a2:00"}
    calls, out, state = _run_up(tmp_path, containers)
    assert ["rm", "-f", web] in calls
    assert [
        c[c.index("--name") + 1] for c in calls if c[0] == "run" and "--rm" not in c
    ] == [web]
    assert f"replacing {web}" in out
    assert state == _defined()


def test_the_scripts_create_only_internal_networks_and_exclude_the_host():
    targets = (VALIDATION / "targets.sh").read_text(encoding="utf-8")
    live = (VALIDATION / "live_scan.sh").read_text(encoding="utf-8")
    for script in (targets, live):
        creates = re.findall(r"docker network create[^\n]*", script)
        assert creates and all("--internal" in c for c in creates)
        # Every container command, continuation lines joined: none publishes a
        # port or uses the host's network.
        joined = script.replace("\\\n", " ")
        containers = re.findall(r"docker (?:run|create)\b[^\n]*", joined)
        assert containers
        for command in containers:
            assert not re.search(
                r"\s(-p|--publish)\s|--network[= ]host|--net[= ]host", command
            ), command
    assert 'CCURE_LIVE_EXCLUDE="$VALIDATION_HOST_ADDRESS"' in live
    # The scanner joins the targets' network first, as the worker's host network
    # would be its first interface (with the database network first, raw
    # discovery finds nothing).
    assert '--network "$VALIDATION_NETWORK" --ip "$VALIDATION_SCANNER_ADDRESS"' in live
    assert 'git -C "$REPO" archive "$COMMIT"' in live


@pytest.mark.parametrize("script", ["targets.sh", "live_scan.sh"])
def test_the_scripts_parse(script):
    done = subprocess.run(
        ["bash", "-n", str(VALIDATION / script)], capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr


# ── The harness ──────────────────────────────────────────────────────────────


def test_importing_the_harness_runs_nothing():
    harness = _load("live_scan_harness")
    assert callable(harness.main)


def test_the_harness_dispatches_with_the_routes_own_arguments():
    """routers/phase_scans.py's run_host_discovery_task.delay(...) keywords."""
    import ast

    harness = _load("live_scan_harness")
    tree = ast.parse((BACKEND_ROOT / "routers" / "phase_scans.py").read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "delay"
        and getattr(node.func.value, "id", None) == "run_host_discovery_task"
    ]
    assert len(calls) == 1
    assert tuple(k.arg for k in calls[0].keywords) == harness.DISPATCH_KWARGS


def test_the_harness_refuses_a_target_list_holding_the_host(monkeypatch):
    harness = _load("live_scan_harness")
    monkeypatch.setenv("CCURE_LIVE_TARGETS", "172.30.250.1,172.30.250.10")
    monkeypatch.setenv("CCURE_LIVE_SWEEP", "172.30.250.0/24")
    monkeypatch.setenv("CCURE_LIVE_EXCLUDE", "172.30.250.1")
    with pytest.raises(SystemExit, match="excluded host address"):
        harness.main("refused")


def test_the_harness_reads_back_against_the_real_schema(db_session):
    from scans.db_helpers import create_scan

    harness = _load("live_scan_harness")
    org_id, user_id = harness.make_identity(f"schema-{uuid.uuid4().hex[:6]}")
    scan = create_scan(
        db=db_session,
        user_id=user_id,
        target="192.0.2.1",
        targets=["192.0.2.1"],
        scan_type="adaptive",
        pipeline_mode="basic",
        org_id=org_id,
    )
    result = harness.stored(str(scan.id), org_id)
    assert set(result) == {"scan", "phases", "assets", "services", "findings"}
    assert result["scan"]["status"] == "running"
    assert result["phases"] == [] and result["findings"] == []


def test_the_harness_stops_a_scan_as_the_stop_route_does(db_session, monkeypatch):
    import core.redis_client as redis_client
    from db.models import Scan
    from scans.db_helpers import create_scan

    frames = []
    monkeypatch.setattr(
        redis_client,
        "publish_progress_sync",
        lambda scan_id, phase, progress: frames.append((scan_id, phase, progress)),
    )
    harness = _load("live_scan_harness")
    org_id, user_id = harness.make_identity(f"stop-{uuid.uuid4().hex[:6]}")
    scan = create_scan(
        db=db_session,
        user_id=user_id,
        target="192.0.2.1",
        targets=["192.0.2.1"],
        scan_type="adaptive",
        pipeline_mode="basic",
        org_id=org_id,
    )
    scan_id = str(scan.id)

    assert harness.stop_like_the_route(scan_id) is True
    db_session.expire_all()
    stopped = db_session.query(Scan).filter(Scan.id == scan_id).one()
    assert stopped.status == "cancelled" and stopped.completed_at is not None
    assert frames == [
        (scan_id, 1, {"status": "cancelled", "reason": "Scan cancelled by user."})
    ]
    # A scan already over is left alone, as the route leaves it.
    assert harness.stop_like_the_route(scan_id) is False


def test_frames_are_reduced_to_one_scan_with_relative_times():
    harness = _load("live_scan_harness")
    frames = [
        {
            "scan_id": "a",
            "phase": 1,
            "progress": {
                "status": "running",
                "hosts": [{"ip_address": "10.0.0.2"}, {"ip_address": "10.0.0.1"}],
            },
            "_t": 10.5,
        },
        {"scan_id": "b", "phase": 1, "progress": {"status": "running"}, "_t": 11.0},
    ]
    assert harness.frame_view(frames, "a", 10.0) == [
        {
            "t": 0.5,
            "phase": 1,
            "status": "running",
            "host_ips": ["10.0.0.1", "10.0.0.2"],
        }
    ]


# ── The comparison ───────────────────────────────────────────────────────────


def _result(findings, frame_t=1.0, elapsed=300.0):
    run = {
        "scan": {
            "status": "complete",
            "duration_seconds": elapsed,
            "progress": {"active": 4, "start_time": f"t{elapsed}"},
        },
        "phases": [{"phase_order": 1, "status": "complete"}],
        "assets": [{"ip_address": "10.0.0.1"}],
        "services": [],
        "findings": findings,
        "task_result": {"success": True},
        "frames": [{"t": frame_t, "phase": 1, "status": "running"}],
        "elapsed_s": elapsed,
    }
    cancel = dict(
        run, stop={"applied": True, "task_returned_s_after_stop": elapsed / 30}
    )
    return {"full": run, "cancel": cancel}


def test_the_comparison_ignores_time_and_names_everything_else(tmp_path):
    compare = _load("compare_live_scans")
    finding = {"ip_address": "10.0.0.1", "vuln_id": "CCURE-CHK-X", "severity": "high"}
    before = _result([finding])
    later = _result([finding], frame_t=7.5, elapsed=330.0)
    assert compare.compare(before, later) == []

    changed = _result([dict(finding, severity="low")])
    lines = compare.compare(before, changed)
    assert len(lines) == 2  # the same finding differs in both runs
    assert all(" findings:" in line for line in lines)

    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(before))
    b.write_text(json.dumps(changed))
    done = subprocess.run(
        [sys.executable, str(VALIDATION / "compare_live_scans.py"), str(a), str(b)],
        capture_output=True,
        text=True,
    )
    assert done.returncode == 1 and "2 difference(s)" in done.stdout
    same = subprocess.run(
        [sys.executable, str(VALIDATION / "compare_live_scans.py"), str(a), str(a)],
        capture_output=True,
        text=True,
    )
    assert same.returncode == 0 and "identical apart from time" in same.stdout
