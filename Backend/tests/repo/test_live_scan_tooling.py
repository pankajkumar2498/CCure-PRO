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
* the harness points Scapy at the targets' network itself, before any scan,
  and refuses when no interface holds the scanner's address;
* the harness's queries run against the real schema (B2's first run queried a
  column that does not exist);
* the comparison names every difference except time, and tolerates only the
  two things B3 measured as timing: discovery's sampled frames and where the
  stop route's frame lands;
* the throwaway credentials of the credentialed runs (T0) are made per run,
  reach no argument, environment or file, are set on the targets in sessions
  that log nothing, and are revoked and confirmed on every exit; the leak check
  finds one planted where it searches;
* the harness stores them through the credential vault, encrypted, dispatches
  the credentialed scans with the credentialed route's own arguments, and
  refuses a run whose credentialed scans did not authenticate;
* the comparison reads the credentialed runs' verdicts and ignores the send
  time their frames carry.
"""

import importlib.util
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import types
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
    elif "Config.Image" in template:
        print(box.get("image", ""))
elif args[0] == "rm":
    state.pop(args[-1], None)
    save()
elif args[0] == "run" and "--rm" not in args:
    state[opt("--name")] = {
        "address": f"{opt('--ip')} {opt('--mac-address')}",
        "image": args[-1],
    }
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


def _image(env: dict, target: str) -> str:
    return env["SSH_IMAGE_TAG"] if target == "SSH" else env[f"{target}_IMAGE"]


def _defined() -> dict:
    env = _targets_env()
    return {
        env[f"{t}_CONTAINER"]: {
            "address": f"{env[f'{t}_TARGET']} {env[f'{t}_MAC']}",
            "image": _image(env, t),
        }
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
    containers[web] = {
        "address": f"{env['WEB_TARGET']} 3a:2e:0d:74:a2:00",
        "image": env["WEB_IMAGE"],
    }
    calls, out, state = _run_up(tmp_path, containers)
    assert ["rm", "-f", web] in calls
    assert [
        c[c.index("--name") + 1] for c in calls if c[0] == "run" and "--rm" not in c
    ] == [web]
    assert f"replacing {web}" in out
    assert state == _defined()


def test_up_replaces_a_target_running_another_image(tmp_path):
    """
    T0: an SSH target from the image before the audit account existed holds the
    right address and MAC, and must still be replaced: a credentialed run
    against it could not log in.
    """
    env = _targets_env()
    containers = _defined()
    ssh = env["SSH_CONTAINER"]
    containers[ssh] = dict(containers[ssh], image="ccure-validation-ssh:ubuntu-24.04")
    calls, out, state = _run_up(tmp_path, containers)
    assert ["rm", "-f", ssh] in calls
    assert f"replacing {ssh}" in out
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
    # The scanner's address on the targets' network, which the harness uses to
    # find the interface Scapy must send from: Docker's attach order, which
    # Scapy would otherwise follow, is not guaranteed (B5).
    assert '--network "$VALIDATION_NETWORK" --ip "$VALIDATION_SCANNER_ADDRESS"' in live
    assert 'CCURE_LIVE_SCANNER_ADDRESS="$VALIDATION_SCANNER_ADDRESS"' in live
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


def test_the_scanner_interface_is_the_one_holding_its_address():
    harness = _load("live_scan_harness")
    seen = [("lo", "127.0.0.1"), ("eth0", "172.19.0.2"), ("eth1", "172.30.250.5")]
    assert harness.interface_holding("172.30.250.5", seen) == "eth1"
    for address, interfaces, why in (
        ("", seen, "not set"),
        ("172.30.250.5", seen[:2], "0 interfaces"),
        ("172.30.250.5", [*seen, ("eth2", "172.30.250.5")], "2 interfaces"),
    ):
        with pytest.raises(SystemExit, match=why):
            harness.interface_holding(address, interfaces)


def test_scapy_is_pointed_at_the_targets_network(monkeypatch):
    """The order B5 failed in: the database network attached first."""
    import types

    import scapy.all

    harness = _load("live_scan_harness")
    fake_conf = types.SimpleNamespace(iface="eth0")
    addresses = {"lo": "127.0.0.1", "eth0": "172.19.0.2", "eth1": "172.30.250.5"}
    monkeypatch.setattr(scapy.all, "conf", fake_conf)
    monkeypatch.setattr(scapy.all, "get_if_list", lambda: list(addresses))
    monkeypatch.setattr(scapy.all, "get_if_addr", lambda name: addresses[name])
    assert harness.pin_scapy_interface("172.30.250.5") == {
        "pinned": "eth1",
        "address": "172.30.250.5",
        "scapy_default": "eth0",
    }
    assert fake_conf.iface == "eth1"


@pytest.mark.parametrize("scanner", ["", "192.0.2.77"])
def test_the_harness_refuses_before_anything_when_the_interface_is_unknown(
    monkeypatch, scanner
):
    harness = _load("live_scan_harness")
    monkeypatch.setenv("CCURE_LIVE_TARGETS", "172.30.250.10")
    monkeypatch.setenv("CCURE_LIVE_SWEEP", "172.30.250.0/24")
    monkeypatch.setenv("CCURE_LIVE_EXCLUDE", "172.30.250.1")
    monkeypatch.setenv("CCURE_LIVE_SCANNER_ADDRESS", scanner)
    monkeypatch.setenv("CCURE_LIVE_SSH_TARGET", "172.30.250.10")
    monkeypatch.setenv("CCURE_LIVE_PG_TARGET", "172.30.250.13")

    def created(*_args):
        raise AssertionError("an identity was created before the interface was known")

    monkeypatch.setattr(harness, "make_identity", created)
    monkeypatch.setattr(harness, "store_credentials", created)
    with pytest.raises(SystemExit, match="scanner's"):
        harness.main("no-interface", io.StringIO(json.dumps(CREDENTIALS) + "\n"))


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
    # The comparison recognises this frame by its content.
    _, phase, progress = frames[0]
    assert {"phase": phase, **progress} == _load("compare_live_scans").ROUTE_STOP_FRAME
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
    """
    A result in the harness's shape: the concurrent runs carry their own row,
    phases and frames, and share the organisation's state ("concurrent"); the
    cancel run, alone, carries its own.
    """
    run = {
        "scan": {
            "status": "complete",
            "duration_seconds": elapsed,
            "progress": {"active": 4, "start_time": f"t{elapsed}"},
        },
        "phases": [{"phase_order": 1, "status": "complete"}],
        "task_result": {"success": True},
        "frames": [{"t": frame_t, "phase": 1, "status": "running"}],
        "elapsed_s": elapsed,
    }
    state = {
        "assets": [{"ip_address": "10.0.0.1"}],
        "services": [],
        "findings": findings,
    }
    cancel = dict(
        run, **state, stop={"applied": True, "task_returned_s_after_stop": elapsed / 30}
    )
    return {"full": run, "concurrent": state, "cancel": cancel}


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


# ── The comparison's timing tolerance ────────────────────────────────────────
#
# The frames are B3's own (refactoring log §6): the cancel run's frames of
# `before` (22aa824) and `after2` (ad4aab7), which differed only because the
# first discovery sample held one host in one run and four in the other.

HOSTS = ["172.30.250.10", "172.30.250.11", "172.30.250.12", "172.30.250.13"]
STOP = {"phase": 1, "status": "cancelled", "reason": "Scan cancelled by user."}
END = {"phase": 1, "status": "cancelled"}


def _sample(hosts, total=253):
    n = len(hosts)
    return {
        "phase": 1,
        "status": "running",
        "discovered": n,
        "active": n,
        "total_ips": total,
        "host_ips": hosts,
    }


def _cancel_run(frames, after_discovered):
    run = _result([])["cancel"]
    run["frames"] = [dict(f, t=i * 0.5) for i, f in enumerate(frames)]
    run["stop"] = {
        "applied": True,
        "after_discovered": after_discovered,
        "task_returned_s_after_stop": 9.1,
    }
    return run


B3_BEFORE = [_sample(HOSTS[:1]), STOP, _sample(HOSTS), END]
B3_AFTER = [_sample(HOSTS), STOP, END]


def _with_cancel(frames, after_discovered):
    result = _result([])
    result["cancel"] = _cancel_run(frames, after_discovered)
    return result


def test_the_b3_timing_differences_are_tolerated_and_still_shown(tmp_path):
    compare = _load("compare_live_scans")
    before = _with_cancel(B3_BEFORE, 1)
    after = _with_cancel(B3_AFTER, 4)
    differences, tolerated = compare.classify(before, after)
    assert differences == []
    assert len(tolerated) == 2
    assert compare.compare(before, after) == []
    # --strict is the comparison before B3: both count.
    assert len(compare.compare(before, after, strict=True)) == 2

    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(before))
    b.write_text(json.dumps(after))
    tool = [sys.executable, str(VALIDATION / "compare_live_scans.py")]
    done = subprocess.run(tool + [str(a), str(b)], capture_output=True, text=True)
    assert done.returncode == 0
    assert done.stdout.count("tolerated: ") == 2
    assert "2 timing-dependent difference(s)" in done.stdout
    strict = subprocess.run(
        tool + ["--strict", str(a), str(b)], capture_output=True, text=True
    )
    assert strict.returncode == 1 and "2 difference(s)" in strict.stdout


@pytest.mark.parametrize(
    "frames, after_discovered, what",
    [
        ([_sample(HOSTS[:3]), STOP, END], 3, "a host missing from discovery"),
        ([_sample(HOSTS), STOP], 4, "no terminal frame from the engine"),
        ([_sample(HOSTS), END], 4, "no frame from the stop route"),
        ([_sample(HOSTS), STOP, STOP, END], 4, "the stop route's frame twice"),
        (
            [_sample(HOSTS), _sample(HOSTS[:1]), STOP, END],
            4,
            "a sample going backwards",
        ),
        ([_sample(HOSTS, total=254), STOP, END], 4, "a different sweep size"),
        # An earlier sample is dropped only when the next one covers it. These
        # end on the right sample, so only that rule can catch them.
        (
            [_sample([*HOSTS, "172.30.250.14"]), _sample(HOSTS), STOP, END],
            5,
            "a host reported, then gone",
        ),
        (
            [_sample(HOSTS[:1], total=254), _sample(HOSTS), STOP, END],
            1,
            "an early sample with another sweep size",
        ),
        (
            [dict(_sample(HOSTS[:1]), error="x"), _sample(HOSTS), STOP, END],
            1,
            "an early sample carrying another field",
        ),
        ([_sample(HOSTS), STOP, {"phase": 1, "status": "failed"}], 4, "a failed end"),
        (B3_AFTER, None, "no stop issued"),
    ],
)
def test_a_real_difference_in_the_cancel_run_is_still_a_difference(
    frames, after_discovered, what
):
    compare = _load("compare_live_scans")
    differences = compare.compare(
        _with_cancel(B3_BEFORE, 1), _with_cancel(frames, after_discovered)
    )
    assert differences, what


#: The full run's frames as B3 recorded them, less the time.
FULL_FRAMES = [
    _sample(HOSTS, total=6),
    dict(_sample(HOSTS, total=6), discovered=6),
    dict(_sample(HOSTS, total=6), discovered=6, status="enriching"),
    {"phase": 2, "status": "running", "total_hosts": 4},
    {"phase": 2, "status": "running", "scanned_hosts": 4, "total_hosts": 4},
    *(
        {"phase": 3, "status": "running", "scanned_hosts": n, "total_hosts": 4}
        for n in range(5)
    ),
    {"phase": 3, "status": "complete", "scanned_hosts": 6, "total_hosts": 6},
    {"phase": 2, "status": "complete", "scanned_hosts": 6, "total_hosts": 6},
    {"phase": 1, "status": "complete", "discovered": 4, "total_ips": 6},
]


def _with_full(frames):
    result = _result([])
    result["full"]["frames"] = [dict(f, t=float(i)) for i, f in enumerate(frames)]
    return result


@pytest.mark.parametrize(
    "drop, what",
    [
        (1, "the batch's own discovery frame"),
        (6, "a per-host progress frame of the audit"),
        (12, "the end of discovery"),
    ],
)
def test_a_missing_frame_outside_the_samples_is_still_a_difference(drop, what):
    """A frame the engine publishes once per event, not per tick, is never a sample."""
    compare = _load("compare_live_scans")
    fewer = [f for i, f in enumerate(FULL_FRAMES) if i != drop]
    assert compare.compare(_with_full(FULL_FRAMES), _with_full(fewer)), what


def test_a_discovery_sample_the_batch_frame_covers_is_tolerated():
    """The same tolerance in the full run: the first sample may hold fewer hosts."""
    compare = _load("compare_live_scans")
    early = [_sample(HOSTS[:1], total=6), *FULL_FRAMES]
    differences, tolerated = compare.classify(
        _with_full(FULL_FRAMES), _with_full(early)
    )
    assert differences == [] and len(tolerated) == 1


# ── T0: throwaway credentials and the credentialed runs ──────────────────────
#
# The credentials are made by live_scan.sh for one run and revoked when it
# ends; the harness stores them as the application stores any credential and
# keeps only their ids. These pin where a credential may and may not go.

#: Placeholder credentials for the harness's own tests. Never a real secret.
CREDENTIALS = {
    "ssh": {"username": "ccure-audit", "password": "placeholder ssh password"},
    "database": {
        "username": "ccure_audit",
        "password": "placeholder database password",
        "database": "postgres",
    },
}


def _live() -> str:
    return (VALIDATION / "live_scan.sh").read_text(encoding="utf-8")


def test_the_ssh_target_has_one_locked_audit_account_and_no_secret():
    env = _targets_env()
    text = (VALIDATION / "ssh-target" / "Dockerfile").read_text(encoding="utf-8")
    # The instructions, not the comments explaining them.
    docker = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    assert f"ARG AUDIT_USER={env['SSH_AUDIT_USER']}" in docker
    # Created, then locked: "!" matches no password.
    assert 'useradd --create-home --shell /bin/bash "$AUDIT_USER"' in docker
    assert "usermod --password '!' \"$AUDIT_USER\"" in docker
    # Elevation asks for the password; nothing is NOPASSWD.
    assert "ALL=(ALL:ALL) ALL" in docker and "NOPASSWD" not in docker
    # No password and no key is ever put into the image.
    for forbidden in (
        "chpasswd",
        "passwd -d",
        "authorized_keys",
        "ssh-copy-id",
        "COPY",
        "ADD ",
    ):
        assert forbidden not in docker, forbidden
    targets = (VALIDATION / "targets.sh").read_text(encoding="utf-8")
    assert '--build-arg AUDIT_USER="$SSH_AUDIT_USER"' in targets


def test_the_throwaway_credentials_never_reach_an_argument_an_environment_or_a_file():
    """
    Each credential is a shell variable made from /dev/urandom, never exported,
    and only ever given to `printf` (a builtin, so never a process argument)
    piped into a container's stdin, or matched through a pipe by the leak check.
    """
    live = _live().replace("\\\n", " ")
    assert "SSH_PW=$(random_hex 16)" in live and "DB_PW=$(random_hex 16)" in live
    assert not re.search(r"export\s+(SSH_PW|DB_PW)|declare\s+-x", live)
    uses = [
        line.strip()
        for line in live.splitlines()
        if re.search(r"\$\{?(SSH_PW|DB_PW)", line)
    ]
    assert uses
    for line in uses:
        assert line.startswith(("printf ", "secrets() {")), line
        # The printf itself, before any pipe, never writes to a file.
        assert ">" not in line.split("|")[0], line
    # Every printf that carries one feeds a container's stdin.
    grant = live[
        live.index("grant_credentials() {") : live.index("# Revoke, then confirm")
    ]
    assert '| docker exec -i "$SSH_CONTAINER" chpasswd' in grant
    assert '} | docker exec -i "$PG_CONTAINER" psql' in grant
    assert '| docker start -a -i "$RUN-scan"' in live
    # And no credential appears where a container's configuration would hold it.
    for command in re.findall(r"docker (?:run|create)\b[^\n]*", live):
        assert "_PW" not in command.replace("$PW", ""), command
    # The harness takes them on stdin, which it reads before anything else.
    assert 'docker create --name "$RUN-scan" --init -i ' in live
    assert 'docker start -a -i "$RUN-scan"' in live


def test_the_role_password_is_set_in_a_session_that_logs_no_statement():
    """A failing ALTER ROLE would otherwise be logged with the password in it."""
    live = _live()
    grant = live[
        live.index("grant_credentials() {") : live.index("# Revoke, then confirm")
    ]
    for setting in (
        "SET log_statement = 'none';",
        "SET log_min_error_statement = 'panic';",
    ):
        assert grant.index(setting) < grant.index(
            "ALTER ROLE %s LOGIN PASSWORD"
        ), setting


def test_the_credentials_are_revoked_and_confirmed_on_every_exit():
    live = _live()
    assert "trap cleanup EXIT" in live
    cleanup = live[live.index("cleanup() {") : live.index("trap cleanup EXIT")]
    assert cleanup.index("revoke_credentials") < cleanup.index("docker rm -f")
    assert "exit 4" in cleanup
    revoke = live[live.index("revoke_credentials() {") : live.index("holds_secret() {")]
    assert "usermod --password '!'" in revoke
    assert "NOLOGIN PASSWORD NULL" in revoke
    # Confirmed from the targets themselves, not assumed.
    assert "getent shadow" in revoke and "pg_authid" in revoke


#: The leak check's functions, run against a stand-in docker.
_LEAK_DOCKER = r"""#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
leaky = os.environ.get("LEAKY", "")
if args[:1] == ["logs"] and args[-1] == leaky:
    print("a line holding " + os.environ["PLANTED"])
elif args[:2] == ["exec", leaky]:
    print("COPY credentials FROM stdin; " + os.environ["PLANTED"])
else:
    print("nothing to see")
"""


def _leak_check(tmp_path, leaky: str) -> subprocess.CompletedProcess:
    live = _live()
    functions = live[
        live.index("# Both credentials as patterns") : live.index("cleanup() {")
    ]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(_LEAK_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    out = tmp_path / "out"
    out.mkdir()
    (out / "x.log").write_text("harness output\n")
    (out / "x.json").write_text("{}\n")
    script = "\n".join(
        [
            "set -uo pipefail",
            'SSH_PW="$PLANTED"; DB_PW=unrelated-0000; SINCE=2026-01-01T00:00:00Z',
            f'OUT="{out}"; LABEL=x; RUN=r',
            "SSH_CONTAINER=s WEB_CONTAINER=w REDIS_CONTAINER=rd PG_CONTAINER=p",
            functions,
            "leak_check",
        ]
    )
    return subprocess.run(
        ["bash", "-c", script],
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "PLANTED": "planted-secret-7f3a",
            "LEAKY": leaky,
        },
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "leaky, where",
    [
        ("w", "docker logs w"),
        ("r-pg", "docker logs r-pg"),
        ("r-pg", "the throwaway database"),
    ],
)
def test_the_leak_check_finds_a_planted_credential(tmp_path, leaky, where):
    done = _leak_check(tmp_path, leaky)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "SECRET LEAK" in done.stderr and where in done.stderr
    # It names where, never what.
    assert "planted-secret-7f3a" not in done.stdout + done.stderr


def test_the_leak_check_passes_a_clean_run(tmp_path):
    done = _leak_check(tmp_path, "nobody")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "secret check: neither credential appears" in done.stdout


def test_the_harness_reads_its_credentials_from_stdin_and_refuses_without():
    harness = _load("live_scan_harness")
    assert (
        harness.read_credentials(io.StringIO(json.dumps(CREDENTIALS) + "\n"))
        == CREDENTIALS
    )
    for bad, why in (
        ("", "no throwaway credentials"),
        ("not json\n", "not one JSON line"),
        (json.dumps({"ssh": CREDENTIALS["ssh"]}) + "\n", "database credential"),
        (
            json.dumps(dict(CREDENTIALS, ssh={"username": "u", "password": ""})) + "\n",
            "ssh credential",
        ),
    ):
        with pytest.raises(SystemExit, match=why) as refused:
            harness.read_credentials(io.StringIO(bad))
        for part in CREDENTIALS.values():
            assert part["password"] not in str(refused.value)


def test_the_harness_dispatches_credentialed_scans_with_the_routes_own_arguments():
    """routers/credentialed.py's run_credentialed_scan_task.delay(...) keywords."""
    import ast

    harness = _load("live_scan_harness")
    tree = ast.parse((BACKEND_ROOT / "routers" / "credentialed.py").read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "delay"
        and getattr(node.func.value, "id", None) == "run_credentialed_scan_task"
    ]
    assert len(calls) == 1
    assert (
        tuple(k.arg for k in calls[0].keywords) == harness.CREDENTIALED_DISPATCH_KWARGS
    )


def test_stored_credentials_are_encrypted_and_only_their_ids_kept(db_session):
    from db.models import ComplianceCredential

    harness = _load("live_scan_harness")
    org_id, user_id = harness.make_identity(f"cred-{uuid.uuid4().hex[:6]}")
    ids = harness.store_credentials(org_id, user_id, CREDENTIALS)
    assert set(ids) == {"ssh", "database"}
    rows = {
        r.id: r
        for r in db_session.query(ComplianceCredential).filter(
            ComplianceCredential.tenant_id == org_id
        )
    }
    ssh, database = rows[ids["ssh"]], rows[ids["database"]]
    assert (ssh.credential_type, ssh.transport, ssh.port) == ("ssh", "ssh", 22)
    assert (database.credential_type, database.transport, database.port) == (
        "database",
        "postgresql",
        5432,
    )
    for row in (ssh, database):
        values = " ".join(str(getattr(row, c.name)) for c in row.__table__.columns)
        for part in CREDENTIALS.values():
            assert part["password"] not in values  # stored encrypted, never plain


def test_the_phase_35_scan_carries_the_credential_plan_as_the_route_merges_it(
    db_session,
):
    from db.models import Scan

    harness = _load("live_scan_harness")
    org_id, user_id = harness.make_identity(f"plan-{uuid.uuid4().hex[:6]}")
    plan = {"credentials": [{"credential_id": "cred-x", "targets": ["192.0.2.10"]}]}
    scan_id, kwargs, _task = harness.dispatch(
        org_id,
        user_id,
        ["192.0.2.10"],
        "vulnerability_audit",
        "192.0.2.1",
        options=plan,
    )
    db_session.expire_all()
    scan = db_session.query(Scan).filter(Scan.id == scan_id).one()
    assert scan.options["credentials"] == plan["credentials"]
    assert "scan_policy" in scan.options  # the snapshot survived the merge
    assert "password" not in json.dumps(kwargs)
    # The route's validator applies: a null plan is refused, not ignored.
    with pytest.raises(ValueError, match="not null"):
        harness.dispatch(
            org_id,
            user_id,
            ["192.0.2.10"],
            "basic",
            "192.0.2.1",
            options={"credentials": None},
        )


def test_a_run_whose_credentialed_scans_did_not_authenticate_is_refused():
    harness = _load("live_scan_harness")
    cfg = {"ssh_target": "172.30.250.10"}
    result = {
        "concurrent": {
            "assets": [
                {"ip_address": "172.30.250.10", "credentialed_status": "success"}
            ]
        },
        **{run: {"verdicts": [{"Check ID": "x"}]} for run in harness.CREDENTIALED_RUNS},
    }
    assert all(harness.authenticated(result, cfg).values())
    result["concurrent"]["assets"][0]["credentialed_status"] = "failed"
    result["database"]["verdicts"] = []
    flags = harness.authenticated(result, cfg)
    assert sorted(k for k, ok in flags.items() if not ok) == [
        "database_has_verdicts",
        "ssh_host_marked_success",
    ]


def test_the_harness_exits_5_after_writing_a_result_that_did_not_authenticate(tmp_path):
    """The harness's own `__main__` block, run with `main` replaced."""
    import ast

    harness = _load("live_scan_harness")
    tree = ast.parse((VALIDATION / "live_scan_harness.py").read_text(encoding="utf-8"))
    block = next(
        node
        for node in tree.body
        if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)
    )
    code = compile(
        ast.Module(body=block.body, type_ignores=[]), "harness __main__", "exec"
    )

    def run(flags):
        written = tmp_path / "x.json"
        written.unlink(missing_ok=True)
        namespace = {
            "sys": types.SimpleNamespace(
                argv=["harness", "x"], stdin=None, exit=sys.exit
            ),
            "json": json,
            "main": lambda label, stream: {"authenticated": flags},
            "open": lambda path, *a, **k: open(written, *a, **k),
            "NOT_AUTHENTICATED": harness.NOT_AUTHENTICATED,
        }
        exec(code, namespace)
        return json.loads(written.read_text())

    assert run({"ssh_host_marked_success": True})["authenticated"]
    with pytest.raises(SystemExit) as refused:
        run({"ssh_host_marked_success": True, "database_has_verdicts": False})
    assert refused.value.code == harness.NOT_AUTHENTICATED == 5
    # Written first, so the refused run can still be read.
    assert json.loads((tmp_path / "x.json").read_text())["authenticated"] == {
        "ssh_host_marked_success": True,
        "database_has_verdicts": False,
    }


def _with_credentialed(verdict="PASS", timestamp="2026-10-22T10:00:00"):
    result = _result([])
    for run in ("credentialed", "host", "database"):
        result[run] = dict(
            result["full"],
            frames=[
                {"t": 1.0, "phase": 5, "status": "running", "timestamp": timestamp}
            ],
            verdicts=[{"Host": "172.30.250.10", "Check ID": "c1", "Verdict": verdict}],
        )
    result["authenticated"] = {"ssh_host_marked_success": True}
    return result


def test_the_comparison_reads_the_credentialed_runs_and_ignores_their_send_times():
    compare = _load("compare_live_scans")
    before = _with_credentialed()
    assert (
        compare.compare(before, _with_credentialed(timestamp="2026-10-22T10:09:59"))
        == []
    )

    changed = compare.compare(before, _with_credentialed(verdict="FAIL"))
    assert len(changed) == 3 and all(" verdicts:" in line for line in changed)

    unauthenticated = _with_credentialed()
    unauthenticated["authenticated"] = {"ssh_host_marked_success": False}
    assert compare.compare(before, unauthenticated)

    one_sided = _with_credentialed()
    del one_sided["database"]
    assert any(
        line.startswith("database: missing")
        for line in compare.compare(before, one_sided)
    )
