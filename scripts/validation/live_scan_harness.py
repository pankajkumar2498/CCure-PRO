"""
Live scan validation harness. Runs inside the scanner container, from Backend/,
started by scripts/validation/live_scan.sh — never directly against a real
network. docs/ci/LIVE_SCAN_VALIDATION.md describes the procedure.

    python /validation/live_scan_harness.py <label>

It creates an organisation and a user, then runs two scans exactly the way
``POST /scan/host-discovery`` dispatches them — ``create_scan``, the scan-policy
snapshot, the options, ``run_host_discovery_task.delay`` — with Celery eager,
so the whole pipeline runs in this process:

  full   — vulnerability_audit over CCURE_LIVE_TARGETS;
  cancel — basic discovery over CCURE_LIVE_SWEEP, stopped the way
           ``POST /scans/{id}/stop`` stops a scan as soon as the first
           discovery frame is published.

Every frame on ``scan_progress:*`` is recorded, and afterwards the scan row,
its phases, and the assets, services and findings it stored. The result is
written to ``/out/<label>.json``; ``compare_live_scans.py`` compares two.

Configuration comes from the environment, set by live_scan.sh from
targets.env: CCURE_LIVE_TARGETS (comma-separated addresses), CCURE_LIVE_SWEEP
(a range), CCURE_LIVE_EXCLUDE (the host's own bridge address, always excluded)
and CCURE_LIVE_SCANNER_ADDRESS (the scanner's address on the targets' network).
Nothing here holds a secret.

Scapy's interface is set, not inferred. Discovery's raw ARP leaves by
``scapy.conf.iface``. On the worker's host network that is the interface of the
default route, the one facing the targets. The scanner container has no default
route (both its networks are internal), so Scapy takes the interface of the
broadest route instead: the multicast route every interface carries, listed in
the order Docker attached them. Docker does not guarantee that order, and with
the database network attached first discovery found no host (B5, refactoring
log §6). So ``main()`` sets ``conf.iface`` to the interface holding
CCURE_LIVE_SCANNER_ADDRESS before any scan, and refuses if none holds it. The
choice, and what Scapy would have chosen, are recorded in the result.

Importing this module runs nothing; ``main()`` does the work.
``tests/repo/test_live_scan_tooling.py`` exercises its parts against the test
database and pins its dispatch to the route's.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid


def _config() -> dict:
    return {
        "targets": [
            t for t in os.environ.get("CCURE_LIVE_TARGETS", "").split(",") if t
        ],
        "sweep": os.environ.get("CCURE_LIVE_SWEEP", ""),
        "exclude": os.environ.get("CCURE_LIVE_EXCLUDE", ""),
        "scanner": os.environ.get("CCURE_LIVE_SCANNER_ADDRESS", ""),
    }


def interface_holding(address: str, interfaces: list[tuple[str, str]]) -> str:
    """
    The one interface, of ``(name, address)`` pairs, that holds *address*.

    Raises ``SystemExit`` when the address is unset, held by no interface, or
    held by several: scanning from a guessed interface records a run that may
    not see its targets.
    """
    if not address:
        raise SystemExit(
            "refusing: CCURE_LIVE_SCANNER_ADDRESS is not set, so the scanner's "
            "interface on the targets' network cannot be found"
        )
    names = sorted(name for name, held in interfaces if held == address)
    if len(names) != 1:
        raise SystemExit(
            f"refusing: {len(names)} interfaces hold the scanner's address "
            f"{address} ({names}); interfaces seen: {sorted(interfaces)}"
        )
    return names[0]


def pin_scapy_interface(address: str) -> dict:
    """Point Scapy's layer-2 traffic at the targets' network; report what changed."""
    from scapy.all import conf, get_if_addr, get_if_list

    default = getattr(conf.iface, "name", str(conf.iface))
    interfaces = []
    for name in get_if_list():
        try:
            interfaces.append((name, get_if_addr(name)))
        except Exception:  # noqa: BLE001 - an interface without an address
            continue
    chosen = interface_holding(address, interfaces)
    conf.iface = chosen
    return {
        "pinned": getattr(conf.iface, "name", str(conf.iface)),
        "address": address,
        "scapy_default": default,
    }


class FrameRecorder:
    """Every message on scan_progress:*, with its arrival time."""

    def __init__(self):
        from core.redis_client import get_redis_client

        self.frames: list[dict] = []
        self._pubsub = get_redis_client().pubsub()
        self._pubsub.psubscribe("scan_progress:*")
        self._stop = threading.Event()
        self._listeners = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def on_frame(self, fn) -> None:
        self._listeners.append(fn)

    def _run(self) -> None:
        while not self._stop.is_set():
            msg = self._pubsub.get_message(timeout=0.2)
            if not msg or msg.get("type") != "pmessage":
                continue
            data = json.loads(msg["data"])
            data["_t"] = time.monotonic()
            self.frames.append(data)
            for fn in list(self._listeners):
                fn(data)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._pubsub.close()


def make_identity(label: str) -> tuple[str, str]:
    """A fresh organisation and an approved user to own the scans."""
    from db.base import SessionLocal, gen_user_id, utcnow
    from db.models import Organization, User

    db = SessionLocal()
    try:
        org = Organization(
            name=f"Live validation {label}",
            slug=f"liveval-{uuid.uuid4().hex[:6]}",
            is_active=True,
        )
        db.add(org)
        db.commit()
        uid = uuid.uuid4().hex[:8]
        user = User(
            id=gen_user_id(org.slug, f"lv{uid}"),
            username=f"lv{uid}",
            email=f"lv{uid}@example.invalid",
            full_name="Live validation",
            password_hash="x",
            org_id=org.id,
            is_active=True,
            is_verified=True,
            approved_at=utcnow(),
            approved_by="live-validation",
        )
        db.add(user)
        db.commit()
        return org.id, user.id
    finally:
        db.close()


#: The keyword arguments the route passes to run_host_discovery_task.delay, in
#: the route's own names. The test compares them with routers/phase_scans.py.
DISPATCH_KWARGS = (
    "user_id",
    "targets",
    "scan_type",
    "pipeline_mode",
    "discovery_intensity",
    "scan_id",
    "rate_limit",
    "max_concurrency",
    "os_detection",
    "port_scan_intensity",
    "custom_ports",
    "exclude_ports",
    "passive_first",
    "exclude_ot_from_nmap",
    "exclude_ips",
)


def dispatch(
    org_id: str, user_id: str, targets: list[str], pipeline_mode: str, exclude: str
):
    """The host-discovery route's steps, minus HTTP. Returns (scan_id, kwargs, task)."""
    from core.scan_scope import org_scan_scope
    from core.tasks import run_host_discovery_task
    from db.base import SessionLocal
    from scan_helpers import validate_scan_targets
    from scans.db_helpers import create_scan
    from scans.policy_binding import reapply_policy_snapshot, resolve_scan_policy

    db = SessionLocal()
    try:
        targets = validate_scan_targets(targets, scope=org_scan_scope(db, org_id))
        scan = create_scan(
            db=db,
            user_id=user_id,
            target=", ".join(targets),
            targets=targets,
            scan_type="adaptive",
            pipeline_mode=pipeline_mode,
            org_id=org_id,
        )
        effective, _ = resolve_scan_policy(
            db,
            scan=scan,
            policy_id=None,
            org_id=org_id,
            scan_kind="network",
            has_credential=False,
            request_options={
                "custom_ports": None,
                "exclude_ports": None,
                "discovery_intensity": "normal",
                "port_scan_intensity": "normal",
                "os_detection": True,
                "exclude_ips": exclude,
            },
        )
        scan.options = {
            **(scan.options or {}),
            "execution_mode": "automatic",
            "exclude_ips": exclude,
        }
        reapply_policy_snapshot(scan, effective)
        db.commit()
        scan_id = str(scan.id)
    finally:
        db.close()
    kwargs = dict(
        user_id=user_id,
        targets=targets,
        scan_type="adaptive",
        pipeline_mode=pipeline_mode,
        discovery_intensity="normal",
        scan_id=scan_id,
        rate_limit=None,
        max_concurrency=None,
        os_detection=True,
        port_scan_intensity="normal",
        custom_ports=None,
        exclude_ports=None,
        passive_first=None,
        exclude_ot_from_nmap=None,
        exclude_ips=exclude,
    )
    if tuple(kwargs) != DISPATCH_KWARGS:
        raise RuntimeError("dispatch kwargs drifted from DISPATCH_KWARGS")
    return scan_id, kwargs, run_host_discovery_task


def stop_like_the_route(scan_id: str) -> bool:
    """
    What ``POST /scans/{id}/stop`` does to the scan row and the progress
    channel. There is no Celery task to revoke in eager mode; the engines only
    ever observe the status.
    """
    from core.redis_client import publish_progress_sync
    from core.scan_control import TERMINAL_STATUSES
    from db.base import SessionLocal, utcnow
    from db.models import Scan

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None or scan.status in TERMINAL_STATUSES:
            return False
        stopped_at = utcnow()
        scan.status = "cancelled"
        scan.updated_at = stopped_at
        if not scan.completed_at:
            scan.completed_at = stopped_at
        if scan.started_at and scan.duration_seconds is None:
            scan.duration_seconds = (
                scan.completed_at - scan.started_at
            ).total_seconds()
        for phase in scan.phases:
            if phase.status not in ("complete", "failed", "skipped", "cancelled"):
                phase.status = "cancelled"
                phase.completed_at = stopped_at
        db.add(scan)
        db.commit()
    finally:
        db.close()
    publish_progress_sync(
        scan_id, 1, {"status": "cancelled", "reason": "Scan cancelled by user."}
    )
    return True


def stored(scan_id: str, org_id: str) -> dict:
    """What the scan left behind: its row, phases, and the org's assets, services and findings."""
    from sqlalchemy import text

    from db.base import SessionLocal

    db = SessionLocal()
    try:

        def rows(sql, **params):
            return [dict(r._mapping) for r in db.execute(text(sql), params)]

        scan = rows(
            "SELECT status, failure_reason, pipeline_mode,"
            " completed_at IS NOT NULL AS has_completed_at, duration_seconds,"
            " options->'progress' AS progress FROM scans WHERE id = :s",
            s=scan_id,
        )[0]
        phases = rows(
            "SELECT phase_order, phase_key, status, hosts_processed, error_message, summary"
            " FROM scan_phases WHERE scan_id = :s ORDER BY phase_order",
            s=scan_id,
        )
        assets = rows(
            "SELECT ip_address, mac_address, os_name, device_category"
            " FROM assets WHERE org_id = :o ORDER BY ip_address",
            o=org_id,
        )
        services = rows(
            "SELECT a.ip_address, s.port, s.protocol, s.state, s.service_name,"
            " s.service_product, s.service_version"
            " FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.org_id = :o"
            " ORDER BY a.ip_address, s.port, s.protocol",
            o=org_id,
        )
        findings = rows(
            "SELECT a.ip_address, v.vuln_id, v.severity, v.status, v.detection_method"
            " FROM asset_vulnerabilities v JOIN assets a ON a.id = v.asset_id"
            " WHERE v.org_id = :o AND v.scan_id = :s ORDER BY a.ip_address, v.vuln_id",
            o=org_id,
            s=scan_id,
        )
    finally:
        db.close()
    for phase in phases:
        summary = phase.pop("summary") or {}
        phase["summary_keys"] = sorted(summary)
        for key in ("active_hosts", "total_hosts", "inactive_hosts"):
            if key in summary:
                phase[key] = summary[key]
    scan["duration_seconds"] = round(scan["duration_seconds"] or 0, 1)
    return {
        "scan": scan,
        "phases": phases,
        "assets": assets,
        "services": services,
        "findings": findings,
    }


def frame_view(frames: list[dict], scan_id: str, t0: float) -> list[dict]:
    """One scan's frames, host lists reduced to addresses, times relative to t0."""
    out = []
    for frame in frames:
        if frame.get("scan_id") != scan_id:
            continue
        progress = dict(frame.get("progress") or {})
        hosts = progress.pop("hosts", None)
        row = {"t": round(frame["_t"] - t0, 2), "phase": frame.get("phase"), **progress}
        if hosts is not None:
            row["host_ips"] = sorted(h.get("ip_address") for h in hosts)
        out.append(row)
    return out


def main(label: str) -> dict:
    cfg = _config()
    if not cfg["targets"] or not cfg["sweep"] or not cfg["exclude"]:
        raise SystemExit(
            "CCURE_LIVE_TARGETS, CCURE_LIVE_SWEEP and CCURE_LIVE_EXCLUDE must be set"
        )
    if cfg["exclude"] in cfg["targets"]:
        raise SystemExit("refusing: the excluded host address is in the target list")
    interface = pin_scapy_interface(cfg["scanner"])

    org_id, user_id = make_identity(label)
    recorder = FrameRecorder()
    result = {"label": label, "config": cfg, "interface": interface}

    scan_id, kwargs, task = dispatch(
        org_id, user_id, cfg["targets"], "vulnerability_audit", cfg["exclude"]
    )
    t0 = time.monotonic()
    outcome = task.delay(**kwargs).get(disable_sync_subtasks=False)
    elapsed = round(time.monotonic() - t0, 1)
    time.sleep(1)
    result["full"] = {
        "task_result": (
            {k: outcome.get(k) for k in ("success", "error", "status")}
            if isinstance(outcome, dict)
            else str(outcome)
        ),
        "elapsed_s": elapsed,
        "frames": frame_view(recorder.frames, scan_id, t0),
        **stored(scan_id, org_id),
    }

    scan_id, kwargs, task = dispatch(
        org_id, user_id, [cfg["sweep"]], "basic", cfg["exclude"]
    )
    stop: dict = {}

    def stop_on_first_discovery_frame(frame):
        p = frame.get("progress") or {}
        if (
            frame.get("scan_id") == scan_id
            and "stopped_at" not in stop
            and frame.get("phase") == 1
            and p.get("status") == "running"
            and p.get("discovered")
        ):
            stop["stopped_at"] = time.monotonic()
            stop["stopped_after_discovered"] = p.get("discovered")
            stop["applied"] = stop_like_the_route(scan_id)

    recorder.on_frame(stop_on_first_discovery_frame)
    t0 = time.monotonic()
    outcome = task.delay(**kwargs).get(disable_sync_subtasks=False)
    ended = time.monotonic()
    time.sleep(1)
    result["cancel"] = {
        "task_result": outcome if isinstance(outcome, dict) else str(outcome),
        "elapsed_s": round(ended - t0, 1),
        "stop": {
            "applied": stop.get("applied"),
            "after_discovered": stop.get("stopped_after_discovered"),
            "task_returned_s_after_stop": (
                round(ended - stop["stopped_at"], 1) if "stopped_at" in stop else None
            ),
        },
        "frames": frame_view(recorder.frames, scan_id, t0),
        **stored(scan_id, org_id),
    }
    recorder.close()
    return result


if __name__ == "__main__":
    label = sys.argv[1]
    result = main(label)
    with open(f"/out/{label}.json", "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True, default=str)
    print(f"wrote /out/{label}.json")
