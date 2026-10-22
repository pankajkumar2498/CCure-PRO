"""
Live scan validation harness. Runs inside the scanner container, from Backend/,
started by scripts/validation/live_scan.sh — never directly against a real
network. docs/ci/LIVE_SCAN_VALIDATION.md describes the procedure.

    printf '<credentials json>\\n' | python /validation/live_scan_harness.py <label>

It creates an organisation and a user, stores the run's throwaway credentials
the way the application stores any credential, and then runs four scans at
once, each dispatched exactly the way its route dispatches it, with Celery
eager so every pipeline runs in this process (one thread per scan):

  full         — vulnerability_audit over CCURE_LIVE_TARGETS, unauthenticated,
                 as ``POST /scan/host-discovery`` sends it;
  credentialed — vulnerability_audit over the SSH target with the stored SSH
                 credential in ``options.credentials``: the pipeline's own
                 credentialed enrichment (Phase 3.5);
  host         — the standalone credentialed audit of the SSH target, as
                 ``POST /scan/credentialed`` sends it with ``credential_id``;
  database     — the same route with the stored database credential, against
                 the PostgreSQL target: the database audit.

Then, alone:

  cancel — basic discovery over CCURE_LIVE_SWEEP, stopped the way
           ``POST /scans/{id}/stop`` stops a scan as soon as the first
           discovery frame is published.

Every frame on ``scan_progress:*`` is recorded. For each scan, the scan row and
its phases; for each credentialed scan, its configuration verdicts as the
export reads them (``reporting.exports.export_payload``). After the four, the
organisation's assets, services and findings — once, because four scans of
overlapping hosts share those rows and which scan touched a row last is timing.
The result is written to ``/out/<label>.json``; ``compare_live_scans.py``
compares two.

**Credentials.** live_scan.sh writes one JSON line on stdin:
``{"ssh": {"username", "password"}, "database": {"username", "password",
"database"}}``. The harness reads it before anything else, stores both through
``core.credential_vault.create`` (encrypted, in the throwaway database) and
keeps only the ids. Nothing it writes or prints holds a password, and
live_scan.sh searches its output to make sure. A credentialed scan that never
authenticated proves nothing about credentialed code, so the harness refuses a
run in which one did not (exit 5, after writing the result).

Configuration comes from the environment, set by live_scan.sh from
targets.env: CCURE_LIVE_TARGETS (comma-separated addresses), CCURE_LIVE_SWEEP
(a range), CCURE_LIVE_EXCLUDE (the host's own bridge address, always excluded),
CCURE_LIVE_SCANNER_ADDRESS (the scanner's address on the targets' network) and
CCURE_LIVE_SSH_TARGET and CCURE_LIVE_PG_TARGET (the credentialed targets).

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
database and pins its dispatch to the routes'.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid

#: Exit status when a credentialed scan did not authenticate.
NOT_AUTHENTICATED = 5


def _config() -> dict:
    return {
        "targets": [
            t for t in os.environ.get("CCURE_LIVE_TARGETS", "").split(",") if t
        ],
        "sweep": os.environ.get("CCURE_LIVE_SWEEP", ""),
        "exclude": os.environ.get("CCURE_LIVE_EXCLUDE", ""),
        "scanner": os.environ.get("CCURE_LIVE_SCANNER_ADDRESS", ""),
        "ssh_target": os.environ.get("CCURE_LIVE_SSH_TARGET", ""),
        "pg_target": os.environ.get("CCURE_LIVE_PG_TARGET", ""),
    }


def read_credentials(stream) -> dict:
    """
    The run's throwaway credentials, from one JSON line on *stream*.

    Refuses rather than continuing without them: a run whose credentialed
    scans cannot authenticate records nothing about credentialed code. The
    error names the missing part, never a value.
    """
    line = stream.readline() if stream is not None else ""
    if not line.strip():
        raise SystemExit(
            "refusing: no throwaway credentials on stdin; run through live_scan.sh"
        )
    try:
        creds = json.loads(line)
    except ValueError:
        raise SystemExit("refusing: the credentials on stdin are not one JSON line")
    for kind, fields in (
        ("ssh", ("username", "password")),
        ("database", ("username", "password", "database")),
    ):
        part = creds.get(kind) if isinstance(creds, dict) else None
        if not isinstance(part, dict) or not all(
            isinstance(part.get(f), str) and part.get(f) for f in fields
        ):
            raise SystemExit(
                f"refusing: the {kind} credential on stdin needs {', '.join(fields)}"
            )
    return creds


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


def store_credentials(org_id: str, user_id: str, creds: dict) -> dict:
    """
    Store the run's credentials as the application stores any credential
    (``core.credential_vault.create``: validated, encrypted, audited) and return
    only their ids. The scans then resolve them by id, as production does.
    """
    from core import credential_vault
    from db.base import SessionLocal
    from db.models import User

    db = SessionLocal()
    try:
        actor = db.query(User).filter(User.id == user_id).one()
        ssh = credential_vault.create(
            db,
            actor=actor,
            org_id=org_id,
            name="live validation ssh",
            username=creds["ssh"]["username"],
            auth_method="password",
            credential_type="ssh",
            password=creds["ssh"]["password"],
            transport="ssh",
            port=22,
        )
        database = credential_vault.create(
            db,
            actor=actor,
            org_id=org_id,
            name="live validation database",
            username=creds["database"]["username"],
            auth_method="password",
            credential_type="database",
            password=creds["database"]["password"],
            transport="postgresql",
            port=5432,
            options={"database": creds["database"]["database"]},
        )
        return {"ssh": str(ssh.id), "database": str(database.id)}
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
    org_id: str,
    user_id: str,
    targets: list[str],
    pipeline_mode: str,
    exclude: str,
    options: dict | None = None,
):
    """
    The host-discovery route's steps, minus HTTP. Returns (scan_id, kwargs, task).

    ``options`` is the request's ``options`` (here only ``credentials``): the
    route validates it, marks the policy as having a credential when it names
    one, and merges it onto the scan's options last.
    """
    from core.credential_scope import validate_credential_options
    from core.scan_scope import org_scan_scope
    from core.tasks import run_host_discovery_task
    from db.base import SessionLocal
    from scan_helpers import validate_scan_targets
    from scans.db_helpers import create_scan
    from scans.policy_binding import reapply_policy_snapshot, resolve_scan_policy

    options = validate_credential_options(options)
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
            has_credential=bool((options or {}).get("credentials")),
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
            **(options or {}),
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


#: The keyword arguments routers/credentialed.py passes to
#: run_credentialed_scan_task.delay, in its own names. The test compares them.
CREDENTIALED_DISPATCH_KWARGS = (
    "user_id",
    "targets",
    "username",
    "password",
    "key_path",
    "port",
    "discover_transport",
    "auth_method",
    "sections",
    "os_type_req",
    "scan_id",
    "credential_id",
)


def dispatch_credentialed(org_id: str, user_id: str, credential_id: str, target: str):
    """
    The credentialed route's steps for a stored credential, minus HTTP:
    the credential read for its port and transport, target expansion, the
    scope check, the reachability preflight, the scan row, the policy gate.
    Returns (scan_id, kwargs, task). No secret is in the kwargs: the worker
    resolves the credential by id.
    """
    from core.scan_scope import enforce_org_scan_scope, org_scan_scope
    from core.tasks import MAX_CREDENTIALED_TARGETS, run_credentialed_scan_task
    from db.base import SessionLocal
    from db.models import ComplianceCredential
    from engines.credentialed.transport_resolver import TRANSPORT_SSH, resolve_endpoint
    from orchestrator.scan_orchestrator import ScanOrchestrator
    from scans.db_helpers import create_scan
    from scans.policy_binding import resolve_scan_policy

    db = SessionLocal()
    try:
        cred = (
            db.query(ComplianceCredential)
            .filter(
                ComplianceCredential.id == credential_id,
                ComplianceCredential.tenant_id == org_id,
            )
            .one()
        )
        target_port = cred.port
        target_transport = cred.transport or TRANSPORT_SSH
        use_tls = (cred.options or {}).get("use_tls")
        hosts = ScanOrchestrator._expand_targets([target])
        enforce_org_scan_scope(hosts, org_scan_scope(db, org_id))
        if not hosts or len(hosts) > MAX_CREDENTIALED_TARGETS:
            raise RuntimeError(f"credentialed target {target!r} expands to {hosts}")
        if len(hosts) == 1:
            preflight = resolve_endpoint(
                ip=hosts[0],
                transport=target_transport,
                stated_port=target_port,
                use_tls=use_tls,
                include_fallbacks=True,
                timeout=5,
            )
            if not preflight.resolved:
                raise RuntimeError(f"preflight refused {hosts[0]}: {preflight.reason}")
        scan = create_scan(
            db=db,
            user_id=user_id,
            target=", ".join(hosts),
            targets=hosts,
            scan_type="credentialed",
            pipeline_mode="credentialed",
            org_id=org_id,
        )
        effective, _ = resolve_scan_policy(
            db,
            scan=scan,
            policy_id=None,
            org_id=org_id,
            scan_kind="credentialed",
            has_credential=True,
            request_options={"sections": None},
        )
        db.commit()
        scan_id = str(scan.id)
        sections = list(effective.sections) or None
    finally:
        db.close()
    kwargs = dict(
        user_id=user_id,
        targets=hosts,
        username=None,
        password=None,
        key_path=None,
        port=target_port,
        # The route's rule: discover the transport when no port was requested.
        discover_transport=True,
        auth_method="password",
        sections=sections,
        os_type_req="auto",
        scan_id=scan_id,
        credential_id=credential_id,
    )
    if tuple(kwargs) != CREDENTIALED_DISPATCH_KWARGS:
        raise RuntimeError("dispatch kwargs drifted from CREDENTIALED_DISPATCH_KWARGS")
    return scan_id, kwargs, run_credentialed_scan_task


def run_concurrently(jobs: dict) -> dict:
    """
    Run each ``name -> (task, kwargs)`` in its own thread, all at once, and
    return ``name -> {outcome, error, t0, ended}``. A task that raises is
    recorded, not re-raised: the other scans still finish and are recorded.
    """
    results: dict = {}

    def work(name, task, kwargs):
        t0 = time.monotonic()
        try:
            outcome = task.delay(**kwargs).get(disable_sync_subtasks=False)
            error = None
        except Exception as exc:  # noqa: BLE001 - recorded in the result
            outcome, error = None, f"{type(exc).__name__}: {exc}"
        results[name] = {
            "outcome": outcome,
            "error": error,
            "t0": t0,
            "ended": time.monotonic(),
        }

    threads = [
        threading.Thread(target=work, args=(name, task, kwargs), name=f"live-{name}")
        for name, (task, kwargs) in jobs.items()
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


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


def _rows(db, sql, **params):
    from sqlalchemy import text

    return [dict(r._mapping) for r in db.execute(text(sql), params)]


def scan_record(scan_id: str) -> dict:
    """One scan's row and phases: everything about it no other scan writes."""
    from db.base import SessionLocal

    db = SessionLocal()
    try:
        scan = _rows(
            db,
            "SELECT status, failure_reason, pipeline_mode,"
            " completed_at IS NOT NULL AS has_completed_at, duration_seconds,"
            " total_vulns, critical_count, high_count, medium_count, low_count,"
            " info_count, options->'progress' AS progress FROM scans WHERE id = :s",
            s=scan_id,
        )[0]
        phases = _rows(
            db,
            "SELECT phase_order, phase_key, status, hosts_processed, error_message, summary"
            " FROM scan_phases WHERE scan_id = :s ORDER BY phase_order",
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
    return {"scan": scan, "phases": phases}


def org_state(org_id: str, scan_id: str | None = None) -> dict:
    """
    The organisation's assets, services and findings. Findings are the scan's
    own when *scan_id* is given and the organisation's otherwise; the scan that
    last wrote a shared row is timing when scans overlap, so it is not shown.
    """
    from db.base import SessionLocal

    db = SessionLocal()
    try:
        assets = _rows(
            db,
            "SELECT ip_address, mac_address, os_name, device_category,"
            " custom_attributes->>'credentialed_status' AS credentialed_status"
            " FROM assets WHERE org_id = :o ORDER BY ip_address",
            o=org_id,
        )
        services = _rows(
            db,
            "SELECT a.ip_address, s.port, s.protocol, s.state, s.service_name,"
            " s.service_product, s.service_version"
            " FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.org_id = :o"
            " ORDER BY a.ip_address, s.port, s.protocol",
            o=org_id,
        )
        findings = _rows(
            db,
            "SELECT a.ip_address, v.vuln_id, v.severity, v.status, v.detection_method"
            " FROM asset_vulnerabilities v JOIN assets a ON a.id = v.asset_id"
            " WHERE v.org_id = :o AND (CAST(:s AS TEXT) IS NULL OR v.scan_id = :s)"
            " ORDER BY a.ip_address, v.vuln_id",
            o=org_id,
            s=scan_id,
        )
    finally:
        db.close()
    return {"assets": assets, "services": services, "findings": findings}


def stored(scan_id: str, org_id: str) -> dict:
    """What the scan left behind: its row, phases, and the org's assets, services and findings."""
    return {**scan_record(scan_id), **org_state(org_id, scan_id)}


#: The configuration-verdict columns that describe the host and the check,
#: and none that names this run: no scan, asset or configuration id, no time,
#: no organisation name.
VERDICT_COLUMNS = (
    "Host",
    "Platform",
    "Check ID",
    "Check Type",
    "Verdict",
    "Severity",
    "Expected",
    "Observed",
    "Applicability",
    "Error",
)


def verdicts(scan_id: str) -> list[dict]:
    """
    A credentialed scan's configuration verdicts, read the way the export reads
    them (``reporting.exports.export_payload``, the compliance dataset), reduced
    to VERDICT_COLUMNS and sorted.
    """
    from db.base import SessionLocal
    from db.models import Scan
    from reporting.exports import export_payload

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).one()
        dataset = export_payload(db, scan, datasets=("compliance",))["datasets"][
            "compliance"
        ]
    finally:
        db.close()
    index = {name: dataset["columns"].index(name) for name in VERDICT_COLUMNS}
    rows = [{name: row[i] for name, i in index.items()} for row in dataset["rows"]]
    return sorted(rows, key=lambda r: (str(r["Host"]), str(r["Check ID"])))


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


def _task_result(outcome, error) -> dict | str:
    if error is not None:
        return {"raised": error}
    if isinstance(outcome, dict):
        return {k: outcome.get(k) for k in ("success", "error", "status")}
    return str(outcome)


def authenticated(result: dict, cfg: dict) -> dict:
    """
    Whether each credentialed scan got in: the SSH host recorded as
    credentialed ``success`` (written only after an authenticated collection)
    and every credentialed scan holding configuration verdicts (the audit runs
    only on an authenticated session).
    """
    status = {
        a["ip_address"]: a["credentialed_status"] for a in result["concurrent"]["assets"]
    }
    return {
        "ssh_host_marked_success": status.get(cfg["ssh_target"]) == "success",
        **{f"{run}_has_verdicts": bool(result[run]["verdicts"]) for run in CREDENTIALED_RUNS},
    }


#: The credentialed runs, in result order.
CREDENTIALED_RUNS = ("credentialed", "host", "database")


def main(label: str, credentials_stream=None) -> dict:
    cfg = _config()
    if not cfg["targets"] or not cfg["sweep"] or not cfg["exclude"]:
        raise SystemExit(
            "CCURE_LIVE_TARGETS, CCURE_LIVE_SWEEP and CCURE_LIVE_EXCLUDE must be set"
        )
    if cfg["exclude"] in cfg["targets"]:
        raise SystemExit("refusing: the excluded host address is in the target list")
    if not cfg["ssh_target"] or not cfg["pg_target"]:
        raise SystemExit("CCURE_LIVE_SSH_TARGET and CCURE_LIVE_PG_TARGET must be set")
    creds = read_credentials(credentials_stream)
    interface = pin_scapy_interface(cfg["scanner"])

    org_id, user_id = make_identity(label)
    credential_ids = store_credentials(org_id, user_id, creds)
    del creds  # only the ids from here on
    recorder = FrameRecorder()
    result = {"label": label, "config": cfg, "interface": interface}

    jobs, scan_ids = {}, {}
    for run, (scan_id, kwargs, task) in (
        (
            "full",
            dispatch(org_id, user_id, cfg["targets"], "vulnerability_audit", cfg["exclude"]),
        ),
        (
            "credentialed",
            dispatch(
                org_id,
                user_id,
                [cfg["ssh_target"]],
                "vulnerability_audit",
                cfg["exclude"],
                options={
                    "credentials": [
                        {
                            "credential_id": credential_ids["ssh"],
                            "targets": [cfg["ssh_target"]],
                        }
                    ]
                },
            ),
        ),
        (
            "host",
            dispatch_credentialed(org_id, user_id, credential_ids["ssh"], cfg["ssh_target"]),
        ),
        (
            "database",
            dispatch_credentialed(
                org_id, user_id, credential_ids["database"], cfg["pg_target"]
            ),
        ),
    ):
        jobs[run], scan_ids[run] = (task, kwargs), scan_id

    ran = run_concurrently(jobs)
    time.sleep(1)
    for run, outcome in ran.items():
        result[run] = {
            "task_result": _task_result(outcome["outcome"], outcome["error"]),
            "elapsed_s": round(outcome["ended"] - outcome["t0"], 1),
            "frames": frame_view(recorder.frames, scan_ids[run], outcome["t0"]),
            **scan_record(scan_ids[run]),
        }
        if run in CREDENTIALED_RUNS:
            result[run]["verdicts"] = verdicts(scan_ids[run])
    result["concurrent"] = org_state(org_id)

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
    result["authenticated"] = authenticated(result, cfg)
    return result


if __name__ == "__main__":
    label = sys.argv[1]
    result = main(label, sys.stdin)
    with open(f"/out/{label}.json", "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True, default=str)
    print(f"wrote /out/{label}.json")
    missing = sorted(k for k, ok in result["authenticated"].items() if not ok)
    if missing:
        print(
            "refusing: a credentialed scan did not authenticate, so this run proves "
            f"nothing about credentialed code: {', '.join(missing)}"
        )
        sys.exit(NOT_AUTHENTICATED)
