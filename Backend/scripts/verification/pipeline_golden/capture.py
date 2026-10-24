"""
Phase-pipeline golden: run the network scan's phase tasks, Celery eager, on a
restored copy of the database with one commit's code, and capture what crosses
each phase boundary, in what order, and what a failure or a cancellation leaves
behind, so two commits can be compared byte for byte.

Run by ``run.sh`` inside the backend image, from one commit's ``Backend/`` tree,
against a throwaway copy of the findings golden's restored template. It refuses
any database whose name does not start with ``pipeline_golden_``.

The phase tasks, the scan-phase writers, the asset syncer, the findings writer,
the credentialed enrichment and the topology check are the commit's own code.
Only the orchestrator is replaced, by a recorder that takes each phase's input
as the task hands it over and answers from the phase results the restored
database stores: so the engines do not run, nothing touches a network, and
what is compared is the hand-off itself. The recorder answers phase 3 the way
the real orchestrator does in two respects the hand-off depends on: it edits
the port records of the hosts it was given in place (the real phase 3's Nmap
pre-enrichment does), and it returns hosts without their open ports, hostname
or vendor (the real phase 3's projection), which the task restores from the
hosts it handed over.

Every scenario starts a scan the way a request does, by dispatching host
discovery by name, and records, in order:

* every task dispatch: the registered name and its arguments as JSON, as the
  broker would carry them (top-level keys sorted, everything else in the
  order it was written);
* every orchestrator call, with its arguments as the phase received them;
* every progress frame;
* each dispatch's result.

Scenarios: each pipeline mode run through; options forwarded from the request
and from the scan record; no active host; interactive continuation with the
browser's host records (extra keys, an address under ``ip``, a truthy
non-boolean ``is_active``); a phase that reports failure, one that raises, and
one cancelled between phases; a broker refusing the next dispatch; a phase-3
hand-off holding records with no address.

Then every table's digest, and the scan-pipeline tables in full.

Determinism: the clock frozen, ``random`` seeded, ``secrets``, ``uuid4`` and
Celery task ids replaced by counters spread over every digit, ``PYTHONHASHSEED``
fixed by ``run.sh``.
"""

from __future__ import annotations

import argparse
import copy
import datetime as _dt_module
import hashlib
import itertools
import json
import os
import random
import sys
import traceback
import uuid
from pathlib import Path

BACKEND = os.path.abspath(os.getcwd())
ORG = "org_development"
DB_PREFIX = "pipeline_golden_"
START = _dt_module.datetime(2026, 10, 24, 9, 0, 0, tzinfo=_dt_module.timezone.utc)

# ── Deterministic clock and identifiers ─────────────────────────────────────

_REAL_DT = _dt_module.datetime
_REAL_DATE = _dt_module.date
_UTC = _dt_module.timezone.utc


class _Clock:
    now = START


CLOCK = _Clock()


class _DatetimeMeta(type):
    def __instancecheck__(cls, obj):
        return isinstance(obj, _REAL_DT)

    def __subclasscheck__(cls, sub):
        return issubclass(sub, _REAL_DT)


class _DateMeta(type):
    def __instancecheck__(cls, obj):
        return isinstance(obj, _REAL_DATE)

    def __subclasscheck__(cls, sub):
        return issubclass(sub, _REAL_DATE)


class FrozenDatetime(_REAL_DT, metaclass=_DatetimeMeta):
    def __new__(cls, *args, **kwargs):
        return _REAL_DT(*args, **kwargs)

    @classmethod
    def now(cls, tz=None):
        return CLOCK.now.astimezone(tz) if tz else CLOCK.now.replace(tzinfo=None)

    @classmethod
    def utcnow(cls):
        return CLOCK.now.replace(tzinfo=None)

    @classmethod
    def today(cls):
        return cls.now()


class FrozenDate(_REAL_DATE, metaclass=_DateMeta):
    def __new__(cls, *args, **kwargs):
        return _REAL_DATE(*args, **kwargs)

    @classmethod
    def today(cls):
        return CLOCK.now.date()


def _spread(n: int, nbytes: int) -> str:
    """The *n*-th identifier: deterministic, and different in every digit."""
    out = b""
    block = 0
    while len(out) < nbytes:
        out += hashlib.sha256(f"{n}:{block}".encode()).digest()
        block += 1
    return out[:nbytes].hex()


class _Counter:
    def __init__(self):
        self._n = itertools.count(1)

    def token_hex(self, nbytes=32):
        return _spread(next(self._n), nbytes)

    def token_urlsafe(self, nbytes=32):
        return self.token_hex(nbytes)

    def __getattr__(self, name):
        import secrets

        return getattr(secrets, name)


_SECRETS = _Counter()
_UUIDS = itertools.count(1)
_TASK_IDS = itertools.count(1)
_SEEN_MODULES: set = set()


def _patch_module(module) -> None:
    for name, value in list(vars(module).items()):
        if value is _REAL_DT:
            setattr(module, name, FrozenDatetime)
        elif value is _REAL_DATE:
            setattr(module, name, FrozenDate)
        elif name == "secrets" and getattr(value, "__name__", "") == "secrets":
            setattr(module, name, _SECRETS)


def _patch_new_first_party_modules() -> None:
    for name, module in list(sys.modules.items()):
        if name in _SEEN_MODULES or module is None:
            continue
        _SEEN_MODULES.add(name)
        path = getattr(module, "__file__", None) or ""
        if path.startswith(BACKEND + os.sep):
            _patch_module(module)


def install_determinism() -> None:
    random.seed(0)
    uuid.uuid4 = lambda: uuid.UUID(hex=_spread(next(_UUIDS), 16))  # noqa: E731
    _dt_module.datetime = FrozenDatetime
    _dt_module.date = FrozenDate
    _patch_new_first_party_modules()


def at(when) -> None:
    CLOCK.now = when.astimezone(_UTC)
    _patch_new_first_party_modules()


def jdump(obj) -> str:
    return json.dumps(obj, sort_keys=True, indent=1, default=str, ensure_ascii=False)


def wire(obj) -> str:
    """JSON as the broker carries it: written order kept."""
    return json.dumps(obj, default=str, ensure_ascii=False)


def short_error(exc: BaseException) -> str:
    first = str(exc).splitlines()[0][:300] if str(exc) else ""
    return f"{type(exc).__name__}: {first}"


# ── The code under test, loaded as the worker loads it ──────────────────────

import celery.app.task as celery_task_module  # noqa: E402

from core.celery_app import celery_app, registered_task  # noqa: E402

celery_app.loader.import_default_modules()

from sqlalchemy import text  # noqa: E402

import core.redis_client as redis_client  # noqa: E402
import db.models  # noqa: E402,F401
import scans.tasks.phases as phases  # noqa: E402
from core import task_names  # noqa: E402
from db.base import SessionLocal  # noqa: E402

install_determinism()

# ── Recorders ────────────────────────────────────────────────────────────────

EVENTS: list = []
FAIL_DISPATCH: set = set()


def event(kind: str, **fields) -> None:
    EVENTS.append({"event": kind, **fields})


def _sorted_top(mapping) -> dict:
    return {k: mapping[k] for k in sorted(mapping or {})}


_REAL_APPLY_ASYNC = celery_task_module.Task.apply_async


def _recording_apply_async(self, args=None, kwargs=None, task_id=None, **options):
    event(
        "dispatch",
        task=self.name,
        args=wire(list(args or ())),
        kwargs=wire(_sorted_top(kwargs or {})),
    )
    if self.name in FAIL_DISPATCH:
        FAIL_DISPATCH.discard(self.name)
        raise ConnectionError(f"broker refused {self.name}")
    return _REAL_APPLY_ASYNC(
        self,
        args,
        kwargs,
        task_id=task_id or f"golden-task-{next(_TASK_IDS):04d}",
        **options,
    )


celery_task_module.Task.apply_async = _recording_apply_async

_REAL_PUBLISH = redis_client.publish_progress_sync


def _recording_publish(scan_id, phase, payload, *args, **kwargs):
    event("progress", scan_id=scan_id, phase=phase, payload=wire(payload))


def _install_progress_recorder() -> None:
    for module in list(sys.modules.values()):
        if module is None:
            continue
        path = getattr(module, "__file__", None) or ""
        if not path.startswith(BACKEND + os.sep):
            continue
        if getattr(module, "publish_progress_sync", None) is _REAL_PUBLISH:
            module.publish_progress_sync = _recording_publish


_install_progress_recorder()


# ── The stored phase results the recorder answers from ──────────────────────


def _stored_phase_hosts(db, phase_order: int, mode: str | None = None) -> list:
    rows = db.execute(
        text(
            "select p.summary from scan_phases p join scans s on s.id = p.scan_id "
            "where p.phase_order = :o and (:m is null or s.pipeline_mode = :m) "
            "order by s.started_at, s.id"
        ),
        {"o": phase_order, "m": mode},
    ).all()
    hosts = []
    for (summary,) in rows:
        data = (summary or {}).get("_phase_data")
        if isinstance(data, list):
            hosts.extend(h for h in data if isinstance(h, dict))
    return hosts


def _stored_summary(db, phase_order: int) -> dict:
    row = db.execute(
        text(
            "select p.summary from scan_phases p join scans s on s.id = p.scan_id "
            "where p.phase_order = :o and s.pipeline_mode = 'vulnerability_audit' "
            "order by s.started_at, s.id limit 1"
        ),
        {"o": phase_order},
    ).first()
    summary = dict((row[0] if row else None) or {})
    summary.pop("_phase_data", None)
    return summary


def _latest_by_ip(hosts: list) -> dict:
    out = {}
    for host in hosts:
        ip = host.get("ip_address") or host.get("ip")
        if ip:
            out[ip] = host
    return out


def _slim_phase3(host: dict) -> dict:
    """A stored phase-3 host without the credentialed audit's bulk."""
    slim = copy.deepcopy(host)
    for key in ("credentialed_report", "credentialed", "open_ports_credentialed"):
        slim.pop(key, None)
    slim["cves"] = list(slim.get("cves") or [])[:15]
    slim["suppressed_cves"] = list(slim.get("suppressed_cves") or [])[:5]
    return slim


class Stored:
    p1_hosts: list = []
    p1_summary: dict = {}
    p2_by_ip: dict = {}
    p2_summary: dict = {}
    p3_by_ip: dict = {}
    p3_summary: dict = {}


def load_stored(db) -> dict:
    seen, hosts = set(), []
    for host in _stored_phase_hosts(db, 1):
        ip = host.get("ip_address") or host.get("ip")
        if ip and ip not in seen:
            seen.add(ip)
            hosts.append(copy.deepcopy(host))
    # One host discovery answered for but found down, as every real scan of a
    # range has.
    down = copy.deepcopy(hosts[0])
    down.update(ip_address="10.250.1.1", is_active=False, status="Inactive")
    Stored.p1_hosts = hosts + [down]
    Stored.p1_summary = _stored_summary(db, 1)
    Stored.p2_by_ip = _latest_by_ip(_stored_phase_hosts(db, 2, "vulnerability_audit"))
    Stored.p2_summary = _stored_summary(db, 2)
    Stored.p3_by_ip = {
        ip: _slim_phase3(h)
        for ip, h in _latest_by_ip(
            _stored_phase_hosts(db, 3, "vulnerability_audit")
        ).items()
    }
    Stored.p3_summary = _stored_summary(db, 3)
    return {
        "phase1_hosts": len(Stored.p1_hosts),
        "phase2_hosts": len(Stored.p2_by_ip),
        "phase3_hosts": len(Stored.p3_by_ip),
    }


# ── The recorder that stands in for the orchestrator ────────────────────────


class Behaviour:
    """What the recorder does in each phase of the current scenario."""

    def __init__(self, **overrides):
        self.p1 = overrides.get("p1", "ok")
        self.p2 = overrides.get("p2", "ok")
        self.p3 = overrides.get("p3", "ok")
        self.p1_hosts = overrides.get("p1_hosts")


CURRENT = {"behaviour": Behaviour(), "scan_id": None}


def _cancel_scan(scan_id: str) -> None:
    db = SessionLocal()
    try:
        db.execute(
            text("update scans set status = 'cancelled' where id = :i"), {"i": scan_id}
        )
        db.commit()
    finally:
        db.close()


def _outcome(mode: str, phase: str, build):
    if mode == "fail":
        return {"success": False, "error": f"{phase} reported failure (golden)"}
    if mode == "raise":
        raise RuntimeError(f"{phase} raised (golden)")
    if mode == "cancel":
        _cancel_scan(CURRENT["scan_id"])
    return build()


def _ip(host: dict):
    return host.get("ip_address") or host.get("ip")


class RecordingOrchestrator:
    def __init__(self, *args, **kwargs):
        event("orchestrator", kwargs=wire(_sorted_top(kwargs)))

    async def run_host_discovery_only(self, **kwargs):
        event("orch.phase1", kwargs=wire(_sorted_top(kwargs)))
        behaviour = CURRENT["behaviour"]

        def build():
            hosts = behaviour.p1_hosts
            data = copy.deepcopy(hosts if hosts is not None else Stored.p1_hosts)
            summary = copy.deepcopy(Stored.p1_summary)
            summary.update(
                total_hosts=len(data),
                active_hosts=sum(1 for h in data if h.get("is_active")),
            )
            return {
                "success": True,
                "data": data,
                "summary": summary,
                "metadata": {"target": ", ".join(kwargs.get("targets") or [])},
            }

        return _outcome(behaviour.p1, "phase 1", build)

    async def run_asset_discovery_only(self, **kwargs):
        event("orch.phase2", kwargs=wire(_sorted_top(kwargs)))
        hosts = kwargs.get("hosts") or []

        def build():
            data = []
            for host in hosts:
                stored = Stored.p2_by_ip.get(_ip(host))
                if stored is not None:
                    data.append(copy.deepcopy(stored))
                else:
                    out = copy.deepcopy(host)
                    out["open_ports"] = [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                        }
                    ]
                    data.append(out)
            summary = copy.deepcopy(Stored.p2_summary)
            summary["total_hosts"] = len(data)
            return {
                "success": True,
                "data": data,
                "summary": summary,
                "metadata": {"scan_type": "golden"},
            }

        return _outcome(CURRENT["behaviour"].p2, "phase 2", build)

    def run_vulnerability_audit_only(self, **kwargs):
        event("orch.phase3", kwargs=wire(_sorted_top(kwargs)))
        hosts = kwargs.get("hosts") or []

        def build():
            data = []
            for host in hosts:
                # The real phase 3 edits the port records it was handed, in
                # place (Nmap pre-enrichment), and the task reads them back.
                for port in host.get("open_ports") or []:
                    if isinstance(port, dict):
                        port["golden_phase3"] = "enriched in place"
                stored = Stored.p3_by_ip.get(_ip(host))
                out = (
                    copy.deepcopy(stored)
                    if stored is not None
                    else {
                        "ip_address": _ip(host),
                        "is_active": bool(host.get("is_active")),
                    }
                )
                # The real phase 3's projection: no open ports, and identity
                # the task restores from the hosts it handed over.
                out.pop("open_ports", None)
                out.pop("hostname", None)
                out["vendor"] = ""
                data.append(out)
            summary = copy.deepcopy(Stored.p3_summary)
            summary["total_hosts"] = len(data)
            return {
                "success": True,
                "data": data,
                "summary": summary,
                "metadata": {"scan_type": "vulnerability_audit"},
            }

        return _outcome(CURRENT["behaviour"].p3, "phase 3", build)

    def generate_phase_report(self, result, scan_type):
        event(
            "orch.report",
            scan_type=scan_type,
            hosts=len((result or {}).get("data") or []),
        )
        return {}


def _new_recording_orchestrator(*args, **kwargs):
    return RecordingOrchestrator(*args, **kwargs)


phases._new_orchestrator = _new_recording_orchestrator


# ── Scenarios ────────────────────────────────────────────────────────────────


def _user_id(db) -> str:
    return db.execute(
        text(
            "select created_by from scans where org_id = :o order by started_at limit 1"
        ),
        {"o": ORG},
    ).scalar()


def _new_scan(db, scan_id: str, number: int, mode: str, options: dict) -> None:
    """A scan row as a request leaves it, cloned from a stored one's columns."""
    db.execute(
        text(
            "insert into scans select (jsonb_populate_record(null::scans, to_jsonb(s) "
            "|| jsonb_build_object('id', cast(:id as text), 'scan_no', :no, "
            "'pipeline_mode', cast(:mode as text), 'options', cast(:opts as jsonb), "
            "'status', 'running', 'started_at', cast(:t as timestamptz), "
            "'queued_at', cast(:t as timestamptz), 'created_at', cast(:t as timestamptz), "
            "'updated_at', cast(:t as timestamptz), 'completed_at', null, "
            "'duration_seconds', null, 'failure_reason', null, 'current_task_id', null, "
            "'report_pdf_path', null, 'report_technical_path', null, "
            "'report_executive_path', null, 'total_hosts', 0, 'active_hosts', 0, "
            "'total_vulns', 0, 'critical_count', 0, 'high_count', 0, 'medium_count', 0, "
            "'low_count', 0, 'info_count', 0))).* from scans s "
            "where s.org_id = :o order by s.started_at limit 1"
        ),
        {
            "id": scan_id,
            "no": 9000 + number,
            "mode": mode,
            "opts": json.dumps(options),
            "t": CLOCK.now.isoformat(),
            "o": ORG,
        },
    )
    db.commit()


def _stored_data(db, scan_id: str, phase_order: int) -> list:
    row = db.execute(
        text("select summary from scan_phases where scan_id = :s and phase_order = :o"),
        {"s": scan_id, "o": phase_order},
    ).first()
    data = ((row[0] if row else None) or {}).get("_phase_data")
    return copy.deepcopy(data) if isinstance(data, list) else []


def _record_result(label: str, async_result) -> None:
    try:
        value = async_result.result
    except Exception as exc:  # an eager result holding an exception
        value = {"raised": short_error(exc)}
    if isinstance(value, BaseException):
        value = {"raised": short_error(value)}
    event("result", dispatch=label, value=wire(value))


def _dispatch(name: str, label: str, **kwargs) -> None:
    try:
        result = registered_task(name).delay(**kwargs)
    except Exception as exc:
        event(
            "result", dispatch=label, value=wire({"dispatch_raised": short_error(exc)})
        )
        return
    _record_result(label, result)


def _browser_hosts(stored: list) -> list:
    """Host records as the browser sends them back to continue a scan."""
    hosts = []
    for index, host in enumerate(h for h in stored if h.get("is_active")):
        host = dict(host)
        host["selected"] = True
        if index == 0:
            host["is_active"] = "true"
        hosts.append(host)
    hosts.append({"ip": "10.250.3.3", "is_active": True, "note": "address under ip"})
    hosts.append({"ip_address": "10.250.3.4", "is_active": 0})
    return hosts


SCENARIOS = []


def scenario(fn):
    SCENARIOS.append(fn)
    return fn


def _start(db, ctx, name, mode, *, options=None, behaviour=None, **task_kwargs):
    ctx["n"] += 1
    at(START + _dt_module.timedelta(hours=ctx["n"]))
    scan_id = f"scn_golden_{name}"
    CURRENT["scan_id"] = scan_id
    CURRENT["behaviour"] = behaviour or Behaviour()
    _new_scan(db, scan_id, ctx["n"], mode, options or {})
    event("scenario", name=name, scan_id=scan_id, mode=mode)
    _dispatch(
        task_names.RUN_HOST_DISCOVERY,
        "host_discovery",
        user_id=ctx["user"],
        targets=["10.180.6.0/24"],
        scan_type="adaptive",
        pipeline_mode=mode,
        discovery_intensity="normal",
        scan_id=scan_id,
        **task_kwargs,
    )
    return scan_id


@scenario
def basic(db, ctx):
    _start(db, ctx, "basic", "basic")


@scenario
def asset(db, ctx):
    _start(db, ctx, "asset", "asset")


@scenario
def audit(db, ctx):
    _start(db, ctx, "audit", "vulnerability_audit")


@scenario
def audit_forwarded_options(db, ctx):
    _start(
        db,
        ctx,
        "audit_forwarded_options",
        "vulnerability_audit",
        options={"custom_ports": "22,80,443", "exclude_ports": "8080"},
        port_scan_intensity="deep",
        os_detection=False,
        passive_first=True,
        exclude_ot_from_nmap=False,
        exclude_ips="10.250.9.9",
    )


@scenario
def audit_explicit_ports(db, ctx):
    _start(
        db,
        ctx,
        "audit_explicit_ports",
        "vulnerability_audit",
        options={"custom_ports": "1-100", "exclude_ports": "25"},
        custom_ports="22",
        exclude_ports="23",
    )


@scenario
def audit_no_active_host(db, ctx):
    down = [dict(h, is_active=False) for h in Stored.p1_hosts]
    _start(
        db,
        ctx,
        "audit_no_active_host",
        "vulnerability_audit",
        behaviour=Behaviour(p1_hosts=down),
    )


@scenario
def audit_interactive(db, ctx):
    scan_id = _start(
        db,
        ctx,
        "audit_interactive",
        "vulnerability_audit",
        options={"execution_mode": "interactive"},
    )
    # The browser continues the scan, phase by phase, with the records it
    # was shown, as routers/phase_scans.py dispatches them.
    db.execute(
        text("update scans set status = 'running' where id = :i"), {"i": scan_id}
    )
    db.commit()
    _dispatch(
        task_names.RUN_ASSET_DISCOVERY,
        "asset_discovery_continuation",
        user_id=ctx["user"],
        hosts=_browser_hosts(_stored_data(db, scan_id, 1)),
        intensity="normal",
        scan_id=scan_id,
        pipeline_mode="vulnerability_audit",
        os_detection=True,
        custom_ports=None,
        exclude_ports=None,
        exclude_ot_from_nmap=None,
        passive_first=None,
        exclude_ips=None,
    )
    db.execute(
        text("update scans set status = 'running' where id = :i"), {"i": scan_id}
    )
    db.commit()
    _dispatch(
        task_names.RUN_VULNERABILITY_AUDIT,
        "vulnerability_audit_continuation",
        user_id=ctx["user"],
        hosts=_browser_hosts(_stored_data(db, scan_id, 2)),
        scan_id=scan_id,
        pipeline_mode="vulnerability_audit",
        exclude_ot_from_nmap=None,
        exclude_ips=None,
    )


@scenario
def audit_phase2_reports_failure(db, ctx):
    _start(
        db,
        ctx,
        "audit_phase2_reports_failure",
        "vulnerability_audit",
        behaviour=Behaviour(p2="fail"),
    )


@scenario
def audit_phase2_raises(db, ctx):
    _start(
        db,
        ctx,
        "audit_phase2_raises",
        "vulnerability_audit",
        behaviour=Behaviour(p2="raise"),
    )


@scenario
def audit_phase3_raises(db, ctx):
    _start(
        db,
        ctx,
        "audit_phase3_raises",
        "vulnerability_audit",
        behaviour=Behaviour(p3="raise"),
    )


@scenario
def asset_cancelled_in_phase1(db, ctx):
    _start(
        db,
        ctx,
        "asset_cancelled_in_phase1",
        "asset",
        behaviour=Behaviour(p1="cancel"),
    )


@scenario
def audit_cancelled_in_phase2(db, ctx):
    _start(
        db,
        ctx,
        "audit_cancelled_in_phase2",
        "vulnerability_audit",
        behaviour=Behaviour(p2="cancel"),
    )


@scenario
def audit_broker_refuses_phase2(db, ctx):
    FAIL_DISPATCH.add(task_names.RUN_ASSET_DISCOVERY)
    _start(db, ctx, "audit_broker_refuses_phase2", "vulnerability_audit")
    FAIL_DISPATCH.clear()


@scenario
def audit_broker_refuses_phase3(db, ctx):
    FAIL_DISPATCH.add(task_names.RUN_VULNERABILITY_AUDIT)
    _start(db, ctx, "audit_broker_refuses_phase3", "vulnerability_audit")
    FAIL_DISPATCH.clear()


@scenario
def phase3_records_without_address(db, ctx):
    ctx["n"] += 1
    at(START + _dt_module.timedelta(hours=ctx["n"]))
    scan_id = "scn_golden_phase3_records_without_address"
    CURRENT["scan_id"] = scan_id
    CURRENT["behaviour"] = Behaviour()
    _new_scan(db, scan_id, ctx["n"], "vulnerability_audit", {})
    event("scenario", name="phase3_records_without_address", scan_id=scan_id)
    hosts = [copy.deepcopy(h) for h in Stored.p2_by_ip.values()]
    hosts += [
        {"is_active": True, "hostname": "no-address"},
        {"ip": "10.250.4.4", "is_active": True, "open_ports": [{"port": 80}]},
    ]
    _dispatch(
        task_names.RUN_VULNERABILITY_AUDIT,
        "vulnerability_audit_direct",
        user_id=ctx["user"],
        hosts=hosts,
        scan_id=scan_id,
        pipeline_mode="vulnerability_audit",
    )


# ── Capture ──────────────────────────────────────────────────────────────────

FULL_TABLES = ("scans", "scan_phases")

#: Columns PostgreSQL stamps with its own clock, which the frozen one cannot
#: reach: left out of the row, which is otherwise compared in full.
ARBITRARY_COLUMNS = {("audit_chain", "audit_chain_heads"): ("updated_at",)}


def capture_tables(db, out: Path) -> dict:
    tables = db.execute(
        text(
            "select table_schema, table_name from information_schema.tables "
            "where table_type = 'BASE TABLE' and table_schema not in "
            "('pg_catalog', 'information_schema') order by 1, 2"
        )
    ).all()
    digests = {}
    full_dir = out / "tables"
    full_dir.mkdir(parents=True, exist_ok=True)
    raw = db.connection().connection
    for schema, table in tables:
        qualified = f'"{schema}"."{table}"'
        digest = hashlib.sha256()
        count = 0
        keep = schema == "public" and table in FULL_TABLES
        handle = (full_dir / f"{table}.txt").open("w") if keep else None
        with raw.cursor(name=f"dump_{schema}_{table}") as cursor:
            cursor.itersize = 5000
            dropped = ARBITRARY_COLUMNS.get((schema, table))
            row_text = (
                "(to_jsonb(t) - " + " - ".join(f"'{c}'" for c in dropped) + ")::text"
                if dropped
                else "t::text"
            )
            # Names from the catalogue, not from input.
            query = f"select {row_text} from {qualified} t order by 1"  # nosec B608
            cursor.execute(query)
            for (row,) in cursor:
                digest.update(row.encode("utf-8"))
                digest.update(b"\n")
                count += 1
                if handle:
                    handle.write(row + "\n")
        if handle:
            handle.close()
        digests[f"{schema}.{table}"] = {"rows": count, "sha256": digest.hexdigest()}
    (out / "table_digests.json").write_text(jdump(digests))
    return {"tables": len(digests)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    db = SessionLocal()
    name = db.execute(text("select current_database()")).scalar()
    if not str(name).startswith(DB_PREFIX):
        print(
            f"refusing: database {name!r} is not a pipeline golden copy",
            file=sys.stderr,
        )
        return 2
    if not celery_app.conf.task_always_eager:
        print("refusing: Celery is not eager", file=sys.stderr)
        return 2

    summary = {"stored": load_stored(db)}
    ctx = {"n": 0, "user": _user_id(db)}
    events_dir = out / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    for fn in SCENARIOS:
        EVENTS.clear()
        try:
            fn(db, ctx)
        except Exception as exc:
            event("scenario_raised", error=short_error(exc))
            traceback.print_exc()
        db.rollback()
        (events_dir / f"{ctx['n']:02d}_{fn.__name__}.jsonl").write_text(
            "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in EVENTS)
        )
        summary[fn.__name__] = [
            e["event"] + (":" + e.get("task", "") if e["event"] == "dispatch" else "")
            for e in EVENTS
            if e["event"] in ("dispatch", "result", "scenario_raised")
        ]
    db.rollback()
    summary.update(capture_tables(db, out))
    db.close()
    (out / "summary.json").write_text(jdump(summary))
    print(jdump(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
