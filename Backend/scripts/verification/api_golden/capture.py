"""
API golden: drive the findings, remediation, asset and compliance APIs through
the application, on a restored copy of the database with one commit's code,
and capture every response, every message sent to the broker and what the
writes leave behind, so two commits can be compared byte for byte.

Run by ``run.sh`` inside the backend image, from one commit's ``Backend/``
tree, against a throwaway copy of the compliance golden's restored template
(the dump plus that golden's ``setup.sql``: hosts in several states, services
in each observed state, weak, expired and self-signed TLS, copied findings and
every catalogue installed). It refuses any database whose name does not start
with ``api_golden_``.

Requests go through ``main.app`` with FastAPI's test client, so routing,
dependencies, permissions, validation and serialisation are the commit's own.
Only who is signed in is supplied: the installation's platform administrator,
by overriding the identity dependency; every permission is still decided by
the RBAC engine against the restored grants. The limiter is switched off.

**The broker is real.** Celery is not eager: a dispatch is serialised by kombu
and pushed to the Redis beside the database, exactly as in production. After
each request every queue is read back and each message decoded with kombu's
own deserialiser — what a worker would receive — and recorded: task name,
arguments, keyword arguments, routing and the headers that do not name the
run (task ids are counters; the origin host is dropped). A compliance scan's
message is then run, in-process, with the arguments decoded from the broker,
the way a worker would run it. The remediation task's messages are recorded
and not run: they would open a session to a host. The encrypted credential
they carry is checked to decrypt to the posted value and recorded as that
fact, never as ciphertext or plaintext.

Captured:

``responses/``
    one file per request: the request, the status, and the body — JSON as the
    application rendered it (key order kept); a PDF as its SHA-256 (ReportLab
    in invariant mode); a DOCX or XLSX as each member's SHA-256; text as text.
``plans/``
    for the findings, remediation and asset reads, ``EXPLAIN (COSTS OFF)`` of
    every SELECT the request ran, in order.
``broker.jsonl``
    every message, in the order it was sent, with the request that sent it.
``direct/``
    the remediation section of a report, built for each organisation.
``tables/`` and ``table_digests.json``
    a SHA-256 of every table's rows, and the tables the writes touch in full.

Determinism: the clock frozen (``datetime`` and ``date`` in every first-party
module), ``random`` seeded, ``secrets``, ``uuid4`` and task ids replaced by
counters, ``PYTHONHASHSEED`` fixed by ``run.sh``, ReportLab invariant.
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt_module
import hashlib
import io
import itertools
import json
import os
import random
import sys
import traceback
import uuid
import zipfile
from pathlib import Path

BACKEND = os.path.abspath(os.getcwd())
ORG = "org_development"
OTHER_ORG = "org_self-service"
DB_PREFIX = "api_golden_"
START = _dt_module.datetime(2026, 10, 24, 12, 0, 0, tzinfo=_dt_module.timezone.utc)
JIT_PASSWORD = "golden-placeholder-not-a-credential"

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
            try:
                _patch_module(module)
            except (AttributeError, TypeError):
                # A module that refuses a patch (core.tasks, the compatibility
                # facade) holds nothing it reads itself.
                pass


def install_determinism() -> None:
    random.seed(0)
    uuid.uuid4 = lambda: uuid.UUID(hex=_spread(next(_UUIDS), 16))  # noqa: E731
    _dt_module.datetime = FrozenDatetime
    _dt_module.date = FrozenDate
    _patch_new_first_party_modules()


def tick(seconds: int = 1) -> None:
    CLOCK.now = CLOCK.now + _dt_module.timedelta(seconds=seconds)
    _patch_new_first_party_modules()


def jdump(obj) -> str:
    return json.dumps(obj, sort_keys=True, indent=1, default=str, ensure_ascii=False)


def short_error(exc: BaseException) -> str:
    first = str(exc).splitlines()[0][:300] if str(exc) else ""
    return f"{type(exc).__name__}: {first}"


# ── The application, loaded as the API loads it ────────────────────────────

import reportlab.rl_config  # noqa: E402

reportlab.rl_config.invariant = 1

import celery.app.task as celery_task_module  # noqa: E402
import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from kombu.serialization import loads as kombu_loads  # noqa: E402
from sqlalchemy import event, text  # noqa: E402

from ccure_platform.api import CurrentUser, has_permission  # noqa: E402
from ccure_platform.identity.dependencies import get_current_user  # noqa: E402
from core import compliance_frameworks  # noqa: E402
from core.celery_app import celery_app, registered_task  # noqa: E402
from core.security_crypto import decrypt_credential  # noqa: E402
from db.base import SessionLocal, engine  # noqa: E402

install_determinism()

os.environ["COMPLIANCE_ACTIVE_FRAMEWORKS"] = ",".join(
    compliance_frameworks.ALL_FRAMEWORK_IDS
)
main.app.state.limiter.enabled = False
celery_app.conf.task_always_eager = False

_REAL_APPLY_ASYNC = celery_task_module.Task.apply_async


def _counted_apply_async(self, args=None, kwargs=None, task_id=None, **options):
    return _REAL_APPLY_ASYNC(
        self,
        args,
        kwargs,
        task_id=task_id or f"golden-task-{next(_TASK_IDS):04d}",
        **options,
    )


celery_task_module.Task.apply_async = _counted_apply_async

# ── Statements, for the plans ───────────────────────────────────────────────

STATEMENTS: list = []
CAPTURING_PLANS = {"on": False}


@event.listens_for(engine, "before_cursor_execute")
def _record_statement(conn, cursor, statement, parameters, context, executemany):
    if CAPTURING_PLANS["on"] and statement.lstrip().upper().startswith("SELECT"):
        STATEMENTS.append((statement, parameters))


def explain(statements) -> str:
    raw = engine.raw_connection()
    out = []
    try:
        cursor = raw.cursor()
        for n, (statement, parameters) in enumerate(statements):
            try:
                cursor.execute("EXPLAIN (COSTS OFF) " + statement, parameters)
                plan = "\n".join(row[0] for row in cursor.fetchall())
            except Exception as exc:  # noqa: BLE001
                raw.rollback()
                plan = f"EXPLAIN failed: {short_error(exc)}"
            out.append(f"-- statement {n}\n{plan}\n")
        raw.rollback()
    finally:
        raw.close()
    return "\n".join(out)


# ── The broker ──────────────────────────────────────────────────────────────

BROKER_LOG: list = []
VOLATILE_HEADERS = ("origin",)


def _broker():
    import redis

    return redis.Redis.from_url(os.environ["CELERY_BROKER_URL"])


def _normalise_secret_kwargs(kwargs: dict, headers: dict) -> dict:
    out = {}
    for key, value in kwargs.items():
        if key.startswith("jit_enc_") and isinstance(value, str):
            try:
                same = decrypt_credential(value) == JIT_PASSWORD
            except Exception:  # noqa: BLE001
                same = False
            for name in ("argsrepr", "kwargsrepr"):
                if isinstance(headers.get(name), str):
                    headers[name] = headers[name].replace(value, "<ciphertext>")
            out[key] = {"encrypted": True, "decrypts_to_the_posted_value": same}
        else:
            out[key] = value
    return out


def drain_broker(label: str) -> list:
    """Read every queued message back, decode it as a worker would, record it."""
    client = _broker()
    received = []
    for key in sorted(client.keys("*")):
        if client.type(key) != b"list":
            continue
        for raw in client.lrange(key, 0, -1)[::-1]:  # kombu LPUSHes; oldest last
            message = json.loads(raw)
            properties = message.get("properties", {})
            body = message["body"]
            if properties.get("body_encoding") == "base64":
                body = base64.b64decode(body)
            args, kwargs, embed = kombu_loads(
                body, message["content-type"], message["content-encoding"]
            )
            headers = dict(message.get("headers", {}))
            for volatile in VOLATILE_HEADERS:
                headers.pop(volatile, None)
            kwargs = _normalise_secret_kwargs(kwargs, headers)
            properties = {
                k: v
                for k, v in properties.items()
                if k not in ("delivery_tag", "reply_to")
            }
            received.append(
                {
                    "request": label,
                    "queue": key.decode(),
                    "content_type": message["content-type"],
                    "content_encoding": message["content-encoding"],
                    "args": args,
                    "kwargs": kwargs,
                    "embed": embed,
                    "headers": headers,
                    "properties": properties,
                }
            )
        client.delete(key)
    BROKER_LOG.extend(received)
    return received


def run_as_worker(message: dict) -> str:
    """Run a compliance scan from its decoded message, in-process."""
    task = registered_task(message["headers"]["task"])
    result = task.apply(
        args=message["args"], kwargs=message["kwargs"], task_id=message["headers"]["id"]
    )
    return f"{result.status}: {short_error(result.result) if result.failed() else ''}"


# ── Requests ────────────────────────────────────────────────────────────────

SEQ = itertools.count(1)
OUT: Path = Path(".")
CLIENT: TestClient = None  # type: ignore[assignment]
USER_DB = None


def _body_record(response) -> dict:
    ctype = response.headers.get("content-type", "")
    data = response.content
    if "application/json" in ctype:
        try:
            return {"json": json.loads(data)}
        except ValueError:
            return {"text": response.text}
    if ctype.startswith("text/"):
        return {"text": response.text}
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return {
                "zip": {
                    name: hashlib.sha256(archive.read(name)).hexdigest()
                    for name in sorted(archive.namelist())
                }
            }
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def call(label, method, path, *, params=None, json_body=None, files=None, plans=False):
    n = next(SEQ)
    STATEMENTS.clear()
    CAPTURING_PLANS["on"] = plans
    record = {
        "request": {
            "method": method,
            "path": path,
            "params": params,
            "json": json_body,
            "files": sorted(files) if files else None,
        }
    }
    response = None
    try:
        response = CLIENT.request(
            method, path, params=params, json=json_body, files=files
        )
        record["status"] = response.status_code
        record["content_disposition"] = response.headers.get("content-disposition")
        record.update(_body_record(response))
    except Exception as exc:  # noqa: BLE001
        record["raised"] = short_error(exc)
        traceback.print_exc()
    finally:
        CAPTURING_PLANS["on"] = False
    # Read the queues back, run any compliance scan as a worker would, and
    # read again: a task run that way may queue messages of its own.
    record["broker"] = []
    ran = []
    messages = drain_broker(label)
    while messages:
        record["broker"] += [m["headers"].get("task") for m in messages]
        for message in messages:
            if message["headers"].get("task") == "compliance.run_scan":
                ran.append(run_as_worker(message))
        messages = drain_broker(label)
    if ran:
        record["worker_ran"] = ran
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)[:90]
    (OUT / "responses" / f"{n:03d}_{safe}.json").write_text(
        json.dumps(record, indent=1, default=str, ensure_ascii=False)
    )
    if plans:
        (OUT / "plans" / f"{n:03d}_{safe}.txt").write_text(explain(list(STATEMENTS)))
    tick()
    return response


def get(label, path, params=None, plans=False):
    return call(label, "GET", path, params=params, plans=plans)


def body_of(response):
    try:
        return response.json()
    except Exception:  # noqa: BLE001
        return None


# ── Inputs added to the copy before anything runs ───────────────────────────

SETUP_OTHER_ORG = """
INSERT INTO assets
SELECT (jsonb_populate_record(NULL::assets, to_jsonb(src) || jsonb_build_object(
  'id', 'ast_api_other', 'org_id', 'org_self-service', 'ip_address', '10.250.0.21',
  'mac_address', NULL, 'hostname', 'api-other'))).*
FROM (SELECT * FROM assets WHERE id = 'ast_g4_lnx') src;

INSERT INTO services
SELECT (jsonb_populate_record(NULL::services, to_jsonb(s) || jsonb_build_object(
  'id', 'svc_api_' || s.id, 'asset_id', 'ast_api_other'))).*
FROM services s WHERE s.asset_id = 'ast_g4_lnx';

INSERT INTO tls_details (service_id, is_enabled, protocol_version, cert_is_expired,
  cert_is_self_signed, cert_san_domains, is_weak_cipher, issues, created_at)
SELECT 'svc_api_' || t.service_id, t.is_enabled, t.protocol_version, t.cert_is_expired,
  t.cert_is_self_signed, t.cert_san_domains, t.is_weak_cipher, t.issues, t.created_at
FROM tls_details t WHERE t.service_id = 'svc_g4_lnx_443';

INSERT INTO asset_vulnerabilities
SELECT (jsonb_populate_record(NULL::asset_vulnerabilities, to_jsonb(v) || jsonb_build_object(
  'id', 'apio_' || v.id, 'asset_id', 'ast_api_other', 'org_id', 'org_self-service',
  'service_id', NULL))).*
FROM (SELECT * FROM asset_vulnerabilities WHERE asset_id = 'ast_g4_lnx'
      ORDER BY id LIMIT 25) v;
"""


def setup_other_org(db) -> None:
    db.execute(text(SETUP_OTHER_ORG))
    db.commit()


def remediable_findings(db, n: int) -> list:
    """Failing compliance findings whose rule has an automated fix, giving one
    to the first failing findings that lack it so every dispatch path runs."""
    rows = db.execute(
        text(
            "select f.id, r.id from compliance_findings f "
            "join compliance_remediations r on r.rule_id = f.rule_id "
            "where f.tenant_id = :org and f.status = 'fail' "
            "and r.fix_command is not null order by f.id limit :n"
        ),
        {"org": ORG, "n": n},
    ).all()
    if len(rows) < n:
        missing = db.execute(
            text(
                "select f.id, f.rule_id from compliance_findings f "
                "where f.tenant_id = :org and f.status = 'fail' and not exists ("
                " select 1 from compliance_remediations r where r.rule_id = f.rule_id"
                " and r.fix_command is not null) order by f.id limit :n"
            ),
            {"org": ORG, "n": n - len(rows)},
        ).all()
        template = db.execute(
            text(
                "select id from compliance_remediations "
                "where fix_command is not null order by id limit 1"
            )
        ).scalar()
        for k, (finding_id, rule_id) in enumerate(missing):
            db.execute(
                text(
                    "insert into compliance_remediations select (jsonb_populate_record("
                    "null::compliance_remediations, to_jsonb(r) || jsonb_build_object("
                    "'id', :id, 'rule_id', :rule))).* "
                    "from compliance_remediations r where r.id = :template"
                ),
                {"id": f"crm_api_golden_{k}", "rule": rule_id, "template": template},
            )
        db.commit()
        return remediable_findings(db, n)
    return [(f, r) for f, r in rows]


# ── The scenarios ───────────────────────────────────────────────────────────


def ids(db, sql, **params) -> list:
    return [row[0] for row in db.execute(text(sql), params).all()]


def findings_reads(db) -> None:
    assets = ids(db, "select id from assets where org_id = :o order by id", o=ORG)
    sample = ids(
        db,
        "select id from asset_vulnerabilities where org_id = :o order by id limit 12",
        o=ORG,
    )
    other = ids(
        db,
        "select id from asset_vulnerabilities where org_id = :o order by id limit 2",
        o=OTHER_ORG,
    )
    scan = ids(
        db,
        "select scan_id from asset_vulnerabilities where org_id = :o "
        "group by scan_id order by scan_id limit 1",
        o=ORG,
    )
    variants = [
        ("default", {}),
        ("all_statuses", {"status": "open,fixed,accepted", "limit": 500}),
        (
            "crit_high_cvss",
            {"severity": "critical,high", "sort_by": "cvss", "limit": 100},
        ),
        ("first_found_page2", {"sort_by": "first_found", "skip": 50, "limit": 50}),
        ("search_ip", {"search": "10.250", "limit": 200}),
        ("search_cve", {"search": "CVE-2024", "limit": 100}),
        ("search_ip_live", {"search": "10.180.6.45", "limit": 100}),
        ("kev", {"in_kev": "true", "limit": 200}),
        ("priority", {"priority": "CRITICAL,HIGH", "limit": 200}),
        ("fix_none", {"fix_state": "no_fix_released", "limit": 100}),
        ("fix_released", {"fix_state": "fix_released", "limit": 100}),
        ("fix_unrecorded", {"fix_state": "not_recorded", "limit": 100}),
        ("scan", {"scan_id": scan[0] if scan else "none", "limit": 100}),
        ("other_org", {"org_id": OTHER_ORG, "limit": 500}),
        ("other_org_search", {"org_id": OTHER_ORG, "search": "10.250.0.21"}),
    ] + [(f"asset_{a}", {"asset_id": a, "limit": 200}) for a in assets]
    for name, params in variants:
        get(f"findings_{name}", "/findings", params, plans=True)
    for name, params in [
        ("default", {}),
        ("all", {"status": "open,fixed,accepted", "limit": 500}),
        ("critical", {"severity": "critical", "limit": 100}),
        ("page2", {"skip": 10, "limit": 10}),
        ("other_org", {"org_id": OTHER_ORG}),
    ] + [(f"asset_{a}", {"asset_id": a}) for a in assets]:
        get(f"grouped_{name}", "/findings/grouped/by-component", params, plans=True)
    for fid in sample + other + ["fnd_does_not_exist"]:
        get(f"finding_{fid}", f"/findings/{fid}", plans=True)
    for fid in other:
        get(f"finding_other_{fid}", f"/findings/{fid}", {"org_id": OTHER_ORG})


def remediation_reads(db) -> None:
    assets = ids(db, "select id from assets where org_id = :o order by id", o=ORG)
    sample = ids(
        db,
        "select id from asset_vulnerabilities where org_id = :o "
        "and status = 'open' order by id limit 5",
        o=ORG,
    )
    get("rem_summary", "/remediation/summary", plans=True)
    for a in assets:
        get(f"rem_summary_{a}", "/remediation/summary", {"asset_id": a}, plans=True)
    get("rem_summary_other", "/remediation/summary", {"org_id": OTHER_ORG}, plans=True)
    for path in ("/remediation/overdue", "/remediation/pending-verification"):
        get(f"rem_{path.rsplit('/', 1)[1]}", path, {"limit": 100}, plans=True)
        get(f"rem_{path.rsplit('/', 1)[1]}_page", path, {"limit": 5, "offset": 5})
    for fid in sample + ["fnd_does_not_exist"]:
        get(f"rem_finding_{fid}", f"/remediation/findings/{fid}", plans=True)
        get(f"rem_history_{fid}", f"/remediation/findings/{fid}/history")
    other = ids(
        db,
        "select id from asset_vulnerabilities where org_id = :o order by id limit 1",
        o=OTHER_ORG,
    )
    for fid in other:
        get(f"rem_finding_cross_{fid}", f"/remediation/findings/{fid}")
    get("rem_sla", "/remediation/sla-policy")


def asset_reads(db) -> None:
    assets = ids(db, "select id from assets where org_id = :o order by id", o=ORG)
    get("assets_list", "/assets", plans=True)
    get("assets_list_other", "/assets", {"org_id": OTHER_ORG}, plans=True)
    for a in assets + ["ast_api_other", "ast_does_not_exist"]:
        get(f"asset_{a}", f"/assets/{a}", plans=True)
        get(f"asset_services_{a}", f"/assets/{a}/services", plans=True)
        for status in (None, "open", "fixed,accepted"):
            get(
                f"asset_findings_{a}_{status}",
                f"/assets/{a}/findings",
                {"status": status} if status else None,
                plans=True,
            )
    for sort_by in ("grade", "expiration", "port", "ip_address", "hostname", "x"):
        for sort_dir in ("asc", "desc"):
            get(
                f"certs_{sort_by}_{sort_dir}",
                "/assets/certificates",
                {"sort_by": sort_by, "sort_dir": sort_dir},
                plans=True,
            )
    for name, params in [
        ("search_tls", {"search": "TLS"}),
        ("search_ip", {"search": "10.250"}),
        ("search_host", {"search": "g4"}),
        ("page", {"skip": 1, "limit": 1}),
        ("other_org", {"org_id": OTHER_ORG}),
    ]:
        get(f"certs_{name}", "/assets/certificates", params, plans=True)
    services_seen = []
    for sort_by in ("asset_count", "port", "protocol", "service_name", "last_seen"):
        for sort_dir in ("asc", "desc"):
            r = get(
                f"services_{sort_by}_{sort_dir}",
                "/assets/services",
                {"sort_by": sort_by, "sort_dir": sort_dir, "limit": 500},
                plans=True,
            )
            if sort_by == "port" and sort_dir == "asc":
                services_seen = (body_of(r) or {}).get("services", [])
    for name, params in [
        ("search", {"search": "ssh"}),
        ("port", {"port": 443}),
        ("protocol", {"protocol": "udp"}),
        ("asset_type", {"asset_type": "server"}),
        ("subnet", {"subnet": "10."}),
        ("page", {"skip": 2, "limit": 3}),
        ("other_org", {"org_id": OTHER_ORG}),
    ]:
        get(f"services_{name}", "/assets/services", params, plans=True)
    for s in services_seen:
        sig = f"{s['service_name']}_{s['port']}_{s['protocol']}"
        get(
            f"service_hosts_{sig}",
            "/assets/services/assets",
            {
                "service_name": s["service_name"],
                "port": s["port"],
                "protocol": s["protocol"],
            },
            plans=True,
        )
    for name, params in [
        (
            "search",
            {"service_name": "ssh", "port": 22, "protocol": "tcp", "search": "g4"},
        ),
        ("unknown", {"service_name": "unknown", "port": 631, "protocol": "udp"}),
        (
            "other_org",
            {"service_name": "ssh", "port": 22, "protocol": "tcp", "org_id": OTHER_ORG},
        ),
    ]:
        get(f"service_hosts_{name}", "/assets/services/assets", params, plans=True)


def findings_writes(db) -> None:
    open_ids = ids(
        db,
        "select id from asset_vulnerabilities where org_id = :o and status = 'open' "
        "order by id limit 6",
        o=ORG,
    )
    a, b, c, d, e, f = open_ids
    call(
        "status_fixed", "PATCH", f"/findings/{a}/status", json_body={"status": "fixed"}
    )
    call(
        "status_accepted",
        "PATCH",
        f"/findings/{b}/status",
        json_body={"status": "accepted", "accepted_risk_reason": "golden"},
    )
    call("status_open", "PATCH", f"/findings/{a}/status", json_body={"status": "open"})
    call("status_bad", "PATCH", f"/findings/{c}/status", json_body={"status": "nope"})
    call(
        "status_other_org",
        "PATCH",
        "/findings/apio_does_not_exist/status",
        json_body={"status": "fixed"},
    )
    call(
        "notes", "PATCH", f"/findings/{c}/notes", json_body={"remediation_notes": " n "}
    )
    call("rem_assign", "POST", "/remediation/assign", json_body={"finding_ids": [c, d]})
    call(
        "rem_state",
        "PATCH",
        f"/remediation/findings/{d}/state",
        json_body={"state": "in_remediation", "note": "golden"},
    )
    call(
        "rem_note", "POST", f"/remediation/findings/{d}/notes", json_body={"note": "g"}
    )
    call(
        "rem_accept",
        "POST",
        f"/remediation/findings/{e}/accept-risk",
        json_body={"reason": "golden"},
    )
    call(
        "rem_withdraw",
        "POST",
        f"/remediation/findings/{e}/withdraw-acceptance",
        json_body={},
    )
    call(
        "rem_state_verified",
        "PATCH",
        f"/remediation/findings/{f}/state",
        json_body={"state": "verified_fixed"},
    )
    for asset in ids(db, "select id from assets where org_id = :o order by id", o=ORG):
        get(f"after_writes_asset_{asset}", f"/assets/{asset}")
    get("after_writes_summary", "/remediation/summary")


def compliance(db) -> None:
    get("marketplace", "/compliance/marketplace")
    frameworks = [
        row[0]
        for row in db.execute(
            text(
                "select framework_id from compliance_tenant_frameworks "
                "where tenant_id = :o and is_enabled order by framework_id"
            ),
            {"o": ORG},
        ).all()
    ]
    policies = {}
    for fw in frameworks:
        r = get(f"policies_{fw}", "/compliance/policies", {"framework_id": fw})
        rows = (body_of(r) or {}).get("data", [])
        if rows:
            policies[fw] = rows[0]["id"]
    for fw, policy in sorted(policies.items())[:3]:
        get(f"policy_rules_{fw}", f"/compliance/policies/{policy}/rules")
    get("scans_before", "/compliance/scans")
    get("summary_before", "/compliance/summary")

    # One scan of every catalogue with a policy, through the broker.
    for fw, policy in sorted(policies.items()):
        call(
            f"scan_{fw}",
            "POST",
            "/compliance/scans",
            json_body={"framework_id": fw, "policy_id": policy},
        )
    call(
        "scan_scoped",
        "POST",
        "/compliance/scans",
        json_body={
            "framework_id": "cfw_iso27001_2022",
            "policy_id": policies.get("cfw_iso27001_2022", "none"),
            "asset_ids": ["ast_g4_win"],
        },
    )
    call(
        "scan_bad_policy",
        "POST",
        "/compliance/scans",
        json_body={"framework_id": "cfw_iso27001_2022", "policy_id": "nope"},
    )
    r = get("scans_after", "/compliance/scans", {"limit": 100})
    for run in (body_of(r) or {}).get("data", [])[:3]:
        get(f"scan_run_{run['id']}", f"/compliance/scans/{run['id']}")
    for fw in frameworks:
        get(
            f"findings_{fw}",
            "/compliance/findings",
            {"framework_id": fw, "limit": 1000},
        )
        get(f"controls_{fw}", f"/compliance/frameworks/{fw}/controls")
        get(f"summary_{fw}", "/compliance/summary", {"framework_id": fw})
    get(
        "controls_iso_filtered",
        "/compliance/frameworks/cfw_iso27001_2022/controls",
        {"status": "fail", "theme": "TECHNOLOGICAL", "search": "A.8"},
    )
    get("summary_all", "/compliance/summary")
    for src, dst in [
        ("cfw_iso27001_2022", "cfw_nist_csf_v2"),
        ("cfw_nist_csf_v2", "cfw_iso27001_2022"),
        ("cfw_iso27001_2022", None),
    ]:
        params = {"source_framework_id": src}
        if dst:
            params["target_framework_id"] = dst
        get(f"gap_{src}_{dst}", "/compliance/gap-analysis", params)

    reports(frameworks)
    attestation_and_evidence(db)
    schedules_and_policies(db, policies)
    credentials()
    remediation(db)
    exceptions(db)
    get("marketplace_after", "/compliance/marketplace")
    get("scans_final", "/compliance/scans", {"limit": 100})
    get("summary_final", "/compliance/summary")


def reports(frameworks) -> None:
    for fmt in ("pdf", "docx"):
        for fw in frameworks:
            get(
                f"soa_{fw}_{fmt}",
                "/compliance/reports/soa",
                {"fmt": fmt, "framework_id": fw},
            )
        get(f"nist_csf_{fmt}", "/compliance/reports/nist_csf", {"fmt": fmt})
        get(
            f"nist_csf_gv_{fmt}",
            "/compliance/reports/nist_csf",
            {"fmt": fmt, "functions": "GV,PR"},
        )
        get(f"cis_{fmt}", "/compliance/reports/cis_v8_1", {"fmt": fmt})
        get(f"cis_ig1_{fmt}", "/compliance/reports/cis_v8_1", {"fmt": fmt, "ig": "IG1"})
        get(f"soc2_{fmt}", "/compliance/reports/soc2_type2", {"fmt": fmt})
        get(f"cert_in_{fmt}", "/compliance/reports/cert_in_2022", {"fmt": fmt})
        get(f"pci_{fmt}", "/compliance/reports/pci_dss_v4", {"fmt": fmt})
        get(
            f"pci_cde_{fmt}",
            "/compliance/reports/pci_dss_v4",
            {"fmt": fmt, "cde_scope_only": "true"},
        )
        get(f"dpdp_{fmt}", "/compliance/reports/dpdp_2023", {"fmt": fmt})
        get(f"gdpr_{fmt}", "/compliance/reports/gdpr", {"fmt": fmt})
        get(f"nist_800_53_{fmt}", "/compliance/reports/nist_800_53_r5", {"fmt": fmt})
        get(
            f"nist_800_53_low_{fmt}",
            "/compliance/reports/nist_800_53_r5",
            {"fmt": fmt, "impact_level": "low"},
        )
        get(f"iec_62443_{fmt}", "/compliance/reports/iec_62443", {"fmt": fmt})
        get(f"nist_800_82_{fmt}", "/compliance/reports/nist_800_82", {"fmt": fmt})
        get(f"nerc_cip_{fmt}", "/compliance/reports/nerc_cip", {"fmt": fmt})
        get(f"nis2_{fmt}", "/compliance/reports/nis2", {"fmt": fmt})
    get("executive", "/compliance/reports/executive")
    get("soa_bad_fmt", "/compliance/reports/soa", {"fmt": "xml"})
    get("nist_csf_bad_function", "/compliance/reports/nist_csf", {"functions": "ZZ"})


PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def attestation_and_evidence(db) -> None:
    controls = ids(
        db,
        "select c.id from compliance_controls c where c.framework_id = "
        "'cfw_iso27001_2022' order by c.id limit 3",
    )
    first, second, third = controls
    r = call(
        "evidence_upload",
        "POST",
        f"/compliance/controls/{first}/evidence",
        files={"file": ("policy.pdf", PDF, "application/pdf")},
    )
    file_id = (body_of(r) or {}).get("id")
    call(
        "evidence_upload_mismatch",
        "POST",
        f"/compliance/controls/{first}/evidence",
        files={"file": ("x.pdf", b"MZ\x90\x00not a pdf", "application/pdf")},
    )
    get("evidence_list", f"/compliance/controls/{first}/evidence")
    if file_id:
        get("evidence_download", f"/compliance/evidence/{file_id}/download")
    call(
        "attest_pass",
        "POST",
        f"/compliance/controls/{first}/attest",
        json_body={
            "status": "pass",
            "note": "golden",
            "evidence_file_ids": [file_id] if file_id else None,
        },
    )
    call(
        "attest_na_without_reason",
        "POST",
        f"/compliance/controls/{second}/attest",
        json_body={"status": "not_applicable"},
    )
    call(
        "attest_na",
        "POST",
        f"/compliance/controls/{second}/attest",
        json_body={"status": "not_applicable", "justification": "golden reason"},
    )
    call(
        "attest_fail",
        "POST",
        f"/compliance/controls/{third}/attest",
        json_body={"status": "fail"},
    )
    if file_id:
        call("evidence_delete", "DELETE", f"/compliance/evidence/{file_id}")
    get("evidence_list_after", f"/compliance/controls/{first}/evidence")
    get("controls_after_attest", "/compliance/frameworks/cfw_iso27001_2022/controls")


def schedules_and_policies(db, policies) -> None:
    iso = policies.get("cfw_iso27001_2022", "none")
    r = call(
        "schedule_create",
        "POST",
        "/compliance/schedules",
        json_body={
            "framework_id": "cfw_iso27001_2022",
            "policy_id": iso,
            "frequency": "weekly",
        },
    )
    schedule = (body_of(r) or {}).get("schedule_id")
    call(
        "schedule_create_bad",
        "POST",
        "/compliance/schedules",
        json_body={
            "framework_id": "cfw_iso27001_2022",
            "policy_id": iso,
            "frequency": "hourly",
        },
    )
    get("schedules", "/compliance/schedules")
    if schedule:
        call(
            "schedule_patch",
            "PATCH",
            f"/compliance/schedules/{schedule}",
            json_body={"frequency": "monthly", "is_active": False},
        )
        call("schedule_delete", "DELETE", f"/compliance/schedules/{schedule}")
    get("schedules_after", "/compliance/schedules")
    rules = ids(
        db,
        "select r.id from compliance_rules r join compliance_rule_controls rc on "
        "rc.rule_id = r.id join compliance_controls c on c.id = rc.control_id where "
        "c.framework_id = 'cfw_iso27001_2022' and r.status = 'active' "
        "group by r.id order by r.id limit 3",
    )
    call(
        "policy_create",
        "POST",
        "/compliance/policies",
        json_body={
            "framework_id": "cfw_iso27001_2022",
            "name": "Golden policy",
            "target_platform": "any",
            "rule_ids": rules,
        },
    )
    get("policies_after", "/compliance/policies", {"framework_id": "cfw_iso27001_2022"})
    if rules:
        call(
            "rule_update",
            "PUT",
            f"/compliance/rules/{rules[0]}",
            json_body={
                "check_definition": {"key": "x", "operator": "eq", "value": 1},
                "severity": "high",
                "severity_weight": 3,
            },
        )
    call("uninstall_gdpr", "POST", "/compliance/marketplace/cfw_gdpr/uninstall")
    get("report_after_uninstall", "/compliance/reports/gdpr", {"fmt": "pdf"})
    call("install_gdpr", "POST", "/compliance/marketplace/cfw_gdpr/install")
    call("install_unknown", "POST", "/compliance/marketplace/cfw_nope/install")


def credentials() -> None:
    r = call(
        "credential_create",
        "POST",
        "/compliance/credentials",
        json_body={"name": "golden", "username": "golden", "password": JIT_PASSWORD},
    )
    get("credentials", "/compliance/credentials")
    cred = (body_of(r) or {}).get("id")
    if cred:
        call("credential_delete", "DELETE", f"/compliance/credentials/{cred}")
    call("credential_delete_unknown", "DELETE", "/compliance/credentials/cred_nope")


def _jit(bypass: bool) -> dict:
    return {
        "action": "apply_script",
        "jit_credentials": {"username": "golden", "password": JIT_PASSWORD},
        "emergency_bypass": bypass,
    }


def remediation(db) -> None:
    targets = remediable_findings(db, 3)
    rollback_target = rollbackable_finding(db)
    get("remediation_requests_before", "/compliance/remediations/requests")
    if len(targets) < 3 or rollback_target is None:
        print("not every remediation path is reachable here", file=sys.stderr)
        return
    (f1, _), (f2, _), (f3, r3) = targets
    f4, r4 = rollback_target
    # Dispatch 1: an emergency bypass.
    call(
        "remediate_bypass",
        "POST",
        f"/compliance/findings/{f1}/remediate",
        json_body=_jit(True),
    )
    call(
        "remediate_not_failing",
        "POST",
        f"/compliance/findings/{f1}/remediate",
        json_body=_jit(False),
    )
    # A request ticket; its own requester may not approve it.
    r = call(
        "remediate_request",
        "POST",
        f"/compliance/findings/{f2}/remediate",
        json_body=_jit(False),
    )
    own = (body_of(r) or {}).get("request_id")
    if own:
        call(
            "approve_own",
            "POST",
            f"/compliance/remediations/requests/{own}/approve",
            json_body={"status": "approved"},
        )
        call("cancel_own", "POST", f"/compliance/remediations/requests/{own}/cancel")
    # Inputs: a request whose requester has since been purged, and one executed.
    db.execute(
        text(
            "insert into compliance_remediation_requests (id, tenant_id, finding_id, "
            "remediation_id, requested_by, status, emergency_bypass, username, "
            "encrypted_password, port, auth_method, created_at) values "
            "('crrq_api_pending', :o, :f3, :r3, null, 'pending_approval', false, "
            "'golden', :enc, 22, 'password', '2026-10-24T11:00:00Z'), "
            "('crrq_api_executed', :o, :f4, :r4, null, 'executed', false, "
            "'golden', :enc, 22, 'password', '2026-10-24T11:00:00Z')"
        ),
        {"o": ORG, "f3": f3, "r3": r3, "f4": f4, "r4": r4, "enc": _encrypted()},
    )
    db.execute(
        text(
            "update compliance_findings set status = 'pending_reverify' where id = :f"
        ),
        {"f": f3},
    )
    db.commit()
    get("remediation_requests", "/compliance/remediations/requests")
    get(
        "remediation_requests_pending",
        "/compliance/remediations/requests",
        {"status": "pending_approval"},
    )
    # Dispatch 2: an approval by someone other than the requester.
    call(
        "approve",
        "POST",
        "/compliance/remediations/requests/crrq_api_pending/approve",
        json_body={"status": "approved"},
    )
    call(
        "approve_again",
        "POST",
        "/compliance/remediations/requests/crrq_api_pending/approve",
        json_body={"status": "approved"},
    )
    # A rollback through the queue, then dispatch 3: one by emergency bypass.
    rb = {k: v for k, v in _jit(False).items() if k != "action"}
    call(
        "rollback_request",
        "POST",
        "/compliance/remediations/requests/crrq_api_executed/rollback",
        json_body=rb,
    )
    db.execute(
        text(
            "delete from compliance_remediation_requests where id <> 'crrq_api_executed' "
            "and id <> 'crrq_api_pending' and status = 'pending_approval' "
            "and finding_id = :f4"
        ),
        {"f4": f4},
    )
    db.commit()
    call(
        "rollback_bypass",
        "POST",
        "/compliance/remediations/requests/crrq_api_executed/rollback",
        json_body={**rb, "emergency_bypass": True},
    )
    call(
        "rollback_not_executed",
        "POST",
        "/compliance/remediations/requests/crrq_api_pending/rollback",
        json_body={**rb, "emergency_bypass": True},
    )
    get("remediation_requests_after", "/compliance/remediations/requests")


def rollbackable_finding(db):
    """A compliance finding whose rule family has a rollback script, with an
    automated fix for its rule (given one, as above, if it lacks it)."""
    from core.compliance_tasks import ROLLBACK_COMMANDS

    row = db.execute(
        text(
            "select f.id, f.rule_id from compliance_findings f join compliance_rules r "
            "on r.id = f.rule_id where f.tenant_id = :org and "
            "r.rule_family_code = any(:families) order by f.id limit 1"
        ),
        {"org": ORG, "families": sorted(ROLLBACK_COMMANDS)},
    ).first()
    if row is None:
        return None
    finding_id, rule_id = row
    remediation = db.execute(
        text(
            "select id from compliance_remediations where rule_id = :r "
            "and fix_command is not null order by id limit 1"
        ),
        {"r": rule_id},
    ).scalar()
    if remediation is None:
        remediation = "crm_api_golden_rollback"
        db.execute(
            text(
                "insert into compliance_remediations select (jsonb_populate_record("
                "null::compliance_remediations, to_jsonb(r) || jsonb_build_object("
                "'id', :id, 'rule_id', :rule))).* from compliance_remediations r "
                "where r.id = (select id from compliance_remediations "
                "where fix_command is not null order by id limit 1)"
            ),
            {"id": remediation, "rule": rule_id},
        )
        db.commit()
    return finding_id, remediation


def _encrypted() -> str:
    from core.security_crypto import encrypt_credential

    return encrypt_credential(JIT_PASSWORD)


def exceptions(db) -> None:
    failing = ids(
        db,
        "select id from compliance_findings where tenant_id = :o and status = 'fail' "
        "order by id offset 4 limit 1",
        o=ORG,
    )
    if not failing:
        return
    r = call(
        "exception_request",
        "POST",
        f"/compliance/findings/{failing[0]}/exception",
        json_body={
            "reason": "golden compensating",
            "expires_at": "2027-01-01T00:00:00Z",
        },
    )
    exc_id = (body_of(r) or {}).get("exception_id")
    call(
        "exception_request_short",
        "POST",
        f"/compliance/findings/{failing[0]}/exception",
        json_body={"reason": "short", "expires_at": "2027-01-01T00:00:00Z"},
    )
    if exc_id:
        call(
            "exception_approve",
            "PATCH",
            f"/compliance/exceptions/{exc_id}",
            json_body={"status": "approved"},
        )
    get(
        "findings_after_exception",
        "/compliance/findings",
        {"framework_id": "cfw_iso27001_2022", "status": "exception"},
    )


def direct(db, out: Path) -> None:
    from core.remediation import remediation_report_payload

    folder = out / "direct"
    folder.mkdir(parents=True, exist_ok=True)
    for org in (ORG, OTHER_ORG):
        try:
            payload = remediation_report_payload(db, org_id=org, verification=None)
        except Exception as exc:  # noqa: BLE001
            payload = {"raised": short_error(exc)}
        (folder / f"remediation_report_{org}.json").write_text(jdump(payload))
    db.rollback()


# ── Tables ──────────────────────────────────────────────────────────────────

FULL_TABLES = (
    "assets",
    "asset_vulnerabilities",
    "finding_remediation_events",
    "compliance_findings",
    "compliance_finding_history",
    "compliance_scan_runs",
    "compliance_scores",
    "compliance_remediation_requests",
    "compliance_exceptions",
    "compliance_evidence_files",
    "compliance_scan_schedules",
    "compliance_policies",
    "compliance_policy_rules",
    "compliance_tenant_frameworks",
)

#: Columns no frozen clock or counter reaches, left out of the row, which is
#: otherwise compared in full: the time PostgreSQL stamps on an audit chain
#: head, and a credential's ciphertext (encryption draws a fresh nonce; the
#: broker record checks it decrypts to the posted value instead).
ARBITRARY_COLUMNS = {
    ("audit_chain", "audit_chain_heads"): ("updated_at",),
    ("public", "compliance_remediation_requests"): (
        "encrypted_password",
        "encrypted_key_content",
    ),
}


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


def _platform_administrator(db):
    """The first active account the RBAC engine grants everything here; kept
    attached to a session of its own for the whole run."""
    for user in (
        db.query(CurrentUser)
        .filter(CurrentUser.is_active.is_(True))
        .order_by(CurrentUser.created_at, CurrentUser.id)
        .all()
    ):
        if has_permission(db, user, "audit.compliance.manage_frameworks"):
            return user
    raise SystemExit("no platform administrator in the restored copy")


def main_() -> int:
    global OUT, CLIENT
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    OUT = Path(args.out)
    for sub in ("responses", "plans"):
        (OUT / sub).mkdir(parents=True, exist_ok=True)

    db = SessionLocal()
    name = db.execute(text("select current_database()")).scalar()
    if not str(name).startswith(DB_PREFIX):
        print(f"refusing: database {name!r} is not an API golden copy", file=sys.stderr)
        return 2
    if celery_app.conf.task_always_eager:
        print("refusing: Celery is eager; the broker must be real", file=sys.stderr)
        return 2
    _broker().flushall()

    setup_other_org(db)
    global USER_DB
    USER_DB = SessionLocal()
    user = _platform_administrator(USER_DB)
    main.app.dependency_overrides[get_current_user] = lambda: user
    CLIENT = TestClient(main.app, raise_server_exceptions=True)

    summary = {}
    for step in (
        findings_reads,
        remediation_reads,
        asset_reads,
        findings_writes,
        compliance,
    ):
        try:
            step(db)
        except Exception as exc:  # noqa: BLE001
            summary[f"{step.__name__}_raised"] = short_error(exc)
            traceback.print_exc()
        db.rollback()
    direct(db, OUT)
    (OUT / "broker.jsonl").write_text(
        "".join(
            json.dumps(m, ensure_ascii=False, default=str) + "\n" for m in BROKER_LOG
        )
    )
    summary["requests"] = next(SEQ) - 1
    summary["broker_messages"] = [m["headers"].get("task") for m in BROKER_LOG]
    summary.update(capture_tables(db, OUT))
    db.close()
    (OUT / "summary.json").write_text(jdump(summary))
    print(jdump(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main_())
