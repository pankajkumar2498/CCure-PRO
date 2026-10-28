"""
Findings golden: replay stored scan payloads through the findings write paths
on a restored copy of the database, and capture everything those writes
decide, so two commits can be compared byte for byte.

Run by ``run.sh`` inside the backend image, from one commit's ``Backend/``
tree, against a throwaway copy of a restored dump. It refuses any database
whose name does not start with ``findings_golden_``.

Three modes, each on its own copy:

``asis``
    The restored data as it stands. Exports and scan comparisons are read;
    each vulnerability audit's remediation verification and the Audit purge
    hook are computed in a transaction that is rolled back.
``on_top``
    Every stored phase payload replayed, in time order, over the restored
    rows: the upsert paths, re-detection, the fixed sweep.
``from_empty``
    The organisation's assets deleted first (and with them services, TLS and
    HTTP details, findings, the asset change log and remediation events), then
    the same replay: the history rebuilt by the code under test.

Both replay modes run, at each event's own time:

* each phase's ``_phase_data`` through ``sync_host_discovery``,
  ``sync_asset_discovery`` or ``sync_vulnerability_audit``, as
  ``create_completed_scan`` dispatches them by phase order;
* after a vulnerability audit, the comparison against its baseline and
  ``verify_scan``;
* for every host of a vulnerability audit that carried a credentialed report,
  synthetic standalone credentialed scans: ``_sync_credentialed_asset_identity``
  with the host's credentialed findings, then the SLA, the comparison and
  ``verify_from_comparison``, as the standalone task runs them. Synthetic: the
  stored data holds no standalone credentialed scan, so the inputs are built
  from the pipeline's host record. It exercises that write path with real
  shapes; the live harness covers the task itself. Three of them per host:
  every credentialed finding; then four in five, chosen by identifier, so the
  sweep retires the rest; then every finding again, so those reappear and
  verification reopens them.

Captured, after the replay, with the clock frozen:

* a SHA-256 of every table's rows (``SELECT t::text … ORDER BY 1``), and the
  findings-related tables in full;
* for every scan: the comparison, the whole-scan workbook
  (``routers.reports._build_scan_workbook``), the export endpoint's JSON and
  each dataset's CSV, and the legacy findings CSV, rendered as the routes
  render them;
* the verification outcomes and comparisons recorded during the replay.

Determinism: the clock (``datetime.datetime`` / ``date`` everywhere, openpyxl's
document properties and the ZIP entry times) is frozen to each event's time;
``random`` is seeded; ``secrets`` and ``uuid4`` are replaced by counters;
``PYTHONHASHSEED`` is fixed by ``run.sh``. The vulnerability-intel database is
a frozen subset, so a feed sync between two captures cannot change them.
"""

from __future__ import annotations

import argparse
import copy
import csv
import datetime as _dt_module
import hashlib
import io
import itertools
import json
import os
import random
import sys
import tempfile
import time
import traceback
import uuid
import zipfile
from pathlib import Path

BACKEND = os.path.abspath(os.getcwd())
ORG = "org_development"
DB_PREFIX = "findings_golden_"
SYNTHETIC_OFFSET = _dt_module.timedelta(seconds=60)
SYNTHETIC_DURATION = _dt_module.timedelta(seconds=30)
SYNTHETIC_STEP = _dt_module.timedelta(seconds=90)
#: The synthetic standalone scans of one host, in order: every credentialed
#: finding; a deterministic subset, so the sweep retires the rest; every
#: finding again, so the retired ones reappear and verification reopens them.
SYNTHETIC_STEPS = ("", "p", "b")

# ── Deterministic clock and identifiers ─────────────────────────────────────

_REAL_DT = _dt_module.datetime
_REAL_DATE = _dt_module.date
_UTC = _dt_module.timezone.utc


class _Clock:
    now = _REAL_DT(2026, 10, 22, 12, 0, 0, tzinfo=_UTC)


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
    """``datetime`` whose clock is ``CLOCK``; every value it makes is a real one."""

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


class _Counter:
    def __init__(self):
        self._n = itertools.count(1)

    def token_hex(self, nbytes=32):
        return f"{next(self._n):0{2 * nbytes}x}"[-2 * nbytes :]

    def token_urlsafe(self, nbytes=32):
        return self.token_hex(nbytes)

    def __getattr__(self, name):
        import secrets

        return getattr(secrets, name)


class _TimeShim:
    def time(self):
        return CLOCK.now.timestamp()

    def __getattr__(self, name):
        return getattr(time, name)


_SECRETS = _Counter()
_UUIDS = itertools.count(1)


def _patch_module(module) -> None:
    for name, value in list(vars(module).items()):
        if value is _REAL_DT:
            setattr(module, name, FrozenDatetime)
        elif value is _REAL_DATE:
            setattr(module, name, FrozenDate)
        elif name == "secrets" and getattr(value, "__name__", "") == "secrets":
            setattr(module, name, _SECRETS)


_REAL_FROM_FILE = zipfile.ZipInfo.from_file.__func__


def _frozen_from_file(cls, *args, **kwargs):
    # openpyxl's write-only worksheets reach the archive as temporary files,
    # whose entry time ZipInfo takes from the file's mtime.
    info = _REAL_FROM_FILE(cls, *args, **kwargs)
    info.date_time = time.gmtime(CLOCK.now.timestamp())[:6]
    return info


def install_determinism() -> None:
    """Freeze the clock and the identifier sources, here and in every later import."""
    random.seed(0)
    uuid.uuid4 = lambda: uuid.UUID(int=next(_UUIDS))  # noqa: E731
    _dt_module.datetime = FrozenDatetime
    _dt_module.date = FrozenDate
    zipfile.time = _TimeShim()
    zipfile.ZipInfo.from_file = classmethod(_frozen_from_file)
    for module in list(sys.modules.values()):
        path = getattr(module, "__file__", None) or ""
        if path.startswith(BACKEND + os.sep):
            _patch_module(module)


def _patch_new_first_party_modules(seen: set) -> None:
    for name, module in list(sys.modules.items()):
        if name in seen or module is None:
            continue
        seen.add(name)
        path = getattr(module, "__file__", None) or ""
        if path.startswith(BACKEND + os.sep):
            _patch_module(module)


# ── Imports of the code under test (third-party first, then first-party) ────

import fastapi.encoders  # noqa: E402,F401
import openpyxl  # noqa: E402,F401
from sqlalchemy import text  # noqa: E402

from ccure_audit import offboarding  # noqa: E402
from core.findings import compare_scans  # noqa: E402
from core.findings.comparison import previous_scan_for  # noqa: E402
from core.findings.credentialed_scope import is_credentialed_finding  # noqa: E402
from core.remediation import (  # noqa: E402
    apply_sla,
    sla_policy_for_org_id,
    verify_from_comparison,
    verify_scan,
)
from db.base import SessionLocal  # noqa: E402
from db.models import AssetVulnerability, Scan, ScanPhase  # noqa: E402
import reporting.exports as exports  # noqa: E402
import reporting.xlsx_generator  # noqa: E402,F401
import routers.reports as reports  # noqa: E402
from scans import asset_syncer  # noqa: E402
from scans.tasks import credentialed_sync  # noqa: E402

_SEEN_MODULES: set = set()
install_determinism()
_patch_new_first_party_modules(_SEEN_MODULES)

SYNC_BY_ORDER = {
    1: asset_syncer.sync_host_discovery,
    2: asset_syncer.sync_asset_discovery,
    3: asset_syncer.sync_vulnerability_audit,
}

#: Written in full, as well as hashed: the tables the findings writes decide.
FULL_TABLES = (
    "assets",
    "asset_change_log",
    "services",
    "tls_details",
    "http_security_details",
    "asset_vulnerabilities",
    "finding_remediation_events",
    "scans",
)

#: Columns left out of a table's rows because PostgreSQL, not the code,
#: decides them. A sweep logs each finding it retires to asset_change_log,
#: iterating a query with no ORDER BY and stamping every row with the same
#: time; which row the sequence numbers first is the order the rows come back
#: in, and that varies between runs of the same code (measured: two captures
#: of 595f068 paired 738 ids with different findings, every other column
#: equal). The rows themselves are still compared, in full.
ARBITRARY_COLUMNS = {("public", "asset_change_log"): ("id",)}


def at(when) -> None:
    CLOCK.now = when.astimezone(_UTC)
    _patch_new_first_party_modules(_SEEN_MODULES)


def jdump(obj) -> str:
    return json.dumps(obj, sort_keys=True, indent=1, default=str, ensure_ascii=False)


def short_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc).splitlines()[0][:300] if str(exc) else ''}"


# ── Replay ───────────────────────────────────────────────────────────────────


def _phase_events(db):
    """(time, kind, scan_id, phase_order) for every stored phase payload."""
    events = []
    for scan in db.query(Scan).order_by(Scan.started_at, Scan.id).all():
        phases = (
            db.query(ScanPhase)
            .filter(ScanPhase.scan_id == scan.id)
            .order_by(ScanPhase.phase_order)
            .all()
        )
        for phase in phases:
            data = (phase.summary or {}).get("_phase_data")
            if not isinstance(data, list) or phase.phase_key == "credentialed":
                continue
            when = phase.completed_at or scan.completed_at or scan.started_at
            events.append((when, 0, scan.id, int(phase.phase_order)))
        if scan.pipeline_mode == "vulnerability_audit" and scan.completed_at:
            events.append((scan.completed_at, 1, scan.id, 99))
            vuln_phase = next((p for p in phases if p.phase_order >= 3), None)
            data = ((vuln_phase.summary if vuln_phase else None) or {}).get(
                "_phase_data"
            )
            for index, host in enumerate(data if isinstance(data, list) else []):
                if isinstance(host, dict) and isinstance(
                    host.get("credentialed_report"), dict
                ):
                    for step in range(len(SYNTHETIC_STEPS)):
                        events.append(
                            (
                                scan.completed_at
                                + SYNTHETIC_OFFSET
                                + step * SYNTHETIC_STEP,
                                2 + step,
                                scan.id,
                                index,
                            )
                        )
    events.sort(key=lambda e: (e[0], e[1], e[2], e[3]))
    return events


def _stored_hosts(db, scan_id: str, order: int) -> list:
    phase = (
        db.query(ScanPhase)
        .filter(ScanPhase.scan_id == scan_id, ScanPhase.phase_order == order)
        .first()
    )
    if phase is None:
        phase = (
            db.query(ScanPhase)
            .filter(ScanPhase.scan_id == scan_id, ScanPhase.phase_order >= 3)
            .order_by(ScanPhase.phase_order)
            .first()
        )
    return copy.deepcopy((phase.summary or {}).get("_phase_data") or [])


def _comparison_dict(db, scan):
    baseline = previous_scan_for(db, scan)
    if baseline is None:
        return {"baseline": None}
    comparison = compare_scans(db, current=scan, baseline=baseline, limit_findings=None)
    return {"baseline": baseline.id, "comparison": comparison.as_dict()}


def _synthetic_scan(db, source, index: int, host: dict, step: int = 0):
    """A standalone credentialed scan row for one host of a vulnerability audit."""
    started = source.completed_at + SYNTHETIC_OFFSET + step * SYNTHETIC_STEP
    scan_id = f"{source.id}_golden_c{index}{SYNTHETIC_STEPS[step]}"
    existing = db.query(Scan).filter(Scan.id == scan_id).first()
    if existing is not None:
        return existing
    ip = str(host.get("ip_address") or host.get("ip") or "")
    max_no = db.execute(
        text("select coalesce(max(scan_no), 0) from scans where org_id = :o"),
        {"o": source.org_id},
    ).scalar()
    scan = Scan(
        id=scan_id,
        org_id=source.org_id,
        created_by=source.created_by,
        scan_no=int(max_no) + 1,
        scan_name=(
            f"golden standalone credentialed {source.scan_no}/{index}"
            f"{SYNTHETIC_STEPS[step]}"
        ),
        target_hosts=[ip],
        target_str=ip,
        scan_type="credentialed",
        pipeline_mode="credentialed",
        intensity="normal",
        options={"origin": "findings_golden"},
        status="complete",
        queued_at=started,
        started_at=started,
        completed_at=started + SYNTHETIC_DURATION,
        duration_seconds=SYNTHETIC_DURATION.total_seconds(),
        total_hosts=1,
        active_hosts=1,
        total_vulns=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        is_archived=False,
        is_deleted=False,
        created_at=started,
        updated_at=started,
    )
    db.add(scan)
    db.flush()
    return scan


def _retained(finding: dict) -> bool:
    """The partial step keeps four findings in five, chosen by identifier."""
    identifier = str(finding.get("cve_id") or finding.get("cve") or finding.get("id"))
    return hashlib.sha256(identifier.encode()).digest()[0] % 5 != 0


def _standalone_inputs(host: dict, partial: bool = False):
    report = host.get("credentialed_report") or {}
    system_data = dict(report.get("system_info") or {})
    detected_os = str(report.get("detected_os") or "").lower() or "linux"
    system_data.setdefault("detected_os", detected_os)
    cves = [
        v
        for v in (host.get("cves") or [])
        if isinstance(v, dict)
        and is_credentialed_finding(v)
        and (not partial or _retained(v))
    ]
    stored_report = {
        "target": str(host.get("ip_address") or host.get("ip") or ""),
        "cves": cves,
        "severity_summary": {},
        "open_ports_credentialed": host.get("open_ports_credentialed") or [],
        "packages": [],
        "package_count": report.get("package_count"),
        "package_coverage": report.get("package_coverage"),
        "inventory_complete": report.get("inventory_complete"),
        "config_audit": report.get("config_audit"),
        "collection_errors": report.get("collection_errors"),
    }
    return stored_report, system_data, detected_os


def _run_standalone(db, source, index: int, host: dict, step: int = 0) -> dict:
    """The standalone credentialed task's sync, SLA, comparison and verification."""
    record = {"source_scan": source.id, "host_index": index, "step": step}
    scan = _synthetic_scan(db, source, index, host, step)
    db.commit()
    record["scan"] = scan.id
    stored_report, system_data, os_type = _standalone_inputs(
        copy.deepcopy(host), partial=SYNTHETIC_STEPS[step] == "p"
    )
    record["credentialed_findings_in"] = len(stored_report["cves"])
    at(scan.started_at + _dt_module.timedelta(seconds=15))
    sync = getattr(credentialed_sync, "_sync_credentialed_asset_identity")
    sync(
        db,
        user_id=scan.created_by,
        ip=stored_report["target"],
        scan_id=str(scan.id),
        os_type=os_type,
        system_data=system_data,
        stored_report=stored_report,
        cve_list=stored_report.get("cves") or [],
        severity_counts=stored_report.get("severity_summary") or {},
    )
    db.commit()
    at(scan.completed_at)
    policy = sla_policy_for_org_id(db, scan.org_id)
    rows = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.org_id == scan.org_id,
            AssetVulnerability.scan_id == scan.id,
        )
        .all()
    )
    for finding in rows:
        apply_sla(db, finding, policy=policy)
    record["sla_rows"] = len(rows)
    db.flush()
    baseline = previous_scan_for(db, scan)
    if baseline is not None:
        full = compare_scans(db, current=scan, baseline=baseline, limit_findings=None)
        record["baseline"] = baseline.id
        record["comparison"] = full.as_dict()
        record["verification"] = verify_from_comparison(
            db, full, scan_id=str(scan.id), org_id=str(scan.org_id)
        ).as_dict()
    db.commit()
    return record


def replay(db, out: Path, *, from_empty: bool) -> dict:
    if from_empty:
        db.execute(text("delete from assets where org_id = :o"), {"o": ORG})
        db.execute(
            text(
                "update scans set options = options - 'assessment_scope' "
                "where org_id = :o"
            ),
            {"o": ORG},
        )
        db.commit()

    log = []
    for when, kind, scan_id, order in _phase_events(db):
        scan = db.query(Scan).filter(Scan.id == scan_id).one()
        entry = {"at": when.isoformat(), "scan": scan_id}
        try:
            if kind == 0:
                at(when)
                entry["sync"] = SYNC_BY_ORDER[min(order, 3)].__name__
                hosts = _stored_hosts(db, scan_id, order)
                entry["hosts"] = len(hosts)
                SYNC_BY_ORDER[min(order, 3)](
                    db, str(scan.id), str(scan.org_id), scan.created_by, hosts
                )
                db.commit()
            elif kind == 1:
                at(when)
                entry["step"] = "comparison+verify_scan"
                entry["comparison"] = _comparison_dict(db, scan)
                entry["verification"] = verify_scan(db, scan).as_dict()
                db.commit()
            else:
                hosts = _stored_hosts(db, scan_id, 3)
                entry["step"] = "standalone_credentialed"
                entry.update(
                    _run_standalone(db, scan, order, hosts[order], step=kind - 2)
                )
        except Exception as exc:  # recorded, compared, never hidden
            db.rollback()
            entry["error"] = short_error(exc)
            entry["traceback_tail"] = traceback.format_exc().splitlines()[-3:]
        log.append(entry)
    (out / "replay_log.json").write_text(jdump(log))
    return {
        "events": len(log),
        "errors": sum(1 for e in log if "error" in e),
    }


# ── Read-only captures ───────────────────────────────────────────────────────


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


def _render_json(payload) -> bytes:
    content = fastapi.encoders.jsonable_encoder(payload)
    return json.dumps(
        content, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":")
    ).encode("utf-8")


def _render_csv(block) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(block["columns"])
    for row in block["rows"]:
        writer.writerow(reports._csv_safe(cell) for cell in row)
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def _legacy_csv(db, scan, tmp: str) -> bytes | None:
    """``GET /reports/download/{id}?fmt=CSV``, as the route renders it."""
    from reporting.csv_generator import (
        generate_host_inventory_csv,
        generate_scan_csv,
        scan_has_findings,
    )

    payloads = reports.build_legacy_scan_results(db, str(scan.id))
    key = next(
        (
            k
            for k in ("credentialed", "phase3", "phase2", "phase1")
            if isinstance(payloads.get(k), dict)
        ),
        None,
    )
    if key is None:
        return None
    payload = reports._flatten_credentialed_payload(key, payloads.get(key, {}))
    reports._attach_asset_lifecycle_dates(db, scan, payload)
    path = os.path.join(tmp, f"legacy_{scan.id}.csv")
    if scan_has_findings(payload):
        context = exports.finding_context_map(db, scan)
        generate_scan_csv(
            payload, path, scan_type="network", remediation_context=context
        )
    else:
        generate_host_inventory_csv(
            payload, path, ports_scanned=(scan.pipeline_mode or "basic") != "basic"
        )
    return Path(path).read_bytes()


def capture_scan_outputs(db, out: Path) -> dict:
    scans = db.query(Scan).order_by(Scan.started_at, Scan.id).all()
    comparisons = {}
    files = 0
    with tempfile.TemporaryDirectory() as tmp:
        reports._REPORTS_DIR = tmp
        for scan in scans:
            sdir = out / "exports" / scan.id
            sdir.mkdir(parents=True, exist_ok=True)
            try:
                comparisons[scan.id] = _comparison_dict(db, scan)
            except Exception as exc:
                db.rollback()
                comparisons[scan.id] = {"error": short_error(exc)}
            outputs = {}
            try:
                path, _name = reports._build_scan_workbook(db, scan, user=None)
                outputs["workbook.xlsx"] = Path(path).read_bytes()
                comparison = reports._comparison_for(db, scan, None, None)
                payload = exports.export_payload(
                    db,
                    scan,
                    comparison=comparison,
                    datasets=("hosts", "compliance", "findings", "comparison"),
                )
                outputs["export_all.json"] = _render_json(payload)
                for dataset in ("hosts", "compliance", "findings", "comparison"):
                    outputs[f"export_{dataset}.csv"] = _render_csv(
                        payload["datasets"][dataset]
                    )
                legacy = _legacy_csv(db, scan, tmp)
                if legacy is not None:
                    outputs["legacy_download.csv"] = legacy
            except Exception as exc:
                db.rollback()
                outputs["error.txt"] = (short_error(exc) + "\n").encode()
            for name, content in outputs.items():
                (sdir / name).write_bytes(content)
                files += 1
    (out / "comparisons.json").write_text(jdump(comparisons))
    return {"scans": len(scans), "export_files": files}


def capture_verification_rolled_back(db, out: Path) -> dict:
    """Each vulnerability audit's verification, as computed now, then undone."""
    outcomes = {}
    scans = (
        db.query(Scan)
        .filter(Scan.pipeline_mode == "vulnerability_audit")
        .order_by(Scan.started_at, Scan.id)
        .all()
    )
    for scan in scans:
        at(scan.completed_at)
        try:
            outcomes[scan.id] = verify_scan(db, scan).as_dict()
        except Exception as exc:
            outcomes[scan.id] = {"error": short_error(exc)}
        finally:
            db.rollback()
    (out / "verification_rolled_back.json").write_text(jdump(outcomes))
    return {"verified_scans": len(outcomes)}


def capture_purge_hook(db, out: Path) -> dict:
    """Audit's purge hook over findings with an accepted risk, then undone."""
    users = [r[0] for r in db.execute(text("select id from users order by id")).all()]
    if len(users) < 2:
        return {"purge_hook": "skipped: fewer than two users"}
    ids = [
        r[0]
        for r in db.execute(
            text(
                "select id from asset_vulnerabilities where org_id = :o "
                "order by id limit 40"
            ),
            {"o": ORG},
        ).all()
    ]
    for position, finding_id in enumerate(ids):
        db.execute(
            text(
                "update asset_vulnerabilities set accepted_by = :u "
                "where id = :i and org_id = :o"
            ),
            {"u": users[position % 2], "i": finding_id, "o": ORG},
        )
    db.flush()
    offboarding.detach_user_from_audit_data(db, users[0])
    db.flush()
    state = {
        "accepted_by": [
            list(r)
            for r in db.execute(
                text(
                    "select id, accepted_by from asset_vulnerabilities "
                    "where accepted_by is not null order by id"
                )
            ).all()
        ],
        "scans_created_by": [
            list(r)
            for r in db.execute(
                text("select id, created_by from scans order by id")
            ).all()
        ],
    }
    db.rollback()
    (out / "purge_hook.json").write_text(jdump(state))
    return {"purge_hook_findings": len(ids)}


# ── Entry point ──────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode", choices=("asis", "on_top", "from_empty"), required=True
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    db = SessionLocal()
    name = db.execute(text("select current_database()")).scalar()
    if not str(name).startswith(DB_PREFIX):
        print(
            f"refusing: database {name!r} is not a findings golden copy",
            file=sys.stderr,
        )
        return 2

    summary = {"mode": args.mode}
    if args.mode in ("on_top", "from_empty"):
        summary.update(replay(db, out, from_empty=args.mode == "from_empty"))

    last = db.execute(
        text("select max(coalesce(completed_at, started_at)) from scans")
    ).scalar()
    at(last + _dt_module.timedelta(days=1))
    if args.mode == "asis":
        summary.update(capture_verification_rolled_back(db, out))
        at(last + _dt_module.timedelta(days=1))
        summary.update(capture_purge_hook(db, out))
    summary.update(capture_scan_outputs(db, out))
    db.rollback()
    summary.update(capture_tables(db, out))
    db.rollback()
    db.close()
    (out / "summary.json").write_text(jdump(summary))
    print(jdump(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
