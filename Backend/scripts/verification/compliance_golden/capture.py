"""
Compliance golden: run the compliance assessment, its evidence, the scan-policy
catalogue checks and both benchmark loaders on a restored copy of the database
with one commit's code, and capture everything they decide, so two commits can
be compared byte for byte.

Run by ``run.sh`` inside the backend image, from one commit's ``Backend/`` tree,
against a throwaway copy of a restored dump that ``setup.sql`` has added to. It
refuses any database whose name does not start with ``compliance_golden_``.

The code is loaded the way the compliance worker loads it: Celery's
``import_default_modules()``, which imports every module the app's ``imports``
and ``include`` lists name (``main.py`` makes the same call). Evidence the
worker could not reach would show here as a difference.

Captured, each step at its own frozen time:

``evidence/``
    Every asset of the development organisation (and one that does not exist),
    every evidence source the build declares, and one it does not: the payload
    the compliance engine reads (``_fetch_and_translate``), and the cached path
    (``get_normalized_evidence``) on a miss and then a hit.
``scans.json``
    A compliance scan of every catalogue the organisation has a policy for,
    twice, a day apart; then three scoped scans (asset ids, asset tags, a CDE
    scope). Each run's task result.
``reverify.json``
    ``run_reverify_evaluation`` for every asset-level finding of an automated
    rule.
``policy_validation.json``
    ``validate_policy`` and ``validate_for_dispatch`` for policies naming
    installed, parked, missing and uninstalled catalogues, in both
    organisations.
``benchmark_selection.json``
    ``benchmark_frameworks_for_org`` and ``benchmark_checks_for_org`` for both
    organisations and every narrowing argument.
``benchmark_load.json``
    Every shipped benchmark pack loaded into the catalogue, twice.
``stig_load/``
    ``scripts/benchmarks/load_stig.py`` run as an operator runs it, over the
    SCAP test fixture, with and without a CCI list: its output, the pack it
    writes, and its load into the catalogue.
``tables/`` and ``table_digests.json``
    A SHA-256 of every table's rows, and every ``compliance_*`` table in full.

Determinism: the clock (``datetime.datetime`` / ``date`` in every first-party
module) is frozen; ``random`` is seeded; ``secrets`` and ``uuid4`` are replaced
by counters; ``PYTHONHASHSEED`` is fixed by ``run.sh``; the evidence cache is
emptied before every step that reads it.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
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
from pathlib import Path

BACKEND = os.path.abspath(os.getcwd())
ORGS = ("org_development", "org_self-service")
ORG = ORGS[0]
DB_PREFIX = "compliance_golden_"
START = _dt_module.datetime(2026, 10, 22, 12, 0, 0, tzinfo=_dt_module.timezone.utc)

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


def _spread(n: int, nbytes: int) -> str:
    """The *n*-th identifier: deterministic, and different in every digit.

    Callers truncate from the left (``uuid4().hex[:24]`` names compliance
    history rows), so a plain counter, all leading zeros, would hand every
    caller the same identifier.
    """
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


def short_error(exc: BaseException) -> str:
    first = str(exc).splitlines()[0][:300] if str(exc) else ""
    return f"{type(exc).__name__}: {first}"


# ── The code under test, loaded as the compliance worker loads it ───────────

from core.celery_app import celery_app  # noqa: E402

celery_app.loader.import_default_modules()
#: Printed to the log, not written to the capture: the list is configuration,
#: and the comparison is of what the code decides.
WORKER_MODULES = list(celery_app.loader.default_modules)

from sqlalchemy import text  # noqa: E402

# Every model, before the clock is frozen, so none is first imported lazily
# in the middle of a step with the real clock bound.
import db.models  # noqa: E402,F401
import db.models.web_scans  # noqa: E402,F401
import core.compliance_evidence as compliance_evidence  # noqa: E402
import core.compliance_tasks as compliance_tasks  # noqa: E402
from core.benchmarks import load_pack  # noqa: E402
from core.benchmarks.loader import load_pack_into_db  # noqa: E402
from core.benchmarks.selection import (  # noqa: E402
    benchmark_checks_for_org,
    benchmark_frameworks_for_org,
)
from core.scan_policy.spec import effective_from_config  # noqa: E402
from core.scan_policy.validation import (  # noqa: E402
    validate_for_dispatch,
    validate_policy,
)
from db.base import SessionLocal  # noqa: E402
from db.models.compliance import (  # noqa: E402
    ComplianceFinding,
    CompliancePolicy,
    ComplianceRule,
    ComplianceScanRun,
)

sys.path.insert(0, os.path.join(BACKEND, "tests", "scans"))
sys.path.insert(0, os.path.join(BACKEND, "tests"))
import test_scap_parsers as scap_fixture  # noqa: E402

from scripts.benchmarks import load_stig  # noqa: E402

install_determinism()

Provider = compliance_evidence.ComplianceEvidenceProvider


def flush_evidence_cache() -> None:
    compliance_evidence.redis.flushdb()


# ── Steps ────────────────────────────────────────────────────────────────────


def capture_evidence(db, out: Path) -> dict:
    flush_evidence_cache()
    asset_ids = [
        r[0]
        for r in db.execute(
            text("select id from assets where org_id = :o order by id"), {"o": ORG}
        )
    ] + ["ast_does_not_exist"]
    sources = list(compliance_evidence.EVIDENCE_SOURCES) + ["auto_scan"]
    folder = out / "evidence"
    folder.mkdir(parents=True, exist_ok=True)
    errors = 0
    for asset_id in asset_ids:
        record = {}
        for source in sources:
            entry = {}
            try:
                entry["translated"] = Provider._fetch_and_translate(
                    db, asset_id, source
                )
            except Exception as exc:  # recorded, so a difference shows
                entry["translated_error"] = short_error(exc)
                errors += 1
                db.rollback()
            try:
                entry["first_read"] = Provider.get_normalized_evidence(
                    db, asset_id, source
                )
                entry["second_read"] = Provider.get_normalized_evidence(
                    db, asset_id, source
                )
                cached = compliance_evidence.redis.get(
                    Provider.get_cache_key(asset_id, source)
                )
                entry["cached"] = json.loads(cached) if cached else None
            except Exception as exc:
                entry["read_error"] = short_error(exc)
                errors += 1
                db.rollback()
            record[source] = entry
        (folder / f"{asset_id}.json").write_text(jdump(record))
    db.rollback()
    return {"evidence_assets": len(asset_ids), "evidence_errors": errors}


def _new_run(db, run_id: str, framework_id: str, policy_id: str, **extra) -> None:
    db.add(
        ComplianceScanRun(
            id=run_id,
            tenant_id=ORG,
            framework_id=framework_id,
            policy_id=policy_id,
            initiated_by=None,
            scope=extra.pop("scope", {}),
            status="queued",
            created_at=CLOCK.now,
            **extra,
        )
    )
    db.commit()


def capture_scans(db, out: Path) -> dict:
    policies = [
        (p.framework_id, p.id)
        for p in db.query(CompliancePolicy)
        .filter(CompliancePolicy.tenant_id == ORG, CompliancePolicy.status == "active")
        .order_by(CompliancePolicy.framework_id, CompliancePolicy.id)
        .all()
    ]
    results = {}
    step = itertools.count()
    for round_no, day in ((1, 0), (2, 1)):
        for framework_id, policy_id in policies:
            at(START + _dt_module.timedelta(days=day, minutes=next(step)))
            run_id = f"csr_g4_r{round_no}_{framework_id}"
            _new_run(db, run_id, framework_id, policy_id)
            try:
                results[run_id] = compliance_tasks.run_scan_task(run_id, ORG)
            except Exception as exc:
                results[run_id] = {"raised": short_error(exc)}
            db.expire_all()

    by_framework = dict(policies)
    scoped = (
        (
            "asset_ids",
            "cfw_iso27001_2022",
            {"scope": {"asset_ids": ["ast_g4_win", "ast_g4_bare"]}},
        ),
        ("asset_tags", "cfw_nist_csf_v2", {"scope": {"asset_tags": ["PCI", "cde"]}}),
        ("cde_scope", "cfw_pci_dss_v4", {"cde_scope": "CDE"}),
        ("nothing", "cfw_cis_v8_1", {"scope": {"asset_ids": ["ast_nowhere"]}}),
    )
    for label, framework_id, extra in scoped:
        if framework_id not in by_framework:
            results[f"csr_g4_scoped_{label}"] = {"skipped": "no policy"}
            continue
        at(START + _dt_module.timedelta(days=2, minutes=next(step)))
        run_id = f"csr_g4_scoped_{label}"
        _new_run(db, run_id, framework_id, by_framework[framework_id], **dict(extra))
        try:
            results[run_id] = compliance_tasks.run_scan_task(run_id, ORG)
        except Exception as exc:
            results[run_id] = {"raised": short_error(exc)}
        db.expire_all()
    (out / "scans.json").write_text(jdump(results))
    failed = sorted(k for k, v in results.items() if not (v or {}).get("success"))
    return {"scan_runs": len(results), "scan_runs_not_successful": failed}


def capture_reverify(db, out: Path) -> dict:
    flush_evidence_cache()
    at(START + _dt_module.timedelta(days=3))
    rows = (
        db.query(ComplianceFinding.id)
        .join(ComplianceRule, ComplianceRule.id == ComplianceFinding.rule_id)
        .filter(
            ComplianceFinding.tenant_id == ORG,
            ComplianceFinding.asset_id.isnot(None),
            ComplianceRule.evidence_source.notin_(("manual", "config_audit")),
        )
        .order_by(ComplianceFinding.id)
        .all()
    )
    db.rollback()
    results = {}
    for (finding_id,) in rows:
        try:
            results[finding_id] = compliance_tasks.run_reverify_evaluation(finding_id)
        except Exception as exc:
            results[finding_id] = {"raised": short_error(exc)}
    (out / "reverify.json").write_text(jdump(results))
    return {"reverified": len(results)}


POLICY_CONFIGS = {
    "empty": {},
    "iso": {"framework_ids": ["cfw_iso27001_2022"]},
    "missing": {"framework_ids": ["cfw_does_not_exist"]},
    "parked": {"framework_ids": ["cfw_soc2_type2", "cfw_gdpr"]},
    "benchmark_and_iso": {"framework_ids": ["cfw_bm_stig_win11", "cfw_iso27001_2022"]},
    "benchmark_high": {
        "framework_ids": ["cfw_bm_stig_ubuntu2404"],
        "min_severity": "high",
    },
    "mixed": {
        "framework_ids": [
            "cfw_iso27001_2022",
            "cfw_does_not_exist",
            "cfw_hipaa_security_rule",
            "cfw_bm_stig_rhel9",
            "cfw_nist_csf_v2",
            "cfw_cis_v8_1",
        ]
    },
    "require_credential": {
        "framework_ids": ["cfw_cis_v8_1"],
        "require_credential": True,
    },
    "unknown_key": {"framework_ids": ["cfw_iso27001_2022"], "no_such_setting": 1},
}


def capture_policy_validation(db, out: Path) -> dict:
    at(START + _dt_module.timedelta(days=4))
    all_frameworks = [
        r[0]
        for r in db.execute(text("select id from compliance_frameworks order by id"))
    ]
    configs = dict(POLICY_CONFIGS)
    configs["every_catalogue"] = {"framework_ids": all_frameworks}
    results = {}
    for name, config in configs.items():
        entry = {}
        try:
            entry["static"] = validate_policy(config).as_dict()
        except Exception as exc:
            entry["static_error"] = short_error(exc)
        try:
            policy = effective_from_config(
                {k: v for k, v in config.items() if k != "no_such_setting"},
                policy_name=name,
            )
            for org_id in ORGS:
                for has_credential in (True, False):
                    key = f"dispatch:{org_id}:credential={has_credential}"
                    try:
                        entry[key] = validate_for_dispatch(
                            db,
                            policy,
                            org_id=org_id,
                            scan_kind=policy.scan_kind,
                            has_credential=has_credential,
                        ).as_dict()
                    except Exception as exc:
                        entry[key] = {"raised": short_error(exc)}
                        db.rollback()
        except Exception as exc:
            entry["policy_error"] = short_error(exc)
        results[name] = entry
    db.rollback()
    (out / "policy_validation.json").write_text(jdump(results))
    return {"policies_validated": len(results)}


def _check_record(check) -> dict:
    record = (
        dataclasses.asdict(check)
        if dataclasses.is_dataclass(check)
        else {"repr": repr(check)}
    )
    try:
        record["_definition"] = check.to_check_definition()
    except Exception as exc:
        record["_definition_error"] = short_error(exc)
    return record


SELECTION_CASES = {
    "default": {},
    "profile": {"profile": "stig"},
    "linux": {"platforms": ["linux"]},
    "windows_high": {"platforms": ["windows"], "min_severity": "high"},
    "ubuntu2404": {"framework_ids": ["cfw_bm_stig_ubuntu2404"]},
    "not_installed": {"framework_ids": ["cfw_bm_not_loaded"]},
    "critical": {"min_severity": "critical"},
    "info_floor": {"min_severity": "info"},
    "unknown_floor": {"min_severity": "catastrophic"},
}


def capture_benchmark_selection(db, out: Path) -> dict:
    at(START + _dt_module.timedelta(days=4, hours=1))
    results = {}
    for org_id in ORGS:
        results[f"{org_id}:frameworks"] = benchmark_frameworks_for_org(db, org_id)
        for name, kwargs in SELECTION_CASES.items():
            checks = benchmark_checks_for_org(db, org_id, **kwargs)
            results[f"{org_id}:{name}"] = [_check_record(c) for c in checks]
    # Exclusions named from what the default resolution returned.
    default = results[f"{ORG}:default"]
    if default:
        excluded_ids = sorted(c.get("check_id", "") for c in default)[::7]
        tags = sorted({t for c in default for t in (c.get("tags") or ())})[:3]
        checks = benchmark_checks_for_org(
            db, ORG, excluded_check_ids=excluded_ids, excluded_tags=tags
        )
        results[f"{ORG}:excluded"] = {
            "excluded_ids": excluded_ids,
            "excluded_tags": tags,
            "checks": [_check_record(c) for c in checks],
        }
    db.rollback()
    (out / "benchmark_selection.json").write_text(jdump(results))
    return {
        "benchmark_selection_cases": len(results),
        "benchmark_checks_default": len(default),
    }


def _result_record(result) -> dict:
    if dataclasses.is_dataclass(result):
        return dataclasses.asdict(result)
    return {"repr": repr(result)}


def capture_benchmark_load(db, out: Path) -> dict:
    results = {}
    packs = sorted((Path(BACKEND) / "data" / "benchmarks").glob("*.benchmark.json"))
    for index, path in enumerate(packs):
        pack = load_pack(path)
        for attempt in (1, 2):
            at(START + _dt_module.timedelta(days=5, minutes=2 * index + attempt))
            try:
                results[f"{path.name}:{attempt}"] = _result_record(
                    load_pack_into_db(db, pack)
                )
                db.commit()
            except Exception as exc:
                db.rollback()
                results[f"{path.name}:{attempt}"] = {"raised": short_error(exc)}
    (out / "benchmark_load.json").write_text(jdump(results))
    return {"benchmark_packs_loaded": len(packs)}


def _run_load_stig(argv: list) -> dict:
    stdout = io.StringIO()
    saved = sys.argv
    sys.argv = ["load_stig.py", *argv]
    try:
        with contextlib.redirect_stdout(stdout):
            status = load_stig.main()
    except SystemExit as exc:
        status = f"SystemExit({exc.code})"
    except Exception as exc:
        status = f"raised {short_error(exc)}"
        traceback.print_exc()
    finally:
        sys.argv = saved
    return {"status": status, "stdout": stdout.getvalue()}


#: The SCAP fixture's synthetic CCI list (tests/scans/test_scap_parsers.py):
#: no real CCI-to-800-53 mapping is written into this repository.
CCI_LIST = """<?xml version="1.0"?>
<cci_list xmlns="http://iase.disa.mil/cci">
  <cci_items>
    <cci_item id="CCI-999001">
      <references>
        <reference creator="NIST" title="NIST SP 800-53 Revision 5" index="AC-17 (1)"/>
      </references>
    </cci_item>
  </cci_items>
</cci_list>"""


def capture_stig_load(out: Path) -> dict:
    folder = out / "stig_load"
    folder.mkdir(parents=True, exist_ok=True)
    # A fixed directory, because the content's path is recorded in the pack.
    tmp = "/tmp/compliance-golden-scap"
    os.makedirs(tmp, exist_ok=True)
    content = Path(tmp) / "ssg-fixture-ds.xml"
    content.write_text(scap_fixture.datastream(scap_fixture.BENCHMARK))
    cci_list = Path(tmp) / "U_CCI_List.xml"
    cci_list.write_text(CCI_LIST)
    runs = {
        "no_cci_list": ["--code", "FIXTURE_NO_CCI"],
        "cci_list": ["--code", "FIXTURE_CCI", "--cci-list", str(cci_list)],
    }
    results = {}
    for index, (name, extra) in enumerate(runs.items()):
        at(START + _dt_module.timedelta(days=6, minutes=index))
        pack_out = Path(tmp) / f"{name}.json"
        results[name] = _run_load_stig(
            [
                str(content),
                *extra,
                "--profile",
                "stig",
                "--publisher",
                "CCURE (synthetic fixture)",
                "--licence",
                "synthetic test fixture, not benchmark content",
                "--applies-to-name",
                "ubuntu",
                "--out",
                str(pack_out),
                "--load",
            ]
        )
        if pack_out.exists():
            (folder / f"{name}.pack.json").write_text(pack_out.read_text())
    (folder / "runs.json").write_text(jdump(results))
    return {"stig_loads": {k: v["status"] for k, v in results.items()}}


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
        keep = schema == "public" and table.startswith("compliance_")
        handle = (full_dir / f"{table}.txt").open("w") if keep else None
        with raw.cursor(name=f"dump_{schema}_{table}") as cursor:
            cursor.itersize = 5000
            # Names from the catalogue, not from input.
            query = f"select t::text from {qualified} t order by 1"  # nosec B608
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
            f"refusing: database {name!r} is not a compliance golden copy",
            file=sys.stderr,
        )
        return 2

    print("worker modules:", ", ".join(WORKER_MODULES), flush=True)
    summary = {}
    at(START)
    summary.update(capture_evidence(db, out))
    summary.update(capture_scans(db, out))
    summary.update(capture_reverify(db, out))
    summary.update(capture_policy_validation(db, out))
    summary.update(capture_benchmark_selection(db, out))
    summary.update(capture_benchmark_load(db, out))
    summary.update(capture_stig_load(out))
    db.rollback()
    summary.update(capture_tables(db, out))
    db.rollback()
    db.close()
    (out / "summary.json").write_text(jdump(summary))
    print(jdump(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
