"""
Phase 11.2 — proof that a module team can build inside its own boundary.

``fixture/ccure_example`` is a TEST-ONLY module shaped exactly like
``ccure_policy`` and ``ccure_rank``. It is never registered in production and
never shipped: it lives under ``Backend/tests/``, which neither the application
nor the import graph loads. It adds one of each thing a future team adds, and
every file it needs is inside its own folder:

* a **route** — ``api/routes.py``, declared in ``manifest.toml``, mounted by the
  platform under ``/example``;
* a **table** — ``models/tables.py``, on a ``MetaData(schema="example")``;
* a **migration** — ``migrations/ex0001_create_example.py``, its own Alembic
  branch, creating the schema and the table and removing them again;
* a **task** — ``workers/ping.py``, ``ccure.example.ping``, loaded through the
  registry's ``task_modules``.

Then the other half: the guardrails catch a module that imports another
module's code, is imported by anyone else, names another module's table,
declares a table outside its schema, or keeps its tests in the wrong place.
"""

from __future__ import annotations

import shutil
import sys
import textwrap
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ccure_platform.modules import registry
from scripts.architecture import layer_rules
from scripts.architecture import module_boundaries as mb
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

FIXTURE = Path(__file__).resolve().parent / "fixture"
PACKAGE_DIR = FIXTURE / "ccure_example"
OWNERSHIP = BACKEND_ROOT / "scripts" / "architecture" / "table_ownership.yaml"

EXAMPLE_IDENTITY = dict(
    key="example",
    title="Example (test-only proof module)",
    description="A test-only proof module; never registered in production.",
    entry_path="/example-dashboard",
    package="ccure_example",
    db_schema="example",
    route_prefix="/example",
    task_prefix="ccure.example",
    tile_state="not_yet_available",
    enabled=True,
)


@pytest.fixture
def example(monkeypatch):
    """The proof module, registered beside the three real ones for one test,
    through the registry's own loader (its manifest.toml is read as data)."""
    monkeypatch.syspath_prepend(str(FIXTURE))
    manifest = registry.build(EXAMPLE_IDENTITY, root=FIXTURE)
    monkeypatch.setattr(registry, "MODULES", (*registry.MODULES, manifest))
    yield manifest
    for name in [
        n for n in sys.modules if n == "ccure_example" or n.startswith("ccure_example.")
    ]:
        del sys.modules[name]


@pytest.fixture(scope="module")
def ownership():
    data = yaml.safe_load(OWNERSHIP.read_text(encoding="utf-8"))
    # The proof module's table, registered the way a real module registers one.
    data["tables"]["example.example_item"] = {"owner": "example", "capability": "proof"}
    return data


# ── the module is self-contained ─────────────────────────────────────────────
def test_every_file_the_module_needs_is_inside_its_own_folder(example):
    for target in (*example.routers, *example.models):
        module = target.partition(":")[0]
        assert (FIXTURE / (module.replace(".", "/") + ".py")).is_file(), target
    for module in example.task_modules:
        assert (FIXTURE / (module.replace(".", "/") + ".py")).is_file(), module
    assert (PACKAGE_DIR / "migrations" / "ex0001_create_example.py").is_file()
    assert (PACKAGE_DIR / "manifest.toml").is_file()


def test_the_proof_module_is_not_registered_in_production():
    assert [m.key for m in registry.modules()] == ["policy_pro", "audit", "rank"]
    assert not (BACKEND_ROOT / "ccure_example").exists()


# ── a route ──────────────────────────────────────────────────────────────────
def test_route_is_mounted_under_the_module_prefix(example):
    app = FastAPI()
    mounted = registry.mount_module_routers(app)
    assert mounted == [("/example", "ccure_example.api.routes:router")]
    client = TestClient(app)
    response = client.get("/example/ping")
    assert response.status_code == 200
    assert response.json() == {"module": "example", "status": "ok"}
    assert "/example/ping" in app.openapi()["paths"]


def test_a_disabled_module_mounts_nothing(monkeypatch):
    monkeypatch.syspath_prepend(str(FIXTURE))
    off = registry.build({**EXAMPLE_IDENTITY, "enabled": False}, root=FIXTURE)
    monkeypatch.setattr(registry, "MODULES", (*registry.MODULES, off))
    assert registry.mount_module_routers(FastAPI()) == []


# ── a table and a migration ──────────────────────────────────────────────────
def test_table_is_in_the_module_schema_and_owned_by_the_module(example, ownership):
    metadatas = registry.module_metadatas(example)
    assert [t.fullname for md in metadatas for t in md.tables.values()] == [
        "example.example_item"
    ]
    assert mb.module_table_problems(example, metadatas, ownership) == []


@pytest.fixture
def alembic_env(tmp_path):
    """A throwaway Alembic environment that runs ONLY the proof module's branch,
    with its own version table, against the suite's vetted scratch database
    (conftest has already set DATABASE_URL; this reads it, never assigns it)."""
    script_dir = tmp_path / "alembic_example"
    script_dir.mkdir()
    (script_dir / "env.py").write_text(
        textwrap.dedent(
            """
            import os
            from alembic import context
            from sqlalchemy import create_engine, pool

            engine = create_engine(os.environ["DATABASE_URL"], poolclass=pool.NullPool)
            with engine.connect() as connection:
                context.configure(connection=connection, version_table="alembic_version_example")
                with context.begin_transaction():
                    context.run_migrations()
            """
        )
    )
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(script_dir))
    cfg.set_main_option("version_locations", str(PACKAGE_DIR / "migrations"))
    return cfg


def test_migration_creates_and_removes_the_module_schema_and_table(alembic_env):
    from alembic import command
    from sqlalchemy import inspect, text

    from db.base import engine

    try:
        command.upgrade(alembic_env, "example@head")
        insp = inspect(engine)
        assert "example" in insp.get_schema_names()
        assert insp.get_table_names(schema="example") == ["example_item"]
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO example.example_item (label) VALUES ('proof')")
            )
            assert (
                conn.execute(text("SELECT count(*) FROM example.example_item")).scalar()
                == 1
            )

        command.downgrade(alembic_env, "example@base")
        assert "example" not in inspect(engine).get_schema_names()
    finally:
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS example CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS public.alembic_version_example"))


# ── a task ───────────────────────────────────────────────────────────────────
def test_task_is_loaded_through_the_registry_and_runs(example):
    import importlib

    from core.celery_app import celery_app

    assert registry.task_modules() == ["ccure_example.workers.ping"]
    try:
        for module in registry.task_modules():
            importlib.import_module(module)
        task = celery_app.tasks["ccure.example.ping"]
        assert task.name.startswith(example.task_prefix + ".")
        assert task.apply().get() == "pong"
    finally:
        celery_app.tasks.pop("ccure.example.ping", None)


# ── the guardrails catch a module that breaks its boundary ───────────────────
def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    """A synthetic source root: the proof module plus stand-ins for the
    application packages it might reach for."""
    root = tmp_path / "src"
    shutil.copytree(PACKAGE_DIR, root / "ccure_example")
    stubs = [
        "ccure_audit/__init__.py",
        "ccure_policy/__init__.py",
        "core/__init__.py",
        "core/tasks.py",
        "ccure_platform/__init__.py",
        "ccure_platform/api.py",
        "ccure_platform/identity/__init__.py",
        "db/__init__.py",
        "db/base.py",
        "db/models/__init__.py",
        "db/models/scans.py",
        "config.py",
    ]
    for rel in stubs:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).touch()
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


def _broken(root: Path, monkeypatch) -> set[tuple[str, str, str]]:
    """Violations of the SAME generated module rules production modules get."""
    _, edges = collect_edges(root)
    monkeypatch.setattr(
        layer_rules,
        "RULES",
        layer_rules.module_isolation_rules(("ccure_example", "ccure_policy")),
    )
    return {(name, e.src, e.dst) for name, e in layer_rules.violations(edges)}


def test_the_proof_module_as_written_breaks_no_import_rule(tmp_path, monkeypatch):
    assert _broken(_tree(tmp_path, {}), monkeypatch) == set()


def test_allowed_imports_are_allowed(tmp_path, monkeypatch):
    root = _tree(
        tmp_path,
        {
            "ccure_example/services/ok.py": "from ccure_platform.api import CurrentUser\nfrom db.base import SessionLocal\n",
        },
    )
    assert _broken(root, monkeypatch) == set()


@pytest.mark.parametrize(
    "line,target",
    [
        ("import ccure_audit", "ccure_audit"),
        ("from ccure_policy import x", "ccure_policy"),
        ("from core.tasks import run", "core.tasks"),
        ("from db.models.scans import Scan", "db.models.scans"),
        ("from ccure_platform.identity import x", "ccure_platform.identity"),
        ("import config", "config"),
    ],
)
def test_importing_another_modules_implementation_is_caught(
    tmp_path, monkeypatch, line, target
):
    root = _tree(tmp_path, {"ccure_example/services/bad.py": line + "\n"})
    assert (
        "module-isolation:ccure_example",
        "ccure_example.services.bad",
        target,
    ) in _broken(root, monkeypatch)


def test_importing_the_module_from_outside_is_caught(tmp_path, monkeypatch):
    root = _tree(
        tmp_path,
        {"core/reach.py": "from ccure_example.services.status import module_status\n"},
    )
    assert (
        "module-is-private:ccure_example",
        "core.reach",
        "ccure_example.services.status",
    ) in _broken(root, monkeypatch)


def test_the_proof_module_names_no_other_modules_table(ownership):
    assert mb.foreign_table_references(PACKAGE_DIR, "example", ownership) == []


@pytest.mark.parametrize(
    "source,table",
    [
        ('q = "SELECT * FROM scans WHERE id = 1"', "scans"),
        (
            'q = "select a.id from assets a join asset_vulnerabilities v on true"',
            "asset_vulnerabilities",
        ),
        (
            'q = "INSERT INTO policy_pro.baseline (id) VALUES (1)"',
            "policy_pro.baseline",
        ),
        ('from sqlalchemy import ForeignKey\nfk = ForeignKey("scans.id")', "scans"),
    ],
)
def test_naming_another_modules_table_is_caught(tmp_path, ownership, source, table):
    pkg = tmp_path / "ccure_example"
    shutil.copytree(PACKAGE_DIR, pkg)
    (pkg / "repositories" / "bad.py").write_text(source + "\n")
    own = dict(
        ownership,
        tables={
            **ownership["tables"],
            "policy_pro.baseline": {"owner": "policy_pro", "capability": "x"},
        },
    )
    problems = mb.foreign_table_references(pkg, "example", own)
    assert any(repr(table) in p for p in problems), problems


def test_platform_tables_are_not_this_checks_business(tmp_path, ownership):
    pkg = tmp_path / "ccure_example"
    shutil.copytree(PACKAGE_DIR, pkg)
    (pkg / "repositories" / "users.py").write_text('q = "SELECT id FROM users"\n')
    assert mb.foreign_table_references(pkg, "example", ownership) == []


def test_a_table_outside_the_module_schema_is_caught(example, ownership):
    from sqlalchemy import Column, Integer, MetaData, Table

    wrong = MetaData(schema="public")
    Table("stray", wrong, Column("id", Integer, primary_key=True))
    problems = mb.module_table_problems(example, [wrong], ownership)
    assert any("schema 'public'" in p for p in problems)
    assert any("registered to None" in p for p in problems)


def test_an_unregistered_table_is_caught(example, ownership):
    unregistered = dict(
        ownership,
        tables={
            k: v for k, v in ownership["tables"].items() if k != "example.example_item"
        },
    )
    problems = mb.module_table_problems(
        example, registry.module_metadatas(example), unregistered
    )
    assert any("'example.example_item' is registered to None" in p for p in problems)


def test_a_test_outside_its_module_test_folder_is_caught(tmp_path):
    tests = tmp_path / "tests"
    (tests / "scans").mkdir(parents=True)
    (tests / "scans" / "test_reaches_in.py").write_text("import ccure_example\n")
    (tests / "modules" / "example").mkdir(parents=True)
    (tests / "modules" / "example" / "test_fine.py").write_text(
        "import ccure_example\n"
    )
    problems = mb.misplaced_tests(tests, {"ccure_example": "modules/example"})
    assert problems == [
        "tests/scans/test_reaches_in.py imports ccure_example; its tests belong in tests/modules/example/"
    ]
