"""
Phase 11.1 — the platform module registry.

What is pinned:

* the three module identities the core hosts — Policy Pro, Audit, Rank — and
  their packages, schemas, route prefixes and task prefixes;
* the 11.1 state: Audit enabled and declaring nothing (its routers and tasks are
  still listed explicitly until Phase 16), Policy Pro and Rank disabled and
  empty — so the registry mounts no route, loads no task and adds no queue;
* the registry is a **leaf**: its source imports only the standard library and
  itself. ``core/celery_app.py`` reads it, and shared infrastructure may import
  no feature, so the layer rules exempt exactly this package and this test is
  what keeps that exemption honest;
* collisions and out-of-package references are refused at construction;
* ``mount_module_routers`` mounts an enabled module's routers under its prefix
  and ignores a disabled module;
* the consumers read it: ``main.py`` calls ``mount_module_routers`` and
  ``celery_app`` carries exactly its previous task modules and queues.
"""

from __future__ import annotations

import ast
import sys
import types

import pytest
from fastapi import APIRouter, FastAPI

from ccure_platform.modules import ManifestError, ModuleManifest, registry
from scripts.architecture.layer_rules import RULES
from testpaths import BACKEND_ROOT, MAIN_PY

REGISTRY_DIR = BACKEND_ROOT / "ccure_platform" / "modules"
STDLIB_ALLOWED = {
    "__future__",
    "dataclasses",
    "importlib",
    "pathlib",
    "re",
    "tomllib",
    "typing",
}


# ── Phase 11.2: each module declares its contributions in its own manifest.toml ─
@pytest.mark.parametrize(
    "package,key",
    [
        ("ccure_policy", "policy_pro"),
        ("ccure_audit", "audit"),
        ("ccure_rank", "rank"),
    ],
)
def test_each_module_declares_its_contributions_in_its_own_manifest(package, key):
    assert (BACKEND_ROOT / package / "manifest.toml").is_file()
    assert registry.load_contributions(package, key) == {
        "routers": (),
        "task_modules": (),
        "models": (),
        # Audit alone declares where its audit-event definitions are registered
        "audit_event_modules": (
            ("ccure_audit.audit_events",) if key == "audit" else ()
        ),
    }


def _manifest(tmp_path, text, package="ccure_demo"):
    (tmp_path / package).mkdir()
    (tmp_path / package / "manifest.toml").write_text(text)
    return tmp_path


@pytest.mark.parametrize(
    "text,fragment",
    [
        ("", "one [module] table"),
        ('[module]\nkey = "other"\n', "declares key 'other'"),
        ('[module]\nkey = "demo"\nenabled = true\n', "identity is the platform's"),
        ('[module]\nkey = "demo"\nroute_prefix = "/x"\n', "identity is the platform's"),
        (
            '[module]\nkey = "demo"\nrouters = "ccure_demo.api:router"\n',
            "list of strings",
        ),
        ('[module]\nkey = "demo"\n[other]\nx = 1\n', "one [module] table"),
        ("[module\n", "manifest.toml"),
    ],
)
def test_a_bad_manifest_file_is_refused(tmp_path, text, fragment):
    root = _manifest(tmp_path, text)
    with pytest.raises(ManifestError) as err:
        registry.load_contributions("ccure_demo", "demo", root)
    assert fragment in str(err.value)
    assert "'demo'" in str(err.value)


def test_a_registered_module_without_a_manifest_is_refused(tmp_path):
    with pytest.raises(ManifestError, match="manifest.toml is missing"):
        registry.load_contributions("ccure_demo", "demo", tmp_path)


def test_build_joins_the_platform_identity_and_the_module_contributions(tmp_path):
    root = _manifest(
        tmp_path,
        '[module]\nkey = "demo"\nrouters = ["ccure_demo.api:router"]\n'
        'task_modules = ["ccure_demo.workers.jobs"]\nmodels = ["ccure_demo.models:metadata"]\n',
    )
    m = registry.build(
        dict(
            key="demo",
            title="Demo",
            description="A test-only module.",
            entry_path="/demo-dashboard",
            package="ccure_demo",
            db_schema="demo",
            route_prefix="/demo",
            task_prefix="ccure.demo",
        ),
        root,
    )
    assert m.routers == ("ccure_demo.api:router",)
    assert m.task_modules == ("ccure_demo.workers.jobs",)
    assert m.models == ("ccure_demo.models:metadata",)
    assert not m.enabled  # enabling stays the platform's decision


def test_a_manifest_reaching_outside_its_package_is_refused(tmp_path):
    root = _manifest(
        tmp_path, '[module]\nkey = "demo"\nmodels = ["ccure_audit.models:metadata"]\n'
    )
    with pytest.raises(ManifestError, match="outside the module's package"):
        registry.build(
            dict(
                key="demo",
                title="Demo",
                description="A test-only module.",
                entry_path="/demo-dashboard",
                package="ccure_demo",
                db_schema="demo",
                route_prefix="/demo",
                task_prefix="ccure.demo",
            ),
            root,
        )


# ── the three identities ─────────────────────────────────────────────────────
def test_the_core_hosts_exactly_three_modules():
    assert [m.key for m in registry.modules()] == ["policy_pro", "audit", "rank"]


@pytest.mark.parametrize(
    "key,package,schema,prefix,task_prefix",
    [
        ("policy_pro", "ccure_policy", "policy_pro", "/policy", "ccure.policy"),
        ("audit", "ccure_audit", "public", "", "ccure.audit"),
        ("rank", "ccure_rank", "rank", "/rank", "ccure.rank"),
    ],
)
def test_module_identity(key, package, schema, prefix, task_prefix):
    m = registry.get(key)
    assert (m.package, m.db_schema, m.route_prefix, m.task_prefix) == (
        package,
        schema,
        prefix,
        task_prefix,
    )


def test_phase_11_1_state_audit_enabled_policy_and_rank_disabled_and_empty():
    audit, policy, rank = (
        registry.get("audit"),
        registry.get("policy_pro"),
        registry.get("rank"),
    )
    assert audit.enabled and audit.tile_state == "available"
    for m in (policy, rank):
        assert not m.enabled
        assert m.tile_state == "not_yet_available"
    for m in registry.modules():
        # nothing to mount or load yet: Audit's routers and tasks are main.py's
        # and celery_app's explicit lists until Phase 16
        assert (m.routers, m.task_modules, m.queues) == ((), (), ()), m.key
    assert registry.task_modules() == [] and registry.queues() == []


def test_unknown_module_is_a_key_error():
    with pytest.raises(KeyError):
        registry.get("ir")  # IR is a separate service (Phase 13), never a core module


# ── the leaf property ────────────────────────────────────────────────────────
def _imports(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):  # imports inside functions count (CLAUDE.md)
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            yield node.module


def test_the_registry_is_a_leaf():
    files = sorted(REGISTRY_DIR.glob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "manifest.py", "registry.py"}
    for f in files:
        for name in _imports(f):
            top = name.split(".")[0]
            assert top in STDLIB_ALLOWED or name.startswith("ccure_platform.modules"), (
                f"{f.name} imports {name}: the registry must stay a leaf, because "
                "core/celery_app.py (shared infrastructure) reads it"
            )


def test_infrastructure_may_read_the_registry_and_nothing_else_of_the_platform():
    rule = next(r for r in RULES if r.name == "infrastructure-is-foundation")
    assert "ccure_platform" in rule.forbidden
    assert rule.exempt_targets == ("ccure_platform.modules",)


# ── validation ───────────────────────────────────────────────────────────────
def _m(**kw):
    base = dict(
        key="demo",
        title="Demo",
        description="A test-only module.",
        entry_path="/demo-dashboard",
        package="ccure_demo",
        db_schema="demo",
        route_prefix="/demo",
        task_prefix="ccure.demo",
    )
    return ModuleManifest(**{**base, **kw})


@pytest.mark.parametrize(
    "kw,fragment",
    [
        ({"key": "Demo"}, "key"),
        ({"package": "demo"}, "package"),
        ({"package": "ccure_demo.sub"}, "package"),
        ({"db_schema": "demo; drop"}, "db_schema"),
        ({"route_prefix": "demo"}, "route_prefix"),
        ({"route_prefix": "/api/demo"}, "route_prefix"),
        ({"task_prefix": "demo.tasks"}, "task_prefix"),
        ({"tile_state": "coming_soon"}, "tile_state"),
        ({"routers": ("ccure_other.api:router",)}, "outside"),
        ({"routers": ("ccure_demo.api",)}, "package.module:attribute"),
        ({"task_modules": ("core.tasks",)}, "outside"),
        (
            {"routers": ("ccure_demo.api:router",), "route_prefix": ""},
            "own route_prefix",
        ),
        ({"queues": ("Bad Queue",)}, "queue"),
    ],
)
def test_a_bad_manifest_is_refused_with_the_module_named(kw, fragment):
    with pytest.raises(ManifestError) as err:
        _m(**kw)
    assert "'demo'" in str(err.value) or "'Demo'" in str(err.value)
    assert fragment in str(err.value)


@pytest.mark.parametrize(
    "field,a,b",
    [
        ("package", {"package": "ccure_x"}, {"package": "ccure_x"}),
        ("db_schema", {"db_schema": "x"}, {"db_schema": "x"}),
        ("route_prefix", {"route_prefix": "/x"}, {"route_prefix": "/x"}),
        ("task_prefix", {"task_prefix": "ccure.x"}, {"task_prefix": "ccure.x"}),
        ("queue", {"queues": ("q1",)}, {"queues": ("q1",)}),
    ],
)
def test_two_modules_may_not_share(field, a, b):
    one = _m(
        key="one",
        package="ccure_one",
        db_schema="one",
        route_prefix="/one",
        task_prefix="ccure.one",
    )
    two = _m(
        key="two",
        package="ccure_two",
        db_schema="two",
        route_prefix="/two",
        task_prefix="ccure.two",
    )
    one, two = ModuleManifest(**{**_fields(one), **a}), ModuleManifest(
        **{**_fields(two), **b}
    )
    with pytest.raises(ManifestError, match=field):
        registry._check((one, two))


def test_a_task_prefix_may_not_nest_inside_another():
    one = _m(
        key="one",
        package="ccure_one",
        db_schema="one",
        route_prefix="/one",
        task_prefix="ccure.one",
    )
    two = _m(
        key="two",
        package="ccure_two",
        db_schema="two",
        route_prefix="/two",
        task_prefix="ccure.one.two",
    )
    with pytest.raises(ManifestError, match="nests"):
        registry._check((one, two))


def _fields(m):
    return {f: getattr(m, f) for f in m.__dataclass_fields__}


# ── mounting ─────────────────────────────────────────────────────────────────
def test_mount_mounts_an_enabled_module_under_its_prefix_and_skips_a_disabled_one(
    monkeypatch,
):
    for name in ("ccure_demo", "ccure_demo.api", "ccure_off", "ccure_off.api"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    on, off = APIRouter(), APIRouter()

    @on.get("/hello")
    def hello():
        return {"ok": True}

    @off.get("/hidden")
    def hidden():
        return {}

    sys.modules["ccure_demo.api"].router = on
    sys.modules["ccure_off.api"].router = off
    monkeypatch.setattr(
        registry,
        "MODULES",
        (
            _m(routers=("ccure_demo.api:router",), enabled=True),
            _m(
                key="off",
                package="ccure_off",
                db_schema="off",
                route_prefix="/off",
                task_prefix="ccure.off",
                routers=("ccure_off.api:router",),
                enabled=False,
            ),
        ),
    )
    app = FastAPI()
    mounted = registry.mount_module_routers(app)
    paths = {r.path for r in app.routes}
    assert mounted == [("/demo", "ccure_demo.api:router")]
    assert "/demo/hello" in paths and "/off/hidden" not in paths


# ── the consumers ────────────────────────────────────────────────────────────
def test_main_mounts_through_the_registry_after_audits_own_routers():
    source = MAIN_PY.read_text()
    assert "mount_module_routers(app)" in source
    assert source.index("mount_module_routers(app)") > source.index(
        "app.include_router(compliance_router)"
    )


def test_the_application_has_no_module_routes_yet():
    from main import app

    paths = {getattr(r, "path", "") for r in app.routes}
    assert not any(
        p == "/policy" or p.startswith(("/policy/", "/rank/")) or p == "/rank"
        for p in paths
    )


def test_celery_carries_exactly_its_previous_task_modules_and_queues():
    from core.celery_app import celery_app

    assert list(celery_app.conf.include) == [
        "core.tasks",
        "core.web.tasks",
        "core.compliance_tasks",
        "core.email_security_tasks",
        "auth.mail_tasks",
        "ccure_platform.identity.account_maintenance",
        "ccure_platform.audit_log.tasks",
    ]
    assert [q.name for q in celery_app.conf.task_queues] == [
        "default",
        "scanner",
        "web_recon",
        "web_crawl",
        "web_dast",
        "web_audit",
        "compliance",
    ]
