"""
The identity boundary — step 8.1 of the modular-platform programme.

Sign-in, users, organisations and roles belong to ``ccure_platform``, and Phase 8
makes ``ccure_platform.api`` the only way a module reaches them
(``docs/architecture/PHASE8_PLATFORM_IDENTITY.md``). These tests hold the line
while that happens. Each baseline in ``scripts/architecture/identity_boundary.py``
is a ratchet that fails in both directions:

* a new identity import, query, join or eager load in module code fails;
* a recorded one that no longer exists fails too, so the baseline can only
  shrink and a removed dependency cannot quietly return.

And three guards that keep the platform shared rather than a second home for
Audit:

* ``ccure_platform.api`` exports only the declared identity, tenancy and RBAC
  primitives;
* the platform imports no Audit model, and no Audit code
  (``platform-is-shared-foundation`` in ``layer_rules.py``);
* Audit's quotas and scan scope are not the platform's — the mentions that
  exist today are recorded, and step 8.4 removes them.

Everything is measured from source with ``ast``; no application code runs.
"""

from __future__ import annotations

import textwrap

import pytest
import yaml

from scripts.architecture import identity_boundary as ib
from scripts.architecture.import_graph import Edge, collect_edges, discover_modules
from scripts.architecture.layer_rules import violations
from testpaths import BACKEND_ROOT

OWNERSHIP_FILE = BACKEND_ROOT / "scripts" / "architecture" / "table_ownership.yaml"


@pytest.fixture(scope="module")
def measured():
    return ib.measure()


@pytest.fixture(scope="module")
def sites(measured):
    return measured[1]


def _scan(source: str, module: str = "core.example") -> list[tuple[str, str]]:
    return [(s.kind, s.what) for s in ib.scan_source(module, textwrap.dedent(source))]


# ── the measurement must be measuring something ──────────────────────────────


def test_the_measurement_walks_the_backend(measured):
    scanned, _ = measured
    assert scanned > 250, f"only {scanned} modules scanned — walker broken?"


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            "from auth.rbac import require_permission\n",
            [("import", "auth.rbac.require_permission")],
        ),
        ("import auth.jwt_handler\n", [("import", "auth.jwt_handler")]),
        (
            "def f():\n    from auth.email_utils import normalize_email\n",
            [("import", "auth.email_utils.normalize_email")],
        ),
        (
            "from db.models import User as U, Scan\n"
            "def f(db):\n    return db.query(U).first()\n",
            [("import", "db.models.User"), ("query", "User")],
        ),
        (
            "from db.models.rbac import Organization\n"
            "def f(db, o):\n    return db.query(Organization.name).filter(Organization.id == o).scalar()\n",
            [("import", "db.models.rbac.Organization"), ("query", "Organization")],
        ),
        (
            "from sqlalchemy import func, select, delete\nfrom db.models import User\n"
            "a = select(User.id)\nb = db.query(func.count(User.id))\n"
            "c = db.get(User, 'u1')\nd = delete(User)\n",
            [("import", "db.models.User")] + [("query", "User")] * 4,
        ),
        (
            "from db.models import User, RolePermission, Permission\n"
            "q = db.query(RolePermission).join(Permission, Permission.id == RolePermission.permission_id)\n"
            "r = db.query(User).options(joinedload(User.role))\n",
            [
                ("import", "db.models.User"),
                ("import", "db.models.RolePermission"),
                ("import", "db.models.Permission"),
                ("query", "RolePermission"),
                ("query", "User"),
                ("join", "Permission"),
                ("join", "User"),
            ],
        ),
        # an ORM delete of an instance and a dict update are not statements
        (
            "from db.models import User\nsession.delete(User)\nsettings.update(User)\n",
            [("import", "db.models.User")],
        ),
        # an Audit model is not identity, and neither is a local class named User
        ("from db.models import Scan\nq = db.query(Scan)\n", []),
        ("class User: ...\nq = db.query(User)\n", []),
        # the platform's own entry point is the permitted way in …
        (
            "from ccure_platform import api\nfrom ccure_platform.api import current_user\n",
            [],
        ),
        # … and its internals are not
        (
            "from ccure_platform.identity import tokens\nimport ccure_platform.rbac\n"
            "from ccure_platform import tenancy\n",
            [
                ("import", "ccure_platform.identity.tokens"),
                ("import", "ccure_platform.rbac"),
                ("import", "ccure_platform.tenancy"),
            ],
        ),
    ],
)
def test_the_detector_sees_what_it_describes(source, expected):
    assert sorted(_scan(source)) == sorted(expected)


def test_the_platform_side_exemptions_name_real_modules():
    """A renamed identity router must not keep an exemption nobody can see."""
    modules = set(discover_modules())
    for prefix in ib.PLATFORM_SIDE_PREFIXES:
        assert any(
            m == prefix or m.startswith(prefix + ".") for m in modules
        ), f"PLATFORM_SIDE_PREFIXES names {prefix!r}, which does not exist"
    for name in ib.PLATFORM_SIDE_EXACT:
        assert name in modules


def test_audit_modules_are_not_exempt_through_the_model_registry():
    assert ib.is_platform_side("db.models")
    assert ib.is_platform_side("db.models.users")
    assert not ib.is_platform_side("db.models.scans")
    assert not ib.is_platform_side("routers.scan_history")


# ── the ratchets ─────────────────────────────────────────────────────────────


def _diff_counts(current: dict, known: dict) -> tuple[list[str], list[str]]:
    grown, shrunk = [], []
    for module in sorted(set(current) | set(known)):
        now, then = current.get(module, {}), known.get(module, {})
        for model in sorted(set(now) | set(then)):
            a, b = now.get(model, 0), then.get(model, 0)
            if a > b:
                grown.append(f"  {module}: {model} {b} -> {a}")
            elif a < b:
                shrunk.append(f"  {module}: {model} {b} -> {a}")
    return grown, shrunk


def test_no_new_identity_imports(sites):
    current = ib.imports_by_module(sites)
    added = sorted(
        (m, s)
        for m, symbols in current.items()
        for s in symbols - ib.KNOWN_IDENTITY_IMPORTS.get(m, frozenset())
    )
    assert not added, (
        "new identity import(s) outside the platform:\n"
        + "\n".join(f"  {m}: {s}" for m, s in added)
        + "\nModules reach identity through ccure_platform.api (Phase 8). Adding "
        "an entry to KNOWN_IDENTITY_IMPORTS needs an explicit reason in review."
    )


def test_removed_identity_imports_are_removed_from_the_baseline(sites):
    current = ib.imports_by_module(sites)
    stale = sorted(
        (m, s)
        for m, symbols in ib.KNOWN_IDENTITY_IMPORTS.items()
        for s in symbols - current.get(m, frozenset())
    )
    assert not stale, (
        "these identity imports no longer exist — delete them from "
        "KNOWN_IDENTITY_IMPORTS in scripts/architecture/identity_boundary.py:\n"
        + "\n".join(f"  {m}: {s}" for m, s in stale)
    )


@pytest.mark.parametrize(
    "kind, baseline_name",
    [("query", "KNOWN_IDENTITY_QUERIES"), ("join", "KNOWN_IDENTITY_JOINS")],
)
def test_identity_queries_only_ever_fall(sites, kind, baseline_name):
    known = getattr(ib, baseline_name)
    grown, shrunk = _diff_counts(ib.counts_by_module(sites, kind), known)
    assert not grown, (
        f"new direct {kind}(s) of an identity table outside the platform:\n"
        + "\n".join(grown)
        + "\nAsk ccure_platform.api instead (Phase 8, step 8.3)."
    )
    assert not shrunk, (
        f"fewer identity {kind}s than recorded — lower {baseline_name} in "
        "scripts/architecture/identity_boundary.py so they cannot come back:\n"
        + "\n".join(shrunk)
    )


def test_the_baseline_is_the_one_measured_on_28_sep_2026():
    """
    The figures the proposal and the plan quote. Lowering them is the point of
    steps 8.3–8.5; this test is updated with them, never raised.
    """
    queries = sum(sum(v.values()) for v in ib.KNOWN_IDENTITY_QUERIES.values())
    joins = sum(sum(v.values()) for v in ib.KNOWN_IDENTITY_JOINS.values())
    settings = sum(sum(v.values()) for v in ib.KNOWN_AUDIT_SETTING_REFERENCES.values())
    assert len(ib.KNOWN_IDENTITY_IMPORTS) <= 32
    assert queries <= 53
    assert len(ib.KNOWN_IDENTITY_QUERIES) <= 23
    assert joins <= 8
    assert settings <= 11


# ── the platform stays shared ────────────────────────────────────────────────


def test_the_platform_api_exports_only_declared_primitives():
    import ccure_platform.api as api

    exported = set(api.__all__)
    assert exported <= ib.PLATFORM_API_SURFACE, (
        f"ccure_platform.api exports {sorted(exported - ib.PLATFORM_API_SURFACE)}, "
        "which PLATFORM_API_SURFACE does not declare. The platform holds shared "
        "identity, tenancy and RBAC primitives only."
    )
    public = {
        name
        for name, value in vars(api).items()
        if not name.startswith("_")
        and getattr(value, "__module__", api.__name__) == api.__name__
    }
    # Names defined here must be exported. Re-exported dependencies keep the
    # module they were defined in, so they appear in __all__ only.
    assert (
        public <= exported
    ), f"public names not in __all__: {sorted(public - exported)}"


def test_the_platform_api_surface_names_no_audit_setting():
    for name in ib.PLATFORM_API_SURFACE:
        for setting in ib.AUDIT_SETTINGS_ON_ORGANIZATIONS + ("quota", "scope", "scan"):
            assert setting not in name.lower(), name


@pytest.fixture(scope="module")
def model_owner():
    """Mapped class name -> owning module, from the table-ownership registry."""
    import db.models  # noqa: F401  (registers every model)
    from db.base import Base

    owners = yaml.safe_load(OWNERSHIP_FILE.read_text(encoding="utf-8"))["tables"]
    out = {}
    for mapper in Base.registry.mappers:
        table = mapper.persist_selectable
        name = getattr(table, "name", None)
        if name in owners:
            out[mapper.class_.__name__] = owners[name]["owner"]
    return out


def test_platform_code_imports_no_module_model(model_owner):
    """
    ``from db.models import Scan`` is an edge to ``db.models`` — the layer rule
    cannot see it, so it is checked by name. ``auth/`` is included too: since
    step 8.2 it holds only alias stubs, and it must stay that way.
    """
    import ast

    offending = []
    for module, path in sorted(discover_modules().items()):
        if module.split(".")[0] not in ("ccure_platform", "auth"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "db.models"
            ):
                for alias in node.names:
                    owner = model_owner.get(alias.name)
                    if owner is not None and owner != "platform":
                        offending.append(f"  {module}: {alias.name} ({owner})")
    assert not offending, "platform code imports another module's model:\n" + "\n".join(
        offending
    )


def test_model_owner_mapping_is_not_vacuous(model_owner):
    assert model_owner.get("User") == "platform"
    assert model_owner.get("Organization") == "platform"
    assert model_owner.get("Scan") == "audit"


def test_every_model_module_is_classified_for_the_platform_rule():
    """A new model file must be named platform-importable or forbidden."""
    from scripts.architecture.layer_rules import RULES

    rule = next(r for r in RULES if r.name == "platform-is-shared-foundation")
    platform_models = {
        "db.models.users",
        "db.models.rbac",
        "db.models.email_security",
        "db.models.notifications",
    }
    model_modules = {m for m in discover_modules() if m.startswith("db.models.")}
    unclassified = sorted(model_modules - platform_models - set(rule.forbidden))
    assert not unclassified, (
        "model module(s) neither platform-owned nor forbidden to ccure_platform "
        f"in layer_rules.py: {unclassified}"
    )


# ── Audit's settings are Audit's ─────────────────────────────────────────────


def test_audit_settings_detector():
    source = textwrap.dedent(
        """
        class Organization(Base):
            max_assets = Column(Integer)
            scan_scope_cidrs: list = None

        org = Organization(max_assets=100)
        cap = org.max_scans_per_day
        payload = {"scan_scope_cidrs": []}
        def f(max_concurrent_scans): ...
        """
    )
    found = sorted(s.what for s in ib.audit_setting_references("x", source))
    assert found == [
        "max_assets",
        "max_concurrent_scans",
        "max_scans_per_day",
        "scan_scope_cidrs",
    ]


def test_audit_settings_on_the_platform_side_only_ever_fall():
    current = ib.counts_by_module(ib.measure_platform_settings(), "setting")
    grown, shrunk = _diff_counts(current, ib.KNOWN_AUDIT_SETTING_REFERENCES)
    assert not grown, (
        "platform-side code mentions an Audit setting (quota or scan scope) it "
        "did not before:\n"
        + "\n".join(grown)
        + "\nThese are Audit's; step 8.4 moves them to audit_organisation_settings."
    )
    assert not shrunk, (
        "fewer Audit-setting mentions than recorded — lower "
        "KNOWN_AUDIT_SETTING_REFERENCES:\n" + "\n".join(shrunk)
    )
