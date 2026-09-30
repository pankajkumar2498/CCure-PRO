"""
Phase 11.3 — each core module's own Alembic branch, and multi-head handling.

What is pinned:

* ``ccure_policy/migrations`` and ``ccure_rank/migrations`` each hold one base
  revision, ``<key>_0001``, labelled with the module's key, with no parent — a
  branch of its own, not a child of Audit's history;
* with the branches activated (``scripts/db/alembic_module_branches.activate``,
  exactly what the live step applies), the history has three heads: Audit's
  ``f3b5d7e9a1c4`` and the two module bases — and Audit's own lineage is
  unchanged;
* Phase 11 creates **no Policy Pro or Rank table**: the base revisions create
  their schema and nothing else;
* a module's migrations act only on its own schema
  (``module_boundaries.migration_problems``), proven against the real modules,
  the test-only proof module, and synthetic violations;
* Phase 11.4 (decision D11-1): no module roles before Phase 18 — no migration
  creates a role, grants, revokes or changes an owner, and the module schemas
  stay owned by the application's role;
* the activation helper changes exactly two settings and keeps the file's line
  endings;
* nothing that runs a migration still says ``head`` where it must say
  ``heads`` — the start-up migrator, the test bootstrap, CI and the runbooks.
"""

from __future__ import annotations

import ast
import re

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from ccure_platform.modules import registry
from scripts.architecture import module_boundaries as mb
from scripts.db import alembic_module_branches as branches
from testpaths import BACKEND_ROOT, REPO_ROOT

AUDIT_HEAD = "f3b5d7e9a1c4"
MODULES = [m for m in registry.modules() if m.key != "audit"]
EXAMPLE_MIGRATIONS = (
    BACKEND_ROOT
    / "tests"
    / "modules"
    / "example"
    / "fixture"
    / "ccure_example"
    / "migrations"
)


def _activated_script() -> ScriptDirectory:
    """The history exactly as the activated alembic.ini describes it."""
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    value = branches.version_locations_line().split("=", 1)[1].strip()
    cfg.set_main_option("version_locations", value)
    cfg.set_main_option("path_separator", "space")
    return ScriptDirectory.from_config(cfg)


def _audit_script() -> ScriptDirectory:
    """Audit's history alone — the committed, inactive alembic.ini's view."""
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("version_locations", "%(here)s/alembic/versions")
    return ScriptDirectory.from_config(cfg)


def _ini_text() -> str:
    # Bytes: universal-newline reading would hide the file's CRLF.
    return (BACKEND_ROOT / "alembic.ini").read_bytes().decode("utf-8")


# ── the branches ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("m", MODULES, ids=lambda m: m.key)
def test_each_module_has_exactly_one_base_revision_labelled_with_its_key(m):
    files = sorted((BACKEND_ROOT / m.package / "migrations").glob("*.py"))
    assert [f.name for f in files] == [f"{m.key}_0001_create_schema.py"]
    tree = ast.parse(files[0].read_text(encoding="utf-8"))
    values = {
        t.id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        for t in node.targets
        if isinstance(t, ast.Name)
    }
    assert values["revision"] == f"{m.key}_0001"
    assert values["down_revision"] is None
    assert values["branch_labels"] == (m.key,)
    assert values["depends_on"] is None


def test_activated_history_has_audits_head_and_one_head_per_module():
    script = _activated_script()
    assert set(script.get_heads()) == {AUDIT_HEAD, "policy_pro_0001", "rank_0001"}
    assert {"policy_pro_0001", "rank_0001"} <= set(script.get_bases())
    assert script.get_revision("policy_pro@head").revision == "policy_pro_0001"
    assert script.get_revision("rank@head").revision == "rank_0001"


def test_audits_own_lineage_is_unchanged_by_the_branches():
    committed = {r.revision: r.down_revision for r in _audit_script().walk_revisions()}
    activated = {
        r.revision: r.down_revision for r in _activated_script().walk_revisions()
    }
    assert set(activated) - set(committed) == {"policy_pro_0001", "rank_0001"}
    assert {
        k: activated[k] for k in committed
    } == committed  # every Audit revision, same parent
    assert _audit_script().get_heads() == [AUDIT_HEAD]


# ── no feature tables ────────────────────────────────────────────────────────
@pytest.mark.parametrize("m", MODULES, ids=lambda m: m.key)
def test_the_base_revision_creates_only_the_empty_schema(m):
    source = (
        BACKEND_ROOT / m.package / "migrations" / f"{m.key}_0001_create_schema.py"
    ).read_text()
    tree = ast.parse(source)
    ops = [
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "op"
    ]
    assert ops == ["execute", "execute"], ops
    sql = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and n.value.upper().startswith(("CREATE", "DROP"))
    ]
    assert sql == [
        f"CREATE SCHEMA IF NOT EXISTS {m.db_schema}",
        f"DROP SCHEMA IF EXISTS {m.db_schema} RESTRICT",
    ]


@pytest.mark.parametrize("m", MODULES, ids=lambda m: m.key)
def test_the_module_declares_no_tables_yet(m):
    assert m.models == ()
    assert registry.module_metadatas(m) == []


# ── migrations touch only their own schema ───────────────────────────────────
@pytest.mark.parametrize("m", MODULES, ids=lambda m: m.key)
def test_module_migrations_touch_only_the_module_schema(m):
    assert (
        mb.migration_problems(BACKEND_ROOT / m.package / "migrations", m.db_schema)
        == []
    )


def test_the_proof_modules_migration_obeys_the_same_rule():
    assert mb.migration_problems(EXAMPLE_MIGRATIONS, "example") == []


@pytest.mark.parametrize(
    "source,fragment",
    [
        (
            'from alembic import op\nop.execute("CREATE SCHEMA IF NOT EXISTS rank")',
            "names 'rank'",
        ),
        (
            'from alembic import op\nop.execute("DROP SCHEMA public CASCADE")',
            "names 'public'",
        ),
        (
            'from alembic import op\nimport sqlalchemy as sa\nop.create_table("t", sa.Column("id", sa.Integer))',
            "must pass schema='policy_pro' (got None)",
        ),
        (
            'from alembic import op\nimport sqlalchemy as sa\nop.add_column("scans", sa.Column("x", sa.Integer), schema="public")',
            "(got 'public')",
        ),
    ],
)
def test_a_migration_reaching_outside_its_schema_is_caught(tmp_path, source, fragment):
    (tmp_path / "bad_0002.py").write_text(source + "\n")
    problems = mb.migration_problems(tmp_path, "policy_pro")
    assert any(fragment in p for p in problems), problems


# ── Phase 11.4, decision D11-1: no module roles before Phase 18 ──────────────
@pytest.mark.parametrize(
    "sql",
    [
        "CREATE ROLE ccure_policy_owner NOLOGIN",
        "create user policy_app with password 'x'",
        "ALTER ROLE ccure_user CREATEROLE",
        "DROP ROLE IF EXISTS ccure_rank_owner",
        "GRANT USAGE, CREATE ON SCHEMA policy_pro TO ccure_policy_owner",
        "GRANT ccure_policy_owner TO ccure_user",
        "REVOKE ALL ON SCHEMA policy_pro FROM PUBLIC",
        "ALTER SCHEMA policy_pro OWNER TO ccure_policy_owner",
        "ALTER TABLE policy_pro.t OWNER TO someone",
        "REASSIGN OWNED BY ccure_user TO ccure_policy_owner",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA policy_pro GRANT SELECT ON TABLES TO x",
        "SET ROLE ccure_policy_owner",
        "SET SESSION AUTHORIZATION ccure_policy_owner",
    ],
)
def test_a_module_migration_cannot_touch_roles_grants_or_owners(tmp_path, sql):
    (tmp_path / "bad_0002.py").write_text(
        f'from alembic import op\n\n\ndef upgrade():\n    op.execute("{sql}")\n'
    )
    problems = mb.migration_problems(tmp_path, "policy_pro")
    assert any("deferred to Phase 18 (D11-1)" in p for p in problems), problems


def test_prose_about_grants_in_a_docstring_is_not_a_statement(tmp_path):
    (tmp_path / "ok_0002.py").write_text(
        '"""Grant nothing here: roles, and who owns the schema, are Phase 18\'s."""\n'
        "from alembic import op\n\n\n"
        "def upgrade():\n"
        '    """The owner to whom grants go is decided later."""\n'
        '    op.execute("CREATE SCHEMA IF NOT EXISTS policy_pro")\n'
    )
    assert mb.migration_problems(tmp_path, "policy_pro") == []


def test_module_schemas_belong_to_the_application_role_and_no_module_role_exists(
    db_session,
):
    from sqlalchemy import text

    for m in MODULES:
        owner, acl = db_session.execute(
            text(
                "SELECT pg_get_userbyid(nspowner), nspacl::text "
                "FROM pg_namespace WHERE nspname = :s"
            ),
            {"s": m.db_schema},
        ).one()
        me = db_session.execute(text("SELECT current_user")).scalar()
        assert (owner, acl) == (me, None), m.db_schema
    # The role names option B would have created (PHASE11_MODULE_FOLDERS.md §3.4).
    assert (
        db_session.execute(
            text(
                "SELECT count(*) FROM pg_roles "
                "WHERE rolname IN ('ccure_policy_owner', 'ccure_rank_owner')"
            )
        ).scalar()
        == 0
    )


# ── the activation helper ────────────────────────────────────────────────────
def test_activation_changes_exactly_two_settings_and_keeps_line_endings():
    committed = _ini_text()
    if branches.is_active(committed):
        pytest.skip("alembic.ini is already activated (rehearsal copy or live)")
    activated = branches.activate(committed)
    before, after = committed.splitlines(keepends=True), activated.splitlines(
        keepends=True
    )
    added = [line for line in after if line not in before]
    removed = [line for line in before if line not in after]
    newline = "\r\n" if "\r\n" in committed else "\n"
    assert removed == [f"path_separator = os{newline}"]
    assert added == [
        f"{branches.MARKER}{newline}",
        f"{branches.version_locations_line()}{newline}",
        f"path_separator = space{newline}",
    ]
    assert activated.isascii()


def test_activation_is_idempotent_and_detectable():
    committed = _ini_text()
    once = branches.activate(committed)
    assert branches.activate(once) == once
    assert branches.is_active(once)


def test_the_activation_lists_every_module_with_migrations():
    line = branches.version_locations_line()
    assert line == (
        "version_locations = %(here)s/alembic/versions "
        "%(here)s/ccure_policy/migrations %(here)s/ccure_rank/migrations"
    )


# ── every migration command handles several heads ───────────────────────────
_SINGLE_HEAD = re.compile(r"""(?:upgrade|stamp)[\s(,'"cfg]*['"]?head\b(?!s)""")

#: Files that run, or tell a person to run, a migration. Historical records
#: (docs/gap_closure, docs/architecture) describe what was done at the time and
#: are deliberately not rewritten.
_RUNBOOKS = [
    "README.md",
    "Backend/db/migrate_production_schema.py",
    "Backend/tests/conftest.py",
    "Backend/alembic/MIGRATIONS.md",
    "docs/DEVELOPER_SETUP_GUIDE.md",
    "docs/DATABASE_SCHEMA.md",
    "docs/AUDIT_VERIFICATION_GAPS.md",
    "docs/policy compliance/compliance_developer_guide.md",
    "docs/policy compliance/compliance_deployment_guide.md",
    ".github/workflows/ci.yml",
    ".github/pull_request_template.md",
]


@pytest.mark.parametrize("rel", _RUNBOOKS)
def test_no_migration_command_assumes_a_single_head(rel):
    path = REPO_ROOT / rel
    if not path.exists():
        pytest.skip(
            f"{rel} is not reachable from this checkout (CI runs on a full one)"
        )
    hits = [
        f"{rel}:{i}: {line.strip()}"
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _SINGLE_HEAD.search(line)
    ]
    assert not hits, (
        "say `heads`, not `head` — each core module has its own branch:\n  "
        + "\n  ".join(hits)
    )


def test_the_test_bootstrap_compares_heads_as_sets():
    tree = ast.parse(
        (BACKEND_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    )
    called = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    # Both raise once there is more than one head.
    assert not called & {"get_current_head", "get_current_revision"}
    assert {"get_heads", "get_current_heads"} <= called


def test_the_startup_migrator_does_not_refuse_several_heads():
    source = (BACKEND_ROOT / "db" / "migrate_production_schema.py").read_text(
        encoding="utf-8"
    )
    assert '"heads"' in source
    assert "get_current_head()" not in source


def test_a_fresh_install_stamps_only_audits_history():
    # create_all builds Audit's and the platform's tables; the module branches
    # must then run as migrations, not be stamped past a CREATE SCHEMA.
    from db import migrate_production_schema as migrator

    assert migrator._audit_heads() == [AUDIT_HEAD]
