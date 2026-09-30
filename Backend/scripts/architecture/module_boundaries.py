"""
Module boundaries the import graph cannot see (Phase 11.2).

The layer rules (``layer_rules.module_isolation_rules``) stop a module
*importing* another module's code, which is how it would reach another module's
ORM models. Four things remain, and each is checked here from source or from
the SQLAlchemy metadata, without running any module:

* **Tables** — every table a module declares lives in the module's own schema
  and is registered to it in ``table_ownership.yaml``
  (``module_table_problems``);
* **Raw SQL** — a module's string literals never name a table another module
  owns, in ``FROM``/``JOIN``/``INTO``/``UPDATE``/``TABLE``/``TRUNCATE`` or a
  ``ForeignKey("…")`` (``foreign_table_references``). Platform tables are the
  identity boundary's business (Phase 8), not this check's;
* **Tests** — a test importing a module lives in that module's test folder
  (``misplaced_tests``);
* **Ownership** — ``CODEOWNERS`` names an owner line for every module package
  and its test folder (``codeowners_gaps``).

Each function returns a list of human-readable problems; an empty list means the
boundary holds. The functions take their inputs as arguments, so the proof module
in the test suite is checked by exactly the code production modules are.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_SQL_TABLE = re.compile(
    r"\b(?:from|join|into|update|table|truncate)\s+"
    r'(?:"?(?P<schema>[a-z_][a-z0-9_]*)"?\.)?"?(?P<table>[a-z_][a-z0-9_]*)"?',
    re.IGNORECASE,
)
_FK = re.compile(
    r"^(?:(?P<schema>[a-z_][a-z0-9_]*)\.)?(?P<table>[a-z_][a-z0-9_]*)\.[a-z_][a-z0-9_]*$"
)

#: Owners that are modules. `platform` tables are shared and governed by the
#: identity boundary (ccure_platform.api), not by module isolation.
MODULE_OWNERS = ("audit", "policy_pro", "rank")


def table_owners(ownership: dict) -> dict[str, str]:
    """``{"table" or "schema.table": owner}`` from table_ownership.yaml."""
    return {name: entry["owner"] for name, entry in ownership["tables"].items()}


def _owner_of(owners: dict[str, str], schema: str | None, table: str) -> str | None:
    if schema and f"{schema}.{table}" in owners:
        return owners[f"{schema}.{table}"]
    if schema in (None, "public"):
        return owners.get(table)
    return None


def _string_constants(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value


def foreign_table_references(
    package_dir: Path, own_key: str, ownership: dict
) -> list[str]:
    """Every string in a module's source that names a table another *module* owns."""
    owners = table_owners(ownership)
    problems: list[str] = []
    for path in sorted(package_dir.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:  # pragma: no cover
            problems.append(f"{path}: cannot parse: {exc}")
            continue
        for lineno, text in _string_constants(tree):
            candidates = [(m["schema"], m["table"]) for m in _SQL_TABLE.finditer(text)]
            fk = _FK.match(text.strip())
            if fk:
                candidates.append((fk["schema"], fk["table"]))
            for schema, table in candidates:
                owner = _owner_of(
                    owners, schema.lower() if schema else None, table.lower()
                )
                if owner in MODULE_OWNERS and owner != own_key:
                    ref = f"{schema}.{table}" if schema else table
                    problems.append(
                        f"{path.name}:{lineno}: names table {ref!r}, owned by {owner!r} — "
                        f"a module reads only its own tables; other modules' data comes "
                        f"through ccure_contracts"
                    )
    return problems


def module_table_problems(manifest, metadatas: list, ownership: dict) -> list[str]:
    """
    Every table in a module's metadata must be in the module's schema and
    registered to the module as ``<schema>.<table>`` — and nothing registered to
    the module may be missing from its metadata.
    """
    owners = table_owners(ownership)
    problems: list[str] = []
    declared: set[str] = set()
    for md in metadatas:
        for table in md.tables.values():
            key = f"{table.schema}.{table.name}"
            declared.add(key)
            if table.schema != manifest.db_schema:
                problems.append(
                    f"table {table.name!r} is in schema {table.schema!r}; module "
                    f"{manifest.key!r} owns schema {manifest.db_schema!r} only"
                )
            owner = owners.get(key)
            if owner != manifest.key:
                problems.append(
                    f"table {key!r} is registered to {owner!r}, not {manifest.key!r} "
                    f"(scripts/architecture/table_ownership.yaml)"
                )
    for key, owner in owners.items():
        if (
            owner == manifest.key
            and key not in declared
            and manifest.db_schema != "public"
        ):
            problems.append(
                f"{key!r} is registered to {manifest.key!r} but no model declares it"
            )
    return problems


#: Alembic operations that act on a table and take a ``schema=`` argument.
_TABLE_OPS = frozenset(
    {
        "create_table",
        "drop_table",
        "rename_table",
        "add_column",
        "drop_column",
        "alter_column",
        "create_index",
        "drop_index",
        "create_unique_constraint",
        "create_foreign_key",
        "create_check_constraint",
        "create_primary_key",
        "drop_constraint",
        "bulk_insert",
        "create_table_comment",
        "drop_table_comment",
    }
)
_SCHEMA_DDL = re.compile(
    r"\b(?:create|drop|alter)\s+schema\s+(?:if\s+(?:not\s+)?exists\s+)?\"?(?P<schema>[a-z_][a-z0-9_]*)\"?",
    re.IGNORECASE,
)


def migration_problems(migrations_dir: Path, own_schema: str) -> list[str]:
    """
    A module's migrations act on its own schema only (Phase 11.3):

    * every table operation (``op.create_table``, ``op.add_column``, …) names
      ``schema=<own>`` explicitly — without it PostgreSQL puts the table in
      ``public``, which is Audit's and the platform's;
    * any ``CREATE``/``DROP``/``ALTER SCHEMA`` in SQL names the module's own schema.

    Tables named in raw SQL are covered by ``foreign_table_references``, which
    scans the whole package, migrations included.
    """
    problems: list[str] = []
    for path in sorted(migrations_dir.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:  # pragma: no cover
            problems.append(f"{path.name}: cannot parse: {exc}")
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _TABLE_OPS
            ):
                schema = next(
                    (k.value for k in node.keywords if k.arg == "schema"), None
                )
                value = schema.value if isinstance(schema, ast.Constant) else None
                if value != own_schema:
                    problems.append(
                        f"{path.name}:{node.lineno}: op.{node.func.attr} must pass "
                        f"schema={own_schema!r} (got {value!r})"
                    )
        for lineno, text in _string_constants(tree):
            for m in _SCHEMA_DDL.finditer(text):
                if m["schema"].lower() != own_schema:
                    problems.append(
                        f"{path.name}:{lineno}: schema DDL names {m['schema']!r}; "
                        f"this module's migrations touch only {own_schema!r}"
                    )
    return problems


def _imports(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module


def misplaced_tests(tests_root: Path, package_dirs: dict[str, str]) -> list[str]:
    """
    A test importing a module package must live in that module's test folder.
    ``package_dirs`` maps package → its test folder relative to ``tests_root``.
    ``tests/repo`` (the guardrails that inspect every module) is exempt.
    """
    problems: list[str] = []
    for path in sorted(tests_root.rglob("test_*.py")):
        rel = path.relative_to(tests_root).as_posix()
        if rel.startswith("repo/"):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for name in _imports(tree):
            top = name.split(".")[0]
            if top in package_dirs and not rel.startswith(
                package_dirs[top].rstrip("/") + "/"
            ):
                problems.append(
                    f"tests/{rel} imports {top}; its tests belong in tests/{package_dirs[top]}/"
                )
    return problems


def codeowners_gaps(codeowners_text: str, required_paths: list[str]) -> list[str]:
    """Every required path has a rule of its own with at least one owner."""
    rules: dict[str, list[str]] = {}
    for raw in codeowners_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, *owners = line.split()
        rules[pattern] = owners
    problems = []
    for path in required_paths:
        if path not in rules:
            problems.append(f"CODEOWNERS has no rule for {path}")
        elif not rules[path]:
            problems.append(f"CODEOWNERS rule for {path} names no owner")
    return problems
