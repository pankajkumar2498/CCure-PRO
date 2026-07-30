"""
tests/test_schema_drift.py
─────────────────────────────────────────────────────────────────────────────
Guards against a model change that no migration accounts for.

Why this matters here
─────────────────────
This project builds a schema two different ways:

  * a **fresh** install runs ``Base.metadata.create_all()`` and stamps Alembic
    head (``db/migrate_production_schema.py`` — the ``is_database_empty`` branch)
  * an **existing** install runs ``alembic upgrade head``

That is a deliberate and correct pattern for adopting Alembic over a schema that
already existed. Its known failure mode is divergence: add a column to a model
and forget the migration, and a fresh install gets the column while every
existing install silently does not. Nothing fails until a customer upgrades.

This test compares the models against the database the suite is connected to.
When that database was built incrementally — migrations applied over a schema
that already existed — anything the models declare but the database lacks is a
missing migration.

Scope
─────
Only the model-ahead-of-database direction is checked. Objects present in the
database but absent from the models (``audit_logs`` partitions, anything left by
an older revision) are not a defect and are ignored, which also keeps the test
free of autogenerate's usual index and constraint noise.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alembic.autogenerate import compare_metadata  # noqa: E402
from alembic.runtime.migration import MigrationContext  # noqa: E402
from db.base import Base, engine  # noqa: E402

import conftest  # noqa: E402

#: Diff opcodes that mean "the models describe something the database lacks".
_MODEL_AHEAD_OPS = {"add_table", "add_column"}

#: Diff opcodes describing a changed definition on an existing column.
_MODIFIED_OPS = {"modify_type", "modify_nullable", "modify_default"}


def _describe(entry) -> str:
    """Render one autogenerate diff entry as an actionable line."""
    op = entry[0]
    if op == "add_table":
        return f"table '{entry[1].name}' exists in the models but not the database"
    if op == "add_column":
        _, schema, table, column = entry
        return (
            f"column '{table}.{column.name}' exists in the models but not the database"
        )
    if op in _MODIFIED_OPS:
        # ('modify_type', schema, table, column_name, kw, old, new)
        _, _schema, table, column = entry[0], entry[1], entry[2], entry[3]
        return (
            f"column '{table}.{column}' is defined differently in the models "
            f"({op.replace('modify_', '')}: {entry[-2]!r} -> {entry[-1]!r})"
        )
    return f"{op}: {entry[1:]}"


def _collect_drift():
    """Return human-readable descriptions of model-ahead-of-database differences."""
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        diff = compare_metadata(context, Base.metadata)

    findings = []
    for entry in diff:
        # Nested lists appear for grouped column modifications.
        entries = entry if isinstance(entry, list) else [entry]
        for item in entries:
            if not item:
                continue
            op = item[0]
            if op in _MODEL_AHEAD_OPS or op in _MODIFIED_OPS:
                findings.append(_describe(item))
    return findings


@pytest.mark.skipif(
    conftest.SCHEMA_WAS_BOOTSTRAPPED,
    reason=(
        "Schema was built from the models this session, so a comparison against "
        "the models is tautological. Run against a database created by "
        "migrations to make this check meaningful."
    ),
)
def test_models_have_no_unmigrated_changes():
    """
    Every model change must have a migration behind it.

    If this fails, a model was edited without a corresponding revision. Generate
    one and review it before committing:

        python -m alembic revision --autogenerate -m "describe the change"

    Review matters: autogenerate does not detect renames, and will otherwise
    emit a drop plus an add, which loses data on an existing install.
    """
    drift = _collect_drift()
    assert not drift, (
        "The models and the migration chain disagree. A fresh install would get "
        "these, an upgraded install would not:\n  - "
        + "\n  - ".join(drift)
        + "\n\nGenerate a migration with:\n"
        "    python -m alembic revision --autogenerate -m 'describe the change'"
    )
