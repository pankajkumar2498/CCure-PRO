"""compliance_rules: admit configuration-audit check types and platforms

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-08-28

Phase 3 — the generic configuration audit engine.

What this changes
─────────────────
Two CHECK constraints on ``compliance_rules`` are replaced. No column is added
and no row is rewritten: a configuration rule is an ordinary row in this table
whose ``check_definition`` carries the declarative check, which is the whole
point of putting the engine here rather than in a table of its own.

  1. ``ck_rule_check_type`` gains the reusable check-type vocabulary —
     ``file``, ``directory``, ``permission``, ``service``, ``process``,
     ``package``, ``port``, ``config_file``, ``command``, ``security_policy``
     and ``database_query``. The seven names already there are all kept, so
     every existing rule still satisfies the constraint.

  2. ``ck_rule_target_platform`` gains ``database`` and ``container``.

Why the reserved names are here now
───────────────────────────────────
``api``/``database_query`` and the ``database``/``container`` platforms have no
collector yet — they arrive with Phases 9, 10, 11, 16 and 17. Naming them now
means those phases need no CHECK migration on a table holding customer rules,
which is the same reservation Phase 2 made for ``credential_type``. A rule
using one before its collector exists is not silently skipped: the engine
resolves no collector and reports ERROR, so the gap is visible rather than
scoring as a pass.

Why the old names are kept rather than mapped
─────────────────────────────────────────────
``file_content``, ``port_state``, ``service_status``, ``api_response``,
``command_output`` and ``tls_config`` are what the seeded evidence-key rules
already use. Renaming them to the new vocabulary would mean an UPDATE across
every seeded rule in every tenant's database to gain nothing a reader can see —
and the two rule kinds are told apart by ``check_definition.config_check``,
not by the type name, precisely so that they can share it.

Downgrade
─────────
Refuses if any rule uses a value the narrower constraint would reject. Dropping
the constraint and re-adding the old one against such a row fails at the
ALTER with a Postgres error naming the constraint but not the row; checking
first names the rules, so an operator can decide what to do with them.
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


#: Must render byte-identically to ``db/models/compliance.py``, or a fresh
#: install (build from ``Base.metadata``, stamp head) and an upgraded install
#: end up with textually different constraints and autogenerate reports a
#: spurious diff forever.
CHECK_TYPES = (
    # Pre-existing, kept verbatim.
    "registry",
    "file_content",
    "port_state",
    "tls_config",
    "service_status",
    "api_response",
    "command_output",
    # Phase 3 configuration-audit vocabulary.
    "file",
    "directory",
    "permission",
    "service",
    "process",
    "package",
    "port",
    "config_file",
    "command",
    "security_policy",
    "api",
    "database_query",
)

OLD_CHECK_TYPES = (
    "registry",
    "file_content",
    "port_state",
    "tls_config",
    "service_status",
    "api_response",
    "command_output",
)

TARGET_PLATFORMS = (
    "windows",
    "linux",
    "network_device",
    "database",
    "container",
    "cloud",
    "any",
)

OLD_TARGET_PLATFORMS = ("windows", "linux", "network_device", "cloud", "any")


def _sql_in_list(values) -> str:
    """
    Render a SQL ``IN`` list.

    Written out rather than using ``str(tuple)`` because a one-element tuple
    stringifies as ``('x',)`` — a trailing comma Postgres rejects. The same
    helper exists on the model for the same reason.
    """
    return "(" + ", ".join(f"'{v}'" for v in values) + ")"


def _replace_check(name: str, column: str, values) -> None:
    op.drop_constraint(name, "compliance_rules", type_="check")
    op.create_check_constraint(
        name, "compliance_rules", f"{column} IN {_sql_in_list(values)}"
    )


def _refuse_rows_outside(column: str, allowed) -> None:
    rows = (
        op.get_bind()
        .execute(
            text(
                f"SELECT id, {column} FROM compliance_rules "
                f"WHERE {column} NOT IN {_sql_in_list(allowed)}"
            )
        )
        .fetchall()
    )
    if rows:
        listed = ", ".join(f"{r[0]}={r[1]!r}" for r in rows[:10])
        raise RuntimeError(
            f"Cannot narrow {column}: {len(rows)} compliance_rules row(s) use "
            f"a value the earlier constraint does not allow ({listed}"
            f"{', …' if len(rows) > 10 else ''}). Reassign or remove them "
            f"before downgrading — re-adding the constraint would otherwise "
            f"fail without naming which rules are responsible."
        )


def upgrade() -> None:
    _replace_check("ck_rule_check_type", "check_type", CHECK_TYPES)
    _replace_check("ck_rule_target_platform", "target_platform", TARGET_PLATFORMS)


def downgrade() -> None:
    _refuse_rows_outside("check_type", OLD_CHECK_TYPES)
    _refuse_rows_outside("target_platform", OLD_TARGET_PLATFORMS)
    _replace_check("ck_rule_check_type", "check_type", OLD_CHECK_TYPES)
    _replace_check("ck_rule_target_platform", "target_platform", OLD_TARGET_PLATFORMS)
