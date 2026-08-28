"""compliance_rules: admit the privilege enumeration check type

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-08-28

Phase 5 — GAP-08, local privilege and host-exposure checks.

What this changes
─────────────────
One value, ``privilege``, added to ``ck_rule_check_type``. Every existing name
is kept verbatim, so no rule stops satisfying the constraint and no row is
rewritten.

Why it is its own type rather than reusing ``command``
──────────────────────────────────────────────────────
The Phase 3 types read *one value* and compare it to an expected state. A
privilege check asks a different question: **which items are offending** —
which services carry a weak ACL, which SUID binaries are outside the expected
set. The collector returns a list, the rule asserts the list is empty, and the
offenders become the evidence.

That could be expressed with ``command`` and a shell one-liner, and Phase 3
records why it should not be: "a benchmark expressed entirely as shell
one-liners cannot be inspected, cached or reasoned about, and each one is a
fresh opportunity for a non-zero exit to be read as a value". Service-ACL
parsing and SUID allow-listing belong in tested code, not in rule data.

Downgrade
─────────
Refuses if any rule uses ``privilege``. Re-adding the narrower constraint over
such a row fails at the ALTER with a Postgres error naming the constraint but
not the row; checking first names the rules, so an operator can decide what to
do with them.
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


#: Must render byte-identically to ``db.models.compliance.RULE_CHECK_TYPES``.
CHECK_TYPES = (
    "registry",
    "file_content",
    "port_state",
    "tls_config",
    "service_status",
    "api_response",
    "command_output",
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
    "privilege",
    "api",
    "database_query",
)

OLD_CHECK_TYPES = tuple(t for t in CHECK_TYPES if t != "privilege")


def _sql_in_list(values) -> str:
    """See db/models/compliance.py — str(("k",)) yields an invalid SQL list."""
    return "(" + ", ".join("'%s'" % v for v in values) + ")"


def _replace_check(values) -> None:
    op.drop_constraint("ck_rule_check_type", "compliance_rules", type_="check")
    op.create_check_constraint(
        "ck_rule_check_type",
        "compliance_rules",
        "check_type IN %s" % _sql_in_list(values),
    )


def upgrade() -> None:
    _replace_check(CHECK_TYPES)


def downgrade() -> None:
    rows = (
        op.get_bind()
        .execute(
            text(
                "SELECT id FROM compliance_rules WHERE check_type = 'privilege' "
                "LIMIT 10"
            )
        )
        .fetchall()
    )
    if rows:
        raise RuntimeError(
            "Cannot narrow check_type: %d compliance_rules row(s) use "
            "'privilege' (%s). Remove or reassign them before downgrading — "
            "re-adding the constraint would otherwise fail without naming "
            "which rules are responsible." % (len(rows), ", ".join(r[0] for r in rows))
        )
    _replace_check(OLD_CHECK_TYPES)
