"""compliance_rules: admit the structured-configuration check type

Revision ID: a9b0c1d2e3f4
Revises: f8a9b0c1d2e3
Create Date: 2026-08-29

Phase 8 — GAP-09, application and middleware configuration assessment.

What this changes
─────────────────
One value, ``structured_config``, added to ``ck_rule_check_type``. Every
existing name is kept verbatim, so no rule stops satisfying the constraint and
no row is rewritten. Nothing else in the schema changes: the middleware rules
target ``windows`` and ``linux``, both of which ``ck_rule_target_platform``
has always admitted.

Why it is its own type rather than more parameters on ``config_file``
─────────────────────────────────────────────────────────────────────
``config_file`` reads one directive out of a flat ``key<separator>value`` file.
That is exactly right for ``sshd_config`` and useless for the products this
phase assesses, because all four keep their settings inside a structure:

* nginx nests directives in ``{ }`` blocks;
* Apache nests them in ``<Directory>`` / ``<VirtualHost>`` containers;
* Tomcat has no directives at all — the settings are XML attributes;
* the Docker daemon is JSON.

The difference is not the file format, it is the *addressing*. A flat reader
answers "what is this key set to"; these have to answer "what is it set to
**here**". ``AllowOverride None`` under ``<Directory />`` and under a document
root are different statements about different parts of the filesystem, and a
check type that cannot express which one is meant does not merely miss the
distinction — it returns whichever it saw last and reports it confidently.

One type for all four formats rather than four
──────────────────────────────────────────────
``format`` is a parameter, not a type. From the engine's point of view the four
are one shape — name a file and an address, get back COLLECTED, ABSENT or
UNAVAILABLE — and four types would have meant four CHECK-constraint values on a
table holding customer rules for a distinction the engine cannot act on.

Downgrade
─────────
Refuses if any rule uses ``structured_config``, naming the rules. Re-adding the
narrower constraint over such a row fails at the ALTER with a PostgreSQL error
that names the constraint and not the offending rows, which leaves an operator
with nothing to act on.
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "a9b0c1d2e3f4"
down_revision = "f8a9b0c1d2e3"
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
    "structured_config",
    "api",
    "database_query",
)

OLD_CHECK_TYPES = tuple(t for t in CHECK_TYPES if t != "structured_config")


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
                "SELECT id FROM compliance_rules "
                "WHERE check_type = 'structured_config' LIMIT 10"
            )
        )
        .fetchall()
    )
    if rows:
        raise RuntimeError(
            "Cannot narrow check_type: %d compliance_rules row(s) use "
            "'structured_config' (%s). Remove or reassign them before "
            "downgrading — re-adding the constraint would otherwise fail "
            "without naming which rules are responsible."
            % (len(rows), ", ".join(r[0] for r in rows))
        )
    _replace_check(OLD_CHECK_TYPES)
