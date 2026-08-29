"""compliance_rules: admit the container enumeration check type

Revision ID: b0c1d2e3f4a5
Revises: a9b0c1d2e3f4
Create Date: 2026-08-29

Phase 9 — GAP-17, container and Kubernetes configuration assessment.

What this changes
─────────────────
One value, ``container``, added to ``ck_rule_check_type``. Every existing name
is kept verbatim, so no rule stops satisfying the constraint and no row is
rewritten. Nothing else in the schema changes: these rules target the
``linux`` platform, which the constraint has always admitted, because a
container runtime is assessed over the *host's* credentialed session.

Why it is its own type rather than reusing ``structured_config``
────────────────────────────────────────────────────────────────
``structured_config`` reads a document and addresses a value inside it. This
answers a different question: **which running things are offending** — which
containers are privileged, which pods share a host namespace, which subjects
are bound to cluster-admin.

The shape differs accordingly. The collector enumerates and filters, the rule
asserts the list is empty, and the offenders become the evidence — so a clean
host produces an *absence* and a breached one produces the names of the things
to fix. That is exactly the distinction Phase 5 drew when it added
``privilege`` rather than expressing service-ACL enumeration as a ``command``
rule, and the argument is the same one: the enumeration is not a shell
one-liner that belongs in administrator-editable rule data.

Why the ``container`` platform is not used
──────────────────────────────────────────
``target_platform`` has admitted ``container`` since Phase 3, and these rules
deliberately do not use it. They run against a *host* we hold a credential
for, over that host's shell, alongside the operating-system hardening rules —
the same placement Phase 8 gave the middleware rules. The reserved platform
describes a container *as a target in its own right*, which is a different
idea and one this phase does not implement.

Downgrade
─────────
Refuses if any rule uses ``container``, naming the rules. Re-adding the
narrower constraint over such a row fails at the ALTER with a PostgreSQL error
that names the constraint and not the offending records.
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "b0c1d2e3f4a5"
down_revision = "a9b0c1d2e3f4"
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
    "container",
    "api",
    "database_query",
)

OLD_CHECK_TYPES = tuple(t for t in CHECK_TYPES if t != "container")


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
                "SELECT id FROM compliance_rules WHERE check_type = 'container' "
                "LIMIT 10"
            )
        )
        .fetchall()
    )
    if rows:
        raise RuntimeError(
            "Cannot narrow check_type: %d compliance_rules row(s) use "
            "'container' (%s). Remove or reassign them before downgrading — "
            "re-adding the constraint would otherwise fail without naming "
            "which rules are responsible." % (len(rows), ", ".join(r[0] for r in rows))
        )
    _replace_check(OLD_CHECK_TYPES)
