"""compliance_rules: admit the compiled SCAP/OVAL check type

Revision ID: c1d2e3f4a5b6
Revises: b0c1d2e3f4a5
Create Date: 2026-08-30

Phase 10 — GAP-05, DISA STIG / SCAP ingestion and evaluation.

What this changes
─────────────────
One value, ``scap_rule``, added to ``ck_rule_check_type``. Every existing name
is kept verbatim, so no rule stops satisfying the constraint and no row is
rewritten. Nothing else in the schema changes — and that is the point worth
recording, because it is the fourth phase in a row for which it is true.

``compliance_rules`` has carried ``check_type``, a JSONB ``check_definition``,
``target_platform``, ``severity``, versioning and a junction to every framework
control since before Phase 3. A STIG rule is a benchmark control with a check;
Phase 4 established that a benchmark *is* a framework. So an entire national
hardening standard lands in the tables that already exist, and the persistence
cost of the phase is this one CHECK constraint.

Why it is its own type
──────────────────────
A Phase 3 check is one read compared against one expected state. An OVAL
definition is a criteria tree over several tests — 619 ``AND`` and 333 ``OR``
nodes in the content measured before this phase — with per-test existence
semantics that decide the answer before any comparison happens. Flattening
that into a single read cannot be done faithfully, and the unfaithful version
returns a verdict where the honest answer is an error.

The rule row therefore carries the *compiled* definition: the tests, objects,
states and resolved variables it needs, and nothing else. That matters for
more than tidiness — the datastream it came from is a 60 MB file on an
operator's workstation, and the rule is evaluated on a Celery worker months
later. A rule that had to reach back to its source content would be
unevaluable in exactly the situation it exists for.

Why not the ``file_content`` type that is already here
──────────────────────────────────────────────────────
``file_content`` is one of the seven pre-Phase-3 names, used by the original
compliance rules with an entirely different ``check_definition`` shape. Reusing
it would put two incompatible payloads behind one type name, and the evaluator
would have to guess which it was holding.

Downgrade
─────────
Refuses if any rule uses ``scap_rule``, naming the rules. Re-adding the
narrower constraint over such a row fails at the ALTER with a PostgreSQL error
that names the constraint and not the offending records.
"""

from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "c1d2e3f4a5b6"
down_revision = "b0c1d2e3f4a5"
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
    "scap_rule",
    "api",
    "database_query",
)

OLD_CHECK_TYPES = tuple(t for t in CHECK_TYPES if t != "scap_rule")


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
                "SELECT id FROM compliance_rules WHERE check_type = 'scap_rule' "
                "LIMIT 10"
            )
        )
        .fetchall()
    )
    if rows:
        raise RuntimeError(
            "Cannot narrow check_type: %d compliance_rules row(s) use "
            "'scap_rule' (%s). Remove or reassign them before downgrading — "
            "re-adding the constraint would otherwise fail without naming "
            "which rules are responsible." % (len(rows), ", ".join(r[0] for r in rows))
        )
    _replace_check(OLD_CHECK_TYPES)
