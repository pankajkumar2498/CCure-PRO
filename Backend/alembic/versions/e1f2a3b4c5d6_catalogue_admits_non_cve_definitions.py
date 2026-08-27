"""vulnerability catalogue admits definitions that are not CVEs

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-08-27

What this changes
─────────────────
Three things about ``vulnerability_definitions`` and the one foreign key into
it:

  1. ``vulnerability_definitions.id``  varchar(30) → varchar(120)
  2. ``asset_vulnerabilities.vuln_id`` varchar(30) → varchar(120)
  3. ``vulnerability_definitions.definition_type`` — new, NOT NULL,
     server default ``'cve'``, CHECK-constrained, indexed.

Why
───
``asset_vulnerabilities.vuln_id`` is a NOT NULL foreign key into this
catalogue, so every finding this product was able to record had to *be* a CVE.
That is fine for the capabilities that existed — package matching, banner
inference, active template verification all produce CVEs. It is not fine for
the ones being built next: a CIS control, a STIG rule, a weak service ACL, an
unquoted service path, a database account with no password policy, a switch
still answering on Telnet. None of those has a CVE and none of them ever will.

The alternative to widening the catalogue is a second findings table, and at
that moment the product has two finding models, two risk models, two
remediation workflows and two report generators for one question. So the
catalogue admits both kinds of row and ``definition_type`` says which is which.

The two CHECK constraints
─────────────────────────
``ck_vuln_def_definition_type`` restricts the column to the four values
``core/checks/definitions.py`` mints.

``ck_vuln_def_cve_id_matches_type`` is the load-bearing one: a ``cve`` row must
carry ``cve_id``, and a non-``cve`` row must not. Without it a configuration
check filed as ``definition_type='cve'`` would inherit CVE semantics
everywhere downstream — KEV membership, EPSS scoring, CVSS band tables, a
"look this up in NVD" link that resolves to nothing — none of which mean
anything for a benchmark control. The constraint makes that state
unrepresentable rather than merely discouraged.

Existing data satisfies it already: every row in the catalogue on this
deployment has ``cve_id = id`` and none is NULL, so the backfill to ``'cve'``
is correct for all of them by inspection, not by assumption.

Why the widening is cheap
─────────────────────────
PostgreSQL does not rewrite a table when a ``varchar(n)`` is widened — the
length is a constraint on the type, and increasing it is a catalogue update.
That holds with the foreign key in place, so the 262k-row catalogue and the
findings referencing it are altered in metadata only. Narrowing on downgrade
is *not* cheap and is not safe, which is why ``downgrade()`` refuses when any
row would not fit.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e1f2a3b4c5d6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


DEFINITION_TYPE_VALUES = ("cve", "config_check", "plugin_check", "privilege_check")

#: Must render byte-identically to ``db.models.findings.DEFINITION_TYPE_SQL``,
#: or a fresh install (which builds from ``Base.metadata`` and stamps head) and
#: an upgraded install end up with textually different constraints and
#: autogenerate reports a spurious diff forever afterwards.
DEFINITION_TYPE_SQL = "definition_type IN %s" % str(DEFINITION_TYPE_VALUES)

CVE_ID_MATCHES_TYPE_SQL = (
    "(definition_type = 'cve' AND cve_id IS NOT NULL) OR "
    "(definition_type <> 'cve' AND cve_id IS NULL)"
)


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # ── 1. Widen the catalogue key and the one foreign key into it ───────────
    #
    # Order matters only in that both must be the same width before the FK is
    # revalidated; Postgres handles that within the single transaction Alembic
    # runs this in.
    op.alter_column(
        "vulnerability_definitions",
        "id",
        existing_type=sa.String(length=30),
        type_=sa.String(length=120),
        existing_nullable=False,
    )
    op.alter_column(
        "asset_vulnerabilities",
        "vuln_id",
        existing_type=sa.String(length=30),
        type_=sa.String(length=120),
        existing_nullable=False,
    )

    # ── 2. definition_type ───────────────────────────────────────────────────
    #
    # server_default is set here and deliberately kept, not dropped after the
    # backfill. The feeds insert catalogue rows with explicit column lists that
    # predate this column; without a server default every one of those inserts
    # would fail on a NOT NULL violation the moment this migration lands, and
    # the sync scripts run outside this repository's release cycle.
    op.add_column(
        "vulnerability_definitions",
        sa.Column(
            "definition_type",
            sa.String(length=20),
            nullable=False,
            server_default="cve",
        ),
    )

    # Backfill is a no-op given the server default, but it is spelled out so
    # the migration is correct if it is ever re-run against a database where
    # the column was added by create_all() without one.
    op.execute(
        "UPDATE vulnerability_definitions "
        "SET definition_type = 'cve' "
        "WHERE definition_type IS NULL"
    )

    op.create_index(
        "ix_vuln_def_definition_type",
        "vulnerability_definitions",
        ["definition_type"],
    )

    # ── 3. Constraints ───────────────────────────────────────────────────────
    op.create_check_constraint(
        "ck_vuln_def_definition_type",
        "vulnerability_definitions",
        DEFINITION_TYPE_SQL,
    )

    if is_postgres:
        # Fail loudly and before the constraint, rather than letting Postgres
        # report a generic check violation on a 262k-row table with no
        # indication of which rows are at fault.
        offenders = bind.execute(
            sa.text(
                "SELECT count(*) FROM vulnerability_definitions WHERE cve_id IS NULL"
            )
        ).scalar()
        if offenders:
            raise RuntimeError(
                f"{offenders} row(s) in vulnerability_definitions have a NULL "
                "cve_id while being treated as CVEs by this backfill. Decide "
                "what they are — set definition_type explicitly for them — "
                "before applying e1f2a3b4c5d6."
            )

    op.create_check_constraint(
        "ck_vuln_def_cve_id_matches_type",
        "vulnerability_definitions",
        CVE_ID_MATCHES_TYPE_SQL,
    )


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_constraint(
        "ck_vuln_def_cve_id_matches_type",
        "vulnerability_definitions",
        type_="check",
    )
    op.drop_constraint(
        "ck_vuln_def_definition_type", "vulnerability_definitions", type_="check"
    )
    op.drop_index("ix_vuln_def_definition_type", table_name="vulnerability_definitions")

    # Narrowing is destructive where the widened space was used. Refuse rather
    # than truncate: a truncated catalogue key silently re-points findings at
    # the wrong definition, and the rows that collide are exactly the ones a
    # downgrade is least able to reason about.
    if bind.dialect.name == "postgresql":
        too_long = bind.execute(
            sa.text(
                "SELECT count(*) FROM vulnerability_definitions "
                "WHERE length(id) > 30"
            )
        ).scalar()
        if too_long:
            raise RuntimeError(
                f"Cannot downgrade e1f2a3b4c5d6: {too_long} catalogue row(s) "
                "have an id longer than 30 characters. These are check "
                "definitions created after the upgrade. Delete them and their "
                "findings first if this downgrade is really intended — "
                "narrowing the column would truncate their identifiers and "
                "re-point findings at the wrong definition."
            )

    op.drop_column("vulnerability_definitions", "definition_type")
    op.alter_column(
        "asset_vulnerabilities",
        "vuln_id",
        existing_type=sa.String(length=120),
        type_=sa.String(length=30),
        existing_nullable=False,
    )
    op.alter_column(
        "vulnerability_definitions",
        "id",
        existing_type=sa.String(length=120),
        type_=sa.String(length=30),
        existing_nullable=False,
    )
