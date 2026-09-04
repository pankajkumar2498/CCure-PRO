"""asset_vulnerabilities: remediation workflow, ownership and SLA

Revision ID: d8e9f0a1b2c3
Revises: c7d8e9f0a1b2
Create Date: 2026-09-03

GAP-14 — remediation and SLA management.

What this changes
─────────────────
Twelve columns on ``asset_vulnerabilities`` and one new table,
``finding_remediation_events``.

Why the workflow is new columns and not new ``status`` values
──────────────────────────────────────────────────────────────
``status`` already exists with three values — ``open``, ``fixed``,
``accepted`` — and answers a *detection* question: is this finding present on
the host? It is written by both scan sweeps, read by the dashboard, the asset
risk recompute, the findings list and GAP-13's comparison, and roughly a dozen
call sites test ``status == 'open'``.

``remediation_state`` answers a *workflow* question: what is anybody doing
about it? Adding ``in_remediation`` to ``status`` would have been a smaller
migration and much worse — every one of those queries would silently stop
counting the finding, so putting one into remediation would remove it from the
dashboard, from the asset's risk score and from the overdue list.

Backfill, and why there is deliberately almost none
───────────────────────────────────────────────────
``remediation_state`` takes a server default of ``'open'``, so every existing
row acquires the honest answer: nobody owns it and no work has started. That
is what was true.

``sla_due_at`` is left **NULL** and is not backfilled here. A due date is
computed from the organisation's own policy, which lives in
``Organization.settings`` and which no migration should be inventing; the
findings sync sets it on the next scan, and until then the API reports the
deadline as not yet computed rather than asserting one. Backfilling with the
shipped defaults would silently declare thousands of existing findings overdue
against a policy the customer never agreed to.

Existing accepted risks are **not** migrated to ``remediation_state =
'risk_accepted'`` either, for a subtler reason: the old model had no expiry and
no approval record, so converting them would present decisions taken under one
set of rules as though they had been taken under another. They keep
``status = 'accepted'``, which is what they are, and re-accepting one through
the new endpoint records the reason, approver and expiry properly.

Why ``finding_remediation_events`` is its own table
───────────────────────────────────────────────────
``audit_logs`` is tamper-evident, HASH-partitioned on ``org_id`` and subject to
retention. It is the right place for "user X called this endpoint" and the
workflow writes there too. It is the wrong place to read a *finding's*
remediation timeline: that is a per-finding query against a partitioned table
with an append-only trigger, and retention would eventually remove history the
finding still needs. Shaped after ``compliance_finding_history``, which does
the same job for compliance controls.

Note ``finding_id`` is ``varchar(350)`` — ``asset_vulnerabilities.id`` is that
wide because it embeds an asset id and a vulnerability id. The event's own id
hashes the finding rather than embedding it, so it fits in 120.

**The foreign key is composite and had to be.** ``asset_vulnerabilities``'
actual primary key is ``(id, org_id)``, not ``id`` — a leftover of the
HASH-partition-on-``org_id`` design the table was built for, where a
partitioned table must include the partition key in its key. The model
declares only ``id``, so this is invisible from the Python side; PostgreSQL
refuses the single-column reference with "no unique constraint matching given
keys for referenced table". Referencing both columns is also the stronger
constraint: an event row can only ever point at a finding in its own
organisation, enforced by the database rather than by every query remembering
to filter.

Downgrade
─────────
Drops the table and the columns. Any remediation history is lost, which is
stated rather than worked around: preserving it would mean writing it somewhere
the upgraded schema does not have.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "d8e9f0a1b2c3"
down_revision = "c7d8e9f0a1b2"
branch_labels = None
depends_on = None


_STATES = (
    "open",
    "assigned",
    "in_remediation",
    "pending_verification",
    "verified_fixed",
    "reopened",
    "risk_accepted",
)

_EVENT_TYPES = (
    "assigned",
    "unassigned",
    "state_changed",
    "note_added",
    "risk_accepted",
    "exception_expired",
    "verified",
    "reopened",
    "sla_set",
    "sla_changed",
)


def upgrade() -> None:
    # ── The workflow columns ────────────────────────────────────────────────
    op.add_column(
        "asset_vulnerabilities",
        sa.Column(
            "remediation_state",
            sa.String(length=32),
            nullable=False,
            server_default="open",
        ),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("remediation_owner", sa.String(length=150), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("assigned_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("assigned_by", sa.String(length=150), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("sla_due_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("sla_basis", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("verified_scan_id", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("reopened_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("exception_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("accepted_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )

    op.create_check_constraint(
        "ck_asset_vuln_remediation_state",
        "asset_vulnerabilities",
        "remediation_state IN (" + ", ".join(f"'{s}'" for s in _STATES) + ")",
    )

    op.create_foreign_key(
        "fk_asset_vuln_remediation_owner",
        "asset_vulnerabilities",
        "users",
        ["remediation_owner"],
        ["id"],
        ondelete="SET NULL",
        onupdate="CASCADE",
    )
    op.create_foreign_key(
        "fk_asset_vuln_assigned_by",
        "asset_vulnerabilities",
        "users",
        ["assigned_by"],
        ["id"],
        ondelete="SET NULL",
        onupdate="CASCADE",
    )
    op.create_foreign_key(
        "fk_asset_vuln_verified_scan",
        "asset_vulnerabilities",
        "scans",
        ["verified_scan_id"],
        ["id"],
        ondelete="SET NULL",
        onupdate="CASCADE",
    )

    # The two predicates every remediation query runs. "Everything overdue in
    # this organisation" is a WHERE on (org_id, sla_due_at) and "the
    # remediation summary" is a GROUP BY on (org_id, remediation_state); both
    # would otherwise scan a table holding thousands of rows per host.
    op.create_index(
        "ix_asset_vuln_remediation_state",
        "asset_vulnerabilities",
        ["remediation_state"],
    )
    op.create_index(
        "ix_asset_vuln_org_remediation",
        "asset_vulnerabilities",
        ["org_id", "remediation_state"],
    )
    op.create_index("ix_asset_vuln_sla_due", "asset_vulnerabilities", ["sla_due_at"])
    op.create_index(
        "ix_asset_vuln_org_sla_due",
        "asset_vulnerabilities",
        ["org_id", "sla_due_at"],
    )
    op.create_index(
        "ix_asset_vuln_remediation_owner",
        "asset_vulnerabilities",
        ["remediation_owner"],
    )
    # Expiry runs on beat over one predicate and only ever matches a handful of
    # rows, so it is a partial index rather than a full one.
    op.create_index(
        "ix_asset_vuln_exception_expiry",
        "asset_vulnerabilities",
        ["exception_expires_at"],
        postgresql_where=sa.text("exception_expires_at IS NOT NULL"),
    )

    # ── The event trail ─────────────────────────────────────────────────────
    op.create_table(
        "finding_remediation_events",
        sa.Column("id", sa.String(length=120), nullable=False),
        sa.Column("finding_id", sa.String(length=350), nullable=False),
        sa.Column("org_id", sa.String(length=100), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("from_state", sa.String(length=32), nullable=True),
        sa.Column("to_state", sa.String(length=32), nullable=True),
        sa.Column("actor_id", sa.String(length=150), nullable=True),
        sa.Column("actor_label", sa.String(length=64), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("scan_id", sa.String(length=100), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "occurred_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # Composite, and it has to be: `asset_vulnerabilities`' primary key is
        # `(id, org_id)`, not `id` — a leftover of the HASH-partition-on-org_id
        # design, where a partitioned table must carry the partition key in its
        # key. PostgreSQL refuses a single-column reference with "no unique
        # constraint matching given keys for referenced table".
        #
        # It is the better constraint regardless: an event can only reference a
        # finding in its own organisation, enforced by the database rather than
        # by every query remembering to filter.
        sa.ForeignKeyConstraint(
            ["finding_id", "org_id"],
            ["asset_vulnerabilities.id", "asset_vulnerabilities.org_id"],
            ondelete="CASCADE",
            name="fk_finding_rem_event_finding",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], ondelete="CASCADE", onupdate="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], ondelete="SET NULL", onupdate="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], ondelete="SET NULL", onupdate="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "event_type IN (" + ", ".join(f"'{e}'" for e in _EVENT_TYPES) + ")",
            name="ck_finding_rem_event_type",
        ),
    )
    op.create_index(
        "ix_finding_rem_event_finding",
        "finding_remediation_events",
        ["finding_id", "occurred_at"],
    )
    op.create_index(
        "ix_finding_rem_event_org",
        "finding_remediation_events",
        ["org_id", "occurred_at"],
    )
    op.create_index(
        "ix_finding_remediation_events_finding_id",
        "finding_remediation_events",
        ["finding_id"],
    )
    op.create_index(
        "ix_finding_remediation_events_org_id",
        "finding_remediation_events",
        ["org_id"],
    )
    op.create_index(
        "ix_finding_remediation_events_occurred_at",
        "finding_remediation_events",
        ["occurred_at"],
    )


def downgrade() -> None:
    op.drop_table("finding_remediation_events")

    op.drop_index("ix_asset_vuln_exception_expiry", table_name="asset_vulnerabilities")
    op.drop_index("ix_asset_vuln_remediation_owner", table_name="asset_vulnerabilities")
    op.drop_index("ix_asset_vuln_org_sla_due", table_name="asset_vulnerabilities")
    op.drop_index("ix_asset_vuln_sla_due", table_name="asset_vulnerabilities")
    op.drop_index("ix_asset_vuln_org_remediation", table_name="asset_vulnerabilities")
    op.drop_index("ix_asset_vuln_remediation_state", table_name="asset_vulnerabilities")

    op.drop_constraint(
        "fk_asset_vuln_verified_scan", "asset_vulnerabilities", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_asset_vuln_assigned_by", "asset_vulnerabilities", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_asset_vuln_remediation_owner", "asset_vulnerabilities", type_="foreignkey"
    )
    op.drop_constraint(
        "ck_asset_vuln_remediation_state", "asset_vulnerabilities", type_="check"
    )

    for column in (
        "accepted_at",
        "exception_expires_at",
        "reopened_count",
        "reopened_at",
        "verified_scan_id",
        "verified_at",
        "sla_basis",
        "sla_due_at",
        "assigned_by",
        "assigned_at",
        "remediation_owner",
        "remediation_state",
    ):
        op.drop_column("asset_vulnerabilities", column)
