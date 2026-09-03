"""scan_policies: reusable assessment policies, and a schedule's link to one

Revision ID: c7d8e9f0a1b2
Revises: f4a5b6c7d8e9
Create Date: 2026-09-03

GAP-12 — the configurable scan policy engine.

What this creates
─────────────────
``scan_policies``, one row per reusable assessment configuration, plus a
nullable ``policy_id`` on ``scan_schedules`` so a recurring scan can reference
a policy instead of duplicating its settings in every schedule.

Nothing else. In particular there is **no column on ``scans``**: a completed
scan's policy snapshot lives in ``scans.options``, which is JSONB, GIN-indexed
and already carries ``origin``, ``schedule_id`` and GAP-13's
``assessment_scope``. A column there would be a migration on a large live table
for a value with no query predicate of its own.

Why a new table rather than widening ``compliance_policies``
────────────────────────────────────────────────────────────
``compliance_policies.framework_id`` is NOT NULL into the compliance
catalogue, and a network scan policy has no framework while a configuration
policy may name several. Widening it means a nullable framework plus a CHECK
reading "a framework is required unless this is a scan policy" — a
discriminated union wearing a compliance table's name. The same reasoning that
gave ``scan_schedules`` its own table rather than reusing
``compliance_scan_schedules``, and it is recorded at both places.

What *is* borrowed is the lifecycle shape: ``policy_family_code`` +
``version_number`` under a UNIQUE constraint, ``status`` in
draft/active/archived, and ``superseded_by_policy_id``.

Three constraints worth the words
─────────────────────────────────
``uq_scan_policy_family_version`` is on **(org_id, policy_family_code,
version_number)** and not on the pair alone. ``compliance_policies`` scopes its
equivalent to the family and version only, which is right for a catalogue
somebody else authored and shipped; here every policy is tenant-owned, so two
organisations must each be able to have a ``linux-baseline`` family without
colliding.

``org_id`` is **NOT NULL**, where ``compliance_policies.tenant_id`` is
nullable. There is deliberately no such thing as a global scan policy: one
would let an edit in one workspace change what another workspace's scans
assess.

``ck_scan_policy_version_positive`` exists because ``next_version_number``
computes ``max + 1``, and a zero or negative row reaching the table would make
a later version collide with an existing one.

``scan_schedules.policy_id``
────────────────────────────
``ON DELETE SET NULL``, matching ``credential_id`` beside it. A schedule whose
policy is deleted must keep running under the request defaults rather than
disappear — but the dispatcher records the transition in the run row, so the
change is visible rather than silent. ``ON DELETE RESTRICT`` was rejected: it
makes deleting a policy fail with a foreign-key error naming neither the
schedule nor the tenant.

Downgrade
─────────
Drops the column and the table. Policy *snapshots* already written into
``scans.options`` are untouched and stay readable, which is the point of
putting them there: the historical record of what produced a scan does not
depend on the policy table still existing.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "c7d8e9f0a1b2"
down_revision = "f4a5b6c7d8e9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_policies",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("org_id", sa.String(length=100), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("policy_family_code", sa.String(length=100), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "scan_kind", sa.String(length=32), nullable=False, server_default="any"
        ),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="draft"
        ),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("superseded_by_policy_id", sa.String(length=100), nullable=True),
        sa.Column("use_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            onupdate="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], ondelete="SET NULL", onupdate="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["superseded_by_policy_id"], ["scan_policies.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "policy_family_code",
            "version_number",
            name="uq_scan_policy_family_version",
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'active', 'archived')",
            name="ck_scan_policy_status",
        ),
        sa.CheckConstraint(
            "scan_kind IN ('network', 'credentialed', 'any')",
            name="ck_scan_policy_scan_kind",
        ),
        sa.CheckConstraint(
            "version_number >= 1", name="ck_scan_policy_version_positive"
        ),
    )
    op.create_index(
        "ix_scan_policies_org_id", "scan_policies", ["org_id"], unique=False
    )
    op.create_index(
        "ix_scan_policies_org_status",
        "scan_policies",
        ["org_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_scan_policies_org_enabled",
        "scan_policies",
        ["org_id", "is_enabled"],
        unique=False,
    )
    op.create_index(
        "ix_scan_policies_policy_family_code",
        "scan_policies",
        ["policy_family_code"],
        unique=False,
    )
    op.create_index(
        "ix_scan_policies_scan_kind", "scan_policies", ["scan_kind"], unique=False
    )

    op.add_column(
        "scan_schedules",
        sa.Column("policy_id", sa.String(length=100), nullable=True),
    )
    op.create_foreign_key(
        "fk_scan_schedules_policy_id",
        "scan_schedules",
        "scan_policies",
        ["policy_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_scan_schedules_policy_id", "scan_schedules", type_="foreignkey"
    )
    op.drop_column("scan_schedules", "policy_id")

    op.drop_index("ix_scan_policies_scan_kind", table_name="scan_policies")
    op.drop_index("ix_scan_policies_policy_family_code", table_name="scan_policies")
    op.drop_index("ix_scan_policies_org_enabled", table_name="scan_policies")
    op.drop_index("ix_scan_policies_org_status", table_name="scan_policies")
    op.drop_index("ix_scan_policies_org_id", table_name="scan_policies")
    op.drop_table("scan_policies")
