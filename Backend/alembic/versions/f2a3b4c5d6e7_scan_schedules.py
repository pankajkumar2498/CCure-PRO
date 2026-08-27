"""scan scheduling: scan_schedules and scan_schedule_runs

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-08-27

Phase 1 of the Nessus capability gap-closure programme.

Two new tables and nothing else. No existing table is altered, so this
revision cannot affect a running deployment's scans, findings or audit trail —
the worst case if it is rolled back is that scheduling disappears.

Why not extend ``compliance_scan_schedules``
────────────────────────────────────────────
Its ``framework_id`` and ``policy_id`` are NOT NULL foreign keys into the
compliance catalogue and a network scan has no framework. Extending it would
mean making both nullable and adding a CHECK asserting "framework required
unless kind is network" — a discriminated union wearing a compliance table's
name. Execution is what must not be duplicated, and it is not: a due schedule
dispatches the same Celery task the API route dispatches.

The CHECK constraints
─────────────────────
Four of them encode pairings that would otherwise be enforced only by whoever
remembered:

* ``ck_scan_schedule_cron_only_when_custom`` — a cron expression exists exactly
  when the recurrence is ``custom``. ``compliance_scan_schedules`` carries a
  ``cron_expression`` column that nothing reads and nothing constrains, which
  is how a column that looks like a feature comes to exist.
* ``ck_scan_schedule_weekly_needs_weekday`` / ``..._monthly_needs_day`` — a
  weekly schedule with no weekday has no defined next run, and the scheduler
  would have to invent one.
* ``ck_scan_schedule_kind`` admits four kinds that are not dispatchable yet
  (configuration, database, network_device, cloud). They are reserved
  deliberately, so that adding one in a later phase does not require a CHECK
  migration on a table that by then holds customer schedules. The API refuses
  to create a schedule of a kind the dispatcher cannot run, so the reserved
  values cannot be used to create a schedule that silently never fires.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


SCAN_KINDS = (
    "network",
    "credentialed",
    "configuration",
    "database",
    "network_device",
    "cloud",
)
RECURRENCES = ("once", "daily", "weekly", "monthly", "custom")
RUN_STATUSES = ("dispatched", "failed", "skipped")
TRIGGERS = ("schedule", "manual")

#: Must render byte-identically to the constants in
#: ``db/models/scan_schedules.py``, or a fresh install (build from
#: ``Base.metadata``, stamp head) and an upgraded install end up with textually
#: different constraints and autogenerate reports a spurious diff forever.
SCAN_KIND_SQL = "scan_kind IN %s" % str(SCAN_KINDS)
RECURRENCE_SQL = "recurrence IN %s" % str(RECURRENCES)
RUN_STATUS_SQL = "status IN %s" % str(RUN_STATUSES)
TRIGGER_SQL = "trigger IN %s" % str(TRIGGERS)


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("org_id", sa.String(length=100), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scan_kind", sa.String(length=32), nullable=False),
        sa.Column("targets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "scan_options", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("credential_id", sa.String(length=100), nullable=True),
        sa.Column("recurrence", sa.String(length=20), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("run_at_minute", sa.Integer(), nullable=False),
        sa.Column("day_of_week", sa.Integer(), nullable=True),
        sa.Column("day_of_month", sa.Integer(), nullable=True),
        sa.Column("cron_expression", sa.String(length=120), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=20), nullable=True),
        sa.Column("last_scan_id", sa.String(length=100), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("total_run_count", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], onupdate="CASCADE", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], onupdate="CASCADE", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"], ["compliance_credentials.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["last_scan_id"], ["scans.id"], onupdate="CASCADE", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "name", name="uq_scan_schedules_org_name"),
        sa.CheckConstraint(SCAN_KIND_SQL, name="ck_scan_schedule_kind"),
        sa.CheckConstraint(RECURRENCE_SQL, name="ck_scan_schedule_recurrence"),
        sa.CheckConstraint(
            "(recurrence = 'custom' AND cron_expression IS NOT NULL) OR "
            "(recurrence <> 'custom' AND cron_expression IS NULL)",
            name="ck_scan_schedule_cron_only_when_custom",
        ),
        sa.CheckConstraint(
            "(recurrence <> 'weekly') OR "
            "(day_of_week IS NOT NULL AND day_of_week BETWEEN 0 AND 6)",
            name="ck_scan_schedule_weekly_needs_weekday",
        ),
        sa.CheckConstraint(
            "(recurrence <> 'monthly') OR "
            "(day_of_month IS NOT NULL AND day_of_month BETWEEN 1 AND 31)",
            name="ck_scan_schedule_monthly_needs_day",
        ),
        sa.CheckConstraint(
            "consecutive_failures >= 0",
            name="ck_scan_schedule_failures_non_negative",
        ),
    )
    op.create_index(
        "ix_scan_schedules_org_enabled", "scan_schedules", ["org_id", "is_enabled"]
    )
    # The beat query is "enabled AND due", across every tenant. This is the
    # index that keeps it bounded once a deployment holds thousands of
    # schedules, most of them disabled.
    op.create_index(
        "ix_scan_schedules_due", "scan_schedules", ["is_enabled", "next_run_at"]
    )
    op.create_index("ix_scan_schedules_scan_kind", "scan_schedules", ["scan_kind"])

    op.create_table(
        "scan_schedule_runs",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("schedule_id", sa.String(length=100), nullable=False),
        sa.Column("org_id", sa.String(length=100), nullable=False),
        sa.Column("scan_id", sa.String(length=100), nullable=True),
        sa.Column("triggered_by", sa.String(length=150), nullable=True),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("celery_task_id", sa.String(length=100), nullable=True),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["schedule_id"],
            ["scan_schedules.id"],
            onupdate="CASCADE",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], onupdate="CASCADE", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], onupdate="CASCADE", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["triggered_by"], ["users.id"], onupdate="CASCADE", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(RUN_STATUS_SQL, name="ck_scan_schedule_run_status"),
        sa.CheckConstraint(TRIGGER_SQL, name="ck_scan_schedule_run_trigger"),
    )
    op.create_index(
        "ix_scan_schedule_runs_schedule",
        "scan_schedule_runs",
        ["schedule_id", "triggered_at"],
    )
    op.create_index(
        "ix_scan_schedule_runs_org", "scan_schedule_runs", ["org_id", "triggered_at"]
    )


def downgrade() -> None:
    # Runs first: they hold the foreign key into schedules.
    op.drop_index("ix_scan_schedule_runs_org", table_name="scan_schedule_runs")
    op.drop_index("ix_scan_schedule_runs_schedule", table_name="scan_schedule_runs")
    op.drop_table("scan_schedule_runs")

    op.drop_index("ix_scan_schedules_scan_kind", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_due", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_org_enabled", table_name="scan_schedules")
    op.drop_table("scan_schedules")
