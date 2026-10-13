"""
db/models/scan_schedules.py
──────────────────────────────────────────────────────────────────────────────
Scheduled and recurring scans.

Tables
──────
  scan_schedules      — the rule: what to scan, how often, in whose time zone
  scan_schedule_runs  — the history: one row per dispatch attempt, including
                        the ones that failed before a scan record existed

Why a new table rather than reusing ``compliance_scan_schedules``
────────────────────────────────────────────────────────────────
That table is welded to compliance: ``framework_id`` and ``policy_id`` are both
NOT NULL foreign keys into the compliance catalogue, and its frequency
vocabulary (``continuous``, ``quarterly``) is a compliance cadence. A network
scan has no framework. Widening it would mean nullable framework columns and a
CHECK constraint asserting "framework is required unless the kind is network",
which is a discriminated union wearing a compliance table's name.

So this is a separate table with an explicit ``scan_kind`` discriminator, and
compliance keeps its own. What is *not* duplicated is the thing that matters:
execution. A due schedule dispatches the same Celery task the API route
dispatches, so there is exactly one scan engine.

Six properties of ``compliance_scan_schedules`` are deliberately not copied,
each because it is a defect rather than a design:

1. **No time zone.** It computes ``next_run_at = now + delta``, so "daily at
   09:00" is unrepresentable and every tick drifts by however late beat was.
   Here the next run is computed in the schedule's own IANA zone.
2. **``monthly`` as a fixed ``timedelta``.** A 30-day delta is not a calendar
   month and slides against the date the user chose.
3. **A ``cron_expression`` column nothing reads.** A dead column that looks
   like a feature. Here ``cron_expression`` is only permitted when
   ``recurrence = 'custom'``, and a CHECK enforces it.
4. **No duplicate-execution guard.** Nothing stopped one schedule being
   dispatched twice.
5. **No execution history.** Run records are fused to the compliance run
   table, so a dispatch that failed *before* a scan row existed left no trace
   anywhere a user could see. ``scan_schedule_runs`` records the attempt.
6. **A bare ``except`` reporting ``success: False``.** That is what hid a
   ``TypeError`` until it emerged that scheduled compliance scanning had never
   run once.
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

# ─────────────────────────────────────────────────────────────────────────────
# Vocabularies
# ─────────────────────────────────────────────────────────────────────────────

#: Which pipeline a schedule drives. The discriminator exists so the later
#: phases of the gap-closure programme — configuration audit, database,
#: network device, cloud — become one new member plus one dispatch branch,
#: rather than a second scheduler.
#:
#: Only the first two are dispatchable today; the rest are reserved so adding
#: one does not need a CHECK-constraint migration on a table that by then holds
#: customer schedules.
SCAN_KIND_NETWORK = "network"
SCAN_KIND_CREDENTIALED = "credentialed"
SCAN_KIND_CONFIGURATION = "configuration"
SCAN_KIND_DATABASE = "database"
SCAN_KIND_NETWORK_DEVICE = "network_device"
SCAN_KIND_CLOUD = "cloud"

SCAN_KINDS = (
    SCAN_KIND_NETWORK,
    SCAN_KIND_CREDENTIALED,
    SCAN_KIND_CONFIGURATION,
    SCAN_KIND_DATABASE,
    SCAN_KIND_NETWORK_DEVICE,
    SCAN_KIND_CLOUD,
)

#: The kinds `run_due_scan_schedules` can actually dispatch right now. A
#: schedule of any other kind is refused at creation, so the reserved members
#: above cannot be used to create a schedule that silently never runs.
DISPATCHABLE_SCAN_KINDS = (SCAN_KIND_NETWORK, SCAN_KIND_CREDENTIALED)

RECURRENCE_ONCE = "once"
RECURRENCE_DAILY = "daily"
RECURRENCE_WEEKLY = "weekly"
RECURRENCE_MONTHLY = "monthly"
RECURRENCE_CUSTOM = "custom"

RECURRENCES = (
    RECURRENCE_ONCE,
    RECURRENCE_DAILY,
    RECURRENCE_WEEKLY,
    RECURRENCE_MONTHLY,
    RECURRENCE_CUSTOM,
)

#: Outcome of one dispatch attempt.
RUN_STATUS_DISPATCHED = "dispatched"
RUN_STATUS_FAILED = "failed"
RUN_STATUS_SKIPPED = "skipped"

RUN_STATUSES = (RUN_STATUS_DISPATCHED, RUN_STATUS_FAILED, RUN_STATUS_SKIPPED)

#: How a run came to be. Kept because "why did this scan happen?" is the first
#: question asked of any scheduled job, and a manual Run Now that produced a
#: bad result must be distinguishable from the recurrence firing.
TRIGGER_SCHEDULE = "schedule"
TRIGGER_MANUAL = "manual"

TRIGGERS = (TRIGGER_SCHEDULE, TRIGGER_MANUAL)

#: Rendered exactly as the migration renders them, so a bootstrapped database
#: (``Base.metadata.create_all()``) and an upgraded one produce byte-identical
#: CHECK constraints and autogenerate reports no difference between them. Same
#: reasoning as ``SEVERITY_CANONICAL_SQL`` in ``findings.py``.
SCAN_KIND_SQL = "scan_kind IN %s" % str(SCAN_KINDS)
RECURRENCE_SQL = "recurrence IN %s" % str(RECURRENCES)
RUN_STATUS_SQL = "status IN %s" % str(RUN_STATUSES)
TRIGGER_SQL = "trigger IN %s" % str(TRIGGERS)


class ScanSchedule(Base):
    """
    One scheduling rule.

    ID: sch_{org}_{rand}  e.g. sch_defa_1a2b3c4d_x9v1
    """

    __tablename__ = "scan_schedules"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_scan_schedules_org_name"),
        Index("ix_scan_schedules_org_enabled", "org_id", "is_enabled"),
        # The beat query is "enabled AND due", ordered by due time, across all
        # tenants. A partial index on the enabled rows is what keeps that a
        # bounded lookup once a deployment has thousands of disabled schedules.
        Index("ix_scan_schedules_due", "is_enabled", "next_run_at"),
        CheckConstraint(SCAN_KIND_SQL, name="ck_scan_schedule_kind"),
        CheckConstraint(RECURRENCE_SQL, name="ck_scan_schedule_recurrence"),
        # A cron expression is meaningful only for the custom recurrence.
        # compliance_scan_schedules carries a cron_expression column that
        # nothing reads and nothing constrains, which is how a column that
        # looks like a feature comes to exist. This makes the pairing a
        # database fact.
        CheckConstraint(
            "(recurrence = 'custom' AND cron_expression IS NOT NULL) OR "
            "(recurrence <> 'custom' AND cron_expression IS NULL)",
            name="ck_scan_schedule_cron_only_when_custom",
        ),
        # Weekly needs a weekday; monthly needs a day of the month. Without
        # this a weekly schedule with day_of_week NULL has no defined next run
        # and the scheduler would have to invent one.
        CheckConstraint(
            "(recurrence <> 'weekly') OR "
            "(day_of_week IS NOT NULL AND day_of_week BETWEEN 0 AND 6)",
            name="ck_scan_schedule_weekly_needs_weekday",
        ),
        CheckConstraint(
            "(recurrence <> 'monthly') OR "
            "(day_of_month IS NOT NULL AND day_of_month BETWEEN 1 AND 31)",
            name="ck_scan_schedule_monthly_needs_day",
        ),
        CheckConstraint(
            "consecutive_failures >= 0", name="ck_scan_schedule_failures_non_negative"
        ),
    )

    id = Column(String(100), primary_key=True)
    #: No ``index=True``: ``ix_scan_schedules_org_enabled`` has org_id as its
    #: leftmost column, so it already serves an org-only lookup. A second index
    #: would cost every write and answer nothing the first cannot. Same trap as
    #: ``definition_type`` in findings.py.
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    created_by = Column(
        String(150),
        ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    scan_kind = Column(String(32), nullable=False, index=True)

    # ── What to scan ─────────────────────────────────────────────────────────
    #: Target expressions exactly as the manual routes accept them — hostnames,
    #: IPs, ranges, CIDRs. Re-validated against the organisation's scan scope
    #: at dispatch, never trusted from the stored row: a scope narrowed after
    #: the schedule was created must take effect immediately.
    targets = Column(JSONB, nullable=False, default=list)
    #: Everything the manual route would have accepted as options —
    #: scan_type, pipeline_mode, intensities, port lists, sections. Kept as one
    #: JSONB rather than a column per option so a new scan kind's parameters do
    #: not need a migration.
    scan_options = Column(JSONB, nullable=False, default=dict)

    # ── Credentials, by reference only ───────────────────────────────────────
    #: A schedule never holds a secret. ``POST /scan/credentialed`` accepts a
    #: password and passes it into the Celery task's arguments; a stored
    #: schedule doing the same would put a plaintext password in the database,
    #: in every backup of it, and in the broker payload on every run.
    #: ``run_credentialed_scan_task`` already resolves ``credential_id`` and
    #: decrypts worker-side, so the reference is all that is needed.
    credential_id = Column(
        String(100),
        ForeignKey("compliance_credentials.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Which policy ─────────────────────────────────────────────────────────
    #: The reusable assessment configuration this schedule runs under, by
    #: reference. NULL means "the settings in ``scan_options``", which is the
    #: pre-GAP-12 behaviour and stays working unchanged.
    #:
    #: ``ON DELETE SET NULL``, matching ``credential_id`` above: a schedule
    #: whose policy is deleted keeps running under the request defaults rather
    #: than vanishing, and the dispatcher records that transition on the run so
    #: the change is visible rather than silent. RESTRICT was rejected — it
    #: makes deleting a policy fail with a foreign-key error naming neither the
    #: schedule nor the tenant.
    #:
    #: Re-resolved and re-validated at every dispatch, never inherited from the
    #: moment the schedule was written: a policy archived in June must stop
    #: driving scans in July, for the same reason scan scope is re-checked.
    policy_id = Column(
        String(100),
        ForeignKey("scan_policies.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── When to run ──────────────────────────────────────────────────────────
    recurrence = Column(String(20), nullable=False)
    #: IANA zone name, e.g. "Asia/Kolkata". Not an offset: an offset cannot
    #: express daylight saving, so a schedule stored as +01:00 runs an hour
    #: late for half the year.
    timezone = Column(String(64), nullable=False, default="UTC")
    #: Minutes past local midnight, 0-1439. Stored as an integer rather than a
    #: TIME so the arithmetic that projects it into a zone is unambiguous, and
    #: so "09:00 every day" survives a DST boundary as 09:00 rather than
    #: sliding by an hour.
    run_at_minute = Column(Integer, nullable=False, default=0)
    #: 0 = Monday .. 6 = Sunday, matching ``datetime.weekday()``.
    day_of_week = Column(Integer, nullable=True)
    #: 1-31. A month shorter than the chosen day runs on its last day; see
    #: ``core/scheduling/recurrence.py``.
    day_of_month = Column(Integer, nullable=True)
    cron_expression = Column(String(120), nullable=True)
    #: For ``once``, the moment to run. For recurring schedules, the earliest
    #: moment the schedule becomes eligible.
    starts_at = Column(TIMESTAMPTZ, nullable=True)

    # ── State ────────────────────────────────────────────────────────────────
    is_enabled = Column(Boolean, nullable=False, default=True)
    #: Covered by ``ix_scan_schedules_due`` (is_enabled, next_run_at).
    next_run_at = Column(TIMESTAMPTZ, nullable=True)
    last_run_at = Column(TIMESTAMPTZ, nullable=True)
    #: Mirrors the most recent ``ScanScheduleRun.status``. Denormalised so the
    #: list view does not need a correlated subquery per row.
    last_status = Column(String(20), nullable=True)
    last_scan_id = Column(
        String(100),
        ForeignKey("scans.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )
    last_error = Column(Text, nullable=True)
    #: Reset to zero by any dispatch that succeeds. Used to disable a schedule
    #: that fails persistently rather than letting it retry forever — a
    #: schedule pointed at a decommissioned subnet would otherwise generate a
    #: failed scan every day indefinitely.
    consecutive_failures = Column(Integer, nullable=False, default=0)
    total_run_count = Column(BigInteger, nullable=False, default=0)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    policy = relationship(
        "ScanPolicy",
        back_populates="schedules",
        foreign_keys=[policy_id],
    )

    runs = relationship(
        "ScanScheduleRun",
        back_populates="schedule",
        cascade="all, delete-orphan",
        order_by="ScanScheduleRun.triggered_at.desc()",
    )

    def __repr__(self):
        return (
            f"<ScanSchedule {self.id!r} kind={self.scan_kind!r} "
            f"recurrence={self.recurrence!r} enabled={self.is_enabled}>"
        )


class ScanScheduleRun(Base):
    """
    One dispatch attempt.

    A row exists whether or not a scan was created. That is the point: a
    schedule whose targets fell outside the organisation's scan scope, or whose
    credential was deleted, fails *before* there is a ``Scan`` to look at, and
    without this row the user sees a schedule that simply never runs and no
    reason anywhere.
    """

    __tablename__ = "scan_schedule_runs"
    __table_args__ = (
        Index("ix_scan_schedule_runs_schedule", "schedule_id", "triggered_at"),
        Index("ix_scan_schedule_runs_org", "org_id", "triggered_at"),
        CheckConstraint(RUN_STATUS_SQL, name="ck_scan_schedule_run_status"),
        CheckConstraint(TRIGGER_SQL, name="ck_scan_schedule_run_trigger"),
    )

    id = Column(String(100), primary_key=True)
    schedule_id = Column(
        String(100),
        ForeignKey("scan_schedules.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    #: NULL when the attempt failed before a scan record was created.
    scan_id = Column(
        String(100),
        ForeignKey("scans.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )
    #: NULL for a scheduled run; the user who pressed Run Now otherwise.
    triggered_by = Column(
        String(150),
        ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )
    trigger = Column(String(20), nullable=False, default=TRIGGER_SCHEDULE)
    status = Column(String(20), nullable=False)
    #: Why a run failed or was skipped, in the operator's language. NULL on a
    #: clean dispatch.
    detail = Column(Text, nullable=True)
    #: The Celery task id, so a stuck run can be traced to a worker.
    celery_task_id = Column(String(100), nullable=True)
    #: Covered by both composites above as their trailing column.
    triggered_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    schedule = relationship("ScanSchedule", back_populates="runs")

    def __repr__(self):
        return (
            f"<ScanScheduleRun {self.id!r} status={self.status!r} "
            f"trigger={self.trigger!r}>"
        )
