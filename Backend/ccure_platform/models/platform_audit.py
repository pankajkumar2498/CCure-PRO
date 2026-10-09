"""
ccure_platform/models/platform_audit.py — the platform's own audit ledger.

``audit_logs`` is tenant-bound by construction: ``org_id`` is NOT NULL and half
the primary key, the table is hash-partitioned on it, and the tamper-evidence
chain is kept per organisation. That is right for what a tenant did. It cannot
represent an event **no organisation owns** — a catalogue sync at deployment, a
system role being reconciled to a release, a platform-scope role being defined,
the default role being re-pointed — and the two ways of forcing it (borrowing an
arbitrary organisation, or inventing a pseudo-tenant) both write a false statement
into a tenant's trail.

So an event that has an owning organisation goes to ``audit_logs`` in that
organisation, and an event that has none goes here. One service writes both
(``ccure_platform/audit_log/writer.py``); callers decide *attribution*, never the
sink. See ``docs/architecture/RBAC_FOUNDATION.md`` §10.

**Append-only (trigger), but not hash-chained.** The chain machinery is a
privileged DBA bootstrap per organisation (``scripts/audit/bootstrap_chain.sql``);
extending it to a platform chain is a separate, reviewed step. Until then this
table's guarantee is that no row can be changed or removed through SQL a normal
role can run — recorded as a known limit, not a claim of tamper-evidence.

Layer rule ``models-are-leaves``: ``db.base`` and SQLAlchemy only.
"""

from __future__ import annotations

from db.base import TIMESTAMPTZ, Base, gen_uuid
from sqlalchemy import DDL, CheckConstraint, Column, Index, String, Text, event, text
from sqlalchemy.dialects.postgresql import JSONB, UUID


class PlatformAuditEvent(Base):
    __tablename__ = "platform_audit_events"
    __table_args__ = (
        CheckConstraint(
            "actor_kind IN ('system', 'user')", name="ck_platform_audit_actor_kind"
        ),
        # A system event carries a label and no account; a user event carries the
        # account and no label. Neither is guessed from the other.
        CheckConstraint(
            "(actor_kind = 'system' AND actor_user_id IS NULL AND actor_label IS NOT NULL) "
            "OR (actor_kind = 'user' AND actor_user_id IS NOT NULL)",
            name="ck_platform_audit_actor",
        ),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_platform_audit_severity",
        ),
        Index("ix_platform_audit_events_occurred", "occurred_at"),
        Index("ix_platform_audit_events_action", "action"),
    )

    id = Column(
        UUID(as_uuid=False),
        primary_key=True,
        default=gen_uuid,
        server_default=text("gen_random_uuid()"),
    )
    occurred_at = Column(TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    action = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    actor_kind = Column(String(10), nullable=False)
    # Plain ids and labels, no foreign keys: the record of who did something must
    # outlive the account, exactly as audit_logs.actor_user_id does.
    actor_user_id = Column(String(150), nullable=True)
    actor_label = Column(String(100), nullable=True)
    # Where the actor sat when they acted: information, never an owner.
    actor_org_id = Column(String(100), nullable=True)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)
    changes = Column(JSONB, nullable=True)
    request_id = Column(String(64), nullable=True)


TRIGGER_SQL: tuple[str, ...] = (
    """
CREATE OR REPLACE FUNCTION platform_audit_events_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
    MESSAGE = 'platform_audit_events is append-only';
END
$$ LANGUAGE plpgsql
""",
    "DROP TRIGGER IF EXISTS platform_audit_events_append_only_trg ON platform_audit_events",
    """
CREATE TRIGGER platform_audit_events_append_only_trg
  BEFORE UPDATE OR DELETE ON platform_audit_events
  FOR EACH ROW EXECUTE FUNCTION platform_audit_events_append_only()
""",
)

TRIGGER_FUNCTIONS = ("platform_audit_events_append_only",)

for _sql in TRIGGER_SQL:
    event.listen(
        PlatformAuditEvent.__table__,
        "after_create",
        DDL(_sql).execute_if(dialect="postgresql"),
    )
