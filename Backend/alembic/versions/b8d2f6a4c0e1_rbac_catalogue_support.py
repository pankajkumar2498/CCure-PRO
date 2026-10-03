"""RBAC-2: legacy-atom accounting, state changes that leave history, a platform ledger

Revision ID: b8d2f6a4c0e1
Revises: a7c1e5b3d9f2
Create Date: 2026-10-03

Three schema changes, none of which touches the legacy authorization model:

* ``rbac_legacy_map`` gains ``status`` (``mapped`` / ``replaced`` / ``retired``) and
  ``reason``, and a permission row may now have no ``permission_key`` when it is
  retired. Every legacy atom is accounted for — including the ones nothing enforces —
  instead of being dropped from the map.
* ``rbac_roles_guard`` additionally refuses a state change that does not advance
  ``revision`` in the same statement, so a role cannot change state (retire,
  reactivate) without leaving a history row. "Retired roles cannot silently become
  active" is enforced by the database.
* ``platform_audit_events``: an append-only ledger for events no organisation owns.
  ``audit_logs`` is tenant-bound (``org_id`` NOT NULL, hash-partitioned on it) and
  cannot hold a catalogue sync or a platform-scope role change without borrowing an
  organisation. See ``ccure_platform/models/platform_audit.py``.

The statements are generated from the models; ``tests/rbac/test_rbac_schema.py``
checks the migrated schema against them. Downgrade restores the RBAC-1 shape; it
deletes the retired legacy-map rows, which have no representation there, and
refuses while ``platform_audit_events`` holds events (they are history).
"""

import sqlalchemy as sa
from alembic import op

revision = "b8d2f6a4c0e1"
down_revision = "a7c1e5b3d9f2"
branch_labels = None
depends_on = None

LEGACY_MAP_SQL = (
    "ALTER TABLE rbac_legacy_map ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'mapped' NOT NULL",
    "ALTER TABLE rbac_legacy_map ADD COLUMN IF NOT EXISTS reason TEXT",
    "ALTER TABLE rbac_legacy_map DROP CONSTRAINT IF EXISTS ck_rbac_legacy_map_shape",
    "ALTER TABLE rbac_legacy_map DROP CONSTRAINT IF EXISTS ck_rbac_legacy_map_status",
    r"""ALTER TABLE rbac_legacy_map ADD CONSTRAINT ck_rbac_legacy_map_status CHECK (status IN ('mapped', 'replaced', 'retired'))""",
    r"""ALTER TABLE rbac_legacy_map ADD CONSTRAINT ck_rbac_legacy_map_shape CHECK ((kind = 'role' AND legacy_role_name IS NOT NULL AND role_key IS NOT NULL AND legacy_resource IS NULL AND legacy_action IS NULL AND permission_key IS NULL AND status = 'mapped') OR (kind = 'permission' AND legacy_resource IS NOT NULL AND legacy_action IS NOT NULL AND legacy_role_name IS NULL AND role_key IS NULL AND ((status = 'retired' AND permission_key IS NULL) OR (status IN ('mapped', 'replaced') AND permission_key IS NOT NULL))))""",
    r"""CREATE UNIQUE INDEX IF NOT EXISTS uq_rbac_legacy_map_retired ON rbac_legacy_map (legacy_resource, legacy_action) WHERE kind = 'permission' AND permission_key IS NULL""",
)

#: The RBAC-2 role guard: as RBAC-1's, plus a state change must advance the revision.
ROLES_GUARD_SQL = r"""
CREATE OR REPLACE FUNCTION rbac_roles_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'rbac_roles rows are never deleted: retire the role instead';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.key IS DISTINCT FROM OLD.key
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.assignable_scope IS DISTINCT FROM OLD.assignable_scope
     OR NEW.org_id IS DISTINCT FROM OLD.org_id
     OR NEW.managed_by IS DISTINCT FROM OLD.managed_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'rbac_roles identity columns are immutable';
  END IF;
  IF NEW.revision < OLD.revision THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'rbac_roles.revision cannot decrease';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'active' AND NEW.state = 'retiring')
    OR (OLD.state = 'retiring' AND NEW.state IN ('retired', 'active'))
    OR (OLD.state = 'retired' AND NEW.state = 'active')) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'invalid role state transition ' || OLD.state || ' to ' || NEW.state;
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NEW.revision <= OLD.revision THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'a role state change must advance the revision, so it leaves history';
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql
"""

#: The RBAC-1 role guard, restored on downgrade.
OLD_ROLES_GUARD_SQL = r"""
CREATE OR REPLACE FUNCTION rbac_roles_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'rbac_roles rows are never deleted: retire the role instead';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.key IS DISTINCT FROM OLD.key
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.assignable_scope IS DISTINCT FROM OLD.assignable_scope
     OR NEW.org_id IS DISTINCT FROM OLD.org_id
     OR NEW.managed_by IS DISTINCT FROM OLD.managed_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'rbac_roles identity columns are immutable';
  END IF;
  IF NEW.revision < OLD.revision THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'rbac_roles.revision cannot decrease';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'active' AND NEW.state = 'retiring')
    OR (OLD.state = 'retiring' AND NEW.state IN ('retired', 'active'))
    OR (OLD.state = 'retired' AND NEW.state = 'active')) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'invalid role state transition ' || OLD.state || ' to ' || NEW.state;
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql
"""

PLATFORM_AUDIT_TABLE_SQL = (
    r"""CREATE TABLE IF NOT EXISTS platform_audit_events (
	id UUID DEFAULT gen_random_uuid() NOT NULL,
	occurred_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	action VARCHAR(100) NOT NULL,
	severity VARCHAR(20) NOT NULL,
	actor_kind VARCHAR(10) NOT NULL,
	actor_user_id VARCHAR(150),
	actor_label VARCHAR(100),
	actor_org_id VARCHAR(100),
	resource_type VARCHAR(100),
	resource_id VARCHAR(255),
	changes JSONB,
	request_id VARCHAR(64),
	PRIMARY KEY (id),
	CONSTRAINT ck_platform_audit_actor_kind CHECK (actor_kind IN ('system', 'user')),
	CONSTRAINT ck_platform_audit_actor CHECK ((actor_kind = 'system' AND actor_user_id IS NULL AND actor_label IS NOT NULL) OR (actor_kind = 'user' AND actor_user_id IS NOT NULL)),
	CONSTRAINT ck_platform_audit_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
)""",
    r"""CREATE INDEX IF NOT EXISTS ix_platform_audit_events_action ON platform_audit_events (action)""",
    r"""CREATE INDEX IF NOT EXISTS ix_platform_audit_events_occurred ON platform_audit_events (occurred_at)""",
)

PLATFORM_AUDIT_TRIGGER_SQL = (
    r"""
CREATE OR REPLACE FUNCTION platform_audit_events_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
    MESSAGE = 'platform_audit_events is append-only';
END
$$ LANGUAGE plpgsql
""",
    r"""DROP TRIGGER IF EXISTS platform_audit_events_append_only_trg ON platform_audit_events""",
    r"""
CREATE TRIGGER platform_audit_events_append_only_trg
  BEFORE UPDATE OR DELETE ON platform_audit_events
  FOR EACH ROW EXECUTE FUNCTION platform_audit_events_append_only()
""",
)

#: Restores the RBAC-1 legacy-map shape on downgrade.
OLD_SHAPE_SQL = (
    "ALTER TABLE rbac_legacy_map ADD CONSTRAINT ck_rbac_legacy_map_shape CHECK ("
    "(kind = 'role' AND legacy_role_name IS NOT NULL AND role_key IS NOT NULL "
    "AND legacy_resource IS NULL AND legacy_action IS NULL AND permission_key IS NULL) "
    "OR (kind = 'permission' AND legacy_resource IS NOT NULL "
    "AND legacy_action IS NOT NULL AND permission_key IS NOT NULL "
    "AND legacy_role_name IS NULL AND role_key IS NULL))"
)


def upgrade() -> None:
    conn = op.get_bind()
    for statement in LEGACY_MAP_SQL:
        conn.exec_driver_sql(statement)
    conn.exec_driver_sql(ROLES_GUARD_SQL)
    for statement in PLATFORM_AUDIT_TABLE_SQL:
        conn.exec_driver_sql(statement)
    for statement in PLATFORM_AUDIT_TRIGGER_SQL:
        conn.exec_driver_sql(statement)


def downgrade() -> None:
    conn = op.get_bind()
    events = conn.execute(
        sa.text("SELECT count(*) FROM platform_audit_events")
    ).scalar()
    if events:
        raise RuntimeError(
            f"Refusing to drop platform_audit_events: it holds {events} event(s), "
            "which are history. Export them first, then drop the table by hand."
        )
    conn.exec_driver_sql("DROP TABLE IF EXISTS platform_audit_events CASCADE")
    conn.exec_driver_sql("DROP FUNCTION IF EXISTS platform_audit_events_append_only()")
    conn.exec_driver_sql(OLD_ROLES_GUARD_SQL)
    conn.exec_driver_sql("DROP INDEX IF EXISTS uq_rbac_legacy_map_retired")
    conn.exec_driver_sql(
        "DELETE FROM rbac_legacy_map WHERE kind = 'permission' AND permission_key IS NULL"
    )
    conn.exec_driver_sql(
        "ALTER TABLE rbac_legacy_map DROP CONSTRAINT IF EXISTS ck_rbac_legacy_map_shape"
    )
    conn.exec_driver_sql(
        "ALTER TABLE rbac_legacy_map DROP CONSTRAINT IF EXISTS ck_rbac_legacy_map_status"
    )
    conn.exec_driver_sql(OLD_SHAPE_SQL)
    conn.exec_driver_sql("ALTER TABLE rbac_legacy_map DROP COLUMN IF EXISTS reason")
    conn.exec_driver_sql("ALTER TABLE rbac_legacy_map DROP COLUMN IF EXISTS status")
