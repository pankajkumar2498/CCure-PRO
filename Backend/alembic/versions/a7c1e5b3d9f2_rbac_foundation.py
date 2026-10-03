"""RBAC-1: the independent RBAC foundation (dark)

Revision ID: a7c1e5b3d9f2
Revises: f3b5d7e9a1c4
Create Date: 2026-10-03

Seven platform-owned tables for the new RBAC capability, designed and frozen in
RBAC-0: ``rbac_permissions``, ``rbac_roles``, ``rbac_role_revisions``,
``rbac_role_permissions``, ``rbac_user_roles``, ``rbac_default_roles`` and the
temporary ``rbac_legacy_map``.

**This migration changes no authorization behaviour.** Nothing reads these tables
on a request path; the legacy ``users.role_id``, ``roles``, ``permissions`` and
``role_permissions`` are untouched and remain the authority. It adds:

* the tables and their indexes (every foreign key ``ON DELETE RESTRICT``);
* the trigger functions that make role identity immutable, role history
  append-only, an assignment revocable but never rewritten, and that refuse an
  assignment outside a role's scope or a default role carrying a privileged
  permission;
* seed rows, all idempotent: the five system roles (with **no** permission grants
  — the catalogue arrives in RBAC-2), the ``self_registration`` default pointing
  at the Viewer role so today's behaviour is preserved, and the legacy role-name
  mapping used by shadow evaluation.

The table SQL below is generated from ``ccure_platform/models/rbac_tables.py`` and
the trigger SQL is a copy of its ``TRIGGER_SQL``; ``tests/rbac/test_rbac_schema.py``
fails if either drifts from the models. Statements use ``IF NOT EXISTS`` /
``CREATE OR REPLACE`` so a database whose tables were created from the models
first (``create_all``) is brought into line rather than refused.

Downgrade refuses while any assignment exists: ``rbac_user_roles`` is history.
"""

import sqlalchemy as sa
from alembic import op

revision = "a7c1e5b3d9f2"
down_revision = "f3b5d7e9a1c4"
branch_labels = None
depends_on = None

#: Spelled out, not imported: a migration describes the schema as it was.
TABLES = (
    "rbac_permissions",
    "rbac_roles",
    "rbac_role_revisions",
    "rbac_role_permissions",
    "rbac_user_roles",
    "rbac_default_roles",
    "rbac_legacy_map",
)

TABLE_SQL = (
    r"""CREATE TABLE IF NOT EXISTS rbac_permissions (
	key VARCHAR(120) NOT NULL,
	module VARCHAR(50) NOT NULL,
	resource VARCHAR(60) NOT NULL,
	action VARCHAR(60) NOT NULL,
	description TEXT NOT NULL,
	scope_kind VARCHAR(20) NOT NULL,
	sensitivity VARCHAR(20) DEFAULT 'normal' NOT NULL,
	delegable_to_org_roles BOOLEAN DEFAULT true NOT NULL,
	continuity BOOLEAN DEFAULT false NOT NULL,
	status VARCHAR(20) DEFAULT 'active' NOT NULL,
	replaced_by VARCHAR(120),
	retired_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (key),
	CONSTRAINT ck_rbac_permissions_key_grammar CHECK (key ~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*[.][a-z][a-z0-9_]*$' AND length(key) <= 120),
	CONSTRAINT ck_rbac_permissions_key_parts CHECK (key = module || '.' || resource || '.' || action),
	CONSTRAINT ck_rbac_permissions_scope_kind CHECK (scope_kind IN ('platform', 'organization')),
	CONSTRAINT ck_rbac_permissions_sensitivity CHECK (sensitivity IN ('normal', 'privileged')),
	CONSTRAINT ck_rbac_permissions_status CHECK (status IN ('active', 'deprecated', 'retired')),
	CONSTRAINT ck_rbac_permissions_retired_at CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
	CONSTRAINT ck_rbac_permissions_platform_not_delegable CHECK (scope_kind <> 'platform' OR NOT delegable_to_org_roles),
	CONSTRAINT ck_rbac_permissions_not_self_replaced CHECK (replaced_by IS NULL OR replaced_by <> key),
	CONSTRAINT ck_rbac_permissions_description CHECK (length(description) BETWEEN 1 AND 500),
	FOREIGN KEY(replaced_by) REFERENCES rbac_permissions (key) ON DELETE RESTRICT
)""",
    r"""CREATE TABLE IF NOT EXISTS rbac_roles (
	id UUID DEFAULT gen_random_uuid() NOT NULL,
	key VARCHAR(200) NOT NULL,
	display_name VARCHAR(100) NOT NULL,
	description TEXT,
	kind VARCHAR(20) NOT NULL,
	assignable_scope VARCHAR(20) NOT NULL,
	org_id VARCHAR(100),
	managed_by VARCHAR(20) NOT NULL,
	state VARCHAR(20) DEFAULT 'active' NOT NULL,
	auto_grant_new_permissions BOOLEAN DEFAULT false NOT NULL,
	replaced_by_role_id UUID,
	retired_at TIMESTAMP WITH TIME ZONE,
	retired_by VARCHAR(150),
	retirement_reason TEXT,
	revision INTEGER DEFAULT 1 NOT NULL,
	created_by VARCHAR(150),
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_rbac_roles_key_grammar CHECK (key ~ '^(platform[.][a-z][a-z0-9_]*|custom[.]platform[.][a-z][a-z0-9_]*|custom[.]org_[a-z0-9_-]+[.][a-z][a-z0-9_]*)$'),
	CONSTRAINT ck_rbac_roles_key_length CHECK (length(key) <= 200),
	CONSTRAINT ck_rbac_roles_kind CHECK (kind IN ('system', 'custom')),
	CONSTRAINT ck_rbac_roles_assignable_scope CHECK (assignable_scope IN ('platform', 'organization')),
	CONSTRAINT ck_rbac_roles_managed_by CHECK (managed_by IN ('code', 'admin')),
	CONSTRAINT ck_rbac_roles_state CHECK (state IN ('active', 'retiring', 'retired')),
	CONSTRAINT ck_rbac_roles_system_is_code_managed CHECK ((kind = 'system') = (managed_by = 'code')),
	CONSTRAINT ck_rbac_roles_system_key_prefix CHECK ((kind = 'system') = (key ~ '^platform[.]')),
	CONSTRAINT ck_rbac_roles_org_id CHECK ((org_id IS NOT NULL) = (kind = 'custom' AND assignable_scope = 'organization')),
	CONSTRAINT ck_rbac_roles_platform_custom_key CHECK ((key ~ '^custom[.]platform[.]') = (kind = 'custom' AND assignable_scope = 'platform')),
	CONSTRAINT ck_rbac_roles_auto_grant_platform_only CHECK (NOT auto_grant_new_permissions OR assignable_scope = 'platform'),
	CONSTRAINT ck_rbac_roles_retired_at CHECK ((state = 'retired') = (retired_at IS NOT NULL)),
	CONSTRAINT ck_rbac_roles_not_self_replaced CHECK (replaced_by_role_id IS NULL OR replaced_by_role_id <> id),
	CONSTRAINT ck_rbac_roles_revision CHECK (revision >= 1),
	CONSTRAINT ck_rbac_roles_display_name CHECK (length(display_name) BETWEEN 1 AND 100 AND display_name = btrim(display_name) AND display_name !~ '[\x01-\x1f\x7f]'),
	CONSTRAINT uq_rbac_roles_key UNIQUE (key),
	FOREIGN KEY(org_id) REFERENCES organizations (id) ON DELETE RESTRICT,
	FOREIGN KEY(replaced_by_role_id) REFERENCES rbac_roles (id) ON DELETE RESTRICT
)""",
    r"""CREATE UNIQUE INDEX IF NOT EXISTS uq_rbac_roles_display_name_org ON rbac_roles (org_id, lower(display_name)) WHERE org_id IS NOT NULL AND state <> 'retired'""",
    r"""CREATE UNIQUE INDEX IF NOT EXISTS uq_rbac_roles_display_name_platform ON rbac_roles (lower(display_name)) WHERE org_id IS NULL AND state <> 'retired'""",
    r"""CREATE TABLE IF NOT EXISTS rbac_role_revisions (
	id BIGSERIAL NOT NULL,
	role_id UUID NOT NULL,
	revision INTEGER NOT NULL,
	display_name VARCHAR(100) NOT NULL,
	description TEXT,
	permission_set_hash VARCHAR(64) NOT NULL,
	state VARCHAR(20) NOT NULL,
	change_kind VARCHAR(30) NOT NULL,
	changed_by VARCHAR(150),
	changed_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_rbac_role_revisions_revision CHECK (revision >= 1),
	CONSTRAINT ck_rbac_role_revisions_state CHECK (state IN ('active', 'retiring', 'retired')),
	CONSTRAINT ck_rbac_role_revisions_change_kind CHECK (change_kind IN ('created', 'renamed', 'described', 'permissions_changed', 'state_changed', 'retired', 'reactivated', 'synced')),
	CONSTRAINT ck_rbac_role_revisions_hash CHECK (length(permission_set_hash) = 64),
	CONSTRAINT uq_rbac_role_revisions_role_rev UNIQUE (role_id, revision),
	FOREIGN KEY(role_id) REFERENCES rbac_roles (id) ON DELETE RESTRICT
)""",
    r"""CREATE INDEX IF NOT EXISTS ix_rbac_role_revisions_role_id ON rbac_role_revisions (role_id)""",
    r"""CREATE TABLE IF NOT EXISTS rbac_role_permissions (
	role_id UUID NOT NULL,
	permission_key VARCHAR(120) NOT NULL,
	granted_by VARCHAR(150),
	granted_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (role_id, permission_key),
	FOREIGN KEY(role_id) REFERENCES rbac_roles (id) ON DELETE RESTRICT,
	FOREIGN KEY(permission_key) REFERENCES rbac_permissions (key) ON DELETE RESTRICT
)""",
    r"""CREATE INDEX IF NOT EXISTS ix_rbac_role_permissions_permission_key ON rbac_role_permissions (permission_key)""",
    r"""CREATE TABLE IF NOT EXISTS rbac_user_roles (
	id UUID DEFAULT gen_random_uuid() NOT NULL,
	user_id VARCHAR(150) NOT NULL,
	role_id UUID NOT NULL,
	scope_type VARCHAR(20) NOT NULL,
	scope_org_id VARCHAR(100),
	granted_by VARCHAR(150),
	granted_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE,
	revoked_at TIMESTAMP WITH TIME ZONE,
	revoked_by VARCHAR(150),
	revoke_reason VARCHAR(30),
	PRIMARY KEY (id),
	CONSTRAINT ck_rbac_user_roles_scope_type CHECK (scope_type IN ('platform', 'organization')),
	CONSTRAINT ck_rbac_user_roles_scope_org CHECK ((scope_type = 'organization') = (scope_org_id IS NOT NULL)),
	CONSTRAINT ck_rbac_user_roles_revoke_reason CHECK (revoke_reason IS NULL OR revoke_reason IN ('migrated', 'role_retired', 'expired', 'manual')),
	CONSTRAINT ck_rbac_user_roles_revocation CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
	CONSTRAINT ck_rbac_user_roles_expiry CHECK (expires_at IS NULL OR expires_at > granted_at),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE RESTRICT,
	FOREIGN KEY(role_id) REFERENCES rbac_roles (id) ON DELETE RESTRICT,
	FOREIGN KEY(scope_org_id) REFERENCES organizations (id) ON DELETE RESTRICT
)""",
    r"""CREATE INDEX IF NOT EXISTS ix_rbac_user_roles_role_id ON rbac_user_roles (role_id)""",
    r"""CREATE INDEX IF NOT EXISTS ix_rbac_user_roles_user_live ON rbac_user_roles (user_id) WHERE revoked_at IS NULL""",
    r"""CREATE UNIQUE INDEX IF NOT EXISTS uq_rbac_user_roles_live ON rbac_user_roles (user_id, role_id, coalesce(scope_org_id, '')) WHERE revoked_at IS NULL""",
    r"""CREATE TABLE IF NOT EXISTS rbac_default_roles (
	purpose VARCHAR(50) NOT NULL,
	role_id UUID NOT NULL,
	updated_by VARCHAR(150),
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (purpose),
	CONSTRAINT ck_rbac_default_roles_purpose CHECK (purpose IN ('self_registration')),
	FOREIGN KEY(role_id) REFERENCES rbac_roles (id) ON DELETE RESTRICT
)""",
    r"""CREATE TABLE IF NOT EXISTS rbac_legacy_map (
	id BIGSERIAL NOT NULL,
	kind VARCHAR(20) NOT NULL,
	legacy_role_name VARCHAR(50),
	legacy_resource VARCHAR(100),
	legacy_action VARCHAR(50),
	role_key VARCHAR(200),
	permission_key VARCHAR(120),
	behaviour_change TEXT,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_rbac_legacy_map_kind CHECK (kind IN ('role', 'permission')),
	CONSTRAINT ck_rbac_legacy_map_shape CHECK ((kind = 'role' AND legacy_role_name IS NOT NULL AND role_key IS NOT NULL AND legacy_resource IS NULL AND legacy_action IS NULL AND permission_key IS NULL) OR (kind = 'permission' AND legacy_resource IS NOT NULL AND legacy_action IS NOT NULL AND permission_key IS NOT NULL AND legacy_role_name IS NULL AND role_key IS NULL)),
	FOREIGN KEY(role_key) REFERENCES rbac_roles (key) ON DELETE RESTRICT,
	FOREIGN KEY(permission_key) REFERENCES rbac_permissions (key) ON DELETE RESTRICT
)""",
    r"""CREATE UNIQUE INDEX IF NOT EXISTS uq_rbac_legacy_map_permission ON rbac_legacy_map (legacy_resource, legacy_action, permission_key) WHERE kind = 'permission'""",
    r"""CREATE UNIQUE INDEX IF NOT EXISTS uq_rbac_legacy_map_role ON rbac_legacy_map (legacy_role_name) WHERE kind = 'role'""",
)

TRIGGER_SQL = {
    "rbac_roles": (
        r"""
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
""",
        r"""DROP TRIGGER IF EXISTS rbac_roles_guard_trg ON rbac_roles""",
        r"""
CREATE TRIGGER rbac_roles_guard_trg BEFORE UPDATE OR DELETE ON rbac_roles
  FOR EACH ROW EXECUTE FUNCTION rbac_roles_guard()
""",
    ),
    "rbac_role_revisions": (
        r"""
CREATE OR REPLACE FUNCTION rbac_role_revisions_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
    MESSAGE = 'rbac_role_revisions is append-only';
END
$$ LANGUAGE plpgsql
""",
        r"""DROP TRIGGER IF EXISTS rbac_role_revisions_append_only_trg ON rbac_role_revisions""",
        r"""
CREATE TRIGGER rbac_role_revisions_append_only_trg
  BEFORE UPDATE OR DELETE ON rbac_role_revisions
  FOR EACH ROW EXECUTE FUNCTION rbac_role_revisions_append_only()
""",
    ),
    "rbac_role_permissions": (
        r"""
CREATE OR REPLACE FUNCTION rbac_role_permissions_guard() RETURNS trigger AS $$
DECLARE
  r_scope text;
  p_scope text;
  p_delegable boolean;
  p_continuity boolean;
  p_status text;
BEGIN
  SELECT assignable_scope INTO r_scope FROM rbac_roles WHERE id = NEW.role_id;
  SELECT scope_kind, delegable_to_org_roles, continuity, status
    INTO p_scope, p_delegable, p_continuity, p_status
    FROM rbac_permissions WHERE key = NEW.permission_key;
  IF p_status = 'retired' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'a retired permission cannot be granted: ' || NEW.permission_key;
  END IF;
  IF r_scope = 'organization' AND (p_scope <> 'organization' OR NOT p_delegable) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'permission cannot be held by an organisation-scope role: ' || NEW.permission_key;
  END IF;
  IF p_continuity AND EXISTS (
       SELECT 1 FROM rbac_default_roles WHERE role_id = NEW.role_id) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'a default role cannot hold a continuity permission: ' || NEW.permission_key;
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql
""",
        r"""DROP TRIGGER IF EXISTS rbac_role_permissions_guard_trg ON rbac_role_permissions""",
        r"""
CREATE TRIGGER rbac_role_permissions_guard_trg BEFORE INSERT ON rbac_role_permissions
  FOR EACH ROW EXECUTE FUNCTION rbac_role_permissions_guard()
""",
    ),
    "rbac_user_roles": (
        r"""
CREATE OR REPLACE FUNCTION rbac_user_roles_guard() RETURNS trigger AS $$
DECLARE
  r_state text;
  r_scope text;
  r_org text;
  u_org text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        MESSAGE = 'an assignment is created live and revoked later';
    END IF;
    SELECT state, assignable_scope, org_id INTO r_state, r_scope, r_org
      FROM rbac_roles WHERE id = NEW.role_id;
    IF r_state <> 'active' THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        MESSAGE = 'a ' || r_state || ' role cannot be assigned';
    END IF;
    IF r_scope <> NEW.scope_type THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        MESSAGE = 'role is assignable at ' || r_scope || ' scope, not ' || NEW.scope_type;
    END IF;
    IF r_org IS NOT NULL AND r_org IS DISTINCT FROM NEW.scope_org_id THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation',
        MESSAGE = 'an organisation role cannot be assigned outside its organisation';
    END IF;
    IF NEW.scope_type = 'organization' THEN
      SELECT org_id INTO u_org FROM users WHERE id = NEW.user_id;
      IF u_org IS DISTINCT FROM NEW.scope_org_id THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation',
          MESSAGE = 'an organisation-scope assignment must be in the user''s own organisation';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.user_id IS DISTINCT FROM OLD.user_id
     OR NEW.role_id IS DISTINCT FROM OLD.role_id
     OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
     OR NEW.scope_org_id IS DISTINCT FROM OLD.scope_org_id
     OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
     OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'an assignment can only be revoked, not changed';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (
       NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
    OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by
    OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
      MESSAGE = 'a revoked assignment cannot be changed or restored';
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql
""",
        r"""DROP TRIGGER IF EXISTS rbac_user_roles_guard_trg ON rbac_user_roles""",
        r"""
CREATE TRIGGER rbac_user_roles_guard_trg BEFORE INSERT OR UPDATE ON rbac_user_roles
  FOR EACH ROW EXECUTE FUNCTION rbac_user_roles_guard()
""",
    ),
    "rbac_default_roles": (
        r"""
CREATE OR REPLACE FUNCTION rbac_default_roles_guard() RETURNS trigger AS $$
DECLARE
  r_state text;
  r_scope text;
BEGIN
  SELECT state, assignable_scope INTO r_state, r_scope
    FROM rbac_roles WHERE id = NEW.role_id;
  IF r_state <> 'active' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'a default role must be active';
  END IF;
  IF r_scope <> 'organization' THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'a default role must be assignable within an organisation';
  END IF;
  IF EXISTS (
       SELECT 1 FROM rbac_role_permissions rp
         JOIN rbac_permissions p ON p.key = rp.permission_key
        WHERE rp.role_id = NEW.role_id
          AND (NOT p.delegable_to_org_roles OR p.continuity)) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation',
      MESSAGE = 'a default role cannot hold a non-delegable or continuity permission';
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql
""",
        r"""DROP TRIGGER IF EXISTS rbac_default_roles_guard_trg ON rbac_default_roles""",
        r"""
CREATE TRIGGER rbac_default_roles_guard_trg BEFORE INSERT OR UPDATE ON rbac_default_roles
  FOR EACH ROW EXECUTE FUNCTION rbac_default_roles_guard()
""",
    ),
}

TRIGGER_FUNCTIONS = (
    "rbac_default_roles_guard",
    "rbac_user_roles_guard",
    "rbac_role_permissions_guard",
    "rbac_role_revisions_append_only",
    "rbac_roles_guard",
)

#: sha256 of the empty permission set: the seeded roles hold nothing yet.
EMPTY_SET_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

SYSTEM_ROLES = (
    # key, display name, description, assignable scope, auto grant
    (
        "platform.superadmin",
        "Superadmin",
        "Platform-wide administration; holds every active permission.",
        "platform",
        True,
    ),
    (
        "platform.org_admin",
        "Org Admin",
        "Full administration of one organisation.",
        "organization",
        False,
    ),
    (
        "platform.analyst",
        "Analyst",
        "Operates the products and works their results within one organisation.",
        "organization",
        False,
    ),
    (
        "platform.viewer",
        "Viewer",
        "Read-only access within one organisation.",
        "organization",
        False,
    ),
    (
        "platform.scanner",
        "Scanner",
        "API-only account that launches and reads automated work within one organisation.",
        "organization",
        False,
    ),
)
LEGACY_ROLE_NAMES = (
    ("superadmin", "platform.superadmin"),
    ("org_admin", "platform.org_admin"),
    ("analyst", "platform.analyst"),
    ("viewer", "platform.viewer"),
    ("scanner", "platform.scanner"),
)
MIGRATION_ACTOR = "system:migration"


def upgrade() -> None:
    conn = op.get_bind()
    for statement in TABLE_SQL:
        conn.exec_driver_sql(statement)
    for statements in TRIGGER_SQL.values():
        for statement in statements:
            conn.exec_driver_sql(statement)

    for key, display, description, scope, auto in SYSTEM_ROLES:
        params = dict(
            key=key,
            display=display,
            description=description,
            scope=scope,
            auto=auto,
            actor=MIGRATION_ACTOR,
            hash=EMPTY_SET_HASH,
        )
        conn.execute(
            sa.text(
                "INSERT INTO rbac_roles (key, display_name, description, kind, "
                "assignable_scope, managed_by, state, auto_grant_new_permissions, "
                "revision, created_by) "
                "SELECT :key, :display, :description, 'system', :scope, 'code', "
                "'active', :auto, 1, :actor "
                "WHERE NOT EXISTS (SELECT 1 FROM rbac_roles WHERE key = :key)"
            ),
            params,
        )
        conn.execute(
            sa.text(
                "INSERT INTO rbac_role_revisions (role_id, revision, display_name, "
                "description, permission_set_hash, state, change_kind, changed_by) "
                "SELECT id, 1, display_name, description, :hash, state, 'created', :actor "
                "FROM rbac_roles WHERE key = :key "
                "AND NOT EXISTS (SELECT 1 FROM rbac_role_revisions rr "
                "WHERE rr.role_id = rbac_roles.id)"
            ),
            params,
        )
    conn.execute(
        sa.text(
            "INSERT INTO rbac_default_roles (purpose, role_id, updated_by) "
            "SELECT 'self_registration', id, :actor FROM rbac_roles "
            "WHERE key = 'platform.viewer' ON CONFLICT (purpose) DO NOTHING"
        ),
        {"actor": MIGRATION_ACTOR},
    )
    for legacy, key in LEGACY_ROLE_NAMES:
        conn.execute(
            sa.text(
                "INSERT INTO rbac_legacy_map (kind, legacy_role_name, role_key) "
                "SELECT 'role', :legacy, :key WHERE NOT EXISTS ("
                "SELECT 1 FROM rbac_legacy_map WHERE kind = 'role' "
                "AND legacy_role_name = :legacy)"
            ),
            {"legacy": legacy, "key": key},
        )


def downgrade() -> None:
    conn = op.get_bind()
    assignments = conn.execute(sa.text("SELECT count(*) FROM rbac_user_roles")).scalar()
    if assignments:
        raise RuntimeError(
            f"Refusing to drop the RBAC tables: rbac_user_roles holds {assignments} "
            "assignment(s), which are history. Export them first, then drop the "
            "tables by hand if that is really what you want."
        )
    for table in reversed(TABLES):
        conn.exec_driver_sql(f"DROP TABLE IF EXISTS {table} CASCADE")
    for function in TRIGGER_FUNCTIONS:
        conn.exec_driver_sql(f"DROP FUNCTION IF EXISTS {function}()")
