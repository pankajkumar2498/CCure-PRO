"""
ccure_platform/models/rbac_tables.py — the tables of the new RBAC capability.

RBAC-1 of the RBAC programme (design frozen in RBAC-0). Six platform-owned tables, all prefixed ``rbac_``:

    rbac_permissions       the catalogue: written only by catalogue sync
    rbac_roles             role identity (id, key, display_name) and lifecycle
    rbac_role_revisions    append-only history of every role
    rbac_role_permissions  role → permission grants
    rbac_user_roles        user → role assignments, never deleted by the API
    rbac_default_roles     which role a purpose (self-registration) assigns

These tables are the sole authorization authority.

Two things this file does that the other models do not, and why:

* **Triggers travel with the tables.** The invariants that must hold even if a
  caller bypasses governance — role identity cannot change, history is
  append-only, a role cannot be assigned out of its scope, a default role cannot
  carry a privileged permission — are PostgreSQL triggers. ``create_all`` (a
  fresh install, the test bootstrap) and the Alembic migration must produce the
  same schema, so the SQL below is attached to the tables for ``create_all`` and
  spelled out again in the migration; ``tests/rbac/test_rbac_schema.py`` fails if
  the two diverge.
* **Nothing here uses ``%`` or a colon in the SQL**, because the same strings run
  through ``DDL`` (which interpolates ``%``) and a driver-level ``execute``.

Layer rule ``models-are-leaves``: this file imports ``db.base`` and SQLAlchemy
and nothing else. It names ``organizations`` and ``users`` by table, never by
class — RBAC owns no relationship into another capability's models.
"""

from __future__ import annotations

from db.base import TIMESTAMPTZ, Base, gen_uuid
from sqlalchemy import (
    DDL,
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
    event,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

_NOW = text("now()")
_FALSE = text("false")

# Keep these in step with ``ccure_platform.rbac.contract`` (a test compares).
_PERMISSION_KEY_RE = "^[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*[.][a-z][a-z0-9_]*$"
_ROLE_KEY_RE = (
    "^(platform[.][a-z][a-z0-9_]*"
    "|custom[.]platform[.][a-z][a-z0-9_]*"
    "|custom[.]org_[a-z0-9_-]+[.][a-z][a-z0-9_]*)$"
)


class RbacPermission(Base):
    """A permission the catalogue knows. ``key`` is ``<module>.<resource>.<action>``."""

    __tablename__ = "rbac_permissions"
    __table_args__ = (
        CheckConstraint(
            f"key ~ '{_PERMISSION_KEY_RE}' AND length(key) <= 120",
            name="ck_rbac_permissions_key_grammar",
        ),
        CheckConstraint(
            "key = module || '.' || resource || '.' || action",
            name="ck_rbac_permissions_key_parts",
        ),
        CheckConstraint(
            "scope_kind IN ('platform', 'organization')",
            name="ck_rbac_permissions_scope_kind",
        ),
        CheckConstraint(
            "sensitivity IN ('normal', 'privileged')",
            name="ck_rbac_permissions_sensitivity",
        ),
        CheckConstraint(
            "status IN ('active', 'deprecated', 'retired')",
            name="ck_rbac_permissions_status",
        ),
        CheckConstraint(
            "(status = 'retired') = (retired_at IS NOT NULL)",
            name="ck_rbac_permissions_retired_at",
        ),
        # A platform-scope permission is never delegable to an organisation role.
        CheckConstraint(
            "scope_kind <> 'platform' OR NOT delegable_to_org_roles",
            name="ck_rbac_permissions_platform_not_delegable",
        ),
        CheckConstraint(
            "replaced_by IS NULL OR replaced_by <> key",
            name="ck_rbac_permissions_not_self_replaced",
        ),
        CheckConstraint(
            "length(description) BETWEEN 1 AND 500",
            name="ck_rbac_permissions_description",
        ),
    )

    key = Column(String(120), primary_key=True)
    module = Column(String(50), nullable=False)
    resource = Column(String(60), nullable=False)
    action = Column(String(60), nullable=False)
    description = Column(Text, nullable=False)
    scope_kind = Column(String(20), nullable=False)
    sensitivity = Column(String(20), nullable=False, server_default="normal")
    delegable_to_org_roles = Column(
        Boolean, nullable=False, server_default=text("true")
    )
    continuity = Column(Boolean, nullable=False, server_default=_FALSE)
    status = Column(String(20), nullable=False, server_default="active")
    replaced_by = Column(
        String(120),
        ForeignKey("rbac_permissions.key", ondelete="RESTRICT"),
        nullable=True,
    )
    retired_at = Column(TIMESTAMPTZ, nullable=True)
    created_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)
    updated_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)

    def __repr__(self) -> str:
        return f"<RbacPermission {self.key} {self.status}>"


class RbacRole(Base):
    """
    A role. ``id``, ``key``, ``kind``, ``assignable_scope``, ``org_id`` and
    ``managed_by`` are immutable (trigger); ``display_name`` and ``description``
    are presentation; ``state`` follows the lifecycle (trigger-checked).

    No row is ever deleted (trigger, and ``ON DELETE RESTRICT`` everywhere): a
    role is retired, and its history stays readable.
    """

    __tablename__ = "rbac_roles"
    __table_args__ = (
        CheckConstraint(f"key ~ '{_ROLE_KEY_RE}'", name="ck_rbac_roles_key_grammar"),
        CheckConstraint("length(key) <= 200", name="ck_rbac_roles_key_length"),
        CheckConstraint("kind IN ('system', 'custom')", name="ck_rbac_roles_kind"),
        CheckConstraint(
            "assignable_scope IN ('platform', 'organization')",
            name="ck_rbac_roles_assignable_scope",
        ),
        CheckConstraint(
            "managed_by IN ('code', 'admin')", name="ck_rbac_roles_managed_by"
        ),
        CheckConstraint(
            "state IN ('active', 'retiring', 'retired')", name="ck_rbac_roles_state"
        ),
        # system ⇔ code-managed ⇔ a platform.<slug> key
        CheckConstraint(
            "(kind = 'system') = (managed_by = 'code')",
            name="ck_rbac_roles_system_is_code_managed",
        ),
        CheckConstraint(
            "(kind = 'system') = (key ~ '^platform[.]')",
            name="ck_rbac_roles_system_key_prefix",
        ),
        # An organisation custom role belongs to one organisation; every other
        # role is global (its assignment, not the role, carries the organisation).
        CheckConstraint(
            "(org_id IS NOT NULL) = (kind = 'custom' AND assignable_scope = 'organization')",
            name="ck_rbac_roles_org_id",
        ),
        CheckConstraint(
            "(key ~ '^custom[.]platform[.]') = (kind = 'custom' AND assignable_scope = 'platform')",
            name="ck_rbac_roles_platform_custom_key",
        ),
        # Materialised "all permissions" is a platform-scope idea only.
        CheckConstraint(
            "NOT auto_grant_new_permissions OR assignable_scope = 'platform'",
            name="ck_rbac_roles_auto_grant_platform_only",
        ),
        CheckConstraint(
            "(state = 'retired') = (retired_at IS NOT NULL)",
            name="ck_rbac_roles_retired_at",
        ),
        CheckConstraint(
            "replaced_by_role_id IS NULL OR replaced_by_role_id <> id",
            name="ck_rbac_roles_not_self_replaced",
        ),
        CheckConstraint("revision >= 1", name="ck_rbac_roles_revision"),
        CheckConstraint(
            "length(display_name) BETWEEN 1 AND 100 "
            "AND display_name = btrim(display_name) "
            "AND display_name !~ '[\\x01-\\x1f\\x7f]'",
            name="ck_rbac_roles_display_name",
        ),
        UniqueConstraint("key", name="uq_rbac_roles_key"),
        # Display names are unique among live roles within one namespace: the
        # platform namespace (org_id NULL), and each organisation. A retired
        # role frees its name.
        Index(
            "uq_rbac_roles_display_name_platform",
            text("lower(display_name)"),
            unique=True,
            postgresql_where=text("org_id IS NULL AND state <> 'retired'"),
        ),
        Index(
            "uq_rbac_roles_display_name_org",
            "org_id",
            text("lower(display_name)"),
            unique=True,
            postgresql_where=text("org_id IS NOT NULL AND state <> 'retired'"),
        ),
    )

    id = Column(
        UUID(as_uuid=False),
        primary_key=True,
        default=gen_uuid,
        server_default=text("gen_random_uuid()"),
    )
    key = Column(String(200), nullable=False)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    kind = Column(String(20), nullable=False)
    assignable_scope = Column(String(20), nullable=False)
    org_id = Column(
        String(100), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True
    )
    managed_by = Column(String(20), nullable=False)
    state = Column(String(20), nullable=False, server_default="active")
    auto_grant_new_permissions = Column(Boolean, nullable=False, server_default=_FALSE)
    replaced_by_role_id = Column(
        UUID(as_uuid=False),
        ForeignKey("rbac_roles.id", ondelete="RESTRICT"),
        nullable=True,
    )
    retired_at = Column(TIMESTAMPTZ, nullable=True)
    retired_by = Column(String(150), nullable=True)
    retirement_reason = Column(Text, nullable=True)
    revision = Column(Integer, nullable=False, server_default=text("1"))
    created_by = Column(String(150), nullable=True)
    created_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)
    updated_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)

    def __repr__(self) -> str:
        # key, never display_name: a repr lands in logs and a label is not an identity
        return f"<RbacRole {self.key} {self.state}>"


class RbacRoleRevision(Base):
    """Append-only history of a role: what it was called and held, when, by whom.
    Audit events snapshot the same facts; this table is where they are rebuilt."""

    __tablename__ = "rbac_role_revisions"
    __table_args__ = (
        CheckConstraint("revision >= 1", name="ck_rbac_role_revisions_revision"),
        CheckConstraint(
            "state IN ('active', 'retiring', 'retired')",
            name="ck_rbac_role_revisions_state",
        ),
        CheckConstraint(
            "change_kind IN ('created', 'renamed', 'described', 'permissions_changed', "
            "'state_changed', 'retired', 'reactivated', 'synced')",
            name="ck_rbac_role_revisions_change_kind",
        ),
        CheckConstraint(
            "length(permission_set_hash) = 64",
            name="ck_rbac_role_revisions_hash",
        ),
        UniqueConstraint("role_id", "revision", name="uq_rbac_role_revisions_role_rev"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    role_id = Column(
        UUID(as_uuid=False),
        ForeignKey("rbac_roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    revision = Column(Integer, nullable=False)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    permission_set_hash = Column(String(64), nullable=False)
    state = Column(String(20), nullable=False)
    change_kind = Column(String(30), nullable=False)
    changed_by = Column(String(150), nullable=True)
    changed_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)


class RbacRolePermission(Base):
    """A role holds a permission. Granting and removing are deliberate acts that
    write a revision; the engine reads these rows, never a flag."""

    __tablename__ = "rbac_role_permissions"

    role_id = Column(
        UUID(as_uuid=False),
        ForeignKey("rbac_roles.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    permission_key = Column(
        String(120),
        ForeignKey("rbac_permissions.key", ondelete="RESTRICT"),
        primary_key=True,
        index=True,
    )
    granted_by = Column(String(150), nullable=True)
    granted_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)


class RbacUserRole(Base):
    """
    A user holds a role, platform-wide or in one organisation. Several rows per
    user are the multi-role model. A row is *revoked*, never overwritten: its
    identity columns are immutable (trigger) and a revocation cannot be undone,
    so an assignment's history is the table itself.
    """

    __tablename__ = "rbac_user_roles"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('platform', 'organization')",
            name="ck_rbac_user_roles_scope_type",
        ),
        CheckConstraint(
            "(scope_type = 'organization') = (scope_org_id IS NOT NULL)",
            name="ck_rbac_user_roles_scope_org",
        ),
        CheckConstraint(
            "revoke_reason IS NULL OR revoke_reason IN "
            "('migrated', 'role_retired', 'expired', 'manual')",
            name="ck_rbac_user_roles_revoke_reason",
        ),
        CheckConstraint(
            "(revoked_at IS NULL) = (revoke_reason IS NULL)",
            name="ck_rbac_user_roles_revocation",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > granted_at",
            name="ck_rbac_user_roles_expiry",
        ),
        # One live assignment of a role to a user per scope. Revoked rows are
        # history and do not count.
        Index(
            "uq_rbac_user_roles_live",
            "user_id",
            "role_id",
            text("coalesce(scope_org_id, '')"),
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        Index(
            "ix_rbac_user_roles_user_live",
            "user_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id = Column(
        UUID(as_uuid=False),
        primary_key=True,
        default=gen_uuid,
        server_default=text("gen_random_uuid()"),
    )
    user_id = Column(
        String(150), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    role_id = Column(
        UUID(as_uuid=False),
        ForeignKey("rbac_roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    scope_type = Column(String(20), nullable=False)
    scope_org_id = Column(
        String(100), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True
    )
    # The actors are plain ids, not foreign keys: the record of who granted or
    # revoked must outlive the account that did.
    granted_by = Column(String(150), nullable=True)
    granted_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)
    expires_at = Column(TIMESTAMPTZ, nullable=True)
    revoked_at = Column(TIMESTAMPTZ, nullable=True)
    revoked_by = Column(String(150), nullable=True)
    revoke_reason = Column(String(30), nullable=True)


class RbacDefaultRole(Base):
    """The role a purpose assigns (v1: ``self_registration``). A reference to a
    role *id*; nothing depends on which role it is."""

    __tablename__ = "rbac_default_roles"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('self_registration')", name="ck_rbac_default_roles_purpose"
        ),
    )

    purpose = Column(String(50), primary_key=True)
    role_id = Column(
        UUID(as_uuid=False),
        ForeignKey("rbac_roles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_by = Column(String(150), nullable=True)
    updated_at = Column(TIMESTAMPTZ, nullable=False, server_default=_NOW)


# ── trigger SQL ───────────────────────────────────────────────────────────────
#
# One function and one trigger per table that needs one. No ``%`` and no ``:``
# in any of it: these strings run through ``DDL`` here and through a driver-level
# execute in the migration.

TRIGGER_SQL: dict[str, tuple[str, ...]] = {
    "rbac_roles": (
        """
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
""",
        "DROP TRIGGER IF EXISTS rbac_roles_guard_trg ON rbac_roles",
        """
CREATE TRIGGER rbac_roles_guard_trg BEFORE UPDATE OR DELETE ON rbac_roles
  FOR EACH ROW EXECUTE FUNCTION rbac_roles_guard()
""",
    ),
    "rbac_role_revisions": (
        """
CREATE OR REPLACE FUNCTION rbac_role_revisions_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'restrict_violation',
    MESSAGE = 'rbac_role_revisions is append-only';
END
$$ LANGUAGE plpgsql
""",
        "DROP TRIGGER IF EXISTS rbac_role_revisions_append_only_trg ON rbac_role_revisions",
        """
CREATE TRIGGER rbac_role_revisions_append_only_trg
  BEFORE UPDATE OR DELETE ON rbac_role_revisions
  FOR EACH ROW EXECUTE FUNCTION rbac_role_revisions_append_only()
""",
    ),
    "rbac_role_permissions": (
        """
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
        "DROP TRIGGER IF EXISTS rbac_role_permissions_guard_trg ON rbac_role_permissions",
        """
CREATE TRIGGER rbac_role_permissions_guard_trg BEFORE INSERT ON rbac_role_permissions
  FOR EACH ROW EXECUTE FUNCTION rbac_role_permissions_guard()
""",
    ),
    "rbac_user_roles": (
        """
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
        "DROP TRIGGER IF EXISTS rbac_user_roles_guard_trg ON rbac_user_roles",
        """
CREATE TRIGGER rbac_user_roles_guard_trg BEFORE INSERT OR UPDATE ON rbac_user_roles
  FOR EACH ROW EXECUTE FUNCTION rbac_user_roles_guard()
""",
    ),
    "rbac_default_roles": (
        """
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
        "DROP TRIGGER IF EXISTS rbac_default_roles_guard_trg ON rbac_default_roles",
        """
CREATE TRIGGER rbac_default_roles_guard_trg BEFORE INSERT OR UPDATE ON rbac_default_roles
  FOR EACH ROW EXECUTE FUNCTION rbac_default_roles_guard()
""",
    ),
}

#: Function names to drop on downgrade, in dependency order.
TRIGGER_FUNCTIONS = (
    "rbac_default_roles_guard",
    "rbac_user_roles_guard",
    "rbac_role_permissions_guard",
    "rbac_role_revisions_append_only",
    "rbac_roles_guard",
)

for _table_name, _statements in TRIGGER_SQL.items():
    _table = Base.metadata.tables[_table_name]
    for _sql in _statements:
        event.listen(_table, "after_create", DDL(_sql).execute_if(dialect="postgresql"))
