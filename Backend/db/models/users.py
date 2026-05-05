"""
db/models/users.py
──────────────────────────────────────────────────────────────────────────────
User authentication, session management, and audit logging.

Tables
──────
  users                  — Org-scoped user accounts with RBAC role assignment
  refresh_token_sessions — JWT refresh token rotation with revocation support
  audit_logs             — Immutable record of every user action (SIEM-ready)

Production improvements over v1
────────────────────────────────
  - UUID primary keys (not sequential integers) — prevents user enumeration
  - org_id FK — full multi-tenant isolation
  - role_id FK — fine-grained RBAC
  - is_active + is_verified — account lifecycle management
  - failed_login_count / locked_until — brute-force protection
  - preferences JSONB — per-user UI settings without extra migrations
  - AuditLog table — full immutable action trail (required for SOC 2 / ISO 27001)
"""

from sqlalchemy import (
    BigInteger, Boolean, Column, ForeignKey, Integer,
    SmallInteger, String, Text, inspect, text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, gen_uuid, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# User
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    """
    An individual user account — always scoped to one Organization.

    Lifecycle states
    ────────────────
      is_active=False   → Account disabled by admin (soft lock)
      is_verified=False → Email not yet confirmed (for future email workflow)
      locked_until      → Time-based lockout after too many failed logins

    preferences JSONB examples:
      {
        "theme": "dark",
        "default_scan_type": "asset",
        "email_alerts": true,
        "timezone": "Asia/Kolkata"
      }
    """
    __tablename__ = "users"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    org_id          = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    role_id         = Column(SmallInteger,       ForeignKey("roles.id", ondelete="RESTRICT"),
                             nullable=False, index=True)

    # ── Identity ──────────────────────────────────────────────────────────────
    username        = Column(String(100), nullable=False, unique=True, index=True)
    email           = Column(String(320), nullable=False, unique=True, index=True)
    full_name       = Column(String(255), nullable=True)
    password_hash   = Column(String(255), nullable=False)

    # ── Account State ─────────────────────────────────────────────────────────
    is_active        = Column(Boolean, nullable=False, default=True)
    is_deleted       = Column(Boolean, nullable=False, default=False)
    is_verified      = Column(Boolean, nullable=False, default=False)
    last_login_at    = Column(TIMESTAMPTZ, nullable=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until     = Column(TIMESTAMPTZ, nullable=True)   # null = not locked
    deleted_at       = Column(TIMESTAMPTZ, nullable=True)

    # ── Profile ───────────────────────────────────────────────────────────────
    avatar_url      = Column(String(512), nullable=True)
    preferences     = Column(JSONB, nullable=False, default=dict)  # Per-user settings

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at      = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization    = relationship("Organization", back_populates="users")
    role            = relationship("Role",         back_populates="users")
    refresh_tokens  = relationship("RefreshTokenSession", back_populates="user",
                                   cascade="all, delete-orphan")
    audit_logs      = relationship("AuditLog", back_populates="user", passive_deletes=True)
    scans           = relationship("Scan",    back_populates="created_by_user", passive_deletes=True)
    asset_notes     = relationship("AssetNote", back_populates="user", passive_deletes=True)
    asset_tags      = relationship("AssetTag",  back_populates="created_by_user", passive_deletes=True)

    def __repr__(self):
        return f"<User {self.username!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Refresh Token Sessions
# ─────────────────────────────────────────────────────────────────────────────

class RefreshTokenSession(Base):
    """
    Tracks issued JWT refresh tokens for rotation and revocation.

    token_jti   — JWT ID (unique per token; stored in the JWT payload)
    token_hash  — bcrypt/sha256 hash of the raw token (never store raw tokens)
    replaced_by — When a token is rotated, records the JTI of its successor
                  (allows detecting token-reuse attacks)
    device_info — User-agent / device fingerprint for the "active sessions" UI

    Revocation model: token is invalid if (revoked_at IS NOT NULL) OR (expires_at < NOW())
    """
    __tablename__ = "refresh_token_sessions"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    org_id      = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    token_jti   = Column(String(128), nullable=False, unique=True, index=True)
    token_hash  = Column(String(255), nullable=False, unique=True)

    issued_at   = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    expires_at  = Column(TIMESTAMPTZ, nullable=False)
    revoked_at  = Column(TIMESTAMPTZ, nullable=True)
    replaced_by = Column(String(128), nullable=True)    # JTI of successor token

    # Device context — shown in "Active Sessions" UI
    ip_address  = Column(INET,   nullable=True)
    device_info = Column(JSONB,  nullable=True, default=dict)  # {user_agent, os, browser}

    user = relationship("User", back_populates="refresh_tokens")

    @property
    def is_valid(self) -> bool:
        from datetime import datetime, timezone
        return self.revoked_at is None and self.expires_at > datetime.now(timezone.utc)

    def __repr__(self):
        return f"<RefreshTokenSession jti={self.token_jti!r} valid={self.is_valid}>"


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log  (SOC 2 / ISO 27001 compliance trail)
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Immutable record of every user action — never updated or deleted.

    Required for: SOC 2 Type II, ISO/IEC 27001, PCI-DSS, HIPAA audits.

    action examples:
      user.login, user.login_failed, user.logout
      scan.created, scan.cancelled, scan.deleted
      asset.tagged, asset.note_added
      report.exported, settings.changed

    changes JSONB shape (for update events):
      {"before": {"status": "running"}, "after": {"status": "cancelled"}}

    status: "success" | "failure" | "denied"
    """
    __tablename__ = "audit_logs"

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    org_id        = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"),
                           nullable=True, index=True)
    user_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                           nullable=True, index=True)

    action        = Column(String(100), nullable=False, index=True)  # "scan.created"
    resource_type = Column(String(100), nullable=True)               # "scan" | "asset" | "user"
    resource_id   = Column(String(255), nullable=True)               # UUID or integer as string

    changes       = Column(JSONB, nullable=True)       # before/after diff
    ip_address    = Column(INET,  nullable=True)
    user_agent    = Column(Text,  nullable=True)
    status        = Column(String(20), nullable=False, default="success")  # success | failure | denied

    created_at    = Column(TIMESTAMPTZ, nullable=False, default=utcnow, index=True)

    user = relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog action={self.action!r} user={self.user_id}>"


def ensure_user_schema():
    """
    Additive migration for the users table so existing databases gain the
    deleted-user lifecycle columns without destructive schema changes.
    """
    from db.base import engine

    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    columns = {col["name"] for col in inspector.get_columns("users")}
    dialect = engine.dialect.name

    with engine.begin() as conn:
        if "is_deleted" not in columns:
            if dialect == "postgresql":
                conn.execute(text("ALTER TABLE users ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT FALSE"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_is_deleted ON users (is_deleted)"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_is_deleted ON users (is_deleted)"))

        if "deleted_at" not in columns:
            if dialect == "postgresql":
                conn.execute(text("ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_deleted_at ON users (deleted_at)"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN deleted_at DATETIME"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_deleted_at ON users (deleted_at)"))
