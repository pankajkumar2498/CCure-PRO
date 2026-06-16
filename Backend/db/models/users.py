"""
db/models/users.py
──────────────────────────────────────────────────────────────────────────────
User authentication, session management, and audit logging.

Tables
──────
  users                  — Org-scoped user accounts with RBAC role assignment
  refresh_token_sessions — JWT refresh token rotation with revocation support
  audit_logs             — Immutable record of every user action (SIEM-ready)

ID Convention (Stripe-Style)
─────────────────────────────
  User     →  usr_{org_3chars}_{username}_{4rand}
               e.g.  usr_def_pankaj_x9v1
                     usr_acm_alice_3k8p

  The org_id FK uses ON UPDATE CASCADE so renaming an org auto-updates all users.
"""

from sqlalchemy import (
    BigInteger, Boolean, Column, ForeignKey, Integer,
    SmallInteger, String, Text, inspect, text, Index,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, gen_uuid, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# User
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    """
    An individual user account — always scoped to one Organization.

    ID: usr_{org_3chars}_{username}_{4rand}
        e.g. usr_def_pankaj_x9v1

    Lifecycle states
    ────────────────
      is_active=False   → Account disabled by admin (soft lock)
      is_verified=False → Email not yet confirmed
      locked_until      → Time-based lockout after too many failed logins
    """
    __tablename__ = "users"

    # Stripe-style readable ID: "usr_def_pankaj_x9v1"
    id              = Column(String(150), primary_key=True)

    # ON UPDATE CASCADE: if org_id (org_default) changes to org_acme,
    # all users of that org get their org_id updated automatically.
    org_id          = Column(String(100), ForeignKey("organizations.id",
                             ondelete="CASCADE", onupdate="CASCADE"),
                             nullable=False, index=True)
    role_id         = Column(SmallInteger, ForeignKey("roles.id", ondelete="RESTRICT"),
                             nullable=False, index=True)

    # ── Identity ──────────────────────────────────────────────────────────────
    username        = Column(String(100), nullable=False, unique=True, index=True)
    email           = Column(String(320), nullable=False, unique=True, index=True)
    full_name       = Column(String(255), nullable=True)
    password_hash   = Column(String(255), nullable=False)
    totp_secret     = Column(String(255), nullable=True)
    mfa_enabled     = Column(Boolean, nullable=False, default=False)
    mfa_backup_codes = Column(JSONB, nullable=False, default=list)
    email_otp_hash  = Column(String(255), nullable=True)
    email_otp_expires_at = Column(TIMESTAMPTZ, nullable=True)

    # ── Account State ─────────────────────────────────────────────────────────
    is_active        = Column(Boolean, nullable=False, default=True)
    is_deleted       = Column(Boolean, nullable=False, default=False)
    is_verified      = Column(Boolean, nullable=False, default=False)
    last_login_at    = Column(TIMESTAMPTZ, nullable=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until     = Column(TIMESTAMPTZ, nullable=True)
    deleted_at       = Column(TIMESTAMPTZ, nullable=True)

    # ── Profile ───────────────────────────────────────────────────────────────
    avatar_url      = Column(String(512), nullable=True)
    preferences     = Column(JSONB, nullable=False, default=dict)

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
        return f"<User {self.id!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Refresh Token Sessions
# ─────────────────────────────────────────────────────────────────────────────

class RefreshTokenSession(Base):
    """
    Tracks issued JWT refresh tokens for rotation and revocation.
    Uses BigInteger PK — high-volume table, small integer is most efficient.
    """
    __tablename__ = "refresh_token_sessions"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id     = Column(String(150), ForeignKey("users.id",
                          ondelete="CASCADE", onupdate="CASCADE"),
                          nullable=False, index=True)
    org_id      = Column(String(100), ForeignKey("organizations.id",
                          ondelete="CASCADE", onupdate="CASCADE"),
                          nullable=False, index=True)

    token_jti   = Column(String(128), nullable=False, unique=True, index=True)
    token_hash  = Column(String(255), nullable=False, unique=True)

    issued_at   = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    expires_at  = Column(TIMESTAMPTZ, nullable=False)
    revoked_at  = Column(TIMESTAMPTZ, nullable=True)
    replaced_by = Column(String(128), nullable=True)

    ip_address  = Column(INET,  nullable=True)
    device_info = Column(JSONB, nullable=True, default=dict)

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

    ID: aud_{org_3chars}_{action}_{4rand}
        e.g. aud_def_scan_created_x9v1

    Required for: SOC 2 Type II, ISO/IEC 27001, PCI-DSS, HIPAA audits.
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_created", "created_at"),
        Index("ix_audit_logs_org_id", "org_id"),
        {"postgresql_partition_by": "HASH (org_id)"}
    )

    # Stripe-style readable ID: "aud_def_scan_created_x9v1"
    id            = Column(String(200), primary_key=True, default=gen_uuid)

    org_id        = Column(String(100), ForeignKey("organizations.id",
                            ondelete="CASCADE", onupdate="CASCADE"),
                            primary_key=True, nullable=False)
    user_id       = Column(String(150), ForeignKey("users.id",
                            ondelete="SET NULL", onupdate="CASCADE"),
                            nullable=True, index=True)

    action        = Column(String(100), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id   = Column(String(255), nullable=True)  # The readable ID of the resource

    changes       = Column(JSONB, nullable=True)
    ip_address    = Column(INET,  nullable=True)
    user_agent    = Column(Text,  nullable=True)
    status        = Column(String(20), nullable=False, default="success")

    created_at    = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    user = relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.id!r} action={self.action!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Password Reset Token
# ─────────────────────────────────────────────────────────────────────────────

class PasswordResetToken(Base):
    """
    Stores cryptographically secure hashes of active password reset tokens.
    Tokens are single-use and expire after 15 minutes.
    """
    __tablename__ = "password_reset_tokens"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id     = Column(String(150), ForeignKey("users.id",
                          ondelete="CASCADE", onupdate="CASCADE"),
                          nullable=False, index=True)
    token_hash  = Column(String(255), nullable=False, unique=True, index=True)
    created_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    expires_at  = Column(TIMESTAMPTZ, nullable=False)

    user = relationship("User")

    def __repr__(self):
        return f"<PasswordResetToken id={self.id} user_id={self.user_id!r}>"


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

        if "totp_secret" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(255)"))

        if "mfa_enabled" not in columns:
            if dialect == "postgresql":
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0"))

        if "mfa_backup_codes" not in columns:
            if dialect == "postgresql":
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_backup_codes JSONB NOT NULL DEFAULT '[]'::jsonb"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_backup_codes TEXT NOT NULL DEFAULT '[]'"))

        if "email_otp_hash" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN email_otp_hash VARCHAR(255)"))

        if "email_otp_expires_at" not in columns:
            if dialect == "postgresql":
                conn.execute(text("ALTER TABLE users ADD COLUMN email_otp_expires_at TIMESTAMPTZ"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN email_otp_expires_at DATETIME"))
