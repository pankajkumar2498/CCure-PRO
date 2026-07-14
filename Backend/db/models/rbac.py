"""
db/models/rbac.py
──────────────────────────────────────────────────────────────────────────────
Role-Based Access Control (RBAC) + Multi-Tenant Organization schema.

Tables
──────
  organizations   — An org is the top-level tenant (company / department / team)
  roles           — System-wide role definitions (superadmin, org_admin, analyst, viewer, scanner)
  permissions     — Granular permission atoms  (resource × action)
  role_permissions— M:M bridge: which permissions each role holds

ID Convention (Stripe-Style)
─────────────────────────────
  Organization  →  org_{slug}          e.g. org_default, org_acme
  Role          →  SmallInteger (kept — roles are system-seeded and never renamed)
  Permission    →  SmallInteger (kept — permissions are system-seeded atoms)
"""

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Organizations  (top-level multi-tenant boundary)
# ─────────────────────────────────────────────────────────────────────────────


class Organization(Base):
    """
    A logical tenant boundary — think of this as one "company" or "department".

    Every User, Asset, and Scan belongs to exactly one Organization.
    Data from Org A is NEVER visible to Org B (enforced at query level).

    ID Convention:
      id = gen_org_id(slug)  →  e.g. "org_default", "org_acme_corp"
      This ID is readable and used as FK in all child tables.
      ON UPDATE CASCADE means: if you ever rename the slug, all child rows update.

    plan         — 'community' | 'pro' | 'enterprise'  (controls feature flags)
    max_assets   — Hard cap enforced at scan save time
    settings     — JSONB bag for per-org feature flags (e.g. {"sso_enabled": true})
    """

    __tablename__ = "organizations"

    # Stripe-style readable ID: "org_default", "org_acme"
    id = Column(String(100), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True)  # URL-safe short name
    plan = Column(String(50), nullable=False, default="community")
    max_assets = Column(Integer, nullable=False, default=500)
    max_users = Column(Integer, nullable=False, default=10)

    # ── Scan Quota Overrides (NULL = use plan default from core/quota.py) ──────
    # Superadmins can set per-org overrides that take precedence over plan limits.
    max_scans_per_day = Column(Integer, nullable=True)  # rolling 24-h window
    max_concurrent_scans = Column(Integer, nullable=True)  # simultaneous running scans

    is_active = Column(Boolean, nullable=False, default=True)
    settings = Column(JSONB, nullable=False, default=dict)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    users = relationship(
        "User", back_populates="organization", cascade="all, delete-orphan"
    )
    assets = relationship(
        "Asset", back_populates="organization", cascade="all, delete-orphan"
    )
    scans = relationship(
        "Scan", back_populates="organization", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Organization {self.id!r} plan={self.plan!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Roles
# ─────────────────────────────────────────────────────────────────────────────


class Role(Base):
    """
    System-wide role definitions.  Five built-in roles mirror Tenable / Nessus.
    Roles keep SmallInteger PKs — they are seeded once and never renamed by users.
    """

    __tablename__ = "roles"

    id = Column(SmallInteger, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    is_system_role = Column(Boolean, nullable=False, default=False)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    users = relationship("User", back_populates="role")
    permissions = relationship(
        "RolePermission", back_populates="role", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Role {self.name!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Permissions
# ─────────────────────────────────────────────────────────────────────────────


class Permission(Base):
    """Atomic permission tokens: resource × action."""

    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_permissions_resource_action"),
    )

    id = Column(SmallInteger, primary_key=True, autoincrement=True)
    resource = Column(String(100), nullable=False)
    action = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)

    roles = relationship(
        "RolePermission", back_populates="permission", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Permission {self.resource}:{self.action}>"


# ─────────────────────────────────────────────────────────────────────────────
# Role ↔ Permission Bridge
# ─────────────────────────────────────────────────────────────────────────────


class RolePermission(Base):
    """Many-to-many bridge between roles and permissions."""

    __tablename__ = "role_permissions"

    role_id = Column(
        SmallInteger, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id = Column(
        SmallInteger, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )

    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")
