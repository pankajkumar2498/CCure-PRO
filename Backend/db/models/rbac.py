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

This mirrors Nessus / Tenable.io's "Access Group" concept, allowing
multiple teams to share the same CCure instance with strict data isolation.
"""

from sqlalchemy import (
    Boolean, Column, ForeignKey, Integer, SmallInteger,
    String, Text, UniqueConstraint, Index,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from db.base import Base, TIMESTAMPTZ, gen_uuid, utcnow


# ─────────────────────────────────────────────────────────────────────────────
# Organizations  (top-level multi-tenant boundary)
# ─────────────────────────────────────────────────────────────────────────────

class Organization(Base):
    """
    A logical tenant boundary — think of this as one "company" or "department".

    Every User, Asset, and Scan belongs to exactly one Organization.
    Data from Org A is NEVER visible to Org B (enforced at query level).

    plan         — 'community' | 'pro' | 'enterprise'  (controls feature flags)
    max_assets   — Hard cap enforced at scan save time
    settings     — JSONB bag for per-org feature flags (e.g. {"sso_enabled": true})
    """
    __tablename__ = "organizations"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    name        = Column(String(255), nullable=False, unique=True)
    slug        = Column(String(100), nullable=False, unique=True)  # URL-safe short name
    plan        = Column(String(50),  nullable=False, default="community")  # community | pro | enterprise
    max_assets  = Column(Integer, nullable=False, default=500)
    max_users   = Column(Integer, nullable=False, default=10)
    is_active   = Column(Boolean, nullable=False, default=True)
    settings    = Column(JSONB,   nullable=False, default=dict)    # Feature flags / custom config

    created_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at  = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    users  = relationship("User",  back_populates="organization", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="organization", cascade="all, delete-orphan")
    scans  = relationship("Scan",  back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organization {self.slug!r} plan={self.plan!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Roles
# ─────────────────────────────────────────────────────────────────────────────

class Role(Base):
    """
    System-wide role definitions.  Five built-in roles mirror Tenable / Nessus:

      superadmin  — Full platform access (CCure SaaS admin; not bound to any org)
      org_admin   — Full access within their Organization (create users, manage scans)
      analyst     — Can run scans, view all results, generate reports
      viewer      — Read-only: view dashboards and existing scan history
      scanner     — API-only service account; can submit and read back scan jobs

    is_system_role=True means this role is seeded at startup and cannot be deleted.
    """
    __tablename__ = "roles"

    id             = Column(SmallInteger, primary_key=True, autoincrement=True)
    name           = Column(String(50),  nullable=False, unique=True)
    description    = Column(Text, nullable=True)
    is_system_role = Column(Boolean, nullable=False, default=False)

    created_at     = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    # ── Relationships ─────────────────────────────────────────────────────────
    users       = relationship("User",           back_populates="role")
    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Role {self.name!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Permissions
# ─────────────────────────────────────────────────────────────────────────────

class Permission(Base):
    """
    Atomic permission tokens: resource × action.

    resource examples: scans, assets, reports, users, settings, credentials
    action   examples: create, read, update, delete, execute, export

    These are additive — a Role accumulates all permissions assigned to it
    via the role_permissions bridge table.
    """
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_permissions_resource_action"),
    )

    id       = Column(SmallInteger, primary_key=True, autoincrement=True)
    resource = Column(String(100), nullable=False)   # e.g. "scans", "assets", "reports"
    action   = Column(String(50),  nullable=False)   # e.g. "create", "read", "execute"
    description = Column(Text, nullable=True)

    roles = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Permission {self.resource}:{self.action}>"


# ─────────────────────────────────────────────────────────────────────────────
# Role ↔ Permission Bridge
# ─────────────────────────────────────────────────────────────────────────────

class RolePermission(Base):
    """Many-to-many bridge between roles and permissions."""
    __tablename__ = "role_permissions"

    role_id       = Column(SmallInteger, ForeignKey("roles.id",       ondelete="CASCADE"), primary_key=True)
    permission_id = Column(SmallInteger, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

    role       = relationship("Role",       back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")
