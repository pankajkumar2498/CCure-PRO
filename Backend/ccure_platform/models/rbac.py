"""Organization: the platform tenant boundary. RBAC tables live in rbac_tables."""

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "db.models.rbac")

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

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

    settings     — JSONB bag for per-org feature flags (e.g. {"sso_enabled": true})
    """

    __tablename__ = "organizations"

    # Stripe-style readable ID: "org_default", "org_acme"
    id = Column(String(100), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True)  # URL-safe short name
    is_active = Column(Boolean, nullable=False, default=True)
    settings = Column(JSONB, nullable=False, default=dict)

    # ── Archival (end of tenancy) ─────────────────────────────────────────
    # `DELETE /admin/organizations/{id}` archives rather than deletes. Thirty
    # foreign keys reference this table and every one is ON DELETE CASCADE, so
    # a hard delete destroys the tenant's assets, scans, compliance findings,
    # evidence and — the reason this matters here — its entire audit trail,
    # at exactly the moment an offboarding is most likely to be disputed.
    #
    # `archived_at` is deliberately NOT `is_active`. Deactivation is a
    # reversible suspension used for billing and temporary lockout; archival
    # is the end of the tenancy. Overloading one flag would make "reactivate"
    # ambiguous and leave a suspended tenant indistinguishable from a
    # terminated one in the audit trail.
    #
    # Archiving also sets `is_active = False`, which is what actually denies
    # access: that flag is already enforced in auth/jwt_handler.py (twice) and
    # auth/router.py, so archival needs no new authorisation code and adds no
    # new bypass surface.
    #
    # `archived_by_user_id` carries no foreign key, for the same reason as
    # AuditLog.actor_user_id: the record must survive the deletion of the
    # account that made it.
    archived_at = Column(TIMESTAMPTZ, nullable=True)
    archived_by_user_id = Column(String(150), nullable=True)
    archive_reason = Column(Text, nullable=True)

    # ── Authorised scan scope ─────────────────────────────────────────────────
    # The CIDR blocks this organisation is permitted to scan. Deliberately its
    # own column rather than a key in `settings`, because `settings` is
    # writable by org_admin and this must not be: an org widening its own scan
    # authorisation is exactly the escalation the control exists to stop.
    # Only a superadmin may write it.
    #
    #   NULL  → legacy, unrestricted (see AppConfig.REQUIRE_SCAN_SCOPE)
    #   []    → deny all scanning for this org
    #   [...] → scanning permitted only inside these blocks
    scan_scope_cidrs = Column(JSONB, nullable=True)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    def __init__(self, **kwargs):
        if "id" not in kwargs:
            slug = kwargs.get("slug")
            if not slug:
                import uuid

                slug = (
                    kwargs.get("name", "").lower().replace(" ", "-")
                    or uuid.uuid4().hex[:8]
                )
            from db.base import gen_org_id

            kwargs["id"] = gen_org_id(slug)
        super().__init__(**kwargs)

    # ── Relationships ─────────────────────────────────────────────────────────
    users = relationship(
        "User", back_populates="organization", cascade="all, delete-orphan"
    )
    # No relationships to a module's tables: assets and scans are Audit's, and
    # Audit keeps the one-way link (Asset.organization, Scan.organization).
    # Organisations are archived, never deleted, so nothing relies on the ORM
    # cascade that used to sit here; the database's ON DELETE CASCADE is
    # unchanged.

    def __repr__(self):
        return f"<Organization {self.id!r}>"
