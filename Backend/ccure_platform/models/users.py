"""
ccure_platform/models/users.py (was db/models/users.py until Phase 8.2)
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

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "db.models.users")

from db.base import TIMESTAMPTZ, Base, gen_uuid, utcnow
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    inspect,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import relationship

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
    id = Column(String(150), primary_key=True)

    # ON UPDATE CASCADE: if org_id (org_default) changes to org_acme,
    # all users of that org get their org_id updated automatically.
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    role_id = Column(
        SmallInteger,
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    username = Column(String(100), nullable=False, unique=True, index=True)
    email = Column(String(320), nullable=False, unique=True, index=True)

    # The same mailbox, written the one way it can be compared.
    #
    # `email` is unique on the literal string, which means `p.kumar+1@gmail.com`,
    # `pkumar+2@gmail.com` and `p.k.u.m.a.r@gmail.com` are three accounts and one
    # mailbox. That is unlimited account farming through a provider nobody would
    # ever blocklist, and no amount of disposable-domain screening touches it.
    #
    # Nullable because the column is added to a live table and backfilled; the
    # unique index tolerates NULLs, so rows that predate the backfill do not
    # collide with each other. See db/email_canonical.canonicalize_email for what
    # is folded and — more importantly — what is not.
    email_canonical = Column(String(320), nullable=True, unique=True, index=True)

    full_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    totp_secret = Column(String(255), nullable=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_backup_codes = Column(JSONB, nullable=False, default=list)
    email_otp_hash = Column(String(255), nullable=True)
    email_otp_expires_at = Column(TIMESTAMPTZ, nullable=True)

    # ── Account State ─────────────────────────────────────────────────────────
    is_active = Column(Boolean, nullable=False, default=True)
    is_deleted = Column(Boolean, nullable=False, default=False)
    is_verified = Column(Boolean, nullable=False, default=False)
    last_login_at = Column(TIMESTAMPTZ, nullable=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(TIMESTAMPTZ, nullable=True)
    deleted_at = Column(TIMESTAMPTZ, nullable=True)

    # A self-registered account proves control of a mailbox and nothing else.
    # In a product whose "analyst" role executes network scans, that is not a
    # sufficient basis to issue a session, so a second gate is required: a
    # human with admin rights stamps approved_at before the account can log in.
    # Admin-provisioned users are approved at creation, so this is transparent
    # for every path except self-registration.
    approved_at = Column(TIMESTAMPTZ, nullable=True)
    approved_by = Column(String(150), nullable=True)

    # ── Email risk ────────────────────────────────────────────────────────────
    # Set by the email domain guard. `is_email_flagged` drives a badge in the
    # pending-approval queue; `email_risk` carries the signals behind it so the
    # administrator reading that queue is told *why*, not just that something is
    # off.
    #
    # A flag never blocks anything. It exists precisely for the signals that are
    # too weak to refuse an account over — domain age, MX shape, a name that
    # looks throwaway — where being wrong costs an admin four seconds instead of
    # costing a customer their signup.
    is_email_flagged = Column(Boolean, nullable=False, default=False)
    email_risk = Column(JSONB, nullable=False, default=dict)
    flagged_at = Column(TIMESTAMPTZ, nullable=True)

    # ── Profile ───────────────────────────────────────────────────────────────
    avatar_url = Column(String(512), nullable=True)
    preferences = Column(JSONB, nullable=False, default=dict)

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    def __init__(self, **kwargs):
        if "id" not in kwargs:
            from db.base import gen_user_id

            org_id = kwargs.get("org_id", "org_default")
            org_slug = org_id.replace("org_", "") if org_id else "default"
            username = kwargs.get("username", "user")
            kwargs["id"] = gen_user_id(org_slug, username)
        super().__init__(**kwargs)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization = relationship("Organization", back_populates="users")
    role = relationship("Role", back_populates="users")
    refresh_tokens = relationship(
        "RefreshTokenSession", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs = relationship("AuditLog", back_populates="user", passive_deletes=True)
    scans = relationship("Scan", back_populates="created_by_user", passive_deletes=True)
    asset_notes = relationship("AssetNote", back_populates="user", passive_deletes=True)
    asset_tags = relationship(
        "AssetTag", back_populates="created_by_user", passive_deletes=True
    )

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

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(
        String(150),
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )

    token_jti = Column(String(128), nullable=False, unique=True, index=True)
    token_hash = Column(String(255), nullable=False, unique=True)

    issued_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    expires_at = Column(TIMESTAMPTZ, nullable=False)
    revoked_at = Column(TIMESTAMPTZ, nullable=True)
    replaced_by = Column(String(128), nullable=True)

    ip_address = Column(INET, nullable=True)
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

    ID: a UUID4 string, e.g. "227f2894-6218-4c9f-8d8d-1445f14f3aa8".

        This docstring previously described a Stripe-style readable id
        (``aud_{org_3chars}_{action}_{4rand}``) and no such id was ever
        generated: the column has always defaulted to ``gen_uuid``. The
        description is corrected rather than the format, because the id is the
        audit event's permanent external reference — it is quoted in support
        tickets and correlated against application logs, so changing it would
        invalidate every reference already given out. A UUID satisfies what the
        identifier has to be: unique, immutable and searchable.

        The column is ``String(200)`` for the same reason — it was sized for
        the readable form. Left as-is; narrowing it would rewrite the table for
        no functional gain.

    Required for: SOC 2 Type II, ISO/IEC 27001, PCI-DSS, HIPAA audits.
    """

    __tablename__ = "audit_logs"
    # Only two indexes were added for the phase-3 filtering work, and both are
    # here because a measurement demanded them. Everything else the API filters
    # on was measured at 1,000,000 rows and left alone — see
    # `scripts/audit/bench_audit_queries.py` and the notes on each entry.
    __table_args__ = (
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_created", "created_at"),
        Index("ix_audit_logs_org_id", "org_id"),
        # "What did this person do?" — filter by actor, newest first.
        #
        # Without the composite, the planner walks `created_at` DESC in every
        # partition and filters, because a global ORDER BY forces Merge Append
        # to pull from all of them even though one actor's rows live in exactly
        # one partition. Measured at 1M rows: 468,174 buffer hits and 461ms for
        # a 50-row page, with `Rows Removed by Filter: 90432` on partitions
        # holding none of that user's rows. With it: 73 buffers, 4.4ms — 105x.
        Index("ix_audit_logs_user_created", "user_id", "created_at"),
        # The correlation lookup the request_id column exists for: pasting an
        # id from a support ticket or an application log. Measured at 1M rows:
        # 267ms parallel seq scan -> 2.9ms index scan, 92x.
        Index("ix_audit_logs_request_id", "request_id"),
        {"postgresql_partition_by": "HASH (org_id)"},
    )

    # UUID4 — see the class docstring for why this is not the readable
    # Stripe-style id the surrounding models use.
    id = Column(String(200), primary_key=True, default=gen_uuid)

    org_id = Column(
        String(100),
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    user_id = Column(
        String(150),
        ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
        index=True,
    )

    action = Column(String(100), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)  # The readable ID of the resource

    changes = Column(JSONB, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="success")

    # Classified from `action` by core.audit_taxonomy.severity_for(). Stored
    # rather than derived at read time so filtering by severity is an indexed
    # column comparison instead of a scan through a Python mapping.
    severity = Column(String(20), nullable=False, default="medium")

    # The X-Request-ID of the API request that produced this event, from the
    # correlation middleware in main.py. Nullable: events written by Celery
    # tasks and other non-request paths legitimately have none.
    request_id = Column(String(64), nullable=True)

    # ── Immutable actor snapshot ──────────────────────────────────────────
    # `user_id` above is a live foreign key and is legitimately set to NULL
    # when an account is deleted, which is how 88 of the first 511 events on
    # this deployment lost their actor. These two columns are frozen copies
    # taken at write time and carry **no foreign key**, so no referential
    # action can ever reach them.
    #
    # `actor_user_id` is deliberately the same type and length as `users.id`
    # (String(150)) even though nothing enforces the relationship — it is the
    # join key an investigator uses after the account is gone.
    #
    # There is deliberately no `actor_email`. Username is a short handle here;
    # email is PII subject to erasure requests, and freezing it into an
    # append-only, hash-chained table would create a record that by design
    # cannot be erased.
    actor_user_id = Column(String(150), nullable=True)
    actor_username = Column(String(100), nullable=True)

    # ── Tamper-evidence chain ─────────────────────────────────────────────
    # SHA-256 hex, written by the `audit_logs_chain` trigger, never by the
    # application. Both are NULL on rows that predate the chain — see
    # `record_hash IS NULL` as the authoritative legacy test below.
    #
    # VARCHAR rather than CHAR(64): the values are always exactly 64
    # characters, but `char(n)` carries blank-padding semantics and strips
    # trailing spaces when cast to text, which is a hazard in a column whose
    # entire purpose is exact comparison.
    #
    # `prev_hash` is NULL in exactly two situations, and they must not be
    # confused: the organisation's genesis event (the first chained event,
    # recorded in `audit_chain_heads.genesis_event_id`), and any legacy row.
    # `record_hash IS NULL` separates them — legacy rows have no hash at all.
    prev_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=True)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

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

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(
        String(150),
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    expires_at = Column(TIMESTAMPTZ, nullable=False)

    user = relationship("User")

    def __repr__(self):
        return f"<PasswordResetToken id={self.id} user_id={self.user_id!r}>"


class EmailVerificationToken(Base):
    """
    Stores SHA-256 hashes of active email-verification tokens.

    Deliberately a separate table from PasswordResetToken rather than a
    ``purpose`` column on it: the reset flow is the more security-sensitive of
    the two and already works, and a shared table would let a bug in one flow
    mint a token the other accepts. Two tables cannot be confused for each
    other.

    The plaintext token is emailed and never stored, so a database read does
    not yield a usable verification link. Tokens are single-use, enforced by
    deleting the row inside the same transaction that flips is_verified.
    """

    __tablename__ = "email_verification_tokens"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(
        String(150),
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    # The address the token was issued for. A pending email-change must not be
    # confirmable onto a different address than the one that received the link.
    email = Column(String(320), nullable=False)
    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    expires_at = Column(TIMESTAMPTZ, nullable=False)

    user = relationship("User")

    def __repr__(self):
        return f"<EmailVerificationToken id={self.id} user_id={self.user_id!r}>"


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
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_users_is_deleted ON users (is_deleted)"
                    )
                )
            else:
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_users_is_deleted ON users (is_deleted)"
                    )
                )

        if "deleted_at" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ")
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_users_deleted_at ON users (deleted_at)"
                    )
                )
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN deleted_at DATETIME"))
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_users_deleted_at ON users (deleted_at)"
                    )
                )

        if "totp_secret" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(255)"))

        if "mfa_enabled" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
            else:
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0"
                    )
                )

        if "mfa_backup_codes" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN mfa_backup_codes JSONB NOT NULL DEFAULT '[]'::jsonb"
                    )
                )
            else:
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN mfa_backup_codes TEXT NOT NULL DEFAULT '[]'"
                    )
                )

        if "email_otp_hash" not in columns:
            conn.execute(
                text("ALTER TABLE users ADD COLUMN email_otp_hash VARCHAR(255)")
            )

        if "email_otp_expires_at" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN email_otp_expires_at TIMESTAMPTZ"
                    )
                )
            else:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN email_otp_expires_at DATETIME")
                )

        # Approval gate for self-registration. Existing accounts predate the
        # gate and were provisioned by an admin, so they are backfilled as
        # approved — adding this column must not lock out the current userbase.
        if "approved_at" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN approved_at TIMESTAMPTZ")
                )
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN approved_at DATETIME"))
            conn.execute(
                text(
                    "UPDATE users SET approved_at = created_at WHERE approved_at IS NULL"
                )
            )

        if "approved_by" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN approved_by VARCHAR(150)"))

        # ── Email risk columns ────────────────────────────────────────────
        if "is_email_flagged" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN is_email_flagged "
                        "BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
            else:
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN is_email_flagged "
                        "BOOLEAN NOT NULL DEFAULT 0"
                    )
                )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_users_is_email_flagged "
                    "ON users (is_email_flagged)"
                )
            )

        if "email_risk" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN email_risk "
                        "JSONB NOT NULL DEFAULT '{}'::jsonb"
                    )
                )
            else:
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN email_risk "
                        "TEXT NOT NULL DEFAULT '{}'"
                    )
                )

        if "flagged_at" not in columns:
            if dialect == "postgresql":
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN flagged_at TIMESTAMPTZ")
                )
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN flagged_at DATETIME"))

        if "email_canonical" not in columns:
            conn.execute(
                text("ALTER TABLE users ADD COLUMN email_canonical VARCHAR(320)")
            )
            _backfill_email_canonical(conn)


def _backfill_email_canonical(conn) -> None:
    """
    Populate `users.email_canonical`, then add the unique index.

    Order matters and so does the collision handling. Two existing accounts can
    legitimately canonicalize to the same mailbox — that is exactly the abuse
    this column exists to detect, and on a live database some of those pairs are
    already there. Creating the unique index first, or backfilling blindly,
    would abort the migration and leave the deployment unable to start.

    So: compute every canonical form in Python (the Gmail dot rule is not
    expressible in portable SQL), write only the ones that are unique, and leave
    the losers of a collision NULL. NULLs do not collide under a unique index in
    either PostgreSQL or SQLite, so the index still goes on cleanly and future
    registrations are protected. The pre-existing duplicates stay reachable and
    are surfaced by the retro-scan instead of being deleted here — a migration
    is the wrong place to decide which of two real accounts is the impostor.
    """
    import logging

    from db.email_canonical import canonicalize_email

    log = logging.getLogger(__name__)

    rows = conn.execute(text("SELECT id, email FROM users")).fetchall()

    seen: dict[str, str] = {}
    collisions: list[tuple[str, str]] = []
    for user_id, email in rows:
        canonical = canonicalize_email(email)
        if not canonical:
            continue
        if canonical in seen:
            collisions.append((user_id, canonical))
            continue
        seen[canonical] = user_id

    for canonical, user_id in seen.items():
        conn.execute(
            text("UPDATE users SET email_canonical = :c WHERE id = :i"),
            {"c": canonical, "i": user_id},
        )

    if collisions:
        log.warning(
            "email_canonical backfill: %d existing account(s) share a mailbox "
            "with an earlier account and were left NULL: %s",
            len(collisions),
            ", ".join(user_id for user_id, _ in collisions),
        )

    conn.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_canonical "
            "ON users (email_canonical)"
        )
    )
