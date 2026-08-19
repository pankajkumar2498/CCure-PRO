"""Disposable email domain screening.

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-08-18

Two accounts registered from temp-mail domains on 18 Aug 2026. Both were inert —
unverified, inactive, unapproved, `viewer` — so neither ever had access; the
approval gate from b1c2d3e4f5a6 held. What failed is that the administrator
reading the approval queue had no way to tell `safan76549@hutdot.com` from a
real user.

This revision adds the two things that fixes:

1. ``email_domain_rules`` — explicit ALLOW / DENY decisions, seeded with a
   never-block floor covering the major consumer providers and this
   deployment's own domains. ALLOW always beats every other source, so one row
   here permanently overrides an upstream blocklist that wrongly lists a
   customer. That override has to exist before enforcement does.

2. ``disposable_domains`` — the merged upstream corpus, seeded from the
   snapshot bundled at ``Backend/data/disposable_domains_snapshot.txt`` so a
   fresh deployment is screened before any sync has run.

Plus four columns on ``users``:

  * ``email_canonical`` (UNIQUE) closes an account-farming hole that no
    blocklist can reach: ``p.kumar+1@gmail.com`` and ``pkumar@gmail.com`` are
    one mailbox and two rows. **The backfill deliberately tolerates existing
    collisions** — on a live database some are already present, and aborting a
    migration over data that predates the rule would leave the deployment
    unable to start. Losers of a collision are left NULL, which does not
    violate a unique index, and are surfaced by the retro-scan instead.
  * ``is_email_flagged`` / ``email_risk`` / ``flagged_at`` carry the advisory
    verdict to the approval queue. A flag never blocks anything.

Measured, and the reason enforcement is scoped to the corpus rather than to
heuristics: of the two domains above, the canonical `disposable-email-domains`
list contained neither, and merging three lists (75,170 domains) caught only
`hutdot.com`. `radiant-flow.org` has valid MX, Cloudflare nameservers and a
17-month-old registration. Any rule aggressive enough to catch it also refuses
real companies, so it is flagged for a human instead.

The downgrade drops both tables and all four columns.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c2d3e4f5a6b7"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    # ── email_domain_rules ───────────────────────────────────────────────────
    if "email_domain_rules" not in tables:
        op.create_table(
            "email_domain_rules",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("domain", sa.String(length=255), nullable=False),
            sa.Column("verdict", sa.String(length=10), nullable=False),
            sa.Column(
                "source", sa.String(length=40), nullable=False, server_default="admin"
            ),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(length=150), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("domain"),
        )
        op.create_index(
            "ix_email_domain_rules_domain", "email_domain_rules", ["domain"]
        )
        op.create_index(
            "ix_email_domain_rules_verdict", "email_domain_rules", ["verdict"]
        )

    # ── disposable_domains ───────────────────────────────────────────────────
    if "disposable_domains" not in tables:
        op.create_table(
            "disposable_domains",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("domain", sa.String(length=255), nullable=False),
            sa.Column(
                "sources",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column(
                "first_seen_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "last_seen_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("miss_count", sa.Integer(), nullable=False, server_default="0"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("domain"),
        )
        op.create_index(
            "ix_disposable_domains_domain", "disposable_domains", ["domain"]
        )
        op.create_index(
            "ix_disposable_domains_last_seen", "disposable_domains", ["last_seen_at"]
        )

    # ── users columns ────────────────────────────────────────────────────────
    user_columns = {col["name"] for col in inspector.get_columns("users")}

    if "is_email_flagged" not in user_columns:
        op.add_column(
            "users",
            sa.Column(
                "is_email_flagged",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )
        op.create_index("ix_users_is_email_flagged", "users", ["is_email_flagged"])

    if "email_risk" not in user_columns:
        op.add_column(
            "users",
            sa.Column(
                "email_risk",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )

    if "flagged_at" not in user_columns:
        op.add_column(
            "users", sa.Column("flagged_at", sa.DateTime(timezone=True), nullable=True)
        )

    if "email_canonical" not in user_columns:
        op.add_column(
            "users", sa.Column("email_canonical", sa.String(length=320), nullable=True)
        )
        _backfill_canonical(bind)
        op.create_index(
            "ix_users_email_canonical", "users", ["email_canonical"], unique=True
        )

    # ── Seed ─────────────────────────────────────────────────────────────────
    # Order matters: the allowlist floor goes in before the corpus, so there is
    # never an instant at which the blocklist is live and the override is not.
    from db.models.email_security import seed_disposable_snapshot, seed_domain_rules

    seeded_rules = seed_domain_rules(bind)
    seeded_corpus = seed_disposable_snapshot(bind)
    print(
        f"[email-domain-guard] seeded {seeded_rules} allow rule(s), "
        f"{seeded_corpus} corpus row(s)"
    )


def _backfill_canonical(bind) -> None:
    """
    Compute `users.email_canonical` in Python, skipping collisions.

    Not expressible in portable SQL: the Gmail rule removes dots from the local
    part only, and only for Gmail. Doing it in the database would mean either a
    PL/pgSQL function nobody maintains or a regex that quietly folds addresses
    at providers which treat dots as significant.
    """
    from auth.email_utils import canonicalize_email

    rows = bind.execute(sa.text("SELECT id, email FROM users")).fetchall()

    seen: dict[str, str] = {}
    collisions: list[str] = []
    for user_id, email in rows:
        canonical = canonicalize_email(email)
        if not canonical:
            continue
        if canonical in seen:
            collisions.append(user_id)
            continue
        seen[canonical] = user_id

    for canonical, user_id in seen.items():
        bind.execute(
            sa.text("UPDATE users SET email_canonical = :c WHERE id = :i"),
            {"c": canonical, "i": user_id},
        )

    if collisions:
        print(
            "[email-domain-guard] WARNING: "
            f"{len(collisions)} account(s) share a mailbox with an earlier "
            f"account and keep email_canonical NULL: {', '.join(collisions)}"
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    user_columns = {col["name"] for col in inspector.get_columns("users")}
    indexes = {ix["name"] for ix in inspector.get_indexes("users")}

    if "ix_users_email_canonical" in indexes:
        op.drop_index("ix_users_email_canonical", table_name="users")
    if "email_canonical" in user_columns:
        op.drop_column("users", "email_canonical")

    if "ix_users_is_email_flagged" in indexes:
        op.drop_index("ix_users_is_email_flagged", table_name="users")
    for column in ("is_email_flagged", "email_risk", "flagged_at"):
        if column in user_columns:
            op.drop_column("users", column)

    tables = set(inspector.get_table_names())
    if "disposable_domains" in tables:
        op.drop_table("disposable_domains")
    if "email_domain_rules" in tables:
        op.drop_table("email_domain_rules")
