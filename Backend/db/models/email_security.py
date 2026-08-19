"""
db/models/email_security.py
──────────────────────────────────────────────────────────────────────────────
Disposable / throwaway email domain screening.

Tables
──────
  email_domain_rules  — human ALLOW / DENY decisions and the never-block floor
  disposable_domains  — merged upstream blocklist corpus with provenance

Why two tables and not one
──────────────────────────
They have different lifecycles, different sizes and different blast radii.

`email_domain_rules` holds roughly a hundred rows, each one a decision somebody
made on purpose: "this customer's domain is fine", "this domain is banned here".
It is small, precious, and inside the six-hourly `backup_db.ps1` dump.

`disposable_domains` holds ~93,000 rows rebuilt from upstream lists by
`scripts/security/sync_disposable_domains.py`. It is disposable in its own
right — losing it costs one sync run.

Merged into one table, a sync would be writing to the same rows an
administrator edits, and one bad upstream entry could silently overwrite a
deliberate allow. Kept apart, a sync physically cannot reach a human decision.

Both tables are platform-wide, not org-scoped. A throwaway domain is a
throwaway domain for every tenant, and scoping the corpus per organisation
would mean syncing 93,000 rows once per org.
"""

from db.base import TIMESTAMPTZ, Base, utcnow
from sqlalchemy import (
    BigInteger,
    Column,
    Index,
    Integer,
    String,
    Text,
    inspect,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB

#: Verdict values for :class:`EmailDomainRule`.
VERDICT_ALLOW = "allow"
VERDICT_DENY = "deny"


# ─────────────────────────────────────────────────────────────────────────────
# The never-block floor
# ─────────────────────────────────────────────────────────────────────────────
#
# Seeded before the corpus is ever loaded, and never removed by a sync.
#
# This is not belt-and-braces. Upstream blocklists are maintained by volunteers
# and they do get this wrong: `qq.com` — a mail provider with hundreds of
# millions of real users — has been listed, and so has Apple's Private Relay.
# One such entry, unnoticed, silently refuses every signup from a whole country.
# Pinning the providers that obviously must work costs one table scan at
# migration time and removes that entire class of outage.
SEED_ALLOW_DOMAINS: tuple[str, ...] = (
    # Global consumer mail
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "hotmail.co.uk",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.in",
    "ymail.com",
    "rocketmail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "gmx.com",
    "gmx.net",
    "gmx.de",
    "web.de",
    "mail.com",
    "zoho.com",
    "zohomail.com",
    "fastmail.com",
    "fastmail.fm",
    "protonmail.com",
    "protonmail.ch",
    "proton.me",
    "pm.me",
    "tutanota.com",
    "tutanota.de",
    "tuta.com",
    "tuta.io",
    "hushmail.com",
    "yandex.com",
    "yandex.ru",
    "qq.com",
    "163.com",
    "126.com",
    "sina.com",
    "foxmail.com",
    "naver.com",
    "daum.net",
    "hanmail.net",
    "rediffmail.com",
    "indiatimes.com",
    "sify.com",
    # Alias and forwarding services.
    #
    # A deliberate policy choice, not an oversight: several blocklists classify
    # these as disposable because the addresses are per-site and revocable. But
    # they are bought by people who wanted privacy, they forward to a permanent
    # mailbox the person actually reads, and Apple's is issued to paying
    # customers who often do not know an alternative address exists. Blocking
    # them turns a privacy-conscious customer away at the door. They are
    # allowed, and the guard still records a flag so the pattern stays visible.
    "privaterelay.appleid.com",
    "icloud.com",
    "simplelogin.com",
    "simplelogin.io",
    "slmail.me",
    "aleeas.com",
    "passmail.net",
    "passinbox.com",
    "duck.com",
    "mozmail.com",
    "relay.firefox.com",
    "anonaddy.com",
    "anonaddy.me",
    "addy.io",
    "33mail.com",
    # This deployment's own domains.
    "cdac.in",
    "cdacb.in",
    "ccureaudit.pro",
)


def seed_domain_rules(connection) -> int:
    """
    Insert the never-block floor, skipping any domain already present.

    Idempotent, so it is safe from both the alembic migration and application
    startup. Returns the number of rows actually inserted.

    Existing rows are never modified. If an administrator has deliberately
    denied one of these domains, that decision is theirs to make and this must
    not quietly reverse it on the next restart.
    """
    from datetime import datetime, timezone

    existing = {
        row[0]
        for row in connection.execute(text("SELECT domain FROM email_domain_rules"))
    }
    now = datetime.now(timezone.utc)

    rows = []
    for domain in SEED_ALLOW_DOMAINS:
        if domain in existing:
            continue
        rows.append(
            {
                "domain": domain,
                "verdict": VERDICT_ALLOW,
                "source": "seed",
                "reason": (
                    "Established provider or deployment domain — "
                    "shipped allowlist floor."
                ),
                "created_at": now,
                "updated_at": now,
            }
        )
        # SEED_ALLOW_DOMAINS intentionally repeats icloud.com (consumer mail and
        # again beside Private Relay). Guard the in-batch duplicate too, or the
        # unique index rejects the whole insert.
        existing.add(domain)

    if rows:
        connection.execute(EmailDomainRule.__table__.insert(), rows)
    return len(rows)


def seed_disposable_snapshot(connection, snapshot_path=None) -> int:
    """
    Load the bundled snapshot into `disposable_domains` if the table is empty.

    Only when empty. A populated corpus is the product of a sync that knows
    more than this file does, and re-seeding over it would drag the deployment
    backwards to whatever was true the day the snapshot was cut.

    Returns the number of rows inserted.
    """
    import gzip
    import os
    from datetime import datetime, timezone

    count = connection.execute(text("SELECT COUNT(*) FROM disposable_domains")).scalar()
    if count:
        return 0

    if snapshot_path is None:
        data_dir = os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ),
            "data",
        )
        # Gzipped in the repository, and not for tidiness: the plain list is
        # 1.1 MB and pre-commit's check-added-large-files refuses anything over
        # 500 KB. Compressed it is 411 KB. The uncompressed name is still
        # honoured so that a locally regenerated file keeps working.
        gz = os.path.join(data_dir, "disposable_domains_snapshot.txt.gz")
        plain = os.path.join(data_dir, "disposable_domains_snapshot.txt")
        snapshot_path = gz if os.path.isfile(gz) else plain

    if not os.path.isfile(snapshot_path):
        import logging

        logging.getLogger(__name__).error(
            "Disposable domain snapshot missing at %s — the corpus starts empty "
            "and registrations are unscreened until a sync runs.",
            snapshot_path,
        )
        return 0

    now = datetime.now(timezone.utc)
    batch = []
    inserted = 0

    def flush():
        nonlocal inserted, batch
        if not batch:
            return
        connection.execute(DisposableDomain.__table__.insert(), batch)
        inserted += len(batch)
        batch = []

    seen = set()
    opener = gzip.open if snapshot_path.endswith(".gz") else open
    with opener(snapshot_path, "rt", encoding="utf-8") as handle:
        for line in handle:
            domain = line.strip().lower()
            if not domain or domain.startswith("#") or domain in seen:
                continue
            seen.add(domain)
            batch.append(
                {
                    "domain": domain,
                    "sources": ["snapshot"],
                    "first_seen_at": now,
                    "last_seen_at": now,
                    "miss_count": 0,
                }
            )
            if len(batch) >= 5000:
                flush()
    flush()
    return inserted


# ─────────────────────────────────────────────────────────────────────────────
# Human decisions
# ─────────────────────────────────────────────────────────────────────────────


class EmailDomainRule(Base):
    """
    An explicit platform-wide decision about one email domain.

    ALLOW always wins. That ordering is the whole reason this table exists: an
    upstream blocklist is maintained by strangers on a schedule nobody here
    controls, and when it wrongly lists a customer's domain there has to be one
    place an administrator can go to override it permanently. Without that, the
    only remedy for a false positive is to wait for someone else to fix their
    list.

    `domain` is stored in registrable form, lowercased — `example.co.uk`, not
    `mail.example.co.uk` and not `Example.CO.UK`. The guard also tests every
    parent suffix of the address's domain against this table, so a rule on
    `example.co.uk` covers `mail.example.co.uk` without a second row.
    """

    __tablename__ = "email_domain_rules"
    __table_args__ = (Index("ix_email_domain_rules_verdict", "verdict"),)

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    domain = Column(String(255), nullable=False, unique=True, index=True)
    verdict = Column(String(10), nullable=False)

    #: Where the rule came from: 'seed' (shipped floor), 'admin' (a person),
    #: or 'approval' (created by approving a flagged user with allowlist_domain).
    source = Column(String(40), nullable=False, default="admin")

    #: Free text shown to the next administrator who wonders why this is here.
    reason = Column(Text, nullable=True)

    #: Deliberately *not* a ForeignKey to users.id. A rule must outlive the
    #: administrator who created it — deleting a leaver's account must never
    #: cascade into re-blocking a customer's email domain.
    created_by = Column(String(150), nullable=True)

    created_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    updated_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow, onupdate=utcnow)

    def __repr__(self):
        return f"<EmailDomainRule {self.domain!r} {self.verdict!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Synced corpus
# ─────────────────────────────────────────────────────────────────────────────


class DisposableDomain(Base):
    """
    One domain believed by at least one upstream list to be disposable.

    `sources` records which lists named it, so a source that turns out to be
    noisy can be traced and dropped without re-deriving the whole corpus. It
    also makes "how many lists agree" available if a confidence threshold is
    ever wanted; today one credible list is enough to block, because the
    measured failure mode is under-blocking, not over-blocking.

    `miss_count` supports retirement. A domain absent from every source is not
    deleted on the first sync that misses it — an upstream list that briefly
    returns an error page would otherwise silently drain the corpus. It is
    dropped only after `DISPOSABLE_RETIRE_AFTER_MISSES` consecutive successful
    syncs without it.
    """

    __tablename__ = "disposable_domains"
    __table_args__ = (Index("ix_disposable_domains_last_seen", "last_seen_at"),)

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    domain = Column(String(255), nullable=False, unique=True, index=True)

    #: JSONB array of source names, e.g. ["fakefilter", "disposable"].
    sources = Column(JSONB, nullable=False, default=list)

    first_seen_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)
    last_seen_at = Column(TIMESTAMPTZ, nullable=False, default=utcnow)

    #: Consecutive successful syncs in which no source named this domain.
    miss_count = Column(Integer, nullable=False, default=0)

    def __repr__(self):
        return f"<DisposableDomain {self.domain!r}>"


# ─────────────────────────────────────────────────────────────────────────────
# Additive migration
# ─────────────────────────────────────────────────────────────────────────────


def ensure_email_security_schema():
    """
    Create both tables if they are missing.

    Mirrors `ensure_user_schema()`: alembic owns the schema, but the API
    container calls this at startup so a deployment that has not run the
    migration yet comes up with a working guard rather than 500ing on every
    registration. Creating a table that already exists is a no-op.
    """
    from db.base import engine

    inspector = inspect(engine)
    existing = set(inspector.get_table_names())

    to_create = [
        table
        for name, table in (
            ("email_domain_rules", EmailDomainRule.__table__),
            ("disposable_domains", DisposableDomain.__table__),
        )
        if name not in existing
    ]
    if to_create:
        Base.metadata.create_all(bind=engine, tables=to_create)

    # `miss_count` was added after the first cut of these tables shipped.
    inspector = inspect(engine)
    if "disposable_domains" in set(inspector.get_table_names()):
        columns = {col["name"] for col in inspector.get_columns("disposable_domains")}
        if "miss_count" not in columns:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE disposable_domains "
                        "ADD COLUMN miss_count INTEGER NOT NULL DEFAULT 0"
                    )
                )

    # Seed on every startup, not only on creation. Both seeders are idempotent,
    # and the allowlist floor is the one thing that must be present before the
    # corpus is consulted — a deployment that somehow lost those rows would
    # start refusing Gmail.
    import logging

    log = logging.getLogger(__name__)
    try:
        with engine.begin() as conn:
            rules = seed_domain_rules(conn)
            corpus = seed_disposable_snapshot(conn)
        if rules or corpus:
            log.info(
                "Email domain guard seeded: %d allow rule(s), %d corpus row(s)",
                rules,
                corpus,
            )
    except Exception as exc:
        log.error("Could not seed email domain tables: %s", exc, exc_info=True)
