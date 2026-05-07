"""
db/base.py
──────────────────────────────────────────────────────────────────────────────
Production-grade SQLAlchemy base, engine, and session setup.

Key design decisions:
  - Uses PostgreSQL-native types: JSONB, INET, MACADDR, TIMESTAMPTZ, CIDR
  - Connection pool tuned for production workloads
  - All timestamps are timezone-aware (TIMESTAMPTZ)
  - Stripe-style human-readable IDs are used as primary keys:
      org_default          → Organization
      usr_def_pankaj_x9v1  → User (org_slug + username + 4-char random)
      scn_def_07may25_x9v1 → Scan (org + date + 4-char random)
      ast_def_192.168.1.5  → Asset (org + IP address)
      svc_192.168.1.5_22   → Service (IP + port)
"""

import random
import string
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, text, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, sessionmaker

# TIMESTAMPTZ alias — maps to TIMESTAMP WITH TIME ZONE in PostgreSQL
# Used throughout all model files for timezone-aware timestamp columns.
TIMESTAMPTZ = DateTime(timezone=True)

from config import AppConfig

# ─── Engine ───────────────────────────────────────────────────────────────────

engine = create_engine(
    AppConfig.DATABASE_URL,
    **AppConfig.DATABASE_ENGINE_KWARGS
)

# ─── Enable pg_trgm extension for fast text search ───────────────────────────

@event.listens_for(engine, "connect")
def _set_extensions(dbapi_connection, connection_record):
    """Enable useful PostgreSQL extensions on first connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cursor.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    except Exception:
        pass  # Extensions may already exist
    finally:
        cursor.close()

# ─── Session & Base ──────────────────────────────────────────────────────────

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _rand(n: int = 4) -> str:
    """Generate a short random alphanumeric suffix (lowercase)."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ── Keep gen_uuid as a fallback (used by junction tables / sessions) ──────────
def gen_uuid() -> str:
    """Fallback UUID — only used for tables that don't need readable IDs."""
    import uuid
    return str(uuid.uuid4())


# ─── Stripe-Style ID Generators ───────────────────────────────────────────────

def gen_org_id(slug: str) -> str:
    """
    Generate a readable Organization ID.
    Example: org_default, org_acme
    """
    safe = slug.lower().replace(" ", "_")[:20]
    return f"org_{safe}"


def gen_user_id(org_slug: str, username: str) -> str:
    """
    Generate a readable User ID.
    Example: usr_def_pankaj_x9v1
    Org slug is truncated to 3 chars for brevity.
    """
    org_part = org_slug.lower()[:3]
    user_part = username.lower().replace(" ", "_")[:12]
    return f"usr_{org_part}_{user_part}_{_rand()}"


def gen_scan_id(org_slug: str) -> str:
    """
    Generate a readable Scan ID.
    Example: scn_def_07may25_x9v1
    """
    org_part = org_slug.lower()[:3]
    date_part = datetime.now(timezone.utc).strftime("%d%b%y").lower()  # 07may25
    return f"scn_{org_part}_{date_part}_{_rand()}"


def gen_asset_id(org_slug: str, ip_address: str) -> str:
    """
    Generate a readable Asset ID.
    Example: ast_def_192.168.1.5
    NOTE: Asset IDs are deterministic (no random) so the same host always
    maps to the same ID within an org.
    """
    org_part = org_slug.lower()[:3]
    return f"ast_{org_part}_{ip_address}"


def gen_service_id(ip_address: str, port: int, protocol: str = "tcp") -> str:
    """
    Generate a readable Service ID.
    Example: svc_192.168.1.5_22_tcp
    """
    return f"svc_{ip_address}_{port}_{protocol}"


def gen_scan_phase_id(scan_id: str, phase_key: str) -> str:
    """
    Generate a readable ScanPhase ID.
    Example: sph_scn_def_07may25_x9v1_host_discovery
    """
    return f"sph_{scan_id}_{phase_key}"


def gen_notification_id(username: str, notif_type: str) -> str:
    """
    Generate a readable Notification ID.
    Example: ntf_pankaj_scan_complete_x9v1
    """
    user_part = username.lower()[:10]
    type_part = notif_type.lower()[:15]
    return f"ntf_{user_part}_{type_part}_{_rand()}"


def gen_audit_id(org_slug: str, action: str) -> str:
    """
    Generate a readable Audit Log ID.
    Example: aud_def_scan_created_x9v1
    """
    org_part = org_slug.lower()[:3]
    action_part = action.lower().replace(".", "_")[:20]
    return f"aud_{org_part}_{action_part}_{_rand()}"


def gen_vuln_finding_id(asset_id: str, vuln_id: str) -> str:
    """
    Generate a readable AssetVulnerability (Finding) ID.
    Example: fnd_ast_def_192.168.1.5_CVE-2024-4577
    """
    return f"fnd_{asset_id}_{vuln_id}"


def utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# ─── FastAPI dependency ───────────────────────────────────────────────────────

def get_db():
    """FastAPI dependency: yields a scoped DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
