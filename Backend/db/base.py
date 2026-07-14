"""
db/base.py
──────────────────────────────────────────────────────────────────────────────
Production-grade SQLAlchemy base, engine, and session setup.

Key design decisions:
  - Uses PostgreSQL-native types: JSONB, INET, MACADDR, TIMESTAMPTZ, CIDR
  - Connection pool tuned for production workloads
  - All timestamps are timezone-aware (TIMESTAMPTZ)
  - Stripe-style human-readable IDs are used as primary keys:
      org_default               → Organization
      usr_defa_1a2b3c4d_pankaj_x9v1  → User (org namespace + username + random)
      scn_defa_1a2b3c4d_07may25_x9v1 → Scan (org namespace + date + random)
      ast_defa_1a2b3c4d_192_168_1_5   → Asset (org namespace + IP address)
      svc_ast_defa_1a2b3c4d_192_168_1_5_22_tcp → Service (asset id + port + proto)
"""

import hashlib
import random
import re
import string
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

# TIMESTAMPTZ alias — maps to TIMESTAMP WITH TIME ZONE in PostgreSQL
# Used throughout all model files for timezone-aware timestamp columns.
TIMESTAMPTZ = DateTime(timezone=True)

from config import AppConfig

# ─── Engine ───────────────────────────────────────────────────────────────────

engine = create_engine(AppConfig.DATABASE_URL, **AppConfig.DATABASE_ENGINE_KWARGS)

# ─── Enable pg_trgm extension for fast text search ───────────────────────────


@event.listens_for(engine, "connect")
def _set_extensions(dbapi_connection, connection_record):
    """Enable useful PostgreSQL extensions on first connection."""
    old_autocommit = dbapi_connection.autocommit
    dbapi_connection.autocommit = True
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cursor.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    except Exception as exc:
        import logging

        logging.getLogger("db.base").warning(
            "Failed to create postgres extensions: %s", exc
        )
    finally:
        cursor.close()
        dbapi_connection.autocommit = old_autocommit


# ─── Session & Base ──────────────────────────────────────────────────────────

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _rand(n: int = 4) -> str:
    """Generate a short random alphanumeric suffix (lowercase)."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _safe_id_part(value: str, max_len: int = 20) -> str:
    """Normalize a value to a lowercase, underscore-separated ID-safe token."""
    if value is None:
        return "x"
    safe = re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")
    return safe[:max_len] or "x"


def _stable_hash(value: str, length: int = 8) -> str:
    """Generate a stable hex digest for a value, useful for namespace tokens."""
    return hashlib.blake2b(
        str(value).encode("utf-8"), digest_size=(length + 1) // 2
    ).hexdigest()[:length]


def gen_org_token(org_identifier: str) -> str:
    """
    Generate a stable organization namespace token.
    Example: defa_1a2b3c4d
    """
    short_slug = _safe_id_part(org_identifier, max_len=4).strip("_")
    if not short_slug:
        short_slug = "org"
    token = _stable_hash(org_identifier, length=8)
    return f"{short_slug}_{token}"


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
    Example: usr_defa_1a2b3c4d_pankaj_x9v1
    Uses a stable org namespace token so users are unique across orgs.
    """
    org_part = gen_org_token(org_slug)
    user_part = _safe_id_part(username)[:12]
    return f"usr_{org_part}_{user_part}_{_rand()}"


def gen_scan_id(org_slug: str) -> str:
    """
    Generate a readable Scan ID.
    Example: scn_defa_1a2b3c4d_07may25_x9v1
    """
    org_part = gen_org_token(org_slug)
    date_part = datetime.now(timezone.utc).strftime("%d%b%y").lower()  # 07may25
    return f"scn_{org_part}_{date_part}_{_rand()}"


def gen_asset_id(org_identifier: str, ip_address: str) -> str:
    """
    Generate a readable Asset ID.
    Example: ast_defa_1a2b3c4d_192_168_1_5
    NOTE: Asset IDs are deterministic and globally unique by organization and IP.
    """
    org_part = gen_org_token(org_identifier)
    ip_part = _safe_id_part(ip_address, max_len=50)
    return f"ast_{org_part}_{ip_part}"


def gen_service_id(asset_id: str, port: int, protocol: str = "tcp") -> str:
    """
    Generate a readable Service ID.
    Example: svc_ast_org_cdackp2_in_192.168.1.5_22_tcp
    """
    return f"svc_{asset_id}_{port}_{protocol}"


def gen_scan_phase_id(scan_id: str, phase_key: str) -> str:
    """
    Generate a readable ScanPhase ID.
    Example: sph_scn_def_07may25_x9v1_host_discovery
    """
    return f"sph_{scan_id}_{phase_key}"


def gen_notification_id(user_id: str, notif_type: str) -> str:
    """
    Generate a readable Notification ID.
    Example: ntf_usr_defa_1a2b3c4d_pankaj_scan_complete_x9v1
    Uses the user ID to ensure uniqueness across organizations.
    """
    user_part = _safe_id_part(user_id, max_len=30)
    type_part = _safe_id_part(notif_type, max_len=15)
    return f"ntf_{user_part}_{type_part}_{_rand()}"


def gen_audit_id(org_slug: str, action: str) -> str:
    """
    Generate a readable Audit Log ID.
    Example: aud_defa_1a2b3c4d_scan_created_x9v1
    """
    org_part = gen_org_token(org_slug)
    action_part = _safe_id_part(action)[:20]
    return f"aud_{org_part}_{action_part}_{_rand()}"


def gen_vuln_finding_id(asset_id: str, vuln_id: str) -> str:
    """
    Generate a readable AssetVulnerability (Finding) ID.
    Example: fnd_ast_def_192.168.1.5_CVE-2024-4577
    """
    return f"fnd_{asset_id}_{vuln_id}"


# ─── Web Scan ID Generators ──────────────────────────────────────────────────


def gen_web_scan_id(org_slug: str) -> str:
    """
    Generate a readable WebScan ID.
    Example: wsc_defa_1a2b3c4d_24may26_x9v1
    """
    org_part = gen_org_token(org_slug)
    date_part = datetime.now(timezone.utc).strftime("%d%b%y").lower()
    return f"wsc_{org_part}_{date_part}_{_rand()}"


def gen_web_asset_id(web_scan_id: str, url: str) -> str:
    """
    Generate a readable WebAsset ID.
    Deterministic: same scan + URL always produces the same ID.
    Example: was_wsc_defa_24may26_a1b2c3d4
    """
    url_hash = _stable_hash(url, length=8)
    # Truncate scan ID to keep asset ID reasonable length
    scan_short = web_scan_id[:30] if len(web_scan_id) > 30 else web_scan_id
    return f"was_{scan_short}_{url_hash}"


def gen_web_finding_id(web_asset_id: str, finding_type: str) -> str:
    """
    Generate a readable WebFinding ID.
    Example: wfn_was_wsc_defa_xss_k8m2
    """
    asset_short = web_asset_id[:40] if len(web_asset_id) > 40 else web_asset_id
    type_part = _safe_id_part(finding_type, max_len=15)
    return f"wfn_{asset_short}_{type_part}_{_rand()}"


def gen_network_link_id(org_slug: str, src_mac: str, dst_mac: str) -> str:
    """
    Generate a readable, unique NetworkLink ID.
    Example: lnk_defa_1a2b3c4d_001122334455_66778899aabb

    MACs are sorted alphabetically before hashing to ensure that a link
    between the same two devices always has the same ID (undirected determinism).
    """
    org_part = gen_org_token(org_slug)
    # Sort MACs alphabetically to enforce undirected link determinism
    macs = sorted([src_mac.lower(), dst_mac.lower()])
    clean_src = re.sub(r"[^a-f0-9]+", "", macs[0])
    clean_dst = re.sub(r"[^a-f0-9]+", "", macs[1])
    return f"lnk_{org_part}_{clean_src}_{clean_dst}"


def gen_compliance_credential_id(org_slug: str) -> str:
    """
    Generate a readable Compliance Credential ID.
    Example: ccrd_defa_1a2b3c4d_x9v1
    """
    org_part = gen_org_token(org_slug)
    return f"ccrd_{org_part}_{_rand()}"


def gen_compliance_remediation_request_id(org_slug: str) -> str:
    """
    Generate a readable Compliance Remediation Request ID.
    Example: crrq_defa_1a2b3c4d_x9v1
    """
    org_part = gen_org_token(org_slug)
    return f"crrq_{org_part}_{_rand()}"


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
