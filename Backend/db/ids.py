"""
db/ids.py
──────────────────────────────────────────────────────────────────────────────
The deterministic id helpers that need nothing but the standard library: the
organisation token, the asset id and the network link id. Moved verbatim from
``db/base.py``, which imports them back, so ``db.base.gen_asset_id`` and the
rest are these very functions.

They are here so that a library that only has to *compute* an id — the
topology engine merges links on theirs and enrols assets under theirs — does
not load the database engine, SQLAlchemy and the application settings that
importing ``db.base`` does.
"""

import hashlib
import re


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


def gen_asset_id(org_identifier: str, ip_address: str) -> str:
    """
    Generate a readable Asset ID.
    Example: ast_defa_1a2b3c4d_192_168_1_5
    NOTE: Asset IDs are deterministic and globally unique by organization and IP.
    """
    org_part = gen_org_token(org_identifier)
    ip_part = _safe_id_part(ip_address, max_len=50)
    return f"ast_{org_part}_{ip_part}"


def gen_network_link_id(org_slug: str, src_key: str, dst_key: str) -> str:
    """
    Generate a readable, unique NetworkLink ID.
    Example: lnk_defa_1a2b3c4d_001122334455_66778899aabb

    Endpoint keys are sorted before formatting so that a link between the same
    two devices always has the same ID regardless of which side reported it
    (undirected determinism).

    Keys are not always MACs — an endpoint known only by IP or by chassis name
    is keyed ``ip:10.1.1.1`` / ``name:core-sw-01`` (see core.topology.identity).
    Non-MAC keys are hashed rather than stripped of their separators: dropping
    the dots from ``10.1.4.11`` and ``1.0.14.11`` yields the same token for two
    different devices, which would silently merge their links into one row.
    """
    org_part = gen_org_token(org_slug)

    def _endpoint_token(key: str) -> str:
        compact = re.sub(r"[^0-9a-f]+", "", str(key).lower())
        # A bare 48-bit MAC stays readable; anything else gets a stable digest
        # so that distinct identifiers cannot collapse onto the same token.
        if len(compact) == 12 and re.fullmatch(r"[0-9a-f]{12}", compact):
            return compact
        return _stable_hash(str(key).lower(), length=16)

    first, second = sorted([str(src_key).lower(), str(dst_key).lower()])
    return f"lnk_{org_part}_{_endpoint_token(first)}_{_endpoint_token(second)}"
