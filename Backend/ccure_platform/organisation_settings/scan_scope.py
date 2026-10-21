"""
Authorised scan scope — an organisation setting.

The CIDR ranges an organisation is permitted to scan, and whether any are
configured at all. Stored in ``organizations.scan_scope_cidrs``, which only a
superadmin may write: an organisation widening its own scan authorisation is
exactly the escalation the control exists to stop.

Only the authorised range configuration is here. Deciding whether targets fall inside
it — expanding them, refusing with a message, and what an unconfigured scope
means under ``REQUIRE_SCAN_SCOPE`` — is Audit's, in ``core.scan_scope``, the
one Audit module allowed to call this feature.

Stored independently of scan execution.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Iterable

from ccure_platform.models import Organization
from sqlalchemy.orm import Session

# The logger core.scan_scope used when it read the column itself, so the
# malformed-value warning keeps matching existing log filters.
log = logging.getLogger("ccure.scan_scope")


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanScopeView:
    """
    ``configured=False`` — no scope was ever set (the column is NULL).
    ``configured=True`` with no ``cidrs`` — scanning is denied outright.
    ``configured=True`` with ``cidrs`` — scanning is permitted inside them.

    The ranges are the stored entries as text, unparsed: parsing, and dropping
    an entry that does not parse, is the consumer's, which is where that has
    always happened.
    """

    org_id: str
    configured: bool
    cidrs: tuple[str, ...]


def scan_scope(db: Session, org_id: str | None) -> ScanScopeView | None:
    """The organisation's authorised scope, or None if it does not exist."""
    if not org_id:
        return None
    row = db.query(Organization).filter(Organization.id == str(org_id)).first()
    if row is None:
        return None
    raw = row.scan_scope_cidrs
    if raw is None:
        return ScanScopeView(org_id=str(row.id), configured=False, cidrs=())
    if not isinstance(raw, (list, tuple)):
        log.warning(
            "scan_scope_cidrs is %s, expected a list; treating as deny-all",
            type(raw).__name__,
        )
        return ScanScopeView(org_id=str(row.id), configured=True, cidrs=())
    return ScanScopeView(
        org_id=str(row.id), configured=True, cidrs=tuple(str(e) for e in raw)
    )


def normalise_scope(entries: Iterable[str]) -> list[str]:
    """
    Validate and canonicalise operator-supplied CIDRs before storing them.

    Raises ValueError on the first bad entry. Reading stored data drops a bad
    entry and narrows the scope; this is the write path, and a typo should be
    rejected loudly rather than silently narrowing what an admin thought they
    granted. Moved from ``core.scan_scope`` in Phase 8.4: validating what may be
    stored is the platform's job.
    """
    out: list[str] = []
    for entry in entries:
        text = str(entry).strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"Not a valid CIDR block: {text!r} ({exc})") from exc
        out.append(str(network))
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(out))
