"""
core/mac_vendor_cache.py
─────────────────────────────────────────────────────────────────────────────
The asset registry's MAC-vendor cache, as the scan kernel's OUI lookup reads
and writes it (G3, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

``core.oui_lookup`` is part of the scan kernel, which names no table. It asks
its shared cache through a port, and this answers it from ``mac_vendor_cache``
with the session, query and upsert the lookup used to run itself, moved
unchanged. Registered by Audit's composition root,
``ccure_audit/vendor_cache.py``.
"""

from __future__ import annotations

from typing import Optional


class MacVendorCacheStore:
    """``mac_vendor_cache``, one short session per call."""

    def get(self, oui: str) -> Optional[str]:
        from db.base import SessionLocal
        from db.models import MacVendorCache

        db = SessionLocal()
        try:
            cached_entry = (
                db.query(MacVendorCache)
                .filter(MacVendorCache.mac_prefix == oui)
                .first()
            )
            return cached_entry.vendor_name if cached_entry else None
        finally:
            db.close()

    def put(self, oui: str, vendor: str) -> None:
        from db.base import SessionLocal
        from db.models import MacVendorCache
        from sqlalchemy.dialects.postgresql import insert

        db = SessionLocal()
        try:
            stmt = (
                insert(MacVendorCache)
                .values(mac_prefix=oui, vendor_name=vendor)
                .on_conflict_do_update(
                    index_elements=["mac_prefix"], set_={"vendor_name": vendor}
                )
            )
            db.execute(stmt)
            db.commit()
        finally:
            db.close()


STORE = MacVendorCacheStore()
