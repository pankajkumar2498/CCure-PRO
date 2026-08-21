"""
core/oui_lookup.py
------------------
IEEE OUI (Organizationally Unique Identifier) database lookup for MAC address vendor resolution.

The OUI database maps 24-bit MAC address prefixes to vendor names.
Example: 00:1A:2B -> "Company Name"

Data source: IEEE (www.ieee.org/oui)
Format: hex OUI (6 chars) tab Org Name
"""

import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional

import requests

log = logging.getLogger("ccure.oui")

DEFAULT_VENDOR_API_URL = os.environ.get(
    "MAC_VENDOR_API_URL", "https://api.macvendors.com/"
)
DEFAULT_VENDOR_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "vendor_cache.json"
)

#: Separators that sit between the octets of the MAC forms this codebase
#: actually receives: colons (Scapy, Nmap), hyphens (Windows ``getmac``), dots
#: (Cisco's ``001a.2b3c.4d5e``) and stray whitespace.
#:
#: Removing exactly these — rather than "every character that is not a hex
#: digit", which is what ``core.topology.identity.normalize_mac`` does — is what
#: makes the check below a rejection instead of a silent salvage. Stripping all
#: non-hex characters turns ``00:1a:2b:3c:4d:5ezz`` into a well-formed address
#: and would hand it to the vendor API as though it had been scanned that way.
#: Here the ``z`` survives, fails the hex test, and the value is refused.
_MAC_SEPARATORS = re.compile(r"[:.\-\s]")

#: What remains once the separators are gone has to be hexadecimal and nothing
#: else. ``\A``/``\Z`` rather than ``^``/``$``: ``$`` also matches before a
#: trailing newline, so a value ending in one would pass a ``$`` anchor.
_HEX_ONLY = re.compile(r"\A[0-9a-f]+\Z")

#: Accepted lengths, in hex digits, after separators are removed.
#:
#:   6  — a bare 24-bit OUI prefix. This is the key both the local registry and
#:        the ``mac_vendor_cache`` table are indexed on, and ``OUIDatabase``'s
#:        own docstring documents ``lookup("00:1A:2B")``, so it stays supported.
#:   12 — EUI-48: the ordinary MAC address every collector in this repository
#:        emits.
#:   16 — EUI-64. Nothing here produces one today, but it is a valid hardware
#:        address whose leading 24 bits are an OUI like any other, and the
#:        previous ``len >= 6`` rule accepted it. Refusing it would be a
#:        narrowing rather than a fix.
#:
#: Every other length is refused. Note what this excludes that ``len >= 6`` did
#: not: 7-to-11 and 13-to-15 digit strings, which are not addresses in any
#: format, and which reached the network as ``https://api.macvendors.com/<junk>``.
_VALID_MAC_HEX_LENGTHS = frozenset({6, 12, 16})


def _normalize_mac_address(value) -> str | None:
    """
    Return ``value`` as compact lower-case hex, or None when it is not a MAC.

    This is the validation boundary in front of the vendor API. It exists
    because the previous rule — strip separators, accept anything six
    characters or longer — asked only about length and never about content, so
    any word of six or more letters was treated as an address. That was
    reachable in production, not merely in theory: ``_normalize_mac`` in
    ``orchestrator/scan_orchestrator.py`` passes ``"Unknown"`` through
    unchanged, and the vendor-resolution branch beside it guards on
    ``mac != "N/A"`` only, so a host discovered without a MAC produced a live
    request to ``https://api.macvendors.com/unknown``.

    Two consequences, and the second is the one that matters:

    * a value the caller never validated decided the path of an outbound URL,
      and separators are stripped while ``/`` and ``?`` are not; and
    * every such lookup spent a real HTTPS round trip to be told nothing.

    The return value for a non-address is unchanged — callers received ``None``
    before and receive ``None`` now. What changes is that the request is no
    longer made.

    There are two other MAC normalizers in this codebase and neither fits here.
    ``core.utils.normalize_mac`` and ``core.topology.identity.normalize_mac``
    both require exactly 48 bits and both return a colon-delimited string; this
    module is indexed on 24-bit prefixes and needs the compact form to build a
    cache key and a URL. Keeping the rule local also keeps a leaf primitive —
    imported by discovery, the orchestrator, ``core.tasks`` and the device
    classifier — from depending on the topology package.
    """
    if not value:
        return None

    compact = _MAC_SEPARATORS.sub("", str(value).lower())
    if len(compact) not in _VALID_MAC_HEX_LENGTHS:
        return None
    if not _HEX_ONLY.match(compact):
        return None
    return compact


class OUIDatabase:
    """
    Lazy-loaded OUI database for MAC address vendor lookup.

    Usage::
        db = OUIDatabase()
        vendor = db.lookup("00:1A:2B")  # Returns vendor name or None
    """

    def __init__(
        self,
        db_path: str | None = None,
        cache_path: str | None = None,
        api_url: str | None = None,
    ):
        """Initialize OUI database. Loads on first lookup."""
        if db_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            backend_dir = os.path.dirname(current_dir)
            possible_paths = [
                os.path.join(current_dir, "manuf.txt"),
                os.path.join(backend_dir, "manuf.txt"),
                os.path.join(backend_dir, "data", "manuf.txt"),
                os.path.join(backend_dir, "db", "manuf.txt"),
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    db_path = path
                    break

        self.db_path = db_path
        self.cache_path = cache_path or os.environ.get(
            "MAC_VENDOR_CACHE_PATH", DEFAULT_VENDOR_CACHE_FILE
        )
        self.api_url = api_url or DEFAULT_VENDOR_API_URL
        self._database: dict[str, str] = {}
        self._cache: dict[str, str] = {}
        self._loaded = False
        self._cache_lock = threading.Lock()
        self._pending_fetches = set()
        self._executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="oui-fallback"
        )
        self._load_cache()

    def _load(self):
        """Load OUI database from file."""
        if self._loaded:
            return

        if not self.db_path or not os.path.exists(self.db_path):
            log.warning(
                "OUI database not found at %s. Vendor lookup disabled.", self.db_path
            )
            self._loaded = True
            return

        try:
            with open(self.db_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Support tab separation (Assignment \t ShortName \t FullName)
                    parts = [p.strip() for p in line.split("\t") if p.strip()]
                    if not parts:
                        continue

                    oui_str = parts[0]
                    # Normalize MAC Prefix (strip colons, hyphens, spaces)
                    oui_normalized = (
                        oui_str.replace(":", "")
                        .replace("-", "")
                        .replace(" ", "")
                        .lower()
                    )

                    if len(oui_normalized) >= 6:
                        oui_normalized = oui_normalized[:6]

                        # Grab full vendor name (last column) if available, else short name
                        if len(parts) >= 3:
                            vendor = parts[2]
                        elif len(parts) >= 2:
                            vendor = parts[1]
                        else:
                            continue

                        self._database[oui_normalized] = vendor

            log.info("OUI database loaded: %d entries", len(self._database))
        except Exception as e:
            log.error("Failed to load OUI database: %s", e)
        finally:
            self._loaded = True

    def _load_cache(self):
        """Placeholder for disk cache load (disabled in favor of PostgreSQL cache)."""

    def _save_cache(self):
        """Placeholder for disk cache save (disabled in favor of PostgreSQL cache)."""

    def _normalize_mac(self, mac_address: str) -> str | None:
        """Validate and compact ``mac_address``; None when it is not an address.

        See ``_normalize_mac_address`` for why this rejects rather than merely
        shortens. Kept as a method because ``lookup``, ``lookup_sync`` and
        ``_schedule_api_fetch`` all route through it, so the three entry points
        into the vendor API are gated by one check.
        """
        return _normalize_mac_address(mac_address)

    def _query_vendor_api(self, mac_address: str) -> str | None:
        if not self.api_url:
            return None

        # Re-validated here rather than trusted from the caller. This is the
        # only function that turns a scanned value into an outbound URL, so it
        # is where the guarantee has to hold: every current caller normalizes
        # first, but that is a property of today's call graph, not of this
        # function, and a future caller reaching it directly would otherwise
        # reopen the hole. Cheap enough to do twice.
        mac_clean = _normalize_mac_address(mac_address)
        if not mac_clean:
            log.debug(
                "Refusing vendor API request: %r is not a MAC address", mac_address
            )
            return None

        url = self.api_url.rstrip("/") + "/" + mac_clean
        try:
            response = requests.get(url, timeout=2.0)
            if response.status_code != 200:
                return None

            vendor = response.text.strip()
            if not vendor or vendor.lower().startswith("not found"):
                return None

            return vendor
        except requests.RequestException as exc:
            log.debug("Vendor API request failed for %s: %s", mac_address, exc)
            return None

    def _fetch_and_cache(self, mac_address: str) -> None:
        try:
            vendor = self._query_vendor_api(mac_address)
            if not vendor:
                return

            oui = mac_address[:6]
            try:
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
                    log.info(
                        "Cached background vendor lookup to DB for OUI %s -> %s",
                        oui,
                        vendor,
                    )
                finally:
                    db.close()
            except Exception as e:
                log.warning("Failed to save background vendor to DB cache: %s", e)
        finally:
            with self._cache_lock:
                self._pending_fetches.discard(mac_address)

    def _schedule_api_fetch(self, mac_address: str) -> None:
        # Check database cache first to avoid scheduling redundant calls
        mac_clean = self._normalize_mac(mac_address)
        if not mac_clean:
            return

        oui = mac_clean[:6]
        try:
            from db.base import SessionLocal
            from db.models import MacVendorCache

            db = SessionLocal()
            try:
                cached_entry = (
                    db.query(MacVendorCache)
                    .filter(MacVendorCache.mac_prefix == oui)
                    .first()
                )
                if cached_entry:
                    return
            finally:
                db.close()
        except Exception:
            pass

        with self._cache_lock:
            if mac_clean in self._pending_fetches:
                return
            self._pending_fetches.add(mac_clean)

        try:
            self._executor.submit(self._fetch_and_cache, mac_clean)
        except Exception as exc:
            log.debug("Failed to schedule vendor API fetch for %s: %s", mac_clean, exc)
            with self._cache_lock:
                self._pending_fetches.discard(mac_clean)

    def lookup(self, mac_address: str) -> str | None:
        """
        Look up vendor name for a MAC address.

        Args:
            mac_address: MAC address in any of the accepted forms — colon,
                hyphen or Cisco dot separated, or bare hex; a 24-bit OUI prefix
                ("00:1A:2B"), a 48-bit EUI-48 or a 64-bit EUI-64. Anything else
                returns None without a lookup.

        Returns:
            Vendor name or None if not found
        """
        if not self._loaded:
            self._load()

        if not mac_address:
            return None

        mac_clean = self._normalize_mac(mac_address)
        if not mac_clean:
            return None

        oui = mac_clean[:6]

        # 1. Primary path: Local offline file registry
        vendor = self._database.get(oui)
        if vendor:
            return vendor

        # 2. Secondary path: Shared database cache table
        try:
            from db.base import SessionLocal
            from db.models import MacVendorCache

            db = SessionLocal()
            try:
                cached_entry = (
                    db.query(MacVendorCache)
                    .filter(MacVendorCache.mac_prefix == oui)
                    .first()
                )
                if cached_entry:
                    return cached_entry.vendor_name
            finally:
                db.close()
        except Exception as e:
            log.warning("Database OUI cache lookup failed: %s", e)

        # 3. Tertiary path: Schedule async web request to fetch and save to cache
        self._schedule_api_fetch(mac_clean)
        return None

    def lookup_sync(self, mac_address: str) -> str | None:
        """Synchronous vendor lookup using API fallback."""
        vendor = self.lookup(mac_address)
        if vendor:
            return vendor

        mac_clean = self._normalize_mac(mac_address)
        if not mac_clean:
            return None

        # Fetch directly from API
        vendor = self._query_vendor_api(mac_clean)
        if vendor:
            oui = mac_clean[:6]
            try:
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
            except Exception as e:
                log.warning("Failed to save vendor to DB cache synchronously: %s", e)

        return vendor


# Global OUI database instance
_oui_db: OUIDatabase | None = None


def get_oui_db() -> OUIDatabase:
    """Get or create global OUI database instance."""
    global _oui_db
    if _oui_db is None:
        _oui_db = OUIDatabase()
    return _oui_db


def lookup_vendor(mac_address: str) -> str | None:
    """
    Lookup vendor name for a MAC address.

    Args:
        mac_address: MAC address in format "XX:XX:XX:XX:XX:XX" or similar

    Returns:
        Vendor name or None if not found
    """
    if not mac_address:
        return None
    return get_oui_db().lookup(mac_address)


# =============================================================================
# OUI -> Device Category mapping (Priority 1 - C)
# =============================================================================

#: Maps a substring of a vendor name (lowercase) to a device category string.
VENDOR_DEVICE_MAP: dict[str, str] = {
    "cisco": "router",
    "juniper": "router",
    "ubiquiti": "wireless_ap",
    "mikrotik": "router",
    "fortinet": "firewall",
    "palo alto": "firewall",
    "aruba": "wireless_ap",
    "brother": "printer",
    "canon": "printer",
    "epson": "printer",
    "hp": "printer",
    "raspberry": "iot",
    "espressif": "iot",
    "siemens": "scada_ics",
    "schneider": "scada_ics",
    "honeywell": "scada_ics",
    "rockwell": "scada_ics",
    "yokogawa": "scada_ics",
    "beckhoff": "scada_ics",
    "omron": "scada_ics",
    "abb": "scada_ics",
    "wago": "scada_ics",
    "moxa": "scada_ics",
    "vmware": "virtual_machine",
    "xen": "virtual_machine",
    "hyper-v": "virtual_machine",
    "hyperv": "virtual_machine",
}


def classify_from_oui(vendor: str) -> str:
    """
    Classify a device category from an OUI vendor name string.

    Args:
        vendor: Vendor name returned by ``lookup_vendor()`` or similar.

    Returns:
        A snake_case device category string (e.g. ``"network_switch_router"``)
        or ``"unknown"`` when no keyword matches.
    """
    if not vendor:
        return "unknown"
    v = vendor.lower()
    for keyword, category in VENDOR_DEVICE_MAP.items():
        if keyword in v:
            return category
    return "unknown"


def classify_mac(mac_address: str) -> str:
    """
    Convenience wrapper: lookup vendor then classify device category.

    Args:
        mac_address: MAC address in any common format.

    Returns:
        Device category string or ``"unknown"``.
    """
    vendor = lookup_vendor(mac_address)
    return classify_from_oui(vendor or "")
