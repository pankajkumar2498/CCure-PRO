"""
core/oui_lookup.py
------------------
IEEE OUI (Organizationally Unique Identifier) database lookup for MAC address vendor resolution.

The OUI database maps 24-bit MAC address prefixes to vendor names.
Example: 00:1A:2B -> "Company Name"

Data source: IEEE (www.ieee.org/oui)
Format: hex OUI (6 chars) tab Org Name
"""

import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict

import requests

log = logging.getLogger("ccure.oui")

DEFAULT_VENDOR_API_URL = os.environ.get("MAC_VENDOR_API_URL", "https://api.macvendors.com/")
DEFAULT_VENDOR_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor_cache.json")


class OUIDatabase:
    """
    Lazy-loaded OUI database for MAC address vendor lookup.

    Usage::
        db = OUIDatabase()
        vendor = db.lookup("00:1A:2B")  # Returns vendor name or None
    """

    def __init__(self, db_path: Optional[str] = None, cache_path: Optional[str] = None, api_url: Optional[str] = None):
        """Initialize OUI database. Loads on first lookup."""
        if db_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            backend_dir = os.path.dirname(current_dir)
            possible_paths = [
                os.path.join(current_dir, "manuf.txt"),
                os.path.join(backend_dir, "manuf.txt"),
                os.path.join(backend_dir, "data", "manuf.txt"),
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    db_path = path
                    break

        self.db_path = db_path
        self.cache_path = cache_path or os.environ.get("MAC_VENDOR_CACHE_PATH", DEFAULT_VENDOR_CACHE_FILE)
        self.api_url = api_url or DEFAULT_VENDOR_API_URL
        self._database: Dict[str, str] = {}
        self._cache: Dict[str, str] = {}
        self._loaded = False
        self._cache_lock = threading.Lock()
        self._pending_fetches = set()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="oui-fallback")
        self._load_cache()

    def _load(self):
        """Load OUI database from file."""
        if self._loaded:
            return

        if not self.db_path or not os.path.exists(self.db_path):
            log.warning("OUI database not found at %s. Vendor lookup disabled.", self.db_path)
            self._loaded = True
            return

        try:
            with open(self.db_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split('\t', 1)
                    if len(parts) < 2:
                        continue

                    oui_str = parts[0].strip()
                    vendor = parts[1].strip()
                    oui_normalized = oui_str.replace('-', '').replace(' ', '').lower()

                    if len(oui_normalized) >= 6:
                        oui_normalized = oui_normalized[:6]
                        self._database[oui_normalized] = vendor

            log.info("OUI database loaded: %d entries", len(self._database))
        except Exception as e:
            log.error("Failed to load OUI database: %s", e)
        finally:
            self._loaded = True

    def _load_cache(self):
        """Load cached vendor lookups from disk."""
        if not self.cache_path:
            return

        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    if isinstance(cache_data, dict):
                        with self._cache_lock:
                            self._cache = {k.lower(): str(v) for k, v in cache_data.items()}
                log.info("Vendor cache loaded: %d entries", len(self._cache))
        except Exception as e:
            log.warning("Failed to load vendor cache %s: %s", self.cache_path, e)

    def _save_cache(self):
        """Save cached vendor lookups to disk."""
        if not self.cache_path:
            return

        try:
            with self._cache_lock:
                cache_data = dict(self._cache)
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            log.warning("Failed to save vendor cache %s: %s", self.cache_path, e)

    def _normalize_mac(self, mac_address: str) -> Optional[str]:
        if not mac_address:
            return None
        mac_clean = mac_address.lower().replace(':', '').replace('-', '').replace('.', '')
        return mac_clean if len(mac_clean) >= 6 else None

    def _query_vendor_api(self, mac_address: str) -> Optional[str]:
        if not self.api_url:
            return None

        url = self.api_url.rstrip('/') + '/' + mac_address
        try:
            response = requests.get(url, timeout=5)
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

            with self._cache_lock:
                self._cache[mac_address] = vendor
            self._save_cache()
            log.info("Cached vendor lookup for %s -> %s", mac_address, vendor)
        finally:
            with self._cache_lock:
                self._pending_fetches.discard(mac_address)

    def _schedule_api_fetch(self, mac_address: str) -> None:
        with self._cache_lock:
            if mac_address in self._pending_fetches or mac_address in self._cache:
                return
            self._pending_fetches.add(mac_address)

        try:
            self._executor.submit(self._fetch_and_cache, mac_address)
        except Exception as exc:
            log.debug("Failed to schedule vendor API fetch for %s: %s", mac_address, exc)
            with self._cache_lock:
                self._pending_fetches.discard(mac_address)

    def lookup(self, mac_address: str) -> Optional[str]:
        """
        Look up vendor name for a MAC address.

        Args:
            mac_address: MAC address in format "XX:XX:XX:XX:XX:XX" or "XXXXXXXXXX"

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
        vendor = self._database.get(oui)
        if vendor:
            return vendor

        with self._cache_lock:
            vendor = self._cache.get(mac_clean)
        if vendor:
            return vendor

        self._schedule_api_fetch(mac_clean)
        return None

    def lookup_sync(self, mac_address: str) -> Optional[str]:
        """Synchronous vendor lookup using API fallback for tests or one-off queries."""
        vendor = self.lookup(mac_address)
        if vendor:
            return vendor

        mac_clean = self._normalize_mac(mac_address)
        if not mac_clean:
            return None

        vendor = self._query_vendor_api(mac_clean)
        if vendor:
            with self._cache_lock:
                self._cache[mac_clean] = vendor
            self._save_cache()
        return vendor


# Global OUI database instance
_oui_db: Optional[OUIDatabase] = None


def get_oui_db() -> OUIDatabase:
    """Get or create global OUI database instance."""
    global _oui_db
    if _oui_db is None:
        _oui_db = OUIDatabase()
    return _oui_db


def lookup_vendor(mac_address: str) -> Optional[str]:
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
VENDOR_DEVICE_MAP: Dict[str, str] = {
    "cisco":       "network_switch_router",
    "juniper":     "network_router_firewall",
    "ubiquiti":    "wireless_access_point",
    "mikrotik":    "network_router",
    "fortinet":    "firewall",
    "palo alto":   "firewall",
    "aruba":       "wireless_access_point",
    "brother":     "printer",
    "canon":       "printer",
    "epson":       "printer",
    "hp":          "printer_or_server",
    "raspberry":   "iot_device",
    "espressif":   "iot_device",
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
