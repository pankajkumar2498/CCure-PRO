"""
ccure_audit/preferences.py — Audit's user preferences.

Audit owns ``default_scan_type``: the scan type the settings drawer's "Scan
Defaults" section offers. It used to sit in the platform's preference document
and in ``ccure_platform/identity/profile.py``'s schema; the platform no longer
knows it. The platform stores the block under ``products.audit`` and asks this
model to validate it (``ccure_platform/preferences.py``).

The allowed values and the error message are the ones the platform's schema had.
The legacy flat key stays accepted and returned by ``/user/preferences`` for
clients that predate the namespaced block.

Registered at import; ``main.py`` imports this module.
"""

from __future__ import annotations

from ccure_platform.api import register_product_preferences
from pydantic import BaseModel, field_validator

SCAN_TYPES = (
    "host-discovery",
    "asset",
    "vulnerability_audit",
    "advanced",
    "credentialed",
)


class AuditPreferences(BaseModel):
    default_scan_type: str = "asset"

    @field_validator("default_scan_type")
    @classmethod
    def validate_scan_type(cls, v):
        if v is not None and v not in list(SCAN_TYPES):
            raise ValueError(f"Scan type must be one of {list(SCAN_TYPES)}")
        return v


register_product_preferences(
    "audit", AuditPreferences, legacy_flat_keys=("default_scan_type",)
)
