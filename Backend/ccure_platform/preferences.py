"""
ccure_platform/preferences.py — who owns which user preference.

``users.preferences`` is one JSONB document per account. The platform owns the
keys that describe the platform (theme, rows per page, sidebar, notification
channels, timezone) and validates them in ``identity/profile.py``. A product
owns its own preferences, and the platform must not have to know their names, so
a product's preferences live in a **namespaced block**:

    {"theme": "dark", …, "products": {"audit": {"default_scan_type": "asset"}}}

and the product tells the platform what its block looks like, once, at start-up:

    register_product_preferences("audit", AuditPreferences,
                                 legacy_flat_keys=("default_scan_type",))

``model`` is a Pydantic model whose fields all have defaults; it is the block's
schema and its validation. The platform stores and returns the block without
reading it.

**Compatibility.** Before this, Audit's one preference sat flat in the document
(``{"default_scan_type": "asset"}``) and in the API (``GET`` and ``PUT
/user/preferences``). ``legacy_flat_keys`` names those keys:

* **reading** — a stored flat key is the namespaced value when the block does not
  carry one; nothing is rewritten on read;
* **the API** — the response still carries each flat key, so a client that has
  never heard of ``products`` is unaffected, and a ``PUT`` that sends the flat
  key is accepted and validated exactly as before;
* **writing** — a value written through either form is stored in the namespaced
  block and the flat key it replaces is removed from the document in the same
  write: the value moves, it is not lost.

Where both forms arrive in one request (the settings drawer sends back the whole
document), the namespaced one wins.

No registration means no block: the platform behaves as if no product had any
preference. Registration happens when the API process loads (``main.py`` imports
the product's module); preferences are read and written only by the API.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

#: Top-level keys the platform itself owns; a product may not claim one.
PLATFORM_KEYS = frozenset(
    {
        "theme",
        "email_alerts",
        "in_app_alerts",
        "timezone",
        "sidebar_collapsed",
        "default_rows_per_page",
        "products",
    }
)


@dataclass(frozen=True)
class ProductPreferences:
    namespace: str
    model: type[BaseModel]
    legacy_flat_keys: tuple[str, ...] = ()

    @property
    def defaults(self) -> dict[str, Any]:
        return self.model().model_dump()


class UnknownProductPreferences(ValueError):
    """A request named a product namespace nobody registered."""


_registered: dict[str, ProductPreferences] = {}


def register_product_preferences(
    namespace: str,
    model: type[BaseModel],
    legacy_flat_keys: tuple[str, ...] = (),
) -> None:
    """Register a product's preference block. Registering the same one again is a no-op."""
    entry = ProductPreferences(namespace, model, tuple(legacy_flat_keys))
    existing = _registered.get(namespace)
    if existing is not None:
        if existing == entry:
            return
        raise ValueError(f"Preferences for {namespace!r} are already registered.")
    fields = set(model.model_fields)
    for key in entry.legacy_flat_keys:
        if key not in fields:
            raise ValueError(f"{key!r} is not a field of {model.__name__}.")
        if key in PLATFORM_KEYS:
            raise ValueError(f"{key!r} is a platform preference.")
        if any(key in other.legacy_flat_keys for other in _registered.values()):
            raise ValueError(f"{key!r} is already a legacy key of another product.")
    entry.defaults  # every field must have a default: fails here, not on a request
    _registered[namespace] = entry


def registered_namespaces() -> tuple[str, ...]:
    return tuple(_registered)


def _stored_block(stored: dict, reg: ProductPreferences) -> dict[str, Any]:
    """What the document holds for a product: its block, else its legacy flat keys."""
    block = dict(((stored.get("products") or {}).get(reg.namespace)) or {})
    for key in reg.legacy_flat_keys:
        if key not in block and key in stored:
            block[key] = stored[key]
    return {k: v for k, v in block.items() if k in reg.model.model_fields}


def product_blocks(stored: dict) -> dict[str, dict[str, Any]]:
    """Every registered product's effective block: defaults, overlaid by what is stored."""
    return {
        ns: {**reg.defaults, **_stored_block(stored, reg)}
        for ns, reg in _registered.items()
    }


def legacy_flat(blocks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The flat keys the API has always carried, read from the blocks."""
    return {
        key: blocks[ns][key]
        for ns, reg in _registered.items()
        for key in reg.legacy_flat_keys
    }


def apply_product_updates(
    stored: dict, products: dict | None, flat: dict | None
) -> dict[str, Any]:
    """
    Apply a request's product preferences to ``stored`` in place and return the
    changes, keyed ``products.<namespace>.<field>``.

    Raises ``UnknownProductPreferences`` for a namespace nobody registered and
    ``ValidationError`` (with the product's own message) for an invalid value.
    Only non-null values are applied, and only ones that differ from what the
    document stores.
    """
    incoming: dict[str, dict[str, Any]] = {}
    for ns, reg in _registered.items():
        for key in reg.legacy_flat_keys:
            if flat and flat.get(key) is not None:
                incoming.setdefault(ns, {})[key] = flat[key]
    for ns, block in (products or {}).items():
        reg = _registered.get(ns)
        if reg is None:
            raise UnknownProductPreferences(ns)
        for key, value in (block or {}).items():
            if value is not None and key in reg.model.model_fields:
                incoming.setdefault(ns, {})[key] = value

    changes: dict[str, Any] = {}
    for ns, update in incoming.items():
        reg = _registered[ns]
        current = _stored_block(stored, reg)
        # The product's own validation, over the whole effective block.
        reg.model.model_validate({**reg.defaults, **current, **update})
        block = stored.setdefault("products", {}).setdefault(ns, {})
        for key, value in update.items():
            if key in current and current[key] == value:
                continue
            block[key] = value
            changes[f"products.{ns}.{key}"] = value
            if key in reg.legacy_flat_keys:
                stored.pop(key, None)  # the value moved into the namespace
        if not block:
            stored["products"].pop(ns, None)
    if "products" in stored and not stored["products"]:
        del stored["products"]
    return changes


__all__ = (
    "PLATFORM_KEYS",
    "ProductPreferences",
    "UnknownProductPreferences",
    "ValidationError",
    "apply_product_updates",
    "legacy_flat",
    "product_blocks",
    "register_product_preferences",
    "registered_namespaces",
)
