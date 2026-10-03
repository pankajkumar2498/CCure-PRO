"""
ccure_platform/rbac/authority.py — RBAC-4: letting the new engine decide, per path.

RBAC-3 compared the new engine with the legacy check and discarded the answer. This
module is the controlled cutover: for a *migrated path* — one the migration inventory
(``data/rbac/authorization_migration_inventory.json``) marks ``migrated`` and the
operator has switched on — the new engine's decision is the one the guard enforces.

A **path** is the unit that is switched and rolled back: a legacy atom
(``module:read``) or a permission key (``platform.email_domain.read``).

Rules, each tested:

1. **Off by default, free when off.** ``RBAC_AUTHORITY_MODE`` is ``off`` unless exactly
   ``enforce``; with it off, or the path not listed in ``RBAC_AUTHORITY_PATHS``, the
   legacy decision stands and nothing is queried.
2. **Only inventory-migrated paths.** Configuration cannot switch on a path the
   inventory defers (scope, hierarchy, org switching ...).
3. **The new engine decides when it can answer.** MATCH or MISMATCH: the new decision
   wins (a divergence is recorded). That is what makes permission removal immediate.
4. **When it cannot answer, legacy decides, and the fact is recorded.** A principal with
   no RBAC assignment (never provisioned), an unsynced catalogue, a scope-driven denial
   or an evaluator error fall back to the legacy decision, so enabling a path never
   locks out an account nobody has provisioned. A principal that *had* a role and lost
   it is not "unprovisioned": the new model denies.
5. **No role name is an input.** The engine is handed grants; the legacy fallback is
   the existing legacy rule, untouched.
6. **Shadow mode still works**: the legacy guard still calls the RBAC-3 observer.
7. **Rollback** is configuration: remove the path (or set the mode ``off``). No data,
   no schema, no code change.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import resolver, shadow

logger = logging.getLogger("ccure.rbac.authority")

MODE_OFF, MODE_ENFORCE = "off", "enforce"
INVENTORY_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "rbac"
    / "authorization_migration_inventory.json"
)

SOURCE_NEW, SOURCE_LEGACY = "new", "legacy"

_lock = threading.Lock()
_migrated: frozenset[str] | None = None
_rolled_back: set[str] = set()


@dataclass(frozen=True, slots=True)
class Outcome:
    allowed: bool
    source: str  # new | legacy
    path: str
    reason: str = ""
    diverged: bool = False


# ── configuration and inventory ───────────────────────────────────────────────


def _config():
    from config import AppConfig

    return AppConfig


def mode() -> str:
    raw = (getattr(_config(), "RBAC_AUTHORITY_MODE", MODE_OFF) or MODE_OFF).strip()
    return MODE_ENFORCE if raw.lower() == MODE_ENFORCE else MODE_OFF


def migrated_paths() -> frozenset[str]:
    """Path ids the inventory marks ``migrated`` (read once per process)."""
    global _migrated
    with _lock:
        if _migrated is None:
            try:
                data = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
                _migrated = frozenset(
                    s["path_id"]
                    for s in data["sites"]
                    if s.get("status") == "migrated" and s.get("path_id")
                )
            except (OSError, ValueError, KeyError):
                logger.error("RBAC migration inventory unreadable; authority stays off")
                return frozenset()
        return _migrated


def set_migrated_paths(paths) -> None:
    """Install (or with None, clear) the migrated set. Tests only."""
    global _migrated
    with _lock:
        _migrated = None if paths is None else frozenset(paths)


def configured_paths() -> frozenset[str]:
    raw = (getattr(_config(), "RBAC_AUTHORITY_PATHS", "") or "").strip()
    if not raw:
        return frozenset()
    if raw == "*":
        return migrated_paths()
    wanted = {p.strip() for p in raw.split(",") if p.strip()}
    return frozenset(wanted & migrated_paths())


def enabled_for(path: str) -> bool:
    """Whether ``path`` is decided by the new engine right now."""
    if mode() != MODE_ENFORCE or path in _rolled_back:
        return False
    return path in configured_paths()


def roll_back(path: str) -> None:
    """Return one path to legacy in this process (an operator switch for tests and
    emergencies; the durable form is the configuration)."""
    _rolled_back.add(path)


def restore(path: str | None = None) -> None:
    if path is None:
        _rolled_back.clear()
    else:
        _rolled_back.discard(path)


# ── recorder ──────────────────────────────────────────────────────────────────


class AuthorityRecorder:
    """Per-path counts of who decided, so a cutover is observable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counts: Counter = Counter()
        self.divergences: list[dict] = []

    def record(self, o: Outcome) -> None:
        with self._lock:
            self.counts[(o.path, o.source)] += 1
            if o.diverged:
                self.divergences.append(
                    {"path": o.path, "allowed": o.allowed, "reason": o.reason}
                )
                del self.divergences[:-200]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "by_path": {f"{p}|{s}": n for (p, s), n in sorted(self.counts.items())},
                "divergences": list(self.divergences),
            }

    def reset(self) -> None:
        with self._lock:
            self.counts.clear()
            self.divergences.clear()


recorder = AuthorityRecorder()


# ── deciding ──────────────────────────────────────────────────────────────────


def _legacy(path: str, allowed: bool, reason: str) -> Outcome:
    return Outcome(bool(allowed), SOURCE_LEGACY, path, reason)


def _from_comparison(
    path: str, legacy_allowed: bool, r: shadow.ShadowResult
) -> Outcome:
    if r.kind in (shadow.MATCH, shadow.MISMATCH) and r.new_decision is not None:
        return Outcome(
            bool(r.new_decision),
            SOURCE_NEW,
            path,
            r.classification,
            diverged=r.kind == shadow.MISMATCH,
        )
    return _legacy(path, legacy_allowed, f"fallback:{r.classification}")


def decide_atom(
    db,
    user,
    resource: str,
    action: str,
    legacy_allowed: bool,
    *,
    operation=None,
    org_id: str | None = None,
) -> Outcome:
    """The decision for a legacy ``resource:action`` check. Never raises: anything
    unexpected is a legacy decision."""
    path = f"{resource}:{action}"
    if not enabled_for(path):
        return _legacy(path, legacy_allowed, "authority_off")
    try:
        scope = None
        if org_id is not None:
            # RBAC-5: the check is about one organisation. The legacy answer for it
            # is the atom *and* the legacy reach into another organisation.
            from ccure_platform.rbac.legacy_scope import (
                legacy_acts_across_organisations,
            )

            if str(org_id) != str(getattr(user, "org_id", "")):
                legacy_allowed = bool(
                    legacy_allowed
                ) and legacy_acts_across_organisations(user)
            scope = c.ScopeContext(requested_org_id=str(org_id))
        r = shadow.shadow_compare(
            db,
            user,
            resource,
            action,
            bool(legacy_allowed),
            scope=scope,
            operation=operation,
            scope_aware=org_id is not None,
        )
        out = _from_comparison(path, legacy_allowed, r)
    except Exception:  # noqa: BLE001 - fall back to the legacy authority
        logger.warning(
            "RBAC authority failed for %s; legacy decides", path, exc_info=True
        )
        out = _legacy(path, legacy_allowed, "fallback:evaluator_error")
    recorder.record(out)
    return out


def decide_key(db, user, key: str, legacy_allowed: bool, *, operation=None) -> Outcome:
    """The decision for a permission *key* that replaced a role-name check."""
    if not enabled_for(key):
        return _legacy(key, legacy_allowed, "authority_off")
    try:
        entry = shadow.MappingEntry(atom=f"key:{key}", status="mapped", keys=(key,))
        principal = resolver.principal_for_user(user)
        with db.begin_nested():
            catalogue = resolver.load_catalogue(db)
            info = resolver.assignment_summary(db, principal)
            grants = resolver.resolve_grants(db, principal)
        assignments = tuple(
            shadow.RoleInfo(
                role_key=i.role_key,
                role_state=i.role_state,
                scope_type=i.scope_type,
                scope_org_id=i.scope_org_id,
                live=i.live,
            )
            for i in info
        )
        r = shadow.compare_decision(
            principal,
            grants,
            catalogue,
            assignments,
            entry,
            legacy_atom=f"key:{key}",
            legacy_allowed=legacy_allowed,
            scope=c.ScopeContext(),
            operation=operation,
        )
        out = _from_comparison(key, legacy_allowed, r)
    except Exception:  # noqa: BLE001
        logger.warning(
            "RBAC authority failed for %s; legacy decides", key, exc_info=True
        )
        out = _legacy(key, legacy_allowed, "fallback:evaluator_error")
    recorder.record(out)
    return out


def legacy_roles_for_key(key: str) -> tuple[str, ...]:
    """The legacy role names a replaced key's guard falls back to: those whose
    new-model role the golden mapping grants ``key``. Empty for an unknown key."""
    from ccure_platform.rbac import legacy_map

    golden = legacy_map.load_golden()
    if key not in {p["key"] for p in golden["permissions"]}:
        return ()
    # a role that holds everything is recorded as a marker string, not a list
    holders = {
        k
        for k, grants in golden["role_grants"].items()
        if isinstance(grants, str) or key in grants
    }
    return tuple(
        sorted(r["legacy_role"] for r in golden["roles"] if r["role_key"] in holders)
    )


#: Keys whose legacy rule was an inline "superadmin only" check on top of (or instead
#: of) a permission atom, so their fallback stays the role-name rule rather than the
#: atom (RBAC-7): an atom a custom legacy role could hold must not widen them.
LEGACY_ROLE_NAME_ONLY_KEYS = frozenset(
    {"platform.organization.archive", "platform.audit_log.retention"}
)


def legacy_atoms_for_key(key: str) -> tuple[tuple[str, str], ...]:
    """The legacy ``(resource, action)`` atoms that were the same capability as the
    permission ``key`` — read from the golden mapping, so nothing is copied. Empty
    for a key that never had an atom (or whose legacy rule was role-name only)."""
    if key in LEGACY_ROLE_NAME_ONLY_KEYS:
        return ()
    from ccure_platform.rbac import legacy_map

    out = []
    for entry in legacy_map.load_golden()["atoms"]:
        if entry["status"] in ("mapped", "replaced") and key in entry["new_keys"]:
            resource, _, action = entry["atom"].partition(":")
            out.append((resource, action))
    return tuple(sorted(out))
