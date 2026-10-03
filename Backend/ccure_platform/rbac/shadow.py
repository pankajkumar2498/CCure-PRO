"""
ccure_platform/rbac/shadow.py — comparing the new decision with the legacy one.

RBAC-3 (shadow authorization). The migration (RBAC-0 §12) runs the new engine
**beside** the old one, compares, and only cuts over when they agree everywhere.
This file is the comparison. ``shadow_runtime.py`` decides *whether* to run it
(a flag, default OFF) and hooks it to the legacy check; nothing here touches a
request.

**RBAC-3 = SHADOW ONLY. LEGACY AUTHORIZATION = AUTHORITATIVE.** The comparison
takes the legacy verdict as an argument and returns a *result about it*. It has no
way to change what the caller does, and the result is a ``ShadowResult`` — not a
boolean — so it cannot be mistaken for the answer.

Four kinds of result, and the distinction between them is the point:

``MATCH``
    Both sides answered and agree (``allow_both`` / ``deny_both``).
``MISMATCH``
    Both sides answered and disagree: ``new_denies_legacy_allows`` or
    ``new_allows_legacy_denies``. Always diagnosable — the principal, organisation,
    legacy atom, mapped keys, both decisions, each key's reason, the principal's
    role assignments and the operation are in the result.
``NOT_COMPARABLE``
    One side cannot answer *by design*, so counting it as match or mismatch would
    be a lie in either direction (**unknown ≠ match, unassessed ≠ pass**):
    ``retired_atom``, ``unmapped_atom``, ``scope_deferred``,
    ``principal_not_provisioned``, ``catalogue_not_populated``,
    ``role_name_check``.
``ERROR``
    The comparison itself failed (``evaluator_error``, ``mapping_unavailable``,
    ``mapping_drift``). Recorded, never raised: a shadow error cannot deny or grant.

The mapping is **the RBAC-2 golden mapping** (``Backend/data/rbac/
golden_legacy_mapping.json``), read through ``legacy_map`` — not a second mapping
system. A legacy atom may map to several new keys (a split): the new decision is
ALLOW only if **every** key it maps to is allowed. Several atoms may map to one key
(a merge): each atom is compared on its own.

**Permission and scope are kept separate; RBAC-5 is not solved here.** A legacy
permission check carries no organisation, so the comparison is *at the principal's
own organisation*. Anything that depends on the deferred cross-organisation model
(a resource in another organisation, a denial that is scope-driven) is
``NOT_COMPARABLE``/``scope_deferred`` — recorded with both decisions for diagnosis,
never forced into match or mismatch.

**No secret can appear in a result**, by construction: its fields are identifiers
(principal, organisation, role keys), the legacy atom, the mapped keys, the two
decisions, reasons and a route *template* — never a password, token, cookie, MFA
secret, header, query string or body, none of which it has a field for.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Iterable, Mapping

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import engine, resolver
from sqlalchemy.orm import Session

logger = logging.getLogger("ccure.rbac.shadow")

# ── result kinds ──────────────────────────────────────────────────────────────

MATCH = "match"
MISMATCH = "mismatch"
NOT_COMPARABLE = "not_comparable"
ERROR = "error"
KINDS = (MATCH, MISMATCH, NOT_COMPARABLE, ERROR)

# ── classifications ───────────────────────────────────────────────────────────

ALLOW_BOTH = "allow_both"
DENY_BOTH = "deny_both"
NEW_DENIES = "new_denies_legacy_allows"
NEW_ALLOWS = "new_allows_legacy_denies"

RETIRED_ATOM = "retired_atom"
UNMAPPED_ATOM = "unmapped_atom"
SCOPE_DEFERRED = "scope_deferred"
PRINCIPAL_NOT_PROVISIONED = "principal_not_provisioned"
CATALOGUE_NOT_POPULATED = "catalogue_not_populated"
ROLE_NAME_CHECK = "role_name_check"

EVALUATOR_ERROR = "evaluator_error"
MAPPING_UNAVAILABLE = "mapping_unavailable"
MAPPING_DRIFT = "mapping_drift"

CLASSIFICATIONS: Mapping[str, tuple[str, ...]] = {
    MATCH: (ALLOW_BOTH, DENY_BOTH),
    MISMATCH: (NEW_DENIES, NEW_ALLOWS),
    NOT_COMPARABLE: (
        RETIRED_ATOM,
        UNMAPPED_ATOM,
        SCOPE_DEFERRED,
        PRINCIPAL_NOT_PROVISIONED,
        CATALOGUE_NOT_POPULATED,
        ROLE_NAME_CHECK,
    ),
    ERROR: (EVALUATOR_ERROR, MAPPING_UNAVAILABLE, MAPPING_DRIFT),
}

#: Engine denial reasons that are about *where*, not *what*. A legacy check has no
#: organisation, so a new denial for one of these is the deferred scope model
#: speaking, not a permission disagreement.
SCOPE_REASONS = frozenset({c.CROSS_ORG, c.NO_TARGET_ORG, c.ORG_SWITCH_REQUIRED})


# ── the golden mapping, indexed ───────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class MappingEntry:
    atom: str
    status: str  # mapped | replaced | retired
    keys: tuple[str, ...]


class MappingUnavailable(RuntimeError):
    """The golden mapping cannot be read. Never raised past the comparison: it
    becomes an ``ERROR`` result."""


_golden_lock = threading.Lock()
_golden_index: dict[str, MappingEntry] | None = None


def index_golden(golden: Mapping) -> dict[str, MappingEntry]:
    """``{legacy atom: entry}`` from a golden mapping (as ``legacy_map.load_golden``
    returns it)."""
    try:
        return {
            a["atom"]: MappingEntry(
                atom=a["atom"], status=a["status"], keys=tuple(a["new_keys"])
            )
            for a in golden["atoms"]
        }
    except (KeyError, TypeError) as exc:
        raise MappingUnavailable(f"golden mapping is malformed: {exc!r}") from exc


def golden_index() -> dict[str, MappingEntry]:
    """The indexed golden mapping, read once per process. A file that cannot be
    read raises ``MappingUnavailable`` (and is retried on the next call)."""
    global _golden_index
    with _golden_lock:
        if _golden_index is None:
            from ccure_platform.rbac import legacy_map

            try:
                _golden_index = index_golden(legacy_map.load_golden())
            except legacy_map.GoldenError as exc:
                raise MappingUnavailable(str(exc)) from exc
        return _golden_index


def set_golden_index(index: dict[str, MappingEntry] | None) -> None:
    """Install (or, with None, clear) the indexed mapping. For tests."""
    global _golden_index
    with _golden_lock:
        _golden_index = index


# ── the result ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class KeyDecision:
    key: str
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class RoleInfo:
    """One of the principal's new-model assignments: the role's key and state (never
    a display name), where it applies, and whether it is live."""

    role_key: str
    role_state: str
    scope_type: str
    scope_org_id: str | None
    live: bool


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True, kw_only=True)
class ShadowResult:
    kind: str
    classification: str
    reason: str = ""
    # who and where
    principal_id: str = ""
    principal_kind: str = "human"
    org_id: str | None = None
    #: The legacy role's label, for diagnosis only. Never a decision input: the new
    #: decision is the same whatever this says.
    legacy_role: str | None = None
    new_roles: tuple[RoleInfo, ...] = ()
    # what was asked
    legacy_atom: str | None = None
    mapping_status: str | None = None
    mapped_keys: tuple[str, ...] = ()
    #: The role names a ``require_role`` check named (a role-name check has no
    #: permission to map; it is evidence for RBAC-4).
    required_roles: tuple[str, ...] = ()
    # the two answers
    legacy_decision: bool | None = None
    new_decision: bool | None = None
    key_decisions: tuple[KeyDecision, ...] = ()
    # scope and place
    scope_requested_org: str | None = None
    scope_resource_org: str | None = None
    #: ``METHOD route-template``, where available. Never a raw path or a query.
    operation: str | None = None
    duration_ms: float | None = None
    at: str = field(default_factory=_now)

    @property
    def is_match(self) -> bool:
        return self.kind == MATCH

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "classification": self.classification,
            "reason": self.reason,
            "principal_id": self.principal_id,
            "principal_kind": self.principal_kind,
            "org_id": self.org_id,
            "legacy_role": self.legacy_role,
            "new_roles": [
                [r.role_key, r.role_state, r.scope_type, r.scope_org_id, r.live]
                for r in self.new_roles
            ],
            "legacy_atom": self.legacy_atom,
            "mapping_status": self.mapping_status,
            "mapped_keys": list(self.mapped_keys),
            "required_roles": list(self.required_roles),
            "legacy_decision": self.legacy_decision,
            "new_decision": self.new_decision,
            "key_decisions": [[k.key, k.allowed, k.reason] for k in self.key_decisions],
            "scope_requested_org": self.scope_requested_org,
            "scope_resource_org": self.scope_resource_org,
            "operation": self.operation,
            "duration_ms": self.duration_ms,
            "at": self.at,
        }

    def log_fields(self) -> dict[str, str]:
        """The fields a log line carries: scalars only, whitespace folded, length
        capped — so a value cannot forge a second log line."""

        def clean(value) -> str:
            text = "-" if value is None else str(value)
            return re.sub(r"\s+", "_", text)[:160]

        return {
            "kind": clean(self.kind),
            "class": clean(self.classification),
            "reason": clean(self.reason),
            "principal": clean(self.principal_id),
            "org": clean(self.org_id),
            "atom": clean(self.legacy_atom),
            "status": clean(self.mapping_status),
            "keys": clean(",".join(self.mapped_keys)),
            "legacy": clean(self.legacy_decision),
            "new": clean(self.new_decision),
            "decisions": clean(
                ",".join(
                    f"{k.key}={'allow' if k.allowed else k.reason}"
                    for k in self.key_decisions
                )
            ),
            "roles": clean(
                ",".join(
                    f"{r.role_key}:{r.role_state}:{'live' if r.live else 'not_live'}"
                    for r in self.new_roles
                )
            ),
            "legacy_role": clean(self.legacy_role),
            "required_roles": clean(",".join(self.required_roles)),
            "scope_org": clean(self.scope_requested_org or self.scope_resource_org),
            "op": clean(self.operation),
            "ms": clean(self.duration_ms),
        }


# ── the comparison (pure) ─────────────────────────────────────────────────────


def _legacy_role_label(user) -> str | None:
    try:
        label = getattr(getattr(user, "role", None), "name", None)
    except Exception:  # noqa: BLE001 - a lazy load must never matter here
        return None
    return str(label) if label else None


def compare_decision(
    principal: c.Principal,
    grants: Iterable[c.Grant],
    catalogue: Mapping[str, c.Permission],
    assignments: tuple[RoleInfo, ...],
    entry: MappingEntry | None,
    *,
    legacy_atom: str,
    legacy_allowed: bool,
    scope: c.ScopeContext | None = None,
    operation: str | None = None,
    legacy_role: str | None = None,
) -> ShadowResult:
    """
    Compare the new engine's answer with the legacy one. Pure: everything arrives as
    an argument, so it needs no database and can be tested as a truth table.
    """
    scope = scope or c.ScopeContext()
    base = dict(
        principal_id=principal.principal_id,
        principal_kind=principal.kind,
        org_id=principal.home_org_id,
        legacy_role=legacy_role,
        new_roles=assignments,
        legacy_atom=legacy_atom,
        legacy_decision=bool(legacy_allowed),
        scope_requested_org=scope.requested_org_id,
        scope_resource_org=scope.resource_org_id,
        operation=operation,
    )

    def result(kind, classification, reason="", **extra):
        return ShadowResult(
            kind=kind, classification=classification, reason=reason, **{**base, **extra}
        )

    if entry is None:
        return result(
            NOT_COMPARABLE,
            UNMAPPED_ATOM,
            "the legacy atom is not in the golden mapping",
        )
    base["mapping_status"] = entry.status
    base["mapped_keys"] = entry.keys
    if entry.status == "retired" or not entry.keys:
        return result(
            NOT_COMPARABLE,
            RETIRED_ATOM,
            "retired in RBAC-2: nothing enforces this atom",
        )
    if not catalogue:
        return result(
            NOT_COMPARABLE,
            CATALOGUE_NOT_POPULATED,
            "the RBAC catalogue has not been synced to this database",
        )
    missing = [k for k in entry.keys if k not in catalogue]
    if missing:
        return result(
            ERROR,
            MAPPING_DRIFT,
            "the golden mapping names keys the catalogue lacks: " + ",".join(missing),
        )
    if not assignments:
        return result(
            NOT_COMPARABLE,
            PRINCIPAL_NOT_PROVISIONED,
            "the principal has no RBAC role assignment, so the new side has nothing to compare",
        )

    grants = tuple(grants)
    decisions = []
    for key in entry.keys:
        d = engine.decide(principal, grants, catalogue, key, scope)
        decisions.append(KeyDecision(key=key, allowed=d.allowed, reason=d.reason))
    new_allowed = all(d.allowed for d in decisions)
    extra = dict(new_decision=new_allowed, key_decisions=tuple(decisions))

    if scope.resource_org_id and scope.resource_org_id != principal.home_org_id:
        return result(
            NOT_COMPARABLE,
            SCOPE_DEFERRED,
            "a legacy permission check carries no organisation; a resource in another "
            "organisation is the deferred scope model (RBAC-5)",
            **extra,
        )
    denied_for_scope = [
        d for d in decisions if not d.allowed and d.reason in SCOPE_REASONS
    ]
    if denied_for_scope and legacy_allowed:
        return result(
            NOT_COMPARABLE,
            SCOPE_DEFERRED,
            "the new denial is scope-driven ("
            + ",".join(sorted({d.reason for d in denied_for_scope}))
            + "), which the legacy check does not model",
            **extra,
        )

    if new_allowed == bool(legacy_allowed):
        return result(
            MATCH,
            ALLOW_BOTH if new_allowed else DENY_BOTH,
            "both allow" if new_allowed else "both deny",
            **extra,
        )
    if legacy_allowed:
        why = ",".join(f"{d.key}:{d.reason}" for d in decisions if not d.allowed)
        return result(MISMATCH, NEW_DENIES, why, **extra)
    return result(
        MISMATCH,
        NEW_ALLOWS,
        "the new model grants "
        + ",".join(entry.keys)
        + " and the legacy role does not hold the atom",
        **extra,
    )


def role_name_check_result(
    user,
    required_roles: Iterable[str],
    legacy_allowed: bool,
    *,
    operation: str | None = None,
) -> ShadowResult:
    """
    A ``require_role`` check names roles, not permissions, so there is nothing to
    map or compare: it is ``NOT_COMPARABLE``/``role_name_check`` — and the fact that
    this route is guarded by a role *name* is RBAC-4 migration evidence. Needs no
    database.
    """
    return ShadowResult(
        kind=NOT_COMPARABLE,
        classification=ROLE_NAME_CHECK,
        reason="a role-name guard has no permission to compare; it becomes a permission in RBAC-4",
        principal_id=str(getattr(user, "id", "") or ""),
        org_id=getattr(user, "org_id", None),
        legacy_role=_legacy_role_label(user),
        required_roles=tuple(sorted(str(r) for r in required_roles)),
        legacy_decision=bool(legacy_allowed),
        operation=operation,
    )


# ── the comparison (with the database) ────────────────────────────────────────


def shadow_compare(
    db: Session,
    user,
    legacy_resource: str,
    legacy_action: str,
    legacy_allowed: bool,
    *,
    scope: c.ScopeContext | None = None,
    operation: str | None = None,
    index: Mapping[str, MappingEntry] | None = None,
    recorder: "ShadowRecorder | None" = None,
) -> ShadowResult:
    """
    Evaluate the new engine for the question the legacy check answered, and report
    whether they agree. **Never raises, never changes the legacy verdict, returns
    only a comparison.**

    Everything that reads the database runs in a savepoint, so a failed query rolls
    back only itself. Any failure becomes an ``ERROR`` result. ``recorder`` (when
    given) records the result; logging is the recorder's.
    """
    started = time.perf_counter()
    atom = f"{legacy_resource}:{legacy_action}"
    try:
        entries = index if index is not None else golden_index()
        entry = entries.get(atom)
        principal = resolver.principal_for_user(user)
        label = _legacy_role_label(user)
        if entry is None or entry.status == "retired" or not entry.keys:
            # decided from the mapping alone: no query is made
            result = compare_decision(
                principal,
                (),
                {},
                (),
                entry,
                legacy_atom=atom,
                legacy_allowed=legacy_allowed,
                scope=scope,
                operation=operation,
                legacy_role=label,
            )
        else:
            with db.begin_nested():
                catalogue = resolver.load_catalogue(db)
                info = resolver.assignment_summary(db, principal)
                grants = resolver.resolve_grants(db, principal)
            assignments = tuple(
                RoleInfo(
                    role_key=i.role_key,
                    role_state=i.role_state,
                    scope_type=i.scope_type,
                    scope_org_id=i.scope_org_id,
                    live=i.live,
                )
                for i in info
            )
            result = compare_decision(
                principal,
                grants,
                catalogue,
                assignments,
                entry,
                legacy_atom=atom,
                legacy_allowed=legacy_allowed,
                scope=scope,
                operation=operation,
                legacy_role=label,
            )
    except MappingUnavailable as exc:
        result = _error(
            user,
            atom,
            legacy_allowed,
            scope,
            operation,
            MAPPING_UNAVAILABLE,
            str(exc)[:200],
        )
    except Exception as exc:  # noqa: BLE001 - shadow must never break what it observes
        logger.debug("RBAC shadow evaluation failed for %s", atom, exc_info=True)
        result = _error(
            user,
            atom,
            legacy_allowed,
            scope,
            operation,
            EVALUATOR_ERROR,
            exc.__class__.__name__,
        )
    result = replace(
        result, duration_ms=round((time.perf_counter() - started) * 1000, 2)
    )
    if recorder is not None:
        recorder.record(result)
    return result


def _error(
    user, atom, legacy_allowed, scope, operation, classification, reason
) -> ShadowResult:
    scope = scope or c.ScopeContext()
    return ShadowResult(
        kind=ERROR,
        classification=classification,
        reason=reason,
        principal_id=str(getattr(user, "id", "") or ""),
        org_id=getattr(user, "org_id", None),
        legacy_role=_legacy_role_label(user),
        legacy_atom=atom,
        legacy_decision=bool(legacy_allowed),
        scope_requested_org=scope.requested_org_id,
        scope_resource_org=scope.resource_org_id,
        operation=operation,
    )


# ── recording ─────────────────────────────────────────────────────────────────


class ShadowRecorder:
    """
    Counts results and keeps the most recent mismatches and errors, and logs them.

    * ``MISMATCH`` and ``ERROR`` are logged at WARNING every time — they are the
      findings;
    * ``NOT_COMPARABLE`` is logged once per (classification, atom) per process at
      INFO, then only counted, so a retired atom does not write a line per request;
    * ``MATCH`` is only counted unless ``log_matches``.

    Thread-safe. Holds nothing a log line could not carry.
    """

    def __init__(self, buffer: int = 200, log_matches: bool = False):
        self._lock = threading.Lock()
        self.log_matches = log_matches
        self.counts: Counter = Counter()
        self.by_atom: Counter = Counter()
        self.mismatches: deque = deque(maxlen=max(1, buffer))
        self.errors: deque = deque(maxlen=max(1, buffer))
        self._seen: set = set()

    def record(self, result: ShadowResult) -> None:
        with self._lock:
            self.counts[(result.kind, result.classification)] += 1
            self.by_atom[(result.legacy_atom, result.kind)] += 1
            if result.kind == MISMATCH:
                self.mismatches.append(result)
            elif result.kind == ERROR:
                self.errors.append(result)
            first = (result.classification, result.legacy_atom) not in self._seen
            if result.kind == NOT_COMPARABLE:
                self._seen.add((result.classification, result.legacy_atom))
        fields = " ".join(f"{k}={v}" for k, v in result.log_fields().items())
        if result.kind == MISMATCH:
            logger.warning("RBAC shadow mismatch %s", fields)
        elif result.kind == ERROR:
            logger.warning("RBAC shadow error %s", fields)
        elif result.kind == NOT_COMPARABLE and first:
            logger.info("RBAC shadow not-comparable %s", fields)
        elif result.kind == MATCH and self.log_matches:
            logger.info("RBAC shadow match %s", fields)

    def total(self, kind: str | None = None) -> int:
        with self._lock:
            return sum(v for (k, _), v in self.counts.items() if kind in (None, k))

    def snapshot(self) -> dict:
        with self._lock:
            by_kind: Counter = Counter()
            for (kind, _), n in self.counts.items():
                by_kind[kind] += n
            return {
                "by_kind": dict(by_kind),
                "by_classification": {
                    f"{k}/{c_}": n for (k, c_), n in sorted(self.counts.items())
                },
                "mismatches": [r.to_dict() for r in self.mismatches],
                "errors": [r.to_dict() for r in self.errors],
            }

    def reset(self) -> None:
        with self._lock:
            self.counts.clear()
            self.by_atom.clear()
            self.mismatches.clear()
            self.errors.clear()
            self._seen.clear()
