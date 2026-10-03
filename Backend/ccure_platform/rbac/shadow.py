"""
ccure_platform/rbac/shadow.py — comparing the new decision with the legacy one.

The migration (RBAC-0 §12) runs the new engine **beside** the old one, compares,
and only cuts over when they agree everywhere. This file is the comparison
primitive. RBAC-1 builds it and wires it to **nothing**: no route, middleware or
dependency calls it, and ``tests/rbac/test_rbac_shadow.py`` asserts that. Turning
it on is RBAC-3.

Two properties are the point, and both are tested:

* **The new decision never controls the request.** ``shadow_compare`` takes the
  legacy verdict as an argument and returns an outcome *about* it; it has no way
  to change what the caller does, and it returns nothing the caller could mistake
  for the answer.
* **It cannot break the request it observes.** Everything it does is inside a
  savepoint and a ``try``: a failed query rolls back only the savepoint, never
  the caller's transaction, and any failure becomes an ``error`` outcome rather
  than an exception. A disagreement is logged (``ccure.rbac.shadow``) and
  counted — observable, never enforced.

A legacy atom may map to several new keys (a split) or several atoms to one (a
merge). The new decision for an atom is ALLOW only if **every** key it maps to
is allowed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ccure_platform.rbac import contract as c
from ccure_platform.rbac import resolver
from ccure_platform.rbac.model import RbacLegacyMap
from sqlalchemy import select
from sqlalchemy.orm import Session

logger = logging.getLogger("ccure.rbac.shadow")

MATCH = "match"
MISMATCH = "mismatch"
#: The legacy atom has no mapping yet. Neither a match nor a mismatch: the new
#: side cannot answer, and counting it either way would hide that.
NOT_MAPPED = "not_mapped"
#: The legacy atom was **retired** (RBAC-2): nothing enforces it, so the new model
#: has no key for it. Neither a match nor a mismatch, and said so — an atom with no
#: successor is a different fact from an atom nobody has mapped yet.
RETIRED = "retired"
ERROR = "error"


@dataclass(frozen=True, slots=True)
class ShadowOutcome:
    kind: str
    legacy_resource: str
    legacy_action: str
    legacy_allowed: bool
    new_allowed: bool | None = None
    permission_keys: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()


@dataclass(slots=True)
class ShadowRecorder:
    """Counts outcomes and keeps the first ``limit`` disagreements."""

    limit: int = 200
    counts: dict[str, int] = field(default_factory=dict)
    mismatches: list[ShadowOutcome] = field(default_factory=list)

    def record(self, outcome: ShadowOutcome) -> None:
        self.counts[outcome.kind] = self.counts.get(outcome.kind, 0) + 1
        if outcome.kind == MISMATCH and len(self.mismatches) < self.limit:
            self.mismatches.append(outcome)


def mapped_keys(db: Session, resource: str, action: str) -> tuple[str, ...]:
    """The new permission keys a legacy ``resource:action`` atom maps to. A retired
    atom has none (its row carries no key)."""
    return tuple(
        sorted(
            key
            for key in db.execute(
                select(RbacLegacyMap.permission_key).where(
                    RbacLegacyMap.kind == "permission",
                    RbacLegacyMap.legacy_resource == resource,
                    RbacLegacyMap.legacy_action == action,
                )
            ).scalars()
            if key is not None
        )
    )


def is_retired(db: Session, resource: str, action: str) -> bool:
    """Whether the legacy atom is recorded as retired."""
    return (
        db.execute(
            select(RbacLegacyMap.id).where(
                RbacLegacyMap.kind == "permission",
                RbacLegacyMap.legacy_resource == resource,
                RbacLegacyMap.legacy_action == action,
                RbacLegacyMap.status == "retired",
            )
        ).first()
        is not None
    )


def shadow_compare(
    db: Session,
    user,
    legacy_resource: str,
    legacy_action: str,
    legacy_allowed: bool,
    *,
    scope: c.ScopeContext | None = None,
    recorder: ShadowRecorder | None = None,
) -> ShadowOutcome:
    """
    Evaluate the new engine for the same question the legacy check answered and
    report whether they agree. **Never raises, never changes the legacy verdict,
    and returns only a comparison.**
    """
    try:
        with db.begin_nested():
            keys = mapped_keys(db, legacy_resource, legacy_action)
            if not keys:
                outcome = ShadowOutcome(
                    kind=(
                        RETIRED
                        if is_retired(db, legacy_resource, legacy_action)
                        else NOT_MAPPED
                    ),
                    legacy_resource=legacy_resource,
                    legacy_action=legacy_action,
                    legacy_allowed=legacy_allowed,
                )
            else:
                principal = resolver.principal_for_user(user)
                decisions = [
                    resolver.authorize(db, principal, key, scope) for key in keys
                ]
                new_allowed = all(d.allowed for d in decisions)
                outcome = ShadowOutcome(
                    kind=MATCH if new_allowed == bool(legacy_allowed) else MISMATCH,
                    legacy_resource=legacy_resource,
                    legacy_action=legacy_action,
                    legacy_allowed=bool(legacy_allowed),
                    new_allowed=new_allowed,
                    permission_keys=keys,
                    reasons=tuple(d.reason for d in decisions),
                )
    except Exception:  # noqa: BLE001 - shadow must never break what it observes
        logger.exception(
            "RBAC shadow evaluation failed for %s:%s", legacy_resource, legacy_action
        )
        outcome = ShadowOutcome(
            kind=ERROR,
            legacy_resource=legacy_resource,
            legacy_action=legacy_action,
            legacy_allowed=bool(legacy_allowed),
        )
    if outcome.kind == MISMATCH:
        logger.warning(
            "RBAC shadow mismatch %s:%s legacy=%s new=%s keys=%s reasons=%s",
            outcome.legacy_resource,
            outcome.legacy_action,
            outcome.legacy_allowed,
            outcome.new_allowed,
            ",".join(outcome.permission_keys),
            ",".join(outcome.reasons),
        )
    if recorder is not None:
        recorder.record(outcome)
    return outcome
