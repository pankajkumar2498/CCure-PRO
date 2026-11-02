"""
core/scan_policy/schedule_references.py — the schedules that refer to a
policy, as the scheduling capability answers.

The policy API warns about, refuses or reports the schedules a change affects:
a disable names the enabled schedules it breaks, an archive is refused while
one is enabled, a new version names those left on the old one, a deletion is
refused unless forced, and the usage and serialised policy report them. The
router used to query ``scan_schedules`` itself, while scheduling depends on
scan policy (the dispatcher resolves a schedule's policy), so the two sat in a
cycle. Scheduling answers for its own rows instead,
``core/scheduling/policy_references.py``, registered by Audit's composition
root, ``ccure_audit/policy_references.py``, which ``main.py`` imports.

Nothing here imports the schedule model. Without the registration a read
raises ``ScheduleReferencesMissing``: no schedules would wave through the very
changes the warnings exist to stop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Protocol, Tuple

from sqlalchemy.orm import Session


@dataclass(frozen=True)
class ScheduleReference:
    """A schedule that names a policy: what the policy API reports of it."""

    id: str
    name: str
    is_enabled: bool


class ScheduleReferences(Protocol):
    """What scheduling answers for the policy API."""

    def count(self, db: Session, policy_id: str) -> int:
        """Schedules naming the policy, in any organisation."""

    def schedules(
        self, db: Session, org_id: str, policy_id: str, *, enabled_only: bool
    ) -> Iterable[Tuple[str, str, bool]]:
        """``(id, name, is_enabled)`` of the organisation's schedules naming
        the policy, enabled ones only when *enabled_only*."""


class ScheduleReferencesMissing(RuntimeError):
    """A policy's schedules were read in a process that registered no answer."""


_references: Optional[ScheduleReferences] = None


def register_schedule_references(references: ScheduleReferences) -> None:
    """Register who answers; the same answer again is a no-op, another refused."""
    global _references
    if _references is references:
        return
    if _references is not None:
        raise ValueError("schedule references are already registered")
    _references = references


def _registered() -> ScheduleReferences:
    if _references is None:
        raise ScheduleReferencesMissing(
            "No schedule references are registered in this process. Audit's "
            "composition root, ccure_audit/policy_references.py, registers "
            "scheduling's: main.py imports it."
        )
    return _references


def schedule_count(db: Session, policy_id: str) -> int:
    """Schedules naming the policy, in any organisation."""
    return _registered().count(db, policy_id)


def schedules_using(
    db: Session, org_id: str, policy_id: str, *, enabled_only: bool = False
) -> List[ScheduleReference]:
    """The organisation's schedules naming the policy."""
    return [
        ScheduleReference(id=sid, name=name, is_enabled=is_enabled)
        for sid, name, is_enabled in _registered().schedules(
            db, org_id, policy_id, enabled_only=enabled_only
        )
    ]
