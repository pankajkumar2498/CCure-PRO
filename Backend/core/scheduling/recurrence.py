"""
core/scheduling/recurrence.py
──────────────────────────────────────────────────────────────────────────────
When does a schedule next run?

Everything here is pure: it takes a description of a recurrence and a moment,
and returns a moment. No database, no clock of its own. That is what makes the
awkward cases — daylight saving, the 31st of February, a schedule enabled after
its window has passed — testable without a scan pipeline attached.

The rule that shapes the whole module
─────────────────────────────────────
**A wall-clock schedule keeps its wall-clock time.** "09:00 daily, Europe/London"
means 09:00 in London on both sides of a DST boundary, even though the UTC
instant moves by an hour. The compliance scheduler computes
``next_run_at = now + timedelta(days=1)``, which is the other answer: it keeps
the *interval* and lets the local time slide. Users do not experience a nightly
job that way — they experience "it used to run before I got in, now it runs
during the working day".

So the arithmetic is done on a naive local date-time inside the target zone and
converted to UTC exactly once, at the end.

Two DST edge cases, both of which have exactly one defensible answer
────────────────────────────────────────────────────────────────────
* **The hour that does not exist.** On a spring-forward night, 02:30 never
  occurs. ``fold`` cannot help — the time is absent, not ambiguous. A schedule
  set for 02:30 must still run that day, so the time is pushed forward to the
  first instant that does exist. Skipping the day would mean a monthly job
  silently missing a month.
* **The hour that happens twice.** On a autumn-back night, 01:30 occurs twice.
  ``fold=0`` selects the first — the earlier UTC instant — so the job runs once
  and runs at the first opportunity. Selecting the second would delay it by an
  hour with no benefit; running at both is not an option the caller can express.

Month-end
─────────
"The 31st" in a 30-day month runs on the 30th, and in February on the 28th or
29th. The alternative — skipping the month — means a schedule set on the 31st
runs seven times a year, which is never what anyone means by monthly.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

__all__ = [
    "MAX_RUN_MINUTE",
    "RecurrenceSpec",
    "compute_next_run",
    "describe_recurrence",
    "is_valid_timezone",
    "minute_to_hhmm",
    "parse_hhmm",
]

#: 23:59 as minutes past local midnight.
MAX_RUN_MINUTE = 24 * 60 - 1


def is_valid_timezone(name: str) -> bool:
    """True if *name* is an IANA zone this interpreter can resolve."""
    try:
        ZoneInfo(str(name))
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return False
    return True


def parse_hhmm(value: str) -> int:
    """
    "09:30" -> 570 minutes past midnight.

    Rejects anything else rather than coercing. A schedule silently reading
    "9am" as midnight would run twelve hours from where the user put it.
    """
    text = str(value or "").strip()
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError(f"time must be HH:MM, got {value!r}")
    try:
        hour, minute = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise ValueError(f"time must be HH:MM, got {value!r}") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"time must be between 00:00 and 23:59, got {value!r}")
    return hour * 60 + minute


def minute_to_hhmm(minute: int) -> str:
    """570 -> "09:30"."""
    minute = max(0, min(int(minute), MAX_RUN_MINUTE))
    return f"{minute // 60:02d}:{minute % 60:02d}"


@dataclass(frozen=True)
class RecurrenceSpec:
    """
    Everything needed to place the next run, and nothing else.

    Deliberately decoupled from the ORM model so this module can be exercised
    without a database — the DST and month-end cases are where scheduling goes
    wrong, and they should not need a Postgres connection to test.
    """

    recurrence: str
    timezone: str = "UTC"
    run_at_minute: int = 0
    day_of_week: Optional[int] = None  # 0 = Monday .. 6 = Sunday
    day_of_month: Optional[int] = None  # 1..31
    starts_at: Optional[datetime] = None

    @classmethod
    def from_schedule(cls, schedule) -> "RecurrenceSpec":
        return cls(
            recurrence=schedule.recurrence,
            timezone=schedule.timezone or "UTC",
            run_at_minute=schedule.run_at_minute or 0,
            day_of_week=schedule.day_of_week,
            day_of_month=schedule.day_of_month,
            starts_at=schedule.starts_at,
        )


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(str(name or "UTC"))
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        # Falling back rather than raising is deliberate: a zone that vanished
        # from the system tzdata must not stop every *other* tenant's schedules
        # from being evaluated on this beat tick. The caller records the
        # substitution; the schedule still runs, an hour or two out at worst.
        return ZoneInfo("UTC")


def _localise(naive_local: datetime, zone: ZoneInfo) -> datetime:
    """
    Turn a naive local wall-clock time into a real UTC instant.

    Handles the two DST cases described in the module docstring. ``fold=0``
    picks the earlier of a repeated hour. A time that does not exist is
    detected by round-tripping through UTC: for a skipped hour the round trip
    does not return what went in, and the time is advanced until it does.
    """
    candidate = naive_local.replace(tzinfo=zone, fold=0)
    # A nonexistent local time round-trips to a different wall clock.
    if candidate.astimezone(timezone.utc).astimezone(zone).replace(
        tzinfo=None
    ) != naive_local.replace(tzinfo=None):
        # Step forward a minute at a time to the first instant that exists.
        # Bounded at three hours: no real transition is larger, and an
        # unbounded loop here would hang the beat tick for every tenant.
        probe = naive_local
        for _ in range(180):
            probe = probe + timedelta(minutes=1)
            attempt = probe.replace(tzinfo=zone, fold=0)
            if attempt.astimezone(timezone.utc).astimezone(zone).replace(
                tzinfo=None
            ) == probe.replace(tzinfo=None):
                return attempt.astimezone(timezone.utc)
        # No existing time found — fall back to the original instant rather
        # than returning None and stalling the schedule forever.
        return candidate.astimezone(timezone.utc)
    return candidate.astimezone(timezone.utc)


def _at_time(day: datetime, minute: int) -> datetime:
    """Naive local midnight on *day*, plus *minute* minutes."""
    return datetime.combine(day.date(), time(0, 0)) + timedelta(minutes=int(minute))


def _clamp_day(year: int, month: int, day: int) -> int:
    """The 31st of a 30-day month is that month's last day. See the docstring."""
    return min(int(day), calendar.monthrange(year, month)[1])


def compute_next_run(
    spec: RecurrenceSpec, after: Optional[datetime] = None
) -> Optional[datetime]:
    """
    The first moment at or after *after* that this schedule should run.

    Returns a timezone-aware UTC datetime, or ``None`` for a one-time schedule
    whose moment has already passed — which is what makes "once" terminal
    rather than something the beat tick re-fires forever.

    *after* defaults to now. It is a parameter so tests can place the clock
    exactly, and so the scheduler can compute the run *after* the one it just
    dispatched without asking the wall clock twice.
    """
    now = after or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError(
            "compute_next_run requires an aware datetime — a naive one would "
            "be interpreted as local time on whichever host evaluates it."
        )
    now = now.astimezone(timezone.utc)

    recurrence = (spec.recurrence or "").strip().lower()
    zone = _zone(spec.timezone)
    minute = max(0, min(int(spec.run_at_minute or 0), MAX_RUN_MINUTE))

    # A schedule that has not started yet is placed at its start boundary, not
    # at the next matching slot before it.
    floor = now
    if spec.starts_at is not None:
        starts_at = spec.starts_at
        if starts_at.tzinfo is None:
            starts_at = starts_at.replace(tzinfo=timezone.utc)
        floor = max(now, starts_at.astimezone(timezone.utc))

    if recurrence == "once":
        # `starts_at` is the moment. Without one there is nothing to schedule —
        # returning `now` would fire it immediately on the next tick, which is
        # a surprising reading of "one-time" for a row created without a time.
        if spec.starts_at is None:
            return None
        moment = spec.starts_at
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
        return moment if moment > now else None

    local_floor = floor.astimezone(zone)

    if recurrence == "daily":
        candidate_day = local_floor
        for _ in range(3):  # today, tomorrow, and one spare for DST edges
            candidate = _localise(_at_time(candidate_day, minute), zone)
            if candidate > floor:
                return candidate
            candidate_day = candidate_day + timedelta(days=1)
        return None

    if recurrence == "weekly":
        target = spec.day_of_week
        if target is None:
            return None
        target = int(target) % 7
        # Scan a fortnight: the first pass finds this week's slot or next
        # week's, and the extra week covers a slot that today has already
        # passed on the target weekday itself.
        for offset in range(0, 15):
            day = local_floor + timedelta(days=offset)
            if day.weekday() != target:
                continue
            candidate = _localise(_at_time(day, minute), zone)
            if candidate > floor:
                return candidate
        return None

    if recurrence == "monthly":
        requested = spec.day_of_month
        if requested is None:
            return None
        year, month = local_floor.year, local_floor.month
        # This month, then the next two — two is enough for any clamped day,
        # and bounding the loop keeps a malformed spec from spinning.
        for _ in range(3):
            day = _clamp_day(year, month, requested)
            naive = datetime(year, month, day) + timedelta(minutes=minute)
            candidate = _localise(naive, zone)
            if candidate > floor:
                return candidate
            month += 1
            if month > 12:
                month = 1
                year += 1
        return None

    if recurrence == "custom":
        # Cron is parsed by the caller, which owns the dependency. Returning
        # None here rather than guessing keeps this module honest: it does not
        # know what the expression means.
        return None

    return None


def describe_recurrence(spec: RecurrenceSpec) -> str:
    """A short human sentence for the UI and for audit-log payloads."""
    recurrence = (spec.recurrence or "").strip().lower()
    at = minute_to_hhmm(spec.run_at_minute or 0)
    zone = spec.timezone or "UTC"

    if recurrence == "once":
        if spec.starts_at is None:
            return "One time (no start time set)"
        return f"Once at {spec.starts_at.isoformat()}"
    if recurrence == "daily":
        return f"Daily at {at} ({zone})"
    if recurrence == "weekly":
        names = [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ]
        if spec.day_of_week is None:
            return f"Weekly at {at} ({zone})"
        return f"Weekly on {names[int(spec.day_of_week) % 7]} at {at} ({zone})"
    if recurrence == "monthly":
        if spec.day_of_month is None:
            return f"Monthly at {at} ({zone})"
        return f"Monthly on day {int(spec.day_of_month)} at {at} ({zone})"
    if recurrence == "custom":
        return f"Custom schedule ({zone})"
    return recurrence or "unknown"
