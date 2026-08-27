"""
tests/scans/test_scan_schedule_recurrence.py
─────────────────────────────────────────────────────────────────────────────
The recurrence engine, in isolation.

No database, no Celery, no scan pipeline. Scheduling goes wrong in exactly two
places — daylight saving and the end of the month — and neither needs any of
that to reproduce. Keeping these pure means the awkward cases are cheap enough
to cover exhaustively.

Every case here is a behaviour ``compliance_scan_schedules`` gets wrong by
computing ``next_run_at = now + timedelta(...)``.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest
from core.scheduling.recurrence import (
    RecurrenceSpec,
    compute_next_run,
    describe_recurrence,
    is_valid_timezone,
    minute_to_hhmm,
    parse_hhmm,
)

LONDON = "Europe/London"
KOLKATA = "Asia/Kolkata"


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def _local(moment: datetime, zone: str) -> str:
    return moment.astimezone(ZoneInfo(zone)).strftime("%Y-%m-%d %H:%M")


# ─────────────────────────────────────────────────────────────────────────────
# Time parsing
# ─────────────────────────────────────────────────────────────────────────────


def test_hhmm_round_trips():
    assert parse_hhmm("09:30") == 570
    assert minute_to_hhmm(570) == "09:30"
    assert parse_hhmm("00:00") == 0
    assert parse_hhmm("23:59") == 1439


@pytest.mark.parametrize("bad", ["9am", "25:00", "09:60", "0930", "", "  ", "9:0:0"])
def test_unparseable_times_are_refused_not_coerced(bad):
    """
    A schedule that silently read "9am" as midnight would run twelve hours from
    where the user put it, and nothing in the UI would show that it had.
    """
    with pytest.raises(ValueError):
        parse_hhmm(bad)


def test_only_iana_names_are_accepted_as_zones():
    assert is_valid_timezone("Asia/Kolkata")
    assert is_valid_timezone("UTC")
    # An offset cannot express daylight saving, so a schedule stored as +05:30
    # would be an hour out for half the year in any zone that observes DST.
    assert not is_valid_timezone("+05:30")
    assert not is_valid_timezone("IST")
    assert not is_valid_timezone("Mars/Olympus_Mons")


# ─────────────────────────────────────────────────────────────────────────────
# Daily, and the daylight-saving cases
# ─────────────────────────────────────────────────────────────────────────────


def test_daily_keeps_its_wall_clock_time_across_spring_forward():
    """
    The headline property. "09:00 daily, Europe/London" means 09:00 in London
    on both sides of the boundary, even though the UTC instant moves by an
    hour. ``now + timedelta(days=1)`` keeps the *interval* instead and lets the
    local time slide, which users experience as a nightly job drifting into the
    working day.
    """
    spec = RecurrenceSpec("daily", LONDON, parse_hhmm("09:00"))

    before = compute_next_run(spec, _utc(2027, 3, 27, 12, 0))
    after = compute_next_run(spec, _utc(2027, 3, 28, 2, 0))

    assert _local(before, LONDON).endswith("09:00")
    assert _local(after, LONDON).endswith("09:00")


def test_a_time_inside_the_skipped_hour_still_runs_that_day():
    """
    On a spring-forward night 01:30 never occurs in London. ``fold`` cannot
    help — the time is absent, not ambiguous. Skipping the day would mean a
    monthly job silently missing a month, so the run is pushed forward to the
    first instant that exists.
    """
    spec = RecurrenceSpec("daily", LONDON, parse_hhmm("01:30"))
    moment = compute_next_run(spec, _utc(2027, 3, 27, 23, 0))

    assert moment is not None
    assert _local(moment, LONDON).startswith(
        "2027-03-28"
    ), "the run must still happen on the transition day, not be skipped"


def test_a_time_inside_the_repeated_hour_runs_once_at_the_first_occurrence():
    """
    On an autumn-back night 01:30 occurs twice. Running at both is not
    something the caller can express, and choosing the second delays the job
    for no benefit — so the earlier UTC instant wins.
    """
    spec = RecurrenceSpec("daily", LONDON, parse_hhmm("01:30"))
    moment = compute_next_run(spec, _utc(2027, 10, 30, 23, 0))

    assert moment is not None
    # The first 01:30 that night is still BST (UTC+1), i.e. 00:30 UTC.
    assert moment == _utc(2027, 10, 31, 0, 30)


def test_daily_moves_to_tomorrow_once_todays_slot_has_passed():
    spec = RecurrenceSpec("daily", KOLKATA, parse_hhmm("02:00"))
    # 21:30 UTC on the 26th is 03:00 IST on the 27th, so the 27th's 02:00 slot
    # has already gone and the next one is the 28th.
    moment = compute_next_run(spec, _utc(2026, 8, 26, 21, 30))
    assert _local(moment, KOLKATA) == "2026-08-28 02:00"


# ─────────────────────────────────────────────────────────────────────────────
# Weekly
# ─────────────────────────────────────────────────────────────────────────────


def test_weekly_lands_on_the_requested_weekday():
    spec = RecurrenceSpec("weekly", KOLKATA, parse_hhmm("18:45"), day_of_week=2)
    moment = compute_next_run(spec, _utc(2026, 8, 24, 0, 0))  # Monday
    local = moment.astimezone(ZoneInfo(KOLKATA))
    assert local.weekday() == 2, "0 = Monday, so 2 must be Wednesday"
    assert local.strftime("%H:%M") == "18:45"


def test_weekly_skips_to_next_week_when_todays_slot_has_passed():
    """The subtle one: it *is* Wednesday, but 18:45 has already gone."""
    spec = RecurrenceSpec("weekly", KOLKATA, parse_hhmm("18:45"), day_of_week=2)
    moment = compute_next_run(spec, _utc(2026, 8, 26, 13, 30))  # Wed 19:00 IST
    assert _local(moment, KOLKATA) == "2026-09-02 18:45"


def test_weekly_without_a_weekday_has_no_next_run():
    """Rather than inventing one. The CHECK constraint refuses the row too."""
    assert compute_next_run(RecurrenceSpec("weekly", "UTC"), _utc(2026, 8, 27)) is None


# ─────────────────────────────────────────────────────────────────────────────
# Monthly, and the month-end case
# ─────────────────────────────────────────────────────────────────────────────


def test_day_31_runs_on_the_last_day_of_a_shorter_month():
    """
    Skipping the month instead would make a schedule set on the 31st run seven
    times a year, which is not what anyone means by monthly.
    """
    spec = RecurrenceSpec("monthly", KOLKATA, parse_hhmm("02:00"), day_of_month=31)
    moment = compute_next_run(spec, _utc(2027, 2, 1, 0, 0))
    assert _local(moment, KOLKATA) == "2027-02-28 02:00"


def test_day_31_uses_the_29th_in_a_leap_february():
    spec = RecurrenceSpec("monthly", KOLKATA, parse_hhmm("02:00"), day_of_month=31)
    moment = compute_next_run(spec, _utc(2028, 2, 1, 0, 0))
    assert _local(moment, KOLKATA) == "2028-02-29 02:00"


def test_monthly_rolls_into_the_next_year():
    spec = RecurrenceSpec("monthly", "UTC", parse_hhmm("06:00"), day_of_month=5)
    moment = compute_next_run(spec, _utc(2026, 12, 10, 0, 0))
    assert moment == _utc(2027, 1, 5, 6, 0)


def test_monthly_without_a_day_has_no_next_run():
    assert compute_next_run(RecurrenceSpec("monthly", "UTC"), _utc(2026, 8, 27)) is None


# ─────────────────────────────────────────────────────────────────────────────
# One-time
# ─────────────────────────────────────────────────────────────────────────────


def test_a_one_time_schedule_is_terminal_once_its_moment_has_passed():
    """
    Returning None is what makes ``once`` stop. If it returned a time, the beat
    tick would re-fire it every minute forever.
    """
    spec = RecurrenceSpec("once", "UTC", starts_at=_utc(2026, 9, 1, 10, 0))
    assert compute_next_run(spec, _utc(2026, 8, 27)) == _utc(2026, 9, 1, 10, 0)
    assert compute_next_run(spec, _utc(2026, 9, 2)) is None


def test_a_one_time_schedule_with_no_moment_never_fires():
    """
    Rather than firing immediately on the next tick, which is a surprising
    reading of "one-time" for a row created without a time.
    """
    assert compute_next_run(RecurrenceSpec("once", "UTC"), _utc(2026, 8, 27)) is None


# ─────────────────────────────────────────────────────────────────────────────
# Start boundary and misc
# ─────────────────────────────────────────────────────────────────────────────


def test_a_schedule_does_not_run_before_its_start():
    spec = RecurrenceSpec(
        "daily", "UTC", parse_hhmm("09:00"), starts_at=_utc(2026, 12, 1, 0, 0)
    )
    moment = compute_next_run(spec, _utc(2026, 8, 27, 0, 0))
    assert moment == _utc(2026, 12, 1, 9, 0)


def test_custom_recurrence_returns_none_rather_than_guessing():
    """
    This module does not know what a cron expression means, and inventing a
    time from one it cannot parse would schedule a scan at an arbitrary moment.
    """
    assert compute_next_run(RecurrenceSpec("custom", "UTC"), _utc(2026, 8, 27)) is None


def test_a_naive_now_is_refused():
    """It would be read as local time on whichever host evaluated it."""
    with pytest.raises(ValueError, match="aware datetime"):
        compute_next_run(RecurrenceSpec("daily", "UTC"), datetime(2026, 8, 27, 9, 0))


def test_an_unresolvable_zone_falls_back_rather_than_stalling_every_tenant():
    """
    A zone that vanished from the system tzdata must not stop other tenants'
    schedules being evaluated on the same beat tick. UTC is wrong by at most a
    few hours; not running at all is wrong indefinitely.
    """
    spec = RecurrenceSpec("daily", "Nowhere/Fictional", parse_hhmm("09:00"))
    moment = compute_next_run(spec, _utc(2026, 8, 27, 0, 0))
    assert moment == _utc(2026, 8, 27, 9, 0)


def test_descriptions_name_the_zone():
    """The UI shows this, and a time without its zone is ambiguous."""
    text = describe_recurrence(
        RecurrenceSpec("weekly", KOLKATA, parse_hhmm("18:45"), day_of_week=2)
    )
    assert "Wednesday" in text and "18:45" in text and KOLKATA in text
