"""
Compare two live-scan results (live_scan_harness.py output), ignoring time.

    python3 scripts/validation/compare_live_scans.py before.json after.json

Standard library only. For each run ("full" and "cancel") it compares the scan
row, the phases, the assets, the services, the findings, the task's result and
every progress frame in order. Wall-clock fields are excluded: the frames'
``t``, the run's elapsed time, the scan's duration and the progress counters'
``start_time`` and ``elapsed_time``, and the stop's delay. Everything else
must match.

Exit 0 when everything matches, 1 when anything differs (each difference is
named), 2 on bad input.
"""

from __future__ import annotations

import json
import sys

RUNS = ("full", "cancel")
TABLES = ("phases", "assets", "services", "findings")


def _scan(row: dict) -> dict:
    row = dict(row)
    row.pop("duration_seconds", None)
    progress = dict(row.get("progress") or {})
    for key in ("start_time", "elapsed_time"):
        progress.pop(key, None)
    row["progress"] = progress
    return row


def _frames(frames: list[dict]) -> list[dict]:
    return [{k: v for k, v in frame.items() if k != "t"} for frame in frames]


def _stop(stop: dict | None) -> dict:
    stop = dict(stop or {})
    stop.pop("task_returned_s_after_stop", None)
    return stop


def compare(before: dict, after: dict) -> list[str]:
    """One line per difference; empty when the two runs agree."""
    problems: list[str] = []
    for run in RUNS:
        old, new = before.get(run), after.get(run)
        if old is None or new is None:
            problems.append(
                f"{run}: missing from {'before' if old is None else 'after'}"
            )
            continue
        pairs = [(t, old.get(t), new.get(t)) for t in TABLES]
        pairs += [
            ("scan", _scan(old["scan"]), _scan(new["scan"])),
            ("task_result", old.get("task_result"), new.get("task_result")),
            ("frames", _frames(old.get("frames", [])), _frames(new.get("frames", []))),
        ]
        if run == "cancel":
            pairs.append(("stop", _stop(old.get("stop")), _stop(new.get("stop"))))
        for name, a, b in pairs:
            if a != b:
                problems.append(
                    f"{run} {name}: before {json.dumps(a, sort_keys=True, default=str)[:400]}"
                    f" | after {json.dumps(b, sort_keys=True, default=str)[:400]}"
                )
    return problems


def summary(result: dict) -> list[str]:
    lines = []
    for run in RUNS:
        r = result.get(run) or {}
        scan = r.get("scan") or {}
        lines.append(
            f"{run}: status {scan.get('status')}, {len(r.get('phases') or [])} phases,"
            f" {len(r.get('assets') or [])} assets, {len(r.get('services') or [])} services,"
            f" {len(r.get('findings') or [])} findings, {len(r.get('frames') or [])} frames,"
            f" {r.get('elapsed_s')} s"
        )
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        before, after = (json.load(open(path, encoding="utf-8")) for path in argv)
    except (OSError, ValueError) as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 2
    for label, result in (("before", before), ("after", after)):
        for line in summary(result):
            print(f"{label:6} {line}")
    problems = compare(before, after)
    for line in problems:
        print(line)
    print(
        "identical apart from time"
        if not problems
        else f"{len(problems)} difference(s)"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
