"""
Compare two live-scan results (live_scan_harness.py output), ignoring time.

    python3 scripts/validation/compare_live_scans.py [--strict] before.json after.json

Standard library only. For each run (the four that run together — "full",
"credentialed", "host", "database" — and "cancel", which runs alone) it compares
the scan row, the phases, the task's result, every progress frame in order and,
for a credentialed run, its configuration verdicts. The four concurrent runs
share the organisation's assets, services and findings, which are compared
once, as "concurrent"; the cancel run's are its own. Whether each credentialed
scan authenticated is compared too. Wall-clock fields are excluded: the frames'
``t`` and ``timestamp``, the run's elapsed time, the scan's duration and the
progress counters' ``start_time`` and ``elapsed_time``, and the stop's delay.

Two more things depend on timing alone. Both were measured during B3
(docs/architecture/MODULAR_REFACTORING_LOG.md §6), and a difference in either
is reported as tolerated rather than as a difference:

* **Discovery's sampled frames.** While a batch runs, discovery publishes the
  hosts marked active so far, sampled every 150 ms. How many of those frames
  there are, and how many hosts the first holds, depends on when the samples
  land. A phase-1 ``running`` frame that the next phase-1 ``running`` frame
  covers completely (the same or more hosts, the same or higher counters, the
  same keys) is a sample, and may be present in one run and absent in the
  other. The harness stops the cancel run on the first such frame, so the
  stop's ``after_discovered`` is a sample too.
* **Where the stop route's frame lands.** ``POST /scans/{id}/stop`` publishes
  its own ``cancelled`` frame from another thread, so its position among the
  engine's frames is timing. That it was sent, and how often, is not.

Nothing else is tolerated: the last frame of every run of samples, every frame
of the later phases (their counters are per host, not sampled), every terminal
frame, a frame that goes backwards, and every stored row are compared exactly.
Every tolerated difference is still printed. ``--strict`` compares everything
exactly, as before B3.

The rescans (G3) run one at a time, so nothing in them is timing: for each,
its row, phases and task result, its comparison with its baseline, the
remediation events it wrote, the verification a pipeline rescan would make,
and the target's findings after it are compared exactly, and so is whether
the rescans reached every classification. Their frames are not recorded.

Exit 0 when nothing differs or only tolerated differences remain, 1 when
anything else differs (each difference is named), 2 on bad input.
"""

from __future__ import annotations

import json
import sys

RUNS = ("full", "credentialed", "host", "database", "cancel")
#: What each run carries itself. The cancel run runs alone, so the
#: organisation's state after it is its own; the four concurrent runs share
#: theirs, compared once under CONCURRENT.
RUN_TABLES = {"cancel": ("phases", "assets", "services", "findings")}
DEFAULT_RUN_TABLES = ("phases", "verdicts")
CONCURRENT = "concurrent"
CONCURRENT_TABLES = ("assets", "services", "findings")
#: Frame fields that are wall-clock time: the harness's arrival time, and the
#: send time the credentialed task stamps on its progress frames.
FRAME_TIME_KEYS = frozenset({"t", "timestamp"})

#: What each rescan carries, compared exactly (the row and task result too).
RESCAN_FIELDS = (
    "kind",
    "target_state",
    "phases",
    "comparison",
    "remediation_events",
    "verification_preview",
    "target_findings",
)

#: The frame POST /scans/{id}/stop publishes (live_scan_harness.stop_like_the_route,
#: pinned against it by tests/repo/test_live_scan_tooling.py), as frame_view records it.
ROUTE_STOP_FRAME = {
    "phase": 1,
    "status": "cancelled",
    "reason": "Scan cancelled by user.",
}

#: The counters a discovery frame carries, which only ever grow during a batch.
_SAMPLE_COUNTERS = ("discovered", "active")


def _scan(row: dict) -> dict:
    row = dict(row)
    row.pop("duration_seconds", None)
    progress = dict(row.get("progress") or {})
    for key in ("start_time", "elapsed_time"):
        progress.pop(key, None)
    row["progress"] = progress
    return row


def _frames(frames: list[dict]) -> list[dict]:
    return [
        {k: v for k, v in frame.items() if k not in FRAME_TIME_KEYS} for frame in frames
    ]


def _stop(stop: dict | None) -> dict:
    stop = dict(stop or {})
    stop.pop("task_returned_s_after_stop", None)
    return stop


def _is_discovery_sample(frame: dict) -> bool:
    return (
        frame.get("phase") == 1
        and frame.get("status") == "running"
        and "host_ips" in frame
    )


def _covered_by(frame: dict, later: dict) -> bool:
    """True when ``later`` reports everything ``frame`` reports, and more or the same."""
    if set(frame) != set(later) or frame.get("total_ips") != later.get("total_ips"):
        return False
    if not set(frame["host_ips"]) <= set(later["host_ips"]):
        return False
    return all(
        isinstance(frame.get(k), int)
        and isinstance(later.get(k), int)
        and frame[k] <= later[k]
        for k in _SAMPLE_COUNTERS
        if k in frame
    )


def timing_free(frames: list[dict]) -> dict:
    """
    A run's frames without what timing alone decides.

    The stop route's frames are counted and taken out of the sequence, and a
    discovery frame the next discovery frame covers is dropped. Everything else
    stays, in order.
    """
    route = [f for f in frames if f == ROUTE_STOP_FRAME]
    engine = [f for f in frames if f != ROUTE_STOP_FRAME]
    kept = [
        frame
        for frame, following in zip(engine, engine[1:] + [None])
        if not (
            following is not None
            and _is_discovery_sample(frame)
            and _is_discovery_sample(following)
            and _covered_by(frame, following)
        )
    ]
    return {"stop_route_frames": len(route), "frames": kept}


def _brief(frames: list[dict]) -> str:
    """Frames in one line, host lists as counts: enough to see what was tolerated."""
    parts = []
    for f in frames:
        detail = ",".join(
            f"{k}={f[k]}"
            for k in ("discovered", "active", "scanned_hosts", "reason")
            if k in f
        )
        hosts = f" hosts={len(f['host_ips'])}" if "host_ips" in f else ""
        parts.append(
            f"{f.get('phase')}:{f.get('status')}{'(' + detail + ')' if detail else ''}{hosts}"
        )
    return f"{len(frames)} [" + "; ".join(parts) + "]"


def _line(run: str, name: str, a, b) -> str:
    return (
        f"{run} {name}: before {json.dumps(a, sort_keys=True, default=str)[:400]}"
        f" | after {json.dumps(b, sort_keys=True, default=str)[:400]}"
    )


def classify(
    before: dict, after: dict, strict: bool = False
) -> tuple[list[str], list[str]]:
    """
    (differences, tolerated): one line each. With ``strict`` every difference
    is a difference and nothing is tolerated.
    """
    differences: list[str] = []
    tolerated: list[str] = []
    for run in RUNS:
        old, new = before.get(run), after.get(run)
        if old is None and new is None:
            continue  # neither recorded it: a result from before the run existed
        if old is None or new is None:
            differences.append(
                f"{run}: missing from {'before' if old is None else 'after'}"
            )
            continue
        pairs = [
            (t, old.get(t), new.get(t))
            for t in RUN_TABLES.get(run, DEFAULT_RUN_TABLES)
        ]
        pairs += [
            ("scan", _scan(old["scan"]), _scan(new["scan"])),
            ("task_result", old.get("task_result"), new.get("task_result")),
        ]
        for name, a, b in pairs:
            if a != b:
                differences.append(_line(run, name, a, b))

        a, b = _frames(old.get("frames", [])), _frames(new.get("frames", []))
        if a != b:
            if strict or timing_free(a) != timing_free(b):
                differences.append(_line(run, "frames", a, b))
            else:
                tolerated.append(
                    f"{run} frames, timing only: before {_brief(a)} | after {_brief(b)}"
                )

        if run == "cancel":
            a, b = _stop(old.get("stop")), _stop(new.get("stop"))
            if a != b:
                sampled = dict(a, after_discovered=None) == dict(
                    b, after_discovered=None
                ) and all(
                    isinstance(s.get("after_discovered"), int)
                    and s["after_discovered"] > 0
                    for s in (a, b)
                )
                if sampled and not strict:
                    tolerated.append(
                        f"{run} stop after_discovered, timing only:"
                        f" before {a['after_discovered']} | after {b['after_discovered']}"
                    )
                else:
                    differences.append(_line(run, "stop", a, b))

    old, new = before.get(CONCURRENT), after.get(CONCURRENT)
    if old is None and new is None:
        pass
    elif old is None or new is None:
        differences.append(
            f"{CONCURRENT}: missing from {'before' if old is None else 'after'}"
        )
    else:
        for table in CONCURRENT_TABLES:
            if old.get(table) != new.get(table):
                differences.append(
                    _line(CONCURRENT, table, old.get(table), new.get(table))
                )
    if before.get("authenticated") != after.get("authenticated"):
        differences.append(
            _line("authenticated", "", before.get("authenticated"), after.get("authenticated"))
        )
    differences.extend(_rescan_differences(before, after))
    return differences, tolerated


def _rescan_differences(before: dict, after: dict) -> list[str]:
    old, new = before.get("rescans"), after.get("rescans")
    if old is None and new is None:
        return []  # neither recorded them: a result from before G3
    if old is None or new is None:
        return [f"rescans: missing from {'before' if old is None else 'after'}"]
    differences = []
    for run in sorted(set(old) | set(new)):
        a, b = old.get(run), new.get(run)
        if a is None or b is None:
            differences.append(
                f"rescan {run}: missing from {'before' if a is None else 'after'}"
            )
            continue
        pairs = [(name, a.get(name), b.get(name)) for name in RESCAN_FIELDS]
        pairs += [
            ("scan", _scan(a.get("scan") or {}), _scan(b.get("scan") or {})),
            ("task_result", a.get("task_result"), b.get("task_result")),
        ]
        for name, x, y in pairs:
            if x != y:
                differences.append(_line(f"rescan {run}", name, x, y))
    if before.get("rescan_coverage") != after.get("rescan_coverage"):
        differences.append(
            _line(
                "rescan_coverage",
                "",
                before.get("rescan_coverage"),
                after.get("rescan_coverage"),
            )
        )
    return differences


def compare(before: dict, after: dict, strict: bool = False) -> list[str]:
    """One line per difference that is not timing; empty when the two runs agree."""
    return classify(before, after, strict)[0]


def summary(result: dict) -> list[str]:
    lines = []
    for run in RUNS:
        r = result.get(run) or {}
        scan = r.get("scan") or {}
        own = (
            f" {len(r.get('assets') or [])} assets, {len(r.get('services') or [])} services,"
            f" {len(r.get('findings') or [])} findings,"
            if run in RUN_TABLES
            else f" {scan.get('total_vulns')} findings reported,"
            + (f" {len(r.get('verdicts') or [])} verdicts," if "verdicts" in r else "")
        )
        lines.append(
            f"{run}: status {scan.get('status')}, {len(r.get('phases') or [])} phases,"
            f"{own} {len(r.get('frames') or [])} frames, {r.get('elapsed_s')} s"
        )
    state = result.get(CONCURRENT) or {}
    lines.append(
        f"{CONCURRENT}: {len(state.get('assets') or [])} assets,"
        f" {len(state.get('services') or [])} services,"
        f" {len(state.get('findings') or [])} findings"
    )
    auth = result.get("authenticated") or {}
    lines.append(
        "authenticated: "
        + (", ".join(f"{k} {v}" for k, v in sorted(auth.items())) or "not recorded")
    )
    for run, r in (result.get("rescans") or {}).items():
        comparison = r.get("comparison") or {}
        counts = {k: v for k, v in sorted((comparison.get("counts") or {}).items()) if v}
        events = {}
        for row in r.get("remediation_events") or []:
            events[row[3]] = events.get(row[3], 0) + 1
        lines.append(
            f"rescan {run}: status {(r.get('scan') or {}).get('status')},"
            f" baseline {comparison.get('baseline')}, {counts or 'no changes'},"
            f" events {events or 'none'}, {r.get('elapsed_s')} s"
        )
    coverage = result.get("rescan_coverage")
    if coverage is not None:
        missing = sorted(k for k, ok in coverage.items() if not ok)
        lines.append(
            "rescan coverage: " + ("complete" if not missing else f"missing {missing}")
        )
    return lines


def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    paths = [a for a in argv if a != "--strict"]
    if len(paths) != 2 or len(argv) - len(paths) > 1:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        before, after = (json.load(open(path, encoding="utf-8")) for path in paths)
    except (OSError, ValueError) as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 2
    for label, result in (("before", before), ("after", after)):
        for line in summary(result):
            print(f"{label:6} {line}")
    differences, tolerated = classify(before, after, strict)
    for line in tolerated:
        print(f"tolerated: {line}")
    for line in differences:
        print(line)
    if differences:
        print(f"{len(differences)} difference(s)")
    elif tolerated:
        print(
            f"identical apart from time and {len(tolerated)} timing-dependent"
            " difference(s), listed above"
        )
    else:
        print("identical apart from time")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
