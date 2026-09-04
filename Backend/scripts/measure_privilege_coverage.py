"""
scripts/measure_privilege_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-08 coverage — local privilege-escalation and host-exposure checks.

    python -m scripts.measure_privilege_coverage

Run before and after a change to get a comparable number.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
The first version of this file listed twenty areas, all of which Phase 5 then
implemented, and reported 100%. That is a tautology wearing a percentage: a
list written by the same person who then implements every item measures the
list, not the capability.

So the scope below also names eight real Nessus local checks this build does
**not** perform. They are in the denominator on purpose. A coverage figure is
only worth reading if it can go down.

Three things are counted separately and must never be conflated
──────────────────────────────────────────────────────────────
``implemented``   a check exists and the engine can execute it
``tested``        an automated test names the area and exercises it
``validated``     it has produced a correct result against a real host

**The headline coverage figure is implemented *and* tested.** Implemented alone
is not proven; a check nothing exercises is a check nobody has seen work.
Real-target validation is reported beside the number and never folded into it —
Phases 3 and 4 both ended unvalidated, and collapsing the distinction is how
that stops being visible.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: (area id, platform, description). The first twenty-one are what Phase 5
#: implements; the last eight are real Nessus local checks it does not.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Windows, implemented ─────────────────────────────────────────────────
    ("win.unquoted_service_path", "windows", "Unquoted service paths"),
    ("win.service_permissions", "windows", "Weak service ACLs"),
    ("win.service_binary_permissions", "windows", "Writable service binaries"),
    ("win.always_install_elevated", "windows", "AlwaysInstallElevated"),
    ("win.scheduled_task_permissions", "windows", "Writable scheduled-task binaries"),
    ("win.writable_path", "windows", "Writable directories on the system PATH"),
    ("win.unattend_files", "windows", "Unattended-install files left on disk"),
    ("win.cached_logons", "windows", "Cached logon credential count"),
    ("win.lsa_protection", "windows", "LSA protection (RunAsPPL)"),
    ("win.powershell_logging", "windows", "PowerShell script-block logging"),
    # ── Linux, implemented ───────────────────────────────────────────────────
    ("linux.suid_binaries", "linux", "SUID binaries outside the expected set"),
    ("linux.sgid_binaries", "linux", "SGID binaries outside the expected set"),
    ("linux.world_writable_dirs", "linux", "World-writable dirs without sticky bit"),
    ("linux.world_writable_files", "linux", "World-writable files"),
    ("linux.sudo_nopasswd", "linux", "NOPASSWD sudo rules"),
    ("linux.writable_path", "linux", "Writable directories on root's PATH"),
    ("linux.unowned_files", "linux", "Files owned by no valid user"),
    ("linux.ungrouped_files", "linux", "Files owned by no valid group"),
    ("linux.sensitive_file_modes", "linux", "Ownership/modes of the account files"),
    ("linux.root_path_integrity", "linux", "Relative or empty entries on root's PATH"),
    ("linux.file_capabilities", "linux", "File capabilities granting privilege"),
    # ── In scope, NOT implemented ────────────────────────────────────────────
    ("win.token_privileges", "windows", "Dangerous token privileges on services"),
    ("win.dll_hijack_paths", "windows", "DLL search-order hijack opportunities"),
    ("win.autorun_permissions", "windows", "Writable autorun binaries"),
    ("win.stored_credentials", "windows", "Credential Manager / cmdkey entries"),
    ("linux.docker_group", "linux", "docker group membership (effective root)"),
    ("linux.writable_systemd_units", "linux", "Unit files writable by non-root"),
    ("linux.nfs_root_squash", "linux", "NFS exports with no_root_squash"),
    ("linux.ld_preload", "linux", "ld.so.preload and writable loader config"),
)

#: Named so the exclusion is visible rather than silent. Excluding these is a
#: scoping decision agreed for Phase 5, not a way to raise the percentage.
OUT_OF_SCOPE = (
    "kernel exploit suggestion",
    "memory-resident / in-process checks",
    "agent-based collection",
)


def _implemented() -> Dict[str, object]:
    """Areas with a built-in check the engine can execute."""
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS
    except Exception as exc:  # pragma: no cover - import guard
        print(f"could not import the built-in checks: {exc}")
        return {}
    return {
        str(check.metadata.get("gap08_area")): check
        for check in BUILTIN_CHECKS
        if check.metadata.get("gap08_area")
    }


def _tested() -> Set[str]:
    """
    Areas an automated test names.

    Read from the test sources rather than from a hand-maintained list — a list
    would keep saying "tested" for as long as nobody updated it, which is
    precisely the failure a coverage figure must not have.
    """
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for path in root.rglob("test_privilege*.py"):
        corpus += path.read_text(encoding="utf-8")
    return {area for area, _p, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()

    print("=" * 78)
    print("GAP-08 — LOCAL PRIVILEGE & HOST-EXPOSURE COVERAGE")
    print("=" * 78)
    print(f"\n{'area':34} {'platform':9} {'impl':6} {'test':6} description")
    print("-" * 78)

    by_platform: Dict[str, List[bool]] = {"windows": [], "linux": []}
    for area, platform, description in SCOPE:
        has = area in implemented
        has_test = area in tested
        by_platform[platform].append(has and has_test)
        print(
            f"{area:34} {platform:9} {'yes' if has else 'NO':6} "
            f"{'yes' if has_test else 'NO':6} {description}"
        )

    total = len(SCOPE)
    done = sum(1 for area, _p, _d in SCOPE if area in implemented)
    proven = sum(1 for area, _p, _d in SCOPE if area in implemented and area in tested)

    print("-" * 78)
    for platform, flags in by_platform.items():
        print(
            f"  {platform:8} proven: {sum(flags)}/{len(flags)} "
            f"({round(100.0 * sum(flags) / len(flags), 1)}%)"
        )

    print(
        f"\n  implemented          : {done}/{total} = "
        f"{round(100.0 * done / total, 1)}%"
    )
    print(
        f"  implemented + tested : {proven}/{total} = "
        f"**{round(100.0 * proven / total, 1)}%**   <- GAP-08 coverage"
    )
    print("  real-target validated: reported separately, never folded in")
    if done != proven:
        print(
            f"\n  {done - proven} area(s) have a check no automated test names. "
            f"Implemented is not proven, and only proven counts."
        )

    orphans = sorted(set(implemented) - {a for a, _p, _d in SCOPE})
    if orphans:
        print(
            f"\n  WARNING: {len(orphans)} check(s) claim a gap08_area outside "
            f"the scope: {orphans}"
        )
        print("  The denominator is fixed; an area outside it counts for nothing.")

    print("\n  Deliberately out of scope (not in the denominator):")
    for item in OUT_OF_SCOPE:
        print(f"    - {item}")

    print("\n" + "-" * 78)
    print("SUPPORTING MEASUREMENTS")
    try:
        from core.checks.definitions import (
            DEFINITION_TYPE_PRIVILEGE_CHECK,
            definition_id_for_check,
        )
        from core.config_audit.builtin import BUILTIN_CHECKS

        privilege = [
            c
            for c in BUILTIN_CHECKS
            if c.finding_type == DEFINITION_TYPE_PRIVILEGE_CHECK
        ]
        by_severity: Dict[str, int] = {}
        for check in privilege:
            by_severity[check.severity] = by_severity.get(check.severity, 0) + 1
        print(f"  built-in checks total          : {len(BUILTIN_CHECKS)}")
        print(f"  minting CCURE-PRV- identifiers : {len(privilege)}")
        print(
            "  severity distribution          : "
            + ", ".join(
                f"{sev}={by_severity[sev]}"
                for sev in ("critical", "high", "medium", "low")
                if sev in by_severity
            )
        )
        if privilege:
            print(
                "  example identifier             : "
                + definition_id_for_check(
                    privilege[0].check_id, DEFINITION_TYPE_PRIVILEGE_CHECK
                )
            )
    except Exception as exc:  # pragma: no cover
        print(f"  (could not measure finding types: {exc})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
