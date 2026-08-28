"""
scripts/benchmarks/build_baseline_packs.py
─────────────────────────────────────────────────────────────────────────────
Generates the two CCURE hardening baseline packs from the Phase 3 built-in
rules.

    python -m scripts.benchmarks.build_baseline_packs [--check]

``--check`` regenerates in memory and reports whether the committed files
differ, without writing. That is what ``tests/compliance/test_benchmark_packs.py``
runs, so the JSON cannot drift from the rules it was generated from — the same
arrangement ``scripts/enrich_nist_csf_v2_seed.py`` has with its seed.

**Edit the rules in ``core/config_audit/builtin/``, or the crosswalk table
below. Never edit the generated JSON.**

Why these packs exist
─────────────────────
They are *not* CIS Benchmarks and must never be described as such. They are
CCURE's own hardening baseline, expressed in the benchmark pack format, for two
purposes:

  1. To exercise the whole Phase 4 path end to end — pack → framework →
     controls → rules → engine → evidence → verdict → compliance finding →
     risk → remediation → report — with content this project owns and can
     therefore ship.
  2. To show what a real benchmark pack looks like, so a licensed CIS
     Benchmark export can be converted into one.

The crosswalk targets *are* real: CIS Critical Security Controls v8.1
safeguards, taken from ``data/compliance_seeds/cis_v8_1_controls_seed.json``
which ships in this repository. ``--check`` verifies every crosswalk resolves
to a safeguard that exists, so a mistyped target cannot silently map to
nothing — the defect CLAUDE.md records for the thirteen dangling ISO
crosswalks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Run as `python -m scripts.benchmarks.build_baseline_packs` from Backend/, or
# directly. The insert covers the second case; `parents[2]` is Backend/ because
# this file is Backend/scripts/benchmarks/. Never spelled as a chain of
# `os.path.dirname` calls — CLAUDE.md records that a module's depth is not a
# constant here and the expression silently resolves somewhere else.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.compliance_seeds import seed_path  # noqa: E402
from core.config_audit.builtin import (  # noqa: E402
    LINUX_HOST_CHECKS,
    WINDOWS_HOST_CHECKS,
)

OUTPUT_DIR = Path(__file__).resolve().parents[2] / "data" / "benchmarks"

LICENCE = (
    "CCURE Audit PRO original content. Distributed with the product under its "
    "own licence. This is not a CIS Benchmark and must not be presented as one."
)

PROFILES = [
    {
        "id": "L1",
        "title": "Level 1 — settings a general-purpose host should meet",
    },
    {
        "id": "L2",
        "title": "Level 2 — defence in depth, may affect usability",
    },
]

#: check_id -> (section, control number, profiles, CIS v8.1 safeguard(s))
#:
#: The safeguard ids are real and are verified against the shipped v8.1
#: catalogue by ``--check``. The *numbering* on the left is this baseline's
#: own; it deliberately does not imitate any CIS Benchmark's numbering, because
#: a number that looks like a CIS recommendation but is not one is exactly the
#: false citation this phase refuses to produce.
WINDOWS_MAP: Dict[str, Tuple[str, str, List[str], List[str]]] = {
    "ccure.win.password.minimum_length": ("1 Account Policies", "1.1", ["L1"], ["5.2"]),
    "ccure.win.password.history": ("1 Account Policies", "1.2", ["L1"], ["5.2"]),
    "ccure.win.lockout.threshold": ("1 Account Policies", "1.3", ["L1"], ["5.2"]),
    "ccure.win.uac.enabled": ("2 Local Policies", "2.1", ["L1"], ["5.4"]),
    "ccure.win.lsa.restrict_anonymous_sam": (
        "2 Local Policies",
        "2.2",
        ["L2"],
        ["4.6"],
    ),
    "ccure.win.smbv1.server_disabled": ("3 Protocols", "3.1", ["L1"], ["4.8"]),
    "ccure.win.telnet.server_absent": ("3 Protocols", "3.2", ["L1"], ["4.8"]),
    "ccure.win.rdp.nla_required": ("4 Remote Access", "4.1", ["L1"], ["4.10"]),
    "ccure.win.remote_registry.not_running": (
        "4 Remote Access",
        "4.2",
        ["L2"],
        ["4.8"],
    ),
    "ccure.win.firewall.service_running": (
        "5 Host Firewall",
        "5.1",
        ["L1"],
        ["4.4", "4.5"],
    ),
}

LINUX_MAP: Dict[str, Tuple[str, str, List[str], List[str]]] = {
    "ccure.linux.password.max_age": ("1 Account Policies", "1.1", ["L1"], ["5.2"]),
    "ccure.linux.password.min_length": ("1 Account Policies", "1.2", ["L1"], ["5.2"]),
    "ccure.linux.ssh.permit_root_login": ("2 SSH Server", "2.1", ["L1"], ["5.4"]),
    "ccure.linux.ssh.password_authentication": (
        "2 SSH Server",
        "2.2",
        ["L2"],
        ["5.2"],
    ),
    "ccure.linux.ssh.max_auth_tries": ("2 SSH Server", "2.3", ["L1"], ["5.2"]),
    "ccure.linux.passwd.permissions": ("3 Filesystem", "3.1", ["L1"], ["3.3"]),
    "ccure.linux.shadow.permissions": ("3 Filesystem", "3.2", ["L1"], ["3.3"]),
    "ccure.linux.cron.permissions": ("3 Filesystem", "3.3", ["L1"], ["3.3"]),
    "ccure.linux.telnet.port_closed": ("4 Protocols", "4.1", ["L1"], ["4.8"]),
    "ccure.linux.auditd.running": ("5 Logging", "5.1", ["L1"], ["8.2"]),
}

#: Controls this baseline names but does not implement, so the pack exercises
#: the ``unimplemented`` assessment state and the coverage figures show a
#: genuine gap rather than a rounded-up one.
UNIMPLEMENTED = {
    "windows": [
        {
            "control_id": "6.1",
            "section": "6 Audit Policy",
            "title": "Advanced audit policy subcategories are configured",
            "profiles": ["L1"],
            "severity": "medium",
            "description": (
                "Windows advanced audit policy decides which security events "
                "reach the event log at all."
            ),
            "rationale": (
                "Without the subcategories configured, an investigation has no "
                "record of the actions it is trying to reconstruct."
            ),
            "remediation": (
                "Configure Advanced Audit Policy Configuration under Security "
                "Settings, and set the audit subcategories your logging "
                "standard requires."
            ),
            "crosswalk": ["CIS_V8_1:8.5"],
            "unimplemented_reason": (
                "auditpol output is collected as free text and is not yet "
                "parsed into per-subcategory settings, so no expected state "
                "can be compared against it."
            ),
        },
    ],
    "linux": [
        {
            "control_id": "6.1",
            "section": "6 Logging",
            "title": "auditd rules cover privileged command execution",
            "profiles": ["L2"],
            "severity": "medium",
            "description": (
                "The audit daemon running is necessary but not sufficient; it "
                "records only what its ruleset tells it to."
            ),
            "rationale": (
                "An auditd with no rules produces an empty trail while "
                "appearing healthy to every check that looks only at the "
                "service state."
            ),
            "remediation": (
                "Install an audit ruleset covering execve of privileged "
                "binaries and reload it with augenrules --load."
            ),
            "crosswalk": ["CIS_V8_1:8.5"],
            "unimplemented_reason": (
                "requires parsing and semantically comparing an auditd "
                "ruleset, which the command collector returns as raw text."
            ),
        },
    ],
}


def _control_from_check(check, mapping) -> dict:
    section, control_id, profiles, safeguards = mapping
    definition = check.to_check_definition()
    # The narrative lives on the control, not duplicated inside the check.
    for key in ("description", "rationale", "remediation", "references", "title"):
        definition.pop(key, None)
    return {
        "control_id": control_id,
        "section": section,
        "title": check.title,
        "assessment": "automated",
        "severity": (
            "info" if check.severity in ("none", "unscored") else check.severity
        ),
        "profiles": profiles,
        "description": check.description,
        "rationale": check.rationale,
        "remediation": check.remediation,
        "references": list(check.references),
        "crosswalk": [f"CIS_V8_1:{s}" for s in safeguards],
        "check": definition,
    }


def _build(platform: str, checks, mapping) -> dict:
    by_id = {c.check_id: c for c in checks}
    missing = [k for k in mapping if k not in by_id]
    if missing:
        raise SystemExit(
            f"{platform}: the crosswalk names check(s) that do not exist: {missing}"
        )
        # A stale mapping entry would silently produce a shorter benchmark.
    unmapped = [c.check_id for c in checks if c.check_id not in mapping]
    if unmapped:
        raise SystemExit(
            f"{platform}: built-in check(s) with no benchmark mapping: {unmapped}. "
            f"Add them to the table in this script — a check left out is a "
            f"control silently missing from the pack."
        )

    controls = [
        _control_from_check(by_id[check_id], mapping[check_id])
        for check_id in sorted(mapping, key=lambda k: mapping[k][1])
    ]
    controls.extend(
        {**entry, "assessment": "unimplemented"} for entry in UNIMPLEMENTED[platform]
    )
    controls.sort(key=lambda c: [int(p) for p in c["control_id"].split(".")])

    label = "Windows" if platform == "windows" else "Linux"
    return {
        "benchmark": {
            "code": f"CCURE_{platform.upper()}_BASELINE",
            "name": f"CCURE {label} Hardening Baseline",
            "version": "1.0.0",
            "platform": platform,
            "publisher": "CCURE Audit PRO",
            "licence": LICENCE,
            "profiles": PROFILES,
            "notes": (
                "Generated by scripts/benchmarks/build_baseline_packs.py from "
                "the built-in rules in core/config_audit/builtin/. Not a CIS "
                "Benchmark. Crosswalk targets are CIS Critical Security "
                "Controls v8.1 safeguards."
            ),
        },
        "controls": controls,
    }


def _known_safeguards() -> set:
    with open(seed_path("cis_v8_1_controls_seed.json"), encoding="utf-8") as fh:
        return {str(c["id"]) for c in json.load(fh)["controls"]}


def build_all() -> Dict[str, dict]:
    packs = {
        "windows": _build("windows", WINDOWS_HOST_CHECKS, WINDOWS_MAP),
        "linux": _build("linux", LINUX_HOST_CHECKS, LINUX_MAP),
    }
    known = _known_safeguards()
    dangling = []
    for pack in packs.values():
        for control in pack["controls"]:
            for target in control.get("crosswalk", []):
                code, _, safeguard = target.partition(":")
                if code == "CIS_V8_1" and safeguard not in known:
                    dangling.append(f"{control['control_id']} -> {target}")
    if dangling:
        raise SystemExit(
            "crosswalk target(s) that resolve to no CIS v8.1 safeguard: "
            + ", ".join(dangling)
            + ". A dangling crosswalk maps to nothing in gap analysis and in "
            "cross-framework rule inheritance, and does so silently."
        )
    return packs


def path_for(platform: str) -> Path:
    return OUTPUT_DIR / f"ccure_{platform}_baseline.benchmark.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift between the generator and the committed packs",
    )
    args = parser.parse_args()

    packs = build_all()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    drift = []

    for platform, pack in packs.items():
        rendered = json.dumps(pack, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        target = path_for(platform)
        if args.check:
            current = target.read_text(encoding="utf-8") if target.exists() else ""
            if current != rendered:
                drift.append(str(target))
        else:
            target.write_text(rendered, encoding="utf-8")
            print(
                f"wrote {target.name}: {len(pack['controls'])} controls "
                f"({sum(1 for c in pack['controls'] if c['assessment'] == 'automated')} "
                f"automated)"
            )

    if args.check and drift:
        print("Generated packs differ from the committed files:")
        for item in drift:
            print(f"  {item}")
        print("Run: python -m scripts.benchmarks.build_baseline_packs")
        return 1
    if args.check:
        print("committed packs match the generator")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
