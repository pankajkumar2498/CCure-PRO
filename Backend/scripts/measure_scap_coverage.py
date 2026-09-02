"""
scripts/measure_scap_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-05 coverage — DISA STIG / SCAP ingestion and evaluation.

    python -m scripts.measure_scap_coverage

Run before and after a change to get a comparable number.

What this denominator covers
────────────────────────────
**Taking published SCAP content — an XCCDF benchmark and the OVAL definitions
its rules check through — and evaluating it against a credentialed host**, so
that a STIG rule becomes an ordinary compliance verdict in this product's
existing register, findings queue and report.

It does **not** cover writing benchmark content. GAP-04 owns authored content
and remains ``Partial`` for the reason recorded there: CIS Benchmark text is
licensed and may not be committed. GAP-05 is the opposite case — the content is
somebody else's *and obtainable*, so the deliverable is the reader, not the
text.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Nineteen of the fifty-two areas below are real SCAP capabilities this build
does **not** perform. OVAL 5.11 defines well over a hundred tests across nine
platform schemas; a phase that implemented eight of them and then measured
itself against the eight it chose would report 100% and mean nothing.

The frozen list is set from **what the available STIG content actually uses**,
measured before implementation against SCAP Security Guide 0.1.81 (713 OVAL
fragments, 1,318 test elements). Each unimplemented area carries its reason.

A coverage figure is only worth reading if it can go down.

Three things are counted separately and must never be conflated
──────────────────────────────────────────────────────────────
``implemented``   the code supports it, read from its own dispatch tables
``tested``        an automated test names the area and exercises it
``validated``     it has produced a correct result against real STIG content
                  on a real host

**The headline coverage figure is implemented *and* tested.**

Content breadth is reported separately and never folded in
──────────────────────────────────────────────────────────
Supporting a construct is one area whether one benchmark uses it or six do.
The number of operating systems whose STIG content loads is reported beside
the figure, never inside it — the same rule Phase 7 applied to database
engines and Phase 9 to container runtimes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: The operating systems whose published STIG content this phase set out to
#: load and evaluate. Breadth, reported separately from coverage.
TARGET_OPERATING_SYSTEMS: Tuple[str, ...] = ("rhel9", "ubuntu2404")

#: (area id, theme, description). **Frozen at the start of Phase 10 and not to
#: be edited to match what was built.**
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Content ingestion ────────────────────────────────────────────────────
    (
        "scap.ingest.datastream",
        "ingest",
        "SCAP 1.2/1.3 source datastream: component and component-ref resolution",
    ),
    (
        "scap.ingest.xccdf_benchmark",
        "ingest",
        "XCCDF 1.2 Benchmark / Group / Rule tree",
    ),
    (
        "scap.ingest.xccdf_profile",
        "ingest",
        "XCCDF Profile selection, including profile inheritance (extends)",
    ),
    (
        "scap.ingest.xccdf_value",
        "ingest",
        "XCCDF Value definitions and per-profile refine-value overrides",
    ),
    (
        "scap.ingest.xccdf_metadata",
        "ingest",
        "Rule title, description, rationale, fixtext, severity, version",
    ),
    (
        "scap.ingest.stig_identity",
        "ingest",
        "STIG identity preserved: V-ID / rule id / SRG / CCI idents",
    ),
    (
        "scap.ingest.cci_map",
        "ingest",
        "CCI reference to NIST SP 800-53 control crosswalk",
    ),
    (
        "scap.ingest.oval_document",
        "ingest",
        "OVAL 5.11 definitions, tests, objects, states and variables",
    ),
    (
        "scap.ingest.integrity",
        "ingest",
        "Content digest recorded, and a mismatch against an expected one refused",
    ),
    (
        "scap.ingest.tailoring",
        "ingest",
        "XCCDF Tailoring file overriding profile selections and values",
    ),
    (
        "scap.ingest.ocil",
        "ingest",
        "OCIL questionnaires for rules the benchmark answers by interview",
    ),
    (
        "scap.ingest.cpe_applicability",
        "ingest",
        "CPE dictionary and inventory-OVAL platform applicability",
    ),
    # ── OVAL evaluation semantics ────────────────────────────────────────────
    (
        "scap.oval.criteria_logic",
        "oval",
        "criteria trees: AND / OR / ONE / XOR, with negation",
    ),
    (
        "scap.oval.check_existence",
        "oval",
        "check_existence: all_exist / any_exist / at_least_one_exists / "
        "none_exist / only_one_exists",
    ),
    (
        "scap.oval.check_attribute",
        "oval",
        "check: all / at least one / none satisfy, over collected items",
    ),
    (
        "scap.oval.state_operations",
        "oval",
        "state operations: pattern match, equals, not equal, <, <=, >, >=, "
        "case insensitive equals",
    ),
    (
        "scap.oval.datatypes",
        "oval",
        "datatypes: int, string, boolean, version, evr_string",
    ),
    (
        "scap.oval.textfilecontent54",
        "oval",
        "textfilecontent54: regular expression over a text file (68.2% of tests)",
    ),
    (
        "scap.oval.file",
        "oval",
        "unix file: existence, type, uid, gid and the individual mode bits",
    ),
    ("scap.oval.rpminfo", "oval", "rpminfo: RPM presence, version and EVR"),
    ("scap.oval.dpkginfo", "oval", "dpkginfo: dpkg presence and version"),
    ("scap.oval.xmlfilecontent", "oval", "xmlfilecontent: XPath over an XML file"),
    (
        "scap.oval.yamlfilecontent",
        "oval",
        "yamlfilecontent: YAML path over a YAML file",
    ),
    (
        "scap.oval.systemdunitproperty",
        "oval",
        "systemdunitproperty: a property of a systemd unit",
    ),
    ("scap.oval.family", "oval", "family: operating-system family targeting"),
    ("scap.oval.uname", "oval", "uname: kernel and release targeting"),
    (
        "scap.oval.variable_external",
        "oval",
        "external_variable and constant_variable, bound from XCCDF Values",
    ),
    (
        "scap.oval.variable_local",
        "oval",
        "local_variable components: object_component, concat, arithmetic, "
        "regex_capture, split, substring, count, unique",
    ),
    (
        "scap.oval.set_objects",
        "oval",
        "object <set>: union, intersection and complement composition",
    ),
    (
        "scap.oval.environmentvariable58",
        "oval",
        "environmentvariable58: a process's environment",
    ),
    (
        "scap.oval.selinuxsecuritycontext",
        "oval",
        "selinuxsecuritycontext: SELinux labels on files and processes",
    ),
    ("scap.oval.partition", "oval", "partition: mount points and mount options"),
    ("scap.oval.sysctl", "oval", "sysctl: kernel parameters"),
    (
        "scap.oval.shadow_password",
        "oval",
        "shadow and password: account ageing and hash fields",
    ),
    (
        "scap.oval.rpmverify",
        "oval",
        "rpmverifyfile and rpmverifypackage: package integrity",
    ),
    (
        "scap.oval.inetlisteningservers",
        "oval",
        "inetlisteningservers: listening sockets",
    ),
    ("scap.oval.interface", "oval", "interface: network interface state"),
    ("scap.oval.symlink", "oval", "symlink: symbolic-link targets"),
    ("scap.oval.filehash58", "oval", "filehash58: cryptographic hashes of files"),
    ("scap.oval.process58", "oval", "process58: running processes"),
    (
        "scap.oval.windows_tests",
        "oval",
        "the Windows OVAL schema: registry, wmi57, auditeventpolicy, userright, "
        "accesstoken and the rest",
    ),
    # ── Running content against a host ───────────────────────────────────────
    (
        "scap.run.pack_conversion",
        "run",
        "SCAP content converted into a Phase 4 benchmark pack, self-contained",
    ),
    (
        "scap.run.unsupported_not_assessed",
        "run",
        "an unsupported OVAL or XCCDF construct is not assessed, never a pass",
    ),
    (
        "scap.run.credentialed_execution",
        "run",
        "evaluated inside the existing credentialed host audit",
    ),
    (
        "scap.run.os_targeting",
        "run",
        "benchmark applies_to targeting, so RHEL content does not run on Ubuntu",
    ),
    (
        "scap.run.profile_selection",
        "run",
        "only the selected profile's rules are evaluated",
    ),
    (
        "scap.run.provenance",
        "run",
        "publisher, licence, source and version recorded and reportable",
    ),
    (
        "scap.run.read_memoisation",
        "run",
        "one read per distinct target object across the whole benchmark run",
    ),
    # ── Results ──────────────────────────────────────────────────────────────
    (
        "scap.report.finding",
        "report",
        "a failed rule becomes an ordinary finding on the existing path",
    ),
    ("scap.report.arf", "report", "ARF (Asset Reporting Format) result export"),
    ("scap.report.xccdf_results", "report", "XCCDF TestResult document export"),
    ("scap.report.stig_checklist", "report", "DISA STIG Viewer .ckl checklist export"),
)

#: Areas this build deliberately does not implement, each with its reason.
#: Present in the denominator so the figure reflects the real surface.
NOT_PLANNED: Dict[str, str] = {
    "scap.ingest.tailoring": (
        "a tailoring file customises a profile the operator already selected; "
        "it changes which rules run, not whether any of them can be evaluated, "
        "and no STIG ships one — it is a customer artefact"
    ),
    "scap.ingest.ocil": (
        "OCIL is a questionnaire for a human. The rules that use it are "
        "manual by nature and already land as manual controls through the "
        "XCCDF metadata, so an OCIL reader would add wording, not verdicts"
    ),
    "scap.oval.variable_local": (
        "191 of 276 local_variables in the measured corpus use "
        "object_component, which needs a second collection pass whose results "
        "feed the first. A rule using one is loaded as unimplemented with that "
        "reason rather than guessed at"
    ),
    "scap.oval.set_objects": (
        "object <set> composes the results of other objects, and like "
        "object_component needs multi-pass collection. 24 textfilecontent54 "
        "objects in the corpus use it"
    ),
    "scap.oval.environmentvariable58": (
        "reads the environment of a running process, which varies with how the "
        "process was started; five objects in the corpus and no stable "
        "expected value"
    ),
    "scap.oval.selinuxsecuritycontext": (
        "SELinux labels are meaningful only on a host with SELinux enforcing; "
        "the Ubuntu target uses AppArmor, so half the validation matrix could "
        "not exercise it"
    ),
    "scap.oval.partition": (
        "mount options are readable but the OVAL object addresses them through "
        "a mount-point enumeration with its own record datatype, which no "
        "other test in this phase needs"
    ),
    "scap.oval.sysctl": (
        "four objects in the corpus. The same settings are reached by the "
        "textfilecontent54 rules over /etc/sysctl.conf and sysctl.d, which are "
        "implemented"
    ),
    "scap.oval.shadow_password": (
        "the record datatype: one object yields a structured row per account "
        "and states address its fields. Supporting records is a data-model "
        "change, not one more probe"
    ),
    "scap.oval.rpmverify": (
        "rpm -V against every file of every package is minutes of target CPU "
        "and disk; this product scans production and OT hosts, where an audit "
        "that causes load is worse than the finding"
    ),
    "scap.oval.inetlisteningservers": (
        "listening sockets are already assessed by the Phase 3 port collector "
        "and by GAP-06 over the network; a third answer would be a third "
        "chance to disagree"
    ),
    "scap.oval.interface": (
        "two objects in the corpus, both about interface flags that are a "
        "runtime property rather than a configuration one"
    ),
    "scap.oval.symlink": (
        "seven objects in the corpus, all resolving a link to compare its "
        "target; useful but not load-bearing for any measured STIG rule"
    ),
    "scap.oval.filehash58": (
        "two objects. A hash comparison needs a known-good value, which STIG "
        "content does not publish"
    ),
    "scap.oval.process58": (
        "one object in the corpus. Running processes are collected already by "
        "the Phase 3 process collector"
    ),
    "scap.oval.windows_tests": (
        "no Windows STIG was validated in this phase and the Windows OVAL "
        "schema is a second, larger test family. Shipping it unvalidated is "
        "what this programme recorded as refused for IIS in Phase 8"
    ),
    "scap.report.arf": (
        "ARF is an exchange format for another tool to consume. This product's "
        "results already reach the register, the findings queue and the "
        "reports; ARF is an integration, not an assessment"
    ),
    "scap.report.xccdf_results": (
        "same reason as ARF. Worth having, and it is a reporting deliverable "
        "rather than a detection one"
    ),
    "scap.report.stig_checklist": (
        ".ckl is DISA STIG Viewer's format and carries a reviewer's own "
        "comments and status overrides, which is a workflow this product "
        "expresses through attestation instead"
    ),
}

#: Capabilities the *real content* turned out to use that the frozen
#: denominator did not name. None is implemented.
#:
#: The denominator is frozen, so these are **not** added to ``SCOPE``. They are
#: reported separately, and a second coverage figure is printed against the
#: corrected total — which is lower, and is the honest one. Recording them here
#: rather than editing ``SCOPE`` keeps both facts available: what was predicted
#: before implementation, and what measurement then showed the surface actually
#: to be.
DISCOVERED_AFTER_FREEZE: Dict[str, str] = {
    "scap.oval.systemdunitdependency": (
        "systemdunitdependency_test — 9 rules in the RHEL 9 STIG profile and 5 "
        "in Ubuntu 24.04. Not implemented: it enumerates a unit's transitive "
        "Wants/Requires closure, which is a different question from the "
        "property read that scap.oval.systemdunitproperty answers"
    ),
    "scap.ingest.sce": (
        "the OpenSCAP Script Check Engine — 2 rules in the Ubuntu 24.04 STIG "
        "profile. Not implemented, and would not be: SCE runs a shell script "
        "supplied by the content on the target, which is arbitrary code "
        "execution from a downloaded file and the opposite of the boundary "
        "every probe in this phase is written to keep"
    ),
}

#: Named so the exclusion is visible rather than silent.
OUT_OF_SCOPE = (
    "authoring benchmark content — GAP-04, which remains Partial for licensing",
    "CIS Benchmark content, which may not be committed to this repository",
    "OVAL as a patch-advisory feed (RHEL/Ubuntu/SUSE OVAL) — the package "
    "matching path already answers that through OSV and CSAF",
    "SCAP validation programme conformance (NIST SCAP 1.3 validated product)",
    "the operating system's own hardening rules authored by CCURE — GAP-03",
    "remediation script generation from XCCDF fix elements",
)


# ─────────────────────────────────────────────────────────────────────────────
# Windows
# ─────────────────────────────────────────────────────────────────────────────
#
# `SCOPE` above is frozen at the start of Phase 10 and says so. It deliberately
# excluded the Windows OVAL schema, because no Windows STIG had been validated
# and shipping one unvalidated is what Phase 8 recorded as refused for IIS.
# Windows therefore gets its own denominator rather than an edit to that one.
#
# **Derived from the content, before anything was built.** The DISA Microsoft
# Windows 11 STIG V2R10 (SCAP 1.3, MAC-2_Classified) was converted first and
# reported 219 controls, 0 automated, 0.0% — and named the ten Windows OVAL
# test types its rules use, with the rule count each costs. Those ten are the
# denominator. Nothing was added to it afterwards to flatter the result, and
# the four that are still unimplemented are listed with what they cost.

#: (area id, theme, description). Frozen from the pre-implementation tally.
WINDOWS_SCOPE: Tuple[Tuple[str, str, str], ...] = (
    (
        "scap.oval.registry",
        "windows",
        "windows:registry_test — one registry value (117 of 219 rules)",
    ),
    (
        "scap.oval.auditeventpolicysubcategories",
        "windows",
        "windows:auditeventpolicysubcategories_test — audit policy (43 rules)",
    ),
    (
        "scap.oval.userright",
        "windows",
        "windows:userright_test — who holds a privilege (25 rules)",
    ),
    (
        "scap.oval.wmi57",
        "windows",
        "windows:wmi57_test — a WQL query returning records (15 rules)",
    ),
    (
        "scap.oval.passwordpolicy",
        "windows",
        "windows:passwordpolicy_test — local password policy (7 rules)",
    ),
    (
        "scap.oval.lockoutpolicy",
        "windows",
        "windows:lockoutpolicy_test — account lockout policy (3 rules)",
    ),
    (
        "scap.oval.fileeffectiverights53",
        "windows",
        "windows:fileeffectiverights53_test — effective ACL on a path (3 rules)",
    ),
    (
        "scap.oval.ntuser",
        "windows",
        "windows:ntuser_test — per-user registry under HKU (3 rules)",
    ),
    (
        "scap.oval.sid_sid",
        "windows",
        "windows:sid_sid_test — group membership by SID (2 rules)",
    ),
    (
        "scap.oval.user_sid55",
        "windows",
        "windows:user_sid55_test — local account flags by SID (1 rule)",
    ),
)

#: Why the four that remain are not implemented. Each states what it costs, so
#: the figure below can be read as a decision rather than an omission.
WINDOWS_NOT_IMPLEMENTED: Dict[str, str] = {
    "scap.oval.fileeffectiverights53": (
        "resolving an effective ACL means expanding group membership and "
        "inherited ACEs into a per-trustee answer; every object in the measured "
        "corpus also composes filepaths with <set>, which needs the second "
        "collection pass this build does not make. 3 of 219 rules"
    ),
    "scap.oval.ntuser": (
        "reads HKEY_USERS for *each loaded profile*, so the item set depends on "
        "who is logged in at scan time — a rule whose answer changes with the "
        "session count needs a defined policy before it can be a verdict. "
        "3 of 219 rules"
    ),
    "scap.oval.sid_sid": (
        "group membership expanded transitively by SID. The measured rules pair "
        "it with <set> composition, so implementing the probe alone would not "
        "make them evaluable. 2 of 219 rules"
    ),
    "scap.oval.user_sid55": (
        "local account flags by SID; needs SAMR enumeration this build does not "
        "perform over either Windows transport. 1 of 219 rules"
    ),
}


def windows_area_ids() -> Tuple[str, ...]:
    return tuple(area for area, _, _ in WINDOWS_SCOPE)


def windows_coverage() -> Tuple[int, int, float]:
    """(implemented, total, percent) over the frozen Windows denominator."""
    total = len(WINDOWS_SCOPE)
    implemented = total - len(WINDOWS_NOT_IMPLEMENTED)
    return implemented, total, round(100.0 * implemented / total, 1)


def _capabilities() -> Set[str]:
    """
    Areas the code supports, read from the live registries.

    Read from the implementation's own dispatch tables rather than a list kept
    beside them — a list keeps saying "implemented" after the code it describes
    is removed, which is exactly the failure a coverage figure must not have.
    """
    try:
        from core.scap import supported_areas
    except Exception as exc:  # pragma: no cover - import guard
        print(f"  (core.scap not importable yet: {exc})")
        return set()
    return set(supported_areas())


def _tested() -> Set[str]:
    """Areas an automated test names, read from the test sources."""
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for pattern in ("test_scap*.py", "test_stig*.py"):
        for path in root.rglob(pattern):
            corpus += path.read_text(encoding="utf-8")
    return {area for area, _t, _d in SCOPE if area in corpus}


def _loadable_operating_systems() -> List[str]:
    try:
        from core.scap import SUPPORTED_OPERATING_SYSTEMS
    except Exception:  # pragma: no cover
        return []
    return sorted(SUPPORTED_OPERATING_SYSTEMS)


def main() -> int:
    implemented = _capabilities()
    tested = _tested()
    not_planned = set(NOT_PLANNED)

    areas = [a for a, _t, _d in SCOPE]
    total = len(areas)

    # A denominator that quietly grew to match the implementation is the one
    # failure this whole file exists to prevent.
    unknown = implemented - set(areas)
    if unknown:
        print(
            f"!! the code claims area(s) not in the frozen denominator: "
            f"{sorted(unknown)}\n"
            f"   Either the area belongs in SCOPE and the denominator was "
            f"wrong, or the claim is wrong. Do not add it to make the number "
            f"go up.\n"
        )

    both = [a for a in areas if a in implemented and a in tested]

    print("=" * 78)
    print("GAP-05 — DISA STIG / SCAP ingestion and evaluation")
    print("=" * 78)
    print()

    by_theme: Dict[str, List[Tuple[str, str]]] = {}
    for area, theme, desc in SCOPE:
        by_theme.setdefault(theme, []).append((area, desc))

    for theme in ("ingest", "oval", "run", "report"):
        rows = by_theme.get(theme, [])
        print(f"── {theme} " + "─" * (72 - len(theme)))
        for area, desc in rows:
            if area in not_planned:
                mark = "  —  "
            elif area in implemented and area in tested:
                mark = " [x] "
            elif area in implemented:
                mark = " [~] "
            else:
                mark = " [ ] "
            print(f"{mark}{area:38s} {desc[:62]}")
        done = len([a for a, _d in rows if a in implemented and a in tested])
        print(f"      {done}/{len(rows)} implemented and tested\n")

    print("legend: [x] implemented and tested   [~] implemented, untested")
    print("        [ ] not implemented          —   not planned (reason below)")
    print()

    print("── not planned, with reasons " + "─" * 49)
    for area in areas:
        if area in not_planned:
            print(f"  {area}")
            print(f"      {NOT_PLANNED[area]}")
    print()

    print("── found after the denominator was frozen " + "─" * 36)
    for area, reason in DISCOVERED_AFTER_FREEZE.items():
        print(f"  {area}")
        print(f"      {reason}")
    print()

    print("── out of scope entirely " + "─" * 53)
    for line in OUT_OF_SCOPE:
        print(f"  · {line}")
    print()

    pct = 100.0 * len(both) / total if total else 0.0
    print("=" * 78)
    print(f"  areas in the frozen denominator        : {total}")
    print(f"  not planned (reason recorded)          : {len(not_planned)}")
    print(f"  implemented                            : {len(implemented & set(areas))}")
    print(f"  implemented AND tested                 : {len(both)}")
    print(f"  GAP-05 coverage                        : {pct:.1f}%")
    print("-" * 78)
    corrected_total = total + len(DISCOVERED_AFTER_FREEZE)
    corrected = 100.0 * len(both) / corrected_total if corrected_total else 0.0
    print(f"  areas found after the freeze           : {len(DISCOVERED_AFTER_FREEZE)}")
    print(f"  corrected denominator                  : {corrected_total}")
    print(f"  GAP-05 coverage, corrected             : {corrected:.1f}%")
    print("=" * 78)
    print()

    oses = _loadable_operating_systems()
    print(f"  STIG content validated against         : {', '.join(oses) or '(none)'}")
    print(
        "  Content breadth is reported here and never folded into the figure "
        "above:\n"
        "  supporting a construct is one area whether one benchmark uses it or "
        "six do."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
