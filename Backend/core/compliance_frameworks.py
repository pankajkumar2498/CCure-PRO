"""
Module: core.compliance_frameworks
Purpose: One place that decides which compliance frameworks this installation
         actually offers.

Thirteen framework catalogues ship in `scripts/*_controls_seed.json`. Only two
are finished to production standard — ISO/IEC 27001:2022 and NIST CSF 2.0 — and
the other eleven are *parked*: seeded, kept current, crosswalk-reachable, but
not offered in the workspace and not scannable. They are brought back one at a
time as each is verified, by adding its id here or by setting
`COMPLIANCE_ACTIVE_FRAMEWORKS` in the environment.

Why an allow-list rather than deleting or un-seeding them
─────────────────────────────────────────────────────────
`main.py`'s bootstrap treats a missing framework as a catalogue to repair, and
its condition names all thirteen. Remove a seed file and that condition becomes
permanently true, so the whole seeder runs on every container start and can
never satisfy itself. The parked catalogues are also the *targets* of ISO's and
NIST's crosswalks — `/compliance/gap-analysis` and the rule mapper both read
them — so deleting the rows would degrade the two frameworks we are keeping.

Parking is therefore a visibility and enforcement decision, never a data one.
Nothing here deletes anything, and re-enabling a framework is one entry in this
list plus a re-run of `scripts/set_active_frameworks.py`.

Two layers, and both are needed
───────────────────────────────
`ComplianceTenantFramework.is_enabled` is the per-tenant switch the product
already honours on every working route — the register, scans, findings,
attestation, evidence, schedules, policies and the dashboard all filter on it.
`set_active_frameworks.py` writes that flag from this list.

This module is the *installation-wide* layer above it, and it exists because
the tenant flag alone leaves two holes: a tenant admin can re-install a parked
framework from the marketplace, and none of the thirteen report endpoints
checked enablement at all — `/compliance/reports/nis2` would render a PDF for a
framework the workspace does not show. `require_active_framework()` closes both.

`ComplianceFramework.is_active` is deliberately not used for this. It is a
column on the global catalogue that no query in the codebase has ever read, so
setting it would look like it worked and change nothing; it is left alone
rather than quietly repurposed.
"""

from __future__ import annotations

import os

# The frameworks this installation offers. Order is the order the workspace
# lists them in.
DEFAULT_ACTIVE_FRAMEWORK_IDS: tuple[str, ...] = (
    "cfw_iso27001_2022",
    "cfw_nist_csf_v2",
    # Activated by Phase 4. CIS Critical Security Controls v8.1 is the
    # framework a hardening benchmark's findings roll up into: a benchmark
    # recommendation crosswalks to a v8.1 safeguard, so leaving the safeguards
    # parked would give benchmark results nowhere to land.
    #
    # Note this is the *Controls*, not the *Benchmarks*. They are separate
    # publications: 153 governance safeguards here, per-platform hardening
    # recommendations there. Benchmark content is loaded as its own framework
    # by `core/benchmarks/loader.py` and is not seeded in this repository.
    "cfw_cis_v8_1",
)

# Every catalogue that ships, active or parked. Kept so callers can tell
# "parked" apart from "misspelled", which are very different answers to give a
# caller asking for a framework by id.
ALL_FRAMEWORK_IDS: tuple[str, ...] = (
    "cfw_iso27001_2022",
    "cfw_nist_csf_v2",
    "cfw_cis_v8_1",
    "cfw_soc2_type2",
    "cfw_cert_in_2022",
    "cfw_pci_dss_v4",
    "cfw_dpdp_2023",
    "cfw_gdpr",
    "cfw_nist_800_53_r5",
    "cfw_iec_62443",
    "cfw_nist_800_82_r3",
    "cfw_nerc_cip",
    "cfw_nis2",
)

# Framework id -> the `/compliance/reports/<slug>` endpoint that renders it, so
# the report guard can resolve a slug back to the framework it belongs to. The
# SoA is deliberately absent: it takes `framework_id` as a parameter and is
# guarded on that instead.
REPORT_SLUG_TO_FRAMEWORK: dict[str, str] = {
    "nist_csf": "cfw_nist_csf_v2",
    "cis_v8_1": "cfw_cis_v8_1",
    "soc2_type2": "cfw_soc2_type2",
    "cert_in_2022": "cfw_cert_in_2022",
    "pci_dss_v4": "cfw_pci_dss_v4",
    "dpdp_2023": "cfw_dpdp_2023",
    "gdpr": "cfw_gdpr",
    "nist_800_53_r5": "cfw_nist_800_53_r5",
    "iec_62443": "cfw_iec_62443",
    "nist_800_82": "cfw_nist_800_82_r3",
    "nerc_cip": "cfw_nerc_cip",
    "nis2": "cfw_nis2",
}


def _configured() -> tuple[str, ...]:
    """Reads the override, falling back to the default pair.

    Read per call rather than captured at import: the test suite and the
    framework-integration suites for the parked catalogues set this for the
    duration of a test, and a module-level constant would freeze whichever
    value happened to be set when the module was first imported.
    """
    raw = os.getenv("COMPLIANCE_ACTIVE_FRAMEWORKS")
    if raw is None:
        return DEFAULT_ACTIVE_FRAMEWORK_IDS

    ids = tuple(part.strip() for part in raw.split(",") if part.strip())
    # An empty or whitespace-only override would disable compliance entirely
    # and read as a configuration accident rather than an intention.
    return ids or DEFAULT_ACTIVE_FRAMEWORK_IDS


def active_framework_ids() -> tuple[str, ...]:
    """The frameworks this installation currently offers."""
    return _configured()


#: Framework ids created by ``core/benchmarks/loader.py`` carry this prefix.
#:
#: It is what separates *content the operator loaded* from *a catalogue that
#: ships with the product*. The parked/active mechanism exists because eleven
#: shipped catalogues are unfinished; it has nothing to say about a benchmark
#: somebody deliberately installed, and a loaded benchmark can never appear in
#: a hardcoded tuple anyway.
#:
#: A prefix rather than "anything not in ALL_FRAMEWORK_IDS": that reading would
#: make a misspelled framework id active, and the guard could no longer answer
#: 404 for one that does not exist.
BENCHMARK_FRAMEWORK_PREFIX = "cfw_bm_"


def is_benchmark_framework(framework_id: str | None) -> bool:
    """True for a framework created by loading a benchmark pack."""
    return bool(framework_id) and framework_id.startswith(BENCHMARK_FRAMEWORK_PREFIX)


def is_active(framework_id: str | None) -> bool:
    if not framework_id:
        return False
    if framework_id in _configured():
        return True
    # Loading a benchmark *is* the decision to use it. Requiring a second,
    # separate activation step would mean content that loads cleanly and then
    # silently scores nothing.
    return is_benchmark_framework(framework_id)


def is_known(framework_id: str | None) -> bool:
    """
    True for any catalogue that ships, whether active or parked, and for any
    loaded benchmark.

    The distinction the caller needs is "exists but is switched off" (403)
    versus "no such framework" (404), and a benchmark that was loaded exists.
    """
    if not framework_id:
        return False
    return framework_id in ALL_FRAMEWORK_IDS or is_benchmark_framework(framework_id)


def parked_framework_ids() -> tuple[str, ...]:
    active = set(_configured())
    return tuple(f for f in ALL_FRAMEWORK_IDS if f not in active)
