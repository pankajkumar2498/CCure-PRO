"""
core/scap
─────────────────────────────────────────────────────────────────────────────
DISA STIG and SCAP content: read it, compile it, evaluate it against a host.

    SCAP datastream → XCCDF rules + OVAL definitions
        → compiled definition → ConfigCheck (check_type="scap_rule")
        → BenchmarkPack → compliance_frameworks/_controls/_rules
        → ConfigAuditEngine → PASS / FAIL / ERROR → finding → risk → report

Phase 10 of the gap-closure programme, closing GAP-05; tracker in
``docs/gap_closure/GAP_TRACKER.md``.

**No new engine, no new finding model, no new scan kind, no new route.** The
persistence cost of the whole phase is one value on one CHECK constraint
(migration ``c1d2e3f4a5b6``). Everything else was already here: a benchmark is
a framework, a rule is a check, a failed check is a finding.

What ships here is the *reader*, not the content
────────────────────────────────────────────────
No STIG is committed to this repository, and none needs to be. Unlike CIS
Benchmark text — which is licensed, which is why GAP-04 remains Partial — STIG
content is freely available: DISA publishes its SCAP benchmarks as US
Government works, and SCAP Security Guide publishes STIG profiles under
BSD-3-Clause. An operator fetches the content and loads it; nothing in the code
changes.

**A result from SSG's STIG profile is not a DISA certification.** SSG renders
the STIG's requirements as its own automated content; it is maintained against
the published STIG and is not the STIG. Every pack records its publisher,
licence, source and version for exactly this reason, and
``scripts/benchmarks/load_stig.py`` refuses to load content that does not
declare them.

Where the honesty lives
───────────────────────
``UnsupportedConstruct``. OVAL 5.11 defines well over a hundred tests; this
build evaluates ten, chosen by measuring which ones the available content
actually uses. A definition using anything else fails to compile, and the
converter records that control as ``unimplemented`` **with the reason**, so it
appears in the register, counts against the coverage figure, and can never be
mistaken for a control that passed.
"""

from __future__ import annotations

from typing import Set, Tuple

from core.scap.cci import NIST_FRAMEWORK_CODE, crosswalk_entries, parse_cci_list
from core.scap.evaluate import (
    DefinitionResult,
    Outcome,
    evaluate_applicability,
    evaluate_definition,
)
from core.scap.oval import (
    CRITERIA_OPERATORS,
    CompiledDefinition,
    OvalDocument,
    OvalError,
    SUPPORTED_TESTS,
    UnsupportedConstruct,
    parse_oval,
)
from core.scap.probes import PROBES, ProbeResult, collect_object
from core.scap.translate import ConversionReport, applies_to_from_platforms, to_pack
from core.scap.xccdf import (
    ScapContent,
    XccdfBenchmark,
    XccdfError,
    XccdfProfile,
    XccdfRule,
    XccdfValue,
    load_content,
    parse_content,
)

__all__ = [
    "CompiledDefinition",
    "ConversionReport",
    "DefinitionResult",
    "NIST_FRAMEWORK_CODE",
    "Outcome",
    "OvalDocument",
    "OvalError",
    "PROBES",
    "ProbeResult",
    "SUPPORTED_OPERATING_SYSTEMS",
    "SUPPORTED_TESTS",
    "ScapContent",
    "UnsupportedConstruct",
    "XccdfBenchmark",
    "XccdfError",
    "XccdfProfile",
    "XccdfRule",
    "XccdfValue",
    "applies_to_from_platforms",
    "collect_object",
    "crosswalk_entries",
    "evaluate_applicability",
    "evaluate_definition",
    "load_content",
    "parse_cci_list",
    "parse_content",
    "parse_oval",
    "supported_areas",
    "to_pack",
]

#: STIG content whose load *and* evaluation was validated against a real host
#: during Phase 10. Breadth, reported beside the coverage figure and never
#: folded into it — see ``scripts/measure_scap_coverage.py``.
#:
#: Deliberately not "every operating system SSG publishes a STIG profile for".
#: The reader is content-agnostic and would load all of them; these are the two
#: that were actually run, in both directions, against a host.
SUPPORTED_OPERATING_SYSTEMS: Tuple[str, ...] = ("rhel9", "ubuntu2404")


def supported_areas() -> Set[str]:
    """
    The GAP-05 areas this build actually implements.

    Every entry is decided by a **structural probe of the implementation**, not
    by membership of a list kept beside it. Delete ``_probe_rpminfo`` and
    ``scap.oval.rpminfo`` stops being claimed; drop ``refine_values`` from the
    profile model and ``scap.ingest.xccdf_value`` stops being claimed. A
    coverage figure that keeps reporting a capability after the code is gone is
    worse than no figure, and this is the mechanism that stops it.
    """
    from core.config_audit.collectors import (
        collector_registry,
        register_builtin_collectors,
    )
    from core.config_audit.spec import CHECK_TYPES
    from core.scap import evaluate as _evaluate
    from core.scap import oval as _oval
    from core.scap import probes as _probes
    from core.scap import translate as _translate
    from core.scap import xccdf as _xccdf

    areas: Set[str] = set()

    # ── Ingestion ────────────────────────────────────────────────────────────
    if hasattr(_xccdf, "_datastream_catalog") and callable(_xccdf.parse_content):
        areas.add("scap.ingest.datastream")
    if callable(getattr(_xccdf, "parse_benchmark", None)):
        areas.add("scap.ingest.xccdf_benchmark")
    if callable(getattr(XccdfBenchmark, "resolved_profile", None)):
        areas.add("scap.ingest.xccdf_profile")
    if callable(getattr(XccdfValue, "resolve", None)) and "refine_values" in getattr(
        XccdfProfile, "__dataclass_fields__", {}
    ):
        areas.add("scap.ingest.xccdf_value")
    rule_fields = getattr(XccdfRule, "__dataclass_fields__", {})
    if {"description", "rationale", "fixtext", "severity", "version"} <= set(
        rule_fields
    ):
        areas.add("scap.ingest.xccdf_metadata")
    if "idents" in rule_fields and hasattr(XccdfRule, "cci_ids"):
        areas.add("scap.ingest.stig_identity")
    if callable(parse_cci_list) and callable(crosswalk_entries):
        areas.add("scap.ingest.cci_map")
    if callable(parse_oval) and hasattr(OvalDocument, "compile_definition"):
        areas.add("scap.ingest.oval_document")
    if callable(getattr(_xccdf, "parse_cpe_platforms", None)) and callable(
        getattr(_evaluate, "evaluate_applicability", None)
    ):
        areas.add("scap.ingest.cpe_applicability")
    if "digest" in getattr(ScapContent, "__dataclass_fields__", {}) and (
        "expected_digest" in getattr(load_content, "__code__").co_varnames
    ):
        areas.add("scap.ingest.integrity")

    # ── OVAL evaluation ──────────────────────────────────────────────────────
    for test_type, area in SUPPORTED_TESTS.items():
        if test_type.replace("_test", "_object") in PROBES:
            areas.add(area)
    if set(CRITERIA_OPERATORS) == {"AND", "OR", "ONE", "XOR"} and callable(
        getattr(_evaluate, "_combine", None)
    ):
        areas.add("scap.oval.criteria_logic")
    existence = getattr(_evaluate, "_existence_holds", None)
    if existence is not None and all(
        existence(1, mode) is not None
        for mode in (
            "all_exist",
            "any_exist",
            "at_least_one_exists",
            "none_exist",
            "only_one_exists",
        )
    ):
        areas.add("scap.oval.check_existence")
    if callable(getattr(_evaluate, "_entity_check", None)):
        areas.add("scap.oval.check_attribute")
    operations = set(getattr(_oval, "_SUPPORTED_OPERATIONS", ()))
    if {"pattern match", "equals", "not equal", "greater than or equal"} <= operations:
        areas.add("scap.oval.state_operations")
    datatypes = set(getattr(_oval, "_SUPPORTED_DATATYPES", ()))
    if {"int", "string", "boolean", "version", "evr_string"} <= datatypes:
        areas.add("scap.oval.datatypes")
    if callable(getattr(OvalDocument, "_resolve_variables", None)):
        areas.add("scap.oval.variable_external")

    # ── Running content ──────────────────────────────────────────────────────
    if callable(to_pack):
        areas.add("scap.run.pack_conversion")
    if issubclass(UnsupportedConstruct, OvalError) and "scap_rule" in CHECK_TYPES:
        areas.add("scap.run.unsupported_not_assessed")
    register_builtin_collectors()
    if collector_registry.resolve("scap_rule", "linux") is not None:
        areas.add("scap.run.credentialed_execution")
        # A failed check reaches the ordinary finding path because the check's
        # finding_type is config_check and core.tasks builds findings from the
        # result — nothing GAP-05 adds.
        areas.add("scap.report.finding")
    if callable(applies_to_from_platforms):
        areas.add("scap.run.os_targeting")
    if "profile_id" in getattr(to_pack, "__code__").co_varnames:
        areas.add("scap.run.profile_selection")
    pack_fields = set(
        getattr(
            __import__(
                "core.benchmarks.pack", fromlist=["BenchmarkPack"]
            ).BenchmarkPack,
            "__dataclass_fields__",
            {},
        )
    )
    if {"publisher", "licence", "source_url", "version"} <= pack_fields:
        areas.add("scap.run.provenance")
    if callable(getattr(_probes, "_memo", None)):
        areas.add("scap.run.read_memoisation")

    return areas
