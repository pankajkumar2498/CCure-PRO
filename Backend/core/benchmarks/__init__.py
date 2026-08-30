"""
core/benchmarks
─────────────────────────────────────────────────────────────────────────────
Hardening benchmarks as loadable content, on top of the Phase 3 engine.

Phase 4 of the Nessus capability gap-closure programme.

    BenchmarkPack (JSON) → compliance_frameworks / _controls / _rules
        → Phase 3 ConfigAuditEngine → Evidence → Verdict
        → compliance_findings → risk → remediation → report

Nothing here knows what CIS is. A CIS benchmark, a DISA STIG (Phase 5), a
vendor guide and an in-house baseline are all the same shape — a pack — which
is what stops Phase 5 editing the engine.

Why the content is not in this repository
─────────────────────────────────────────
Benchmark recommendation text, rationale and remediation belong to the
publisher, and CIS distributes theirs under a licence. Making content a file
the operator supplies means a customer with a CIS SecureSuite membership loads
the real document, unchanged, with no code change — and means this repository
never ships text it has no right to.

It also means nobody has to write benchmark content from memory. A rule
labelled with a benchmark's control number and an expected value somebody
recalled is a false compliance claim in a customer's audit report, which is a
worse failure than having no rule at all.

Module map
──────────
``pack``    the content format, and the parser that refuses to guess
``loader``  writing a pack into the tables the compliance engine already has
"""

from __future__ import annotations

from core.benchmarks.loader import (
    BENCHMARK_EVIDENCE_SOURCE,
    BENCHMARK_THEME,
    LoadResult,
    control_row_id,
    load_pack_into_db,
    rule_row_id,
)
from core.benchmarks.pack import (
    ASSESSMENT_STATES,
    BenchmarkControl,
    BenchmarkPack,
    BenchmarkProfile,
    PackError,
    discover_packs,
    dump_pack,
    load_pack,
    parse_pack,
)

__all__ = [
    "ASSESSMENT_STATES",
    "BENCHMARK_EVIDENCE_SOURCE",
    "BENCHMARK_THEME",
    "BenchmarkControl",
    "BenchmarkPack",
    "BenchmarkProfile",
    "LoadResult",
    "PackError",
    "control_row_id",
    "discover_packs",
    "dump_pack",
    "load_pack",
    "load_pack_into_db",
    "parse_pack",
    "rule_row_id",
]
