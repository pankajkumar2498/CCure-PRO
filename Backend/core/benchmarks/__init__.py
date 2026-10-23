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
``pack``       the content format, and the parser that refuses to guess
``loader``     writing a pack into the tables the compliance engine already has
``selection``  which benchmark checks apply to a scan, read from those tables

``loader`` and ``selection`` are compliance's catalogue code, and since G4 they
live in ``core/compliance_catalogue/``; the two names here are aliases of those
modules, kept for existing imports.

The package exports the ``pack`` names only. ``loader`` and ``selection`` need
the database, so they are imported by name (``from core.benchmarks.loader
import load_pack_into_db``). Re-exporting the loader here made every import of
the package load SQLAlchemy and the model registry, the SCAP compiler's
included, since importing ``core.benchmarks.pack`` runs this file first (B4,
docs/architecture/MODULAR_REFACTORING_LOG.md §6).
"""

from __future__ import annotations

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
    "BenchmarkControl",
    "BenchmarkPack",
    "BenchmarkProfile",
    "PackError",
    "discover_packs",
    "dump_pack",
    "load_pack",
    "parse_pack",
]
