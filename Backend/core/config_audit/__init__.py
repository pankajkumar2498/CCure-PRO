"""
core/config_audit
─────────────────────────────────────────────────────────────────────────────
The generic configuration audit engine.

    Configuration Rule → Evidence Collector → Expected State → Actual State
        → PASS / FAIL / MANUAL / N/A → Finding → Risk → Remediation
        → Compliance / Reporting

Phase 3 of the Nessus capability gap-closure programme. It is the reusable
foundation the benchmark phases sit on — CIS (Phase 4), STIG/SCAP (Phase 5),
application (Phase 9), database (Phase 10), network device (Phase 11) and
cloud (Phase 16) all contribute *rules*, not engines.

What is deliberately not here
─────────────────────────────
No benchmark, no vendor name, no CIS or STIG identifier appears in any module
of this package. The moment the engine knows which benchmark it is running,
adding the next one means editing the engine.

Nor is there a second compliance engine. Rules live in ``compliance_rules``
alongside the ones that were already there; verdicts land in
``compliance_findings`` under the statuses that column already accepts; and a
failing check becomes an ordinary ``StandardizedFinding`` that flows through
the existing normalizer, risk model and report generators. See
``core/config_audit/findings.py`` for both joins.

Module map
──────────
``spec``        what a check *is* — the declarative rule, and its adapter to
                and from ``compliance_rules.check_definition``
``collection``  what a collector *returns* — the four-state result whose
                separation the whole engine turns on
``collectors``  how each check type is read, per platform
``operators``   the comparison vocabulary, shared with the compliance engine
``engine``      the pipeline, and the outcome table
``findings``    where results join the finding and compliance models
``builtin``     a small set of real host rules, so the engine ships exercised
"""

from __future__ import annotations

from core.config_audit.collection import (
    CollectedState,
    CollectionContext,
    CollectionStatus,
)
from core.config_audit.collectors import (
    collector_registry,
    register_builtin_collectors,
)
from core.config_audit.engine import (
    ConfigAuditEngine,
    ConfigAuditReport,
    select_checks,
)
from core.config_audit.operators import (
    COMPARISON_OPERATORS,
    ComparisonOutcome,
    evaluate,
    evaluate_detailed,
)
from core.config_audit.spec import (
    CHECK_TYPES,
    PLATFORMS,
    AbsencePolicy,
    ConfigCheck,
    Expectation,
    SpecError,
)

__all__ = [
    "CHECK_TYPES",
    "COMPARISON_OPERATORS",
    "PLATFORMS",
    "AbsencePolicy",
    "CollectedState",
    "CollectionContext",
    "CollectionStatus",
    "ComparisonOutcome",
    "ConfigAuditEngine",
    "ConfigAuditReport",
    "ConfigCheck",
    "Expectation",
    "SpecError",
    "collector_registry",
    "evaluate",
    "evaluate_detailed",
    "register_builtin_collectors",
    "select_checks",
]

# The engine is useless without collectors, and a caller that forgets to
# register them gets ERROR on every check — technically correct and
# indistinguishable from a genuinely unreachable host. Registering at import
# makes the working configuration the default one.
register_builtin_collectors()
