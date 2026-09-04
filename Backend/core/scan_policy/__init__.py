"""
core/scan_policy/
─────────────────────────────────────────────────────────────────────────────
The configurable scan policy engine. GAP-12; tracker §9P.

    ScanPolicy row ─resolve─> EffectivePolicy ─snapshot─> scans.options
                                    │
                                    ├─> benchmark_checks_for_org(framework_ids,
                                    │       profile, platforms, min_severity, …)
                                    ├─> select_checks(domains, excluded, …)
                                    ├─> run_credentialed_scan_task(sections=…)
                                    ├─> run_host_discovery_task(ports, intensity)
                                    └─> allow_intrusive_probes(…)

**There is no second scan engine here, and no second policy engine.** Every
module in this package decides *what* the existing pipeline assesses; none of
them assesses anything. A policy resolves to an ``EffectivePolicy``, that is
written into the scan's own row, and the existing tasks read it back.

Four modules, four jobs
───────────────────────
``spec``        the frozen ``EffectivePolicy`` and its fingerprint
``validation``  refusing an invalid policy, statically and at dispatch
``resolver``    policy + request → the configuration this scan will run
``snapshot``    writing it into ``scans.options`` and reading it back

Read ``spec`` first: it carries the two rules the rest depends on — a field
either changes assessment behaviour or is not here, and an empty collection
means "no restriction" rather than "nothing".
"""

from core.scan_policy.resolver import (  # noqa: F401
    PolicyResolution,
    ResolvedPolicyError,
    effective_for_request,
    resolve_policy,
)
from core.scan_policy.snapshot import (  # noqa: F401
    SNAPSHOT_KEY,
    policy_summary_rows,
    read_policy_snapshot,
    record_policy_snapshot,
    snapshots_agree,
)
from core.scan_policy.spec import (  # noqa: F401
    CHECK_FAMILIES,
    POLICY_SCAN_KINDS,
    SEVERITY_ORDER,
    EffectivePolicy,
    effective_from_config,
    next_version_number,
    policy_fingerprint,
    severity_at_least,
)
from core.scan_policy.validation import (  # noqa: F401
    PolicyValidationError,
    PolicyValidationResult,
    validate_for_dispatch,
    validate_policy,
)

__all__ = [
    "CHECK_FAMILIES",
    "EffectivePolicy",
    "POLICY_SCAN_KINDS",
    "PolicyResolution",
    "PolicyValidationError",
    "PolicyValidationResult",
    "ResolvedPolicyError",
    "SEVERITY_ORDER",
    "SNAPSHOT_KEY",
    "effective_for_request",
    "effective_from_config",
    "next_version_number",
    "policy_fingerprint",
    "policy_summary_rows",
    "read_policy_snapshot",
    "record_policy_snapshot",
    "resolve_policy",
    "severity_at_least",
    "snapshots_agree",
    "validate_for_dispatch",
    "validate_policy",
]
