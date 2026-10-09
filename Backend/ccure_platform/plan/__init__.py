"""
Organisation plan and entitlements — platform-owned (Phase 8.4).

The project owner decided on 29 Sep 2026 that an organisation's plan, its scan
limits (quota), its authorised scan scope and its remediation SLA are the
platform's, not Audit's. CCure Audit consumes them and owns none of them
(``docs/architecture/PHASE8_4_ORGANISATION_PLAN.md``).

The rule every module here follows:

    The platform owns what an organisation is entitled to, and what it has
    configured. Each module owns how its own records are checked against it.

So this package holds entitlement *data* — the plans' defaults, each
organisation's overrides and settings, and who may change them — and never a
module's logic. It does not count scans, expand targets or compute due dates.

**Each feature is one module, and each is removable on its own.** None of these
is needed to run an assessment, and stakeholders may ask for any of them to go.

    catalogue.py        the plans                       (always present)
    scan_limits.py      quota: scans/day, concurrency, target and port size
    scan_scope.py       authorised scan ranges
    remediation_sla.py  the organisation's remediation deadlines

Each feature has exactly one consumer in Audit — its *seam* — and
``tests/repo/test_plan_feature_containment.py`` fails if a second one appears.
Removing a feature is therefore: its module here, its functions in
``ccure_platform.api``, and its seam. The removal recipe for each is in the
design document, §9.

The data still lives in the platform-owned ``organizations`` table (Option A:
no migration). Nothing outside this package reads those columns.
"""
