# CCure Audit PRO — Architecture Documentation Package

Technically accurate, implementation-derived architecture documentation for the
CCure Audit PRO platform. Every diagram and claim in this package is verified
against the current source tree (routers, models, migrations, Docker/compose
files, deployment scripts) as of **2026-08-27**, not inherited from prior
documentation. Where source and existing docs (`docs/*.md`, `CLAUDE.md`)
disagree, the disagreement is recorded rather than silently resolved. Anything
that could not be verified is marked **Not Verified** or **Requires
Confirmation** rather than assumed.

This package is additive to, not a replacement for, the existing `docs/*.md`
set (`SYSTEM_ARCHITECTURE.md`, `DATABASE_SCHEMA.md`, `BACKEND_API_REFERENCE.md`,
`AUTHENTICATION_AND_AUTHORIZATION.md`, `FRONTEND_ARCHITECTURE.md`,
`RBAC_Management_Permissions.md`, `SCAN_ENGINE_DEEP_DIVE.md`) — those remain the
authoritative deep-dive references and are linked from the relevant section
below rather than duplicated. This package's job is the things those documents
don't do: a single verified inventory, an enabled/disabled matrix, module and
dependency diagrams, consolidated security/audit/compliance architecture, a
traceability matrix, and a gaps register.

## Package index

| #   | Document                                               | Status   | Covers                                                                                                                                           |
| --- | ------------------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | [00_INVENTORY.md](00_INVENTORY.md)                     | **Done** | Architecture inventory (all components), enabled/disabled/parked matrix                                                                          |
| 2   | [01_MASTER_ARCHITECTURE.md](01_MASTER_ARCHITECTURE.md) | **Done** | Master system diagram, container/deployment architecture                                                                                         |
| 3   | 02_MODULE_ARCHITECTURE.md                              | Planned  | One diagram + traceability per enabled module (network scan, credentialed, web/DAST, compliance, audit, assets, dashboard, notifications, admin) |
| 4   | 03_MODULE_DEPENDENCIES.md                              | Planned  | Cross-module dependency graph, shared services, circular-dependency check                                                                        |
| 5   | 04_AUTH_ARCHITECTURE.md                                | Planned  | Authentication vs authorization, token lifecycle, RBAC — cross-referencing `docs/AUTHENTICATION_AND_AUTHORIZATION.md`                            |
| 6   | 05_DATABASE_ARCHITECTURE.md                            | Planned  | ER-level diagram, audit hash-chain/retention objects, triggers/functions — cross-referencing `docs/DATABASE_SCHEMA.md`                           |
| 7   | 06_DATA_FLOWS.md                                       | Planned  | End-to-end sequence diagrams for the major workflows                                                                                             |
| 8   | 07_AUDIT_ARCHITECTURE.md                               | Planned  | Full audit lifecycle: capture → chain → storage → retention → verification                                                                       |
| 9   | 08_COMPLIANCE_ARCHITECTURE.md                          | Planned  | Evidence pipeline, upload guard order of operations, rule evaluation                                                                             |
| 10  | 09_API_ARCHITECTURE.md                                 | Planned  | Endpoint groupings, auth/rate-limit posture — cross-referencing `docs/BACKEND_API_REFERENCE.md`                                                  |
| 11  | 10_SECURITY_ARCHITECTURE.md                            | Planned  | Every implemented control: where, what it protects, failure behavior                                                                             |
| 12  | 11_EXTERNAL_INTEGRATIONS.md                            | Planned  | Every external system, protocol, auth, failure/retry behavior                                                                                    |
| 13  | 12_OBSERVABILITY.md                                    | Planned  | Logging, health checks, monitoring — what exists and what doesn't                                                                                |
| 14  | 13_FAILURE_RECOVERY.md                                 | Planned  | Behavior under DB/Redis/container/network failure                                                                                                |
| 15  | 14_SEQUENCE_DIAGRAMS.md                                | Planned  | Critical-path sequence diagrams (login, scan lifecycle, compliance evidence upload, WS progress)                                                 |
| 16  | 15_TRACEABILITY_MATRIX.md                              | Planned  | Every architecture component → file/class/config/endpoint/DB object                                                                              |
| 17  | 16_FINDINGS.md                                         | Planned  | Consolidated gaps/discrepancies register (severity-ranked), rolling up G-1..G-n found throughout the package                                     |

## Methodology

1. **Source first.** Router files, models, migrations, `docker-compose.yml`,
   deployment scripts and Celery configuration were read directly, not
   summarized from memory or from other documentation.
2. **Documentation as one input, not the answer.** Existing `docs/*.md` and
   `CLAUDE.md` were treated as claims to verify, and several were found to have
   drifted from current source (see the Findings entries surfaced in
   [00_INVENTORY.md §7](00_INVENTORY.md#7-preliminary-findings-feeding-into-the-gaps-section-20r)
   — router count, beat schedule, migration count). Drift is recorded, not
   silently corrected in place in the older documents.
3. **Citations.** Claims are backed by file paths and, where practical, line
   numbers, so every diagram element is traceable back to the code that
   justifies it.
4. **Enabled vs. defined.** A component existing in `docker-compose.yml` or a
   router file is not the same as it running in this deployment. Every
   diagram distinguishes the two — see the runtime-topology note in
   [00_INVENTORY.md §1](00_INVENTORY.md#1-runtime-topology-as-it-actually-starts).
