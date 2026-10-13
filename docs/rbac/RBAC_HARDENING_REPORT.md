# RBAC hardening review — 12 October 2026

See [final release validation](RBAC_RELEASE_READINESS.md) for subsequent real
frontend/backend testing, current verification results, image remediation and the
coordinated application-artifact rollback plan. No merge or deployment was performed.

## Scope and review basis

Changes are prepared in `/tmp/ccure-rbac-phases-20261012`, isolated from the running
API's source mount, based on repository commit `08ff49e`. No production records,
credentials, migrations, services or deployment were changed. PostgreSQL 18 test
containers are on a separate network with explicitly named `pytest_*` databases.
Their backups were verified before destructive fixtures. Final tests use a restricted
application database role; audit-chain tests run separately from schema-reset tests.

The original investigation established the plan before implementation. The subsequent
user authorization approved phases 1–6 and explicitly selected immutable system roles
for Phase 4. Changes retain the native catalogue, grants, engine, tenant boundaries,
role IDs, assignment history and append-only revisions. No new permission keys or
application database structures were introduced.

## Root cause and affected components

The original deployment's existing roles were the five code-managed system roles.
Backend governance and the frontend intentionally refuse edits to those permission sets.
Org Admin's predefined grants also omit custom-role creation/update authority. These
are governance restrictions, rather than an inability of the database to update custom
role grants. Active custom roles already supported in-place changes through the API.

The investigation also found genuine defects: last-administrator checks were absent
from permission removal and account deactivation/deletion; assignment/role continuity
checks could race; compatibility assignment APIs omitted step-up; tenant hints could
silently redirect writes; full-set permission updates had no revision precondition;
non-escalation role denials were not audited; the UI omitted explicit creation context
and authorization refresh; assignment controls conflated scope-specific authority.
Final review additionally found empty-role replacement bypassing assignment authority
and stale organisation assignments after account transfer. Those are now governed.
The final tenant-lifecycle review also caught archival flushing `archived_at` before
the continuity baseline and reading tenant membership before acquiring the lock. Five
regressions cover archival/deactivation refusals, allowed operations with another
administrator, and membership changes while waiting for the lock. The two exposed
defects were reproduced before correction; membership is now read under the lock and
archival checks run before any archival state change.

## Phase results and changed files

| Phase | Result                                                                                                                                                                                                                | Changed implementation and evidence                                                                                                                                      |
| ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1     | Continuity lock/checks, consistent step-up and strict write context; system grants unchanged. 162 focused backend tests and 106 architecture/identity tests passed.                                                   | `Backend/ccure_platform/rbac/{administration,governance}.py`; `administration/{rbac_admin,rbac_security,users,organizations}.py`; role-management tests and API contract |
| 2     | Required permission revision, serialized fresh authority, atomic revision/audit and durable governed denials. 184 catalogue/lifecycle/management tests passed, then 82 management tests after shared denial auditing. | RBAC administration/catalogue/audit, shared/API security, compatibility APIs, `Backend/main.py`, management regressions                                                  |
| 3     | Custom-role edits keep IDs, send revision/context, explain conflicts and refresh effective authorization. 39 frontend and 83 backend tests passed.                                                                    | `Frontend/src/shell/admin/pages/RoleManagement.jsx`, `shell/api/rbac.js`, `shell/auth/AuthContext.jsx`, UI/backend tests and frontend authorization inventory            |
| 4     | Approved immutable system grants; existing platform rename/retire, replacement, continuity and recovery retained. 196 system/lifecycle/catalogue/tool tests passed.                                                   | Governance documentation and all-five-system-role security regressions                                                                                                   |
| 5     | Scope-specific assignment controls, delegation metadata, required replacement authority, transfer revocation and membership matching. 148 backend tests plus two denial cases and 43 UI tests passed.                 | RBAC administration/resolver, management/user APIs, permission editor, assignment panel, role page, UI/backend regressions                                               |
| 6     | Exact declaration/database/API coverage, module enforcement, audit-chain verification and current documentation. Final totals are recorded below.                                                                     | Coverage regression; refreshed API/backend/frontend inventories; current RBAC docs; stale migration-head test and foreign-context expectation corrected                  |

Python formatting/lint, high-severity Bandit, frontend lint and patch checks were used
throughout. The initial broad frontend run lacked the prerequisite production build;
the initial broad backend run detected stale generated inventory, an obsolete migration
head assertion, an intentionally changed tenant-fallback expectation and an ambiguous
permission-row variable caught by the role-identity guard. They were corrected without
relaxing security guards. Audit-chain tests skipped after destructive schema fixtures
removed their infrastructure; their final verification uses a dedicated scratch target.

## Permission coverage

The implementation declares 69 permissions: Common Platform 32, Audit 37, organisation
scope 50 and platform scope 19; 33 privileged and four continuity permissions. The
catalogue API is compared exactly with database rows and enabled-module declarations.
Platform catalogue readers can inspect all 69. Organisation readers receive all 50
organisation-scoped entries, bounded by status and delegation for selection. The UI
renders the returned catalogue; no separate hardcoded permission list exists.
Policy Pro and Rank have empty disabled manifests and frontend placeholders; no real
capabilities are omitted from their local catalogues. IR is a separate service/database
and its internal APIs, schema, tokens and enforcement remain outside this verification.
The exact 69-key list and sources are in `docs/RBAC_Management_Permissions.md`.

## API and operational compatibility

Permission PUT requests must include `expected_revision` from role detail. Missing
revisions return 428; stale revisions 409; the UI reloads on a conflict. Body/query
organisation conflicts return 400, unauthorized explicit write context 403. Silent read
fallback keeps its existing contract. Organisation transfers revoke old organisation
assignments with the existing `manual` reason category and the precise transfer reason
in audit data; destination roles require a separate authorized assignment. No new enum,
permission, table, index or migration is needed. Other clients must adopt the revision
precondition and coordinate their selected tenant with writes.

The existing `enforce` MFA mode still permits unenrolled administrators with a recorded
`not_enrolled` outcome. All enrolled sensitive operations now use the same current-code
check; missing/wrong codes and required-enrollment failures are audited. Mandatory MFA
requires enrollment/recovery preparation and an explicit deployment policy change.
Backend permission changes are enforced on the next request. Other browsers can show
old controls until the existing refresh or reload; those controls cannot authorize an
operation the backend now denies. No push/realtime feature was added.

Continuity checks prevent _new_ violations, preserving the existing bootstrap/recovery
model. Existing continuity problems require governed remediation; they are not silently
rewritten. Account transfer is conservative about administrator continuity and can
require another viable administrator before moving a privileged account. A global
transaction lock deliberately favors correctness; management writes are serialized and
should be kept short. Direct database writes can bypass application governance and are
not supported. Independent services and manually operated privileged scripts need their
own deployment-specific review.

## Reviewable deployment and rollback plan

Review the worktree diff, API contract and this test evidence before deploying. Deploy
backend and frontend together: a new UI's revision field is rejected by the old strict
body schema, and an old UI is refused by the new precondition. Existing IDs and records
need no conversion. Do not run a broad RBAC migration or edit production mappings.
After deployment, verify one authorized custom-role edit and a denied edit, current
user authorization, unchanged system grants, revision history and corresponding tenant/
platform audit events in an approved non-production smoke environment first.

Rollback is a coordinated application-artifact rollback, not a database restore or
history deletion. Freeze administrative writes during a rollback and preserve completed
grant/revision/audit records; the old architecture reads the same tables. Reverting to
the old backend restores the original security gaps, so rollback is containment until
the hardened artifacts can be restored. Production rollback/deployment was not performed.
Disposable test infrastructure is removed after verification; its cleanup cannot reach
production. No production database rollback procedure is required for this code-only
change, and any future schema migration still requires a separate reviewed/tested plan.

## Final verification

These are the original phase-closeout runs; overlapping focused suites are not added
to broad-suite totals. The subsequent [pre-merge review](RBAC_PREMERGE_REVIEW.md)
closes the three verification gaps below and records the current results.

| Verification                                                                                                                                                           | Result                                                        | Evidence                                                              |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------- |
| Complete frontend unit suite                                                                                                                                           | 3,138 passed, no failures                                     | `/tmp/ccure-rbac-unit-results.json`; `/tmp/ccure-rbac-unit-tests.log` |
| Chromium browser gate                                                                                                                                                  | 236 passed                                                    | `/tmp/ccure-rbac-browser-tests.log`                                   |
| Backend RBAC, module/API enforcement and architecture suite                                                                                                            | 902 passed, four initial skips                                | `/tmp/ccure-rbac-backend-tests.log`                                   |
| Missing-mount source/identity checks rerun with Frontend and CODEOWNERS mounted                                                                                        | 43 passed                                                     | `/tmp/ccure-rbac-source-checks.log`                                   |
| Dedicated audit suite with existing privileged chain/retention bootstrap on scratch DB                                                                                 | 405 passed, two historical-data skips                         | `/tmp/ccure-rbac-audit-tests.log`                                     |
| Final permission/lifecycle check after denied-audit hardening                                                                                                          | 99 passed; subsequent reset-tool check failed                 | `/tmp/ccure-rbac-final-targeted-tests.log`                            |
| Final tenant-lifecycle correction and affected security/contract suites                                                                                                | 269 passed; two missing-mount hook checks subsequently passed | `/tmp/ccure-rbac-lifecycle-final.log`                                 |
| Production frontend build; UX4G assets, dependency pin and architecture; frontend lint/inventory; Python Black/Ruff/high-severity Bandit; OpenAPI/inventory generation | Passed                                                        | Pinned versions and repository commands; no guard relaxed             |

The OpenAPI-hook rerun passed all four checks after mounting the hook source at
its configured repository path (`/tmp/ccure-rbac-contract-source-final.log`).
The final affected run includes all 104 role-management tests, including the five
new tenant-lifecycle regressions.

The broad backend run used `tests/rbac/`, the relevant security, report, web, topology,
scan-continuation and module tests, and the architecture/RBAC boundary suites. The final
affected run uses management, governance, role lifecycle, tenant isolation/deactivation,
RBAC identity/final-ratchet and OpenAPI-hook tests. The dedicated audit run uses all of
`tests/audit/`. Every database test targeted disposable PostgreSQL, not the application
database. The final suites ran as a non-superuser application role. Browser tests used
the repository synthetic API harness. Firefox/WebKit nightly runs were not executed.

**Unresolved checks and operational limits:**

- The original reset-head mismatch is corrected by explicitly reviewing and pinning
  the current three heads. Read-only gate tests reject stale, missing and unknown
  heads. Destructive reset and legacy migration execution remain excluded as
  requested; passing the gate is not an approval to run reset.
- Both originally skipped historical audit checks now have deterministic isolated
  fixtures and pass: schema-move hash preservation and authoritative pre-chain
  out-of-band deletion detection. App-role privileges remain restricted; only
  separate scratch DBA setup invokes the protected seed/bootstrap.
- IR's independent service requires separate verification. Policy Pro and Rank have
  no implemented local capabilities to verify or add permissions for.
- The existing MFA policy allows unenrolled administrators as described above.
  Mandatory enrollment and realtime cross-browser UI refresh were not added.

No skipped, deselected or failed check is counted as passed. No migration or
production database mutation was needed. The pre-merge report documents the
remaining reset execution limit and the required MFA deployment decision.

## Complete changed-file list

Backend implementation:

- `Backend/ccure_platform/administration/organizations.py`
- `Backend/ccure_platform/administration/rbac_admin.py`
- `Backend/ccure_platform/administration/rbac_security.py` (new)
- `Backend/ccure_platform/administration/users.py`
- `Backend/ccure_platform/rbac/administration.py`
- `Backend/ccure_platform/rbac/audit.py`
- `Backend/ccure_platform/rbac/catalogue.py`
- `Backend/ccure_platform/rbac/governance.py`
- `Backend/ccure_platform/rbac/resolver.py`
- `Backend/main.py`

Backend contract, inventory and regressions:

- `Backend/data/rbac/authorization_migration_inventory.json`
- `Backend/openapi.json`
- `Backend/tests/rbac/test_rbac_administration.py`
- `Backend/tests/rbac/test_rbac_schema.py`
- `Backend/tests/security/test_tenant_isolation_admin.py`

Frontend:

- `Frontend/authorization-inventory.json`
- `Frontend/src/__tests__/shell/admin/components/UserRolesPanel.test.jsx`
- `Frontend/src/__tests__/shell/admin/pages/RoleManagement.test.jsx`
- `Frontend/src/shell/admin/components/RolePermissionEditor.jsx`
- `Frontend/src/shell/admin/components/UserRolesPanel.jsx`
- `Frontend/src/shell/admin/pages/RoleManagement.jsx`
- `Frontend/src/shell/api/rbac.js`
- `Frontend/src/shell/auth/AuthContext.jsx`

Documentation:

- `docs/RBAC_Management_Permissions.md`
- `docs/architecture/RBAC_ADMINISTRATION.md`
- `docs/architecture/RBAC_FRONTEND_AUTHORIZATION.md`
- `docs/architecture/RBAC_SCOPE.md`
- `docs/rbac/RBAC_HARDENING_REPORT.md` (new)

## Pre-merge follow-up files

The follow-up review additionally changes:

- `Backend/scripts/rbac/development_reset.py`
- `Backend/tests/rbac/test_development_reset.py`
- `Backend/tests/audit/audit_historical_support.py` (new)
- `Backend/tests/audit/test_audit_historical_fixture_safety.py` (new)
- `Backend/tests/audit/test_audit_chain_schema_isolation.py`
- `Backend/tests/audit/test_audit_retention_legacy.py`
- `Backend/tests/auth/test_rbac_step_up_policy.py` (new)
- `Backend/tests/README.md`
- `docs/rbac/RBAC_PREMERGE_REVIEW.md` (new)

This report is also updated to distinguish initial evidence from the gap closures.
