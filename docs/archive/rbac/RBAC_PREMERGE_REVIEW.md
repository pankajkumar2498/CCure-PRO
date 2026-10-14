# RBAC pre-merge verification — 12 October 2026

The subsequent [release validation](RBAC_RELEASE_READINESS.md) records the matching
real UI/API rehearsal, final suite results, artifact scans and coordinated rollback
plan. The reported Debian Chromium blocker is now resolved; hosted CI, security
review and deployment approval remain pending. None of this review's local evidence
constitutes hosted CI or deployment approval.

This review supplements [the six-phase report](RBAC_HARDENING_REPORT.md). All work
remains in `/tmp/ccure-rbac-phases-20261012`, based on `08ff49e`. The original
checkout and production services/data/configuration were not changed. Nothing was
merged or deployed. PostgreSQL 18 scratch containers used an internal network,
synthetic credentials, verified backups and a non-superuser application role.

## Patch review

The implementation retains native role/grant tables, role IDs, assignment history,
permission-based authorization and immutable system grants. Permission edits use
the existing revision table, a required revision precondition, a transaction lock
and one grant/revision/success-audit transaction. Refused governed writes and step-up
failures are recorded independently of request rollback. Tenant writes refuse a
foreign context; transfer revokes old tenant assignments. Permission visibility
and scope/delegation controls do not replace backend authorization. No schema,
permission catalogue, production mapping or MFA default was changed in this review.

The API compatibility requirement remains: deploy matching frontend/backend
artifacts, and update other permission-editing clients to send `expected_revision`.
Existing management writes serialize on a global transaction lock. Backend changes
take effect on the next authorization decision; remote browser controls can remain
stale until the existing refresh. These are documented operational constraints.

## Development-reset migration-head failure

The failure was a stale **explicit allowlist**, not an RBAC migration defect:
`development_reset.py` pinned the main head to `e5a7c9d1f3b2`, but the checked-in
main head is `f6a8c0e2b4d7`. Policy Pro and Rank remain on `policy_pro_0001` and
`rank_0001`. Reviewing the intervening migration shows that it only removes five
retired organisation subscription columns: no table, ownership rule, role mapping,
audit structure or reset dependency changed. Its downgrade deliberately requires
restoring a pre-migration backup; no downgrade or migration was run here.

The allowlist now explicitly pins those three reviewed heads. It is **not** derived
automatically from Alembic. The existing exact-set comparison is extracted into
`require_reviewed_migration_heads` so it can be tested independently. Regressions
verify that the source heads match the reviewed set, the gate executes only SELECT,
and stale, missing, extra and empty head sets are refused. Existing confirmation,
environment, sentinel/unreviewed-table, backup, quiescence and ownership guards
remain intact. The reset manifest is unchanged.

The destructive reset entry point, `reset_database`, the full reset test and the
legacy-removal migration test were **not executed**. The head-verification gap is
closed; end-to-end destructive reset/recovery remains outside this review, as
requested. A future use of reset still requires its reviewed plan, recovery dump
and successful restore receipt. Passing the head gate alone is not approval to reset.

## Historical audit checks

- **Hash preservation through schema relocation:** two synthetic chained events,
  including Unicode/null/empty JSON values, are captured before relocation. A
  separate scratch DBA transaction models the old public layout and runs the
  existing `bootstrap_chain.sql`. Tests compare stored hashes/links, head state
  and trigger function OID, recompute each hash, and append another event through
  the application path. Nothing is rehashed or backfilled.
- **Authoritative legacy deletion detection:** a fresh tenant receives six aged
  and two recent unhashed events before a head exists. The separate DBA connection
  invokes the existing seed function's COUNT, then normal application writes start
  the chain. Legitimate retention removes the six aged rows and decrements the
  head to two; the verifier is clean. Deleting a surviving synthetic row outside
  retention leaves the count ahead and the verifier reports a tamper break.
- **Negative/bootstrap security:** tampering with a synthetic event causes the
  existing bootstrap hash guard to refuse and roll back schema relocation. The
  app still cannot drop the protected head table. Fixture guards reject foreign
  host/port/database, live database names, shared credentials and query overrides;
  both connections must identify the same marked scratch server/database.

The application is never granted SUPERUSER, CREATEROLE, writer membership, head
writes or legacy seed execution. Bootstrap/count setup is done with a separate
scratch DBA identity; verification and deliberate owner-scope tampering run as the
restricted app role. Legacy records remain unhashed and cryptographically
unverifiable. This proves the mechanics with synthetic history; it does not inspect
or certify an installation's real historical data. Reproduction prerequisites are
in [the backend test guide](../../../Backend/tests/README.md).

## MFA deployment decision required

`config.py` and `identity/reauth.py` currently define:

| Mode                | Enrolled administrator                                    | Unenrolled/incompletely enrolled administrator         |
| ------------------- | --------------------------------------------------------- | ------------------------------------------------------ |
| `enforce` (default) | Current valid TOTP required for sensitive role operations | Allowed; successful audit records `not_enrolled`       |
| `require_enrolment` | Same current TOTP requirement                             | Refused with `mfa_enrolment_required`; refusal audited |
| `off`               | No step-up                                                | No step-up; `not_required`                             |

Unknown mode strings fall back to `enforce`, which requires TOTP from enrolled
accounts but does not make enrollment mandatory. A decrypt/verification error
refuses the operation. Step-up uses current authenticator TOTP, not the login
email-OTP or backup-code alternatives. Non-sensitive role operations retain the
existing exemption; enrollment requires both the enabled flag and stored secret.

**Required decision before production rollout:** the deployment/security owner
must approve the target mode. Recommend `require_enrolment` after readiness checks.
If `enforce` is retained temporarily, explicitly accept and time-bound the residual
risk that an unenrolled administrator can perform sensitive role operations with
session authentication alone. `off` is unsuitable for production hardening.
No setting was changed and no rollout decision is presumed approved here.

Readiness requires enrolled, independently recoverable administrators covering
all platform continuity authorities and tenant role-administration needs. Confirm
at least two independent platform recovery administrators and adequate tenant
coverage in a non-production smoke test; the continuity counter itself does not
test MFA enrollment. Verify current-code success, missing/wrong-code refusals,
unenrolled refusal, atomic success events and independent denial events. Preserve
the configured MFA encryption key and approved backup/recovery procedure. Login
backup codes alone do not satisfy role-management step-up. Document how an
authorized operator recovers authenticator access without direct role/grant edits
or silently disabling enforcement. Apply the mode consistently to API instances
only after this preparation and owner approval.

New regressions exercise both enforcing modes with real encrypted TOTP secrets,
missing/wrong codes, incomplete enrollment, unknown configuration and an unreadable
secret. The existing HTTP tests verify successful outcomes and audited denials.

## Verification results and remaining limits

| Final verification                                                                          | Result                                                                           | Evidence                                                   |
| ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Affected RBAC, tenant/security, MFA and architecture suites                                 | **760 passed, zero failures/skips; two deliberately deselected execution tests** | `/tmp/ccure-rbac-review-affected.log`                      |
| Complete audit suite with historical data and restricted app role                           | **416 passed, zero failures/skips**                                              | `/tmp/ccure-rbac-review-audit-final.log`                   |
| Final historical fixture binding, both historical checks, tamper rollback and target guards | **11 passed, zero failures/skips**                                               | `/tmp/ccure-rbac-review-history-final-binding.log`         |
| Black, Ruff, high-severity Bandit, OpenAPI contract, RBAC inventory and patch checks        | Passed                                                                           | Pinned repository tools; offline generated-contract checks |

The affected run includes all `tests/rbac/` plus security RBAC routes, authorization
hardening, tenant isolation and organisation deactivation; MFA flow/key-separation
and new step-up policy tests; RBAC identity/boundary/final-ratchet, module-boundary
and OpenAPI-hook checks. It explicitly deselects
`test_reset_bootstraps_native_administrator_without_touching_catalogues` and
`test_forward_migration_removes_only_legacy_objects`. Six new head-gate regressions
and eight real-TOTP policy regressions passed. All audit tests ran, including
the eight fixture-target cases and the formerly skipped historical checks.

Overlapping runs are not added together. The initial 49-test historical subset and
413-test audit run also passed; the final runs above include the additional tamper
refusal and connection-override protections. The final focused run verifies the
lint-compliant fixture export name. Existing dependency deprecation warnings and
the audit suite's deliberate actorless-write warning remain; no test failures remain
in the executed scope. Frontend code did not change in this follow-up, so its prior
3,138 unit and 236 browser passes were not rerun.

Follow-up changes are limited to `development_reset.py`, its tests, the two
historical audit tests and shared/safety fixtures, the new step-up policy test,
the backend test guide and the two review reports. The full changed-file list is
in the [phase report](RBAC_HARDENING_REPORT.md).

No destructive reset, merge, deployment, production migration or production data
mutation was performed. Independent IR verification remains outside the local
repository boundary; Policy Pro and Rank have no implemented local declarations.
The pending MFA deployment decision is an operational release prerequisite.
