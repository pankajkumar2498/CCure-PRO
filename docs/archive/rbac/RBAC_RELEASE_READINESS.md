# RBAC release validation and deployment preparation — 12 October 2026

## Decision

**Release is not yet approved.** The complete candidate is published for review
as [PR #45](https://github.com/pankajkumar2498/CCure-PRO/pull/45). Its published
security workflow and all three image gates/smokes passed. The hosted backend
suite exposed two audit-test assumptions about an empty platform ledger; the
tests now select their own event IDs while retaining append-only and redaction
assertions. The one flaky custom-role audit assertion now orders events by
creation time with the event ID as a tie-breaker.
The updated candidate needs its mandatory hosted check statuses before release.
Current statuses and exact artifact IDs belong to the PR's final release evidence.
Read-only migration preflight and the isolated coordinated rollback rehearsal
passed. Owner approvals remain pending. No merge, deployment, production
configuration change or production data operation was performed.

The candidate is the review worktree `/tmp/ccure-rbac-phases-20261012`,
based on `08ff49e36ccdfe2a556d17a5dd5fca1e3e2bd0e7`. The running application's
checkout was not patched. The final patch, file list and artifact manifest are
retained as `/tmp/ccure-rbac-hardening-release-candidate.patch`,
`/tmp/ccure-rbac-rc-files.txt` and `/tmp/ccure-rbac-rc-artifact-manifest.json`.
The six-phase implementation and
previous gap closures are described in [RBAC_HARDENING_REPORT.md](RBAC_HARDENING_REPORT.md)
and [RBAC_PREMERGE_REVIEW.md](RBAC_PREMERGE_REVIEW.md).

## Outstanding requirements follow-up — 12 October 2026

Previous passing checks remain recorded below and were not rerun for this
follow-up. Production migration metadata was checked inside `BEGIN TRANSACTION
READ ONLY` as `ccure_user` on `ccure_db`: the exact heads are `f6a8c0e2b4d7`,
`policy_pro_0001` and `rank_0001`. No production mutation occurred. This closes
only the migration-head preflight, not enrollment, recovery or release approval.

CI isolation is prepared in `ci.yml`: the required Backend Validation job depends
on a separate Disposable Reset Validation job. That job owns its own PostgreSQL
18 and Redis services, uses `pytest_rbac_reset`, a restricted application role and
separate DBA bootstrap, and takes private backups before bootstrap and execution.
It runs precisely the two previously excluded execution cases and fails if either
skips. All head and refusal checks remain in Backend Validation, whose explicit
scratch database is now `pytest_release_validation`. The first hosted setup failed before either execution case: Ubuntu supplied
pg_dump 16 for PostgreSQL 18. Backup now uses the isolated service container’s
own matching client. Both execution cases then passed with no skips in hosted
Disposable Reset Validation. Its fresh fixture now explicitly initializes the
real lazy NVD metadata table before reset. No reset tool is run against production
or a shared database.

Publishing the complete candidate includes ten already-present prerequisite
commits between published master `89b113aff8297a8dabce2cd865dbc377736d2400` and the
verified local base `08ff49e36ccdfe2a556d17a5dd5fca1e3e2bd0e7`. They include
subscription removal and scan/report fixes. They must remain visible for review;
the RBAC patch adds no migration, but its prerequisite includes the already-applied
production migration `f6a8c0e2b4d7`. No target-branch merge or production deployment
is authorized by draft publication.

The Playwright security review confirms that PyPI's latest stable Python release
is still 1.63.0, whose [official release notes](https://playwright.dev/python/docs/release-notes#version-163)
identify bundled Chromium 153.0.8010.12. Upstream main's newer browser manifest is
not a published stable driver/browser combination. Debian's
[CVE-2026-106237 record](https://security-tracker.debian.org/tracker/CVE-2026-106237)
describes affected Chrome versions before 155.0.8059.39, so the bundled version
cannot be cleared by the Debian package fix or a green package scan. Production
scanner launch paths explicitly use `--no-sandbox`; the live web-worker runs as
root with no custom seccomp policy. Microsoft
[recommends a separate user and seccomp profile for untrusted crawling](https://playwright.dev/python/docs/docker#crawling-and-scraping).
The minimal supported remediation now selects Chrome Stable for all five scanner
launches and authenticates its package through Google's signed APT repository,
with the official active primary-key fingerprint checked and a 155.0.8059.39
minimum. The unused vulnerable bundled browser is removed; the Playwright driver,
Debian Chromium libraries and scanner interfaces remain. The image gate additionally
launches the actual configured browser offline and checks its version. Real-browser
regression probes use the same selector. The local rebuilt image executes Chrome 155.0.8059.39 successfully, offline and
as its default user. RBAC source and all 122 installed Python packages match
the previously verified image; their passing evidence is reused. Three new
selector invariants passed, and the four affected crawler/auth/XSS/workflow
cases passed with no skips after the test runner gained an init reaper. The
first browser run had four process-leak teardown errors from unreaped children;
the guard was preserved and only those four cases were rerun. Hosted final
artifact validation remains required. Previous RBAC suites were not rerun.
No prerelease driver, arbitrary executable override, advisory suppression or
sandbox-policy weakening is introduced. Security-owner approval of the vendor
browser change and existing sandbox/worker policy remains required. See
[CONTAINER_IMAGES.md](../../ci/CONTAINER_IMAGES.md) for the technical justification.
Manual hosted Images runs now retain their exact verified artifacts and checksums
for coordinated promotion, rather than rebuilding after verification.

The exact hosted frontend payload matches the verified integration bundle.
All 702 non-test backend payload files and all 126 visible Python distributions
match the verified browser-fixed backend. The gateway payload also matches;
its transitive `pycparser` resolved from 3.1 to 3.11, so 57 affected existing
token-verification cases were executed on that exact hosted gateway and passed.
Passing RBAC workflows are retained rather than rerun locally. The first backend
image smoke failed during PostgreSQL initialization; the retry passed, and its
readiness probe now waits for TCP instead of the temporary Unix-only init server.

The new Chrome package requires runtime `wget` and libcurl. Its scan adds 40
findings, including six High findings with no fixed version reported; their IDs
and affected packages are recorded in [CONTAINER_IMAGES.md](../../ci/CONTAINER_IMAGES.md).
The gate passed under the existing policy, with no new exception or dependency
removal. This is an additional security-owner decision, not a zero-vulnerability
claim. Exact published reports retain all findings and the existing backlog.

CODEOWNERS contains placeholders, so it records no real approver. Security, CI,
deployment and final release approvals are pending. MFA configuration remains
unchanged; enrollment/recovery readiness is required for the separate future
`require_enrolment` decision. Independent IR security verification remains
separately owned. The isolated coordinated artifact-switch rehearsal now passed candidate →
previous artifacts → candidate recovery. API, worker, web-worker, scheduler,
frontend, gateway verifier and ingress were switched together. Startup
reconciliation, existing signed sessions and effective grants remained valid;
all nine protected catalogue/history/chain fingerprints and migration heads
were unchanged, and both tenant chains recomputed cleanly. All six native and
compatibility management mutation paths stayed contained. No database restore
was used during switching. The initial failures were rehearsal setup errors
(internal-network ingress, worker registration and executable mode on the
materialized baseline snapshot); final evidence retains them and the passing
sequence. No security guard was disabled. Production ingress containment,
previous frontend source provenance and the release window still need owner
approval. Results: `/tmp/ccure-rbac-outstanding/rollback-rehearsal-results.json`.

## Image-blocker remediation and exact-artifact validation

The earlier image installed Debian Chromium and Chromium-common
`154.0.8037.92-1~deb13u1`. Its 4 critical and 144 high package findings represented
74 distinct CVEs, each reported for both packages. Earlier refreshed metadata still
offered 154; the subsequent signed `trixie-security` metadata now offers
`155.0.8059.39-1~deb13u1`. The
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-106237)
records that version as fixed for trixie. Evidence:
`/tmp/ccure-rbac-remediation-package-policy.log`.

`Backend/Dockerfile` now requires both installed packages to be at least that
version. This minimum accepts future security updates, refuses stale mirror
packages, and invalidates the old apt-install layer for hosted same-day caches.
The existing digest-pinned Python base, signed Debian keyring/repositories,
dependencies, scanner versions, gate flags and accepted exceptions are unchanged.
No sid/testing repository, unsigned download, dependency removal, advisory
suppression or security-gate reduction was introduced.

The exact rebuilt image is `ccure-rbac-rc-backend:20261012-fixed`, ID
`sha256:98311f1847dd76cd7366a0168400411b9ad8272a58b9e38f51efae51842e0288`.
This is a local review artifact, not a published release reference. The platform
Python source hash matches the previously reviewed image. Its 122 installed app
packages were compared directly; existing unconstrained resolution updated three
transitive packages: `pycryptodomex` 3.24.0 → 3.24.1, `pycparser` 3.1 → 3.11 and
`httptools` 0.8.0 → 0.9.0. No requirements file was edited. The exact resolved set
was audited rather than assuming the previous dependency audit covered it.
Evidence: `/tmp/ccure-rbac-remediation-parity.json` and
`/tmp/ccure-rbac-remediation-resolved.txt`.

| Executed on this candidate                                                   | Result                                                                                                                                   | Evidence                                                                                                                          |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Fixed backend build                                                          | Passed; first attempt stopped on PyPI timeout, unchanged retry succeeded                                                                 | `/tmp/ccure-rbac-remediation-build-retry.log`                                                                                     |
| Installed packages and version guard                                         | Both packages 155; 154 refused, 155 accepted; only expected slim-base documentation omissions                                            | `/tmp/ccure-rbac-remediation-package-verification.log`, `/tmp/ccure-rbac-remediation-dpkg-policy.log`                             |
| Backend vulnerability gate, pinned Trivy with refreshed database             | **Passed, exit 0, zero blocking findings; zero Debian Chromium findings**                                                                | `/tmp/ccure-rbac-rc-scan-reports/backend-fixed-gate.json`                                                                         |
| Full backend advisory report without exceptions/skips                        | 504 findings: 3 critical, 108 high, 181 medium, 196 low, 16 unknown; gate policy distinguishes accepted/app backlog and unfixed findings | `/tmp/ccure-rbac-rc-scan-reports/backend-fixed-all.json`                                                                          |
| Unchanged matching frontend and gateway image gates, same refreshed database | **Both passed, exit 0, zero blocking findings**                                                                                          | `/tmp/ccure-rbac-rc-scan-reports/frontend-remediation-gate.json`, `/tmp/ccure-rbac-rc-scan-reports/gateway-remediation-gate.json` |
| Exact installed app dependency audit                                         | **Passed, exit 0; existing 89 accepted advisories unchanged**                                                                            | `/tmp/ccure-rbac-remediation-pip-audit.log`                                                                                       |
| Runtime npm dependency gate on unchanged lockfile                            | **Passed, exit 0; two existing moderate findings**                                                                                       | `/tmp/ccure-rbac-remediation-npm-audit.log`                                                                                       |
| Final tracked candidate secret gate, pinned gitleaks                         | **Passed, exit 0, zero findings**; hosted commit-range scan pending                                                                      | `/tmp/ccure-rbac-remediation-gitleaks.log`, `/tmp/ccure-rbac-rc-scan-reports/gitleaks-remediation.json`                           |
| Existing API/scanner/worker/beat artifact smoke suite                        | **Passed**, including default non-root API, Nuclei/ffuf loopback detection and secret-log checks                                         | `/tmp/ccure-rbac-remediation-smoke.log`                                                                                           |
| Explicit affected regression selection, Python 3.11 inside exact fixed image | **36 passed, zero failures/skips**                                                                                                       | `/tmp/ccure-rbac-remediation-targeted-tests-final.log`, `/tmp/ccure-rbac-remediation/selected-tests.json`                         |
| Existing real frontend/API rehearsal, fixed image without source mount       | **13 scenarios passed**                                                                                                                  | `/tmp/ccure-rbac-remediation-fullstack-results.json`, `/tmp/ccure-rbac-remediation-fullstack.log`                                 |
| Read-only audit/revision/assignment verification                             | **7 checks passed**; revision 5, four matching committed permission revisions, retained revoked assignment, both tenant chains clean     | `/tmp/ccure-rbac-remediation/integrity-results.json`                                                                              |

Trivy used its current unexpired database: updated 12 October 2026 at 13:18 UTC,
next update due 13 October at 13:18 UTC. Default update checks were enabled for
the full scan; the three gates used that same database. Package verification
reported missing documentation/man/lintian files intentionally excluded by the
unchanged pinned slim base; there were no executable/data hash mismatches. The
original dpkg output and base exclusion policy are retained rather than claiming
all package files exist. The final tracked snapshot secret gate also passed;
commit-history scanning still requires publishing the reviewed PR.

Only the explicitly selected RBAC edit/conflict/delegation/continuity/history/audit
failure cases, real MFA policy cases, foreign-tenant refusal and four real browser
crawl/session cases were rerun. No reset test or unrelated full suite was invoked.
The real rehearsal used the previously tested matching frontend build and the exact
fixed backend with no application source bind mount. Temporary strict MFA settings,
synthetic recovery accounts and generated signing keys existed only in the isolated
test process. Deployed MFA configuration was not inspected or changed.

Both new PostgreSQL 18 databases (`pytest_rbac_releasefix`, `pytest_rc_integration`)
were in a separate tmpfs-backed container on an internal network, with their own
Redis, no database/API published port, restricted app identity and verified scratch
sentinels. Backups preceded schema/test operations; a final synthetic history dump
was retained. Initial test-directory/key UID permissions were corrected in the
runner without changing application access controls. Scanner invocations used
read-only image exports and no Docker socket. The remaining checks and evidence
packaging do not authorize publication, merge or deployment.

### Residual findings and bundled-browser coverage

Zero blocking findings is the existing policy result, not a zero-advisory claim.
The full report retains accepted Python/scanner backlog and unfixed OS findings;
no exception was added. The two npm moderate findings still require the existing
frontend dependency workstream rather than a forced major router migration here.

The image also retains Playwright 1.63.0's separately downloaded Chrome for Testing
`153.0.8010.12` (revision 1243), unchanged from the prior image. Web scanning launches
that browser, not `/usr/bin/chromium`. Updating Debian packages does **not** update
it. Trivy inventories Debian/package-manager and language dependencies; these
passing gates do not independently establish vulnerability coverage of that
unpackaged browser binary. The security owner must assess applicable Chromium
advisories and a supported upstream browser/driver update before release sign-off.
This is an unresolved browser-security verification risk; it is not waived by the
green Debian package scan. This remediation did not silently switch browser engines
or download an unverified replacement. The four real browser checks establish
runtime compatibility, not absence of browser CVEs.

## Previous full application-patch validation

The following results preceded the package-only image remediation. They remain
useful evidence for unchanged application source; they were **not** all rerun in
this step. The historical failed image row is superseded by the fixed artifact
results above.

All data-bearing tests used new PostgreSQL 18 databases in a separate Docker
instance: `pytest_rc_runtime`, `pytest_rc_audit`, `pytest_rc_integration`, and
`pytest_rc_ci312`. They had disposable sentinels and backups before destructive
fixtures. The application database identity was `NOSUPERUSER NOCREATEROLE
NOCREATEDB`; the historical fixtures received a separate DBA credential for the
same scratch database. The test network was internal, with its own Redis and no
deployment credentials, signing keys, mail account or production data mounts.

| Check                                                                                                                           | Result                                                                                                                                            | Evidence                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Complete non-audit backend suite, Python 3.11 deployment runtime                                                                | **7,213 passed, three explicit skips, two reset execution tests deselected; cookie-name skip subsequently closed by the native-auth rerun below** | `/tmp/ccure-rbac-rc-backend-clean.log`                                                             |
| Complete audit suite, including both historical checks                                                                          | **416 passed, no skips/failures**                                                                                                                 | `/tmp/ccure-rbac-rc-audit.log`                                                                     |
| Affected RBAC, MFA, tenant/security, service identity and module/integration contracts, freshly resolved Python 3.12 CI runtime | **964 passed, two reset execution tests deliberately deselected**                                                                                 | `/tmp/ccure-rbac-rc-python312-final.log`                                                           |
| Native authentication after correcting the obsolete cookie-name assumption                                                      | **9 passed, no skips/failures**                                                                                                                   | `/tmp/ccure-rbac-rc-native-auth-final.log`                                                         |
| Gateway-auth unit/FastAPI parity and production configuration                                                                   | **162 passed**                                                                                                                                    | `/tmp/ccure-rbac-rc-gateway-final.log`                                                             |
| Matching real frontend/API rehearsal, Chromium                                                                                  | **13 scenarios passed**                                                                                                                           | `/tmp/ccure-rbac-rc-fullstack-results.json`, `/tmp/ccure-rbac-rc-fullstack.log`                    |
| Read-only integration history/audit verification                                                                                | **7 integrity checks passed**                                                                                                                     | `/tmp/ccure-rbac-rc-integrity-results.json`                                                        |
| Baseline application readers against post-patch scratch history                                                                 | **Passed; all RBAC/audit row fingerprints unchanged**                                                                                             | `/tmp/ccure-rbac-rc-rollback-compatibility.json`                                                   |
| Frontend unit tests, Node 22                                                                                                    | **3,138 passed**                                                                                                                                  | `/tmp/ccure-rbac-rc-frontend-unit-final.log`                                                       |
| Required Chromium accessibility/responsive/synthetic browser gate                                                               | **236 passed**                                                                                                                                    | `/tmp/ccure-rbac-rc-browser.log`                                                                   |
| Frontend production build, UX4G reproducibility/provenance/boundaries, authorization inventory, ESLint                          | **Passed**                                                                                                                                        | `/tmp/ccure-rbac-rc-frontend-build.log`, `/tmp/ccure-rbac-rc-frontend-gates.log`                   |
| Black for changed Python files, repository-wide Ruff and high-severity Bandit                                                   | **Passed**                                                                                                                                        | `/tmp/ccure-rbac-rc-black.log`, `/tmp/ccure-rbac-rc-ruff.log`, `/tmp/ccure-rbac-rc-bandit.log`     |
| OpenAPI and backend authorization inventory                                                                                     | **Passed; generated baselines current**                                                                                                           | `/tmp/ccure-rbac-rc-openapi.log`, `/tmp/ccure-rbac-rc-backend-inventory.log`                       |
| Documentation compilation                                                                                                       | **Passed**                                                                                                                                        | `/tmp/ccure-rbac-rc-docs-build.log`                                                                |
| CI-equivalent reversible module migration downgrade/upgrade                                                                     | **Passed on scratch; irreversible core downgrades excluded by existing CI policy**                                                                | `/tmp/ccure-rbac-rc-migration-integrity.log`                                                       |
| Tracked candidate snapshot secret scan, gitleaks 8.30.1                                                                         | **Passed**                                                                                                                                        | `/tmp/ccure-rbac-rc-gitleaks-final.log`                                                            |
| Freshly resolved Python dependency vulnerability gate with existing accepted backlog                                            | **Passed; 89 accepted advisories ignored under existing policy**                                                                                  | `/tmp/ccure-rbac-rc-pip-audit.log`                                                                 |
| npm runtime high/critical dependency gate                                                                                       | **Passed; two moderate findings reported**                                                                                                        | `/tmp/ccure-rbac-rc-npm-audit.log`                                                                 |
| Backend, frontend and matching gateway-auth artifact builds and isolated smoke tests                                            | **Passed**                                                                                                                                        | `/tmp/ccure-rbac-rc-*-build*.log`, `/tmp/ccure-rbac-rc-*-smoke.log`                                |
| Frontend and gateway-auth exported-image vulnerability gates                                                                    | **Passed under existing policy**                                                                                                                  | `/tmp/ccure-rbac-rc-trivy-frontend-export.log`, `/tmp/ccure-rbac-rc-trivy-gateway.log`             |
| Final backend exported-image vulnerability gate, including refreshed OS-stage build                                             | **FAILED: 4 critical and 144 high findings**                                                                                                      | `/tmp/ccure-rbac-rc-trivy-backend-final.log`, `/tmp/ccure-rbac-rc-scan-reports/backend-final.json` |

The backend and audit suites were isolated from each other so schema/retention
fixtures could not contaminate their results. Reset execution and the legacy
removal execution test were excluded explicitly. No development-reset command was
invoked. The reviewed migration-head exact-set gate and its stale/missing/extra/
empty-head refusals ran in both RBAC selections. Destructive reset/recovery testing
belongs to a separate approved disposable-database exercise, not release validation.

The full run collected the native-auth module before its final cookie-name correction;
all nine corrected native-auth cases then passed independently. The other two skips
remain explicit: the module-branch activation check is inapplicable to the already
activated Alembic configuration, and the live OSV npm feed was unreachable on the
offline network. Reversible module heads were separately downgraded/upgraded on scratch.
These results are separate runs, not a claim that one final full-suite invocation had
zero skips or that the entire suite also ran under Python 3.12.

After the final test/report edits, the deployment-runtime native-auth, documentation
integrity, OpenAPI hook and RBAC final-ratchet selection passed **25 tests**, with
no skips (`/tmp/ccure-rbac-rc-final-contracts.log`). The required schema/compliance/
real-rule bootstrap commands also passed on the backed-up disposable database
(`/tmp/ccure-rbac-rc-ci-bootstrap.log`). Prettier checked every changed frontend
source/test and RBAC document successfully (`/tmp/ccure-rbac-rc-prettier.log`).

The backend artifact was rebuilt after the cookie-test correction. Its exact final
image passed API, scanner, worker and beat smoke checks
(`/tmp/ccure-rbac-rc-backend-final-smoke.log`) and still failed the vulnerability
gate with the same 148 findings. All three tested image IDs are recorded in the
artifact manifest. Disposable API/database/Redis containers and the loopback test
server were removed after verification; evidence, scratch backups and review
artifacts are retained locally.

Initial failed runner attempts remain in the logs: concurrent asset regeneration
removed files beneath frontend units; the first backend runner lacked Redis and an
init reaper; a subsequent non-root run encountered root-owned synthetic report
output. Correcting the runner resolved these issues without relaxing guards or
changing application code. The report/export rerun passed all 229 selected tests.
The final suite status above refers to the corrected runner.

The only new test change in the earlier full application review was
`Backend/tests/auth/test_native_authentication_end_to_end.py`: read the existing
`REFRESH_COOKIE_NAME` instead of the retired literal `refresh_token`, and assert
that login sets the cookie instead of silently skipping the token-kind check.
This document was the other new file; the prior reports were updated to link it.
The subsequent image-remediation step adds only the Dockerfile minimum-version
guard and updates container/release documentation. Neither review adds application
grants, schemas, migrations, MFA settings or system-role changes.

## Real integration evidence

The production-built React application talked to the real candidate FastAPI app
through a loopback-only test server using the existing CSP. API responses and
authorization dependencies were not mocked. This was separate from the standard
UX4G harness, whose API writes remain synthetic. Test-only `RBAC_REAUTH_MODE` was
`require_enrolment` on this isolated API process; no configuration file was edited.

The rehearsal exercised actual password/TOTP login, platform delegation of tenant
role-management authority, UI creation with explicit organisation context, all 50
tenant-scoped permission declarations, in-place editing, concurrent HTTP writers
(one success and one 409), missing-revision 428, stale UI error/reload, unenrolled/
missing-code/invalid-code denials, foreign-tenant and unprivileged write denials,
and immutable system grants in both API and UI. Assignment and revocation used the
real user-management UI. Permission replacement and revocation changed `/auth/me`
authorization for an already-issued user token; no token reissue was needed.

The final custom role retained its ID and five contiguous revisions. Four committed
permission updates each had a matching successful audit event and revision; the
stale attempts added neither. The revoked assignment remained with its tenant scope.
The latest revision's permission-set hash matched the live grants. The existing
database hash functions recomputed both tenant chains without breaks or legacy rows.
Injected rollback, revision-write/audit-write failures, delegation ceilings and
last-administrator continuity are covered by the affected backend regression suite.

Existing Org Admin system grants intentionally omit `platform.role.create`,
`platform.role.update`, and `platform.role.retire`. A platform authority must delegate
those capabilities using an appropriate custom role and governed assignment. The
rehearsal did this through the APIs; it did not add grants to a system role. Platform
catalogue readers see 69 declared local permissions; tenant readers see 50. The UI
does not invent permissions for disabled or independently owned modules.

Backend enforcement reads current grants on each request. The editing actor's UI
refreshes after a successful change; other open sessions refresh on visibility
changes and the existing 20-minute interval. There is no push invalidation guarantee
for another user's displayed controls, but stale controls do not bypass the server.

## MFA deployment decision

**Keep the deployment's current configuration unchanged.** This review did not
inspect production enrollment, recovery accounts or encryption keys. It does not
approve changing `RBAC_REAUTH_MODE` to `require_enrolment`.

Before that separate change, the security/deployment owner must verify enrollment
for every administrator needed for platform and tenant continuity, at least two
independent platform recovery authorities, and a tested account/MFA recovery path.
The existing continuity count checks account and tenant viability, not MFA enrollment.
Preserve the exact MFA encryption key, signing keyset and approved recovery materials.
Email OTP and backup codes supported at login are not substitutes for the current
TOTP required by sensitive management operations.

Record the approving owner, enrollment/recovery evidence, non-production strict-mode
results and approved rollout window before enabling `require_enrolment`. Its strict
denials and successful TOTP path were tested here. The default `enforce` behavior for
unenrolled administrators remains the previously documented residual risk: it permits
the sensitive operation and records `not_enrolled`. Deploying the patch with the
current mode and approving a future MFA-mode change are separate decisions; strict
enrollment readiness is a prerequisite for the mode change, not a reason to silently
change configuration during this patch.

## Incident Response boundary

IR is a separately owned service. The executed local tests cover service assertion
issuance, replay refusal, requested/allowed scopes, tenant binding, consumer scope
checks and human/service token separation, plus module registry/navigation and the
declared integration schemas/examples/mappers. The `IncidentEvidence`/receipt models
are reviewed drafts and are not wired to a live ingestion endpoint in this repository.
Schema validation proves the draft contract's vocabulary and ownership rules; it does
not prove live receipt persistence, idempotency or authorization in IR.

There are no locally declared `ir.*` RBAC keys. No IR permission was invented or
exposed to tenant administrators. Independent IR security verification must be owned
and tracked separately: deployed service revision and registry/scopes, tenant
enforcement, user/service authorization, incident/receipt persistence, idempotency,
audit logging, enrollment/recovery and evidence ownership. This workstream remains
unverified here; obtain its owner's release evidence before a coordinated IR release
or enabling an IR integration.

## Historical blockers before the outstanding-requirements follow-up

1. **Debian image blocker closed; bundled-browser security review pending.** The
   fixed packages and all three local image gates pass as recorded above. The
   separately bundled Playwright Chromium version and scanner coverage limitation
   still need security-owner triage and a supported remediation decision; local
   functional compatibility tests cannot substitute for that security evidence.
2. **Hosted PR and release-commit evidence is pending.** No PR was merged or candidate
   commit published. Required GitHub statuses—Secret Scan, Python Dependency Audit,
   npm Dependency Audit, Backend Validation, Frontend Validation—and the exact
   release-commit Images run must pass. A directory scan additionally flagged ignored
   public UX4G checksum manifests; the tracked snapshot scan was clean. The future
   commit-range scan still must run; no secret-scanning exemption was added.
   Publish the reviewed source candidate as a PR to the repository's approved
   target branch, then require those five PR statuses on its exact head. Manually
   dispatch the existing Images workflow on that same published candidate before
   release approval; it does not require merging first. No workflow or branch
   protection rule was changed, and nothing was published by this review.
   **CI test-isolation handoff:** the current `ci.yml` backend pytest command is
   unfiltered and would include the two reset/legacy-removal execution cases.
   Before using that run as release validation, the CI owner must establish a
   separate disposable-database reset exercise while preserving the head/refusal
   safety checks and evidence for both execution cases. This review did not
   invoke those cases or silently remove them from a required hosted gate. The
   isolation plan and its required hosted check evidence remain pending.
3. **Owner approvals and deployment preflight remain pending.** Production enrollment,
   recovery readiness, current migration heads, infrastructure posture, previous
   artifact digests and operational rollback containment were not inspected or
   changed. Record approved artifact pair and release window before deployment.
4. **Independent service/external checks remain scoped out.** IR's live service was
   not audited, and the offline test network did not verify the live OSV feed.
   Firefox/WebKit nightly matrix and Docker gateway refusal/fail-closed/trust-boundary
   harness were not executed in this review; they are not required PR checks under
   the current repository policy. Hermetic gateway suites and artifact smoke tests
   did run.

Trivy ran at the repository-pinned digest against exported image files, without a
Docker socket. Automatic approval review rejected an earlier frontend socket-based
scan for broad host access; the safer export-based scan completed. Existing advisory
exceptions were unchanged. Dependency deprecation warnings are retained in the logs.

## Coordinated promotion and application-artifact rollback

This is a preparation plan, not authorization to deploy or change gateway controls.

1. After the blockers are closed, freeze the reviewed candidate and record source
   commit, frontend/backend/gateway image digests, dependency resolution, all check
   results, previous matched artifact digests and approving owners. Build release
   artifacts from that exact commit and rerun Images; local `20261012` tags are review
   artifacts, not immutable production release references.
2. Verify migration heads read-only before startup. This RBAC patch adds no migration.
   If an existing irreversible migration such as `f6a8c0e2b4d7` is still pending,
   stop: it needs its own reviewed data-impact plan and tested recovery procedure.
   Do not let ordinary startup accidentally authorize that separate migration.
3. Use a reviewed maintenance/gateway procedure to stop role-management writes across
   `/platform/rbac/*` and compatibility user/organisation administration entry points
   during version switches. Preserve deployment keys, current MFA settings and
   all database rows. Promote the matching backend API, worker, web-worker, beat,
   gateway verifier and frontend artifacts as one coordinated change. Older frontend
   permission writes lack `expected_revision` and will receive 428 from this backend.
4. Account for bind mounts. Current compose mounts host backend source into running
   services, so switching an image tag alone does not switch the executed backend.
   The deployment owner must choose a reviewed immutable-image configuration or
   atomically coordinate the exact source snapshot with all application artifacts.
   This review did not alter compose, mounts or the deployed checkout.
5. Before reopening administration, use approved non-production/production smoke
   procedures to verify login/step-up, catalogue, role revision reads, assignment
   boundaries, denial logging and chain health. Compare pre/post role IDs, assignment
   history and revision/audit counts; no reset, truncation, history rewriting or
   direct grant updates is part of promotion.
6. If rollback is required, keep administration writes contained, quiesce incompatible
   jobs, and restore the **previous matched application artifacts/source snapshot**
   across API/workers/frontend/gateway. Keep the current database and all changes,
   revisions and audit records made after promotion. Recheck histories and effective
   permissions before reopening access. Old artifacts lack these security guards;
   do not reopen management writes merely because an older build starts. If safe
   containment cannot be enforced, keep the affected service unavailable while a
   forward fix is prepared. Do not turn off MFA as a rollback mechanism.
7. **Do not restore the database as routine rollback.** Baseline application readers
   were tested against the post-patch synthetic database and preserved every RBAC/
   audit fingerprint. That is a read-compatibility test, not a live artifact-switch,
   startup-reconciliation or operational recovery drill. The follow-up above subsequently executed the isolated coordinated
   switch/recovery drill successfully. The deployment owner must still approve
   the production topology, containment procedure and previous artifact provenance. Backup restoration is a separate disaster
   recovery decision requiring a reviewed plan; it discards intervening history and
   is not needed by this additive application patch.

No production mutation, development reset, migration downgrade, deployment,
MFA configuration edit or merge is authorized by this report.
