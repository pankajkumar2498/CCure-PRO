# Programme status — 6 Oct 2026

What is complete, what is prepared but not live, and what remains. Written after the
corrected-checklist work of 6 Oct 2026. Historical records are not rewritten; where
one is superseded it carries a banner pointing here or to `CLAUDE.md`.

## 1. Complete (in the repository)

| Area                                        | State                                                                                                                                       | Record                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Native RBAC as the only authorization model | Done. Legacy tables, `users.role_id` and the cutover tooling are removed; the development installation was reset on 4 Oct 2026              | `backups/native_clean_reset_20261004/final-report.md`, revision `d4f8b2c6e0a1` |
| Role-name ratchet                           | Detects direct comparisons, helper-mediated comparisons, named role sets and `user.role` reads; the inventory derives its count from source | `scripts/architecture/rbac_guardrails.py`                                      |
| Topology authorization                      | Platform scope + `audit.scan.read_all`; organisation-wide map covered                                                                       | `routers/topology.py`, `tests/topology/test_topology_authorization.py`         |
| AMT permission                              | `audit.asset.import_amt` in backend and frontend                                                                                            | done before this checklist                                                     |
| Denied platform-route fallback              | `AccessDenied` in the Platform Shell, never a redirect to Audit                                                                             | done before this checklist                                                     |
| Notification vocabulary                     | Audit's presentation is Audit's, supplied to the shell                                                                                      | done before this checklist                                                     |
| Organisation plan (Phase 8.4)               | **Option A**: platform-owned columns behind platform APIs. Not moved, by decision                                                           | `PHASE8_4_ORGANISATION_PLAN.md` §3                                             |
| Explicit MFA key                            | Required, no fallback, api only; continuity proven                                                                                          | `scripts/security/verify_mfa_key_continuity.py`                                |
| Worker secret exposure                      | Workers hold no JWT/MFA secret and `/app/.env` is masked                                                                                    | `docker-compose.yml`                                                           |
| Legacy HS256                                | **Removed**: issuance, verification, `JWT_SECRET_KEY`, signing-algorithm and legacy-acceptance settings                                     | `tests/repo/test_no_legacy_token_mechanism.py`                                 |
| Sign-in screens                             | In `src/shell/auth/`, name the platform ("CCure") and no product; invented hero figures and a hardcoded status badge removed                | `Frontend/src/shell/auth/`                                                     |

## 2. Prepared, not live

| Item                              | What is missing                                                                                                                                                                                                                         |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Deployment of the Phase 9 cleanup | The running containers still carry the old compose definition. Needs the order in `CLAUDE.md` ("Deploying it"): rebuild `gateway-auth`, then recreate `api`, `worker`, `beat`, `web-worker`. **Not deployed; no service was restarted** |
| Phase 18 database isolation       | Design, bootstrap SQL, generated grants, isolation proof and a guarded rehearsal script exist (`PHASE18_DATABASE_ISOLATION.md`). **Nothing has been run against any database**; the rehearsal on a restored copy is the next step       |

## 2a. Known failures that are not regressions

| Gate                                                                                                           | Result                                                             | Why it is not from this work                                                                                                                                                                                                                     |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tests/rbac/test_development_reset.py::test_reset_bootstraps_native_administrator_without_touching_catalogues` | fails on the disposable `ccure_pytest_db`                          | `audit_retention.retention_holds` does not exist there (the retention DBA bootstrap was never applied to that scratch database). Failed identically before any Phase 9 change                                                                    |
| `tests/repo/test_gateway_route_policy.py`                                                                      | errors (`/openapi.json` not represented by the gateway policy)     | Fails identically on clean `HEAD`; run from the api container, where docs routes differ. Deselected in the full run                                                                                                                              |
| `npm run test:browser` (Playwright)                                                                            | pages that need a signed-in session land on "Sign in" and time out | Reproduced on a build of `5465d60`, the commit before this work: the harness fixtures predate the native `/auth/me` contract. **The browser gate is therefore not a usable signal until its fixtures are updated**; it was not run to completion |

## 3. Open decisions (the owner's)

1. **Terms of Service and Privacy Policy wording** (D12-9). Moved verbatim to
   `@audit/legal`; they still say "CCure Audit PRO" and describe scanning. A platform
   version is a legal decision and was not written.
2. **The sign-in hero wording.** Product marketing copy was removed rather than
   rewritten; the screens carry only functional text. Any positioning copy is the
   owner's.
3. **Phase 18 questions** in `PHASE18_DATABASE_ISOLATION.md` §9.

## 4. Optional compatibility work — assessed, left in place

- **Nine `_resolve_org` wrappers** (`assets`, `credentials`, `dashboard`, `findings`,
  `remediation`, `phase_scans`, `scan_policies`, `scan_schedules`, `web_scans`):
  each is a one-line delegate to `resolve_active_organisation`; 87 call sites; no
  test patches any of them. Replacing them is mechanical but touches nine security
  routers for no behaviour change, so it was not done. If it is, do it as one
  mechanical commit with the whole suite.
- **Legacy module aliases** (24 in `ccure_platform/_legacy.py`): importers are pinned
  by `tests/repo/test_legacy_alias_importers.py`. Removal also changes observable
  names (logger names, limiter route keys), which `CLAUDE.md` says not to alter in
  passing. Left in place.

## 5. Not in scope and not touched

Plan columns on `organizations`; native RBAC removal; backend email/TOTP branding;
AMT alignment; the denied-route fallback.
