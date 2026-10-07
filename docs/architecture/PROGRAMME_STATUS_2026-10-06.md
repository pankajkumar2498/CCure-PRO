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

| Item                                  | What is missing                                                                                                                                                                                                                   |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ~~Deployment of the Phase 9 cleanup~~ | **Done later the same day** (~09:47 IST, from `3920908`; see `CLAUDE.md`, "Deployed 6 Oct 2026"). `gateway-auth`, `api`, `worker`, `beat`, `web-worker` and the frontend were recreated; the database was not touched             |
| Phase 18 database isolation           | Design, bootstrap SQL, generated grants, isolation proof and a guarded rehearsal script exist (`PHASE18_DATABASE_ISOLATION.md`). **Nothing has been run against any database**; the rehearsal on a restored copy is the next step |

## 2a. Known failures that are not regressions — all resolved

All three were resolved by 7 Oct 2026; none remains open.

| Gate                                                                                                           | Was                                                                | Resolution                                                                                                                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/rbac/test_development_reset.py::test_reset_bootstraps_native_administrator_without_touching_catalogues` | failed on a scratch database without the retention DBA bootstrap   | **Resolved** in `2af5071`: the test skips, with that reason, when `audit_retention` is not installed; the bootstrap requirement is documented in `Backend/tests/README.md` (`57614ea`)                                                    |
| `tests/repo/test_gateway_route_policy.py`                                                                      | errored on FastAPI's documentation routes in a development session | **Resolved** in `57614ea`: the test builds the production application (`ENV=production`), which the gateway policy describes. No assertion changed                                                                                        |
| `npm run test:browser` (Playwright)                                                                            | signed-in pages landed on "Sign in" and timed out                  | **Resolved** in `57614ea`: the harness personas speak the native `/auth/me` contract. Chromium, Firefox and WebKit 119/119 each on 7 Oct (§6), and the full gate again for the UX4G 3.0.2 upgrade (`docs/ux4g/B11_UX4G_3_0_2_UPGRADE.md`) |

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

## 6. Final acceptance, 7 Oct 2026

- **Live authentication** against the deployed stack
  (`scripts/security/verify_live_authentication.sh`, run by the operator): login, ES256
  token with a `kid`, `/auth/me` without legacy role fields, RBAC on the administration
  endpoints, organization switching (own organization accepted, unknown organization
  refused with 404), topology, a tampered and a signature-stripped token refused,
  refresh and a refreshed token accepted, logout, and refresh refused after logout:
  **23/23 passed**. The account has no MFA enrolled, so MFA was not exercised live (it is
  covered by `tests/auth/test_mfa*.py` and the key-continuity proof).
- **Browsers:** Chromium 119/119, Firefox 119/119, WebKit 119/119. WebKit ran with
  userland libraries (`Frontend/scripts/ux4g-harness/webkit-userland-deps.sh`) because
  root was unavailable; Playwright's pre-flight was skipped, not any test.
- **Backend** 7431 passed; **gateway** 133; **frontend** 3110.
- **Sign-in claims** ("SOC2 Compliant", "256-bit AES", "TLS 1.3 Secured") removed; a test
  keeps certification, cipher and protocol claims out of `src/shell/auth`.
- **Still the owner's:** Terms/Privacy wording (verbatim, "CCure Audit PRO"); the operator password used for verification
  appeared in a chat transcript and should be rotated.

**Final status: GO (7 Oct 2026).** The new RBAC and authentication migration is complete and
deployed: native RBAC is the only authorization model, tokens are ES256 with a `kid` from the
platform keyset, HS256 and the JWT secret no longer exist anywhere in the runtime path, and the
MFA key is explicit. No `.env.bak-*` copy of the retired secret remains on this host.

## 7. 7 Oct 2026, evening: CI, UX4G 3.0.2 and a full redeploy

- **CI** (`d90bb51`, `76238d5`): the failing Security and Images jobs were reproduced
  locally and fixed (axios, urllib3, base-image `openssl`/`pcre2`/`libexpat`, the
  backend smoke test's token keyset, Frontend Validation's timeout). The frontend
  Trivy exception that expired on 8 Oct was made unnecessary by patching `libexpat`;
  `trivy-frontend.yaml` is empty. The backend exceptions expire **24 Oct**.
- **UX4G 3.0.2** (`15f8c7c`): reviewed and adopted. Upstream renamed its dark-theme
  selector and removed the alert variant rules without saying so; both were measured
  and absorbed. Record: `docs/ux4g/B11_UX4G_3_0_2_UPGRADE.md`.
- **Redeploy from `15f8c7c`**: frontend, then `api`, then `worker`, `beat`,
  `web-worker`. The backend image was rebuilt for the first time since 16 Sep. Gates
  before deploy: Trivy and smoke on both images; frontend unit 3117 and browser 420/420
  (three engines); the backend suite inside the new image, 7003 passed, 239 skipped,
  none failed once its environment matched the api (a compliance key and `/docs`).
  After deploy: api, gateway and edge answer as the 7 Oct acceptance expects; workers
  hold no secrets; the scanner's scapy and nmap work over loopback. Details and
  rollback in `CLAUDE.md`.
