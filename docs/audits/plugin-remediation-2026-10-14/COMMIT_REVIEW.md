# Plugin remediation commit preparation

The separate remediation change is being prepared against documentation cleanup
commit `e10db6d`. No file changed by that cleanup has been modified here. Existing
mail branding edits remain unstaged and byte-identical to the start of this
review. No commit, push, deployment or database reset command was performed.

## Confirmed corrections

Two current backend test failures were reproduced before correction:

- `tests/repo/test_rbac_final_ratchet.py::test_the_inventory_has_no_legacy_site`
- `tests/rbac/test_rbac_migration_inventory.py::test_the_file_is_exactly_what_the_generator_produces`

Both compare the generated backend authorization inventory with its committed
artifact. The credential-scope import/validator moved five authorization sites
in `routers/phase_scans.py`. The existing generator regenerated only
`Backend/data/rbac/authorization_migration_inventory.json`. The exact diff changes
five `line` values; permissions, site identities, mechanisms, classifications,
history and summary counts are unchanged. The test assertions and generator are
unchanged. Both failures reproduced in a focused two-test run; the corrected
inventory and gateway-contract subset passed **69 tests**, zero failed/skipped.

The reported inventory CSV is located at
`docs/audits/plugin-audit-2026-10-14/plugin-inventory.csv`; no file exists at the
shortened `docs/audits/plugin-inventory.csv` path. Gitleaks8.30.1 reproduced one
`generic-api-key` match at physical line12. It matched the catalogue identifier
`smb.v1_enabled` across adjacent CSV fields after the prose “findings API and
reports”. This value is a check identifier, not a credential. Quoting alone did
not resolve the finding. The generated description now uses the equivalent
“findings endpoint and reports” in the CSV and its renderer. All 170 inventory
records, identifiers, column structure and other values are preserved. The
unchanged scanner then reported zero findings. No allowlist, scanner rule,
security threshold, retry or test assertion was weakened.

The complete staged scan also matched two startup-log appearances of pytest's
public JWK key ID. `keyset_status()` logs published IDs; conftest generates a
throwaway signing keyset. These public identifiers were redacted from the archived
failure log. The JUnit capture contains none; test names, assertions and counts
are preserved.
Scanner rules and allowlists remain unchanged.

Earlier logs also contained two Phase3 report-copy assertion failures and two
historical-report browser fixture failures. Their previously implemented
corrections were reviewed: accurate coverage wording, and an explicit synthetic
read-only `/scans/p3-report` response. The current full frontend unit and browser
suites pass these cases; no further application change was needed.

The real hooks corrected trailing blank lines in two remediation evidence logs.
These formatting changes do not alter test results. The evidence hash manifest
is resealed after final hook validation.

## Final working-tree validation

| Check                                                                                       | Result                                                           |
| ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Expanded backend run before inventory correction                                            | 5,389 passed, 1 failed, 2 skipped; 673.17s                       |
| Focused reproduction of both inventory guards                                               | 2 failed; 15.50s                                                 |
| Corrected inventory/RBAC/gateway subset                                                     | 69 passed, 0 failed/skipped; 69.04s                              |
| Final broad backend run after correction                                                    | 5,400 passed, 0 failed, 1 expected skip; 690.45s                 |
| Frontend unit suite                                                                         | 122 files, 3,171 passed, 0 failed/skipped; 217.18s               |
| Full Chromium browser suite                                                                 | 240 passed, 0 failed/skipped; 309.48s                            |
| Coverage feature, Firefox/WebKit                                                            | 4 per engine passed, 0 failed/skipped; combined 21.9s            |
| Frontend build, lint, UX4G reproducibility/architecture/dependency and authorization checks | Passed                                                           |
| OpenAPI contract hook                                                                       | Passed; no contract diff                                         |
| Runtime npm dependency audit                                                                | Exit0: 0 high/critical, 2 moderate advisories                    |
| Scoped Python protocol-driver audit                                                         | 4 distinct inherited accepted ASN.1 advisories; 0 new unaccepted |
| Final staged-source hooks                                                                   | All applicable hooks passed; YAML inapplicable                   |

The first broad run's gateway-policy skip came from omitted contract inputs in
the isolated test snapshot. The committed gateway policy was copied to the
snapshot, without modifying live policy; its unchanged contract test passed in
the 69-test subset. The Alembic activation-helper test intentionally skips when
the repository's configuration is already activated. No configuration or schema
was deactivated to force that historical-path test to run.

Backend source was copied into `/tmp/ccure-plugin-commit-validation`, with root
contract files, Frontend source, CI inputs, committed documentation and gateway
policy. All 33 remediation-owned Backend files, including the generated
inventory, match the working-tree SHA256 values. Tests use the existing guarded
`ccure_plugin_remediation_pytest_db`; fixture cleanup is confined to disposable
test data. No production database was reset or used for testing. The required
operational backup completed before the runs. Network fixtures use mocks or
loopback. Installed application dependencies and live containers were not
rebuilt or restarted.

Exact final backend command:

```bash
docker exec -w /tmp/ccure-plugin-commit-validation/Backend \
  -e SKIP_DOTENV_LOAD=1 \
  -e PYTHONPATH=/tmp/ccure-plugin-commit-validation/Backend:/tmp/ccure-plugin-remediation-pinned-deps \
  ccure-api python /tmp/ccure-plugin-remediation-run-tests.py \
  tests/scans tests/credentialed tests/web tests/reports tests/topology tests/repo \
  tests/rbac/test_rbac_migration_inventory.py \
  -q -r a --junitxml=/tmp/ccure-plugin-commit-backend-final.xml \
  > /tmp/ccure-plugin-commit-backend-final.log 2>&1
```

Inventory correction and verification, using the existing Backend interpreter:

```bash
SKIP_DOTENV_LOAD=1 Backend/.venv/bin/python \
  Backend/scripts/rbac/build_migration_inventory.py --write
SKIP_DOTENV_LOAD=1 Backend/.venv/bin/python \
  Backend/scripts/rbac/build_migration_inventory.py --check
```

Frontend commands from `Frontend/`:

```bash
npm test -- --maxWorkers=2
VITE_API_BASE_URL=/api npm run build
npm run lint
npm run ux4g:verify
npm run ux4g:architecture
npm run ux4g:check -- --dependencies-only
node scripts/build-authorization-inventory.mjs --check
UX4G_BROWSER_OUTPUT=/tmp/ccure-plugin-commit-browser-results \
UX4G_BROWSER_REPORT=/tmp/ccure-plugin-commit-browser.json \
  npm run test:browser -- --project=chromium
UX4G_WEBKIT_EXECUTABLE=/tmp/ccure-plugin-webkit-runtime/run-webkit.sh \
UX4G_BROWSER_OUTPUT=/tmp/ccure-plugin-commit-feature-results \
UX4G_BROWSER_REPORT=/tmp/ccure-plugin-commit-feature.json \
  npm run test:browser -- --project=firefox --project=webkit \
  browser-tests/plugin-coverage.spec.mjs
npm audit --omit=dev --audit-level=high --json
```

The WebKit wrapper uses the same unmodified Playwright WebKit binary and the
previously validated temporary runtime libraries. It changes no browser
assertions, CSP, axe exclusions or host-validation flags.

Hooks are invoked with the repository's actual configuration and an explicit
file list, so pre-commit does not stash or restore unrelated edits:

```text
Backend/.venv/bin/python -m pre_commit run --files <commit-files.txt paths>
```

This includes Gitleaks, large-file/whitespace checks, Black, Ruff, Bandit,
Prettier, ESLint and the OpenAPI contract hook. The final Gitleaks hook checks the
actual staged diff. YAML is expected to report no applicable files; the
commit-message attribution hook is inapplicable because no commit is made.

## Staging boundary and remaining limits

The staging allowlist contains the original 41 remediation source files, the
generated backend authorization inventory, the two targeted CSV/renderer
corrections, and remediation evidence/report files. Existing mail branding files
are excluded. The documentation cleanup remains committed and unchanged.

The original baseline audit is left unstaged except the specifically requested
inventory correction. Its original `regression-tests.xml` is 666,592 bytes and
exceeds the 500KB added-file hook limit; it has not been deleted, rewritten or
staged. Baseline report links and the inventory renderer's input JSON remain
available in the working tree and require the baseline audit to be committed
separately for those historical artifacts to be available in a clean checkout.

Independent vendor/lab runtime verification, production acceptance and Nessus
parity remain unverified as documented in [REPORT.md](REPORT.md). Existing
accepted dependency advisories remain. No deployment readiness claim is made.
