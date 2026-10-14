# Remediation tests and reproducibility

This report covers the corrected plugin behavior, not the historical audit's
defect-asserting characterizations. Those 16 baseline characterizations reproduced
the original conditions and are excluded from acceptance counts. Corrected
assertions and positive/negative cases are in the three new Backend regression
files and the amended promotion/UI tests listed in [REPORT.md](REPORT.md).

## Safety and source provenance

The working tree was inspected before changes. Existing authentication branding
edits, the baseline audit, and subsequent concurrent registry/architecture/docs
edits were preserved. [source-manifest.json](source-manifest.json) records the
41 remediation-owned source files; all 32 Backend files were hash-compared with
the isolated snapshot used for the final acceptance run, with zero mismatches.
No deployment was initiated by this task. An API container recreation outside
this task removed an earlier temporary snapshot; the final snapshot and test-only
dependencies were restored under `/tmp` before final acceptance.

The repository-required backup command was run before destructive tests:

```bash
scripts/backup_db.sh --skip-reference-data
```

Both remediation backups exited 0:
`backups/ccure_db_20261014_175845_ops.dump` (reported 1.6 MB) and
`backups/ccure_db_20261014_200812_ops.dump` (reported 1.7 MB).
Backup contents are sensitive and are not attached as test evidence.

The final tests use **ccure_plugin_remediation_pytest_db**, a separate disposable
database owned by `ccure_user`. The existing name, forbidden-name and scratch
sentinel guards remain enabled. conftest redirects Redis to DB15, disables live
mail fallback and supplies throwaway token keys. No test module assigns
`DATABASE_URL`. The launcher reads `TEST_DATABASE_URL` and changes only its
database path, without printing credentials. No production database was used as
a test database or migrated/truncated by this task. Network fixtures use mocks or
loopback, without live scan dispatch or unauthorized target traffic.

## Exact final commands

Source snapshot, excluding environment files and runtime data:

```bash
tar --exclude='*.env*' --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='Backend/reports' --exclude='Backend/logs' \
  --exclude='Backend/evidence' --exclude='Backend/feeds' --exclude='*.db' \
  -cf /tmp/ccure-plugin-remediation-final.tar \
  Backend docs scripts CLAUDE.md AGENTS.md
docker cp /tmp/ccure-plugin-remediation-final.tar \
  ccure-api:/tmp/ccure-plugin-remediation-final.tar
docker exec ccure-api mkdir -p /tmp/ccure-plugin-remediation
docker exec ccure-api tar -xf /tmp/ccure-plugin-remediation-final.tar \
  -C /tmp/ccure-plugin-remediation
docker cp docs/audits/plugin-remediation-2026-10-14/run_disposable_tests.py \
  ccure-api:/tmp/ccure-plugin-remediation-run-tests.py
docker exec ccure-api python3 -m pip install \
  --target /tmp/ccure-plugin-remediation-pinned-deps \
  'pymongo==4.18.3' 'ldap3==2.9.1' 'pyasn1==0.5.1' 'dnspython==2.9.0'
```

The final malformed AXFR negative fixture was first run without its guard using
the focused command below with `-k empty_or_incomplete_axfr` and only the P0 test
file: **4 passed, 1 failed, 44 deselected**. The failure was the repeated closing
SOA case. The guard was then copied into the frozen snapshot. Final negative
regressions and existing report-integrity tests:

```bash
docker exec -w /tmp/ccure-plugin-remediation/Backend \
  -e SKIP_DOTENV_LOAD=1 \
  -e PYTHONPATH=/tmp/ccure-plugin-remediation/Backend:/tmp/ccure-plugin-remediation-pinned-deps \
  ccure-api python /tmp/ccure-plugin-remediation-run-tests.py \
  tests/scans/test_plugin_remediation_p0.py \
  tests/scans/test_plugin_remediation_p1.py \
  tests/scans/test_plugin_remediation_pipeline.py \
  tests/reports/test_report_integrity.py \
  -q -r a --junitxml=/tmp/ccure-plugin-final-negative-regressions.xml \
  > /tmp/ccure-plugin-final-negative-regressions.log 2>&1
```

**169 passed, 0 failed, 0 skipped**, 11.25 seconds, six deprecation warnings.

Final relevant regression command, once after the last batch of fixes:

```bash
docker exec -w /tmp/ccure-plugin-remediation/Backend \
  -e SKIP_DOTENV_LOAD=1 \
  -e PYTHONPATH=/tmp/ccure-plugin-remediation/Backend:/tmp/ccure-plugin-remediation-pinned-deps \
  ccure-api python /tmp/ccure-plugin-remediation-run-tests.py \
  tests/scans tests/credentialed tests/web tests/reports tests/topology \
  tests/repo/test_architecture_guardrails.py tests/repo/test_schema_drift.py \
  -q -r a --junitxml=/tmp/ccure-plugin-acceptance-regression.xml \
  > /tmp/ccure-plugin-acceptance-regression.log 2>&1
```

**4,779 passed, 0 failed, 0 skipped**, 553.12 seconds, seven deprecation
warnings. Machine-readable totals are in [test-summary.json](test-summary.json),
with full test cases in [compressed JUnit XML](evidence/backend-full.xml.gz).
Earlier broad runs were repeated only to resolve actual
dependency failures or newly corrected selection/evidence conditions, not after
each small edit. Warnings concern existing Starlette/AnyIO, passlib, Pydantic and
SSLyze certificate-serial deprecations.

Frontend commands, from `Frontend/`:

```bash
npm ci --no-audit --no-fund
npm run ux4g:check
VITE_API_BASE_URL=/api npm run build
npm run ux4g:verify
npm run ux4g:check -- --dist
npm run ux4g:architecture
node scripts/build-authorization-inventory.mjs --check
npm run lint
npm test -- --maxWorkers=2
UX4G_BROWSER_OUTPUT=/tmp/ccure-plugin-browser-clean-results \
UX4G_BROWSER_REPORT=/tmp/ccure-plugin-browser-clean.json \
  npm run test:browser -- --project=chromium
```

The unit suite passed **3,171 tests in 122 files**, zero failed/skipped, 230.90s.
The final full Chromium suite passed **240 tests**, zero failed/skipped, 5.2m.
UX4G baseline/dependency/dist/architecture gates, two byte-identical independent
asset builds, authorization inventory and ESLint passed. The production frontend
build succeeded (328 transformed modules); existing bundle-size/dynamic-import
warnings remain. Package manifests, lockfile and UX4G pin/checksums are unchanged.

New coverage feature matrix:

```bash
UX4G_BROWSER_OUTPUT=/tmp/ccure-plugin-browser-matrix-results \
UX4G_BROWSER_REPORT=/tmp/ccure-plugin-browser-matrix.json \
  npm run test:browser -- browser-tests/plugin-coverage.spec.mjs
UX4G_WEBKIT_EXECUTABLE=/tmp/ccure-plugin-webkit-runtime/run-webkit.sh \
UX4G_BROWSER_OUTPUT=/tmp/ccure-plugin-webkit-runtime-results \
UX4G_BROWSER_REPORT=/tmp/ccure-plugin-webkit-runtime.json \
  npm run test:browser -- --project=webkit browser-tests/plugin-coverage.spec.mjs
```

Final feature results: **Chromium 4, Firefox 4, WebKit 4 passed**, no assertions
skipped. Cases cover 320/1440px, light/dark, failure/timeout visibility, keyboard
access, axe, CSP, layout and read-only/no-external-request guards. The first
WebKit launch failed because the host lacked runtime libraries. The successful
run used repository-supported `UX4G_WEBKIT_EXECUTABLE` with the same unmodified
Playwright WebKit2359 binary and temporary extracted libraries under `/tmp`.
No test-validation bypass, assertion relaxation, system-library installation or
browser binary modification was used.

## Intermediate results and corrections

These runs overlap; **do not add their counts** to the final unique suite count.

| Run                                                   | Pass / fail / skip or error   | Resolution                                                                                                                             |
| ----------------------------------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Original baseline characterizations on pre-fix source | 16 / 0 / 0                    | Reproduction only; deliberately defective assertions excluded from acceptance.                                                         |
| Initial P0/contract subset                            | 59 / 1 / 0                    | LDAP rootDSE negative case corrected before the isolated P0 run.                                                                       |
| Initial default scratch DB subset                     | 168 passed / 3 fixture errors | Another test run was using the same scratch DB. Created a separate disposable remediation DB; final fixture runs passed.               |
| Isolated P0 relevant subset                           | 171 / 0 / 0                   | Passed.                                                                                                                                |
| P0 pipeline/report subset                             | 17 / 0 / 0                    | Passed.                                                                                                                                |
| Initial P1 relevant subset                            | 290 passed / 1 fixture error  | Corrected the fixture import to the existing `db.models.findings.Service`; subsequent pipeline run passed 8 tests.                     |
| Earlier broad subset                                  | 4,766 / 1 / 0                 | Temporary unconstrained pyasn1 installation broke SNMP imports; restored the repository's `<0.6.0` constraint.                         |
| Constrained topology suite                            | 110 / 0 / 0                   | Passed with pyasn1 0.5.1; no SNMP code or constraint relaxation.                                                                       |
| P0/P1/contract/promotion/TLS/topology subset          | 229 / 0 / 0                   | Passed.                                                                                                                                |
| Broad run before final negative guard batch           | 4,774 / 0 / 0                 | Passed, 608.68s. Superseded for acceptance by the final frozen-source run.                                                             |
| Initial full Chromium                                 | 238 / 2 / 0                   | Historical P3 fixture omitted the scan API record. Added the read-only response; individual reruns and final full 240-test run passed. |
| Final negative regressions                            | 169 / 0 / 0                   | Scope unknown-key rejection, derived-evidence preservation and AXFR closure guards included.                                           |

Two mistyped command paths were corrected before collection (a report-integrity
test path and an authorization checker path); they produced no test-case results.
One failed snapshot copy occurred after external container recreation and was
resolved by restoring `/tmp` source. These are environment/invocation failures,
not omitted failing acceptance tests.

## Static security and dependency checks

Python checks use Black24.4.2, Ruff0.4.8 and Bandit1.9.4 under a temporary tool
directory. The Python portion of [changed-files.txt](changed-files.txt) is the
exact file argument list (31 files):

```text
python3 -m black --check <31 owned Python paths>
python3 -m ruff check --select=E,F,W \
  --ignore=E402,F401,F841,E711,E712,E741,F601,E722,F821,E501 \
  <31 owned Python paths>
python3 -m bandit -lll -x tests <owned non-test Python paths>
```

All three gates exited 0. Bandit's all-severity exploratory scan also recorded
existing medium/low issues; it was not represented as a zero-issue security
audit. The repository's high-severity gate found zero high findings, used no
blanket rule skips, and retained specific inline `nosec` exceptions reported by
Bandit. Gitleaks v8.30.1 scanned the 41 owned source files with the repository
config, redacted output, read-only source and no network: **no leaks**, exit0.
The final source-plus-report scan also exited 0 with no leaks. Two initial
matches were verified SHA256 digests under credential-named JSON keys; the
manifest now uses explicit `path` and `sha256` fields. No scanner rule or
allowlist changed.

```bash
docker run --rm --network none \
  -v /tmp/ccure-plugin-remediation-secret-scan:/scan:ro \
  -v /tmp/ccure-plugin-remediation-secret-results:/results \
  zricethezav/gitleaks:v8.30.1 dir /scan --config /scan/.gitleaks.toml \
  --redact --no-banner --report-path /results/gitleaks.json
```

Pip-audit2.10.1 audited the isolated set PyMongo4.18.3, ldap3.2.9.1,
pyasn1.0.5.1 and dnspython2.9.0:

```bash
PYTHONPATH=/tmp/ccure-plugin-remediation-audit-tools python3 -m pip_audit \
  --disable-pip --no-deps -r /tmp/ccure-plugin-new-dependencies.txt \
  --format json --output /tmp/ccure-plugin-new-dependencies-audit.json
```

The raw audit reports eight advisory entries representing four distinct ASN.1
advisories: `PYSEC-2026-2263`, `PYSEC-2026-3455`, `PYSEC-2026-3456`,
`PYSEC-2026-3457`. All four already appear in
[the accepted-advisory file](../../../.github/security/pip-audit-accepted.txt)
for the existing SNMP compatibility bound. New unaccepted advisories: **0**.
PyMongo, ldap3 and dnspython had none in this audit. No exception file or ASN.1
constraint changed. This was a scoped dependency audit, not a fresh audit of the
whole existing dependency tree.

The evidence directory contains final logs, compressed JUnit XML, browser JSON
reports, dependency-audit JSON and source/artifact hashes. Runtime capabilities
without independent vendor/lab verification remain explicitly **unverified** in
[REPORT.md](REPORT.md).

Verify the sealed artifact set from the repository root:

```bash
cd docs/audits/plugin-remediation-2026-10-14
sha256sum --check MANIFEST.sha256
```
