# Test report and reproducibility

Source revision: `6d816e23dcbc61a4f96ff106af1f0bc3a1c44ce1`,
14 October 2026. **No production scanner changes** were made, so there is no
before/after fixed-plugin claim. Audit scripts and generated documentation are
the only authored repository changes. Other existing/concurrent user edits were
left intact.

## Environment and safety

The default command sandbox could not initialize (`bwrap: loopback: Failed
RTM_NEWADDR: Operation not permitted`). Approved command execution was used.
This was an environment startup failure, not a test failure or approval rejection.

Required operational backup command:

```bash
scripts/backup_db.sh --skip-reference-data
```

Exit 0; verified archive
`backups/ccure_db_20261014_150321_ops.dump`, reported **5.4 MB**.
It contains sensitive operational data and is not an audit report attachment.
The production application database was not migrated, truncated or used as a
test database. A separate read-only aggregate query inspected content counts.

The API container had pytest installed and an explicit TEST_DATABASE_URL naming
`ccure_pytest_db`. Existing conftest name/forbidden-name/sentinel guards remained
enabled. conftest also redirects Redis to database15, disables live mail
fallback and supplies throwaway test token keys. No test secrets or production
connection URLs were printed.

Current checkout source was copied into `/tmp/ccure-plugin-audit-source` inside
the API container, rather than testing the potentially older baked deployment.
Snapshot command:

```bash
mkdir -p /tmp/ccure-plugin-audit-source
tar --exclude='*.env*' --exclude='*/.env*' --exclude='*/__pycache__' \
  --exclude='Backend/reports' --exclude='Backend/logs' \
  --exclude='Backend/db/*.db*' --exclude='Backend/data/feeds' \
  --exclude='Backend/data/compliance_evidence' \
  --exclude='Backend/data/nuclei-templates' \
  -cf /tmp/ccure-plugin-audit-source.tar Backend docs scripts CLAUDE.md AGENTS.md
docker exec ccure-api mkdir -p /tmp/ccure-plugin-audit-source
docker cp /tmp/ccure-plugin-audit-source.tar ccure-api:/tmp/ccure-plugin-audit-source.tar
docker exec ccure-api tar -xf /tmp/ccure-plugin-audit-source.tar \
  -C /tmp/ccure-plugin-audit-source
```

Read-only scanner-worker availability inspection established:
Nmap, Nuclei, ffuf, sqlmap and subfinder binaries present; Scapy, Paramiko,
pywinrm, Impacket, SSLyze, PyMySQL, psycopg2 and pymssql importable; configured
Nuclei template directory present. **Availability is not successful execution,
template freshness or feed completeness.**

## Executed commands and results

| Step | Result | Evidence scope |
|---|---|---|
| Small relevant subset, first | **178 passed, 0 failed, 0 skipped**, 8.62s; 6 deprecation warnings | Contracts, source selection, network check promotion/normalization/risk/persistence/report seam fixtures |
| Initial audit characterizations | **14 passed, 1 failed** | One attempted combined SMB framing hypothesis was too broad: EternalBlue's payload length is actually correct |
| Corrected audit characterizations | **15 passed**, 1.834s | 14 distinct D IDs; assertions reproduce current defects; source fix was to audit evidence, not production behavior |
| Final characterizations after import-isolation review | **16 passed**, 4.588s | 15 distinct D IDs; fresh subprocess proves unrelated SSH load is blocked by LDAP-only import failure |
| Controlled real loopback engine scan, weak then hardened | **Both assertions passed**, process exit0 | Actual HTTP raw probes, socket TLS/SSLyze, real Nuclei subprocess using a single authored synthetic template; normalization/scoring real |
| Full relevant regression groups, once after targeted validation | **4,592 passed, 0 failed, 0 skipped**, 536.34s; 7 warnings | All scans, credentialed, web, reports and topology tests |
| Nuclei invalid-flag availability/error probe, no target | Exit **2**, message flag not defined | CLI validation only; does not establish live exit1 behavior. D14 exit1 result was exercised through a process double |
| Nuclei nonexistent template and empty /dev/null target list | Exit **1**, fatal no templates provided for scan | Real fatal-exit1 verified without target traffic; plugin acceptance of exit1/no-output separately reproduced with a process double |

The 178 tests are included in the final 4,592; **do not add them as new unique
tests**. The final 16 audit characterizations are outside the Backend pytest suite
and are not release acceptance tests. They intentionally assert the defects
still exist. The first run's failed hypothesis is preserved in
[characterization-initial.log](characterization-initial.log).

Small subset:

```bash
docker exec -w /tmp/ccure-plugin-audit-source/Backend ccure-api python -m pytest \
  tests/scans/test_plugin_contract.py \
  tests/scans/test_network_check_contract.py \
  tests/scans/test_network_check_pipeline.py \
  tests/scans/test_network_check_promotion.py \
  -q -r a --junitxml=/tmp/ccure-plugin-audit-targeted.xml
```

Characterization commands (initial run, correction of the EternalBlue length
assertion, then the final fresh-process import-isolation case):

```bash
docker cp docs/audits/plugin-audit-2026-10-14/characterize.py \
  ccure-api:/tmp/ccure-plugin-audit-source/characterize.py
docker exec -w /tmp/ccure-plugin-audit-source/Backend \
  -e SKIP_DOTENV_LOAD=1 -e PYTHONPATH=/tmp/ccure-plugin-audit-source/Backend \
  ccure-api python /tmp/ccure-plugin-audit-source/characterize.py \
  > docs/audits/plugin-audit-2026-10-14/characterization.log 2>&1
```

Local fixture:

```bash
docker cp docs/audits/plugin-audit-2026-10-14/local_fixture.py \
  ccure-api:/tmp/ccure-plugin-audit-source/local_fixture.py
docker exec -w /tmp/ccure-plugin-audit-source/Backend \
  -e SKIP_DOTENV_LOAD=1 -e PYTHONPATH=/tmp/ccure-plugin-audit-source/Backend \
  ccure-api python /tmp/ccure-plugin-audit-source/local_fixture.py \
  > docs/audits/plugin-audit-2026-10-14/local-fixture.log 2>&1
```

This binds only container-loopback8080/8443 temporarily and shuts them down.
Synthetic content is generated in a temporary directory. SNMP/UDP/ICMP,
Heartbleed/Shellshock and CVE feed lookups are replaced so these do not contact
external targets, perform exploit-condition probes or query production feeds.
Nuclei receives **one local authored template**, not the full third-party corpus.
No FTP write probe is enabled. The fixture is not dispatched as a real Celery
scan and does not persist scan rows.

| Controlled state | Verified findings | HTTP findings | Nuclei findings | TLS findings |
|---|---:|---:|---:|---:|
| Missing headers + exposed synthetic .env | **6** | 2 | 1 | 3 |
| Header/file configuration hardened | **3** | 0 | 0 | 3 |

The three retained TLS findings are self-signed certificate, hostname mismatch
(localhost certificate inspected as127.0.0.1), and absent OCSP stapling. The
certificate was deliberately unchanged between the HTTP states. Thus the second
state is **not a wholly clean TLS host**. Server-side BrokenPipe/handshake
exceptions in local-fixture.log are connection teardown/unsupported-handshake
noise from the protocol/cipher enumeration; the assertions and process completed.
Structured results: [local-fixture-results.json](local-fixture-results.json).

Full relevant suite command, executed **once**:

```bash
docker exec -w /tmp/ccure-plugin-audit-source/Backend ccure-api python -m pytest \
  tests/scans tests/credentialed tests/web tests/reports tests/topology \
  -q -r a --junitxml=/tmp/ccure-plugin-audit-regression.xml \
  > /tmp/ccure-plugin-audit-regression.log 2>&1
```

Warnings: Starlette/AnyIO alias, passlib crypt removal, Pydantic class-based
configuration (four instances), and SSLyze trust-store certificate serial
deprecation in a live TLS test. These did not fail or skip any test.

Archived machine-readable results:
[targeted-tests.xml](targeted-tests.xml),
[regression-tests.xml.gz](regression-tests.xml.gz) (gzip of the original
`regression-tests.xml`, 666,592 bytes, sha256 `822c0fc1…cbcc6` when decompressed),
[regression-tests.log](regression-tests.log),
[characterization.log](characterization.log).

Inventory export (same isolated Python source environment):

```bash
docker cp docs/audits/plugin-audit-2026-10-14/export_inventory.py \
  ccure-api:/tmp/ccure-plugin-audit-source/export_inventory.py
docker exec -w /tmp/ccure-plugin-audit-source/Backend \
  -e SKIP_DOTENV_LOAD=1 -e PYTHONPATH=/tmp/ccure-plugin-audit-source/Backend \
  ccure-api python /tmp/ccure-plugin-audit-source/export_inventory.py \
  > docs/audits/plugin-audit-2026-10-14/inventory.json
python3 docs/audits/plugin-audit-2026-10-14/render_inventory.py
```

The export imported definitions but called no target or database scan. It records
SHA256 for each source module and all 36 Linux and 31 Windows named collection
commands. Those commands are not additional vulnerability-plugin implementations.

Read-only installed-content query:

```bash
docker exec ccure-db psql -U postgres -d ccure_db -X -At -c \
  "BEGIN READ ONLY; SELECT json_build_object(
  'config_rule_rows', (SELECT count(*) FROM compliance_rules WHERE check_definition->>'config_check'='true'),
  'config_rule_rows_active', (SELECT count(*) FROM compliance_rules WHERE check_definition->>'config_check'='true' AND status='active'),
  'installed_benchmark_rows', (SELECT count(*) FROM compliance_tenant_frameworks WHERE is_enabled AND framework_id LIKE 'cfw_bm_%'));
  COMMIT;"
```

Exit0; counts955,955,0. No credentials or benchmark content were exported.

## Representative scenarios and remaining limits

| Requested scenario | Validation performed | What remains unverified |
|---|---|---|
| Linux with valid SSH/package versions | credentialed end-to-end/pipeline fixtures; distro/source/epoch/running-kernel/version tests; real scratch persistence | Real SSH authentication and all collector commands on supported distro targets; feed-to-host detection breadth |
| Linux invalid credentials | Auth/transport failure and selection fixture suites | Real refused account and lockout behavior; no real password guessing attempted |
| Windows supported credentials and enumeration | WinRM/SMB thread/session/native collection, privilege, patch/process identity and selection fixtures | Real Windows host, registry/WMI permissions, DCOM ports, file versions, localized policy evidence |
| Identifiable unauthenticated services | Actual local HTTP/TLS/Nuclei engine; mocked service metadata, candidate/version and port tests | Real Nmap discovery of that fixture and a complete scan initiation/persistence/report run |
| TLS/HTTP | Real local positive/hardened HTTP and retained certificate findings; existing live TLS tests | All STARTTLS products, custom ports, virtual hosts/private trust, vulnerable OpenSSL |
| Prerequisites absent | Gate/unsupported collector/transport/empty-service suites; D01-D04 reproductions | Every supported production service/layout |
| Known vulnerability and clean control | Synthetic exposed-file template weak/hardened; package/CVE ranges positive/negative; mocked active-CVE promotion | Actual known affected and patched CVE-specific SMB/CGI/Heartbleed hosts |
| Config/compliance/database | Full rule/collector/operator/SCAP and configuration-finding fixture tests | Each of155 source built-ins, imported955 rows, production framework scores, actual database targets |

No complete repository test suite, deployment change, external network sweep,
full vendor Nuclei corpus scan or actual Nessus scan was performed. The relevant
scanner groups were run once. Pure governance/compliance, frontend and unrelated
platform suites were not run; none of their code was changed. Tests did not
require a newly provisioned target host or a destructive target operation.

The additional target-free fatal-error probe was:

```bash
docker exec ccure-worker nuclei -t /tmp/ccure-audit-nonexistent-template -l /dev/null -duc -ni -silent
```

It exited 1 with `Could not run nuclei: no templates provided for scan`. No host was supplied.
