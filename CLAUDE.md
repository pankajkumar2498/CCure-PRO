# CCure-Audit-PRO — working notes for agents

## ⚠️ Running the test suite

**`Backend/tests/` is destructive.** It `TRUNCATE`s `organizations` and `users`
`CASCADE`, which reaches `scans`, `scan_phases`, `assets`, `services`,
`asset_change_log`, `audit_logs` and `notifications`.

The live application database is named **`ccure_test`**. That name looks
disposable and is not. On 10 Aug 2026 a full-suite run inherited the API
container's `DATABASE_URL`, was accepted by a guard that matched `_test$`, and
destroyed all users, orgs, scans and assets. There was no recovery:
`archive_mode` is `off`.

Three layers now prevent a repeat, in `Backend/tests/conftest.py`:

1. `TEST_DB_NAME_PATTERN` only accepts `^pytest_`, `_pytest`, `_pytest_db`.
2. `FORBIDDEN_DB_NAMES` rejects `ccure_test`, `ccure_db`, `vuln_intel`, … even
   if renamed into the pattern.
3. `_assert_database_is_disposable()` refuses any database holding rows in
   `users` / `scans` / `assets` / `services` unless it carries the
   `_pytest_scratch_marker` sentinel table.

`docker-compose.yml` also pins `TEST_DATABASE_URL` to `ccure_pytest_db` on the
`api`, `worker` and `web-worker` services, so `docker exec … pytest` cannot
inherit the live URL.

**Before any destructive operation** (test run, migration, bulk delete):

```powershell
$env:PGPASSWORD = '<password>'
.\scripts\backup_db.ps1 -SkipReferenceData   # fast: operational data only
```

Restore with `pg_restore --clean --if-exists -d ccure_test <file>.dump`.

A scheduled task **CCure DB Backup** already dumps operational data every 6
hours into `backups/` and prunes after 30 days (registered by
`scripts/install_backup_schedule.ps1`). Check it with:

```powershell
Get-ScheduledTask -TaskName 'CCure DB Backup' | Get-ScheduledTaskInfo
```

`archive_mode` is still `off`, so recovery granularity is "since the last
dump", not point-in-time. Ad-hoc dumps before risky work are still worth taking.

### Known test-suite failures

None. The three entries that used to sit here are all resolved, and two of them
were not what they looked like:

- `test_scans.py::test_host_discovery_endpoint` was recorded as needing
  `CELERY_TASK_ALWAYS_EAGER=True`. It asserts on rows the Celery task writes, so
  the task has to run before the assertions do — but whether it did was decided
  by a deployment setting this machine deliberately sets to `False` so the host
  worker can perform live scans. The test now enables eager execution for itself
  and restores the previous value afterwards, so it passes under either setting.
  A test should not depend on how the machine it runs on is configured.

- `test_docs_integrity.py` (3 tests) was recorded as documentation drift. It was
  not: `docs/` was never mounted into the container, so the test could not find
  any of the three files it checks and failed on all of them. `docker-compose.yml`
  now mounts `./docs:/docs:ro` on the `api` service. With the mount in place the
  test found exactly one genuinely undocumented route, which is now documented.
  If this fails again, it means a route, table or permission really was added
  without updating `docs/`.
- `test_schema_drift.py::test_models_have_no_unmigrated_changes` was recorded as
  uncommitted model edits. Migration `z9e0f1g2h3i4` brought the schema and the
  models back into agreement and it passes.

Baseline as of 11 Aug 2026: the suites touching scans, findings, reports,
credentialed scanning, compliance and schema run clean apart from the eager-mode
test above.

## Architecture

- **API** — `ccure-api` container, `127.0.0.1:8000`, mounts `./Backend` (restart
  picks up Python changes; no rebuild needed).
- **Frontend** — `ccure-frontend`, `localhost:3200`. Assets are **baked at build
  time**; JSX changes need `docker compose build frontend && docker compose up -d
  --no-deps frontend`.
- **Scanner worker** — Celery on the **Windows host**, not in Docker, so Nmap and
  Scapy get raw-socket access to the physical network. Start with
  `.\Backend\scripts\scan\start_host_scanner_worker.ps1`. Restart it after
  changing anything under `core/`, `scans/` or `orchestrator/`.
- **Database** — PostgreSQL 18 on the host, `ccure_test`. The `ccure-db`
  container runs but is unused; both API and worker point at the host server.
  The cluster's data directory was moved to **`D:\PostgreSQL\18\data`** on
  11 Aug 2026 (C had 61 GB free and the feeds needed room). The service's
  `ImagePath` in `HKLM:\SYSTEM\CurrentControlSet\Services\postgresql-x64-18`
  points there. The old directory is kept as
  `C:\Program Files\PostgreSQL\18\data.old-premove-20260811` — deleting it
  reclaims 8.4 GB. `D:\` grants `Authenticated Users:(F)` by inheritance, so
  inheritance is disabled on both `D:\PostgreSQL` and the data directory; do
  not re-enable it.
- **Auth** — `POST /auth/login` takes `{"email": ..., "password": ...}` (the
  field is `email`, not `username`). Access tokens last 30 minutes; the refresh
  token is an HttpOnly cookie valid 7 days.

## Scan pipeline

`pipeline_mode` selects the phases: `basic` = 1, `asset` = 1+2,
`vulnerability_audit` = 1+2+3. The UI posts to `/scan/host-discovery` and the
backend auto-chains the later phases.

- **Phase 1** — `core/discovery/engine.py`, Scapy only (ARP/ICMP/TCP/UDP). No
  Nmap, no port scanning.
- **Phase 2** — `core/nmap/wrapper.py` via `engines/port/port_engine.py`. Normal
  intensity scans ports 1-1024 plus a curated high-port list from
  `PORT_DB` (~1,127 ports), with OT ports excluded by default.
- **Enrichment** — `core/discovery/enrichment.py`. When adding a probe, pass the
  real transport to `_register_open_port(..., protocol="udp")`. SNMP, mDNS and
  NetBIOS-NS are UDP; recording them as TCP claims an open TCP port that is
  usually filtered, and that claim reaches the asset registry and the reports.

## Data model notes

- `services` is a **current-state projection**, not per-scan history. The row id
  is `gen_service_id(asset, port, protocol)`, so re-scanning re-points rows
  rather than adding a generation. Point-in-time results live in
  `scan_phases.summary`, which the scan-detail API and reports read back.
- `assets` is keyed by `(org_id, ip_address)` and `(org_id, mac_address)`.
  Re-scans update in place; `first_seen_at` is preserved and per-field
  provenance is tracked in `custom_attributes.provenance`.
- Timestamps in scan payloads are timezone-aware UTC. Do not introduce naive
  `datetime.now()` — it renders as local time beside UTC siblings.

## Vulnerability feeds (`vuln_intel`)

`vuln_intel` is a separate database with its own schema, and it is **not under
this repo's alembic control** — its `alembic_version` names a revision that
exists nowhere in the tree. Each sync script asserts the tables it needs, so
the feeds can be rebuilt onto an empty server.

- `Backend/scripts/vuln/sync_osv.py` — osv.dev advisories. Written 11 Aug 2026
  because **there was no ingest path at all**: 3.1M rows existed with nothing
  able to refresh or rebuild them. Stages under `CCURE_FEED_DIR` (see `Backend/.env.example`). Default set
  covers 22 ecosystems; `--list` shows what osv.dev publishes.
- `Backend/scripts/vuln/sync_msrc.py` — Microsoft Security Update Guide
  (CVRF v3.0, no API key). Populates `msrc_document`, `msrc_product`,
  `msrc_remediation` and the `msrc_product_build` view. Caches raw JSON in
  `CCURE_FEED_DIR`; re-runs only fetch months whose `CurrentReleaseDate`
  moved.
- `Backend/scripts/vuln/sync_exploit_intel.py` — exploit availability from
  ExploitDB, Metasploit (read from ExploitDB's tags) and Nuclei templates,
  merged with CISA KEV. Before it, the `exploits` table held 1,647 rows all
  sourced from KEV, so `has_exploit` was an exact synonym for `in_kev` and both
  `has_exploit` branches in `compute_priority` were unreachable. Now 29,287
  rows, 27,640 of them outside KEV. `verified_exploit` marks the subset
  ExploitDB confirmed reproducible.
- `Backend/scans/nvd_sync.py` — NVD, pre-existing. Needs the API key in `.env`.

- `Backend/scripts/vuln/sync_csaf.py` — CSAF 2.0 vendor and government
  advisories: **Siemens ProductCERT**, **CISA ICS/OT and IT**, Red Hat. Adding
  a provider is one entry in `PROVIDERS`, because discovery follows the
  standard — `provider-metadata.json` names ROLIE feeds, the feed lists
  advisories. Documents cache in `CCURE_FEED_DIR`.

  Two things to know before extending it:

  - **The `.well-known/csaf/` path does not work for these providers.** Both
    Siemens and CISA return HTTP 403 there and it looks exactly like a network
    block — it is not. Siemens publishes at
    `/productcert/csaf/provider-metadata.json` and CISA at
    `/sites/default/files/csaf/provider-metadata.json`. Always start from the
    provider's documented metadata URL, never a guessed well-known path.
  - Red Hat publishes a `directory_url` distribution rather than ROLIE, so it
    has no machine-readable index. The script warns and skips it instead of
    scraping HTML.

  Stored data is advisories, their CVEs, affected product names, the vendor's
  own remediation wording, and — in `csaf_affected.version_constraint` — the
  machine-readable version range.

  **Read `version_constraint`, never `product_name`, when matching.** The two
  live side by side and only one is parseable. `product_name` is prose for a
  human: "TIA Portal v15: All versions prior to v15.1 Update 7", "SIMATIC
  STEP 7 (TIA Portal) and WinCC (TIA Portal) V15" (two products in one row),
  "Siemens SIMATIC WinCC 7.3: <Update_10". Measured across 107,747 rows, only
  **11.4%** of those yield a constraint a parser can act on, which makes the
  corpus look unmatchable. The branch name beside it carries the structured
  form — the OpenSSF `vers` spec (54%) or a plain operator and version (43%),
  **97.6% machine-readable**. The first version of this ingest stored only the
  prose and discarded the branch name, and the conclusion drawn from that
  measurement — that CSAF matching could not be built safely — was an artefact
  of measuring the wrong column.

  `engines/credentialed/csaf_matcher.py` matches installed software against
  these. It is the only path that reaches OT software at all: TIA Portal,
  WinCC and SIMATIC either have no CPE or none anyone publishes against, so
  the CPE path sees nothing on an engineering station. On the audited host it
  produced 14 findings nothing else could.

  **Two conditions, both required, both derived from measurement.** Token
  containment — the rule the Microsoft application matcher uses — was tried
  first and produced **1,901 matches from 191 packages**, mostly wrong:

      Google Cloud SDK                    ->  TIA Portal Cloud V16
      SIMATIC WinCC Runtime Advanced V17  ->  SIMATIC WinCC 7.2

  Stripping vendor and family noise from an OT name removes the words that
  distinguish the products — "Runtime", "Advanced", "Professional" — leaving a
  generic token like `wincc` that matches half the catalogue. So:

  1. **Normalised whole-name equality**, not containment.
  2. **Release-line agreement.** An advisory for "SIMATIC ProSave V18" with
     `vers:all/*` means every version *of the V18 line*. Without this rule an
     installed V19 inherits V18's and V20's advisories — the same failure as
     the Windows servicing-line bug. It correctly withheld WinCC Runtime
     Advanced V11–V16 advisories from an installed V17.

  A constraint the matcher cannot order (`<V19_Update_4`, "All versions prior
  to the latest build") yields **no finding** and is counted as unassessed.
  Seven such constraints were skipped on the audited host rather than guessed.

  Enrichment by exact CVE match is separate and also safe
  (`core.vuln_intel.csaf_advisories_for`).

  **Pace it politely.** Fetched with eight threads and no delay, Siemens'
  portal began returning 403 with "You made too many requests in a short time
  for our system… please contact productcert@siemens.com", and 137 of 831
  documents were lost — which looks exactly like corrupt data in the log. At
  1 worker with a 0.4s delay all 831 fetch cleanly. Per-provider `workers` and
  `delay` live in `PROVIDERS`; do not raise Siemens'.

  An enriched advisory covers the same **CVE**, not necessarily the same
  **product**. A Chrome CVE appears in a CISA ICS advisory because an ICS
  product embeds Chrome, and that advisory's mitigation is written for the ICS
  context. `vendor_remediation` is therefore always prefixed with the advisory
  id, so ICS guidance can never read as the desktop vendor's own advice.

- `Backend/scripts/vuln/sync_vulncheck.py` — VulnCheck KEV, 5,117 entries
  against CISA's 1,647: **3,470 exploited CVEs CISA does not list**. Needs
  `VULNCHECK_API_TOKEN` in `Backend/.env` (free tier, vulncheck.com). Note the
  API caps pagination at **6 pages regardless of page size**, so `_PAGE_SIZE`
  must stay large enough that 6 pages covers the catalogue — a smaller page
  size truncates the feed silently. The script warns if it retrieved fewer
  entries than the API reports.

  **Stored in its own table, not merged into `kev`.** CISA KEV drives BOD 22-01
  remediation deadlines and every entry carries a `due_date`; a report showing
  "in KEV" is read as "there is a mandated fix-by date". VulnCheck KEV is
  threat intelligence with no deadline and no compliance duty. Merging them
  would attach an imaginary federal deadline to 3,470 vulnerabilities, and a
  compliance report built on that would be wrong invisibly. `in_kev` keeps
  meaning exactly CISA KEV.

  `vulncheck_kev.canary_confirmed` marks the 481 CVEs observed being exploited
  against VulnCheck's own honeypots — direct observation rather than a report
  of one, and the strongest exploitation evidence in any feed here. It is the
  only VulnCheck signal allowed to set `verified_exploit`.

Secrets live in `Backend/.env` (gitignored), which is what `config.py` loads —
**not** the repository-root `.env`, which is for docker-compose. A token placed
in the root file is silently ignored by every script here.

`has_exploit` means a public exploit exists for the CVE. It does **not** mean
the scanned host is exploitable, which depends on configuration and
reachability this feed knows nothing about. Do not render it as proof of
exploitability.

Things about OSV worth knowing before trusting a query against it. Each of
these was a silent false negative found by scanning a real target, not a
theoretical concern — all four produced a confidently clean report:

- OSV **does** carry `Red Hat`, `Rocky Linux`, `AlmaLinux`, `SUSE` and
  `openSUSE` now. Separate OVAL/CSAF parsers are not needed for RHEL-family
  coverage.
- **Ecosystem names are not uniform.** Rocky and Alma are `Rocky Linux:9` /
  `AlmaLinux:9`, but Red Hat splits a release across repository modules
  (`Red Hat:enterprise_linux:9::appstream`, `::baseos`, `::crb`) and SUSE names
  products (`SUSE:Linux Enterprise Server 15 SP5`). `osv_ecosystems_for()`
  returns **LIKE patterns**, and both OSV queries use `LIKE ANY`. The earlier
  `Red Hat:9` form matched zero rows.
- **RHEL-family and SUSE advisories carry no `aliases` field.** They put CVE
  references in `upstream` and `related` — 0 of 3,846 Rocky records have
  `aliases`. The matcher reaches findings through an inner join on
  `osv_aliases.cve_id`, so ingesting only `aliases` left every RHEL-family
  advisory unreachable. `sync_osv.py` reads all three fields.
- **Distribution versions need distribution comparison.** `_parse_version`
  strips everything from `el9`/`ubuntu` onward, which is right for upstream CPE
  ranges and catastrophic for OSV: a backported fix (`2.34-274.el9_8` against
  installed `2.34-266.el9_8`) compares equal, and backports are how
  distributions fix nearly everything. Use `compare_distro_versions()` —
  rpmvercmp ordering with epoch and `~` handling — on the OSV path.
- **RPM epochs must be collected.** `linux_collector` emits
  `%|EPOCH?{%{EPOCH}}:{0}|` so the epoch is always present. Without it Rocky's
  openssl (epoch 1) defaulted to epoch 0 and matched every advisory fixed in
  `1:3.0.1-…`, reporting a 3.5.5 install as vulnerable to a flaw fixed four
  releases earlier.
- `osv_ranges` now carries `ecosystem` and `package_name`, and both matcher
  queries join on them. Before that, an advisory covering several packages or
  releases had its ranges applied to all of them — an Ubuntu 24.04 package was
  reported as fixed in a 25.10 version that cannot be installed on it. Rows
  predating the columns are NULL and still match, so a partial re-sync degrades
  to the old behaviour rather than dropping ranges.

### Active template verification (Nuclei)

`engines/vulnerability/plugins/nuclei_probe.py` runs ProjectDiscovery's
templates and produces the only findings in this product that are *proven*
rather than inferred — a template matched a live response, so the
vulnerability is present and reachable now. They grade as `active_check` →
`CONFIG_CHECK`, QoD 99, Confirmed.

Binary and templates are located via `NUCLEI_BINARY` and
`NUCLEI_TEMPLATES`; the defaults are `nuclei` on PATH and
`~/nuclei-templates`. This repository is shared, so no absolute path is
hardcoded — a machine-specific default silently disables the plugin for
everyone else. ~13,510 templates when fully installed.
and logs it; an unavailable optional probe is a coverage gap, not an error.

Four things measured the hard way, all of which produced *zero findings*
before they were fixed:

- **Serial plugins are called with three arguments** (`ip, open_ports,
  port_details`). A two-argument `run` raises TypeError, the engine catches
  plugin exceptions at debug level, and the plugin looks registered while
  never executing.
- **Do not allow-list web ports.** An allow-list gave a web server on 8099
  only a bare `host:port` target, so the HTTP templates — most of the corpus —
  never engaged. Everything not in `_NON_HTTP_PORTS` now gets a URL target too.
- **Do not run the full corpus.** 13,510 templates exceeded 600s against one
  host and returned nothing, which reads as "verified, nothing found". Default
  is `critical,high,medium` (7,460 templates); most of the excluded mass is
  `info`, which is technology *detection*, and grading "nginx present" as
  Confirmed at QoD 99 would bury the real findings.
- **`-exclude-tags dos,fuzz,intrusive,brute-force` and `-no-interactsh` are
  not optional.** This scans production and OT hosts: an audit that causes an
  outage is worse than the finding it would have produced, and out-of-band
  callbacks leak target identity off-site and need egress OT segments lack.

Measured: 129s for one web port, 289s for three ports at `critical,high`.
Nuclei ships overlapping templates, so one exposed `.env` legitimately matches
`generic-env`, `laravel-env` and `codeigniter-env` — three rows for one
problem. They are not false positives; the file really is exposed.

### Test targets

Two disposable containers exist for validating credentialed collection. Both
are deliberately **not** updated after build — an up-to-date target cannot tell
"matching works and the host is clean" apart from "matching is broken", which
is how five separate false negatives survived until they were scanned.

```powershell
docker start ccure-rocky-target    # Rocky 9.8,  ssh 127.0.0.1:2222  root / ccure-test-only
docker start ccure-ubuntu-target   # Ubuntu 24.04, ssh 127.0.0.1:2223  root / ccure-test-only
docker start ccure-nuclei-target   # nginx on 127.0.0.1:8099 serving .env and .git/config
```

`ccure-nuclei-target` exists because neither real host triggers a Nuclei
template — 10.180.6.14 is a Windows workstation with no web server, and a
scanner that finds nothing there looks identical to one that is broken. It
serves a deliberately exposed `.env` and `.git/config`, which must produce
**4 findings, all Confirmed at QoD 99**. Zero from it is a regression.

Expected at the time of writing: Rocky 48 findings (4 Critical), Ubuntu 7 (all
with no fix published upstream). A run returning **zero** on either is a
regression, not a clean host.

### Coverage figures

`VulnMatcher.coverage()` reports two percentages and they answer different
questions. `coverage_pct` is over every collected package;
`coverage_pct_software` excludes toolchain components — SDK headers, `vs_*`
resource MSIs, IntelliSense metadata — which NVD publishes no CPE for because
none is independently vulnerable. On a real Windows host 98 of 191 packages
are such components, so the unfiltered figure understates coverage as badly as
counting them assessed would overstate it. Keep reporting both.

### Windows assessment

Windows is absent from the uninstall registry, so package matching never saw
the OS. `engines/credentialed/windows_patch.py` compares the host's build
against MSRC's published fixed builds instead.

- **Do not match on installed KBs.** `Get-HotFix` returned **4 entries** on a
  fully patched host — cumulative updates supersede one another, so the KB that
  first fixed a CVE is never present. Build comparison is the only reliable
  primitive.
- The collector must supply the **UBR**. `Win32_OperatingSystem.Version` stops
  at `10.0.26200` and omits the revision; without it every host looks like the
  day-zero release. `windows_collector` reads it from the registry and folds it
  into `os_version_id`.
- **Compare only within the host's own build line.** Microsoft lists one
  product against several lines — Windows 11 25H2 carries both `10.0.26100.x`
  and `10.0.26200.x` fixes. Taking the earliest fix across lines picks a
  `26100` build a `26200` host exceeds, silently dismissing real findings. This
  reported 19 missing patches where the truth was 736.
- A build line that maps to no product is reported as **not assessed**, never
  as "no missing patches".

## Reports

- `GET /reports/download/{scan_id}?fmt=…` — `JSON`/`executive` → executive PDF,
  `XML`/`technical` → technical PDF, `CSV` → host inventory. All PDF; the
  `JSON`/`XML` names are historical.
- Reports are generated at scan completion and stored on
  `scans.report_executive_path` / `report_technical_path`. The download endpoint
  serves the stored file and only regenerates when it is missing — do not make
  generation unconditional again (it orphaned a PDF pair per download and bumped
  `scans.updated_at`, which corrupted the Scan History date).
- No Excel/XLSX export exists in the scan modules. DOCX exists only in
  Compliance.
