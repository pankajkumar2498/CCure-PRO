# Engineering record: Remediation and SLA, scan comparison and finding lifecycle, data model notes

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 3492–3606, 3721–3825, 3880–3951, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 3492-3606 -->
## Remediation and SLA (`core/remediation/`)

Who owns a finding, when it is due, and whether it was _really_ fixed. GAP-14;
tracker §9Q. **No parallel finding engine and no parallel lifecycle** — it
operates on the `AssetVulnerability` rows the scan pipeline already writes and
consumes GAP-13's comparison for its verdicts. Since G3 it is part of the
findings capability (D-6).

- **`remediation_state` is a second column, not more `status` values.**
  `status` (open/fixed/accepted) answers a _detection_ question — is this
  finding present on the host — and is written by both scan sweeps and read by
  the dashboard, the asset risk recompute, the findings list and GAP-13, with
  roughly a dozen call sites testing `status == "open"`. Adding
  `in_remediation` to it would have made every one of those silently stop
  counting the finding, so **putting a finding into remediation would remove it
  from the dashboard, from the asset's risk score and from the overdue list.**

- **No human action can reach `verified_fixed`, and the transition table says
  so by omission.** `_HUMAN_TRANSITIONS` has no edge into it from any state;
  `core/remediation/verification.py` is the only caller permitted to pass
  `by_assessment=True`. What a person can say is `pending_verification` — "the
  fix is applied and ready to be checked", which is a much weaker claim and the
  only one they are in a position to make. The method is `claim_fixed`, not
  `mark_fixed`, for the same reason.

- **The defect this phase exists to fix.** `PATCH /findings/{id}/status` with
  `status="fixed"` used to stamp `fixed_at = utcnow()` from any user holding
  `findings:update` — and `fixed_at` is the column GAP-13 reconstructs its
  baseline from. A person clicking a button was writing into the evidence
  timeline the comparison, the reports and every remediation figure trust. The
  endpoint still records the caller's own triage status; it no longer writes
  `fixed_at`, routes the finding to `pending_verification`, and says so in the
  response.

- **Verification consumes GAP-13; it does not re-decide.** `fixed` →
  `verified_fixed` citing the scan, `reappeared` → `reopened`, and **nothing
  else moves anything**. Four refusals, each of which would otherwise be a
  false claim of remediation: `not_assessed` never verifies (GAP-13's word for
  "this scan did not look"), a non-comparable comparison verifies nothing, a
  GAP-12 policy mismatch verifies nothing (a finding absent from a narrower
  scan may be out of scope rather than fixed), and an accepted risk is not
  overridden by a scan in either direction. Withheld findings are **counted and
  named**, never dropped.

- **Two unrecorded policies are not a mismatch.** That is the common case for
  scans predating GAP-12, and refusing it would make verification impossible on
  any existing installation.

- **The SLA clock starts at `first_found_at` and rediscovery does not restart
  it.** `last_found_at` moves on every scan; a due date derived from it would
  slide forward for as long as the finding persisted and the finding could
  never go overdue. `sla_anchor` is the one place that decides it. A
  _regression_ does start a new clock, from `reopened_at` — dating a returned
  finding from its original discovery would report an instant, unfixable
  breach.

- **CISA KEV wins where it is earlier and never where it is later.** BOD 22-01
  is a deadline an internal policy cannot extend, and may be stricter than —
  so relaxing to the federal date would be the product loosening a customer's
  own policy.

- **An unrated finding gets `not_applicable`, never `within_sla`.**
  "Comfortably inside its deadline" and "has no deadline" are different, and
  folding them inflates every figure built on this.

- **`sla_due_at` is materialised, and `apply_sla` is idempotent.** "Everything
  overdue" is then one indexed predicate over `(org_id, sla_due_at)`; deriving
  it per row would be the N+1 the column exists to avoid, on the endpoint a
  dashboard calls on every load. An unchanged deadline writes no event —
  otherwise the history would record that nothing happened several thousand
  times a day.

- **`finding_remediation_events` is append-only and is not the audit log.** The
  workflow writes to `audit_logs` too, but that table is tamper-evident,
  HASH-partitioned and subject to retention — right for "user X called this
  endpoint", wrong for "show me this finding's timeline", because retention
  would eventually remove history the finding still needs. Shaped after
  `compliance_finding_history`.

- **`asset_vulnerabilities`' primary key is `(id, org_id)`, not `id`** — a
  leftover of the HASH-partition-on-`org_id` design, invisible from the Python
  side because the model declares only `id`. PostgreSQL refuses a single-column
  foreign key to it. The composite key the event table therefore uses is the
  stronger constraint anyway: an event can only reference a finding **in its
  own organisation**, enforced by the database.

- **`verified_scan_id` is a second FK path between `scans` and
  `asset_vulnerabilities`**, so `Scan.vulnerabilities` needs
  `foreign_keys="AssetVulnerability.scan_id"` or SQLAlchemy raises
  `AmbiguousForeignKeysError`. The cascade stays on `scan_id`: deleting a scan
  removes the findings it reported, but must not remove a finding because the
  scan that _verified_ it was deleted.

- **The event id carries a random tail and it is not decoration.** The first
  version was `fre_<digest>_<type>_<timestamp>` and collided — two events of
  the same type on one finding in the same microsecond produced the same
  primary key, and because every workflow call shares a transaction the
  duplicate took the _whole lifecycle_ down. Not a rare race: a claim-then-
  verify or a bulk assignment runs inside one flush.

- **Accepting a risk is its own permission**, `findings:accept_risk`.
  `findings:update` moves work through the queue; deciding the organisation
  will carry a risk is a different authorisation, and without the split anyone
  who can edit a finding could clear their own overdue list by accepting
  everything on it. A reason is required. An expiry is optional — an
  indefinite acceptance is legitimate for a permanent compensating control and
  is different from nobody having set a date, which `accepted_at` records
  either way.

- **API**: `/remediation` (12 operations), plus the remediation section in both
  reports. The executive line is
  `Open: 120 | In remediation: 35 | Pending verification: 8 | Overdue: 17 | Verified fixed: 42`,
  assembled in one place so a report and a dashboard cannot render it
  differently.

<!-- /verbatim -->

<!-- verbatim: CLAUDE.md@9bb84d9 lines 3721-3825 -->
## Scan comparison and finding lifecycle (`core/findings/`)

What changed between two scans. GAP-13; tracker §9O. **No new finding model, no
second store, no migration** — `asset_vulnerabilities` already carried
everything needed.

- **A baseline is reconstructed from timestamps, not from an occurrence table.**
  A finding was open at time T iff `first_found_at <= T and (fixed_at is null or
fixed_at > T)`, and a baseline scan is just a T. A row per finding per scan
  would be thousands of rows per host per scan for something the lifecycle
  columns already answer.

- **Absence is not a fix, and this is the whole point.** Both fixed-sweeps
  marked every open finding missing from a scan as fixed. For a package finding
  that is defensible; for a configuration check it is not — 126 Windows STIG
  findings are absent from `cve_list` when the audit _passes_ and when it never
  _ran_. A scan now records what it assessed, and a configuration finding is
  marked fixed only if its check reached a verdict (PASS or FAIL — ERROR and
  NOT_APPLICABLE establish nothing). A scan with no recorded scope can never
  report a fix; the finding lands in `NOT_ASSESSED`, which is counted and named
  in the summary rather than quietly dropped.
  **A credentialed finding is retired only by a scan whose credentialed audit
  assessed it** (`core.findings.credentialed_scope`): the pipeline filed its
  credentialed findings under `network_service`, so an unauthenticated rescan
  marked all 2,281 of one audit's findings fixed (13 Oct 2026, fixed in
  `d77b50e`). Package CVEs need an inventory matched without a lookup failure;
  configuration findings need their check's verdict.

- **`record_assessment_scope` writes into `scans.options`** — JSONB, already
  carrying `options.origin`, client-visible, so no secret may go near it. It
  **merges**, because one scan writes findings from several paths and the
  configuration audit's record must not erase the package matcher's. It is
  deliberately not a new column: GAP-12's scan-policy record is where this
  should fold in, and a migration on a live table for something with no query
  predicate of its own buys nothing. **That fold has happened** — the policy
  snapshot is `options["scan_policy"]`, sibling of this key.

- **`completed_at` is stamped after the findings sync, not before.**
  `create_completed_scan` set it when the row was built — before the sync — so
  every finding a scan produced carried a `first_found_at` _later_ than its own
  scan's completion. Measured: baseline completed 18:48:44, its earliest finding
  first seen 18:48:45, and the comparison duly reported **50 new, 0 unchanged**
  on two scans of an almost unchanged host. Do not move it back.
  The pipeline's `update_scan_phase` broke the same rule until `6d816e2`
  (14 Oct 2026): it stamped `completed_at` and "complete" before its inline
  findings sync, so all 2,270 findings one credentialed audit first found were
  dated after its own completion (`tests/scans/test_scan_duration.py`).

- **`updated_at` is not a scan boundary.** It carries `onupdate=utcnow`, so it
  moves whenever the row is touched — the same property that once corrupted the
  Scan History date. `_scan_window` uses `started_at`/`completed_at` and treats
  `updated_at` only as a last-resort fallback for rows predating them.

- **A fix predating the baseline's own start reads as unchanged, not as a
  regression.** `fixed_at` holds only the most recent fix and is not cleared
  when a finding returns, so without this four curl CVEs were correctly flagged
  reappeared once and then flagged again on every subsequent comparison. The
  trade is recorded: a regression between an old fix and the baseline
  under-reports once, against crying wolf indefinitely.

- **A comparison is accurate while it is the latest scan.** It reads current row
  state, so once later scans move `fixed_at` and `last_found_at`, an older pair
  degrades. That is why the report embeds the comparison **at scan time**. The
  report is therefore generated after the sync, and the scan's report paths are
  set before the same commit.

- **The report section returns an empty list when there is no comparison**, so a
  report generated without one is byte-for-byte what it was before. An
  incomparable pair prints _Not comparable_ and the reason rather than a table
  of zeroes, which would read as "nothing changed".

- **API**: `GET /scans/{scan_id}/comparison`. Both scans go through
  `_get_scan_or_404`, so tenant scoping and per-user visibility are the same
  rules every other scan route uses. `limit` bounds the rows and never the
  counts — a truncated count is a wrong number, a short list is a sample.

- **A family is too coarse to decide a configuration fix.** `covers()` answers
  a question about _families_, and every credentialed finding — CVE and
  configuration alike — carries `credentialed_package`. So a scan narrowed by a
  GAP-12 policy still "covered" the checks it had stopped selecting, and five
  controls were reported **fixed** on a host where nothing had changed. The
  scan's own sweep had it right the whole time, because it consults the set of
  checks that reached a PASS or FAIL. That set is now recorded in the
  assessment scope and `covers_check()` requires a non-CVE finding to be in it
  before absence can mean a fix. A CVE is exempt on purpose: the package
  matcher runs over the whole installed inventory. A scan that recorded no set
  keeps the previous behaviour — "we do not know which checks ran" must not
  silently reclassify every historical comparison.

- **GAP-14 consumes this and must keep consuming it.** The remediation layer's
  only route to `verified_fixed` is a `FIXED` classification from here, and its
  only route to `reopened` is `REAPPEARED`. `NOT_ASSESSED` verifies nothing —
  which is the class this phase introduced, now load-bearing for a second
  feature. Note the verification pass recomputes the comparison with
  `limit_findings=None`: the report's copy is bounded at 200, and verifying
  only the first 200 findings would silently leave the rest unverified.

- **Do not test this through `TestClient` with `auth_headers`.** The login
  commits, and because the app shares the test session every uncommitted fixture
  row is committed with it, survives the per-test rollback and collides with
  later tests — measured as 13 failures and 19 errors elsewhere in the suite.
  `tests/scans/test_finding_comparison.py` calls the route function directly
  with a real session, which exercises the same code including
  `_get_scan_or_404`.

<!-- /verbatim -->

<!-- verbatim: CLAUDE.md@9bb84d9 lines 3880-3951 -->
## Data model notes

- **`compliance_credentials` is the platform credential store, not a
  compliance table.** The name is a misnomer kept deliberately — it has been
  the store for credentialed scans since before Phase 1 and
  `scan_schedules.credential_id` points at it, so renaming means an ALTER on
  live encrypted credentials for a cosmetic gain. It is discriminated by
  `credential_type` (`ssh`, `windows`, `database`; `network_device` and
  `snmp` reserved) and `transport` (`ssh`, `winrm`, plus one per database
  engine — `postgresql`, `mysql`, `mssql`, with `oracle` and `mongodb`
  reserved). `domain` is a column rather than
  a prefix on `username` because NTLM wants `DOMAIN\user` and Kerberos wants
  `user@REALM`; `principal()` owns that mapping. Never put a secret in
  `options` — it is returned to clients and logged. Its model is the credential
  vault's, `db/models/credentials.py` (G2); only `core/credential_vault.py`
  queries it, and the rest of the application asks that service.

- **The catalogue holds checks as well as CVEs.** `vulnerability_definitions`
  gained `definition_type` (`cve` | `config_check` | `plugin_check` |
  `privilege_check`) in migration `e1f2a3b4c5d6`, and both `id` and
  `asset_vulnerabilities.vuln_id` widened from 30 to 120 characters. Before
  that, `vuln_id` was a NOT NULL foreign key into a CVE-only catalogue, so
  **every finding the product could record had to be a CVE** — and a CIS
  control, a STIG rule, a weak service ACL or a database privilege finding had
  nowhere to go except its own findings table, which is where a second finding
  model, a second risk model and a second report generator come from.

  Mint non-CVE identifiers with `core.checks.definitions.definition_id_for_check`
  — never by hand. It emits the `CCURE-` vendor prefix (so a reader knows the
  identifier is ours and that NVD has never heard of it), folds dots and
  underscores to one spelling (so `2.3.1.1` and `2_3_1_1` cannot become two
  catalogue rows for one control), and refuses rather than truncating an
  over-long id, because a truncated key silently merges two sibling controls.

  `ck_vuln_def_cve_id_matches_type` enforces that a `cve` row carries `cve_id`
  and a check row does not. Without it a check filed as `cve` inherits KEV
  lookups, EPSS scores, CVSS bands and an NVD link that resolves to nothing.

  The live catalogue used to hold 23 rows keyed `CVE-9999-<hex>` — test residue
  from `tests/scans/test_scans.py`, predating the conftest database guards.
  **They are gone**: measured at 0 on 30 Aug 2026, alongside 0 `cve` rows with
  a NULL `cve_id` and 0 non-CVE rows carrying one, across 263,938 rows. The
  episode is kept here because it is exactly the confusion the `CCURE-` prefix
  exists to prevent, and because nothing stops a future test writing more.

- `services` is a **current-state projection**, not per-scan history. The row id
  is `gen_service_id(asset, port, protocol)`, so re-scanning re-points rows
  rather than adding a generation. Point-in-time results live in
  `scan_phases.summary`, which the scan-detail API and reports read back.
  **Deleting a scan must not delete the inventory**: `services.scan_id` is
  nullable and ON DELETE SET NULL, and `Scan.services` has no delete cascade
  (migration `d5e7f9a1b3c6`). Both halves matter — the ORM's cascade deletes
  loaded rows before the database is asked — and Alembic's drift check does not
  compare ON DELETE rules, so `test_scan_lifecycle_audit` pins model, ORM and
  database together. Until then a purge emptied the inventory of every asset
  the purged scan was the latest to see (104 rows, 14 Oct 2026).
- **`asset_vulnerabilities.fix_state` is the matched advisory's own answer**:
  `fix_released`, `no_fix_released`, or NULL (not established). An empty
  `component_fixed_version` cannot say it — "Ubuntu has released no fix" and
  "no fixed version was recorded" both leave it NULL. `core.findings.fix_state`
  decides it for both credentialed writers. `no_fix_released` is only ever a
  distribution's statement, and only for ecosystems in
  `OPEN_RANGE_MEANS_NO_FIX` (Ubuntu): `sync_osv` stores a `last_affected` range
  as an open window, so an open range means "no fix" only in a feed measured to
  use no `last_affected`. It never changes status or severity. The API filter
  value for NULL is `not_recorded`, never folded into `no_fix_released`.
- `assets` is keyed by `(org_id, ip_address)` and `(org_id, mac_address)`.
  Re-scans update in place; `first_seen_at` is preserved and per-field
  provenance is tracked in `custom_attributes.provenance`.
- Timestamps in scan payloads are timezone-aware UTC. Do not introduce naive
  `datetime.now()` — it renders as local time beside UTC siblings.

<!-- /verbatim -->
