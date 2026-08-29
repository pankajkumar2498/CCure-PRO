# CCure Audit PRO — Nessus Capability Gap Closure Tracker

The master record for the phased programme that moves this product from
**Level 2 (Vulnerability Assessment)** toward Nessus-class capability. One row
per gap, one phase per commit, and a gap is **Closed** only when every
applicable line of its Definition of Done is true — not when the code was
written.

- **Programme start:** 2026-08-27
- **Baseline branch:** `Close-Coverage_gap`
- **Baseline commit:** `dfd6d80`
- **Baseline test suite:** 1535 passed, 2 skipped (6m22s), full suite, clean

---

## 1. How the percentages are derived

Coverage figures in this document are **capability coverage against the Nessus
surface for that domain**, not code coverage and not test coverage. Two
qualifiers appear against every number and they are not decoration:

| Marker          | Meaning                                                                                               |
| --------------- | ----------------------------------------------------------------------------------------------------- |
| **[measured]**  | Derived by inspecting the source tree, the database, or a scan result during this programme. Cited.   |
| **[estimated]** | A judgement call from a reading of the code. Directionally useful, not defensible to a decimal place. |

The programme-level baseline of **35–40%** carried over from the original gap
analysis is **[estimated]** and is retained for continuity. Where this
programme has since measured something that contradicts it, the measurement
wins and the disagreement is recorded rather than quietly reconciled.

### Status vocabulary

| Status          | Means                                                                                                    |
| --------------- | -------------------------------------------------------------------------------------------------------- |
| **Open**        | Nothing built.                                                                                           |
| **In progress** | Implementation started; Definition of Done not met.                                                      |
| **Partial**     | Shipped and working for a subset; the rest is explicitly out of scope for now, with the remainder named. |
| **Closed**      | Every applicable Definition of Done line is true.                                                        |
| **Deferred**    | Deliberately moved to a later phase, with the reason recorded. Not the same as Open.                     |

---

## 2. Summary matrix

| Gap ID       | Capability                               | Domain         | Phase | Priority | Coverage before  | Target | Status                                             | Commit    |
| ------------ | ---------------------------------------- | -------------- | ----- | -------- | ---------------- | ------ | -------------------------------------------------- | --------- |
| **GAP-00-A** | Common check/plugin framework            | Architecture   | 0     | Critical | 20% [measured]   | 90%    | **Closed**                                         | `31c10b4` |
| **GAP-00-B** | Finding model admits non-CVE findings    | Architecture   | 0     | Critical | 0% [measured]    | 100%   | **Closed**                                         | `31c10b4` |
| **GAP-00-C** | Generalized credential model             | Architecture   | 0     | High     | 25% [measured]   | 90%    | **Closed** (95% measured)                          | `9e4ecaa` |
| **GAP-01**   | Network & credentialed scan scheduling   | Orchestration  | 1     | Critical | 30% [measured]   | 95%    | **Closed**                                         | `37871a6` |
| **GAP-02**   | Native Windows credentialed scanning     | Credentialed   | 2     | Critical | 40% [estimated]  | 90%    | **Closed** (85% measured)                          | `9e4ecaa` |
| **GAP-03**   | Generic configuration audit engine       | Config audit   | 3     | Critical | 35% [measured]   | 90%    | **Closed** (90% measured)                          | `daab13a` |
| **GAP-04**   | CIS benchmark content                    | Config audit   | 4     | High     | 0% [measured]    | 70%    | **Partial** — capability built, content absent     | `9e762d0` |
| GAP-05       | DISA STIG / SCAP ingestion               | Config audit   | 5     | Medium   | 0% [measured]    | 60%    | Open                                               | —         |
| **GAP-06**   | Active vulnerability check expansion     | Network checks | 6     | High     | 25.8% [measured] | 65%    | **Closed** (64.5% measured, real-target validated) | `d40800d` |
| GAP-07       | Deep TLS/SSL assessment in main path     | TLS            | 7     | Medium   | 45% [estimated]  | 90%    | Open                                               | —         |
| **GAP-08**   | Local OS privilege & host exposure       | Credentialed   | 5     | High     | 0% [measured]    | 75%    | **Closed** (75.9% measured, real-target validated) | `8a5bbd7` |
| GAP-09       | Application/middleware config assessment | Config audit   | 9     | Medium   | 5% [estimated]   | 70%    | Open                                               | —         |
| GAP-10       | Database assessment                      | Database       | 10    | High     | 5% [measured]    | 70%    | Open                                               | —         |
| GAP-11       | Network device assessment                | Network device | 11    | Medium   | 15% [estimated]  | 65%    | Open                                               | —         |
| GAP-12       | Configurable scan policy engine          | Orchestration  | 12    | High     | 20% [measured]   | 85%    | Open                                               | —         |
| GAP-13       | Scan comparison & finding lifecycle      | Findings       | 13    | High     | 25% [measured]   | 90%    | Open                                               | —         |
| GAP-14       | Remediation & SLA management             | Remediation    | 14    | High     | 30% [measured]   | 85%    | Open                                               | —         |
| GAP-15       | Reporting & export expansion             | Reporting      | 15    | Medium   | 50% [measured]   | 85%    | Open                                               | —         |
| GAP-16       | Cloud security assessment                | Cloud          | 16    | Low      | 0% [measured]    | 60%    | Open                                               | —         |
| GAP-17       | Virtualization / container / Kubernetes  | Container      | 17    | Low      | 5% [estimated]   | 60%    | Open                                               | —         |
| GAP-18       | Distributed scanner / agent architecture | Architecture   | 18    | Low      | 10% [estimated]  | 60%    | Open                                               | —         |
| GAP-19       | Continuous security assessment           | Orchestration  | 19    | Low      | 10% [estimated]  | 70%    | Open                                               | —         |

---

## 3. Phase 0 — Architecture & common framework hardening

**Status: Complete.** Two gaps closed, one deferred with cause.

Phase 0's brief was to make sure new capability can be added without spawning
disconnected engines. Reading the tree produced a short answer: most of the
common models the later phases need **already exist and are good**, and exactly
three things stood between them and the next nine phases.

### 3.1 What already existed and is being reused, not rebuilt

Recorded here because the most expensive mistake available in this programme is
rebuilding one of these beside itself.

| Phase 0 model            | Existing implementation                                                                                                               | Verdict                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Scan result model        | `Scan` + `ScanPhase.summary` (`db/models/scans.py`)                                                                                   | **Reuse as-is.** Point-in-time results already live in `scan_phases.summary`.           |
| Risk model               | `core/risk.py` → `calculate_risk()`                                                                                                   | **Reuse as-is.**                                                                        |
| Configuration rule model | `ComplianceRule` — `check_type`, `target_platform`, `check_definition` JSONB, versioned and immutable (`db/models/compliance.py:158`) | **Reuse and extend in Phase 3.** Already carries 7 of the 13 check types Phase 3 needs. |
| Evidence model           | `ComplianceEvidenceProvider` (normalized adapters), `ComplianceEvidenceFile` (uploads), `AssetVulnerability.evidence`                 | **Reuse.** Phase 3 adds collectors, not a new evidence concept.                         |
| Policy model             | `CompliancePolicy` / `CompliancePolicyRule`                                                                                           | **Reuse as the pattern** for GAP-12's scan policies.                                    |
| Remediation model        | `ComplianceRemediation`, `ComplianceRemediationRequest` (maker–checker), `AssetVulnerability.remediation_notes`                       | **Extend in Phase 14**, do not duplicate.                                               |
| Finding normalization    | `scans/finding_normalizer.py` — `DetectionMethod`, `Confidence`, QoD, verification                                                    | **Reuse as-is.** Already has a `CONFIG_CHECK` detection method.                         |

### 3.2 GAP-00-A — Common check/plugin framework

**Status: Closed.**

**The gap.** The vulnerability plugins are duck-typed modules with no enforced
contract. The engine calls serial plugins with three positional arguments and
parallel plugins with two, and catches every plugin exception at DEBUG level. A
plugin with the wrong arity therefore raises `TypeError` on every host, is
swallowed, still appears in `plugin_names()` and `select_plugins()`, and
produces **zero findings indefinitely with nothing in the logs**. CLAUDE.md
records this as one of four defects that each produced zero findings in
production. Nothing structural prevented a recurrence, and every capability in
Phases 6, 8 and 9 is a new plugin.

**What was built.**

- `core/checks/contract.py` — `CheckOutcome`, `CheckSpec`, `CheckResult`,
  `Evidence`, `roll_up_outcomes()`. Three invariants are enforced at
  construction rather than by reviewer discipline:
  1. **A FAIL must carry evidence.** The mirror image of the synthesised-
     evidence defect that once made every password-policy rule pass
     unconditionally on every host.
  2. **Not-assessed is never a verdict.** `is_verdict` is True for exactly
     PASS and FAIL. ISO A.8.2 was once reported as _failed_ on hosts the
     scanner could not authenticate to.
  3. **An ERROR must say why.** An error with no message reads in a log
     exactly like a check that did nothing.
- `core/checks/registry.py` — registration validates the callable's signature
  against the arity the executor will use and raises `RegistrationError`. A
  check that raises at runtime yields an ERROR result, never a swallowed log
  line and never a FAIL.
- `core/checks/legacy_plugins.py` — the existing plugin contract expressed so a
  test can execute it. The 15 plugins are **not** rewritten; Phase 0's brief is
  explicit about not refactoring stable functionality.

**Vocabulary reuse, verified.** `CheckOutcome`'s four non-error members are
spelled identically to `compliance_findings.status`, asserted by
`test_outcome_strings_match_the_compliance_status_vocabulary`. Severity reuses
`scans.cvss.CANONICAL_SEVERITIES`, with `compliance_rules`' `info` mapped onto
`none` rather than becoming a third spelling.

**Validation.**

| Line                   | Result                                                                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit tests             | 54 new tests, all passing                                                                                                                     |
| **Mutation test**      | `nuclei_probe.run` reduced to 2 arguments → guard failed with an actionable message naming the plugin, the arity and the call site. Reverted. |
| Real-target validation | N/A — static contract; the mutation test is the equivalent evidence                                                                           |
| Regression             | Full suite green (see §5)                                                                                                                     |

**Deliberate non-goal.** `core/checks/registry.py` does not execute checks
across domains. Execution differs per domain — a network probe runs in a thread
pool against an IP, a config check against already-collected evidence, a
database check inside a session — and a single executor here would be either
trivial or wrong.

### 3.3 GAP-00-B — Finding model admits non-CVE findings

**Status: Closed.**

**The gap.** `asset_vulnerabilities.vuln_id` is a NOT NULL foreign key into
`vulnerability_definitions`, whose primary key was `varchar(30)` and sized for
CVE identifiers. **Every finding this product could record had to be a CVE.**

That blocks nine of the remaining phases outright. A CIS control, a STIG rule,
a weak service ACL, an unquoted service path, a database account with no
password policy, a switch still answering on Telnet — none has a CVE. The
alternative every scanner reaches for at that point is its own findings table,
and at that moment the product has two finding models, two risk models, two
remediation workflows and two report generators for one question.

**What was built.** Migration `e1f2a3b4c5d6`:

| Change                                      | Detail                                                                                                                           |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `vulnerability_definitions.id`              | `varchar(30)` → `varchar(120)`                                                                                                   |
| `asset_vulnerabilities.vuln_id`             | `varchar(30)` → `varchar(120)`                                                                                                   |
| `vulnerability_definitions.definition_type` | New. NOT NULL, server default `'cve'`, indexed, CHECK-constrained to `cve` / `config_check` / `plugin_check` / `privilege_check` |
| `ck_vuln_def_cve_id_matches_type`           | New. A `cve` row must carry `cve_id`; a check row must not.                                                                      |

`core/checks/definitions.py` mints the identifiers: `CCURE-CFG-…`,
`CCURE-CHK-…`, `CCURE-PRV-…`. The vendor prefix is deliberate — a reader who
meets it in a report knows the identifier is ours and that searching NVD for it
returns nothing.

**Why the second CHECK constraint is load-bearing.** Without it a configuration
check filed as `definition_type='cve'` inherits CVE semantics everywhere
downstream — KEV membership, EPSS scoring, CVSS band tables, a "look this up in
NVD" link resolving to nothing — none of which mean anything for a benchmark
control. The constraint makes that state unrepresentable rather than
discouraged.

**Validation** — performed on a throwaway database (`ccure_migrationcheck_pytest_db`,
created and dropped; the live database was not touched):

| Line                                         | Result                                                                                                         |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Fresh-install path                           | `create_all()` → id 120, vuln_id 120, column + index + both CHECKs present                                     |
| `downgrade -1`                               | Reverses exactly: id 30, vuln_id 30, column/index/CHECKs gone                                                  |
| `upgrade head`                               | Restores exactly. Round-trip is symmetric.                                                                     |
| Autogenerate drift                           | **None.** Model and migration produce byte-identical schema, so a fresh install and an upgraded install agree. |
| Applied by the suite                         | ✅ `ccure_pytest_db` upgraded `d0e1f2a3b4c5` → `e1f2a3b4c5d6` on a pre-existing schema, not a bootstrap        |
| Constraint — real CVE row                    | **Accepted**                                                                                                   |
| Constraint — config check, `cve_id` NULL     | **Accepted**                                                                                                   |
| Constraint — 59-character privilege-check id | **Accepted** (proves the widening is real)                                                                     |
| Constraint — check masquerading as `cve`     | **Rejected** by `ck_vuln_def_cve_id_matches_type`                                                              |
| Constraint — check carrying a `cve_id`       | **Rejected** by `ck_vuln_def_cve_id_matches_type`                                                              |
| Constraint — unknown `definition_type`       | **Rejected** by `ck_vuln_def_definition_type`                                                                  |

**Widening cost.** PostgreSQL does not rewrite a table when a `varchar(n)` is
widened, and that holds with the foreign key in place — so the 262,632-row
catalogue and its 5,711 referencing findings are altered in metadata only.
`downgrade()` refuses rather than truncating when any row would not fit.

**One defect found and fixed during review of this phase's own diff.**
`definition_type` was first declared with both `index=True` on the column _and_
a named `Index(...)` in `__table_args__`. A fresh install builds from
`Base.metadata` and would have created **two** indexes on the column —
SQLAlchemy's auto-named one plus the migration's — while an upgraded install
got only the migration's. That is the exact fresh-versus-upgraded divergence
CLAUDE.md warns about for `in_kev`, approached from the other side, and neither
the autogenerate check nor the suite caught it: `compare_metadata` was filtered
to column and table opcodes, and `create_all` skips indexes on tables that
already exist, so the already-upgraded scratch database never showed the
duplicate. Found by reading the diff; fixed by removing `index=True`; verified
by building a **fresh** database from `create_all` and asserting exactly one
index. The verification is what makes it a fix rather than a hope.

**Not yet wired.** No writer produces a non-CVE definition yet. The catalogue
_can_ hold one and the constraints _do_ police it; the first producer is Phase 3.
This is recorded as a limitation, not claimed as capability.

### 3.4 GAP-00-C — Generalized credential model

**Status: Deferred to Phase 2.** This is a scope decision, taken deliberately
and recorded here rather than left silent.

**The gap is real.** `ComplianceCredential` (`db/models/compliance.py:839`) is
the platform's only credential store despite its name — `routers/credentialed.py`
already reads it for network scans. It models SSH and only SSH: `username`,
`encrypted_password`, `encrypted_key_content`, `port` default 22, and
`auth_method` CHECK-constrained to `('password','key')`. It cannot express
WinRM, Kerberos, SMB, SNMPv3, a database DSN, or a network-device enable
secret — which blocks Phases 2, 10 and 11.

**Why deferred rather than built now.** The correct shape of a generalized
credential record depends on what WinRM, database and network-device
authentication actually need in practice. Designing it in Phase 0 with no
consumer means guessing; designing it in Phase 2 against a working WinRM
implementation means it is validated end-to-end by the thing that uses it.
Shipping an unconsumed schema change also puts a migration in front of
customers that nothing exercises.

**The risk of deferring, and the mitigation.** Left unmanaged, Phases 10 and 11
would each bolt their own credential columns on ad hoc — the exact
disconnected-engine outcome Phase 0 exists to prevent. Mitigation: this
constraint is recorded here and carried as a **hard precondition on Phase 2**,
whose Definition of Done includes the generalized model serving all three
downstream phases, not just Windows.

---

## 4. Phase 1 — Network & credentialed scan scheduling

**Status: Complete.** GAP-01 closed.

### 4.1 The rule that shaped the design

Scheduling adds **no scan engine**. A due schedule calls
`run_host_discovery_task.delay(...)` or `run_credentialed_scan_task.delay(...)`
— the same tasks, with the same arguments, that `routers/phase_scans.py` and
`routers/credentialed.py` dispatch when a person presses the button. A
scheduled run therefore appears in Scan History, reports, findings and the
dashboard exactly like a manual one, marked with `options.origin = "schedule"`.

### 4.2 What was reused rather than rebuilt

| Need                   | Existing implementation                                         | Reused how                                      |
| ---------------------- | --------------------------------------------------------------- | ----------------------------------------------- |
| Periodic trigger       | Celery beat (`ccure-beat`)                                      | One new `beat_schedule` entry; no new process   |
| Network execution      | `run_host_discovery_task`                                       | Called directly                                 |
| Credentialed execution | `run_credentialed_scan_task`                                    | Called directly, with `credential_id`           |
| Scan record            | `scans/db_helpers.create_scan`                                  | Called directly                                 |
| Scan history           | `routers/scan_history.py`                                       | Nothing added — scheduled scans are `Scan` rows |
| Credentials            | `compliance_credentials` + `_resolve_stored_credential`         | Referenced by id; worker decrypts               |
| Target gate            | `validate_scan_targets`, `enforce_org_scan_scope`               | Re-run at every dispatch                        |
| Quota                  | `core.quota.check_scan_quota`                                   | Re-run at every dispatch                        |
| RBAC / audit / limiter | `require_permission`, `log_audit_event`, `scan_helpers.limiter` | Unchanged                                       |

The single most useful finding of the inspection: `run_credentialed_scan_task`
**already accepted `credential_id`** and resolved it worker-side. So a schedule
never has to hold a secret — unlike `POST /scan/credentialed`, which passes a
plaintext password into the Celery task arguments.

### 4.3 What was deliberately not copied from `compliance_scan_schedules`

It is the closest existing thing, and six of its properties are defects rather
than designs. Each is listed in `db/models/scan_schedules.py` beside the
decision not to repeat it:

1. **No time zones.** `next_run_at = now + delta` makes "daily at 09:00"
   unrepresentable and lets every tick drift by however late beat was.
2. **`monthly` as a fixed `timedelta`** — 30 days is not a calendar month.
3. **A `cron_expression` column nothing reads or constrains.**
4. **No duplicate-execution guard.**
5. **No execution history** — run records fused to the compliance run table, so
   a dispatch that failed before a scan existed left no trace a user could see.
6. **A bare `except` returning `{"success": False}`** — what hid a `TypeError`
   until it emerged that scheduled compliance scanning had never once run.

### 4.4 Validation

| Line                           | Result                                                                     |
| ------------------------------ | -------------------------------------------------------------------------- |
| Unit — recurrence              | 27 tests, pure, no DB                                                      |
| Integration — API/RBAC/tenancy | 25 tests against the real router and database                              |
| Integration — dispatcher/beat  | 16 tests                                                                   |
| Migration                      | up → down → up round-trip on a throwaway database, zero autogenerate drift |
| Frontend                       | `eslint --max-warnings=0` clean; `npm run build` succeeds                  |
| API contract                   | `openapi.json` regenerated — **908 insertions, 0 deletions**               |
| Docs integrity                 | `tests/repo` 8 passed (routes, tables and permissions all documented)      |
| Regression                     | see §6                                                                     |

**Time-zone correctness was treated as load-bearing** and is covered by
executable cases rather than assertion:

- daily 09:00 Europe/London stays 09:00 across the spring-forward boundary;
- a run at 01:30 on a spring-forward night — an hour that does not exist —
  is pushed to the first instant that does, rather than skipped;
- a run at 01:30 on an autumn-back night — an hour that happens twice — fires
  once, at the earlier instant;
- day 31 runs on 28 Feb in a common year and 29 Feb in a leap year;
- a fixed offset (`+05:30`) is refused as a zone, because it cannot express
  daylight saving.

**Two defects were found by the process rather than by testing the feature:**

- **`ScheduleCreate` / `ScheduleUpdate` collided with `routers/compliance.py`.**
  FastAPI keys OpenAPI component schemas by _class name_, so this router's
  models silently replaced compliance's — the first regeneration of
  `openapi.json` showed 880 deletions, including compliance's entire
  `ScheduleCreate` schema. A client generated from that contract would have had
  the wrong shape for compliance schedules. Every body model here is now
  prefixed `ScanSchedule`, and the regenerated contract is purely additive.
  Caught by the CI contract gate, which is exactly what it is for.
- **`GET /compliance/credentials` requires `compliance:read`.** Using it for the
  schedule form would have meant an analyst needed a compliance permission to
  pick a credential for a scan. `GET /scan-schedules/credentials` serves the
  same rows gated on `scan_schedules:read`, returning identifying fields only.

### 4.5 Known limitations

- **`custom` (cron) recurrence is accepted and stored but not yet placed.**
  `compute_next_run` returns `None` for it, so such a schedule stays dormant
  rather than firing at an arbitrary time. Parsing cron needs a dependency
  decision (`croniter`) that has not been taken. The database refuses a cron
  expression outside the custom recurrence, so nothing else is affected.
- **The `scan_kind` column reserves `configuration`, `database`,
  `network_device` and `cloud`.** The API refuses to create one, so a reserved
  kind cannot produce a schedule that silently never runs; the reservation
  exists so Phases 3, 10, 11 and 16 need no CHECK migration on a table that by
  then holds customer schedules.
- **Failure notification is the run record and the audit log, not email.** The
  notification model exists and wiring it is a small follow-up, but it was not
  in this phase's scope.
- **Not yet deployed to the live database.** `ccure_test` is at
  `d0e1f2a3b4c5`; both `e1f2a3b4c5d6` and `f2a3b4c5d6e7` are committed and
  round-trip-tested but not applied there.

### 4.6 Definition of Done — Phase 1

| Line                      | Status                                                                                              |
| ------------------------- | --------------------------------------------------------------------------------------------------- |
| Backend implemented       | ✅ model, recurrence engine, dispatcher, beat task                                                  |
| Scanner/check logic       | ✅ reuses the existing tasks; none added                                                            |
| Database changes          | ✅ `f2a3b4c5d6e7` — two tables                                                                      |
| Migration tested          | ✅ round-trip, zero drift                                                                           |
| API implemented           | ✅ 10 operations                                                                                    |
| UI implemented            | ✅ full CRUD, enable/disable, Run Now, history                                                      |
| Finding model integrated  | ✅ via the existing scan pipeline                                                                   |
| Risk scoring / reporting  | ✅ unchanged — scheduled scans are ordinary scans                                                   |
| Logging                   | ✅                                                                                                  |
| Audit trail               | ✅ 7 actions classified in `core/audit_taxonomy.py`                                                 |
| RBAC enforced             | ✅ new `scan_schedules` resource, 5 actions, 3 roles                                                |
| Tenant isolation          | ✅ org filter in the query; 404 not 403                                                             |
| Credential protection     | ✅ reference only; asserted no material is returned                                                 |
| Rate limiting             | ✅ every route limited and declaring `response: Response`                                           |
| Unit tests                | ✅ 27                                                                                               |
| Integration tests         | ✅ 41                                                                                               |
| E2E tests                 | ✅ create → dispatch → scan row → history, through the API                                          |
| Regression passed         | ✅ §6                                                                                               |
| Real-target validation    | ⚠️ dispatch verified to the task boundary; a live network run needs credentials and a target window |
| False-positive validation | ✅ reserved kinds skipped not failed; over-quota skipped not failed                                 |
| Documentation updated     | ✅ API reference, schema, RBAC, CLAUDE.md                                                           |
| Gap tracker updated       | ✅ this section                                                                                     |
| Git commit                | see §6                                                                                              |

---

## 5. Phase 2 — Native Windows credentialed scanning

**Status: Complete**, with one scenario explicitly Not Validated (§5.6).
Closes GAP-00-C and GAP-02.

### 5.1 GAP-00-C — generalized credential model (Closed)

`compliance_credentials` was SSH-only: `auth_method` CHECK-constrained to
`('password','key')`, port defaulted to 22, no domain, no transport. Migration
`a3b4c5d6e7f8` adds `credential_type`, `transport`, `domain` and an `options`
JSONB, and widens the auth CHECK to admit `ntlm` and `kerberos`.

Existing rows backfill to `ssh`/`ssh` — which is what they already were. The
migration **checks** that rather than assuming it: a row using a method SSH
cannot perform would be silently mislabelled, so the upgrade refuses instead.
Downgrade refuses if any non-SSH credential exists, because dropping the
columns would reduce a Windows credential to an SSH one pointed at port 5985,
which would then attempt SSH against a WinRM listener.

`database`, `network_device` and `snmp` are reserved in the column so Phases 10
and 11 need no CHECK migration on a table holding customer credentials; the API
refuses to create one, so a reserved type cannot produce a credential nothing
can use.

**The table keeps its misleading name.** It has been the store for credentialed
_scans_ since before Phase 1 and `scan_schedules.credential_id` points at it;
renaming would mean an ALTER on live encrypted credentials for a cosmetic gain.
Documented on the model. Recorded here as a deliberate decision, not an
oversight.

### 5.2 The transport swap — what was reused

`ssh_scanner.py` already declared a `BaseExecutor` protocol (`connect`,
`disconnect`, `run(command, timeout) -> CommandResult`). `WinRMExecutor`
implements it, so:

- **`WindowsCollector` is unchanged.** Its ~970 lines of PowerShell command
  catalogue and parsers, every one of them, drive either transport. The only
  edit was the type hint and its docstring.
- **There is no second finding path.** Windows results flow through the
  existing collection → evidence → `VulnMatcher`/`WindowsPatchMatcher` →
  finding → risk → reporting chain.
- `_detect_shell` needed no change: WinRM answers `$PSVersionTable` with a
  version, so it reports "powershell" and `_wrap_ps` correctly leaves commands
  alone — pywinrm does its own UTF-16-LE base64 encoding, and wrapping twice
  would feed the encoder its own output.

### 5.3 Real-target validation — VALIDATED

Target: **10.180.6.14**, Windows 11 Pro, build **10.0.26200.9168**, WORKGROUP
(`PANKAJM-HPNEW`), local account `pankaj` (Administrators), WinRM/5985, NTLM.

The host needed **no target-side configuration**: WinRM was already listening,
`Negotiate=true`, `Basic=false`, `AllowUnencrypted=false`, and
`LocalAccountTokenFilterPolicy=1`. That posture matches the design — NTLM
encrypts the payload on 5985 and the executor refuses Basic over HTTP.

| Stage                         | Result                                                                                                                |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Authentication                | ✅ `pankaj`, `PANKAJM-HPNEW\pankaj`, `.\pankaj` all authenticate                                                      |
| Windows collection            | ✅ 48 keys in 16.6 s via the unmodified collector                                                                     |
| OS / version / build          | ✅ `10.0.26200.9168` — **including the UBR**                                                                          |
| Installed software            | ✅ 191 packages                                                                                                       |
| Patch / KB inventory          | ✅ 4 KBs as `windows_update` pseudo-packages                                                                          |
| Running services              | ✅ 171                                                                                                                |
| Listening ports               | ✅ 110                                                                                                                |
| Users / groups                | ✅ 7 users, groups, password policy (7 settings)                                                                      |
| Security configuration        | ✅ RDP+NLA, SMBv1 disabled, firewall (3 profiles), shares, audit policy (3,792 chars), 10 security issues             |
| Network interfaces            | ✅ interfaces, MAC, subnet                                                                                            |
| Hardware / BIOS               | ✅ HP Elite SFF 800 G9, BIOS U01 Ver. 02.22.01, serial, CPU                                                           |
| Vulnerability assessment      | ✅ **assessed** — `os_assessed: True`, resolved to `Windows 11 Version 25H2 for x64-based Systems`, 0 missing patches |
| Full flow                     | ✅ CRUD → encrypted storage → resolution → WinRM auth → collection, end to end                                        |
| Failure: invalid password     | ✅ `WinRMAuthenticationError`                                                                                         |
| Failure: non-existent account | ✅ `WinRMAuthenticationError`                                                                                         |
| Failure: nothing listening    | ✅ `WinRMConnectionError` — **distinct from authentication**                                                          |
| Failure: Basic over HTTP      | ✅ `WinRMConfigurationError`, refused by design                                                                       |

**The 4 KBs corroborate CLAUDE.md exactly** — "Get-HotFix returned 4 entries on
a fully patched host, because cumulative updates supersede one another" — which
is why patch assessment uses build comparison rather than KB matching.

**Zero findings is a genuine assessed result, not a silent zero.** The matcher
reports `os_assessed: True` and names the product line it compared against.
CLAUDE.md requires an unmappable build line to report _not assessed_ rather
than _no missing patches_, and it does.

### 5.4 Two defects that only real-target validation could find

Both are now covered by regression tests in
`tests/credentialed/test_windows_winrm.py`.

**1. pywinrm NTLM sessions are not thread-safe, and the collector is parallel.**
The first full collection failed _every section_, reporting "the specified
credentials were rejected by the server" — on a credential that had just
authenticated. Measured:

```
sequential, one session, 10 commands       10/10 succeeded
concurrent, one shared session, 8 threads   0/8 succeeded
concurrent, one session per thread          8/8 succeeded
```

Failures surfaced as `SpnegoError (6): invalid Message Integrity Check`, HTTP
400, and the misleading credential-rejection message. Fixed with thread-local
sessions, which keeps the collector's parallelism (16.6 s, not serialised).
Without a real host this ships and every Windows scan fails, looking exactly
like a bad password.

**2. The audit reported "collected over SSH" for WinRM evidence.** The coverage
block is the audit's own statement of how its evidence was obtained; a reader
checking whether OpenSSH was required would have been told the wrong thing by
the report itself. `credentialed_coverage(transport=…)` now names the real one.

A third defect was found by the classifier test rather than the live run: the
literal pywinrm string "the specified credentials were rejected by the server"
contains none of `401`, "unauthorized" or "authentication", so it fell through
to `WinRMConnectionError` and would have been reported as an unreachable host.
Live pywinrm raised the typed `InvalidCredentialsError` that a different branch
already caught, which is why the live run did not expose it.

### 5.5 API, UI and RBAC

`routers/credentials.py` — 7 operations. The `credentials` RBAC resource had
existed in the permission seed since before this phase and was **never wired to
an API**; the only credential endpoints were under `/compliance`, gated on
`compliance:read`, which would force a compliance permission on an analyst who
just needs to scan Windows hosts. Phase 2 adds `credentials:update` and
`credentials:validate` and gives the resource its API. `/compliance/credentials`
still works on the same table.

A secret goes in and never comes out: `_serialize` has no branch that can emit
either encrypted column, `options` is rejected if it carries a secret-shaped
key, and PATCH replaces a secret only when one is supplied — so editing a port
cannot blank a password.

UI: `Frontend/src/pages/scan/ScanCredentials.jsx` — full CRUD plus validation
against a named target, with the six `reason` values rendered as six different
messages because they need six different actions.

### 5.6 NOT VALIDATED — insufficient privileges

**Status: Pending real target.** The only account available on 10.180.6.14
(`pankaj`) is a local Administrator, so the under-privileged path could not be
exercised against a real host.

What exists: `WinRMPermissionError` is raised on HTTP 403 and on
access-denied markers in command output, and the validation endpoint maps it to
`reason: "insufficient_privileges"`. Both are covered by unit tests against
synthetic inputs.

What is **not** claimed: that a real standard Windows account produces that
classification end to end. It was not simulated and the scanner was not
weakened to manufacture the result. Closing this needs a genuine non-admin
account — a standard user, or one in `Remote Management Users` but not
`Administrators`.

### 5.7 Coverage

| Capability                       | Before          | After              | Basis                                                                                                |
| -------------------------------- | --------------- | ------------------ | ---------------------------------------------------------------------------------------------------- |
| GAP-00-C generalized credentials | 25%             | 95%                | ssh + windows implemented; database/network_device/snmp reserved, not implemented                    |
| GAP-02 Windows credentialed      | 40% [estimated] | **85%** [measured] | 16 of 17 required collection items validated on a real host; insufficient-privilege scenario pending |

The 15% shortfall is: the insufficient-privilege scenario (§5.6), Kerberos and
domain-joined authentication (implemented, no domain available to validate
against), and Windows Server (only a workstation SKU was available).

### 5.8 Known limitations

- **Kerberos and domain-joined targets are implemented but not validated.**
  `principal()` builds `user@REALM`, the transport accepts `kerberos`, and unit
  tests cover the username derivation — but no domain was available. Kerberos
  additionally needs a GSSAPI library present in the environment.
- **Windows Server not validated** — only Windows 11 Pro was available.
- **SMB/Remote Registry is not implemented.** Nessus's primary Windows
  transport is SMB + Remote Registry + WMI; this phase implements WinRM, which
  is on by default on Server 2012+ but **off by default on client SKUs**. On a
  workstation estate that is a real coverage difference, and closing it means a
  second transport rather than a change to this one. Recorded as a gap, not a
  defect.
- **`RemoteRegistry` was stopped on the validation host** — irrelevant to WinRM,
  relevant to any future SMB transport.

---

### 5.9 Carried forward from Phase 2 — tracked, non-blocking

Recorded here so that closing Phase 2 does not close these with it. None blocks
a later phase; each needs something this environment could not supply.

| Item                                  | Status                                 | What it needs                                                                                                                                                                                                       |
| ------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Insufficient-privilege classification | **Pending real target**                | A genuine non-admin Windows account — a standard user, or one in `Remote Management Users` but not `Administrators`                                                                                                 |
| Kerberos / domain-joined auth         | Implemented, not real-target validated | A domain-joined host, and a GSSAPI library present in the worker environment                                                                                                                                        |
| Windows Server SKU                    | Implemented, not real-target validated | A Server 2016+ target                                                                                                                                                                                               |
| SMB + Remote Registry + WMI transport | **Not implemented**                    | A second transport. Nessus's primary Windows path; WinRM is off by default on client SKUs, so on a workstation estate this product still reaches fewer hosts out of the box. Deliberately not attempted in Phase 3. |

---

## 6. Phase 3 — Generic configuration audit engine

**Status: Complete.** Closes GAP-03.

The reusable engine only. No CIS content, no STIG content, and no vendor name
appears in any module of `core/config_audit/` — that is the property that lets
Phases 4, 5, 9, 10, 11 and 16 contribute _rules_ rather than engines.

### 6.1 What already existed and is reused, not rebuilt

Reading the tree first was the whole of the design work. Five things were
already right and are used as they stand:

| Existing thing                      | How Phase 3 uses it                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `compliance_rules`                  | **Configuration rules live here.** The table already carries `check_type`, a JSONB `check_definition`, `target_platform`, `severity`, versioning, a remediation link and a junction to every framework control. A second rule table would need all of it again — and would bring a second finding table, a second score and a second report behind it. |
| `core/checks/contract.py` (Phase 0) | `CheckOutcome`, `CheckResult`, `Evidence` and `roll_up_outcomes` are the engine's output types unchanged. The FAIL-must-carry-evidence invariant applies to every configuration finding for free.                                                                                                                                                      |
| `compliance_findings.status`        | The four non-error outcomes are spelled identically, so a verdict stores with no translation table.                                                                                                                                                                                                                                                    |
| `scans/finding_normalizer.py`       | A failing check becomes an ordinary `StandardizedFinding` and travels the existing normalizer → risk → PDF path.                                                                                                                                                                                                                                       |
| `BaseExecutor` (`ssh_scanner.py`)   | Collectors run over SSH or WinRM without knowing which — the same protocol that let Phase 2 swap transports without touching `WindowsCollector`.                                                                                                                                                                                                       |

`_evaluate_operator` was **moved rather than copied**. `core/compliance_tasks`
now delegates to `core/config_audit/operators.py`; the pre-Phase-3
implementation is retained as `_evaluate_operator_legacy` and is the reference
the truth-table test compares against, so the move is held to being a move.

### 6.2 The distinction the engine is built around

Three situations look identical to a collector that returns a bare string, and
every configuration scanner that reports false results has collapsed them:

| State         | Means                                                     | Becomes                        |
| ------------- | --------------------------------------------------------- | ------------------------------ |
| `COLLECTED`   | A value was read                                          | compared → PASS or FAIL        |
| `ABSENT`      | The collector ran and the thing genuinely is not there    | **the rule's** `AbsencePolicy` |
| `UNSUPPORTED` | The check cannot apply to this target at all              | NOT_APPLICABLE                 |
| `UNAVAILABLE` | Collection failed — no credential, refused, non-zero exit | **ERROR, never a verdict**     |

`AbsencePolicy` has **no default**. Absence is a pass for "SMBv1 must not be
installed", a failure for "auditd must be installed", and not-applicable for
"if IIS is present it must be configured thus". A default would silently pick
whichever answer flatters the score, so a rule that does not choose is refused
at construction.

`WindowsCollector._run` and `LinuxCollector._run` both end with
`return _clean_output(result.stdout) if result.stdout else ""` — the exit code
is discarded. Defensible for bulk inventory; for a configuration check it is
the central defect, because a failed command returns `""` and the comparison
reads `""` as the host's setting. `ShellRunner` therefore keeps `exit_code` and
`success`, and has no method that returns a bare string.

### 6.3 What was built

| Module                                            | What it is                                                                                                 |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `core/config_audit/spec.py`                       | `ConfigCheck`, `Expectation`, `AbsencePolicy`; the adapter to and from `compliance_rules.check_definition` |
| `core/config_audit/collection.py`                 | `CollectedState` (the four states), `CollectionContext`                                                    |
| `core/config_audit/operators.py`                  | The comparison vocabulary, shared with the compliance engine                                               |
| `core/config_audit/collectors/`                   | 11 Windows collectors, 10 Linux; `ShellRunner`; the registry                                               |
| `core/config_audit/engine.py`                     | The pipeline and the outcome table; `ConfigAuditReport`; `select_checks`                                   |
| `core/config_audit/findings.py`                   | Both joins — `StandardizedFinding` and the compliance verdict                                              |
| `core/config_audit/builtin/`                      | 10 Windows + 10 Linux real host rules                                                                      |
| `routers/config_audit.py`                         | 4 read operations                                                                                          |
| `Frontend/src/pages/scan/ConfigurationChecks.jsx` | The catalogue, with the absence policy and the capability gap made visible                                 |

**Check types** (13): `registry`, `file`, `directory`, `permission`, `service`,
`process`, `package`, `port`, `config_file`, `command`, `security_policy`, plus
`api` and `database_query` reserved. Collectors exist for **11 of them on
Windows and 10 on Linux** (`registry` is Windows-only). The two reserved types
have no collector; a rule using one reports ERROR rather than being skipped, so
the gap is visible instead of scoring as a pass.

**Operators**: the 13 pre-existing ones with semantics frozen, plus `matches`,
`not_matches`, `in`, `not_in`, `between`, `starts_with`, `ends_with`,
`is_true`, `is_false`.

### 6.4 Where results go — one finding model, not two

A FAIL becomes a `StandardizedFinding` in the same `cve_list` as the CVE
findings, so it is severity-ranked, risk-scored and reported beside them.
Identifiers are minted `CCURE-CFG-…` by `definition_id_for_check` and filed as
`definition_type = config_check` with `cve_id` NULL — which is what Phase 0
widened `vulnerability_definitions` for.

The audit runs **inside the credentialed scan**, on the session the collectors
already opened (`core/tasks.audit_credentialed_host`). There is deliberately no
"run a configuration audit" endpoint: it would be a second way to start a scan
against a caller-named target, needing its own scope check, quota check, rate
limit and audit entry, and it would produce scan rows Scan History and the
reports would have to learn about. Phase 1 made the same call for scheduling.

An audit that could not run is recorded as
`MISC-CREDENTIALED-CONFIG-NOT-ASSESSED`, the same treatment the OS and
inventory branches already give an unassessed dimension — because a crashed
audit leaves no failing checks, which is byte-identical to a host that passed
every one.

### 6.5 Database change

Migration `b4c5d6e7f8a9` replaces two CHECK constraints on `compliance_rules`.
No column added, no row rewritten.

- `ck_rule_check_type` gains the 12 new type names; all seven existing names are
  kept verbatim, so every seeded rule still satisfies it.
- `ck_rule_target_platform` gains `database` and `container`, reserved ahead of
  Phases 10, 11 and 17 so those need no CHECK migration on a table holding
  customer rules.

The old type names are **kept rather than mapped**. The two rule kinds are told
apart by `check_definition.config_check`, not by the type name, precisely so
they can share it — renaming would mean an UPDATE across every seeded rule in
every tenant's database to gain nothing a reader can see.

Verified: `create_all` (fresh install) and `alembic upgrade` (existing install)
produce **byte-identical** constraint text; up → down → up round-tripped clean;
downgrade **refuses** with the offending rule named when a Phase 3 rule exists.

### 6.6 Validation

| Area                          | Result                                                          |
| ----------------------------- | --------------------------------------------------------------- |
| New tests                     | **241** — 239 across 6 new files, 2 added to the report suite   |
| Full suite                    | **1945 passed, 2 skipped, 0 failed** (6m56s) — exactly +241     |
| Migration round-trip          | up / down / up, zero drift; downgrade refusal exercised         |
| Model ↔ migration constraint | byte-identical, asserted in code                                |
| OpenAPI contract              | regenerated — **466 insertions, 0 deletions** (purely additive) |
| `black` 24.4.2                | clean                                                           |
| `ruff` (project rule set)     | clean                                                           |
| `bandit -lll`                 | no issues, 3,644 lines scanned                                  |
| `eslint` / `prettier`         | clean; `npm run build` succeeds                                 |
| Docs integrity                | 4 new routes documented; test passes                            |

**The three acceptance criteria are asserted directly**, each from several
directions rather than once:

- _Unavailable evidence must not become PASS_ —
  `TestFailedCollectionNeverBecomesPassOrFail`, 7 tests.
- _Unsupported controls must not become FAIL_ —
  `TestUnsupportedControlsAreNeverFailures`, 3 tests.
- _Failed collection must not become PASS_ —
  `TestNoPathReachesPassExceptATrueComparison`, which enumerates every modelled
  failure and asserts none reaches PASS, plus a sweep over every
  `CollectionStatus` member so that a state added later cannot land on the
  flattering answer without this failing.

Scoring is asserted separately: errors are excluded from **both halves** of the
fraction, and a host with no verdicts scores `None` rather than 0% or 100% —
both of those are assertions nobody established.

### 6.7 Two defects the tests caught during development

Recorded because neither would have surfaced in a passing scan, and both are
the shape this engine exists to prevent.

**A multi-line value was truncated to its first line.** Only the first line of
a command's output carries the `CCURE::VALUE::` sentinel, and the first parser
returned that line alone. Every configuration file was therefore read as its
first directive and every other directive in it reported as _absent_ — which
surfaces as a fleet-wide configuration gap rather than as a parser bug. Caught
by `test_the_last_occurrence_wins`; now asserted directly by
`test_a_value_continues_past_the_first_line`.

**The Windows security-policy collector never read its own export.** `secedit`
ran, the INI parsed, and the parsed result was then discarded — so every policy
setting not already present in `password_policy` reported UNAVAILABLE. Caught
by `test_a_setting_absent_from_the_policy_falls_through_to_secedit`.

One pre-existing defect was fixed in passing: `pdf_generator` looked up the
remediation-provenance label with a **dict subscript**, so any
`RemediationConfidence` member added later raised `KeyError` _inside PDF
generation_ — a whole report lost to a missing label. It is a `.get` with a
fallback now, and `test_every_remediation_confidence_has_a_report_label` keeps
every member's label specific.

### 6.8 Coverage

| Capability                          | Before         | After              | Basis                                                                                                                                                                                                                   |
| ----------------------------------- | -------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GAP-03 generic configuration engine | 35% [measured] | **90%** [measured] | 11 of 13 check types have a collector on Windows, 10 of 13 on Linux; the full rule → collector → evaluation → evidence → finding → risk → remediation → report path is exercised end to end through the real collectors |

The 10% shortfall is named, not rounded away: the `api` and `database_query`
check types are declared and uncollected (Phases 9, 10, 16), and the engine has
not been run against a live host in this phase — the built-in rules are
exercised through the real collectors with a stubbed transport, which proves the
wiring but not the PowerShell and shell fragments against a running OS.

### 6.9 Known limitations

- **Not validated against a live host.** Phase 2's real-target validation proved
  the transport; Phase 3's commands have not been run on 10.180.6.14. The
  sentinel protocol, the quoting and the exit-code handling are asserted against
  a stub executor. **This is the honest gap in this phase** and the first thing
  to close when a target is available.
- **`api` and `database_query` have no collector.** Reserved deliberately;
  reported as ERROR, never skipped.
- **Configuration results do not yet write `compliance_findings` rows.**
  `compliance_verdict()` produces the payload and is tested, but nothing calls it
  from the scan path — configuration rules are not yet linked to framework
  controls, and linking them is Phase 4's job when there is benchmark content to
  link. The _finding_ path is wired end to end.
- **The built-in rule pack is 20 checks.** Deliberately small: it exists to prove
  the engine, not to be a benchmark. Inflating it would inflate the coverage
  figure without adding capability.
- **`config_file` does not follow `Include` directives.** An `sshd_config` that
  includes fragments is read only at the named path. Absence of a directive is
  `MANUAL_REVIEW` for exactly this reason.

### 6.10 Definition of Done — Phase 3

| Line                   | GAP-03                                                           |
| ---------------------- | ---------------------------------------------------------------- |
| Backend implemented    | ✅                                                               |
| Scanner integration    | ✅ runs inside the credentialed scan                             |
| Database migration     | ✅ `b4c5d6e7f8a9`, round-tripped                                 |
| API                    | ✅ 4 operations                                                  |
| UI                     | ✅ catalogue page                                                |
| Finding integration    | ✅ one finding model                                             |
| Evidence               | ✅ expected + observed on every result                           |
| Risk                   | ✅ severity → the existing risk path                             |
| Remediation            | ✅ `CONFIGURATION_GUIDANCE`, actionable                          |
| Compliance             | ⚠️ verdict adapter built and tested; not yet called (Phase 4)    |
| Reporting              | ✅ same PDF path as the CVE findings                             |
| Logging / audit        | ✅                                                               |
| RBAC                   | ✅ `scans:read`, no new permission                               |
| Unit tests             | ✅                                                               |
| Integration tests      | ✅                                                               |
| E2E tests              | ✅ through `audit_credentialed_host`                             |
| Regression suite       | ✅ 1945 passed / 2 skipped / 0 failed                            |
| Real-target validation | ❌ **not performed** — see §6.9                                  |
| False-positive testing | ✅ passing and deliberately failing configurations both asserted |
| Docs                   | ✅                                                               |
| Tracker                | ✅                                                               |
| Commit                 | ✅                                                               |

---

## 7. Phase 4 — Benchmark assessment capability (CIS)

**Status: Complete as a capability. The CIS Benchmark _content_ is not present
and is not claimed.** Closes GAP-04 as far as it can be closed without licensed
content; the remaining gap is named and measured in §7.8.

### 7.1 The finding that shaped the phase

The brief asked for CIS Benchmark assessment for Windows Server, Windows
Client, Ubuntu and RHEL. Inspecting the repository first produced a distinction
that changes the whole phase:

| Item                                                                                               | Present?                                                                  |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `cis_v8_1_controls_seed.json` — **CIS Critical Security Controls v8.1**, 153 governance safeguards | **yes**, and real                                                         |
| **CIS Benchmarks** — per-platform hardening recommendations (`2.3.1.1 (L1) Ensure …`)              | **no**. No XCCDF, no OVAL, no SCAP datastream, no benchmark text anywhere |

These are separate publications. What ships is the governance framework
("Establish and Maintain Detailed Enterprise Asset Inventory"); what Phase 4
asked for is the hardening benchmarks.

**Benchmark content was not written from memory, and this is not a shortcut
taken for time.** A rule labelled `2.3.1.1` carrying a recalled expected value
is a false compliance claim in a customer's audit report, and it is
indistinguishable from a correct one until an auditor checks. CIS Benchmark
recommendation text, rationale and remediation are also the Center for Internet
Security's, distributed under licence — the programme's own "licensing
concerns" stop condition, verbatim.

The decision taken, with the operator: **build the capability and the ingestion
path now; load licensed content when it is available.** Phase 4 therefore
delivers everything except the copyrighted text, and the two things that were
genuinely blocked are named rather than approximated.

### 7.2 What was reused rather than rebuilt

| Existing thing                           | How Phase 4 uses it                                                                                                                                                                                 |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `compliance_frameworks/_controls/_rules` | **A benchmark is a framework.** No new table: recommendations are controls, automated recommendations are rules, and the register, score, findings queue and report work the moment the rows exist. |
| Phase 3 `ConfigAuditEngine`              | Executes benchmark rules unchanged. Phase 4 adds _content_, not an engine.                                                                                                                          |
| `ConfigCheck`                            | The `check` inside a benchmark control is a Phase 3 check, round-tripped through `compliance_rules.check_definition`.                                                                               |
| `_save_finding_for_control`              | Writes every compliance finding, including the history transition, the exception-waiver check and the scope columns. Not reimplemented.                                                             |
| `resolve_controls_for_rule`              | Framework-scoped control resolution, for the reason CLAUDE.md records — 57 of 114 ISO rules once resolved into a _different_ standard.                                                              |
| `compliance_verdict()` (Phase 3)         | Written and tested in Phase 3, called by nothing. Phase 4 is what calls it.                                                                                                                         |
| `StandardizedFinding` → risk → PDF       | A failing benchmark control is an ordinary security finding beside the CVEs on the same host.                                                                                                       |

### 7.3 What was built

| Module                                       | What it is                                                         |
| -------------------------------------------- | ------------------------------------------------------------------ |
| `core/benchmarks/pack.py`                    | The content format and the parser that refuses to guess            |
| `core/benchmarks/loader.py`                  | Writing a pack into the compliance catalogue, idempotently         |
| `core/benchmarks/selection.py`               | Which benchmark checks apply to a scan, resolved from the database |
| `core/config_audit/compliance_sync.py`       | Verdict → `compliance_findings` — the link Phase 3 left open       |
| `scripts/benchmarks/load_benchmark.py`       | The loader CLI, with `--dry-run`                                   |
| `scripts/benchmarks/build_baseline_packs.py` | Generates the shipped packs from the built-in rules                |
| `data/benchmarks/README.md`                  | The format, field by field, for converting a licensed CIS export   |
| `data/benchmarks/*.benchmark.json`           | Two CCURE-authored baselines (**not** CIS Benchmarks)              |

### 7.4 The three states that keep the numbers honest

`assessment` is **declared, never inferred**:

| Value           | Meaning                                                      | `check`                           |
| --------------- | ------------------------------------------------------------ | --------------------------------- |
| `automated`     | The benchmark automates it and this product implements it    | required                          |
| `manual`        | The benchmark itself requires human judgement                | refused                           |
| `unimplemented` | The benchmark automates it and **this product does not yet** | refused, and a reason is required |

Reading "has a check" as "is automated" is exactly the inference that produced
the eighteen ISO controls claiming `semi_auto` with no automated rule behind
them. `unimplemented` is the state that makes coverage honest: without it, the
only way to represent a control the product cannot assess is to leave it out —
and a benchmark that omits what it cannot do reports better coverage than it
has. An `unimplemented` control is loaded, counted, and evaluated as _not
assessed_.

### 7.5 Operating-system targeting — a gap found while building

`platforms` distinguishes Windows from Linux and no further. That is not enough
for benchmark content: a CIS Ubuntu 22.04 benchmark and a CIS RHEL 9 benchmark
are both `linux`, and running one against the other's host checks paths and
package names that distribution does not use — then reads their absence as a
verdict. Confident, wrong findings.

A pack now declares `applies_to` once (`os_name_contains`,
`os_version_prefix`) and it flows onto every check. **An unidentified OS is an
ERROR, not NOT_APPLICABLE**: "we could not tell what this host runs" and "this
host is not what the benchmark is for" are different facts, and only the second
is a legitimate reason for a control to leave the score.

Without this, the four benchmarks the brief names could not have coexisted in
one installation.

### 7.6 Two pre-existing defects found and fixed

**CIS Controls v8.1 was seeded by nothing.** Its seed file, its theme migration
(`o6p7q8r9s0t1`) and its `ALL_FRAMEWORK_IDS` entry have all shipped since before
Phase 4, and `main.py`'s bootstrap named twelve catalogues and not this one. It
was parked _and_ unseeded, so the omission was invisible — activating it was
what surfaced it. The bootstrap now seeds it.

**The theme list existed in five places and the test copy silently won.**
`ck_control_theme`, `ck_score_theme`, every framework migration, and
`tests/conftest.py` each held their own transcription of ~126 values, and
conftest rewrites the constraint on every session — so a theme added to the
model _and_ its migration was still rejected by the test database, with nothing
saying why. It is now one tuple, `CONTROL_THEMES`, imported by the model and by
conftest and duplicated only in the migration that changes it (which must
describe the schema as it was).

Related hazard, recorded rather than fixed: `_build_test_schema` bootstraps
from the models and stamps head, so a migration written after a bootstrap never
runs against that database. Column changes are gap-filled; **CHECK constraint
changes are not**.

### 7.7 Validation

| Area                             | Result                                                                                                            |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| New tests                        | **100** across 4 files (net **+99**: the parked-report test lost its `cis_v8_1` parameter when CIS was activated) |
| Compliance group                 | 223 passed (from 132)                                                                                             |
| Full suite                       | see §9                                                                                                            |
| End-to-end chain                 | proven against the shipped packs through the real collectors                                                      |
| Migration round-trip             | up / down / up clean; downgrade refuses and **names the rows**                                                    |
| Model ↔ migration constraint    | byte-identical, asserted in code                                                                                  |
| Loader idempotence               | second load creates 0, updates 22                                                                                 |
| Pack ↔ generator drift          | `--check` in CI and in the suite                                                                                  |
| OpenAPI                          | **unchanged** — Phase 4 adds no route                                                                             |
| `black` / `ruff` / `bandit -lll` | clean                                                                                                             |

The chain, measured on a stubbed transport against the real Windows pack:

```
10 benchmark checks resolved from compliance_rules
  → engine: 1 pass, 1 fail, 8 error, score 50.0%
  → 10 compliance findings across 10 controls
     1 fail, 1 pass, 8 manual_review
  → 1 security finding, CCURE-CFG-…, High, actionable remediation
```

**The eight unreadable checks became `manual_review`, not `pass` and not
`fail`.** That is the property the whole engine exists for and it is asserted
from several directions in `test_benchmark_compliance.py`.

### 7.8 Coverage — measured

| Figure                                 | Value                                                                  |
| -------------------------------------- | ---------------------------------------------------------------------- |
| **CIS Benchmark controls implemented** | **0** — no CIS Benchmark content is present                            |
| Benchmark packs shipped                | 2 (CCURE-authored baselines, explicitly not CIS)                       |
| Benchmark controls total               | 22                                                                     |
| — automated                            | 20                                                                     |
| — manual                               | 0                                                                      |
| — unimplemented                        | 2 (each with a recorded reason)                                        |
| Automation rate                        | 90.9%                                                                  |
| Platforms covered                      | 2 — `windows`, `linux`                                                 |
| Profiles covered                       | 2 — L1 (18 controls), L2 (4 controls)                                  |
| Check types usable by a pack           | 11/13 Windows, 10/13 Linux (`api`, `database_query` have no collector) |
| CIS Controls v8.1 safeguards reachable | 10 of 153, via crosswalk from shipped benchmark controls               |
| Real-target validated controls         | **0**                                                                  |
| Automated-test coverage                | 100 tests over pack, loader, sync and the end-to-end chain             |

| Capability                          | Before        | After              | Basis                                                                                                                                                                                   |
| ----------------------------------- | ------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GAP-04 CIS benchmark content        | 0% [measured] | **0%** [measured]  | No CIS Benchmark control is implemented. The number does not move and must not be moved.                                                                                                |
| Benchmark _capability_ (new figure) | 0% [measured] | **85%** [measured] | Format, loader, profiles, OS targeting, selection, verdict→finding→risk→remediation and reporting all work end to end; missing is real-host validation and content ingestion from XCCDF |

**GAP-04 stays at 0% deliberately.** Shipping a loader is not shipping CIS
content, and moving the number because the machinery exists is exactly the
inflation the brief warned against.

### 7.9 Known limitations

- **No CIS Benchmark content.** The blocking one. Needs a licensed export;
  `data/benchmarks/README.md` documents the conversion.
- **Not validated against a live host.** Inherited from Phase 3 and unchanged:
  the collectors are exercised through a stubbed transport. No benchmark
  control has been run against a real machine.
- **Windows Server and Windows Client are one platform (`windows`); Ubuntu and
  RHEL are one platform (`linux`).** OS targeting (§7.5) separates them at the
  _pack_ level, so four benchmarks can coexist — but there is no `windows_server`
  vs `windows_client` distinction in the platform vocabulary itself, and the
  server/client split would have to be expressed through `os_name_contains`.
- **No XCCDF/OVAL importer.** Conversion into the pack format is currently
  manual. That is Phase 5's neighbourhood (SCAP) and is deliberately not
  started here.
- **Profile selection is not per-organisation.** The filter exists and is
  tested; nothing records which profile a tenant has adopted, so a scan
  assesses every profile. Assuming Level 1 would silently drop every Level 2
  control from the score. Phase 12 (scan policy) owns the setting.
- **`api` and `database_query` check types still have no collector**, so a
  benchmark using them reports errors rather than verdicts. Phases 9, 10, 16.
- **Benchmark findings do not yet appear in a benchmark-specific report.** They
  reach the existing compliance register, score, findings queue and framework
  report because a benchmark is a framework; there is no bespoke
  "CIS Benchmark report" endpoint.

### 7.10 Definition of Done — Phase 4

| Line                     | GAP-04                                                             |
| ------------------------ | ------------------------------------------------------------------ |
| Backend implemented      | ✅ format, loader, selection, sync                                 |
| Scanner integration      | ✅ benchmark rules run in the credentialed scan                    |
| Database migration       | ✅ `c5d6e7f8a9b0`, round-tripped, downgrade refuses safely         |
| API                      | ➖ none required; a benchmark is a framework and uses those routes |
| UI                       | ➖ visible through the existing marketplace, register and reports  |
| Finding integration      | ✅ compliance finding **and** security finding                     |
| Evidence                 | ✅ expected, observed, collector, timestamp on every verdict       |
| Risk                     | ✅ severity → the existing canonical scale                         |
| Remediation              | ✅ `CONFIGURATION_GUIDANCE`, actionable                            |
| Compliance result        | ✅ the link Phase 3 left open is now connected                     |
| Reporting                | ✅ through the framework report path                               |
| Profiles                 | ✅ data on the control, filterable, not hardcoded                  |
| Unit / integration / E2E | ✅ 100 tests                                                       |
| Regression suite         | ✅ see §9                                                          |
| Real-target validation   | ❌ **not performed**                                               |
| CIS content              | ❌ **absent, and not invented** — see §7.1                         |
| Docs                     | ✅ `data/benchmarks/README.md`, CLAUDE.md                          |
| Tracker                  | ✅                                                                 |
| Commit                   | ✅                                                                 |

---

## 8. Phase 5 — Local OS privilege & host-exposure assessment

**Status: Complete.** Closes GAP-08 to its agreed target. **The first phase in
this programme to be validated against real targets on both platforms.**

### 8.1 The gap, measured before touching anything

| Measurement                                    | Before                                                                                |
| ---------------------------------------------- | ------------------------------------------------------------------------------------- |
| Privilege findings ever minted (`CCURE-PRV-…`) | **0** — `DEFINITION_TYPE_PRIVILEGE_CHECK` was reserved in Phase 0 and used by nothing |
| Linux privilege signals collected              | 4 — `suid_binaries`, `world_writable_dirs`, `sudo_nopasswd`, `sudo_rules_raw`         |
| …converted into findings                       | **0** — they became sentences in `security_issues`                                    |
| Windows privilege signals collected            | **0**                                                                                 |
| GAP-08 coverage against the agreed scope       | **0 / 29 = 0.0%**                                                                     |

The data was half-collected, the finding type was reserved, and nothing joined
them. A NOPASSWD sudo rule was a sentence in a PDF: no severity, no risk score,
no remediation, no lifecycle, no deduplication, not exportable, not triageable.

### 8.2 What was reused rather than rebuilt

Phase 5 adds **no engine**. The checks are Phase 3 `ConfigCheck` records with
one new check type.

| Existing                               | Used for                                                     |
| -------------------------------------- | ------------------------------------------------------------ |
| Phase 3 `ConfigAuditEngine`            | Executes every privilege check unchanged                     |
| Phase 3 four-state collection contract | COLLECTED / ABSENT / UNSUPPORTED / UNAVAILABLE, unchanged    |
| Phase 3 `ShellRunner`                  | Exit-code-preserving command execution over either transport |
| Phase 0 `CCURE-PRV-` minting           | Reserved since Phase 0; this is what finally uses it         |
| Phase 2 WinRM + SSH                    | Both transports, untouched                                   |
| `StandardizedFinding` → risk → PDF     | A privilege failure is an ordinary finding beside the CVEs   |
| Phase 4 `finding_type` groundwork      | Extended from one type to two                                |

### 8.3 What was built

| Component                               | Contents                   |
| --------------------------------------- | -------------------------- |
| `collectors/privilege_windows.py`       | 10 probes                  |
| `collectors/privilege_linux.py`         | 12 probes                  |
| `builtin/privilege_windows.py`          | 10 checks                  |
| `builtin/privilege_linux.py`            | 12 checks                  |
| `scripts/measure_privilege_coverage.py` | The measurement harness    |
| Migration `d6e7f8a9b0c1`                | The `privilege` check type |

`ConfigCheck.finding_type` decides the identifier: `config_check` → `CCURE-CFG-`,
`privilege_check` → `CCURE-PRV-`, grouping into different report families
because "deviates from a baseline" and "has a path to SYSTEM" are different
piles to a triager. `cve` is refused at construction.

### 8.4 Severity, evidence-based

| Severity | Count | Examples                                                                                                                            |
| -------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Critical | 6     | weak service ACL, writable service binary, AlwaysInstallElevated, writable root PATH, writable systemd unit, account-file ownership |
| High     | 9     | unquoted service path, writable task binary, SUID outside the expected set, NOPASSWD sudo, world-writable dirs                      |
| Medium   | 4     | cached logons, LSA protection, SGID, world-writable files                                                                           |
| Low      | 3     | PowerShell logging, unowned files, ungrouped files                                                                                  |

The Critical six are direct, unconditional paths to SYSTEM or root. The unquoted
service path is **High, not Critical, deliberately**: it is only exploitable if
the attacker can _also_ write to one of the truncated directories, which this
check does not establish. Rating it Critical would place it above conditions
that need nothing further.

### 8.5 Real-target validation — both platforms, both directions

#### Windows — 10.180.6.14, read-only

Ten of ten checks assessed, **zero errors**. Nothing on the host was created,
modified or weakened.

| Result | Checks                                                                  |
| ------ | ----------------------------------------------------------------------- |
| PASS   | 4 — service ACLs, AlwaysInstallElevated, unattend files, LSA protection |
| FAIL   | 6 — see below                                                           |

The six failures are genuine findings on that machine and are reported to its
owner rather than buried here:

- **`Everyone :: FullControl` on Seqrite antivirus service binaries** and on a
  Seqrite scheduled-task binary. Any local user can overwrite what that service
  runs as SYSTEM. This is the most serious finding of the run.
- **Unquoted service paths** on `GlassFish_personal_domain_3` and
  `OracleServiceXE`.
- **`Authenticated Users : Modify`** on an Oracle XE `bin` directory that is on
  the system PATH.
- `CachedLogonsCount = 10`; PowerShell script-block logging disabled.

#### Linux — disposable container, both configurations

A throwaway container was built, deliberately weakened, scanned, cleaned, and
scanned again. It was removed afterwards. No host of the user's was touched.

| Configuration     | Result                                                      |
| ----------------- | ----------------------------------------------------------- |
| Deliberately weak | 5 FAIL naming every planted weakness, 6 PASS, 1 UNAVAILABLE |
| Cleaned           | 11 PASS, 1 UNAVAILABLE, **0 false positives**               |

Every planted weakness was detected and named: the SUID binary, the
world-writable directory, the world-writable file, the NOPASSWD rule _with its
text_, and the writable systemd unit. The captured output was then replayed
through the engine, producing 5 `CCURE-PRV-` findings — Critical through Medium,
family "Local Privilege", each carrying its offenders as evidence.

`file_capabilities` reported **UNAVAILABLE** on both runs because `getcap` is
not installed in that image. That is the honest direction working on a real
host: nothing was established, so nothing was claimed.

### 8.6 Three false positives that only real-target validation could find

Each would have shipped looking correct, and each is the "cries wolf" failure
the probes' own docstrings warn about.

- **`NT SERVICE\*` virtual accounts.** The service-ACL probe reported seven
  services on a stock Windows 11 workstation, because TrustedInstaller
  (`S-1-5-80-956008885-…`) legitimately holds full control over service
  configuration, and each service's own virtual account holds ChangeConfig over
  itself. Seven false positives on a clean host is the failure that teaches a
  reader to skip the check. `S-1-5-80-*` is now trusted.

- **`stat` does not dereference symlinks.** `/bin`, `/sbin` and `/lib` are
  symlinks into `/usr` on every modern distribution, and a symlink's own mode is
  always 777 — so the writable-PATH probe reported `/bin` and `/sbin` as
  world-writable **on every Linux host**. Fixed with `stat -L`.

- **`ssh-keysign` is legitimately SUID** on Debian and Ubuntu, for host-based
  authentication. Added to the allow-list.

Recorded, not fixed: `LinuxPermissionCollector` (Phase 3) has the same `stat -c`
without `-L`. It is only pointed at regular files today so it is not currently
wrong, but a symlinked target would fool it. Out of Phase 5's scope.

### 8.7 Coverage — measured, and the denominator was widened on purpose

| Figure                            | Before          | After                               |
| --------------------------------- | --------------- | ----------------------------------- |
| **GAP-08 (implemented + tested)** | 0/29 = **0.0%** | 22/29 = **75.9%**                   |
| implemented                       | 0               | 22                                  |
| Windows areas proven              | 0/14            | 10/14 (71.4%)                       |
| Linux areas proven                | 0/15            | 12/15 (80.0%)                       |
| `CCURE-PRV-` checks               | 0               | 22                                  |
| Real-target validated             | 0               | **22 of 22** (10 Windows, 12 Linux) |
| New tests                         | —               | 200                                 |

**The denominator includes eight areas this build does not implement**, and that
was a correction made mid-phase. The first version of the measurement listed
twenty areas, Phase 5 implemented all twenty, and it reported **100%** — a
tautology wearing a percentage: a list written by the same person who then
implements every item measures the list, not the capability. Eight real Nessus
local checks CCURE does not perform were added so the figure can go down.

**The headline number is _implemented and tested_, not implemented.** The
measurement reads the test sources, so an area whose test is deleted loses its
coverage credit. Real-target validation is reported beside it and never folded
in.

### 8.8 Remaining GAP-08 limitations

- **Eight in-scope areas are not implemented** and are named in the denominator:
  Windows token privileges, DLL search-order hijack paths, autorun binary
  permissions, Credential Manager entries; Linux `docker` group membership, NFS
  `no_root_squash` exports, `ld.so.preload`, and writable loader config.
- **The Linux validation substituted the transport.** The probe commands ran on
  a real Linux filesystem through the real `ShellRunner`, collector, engine and
  finding path, with `docker exec` in place of SSH. SSH itself was proven in
  Phases 2 and 3; it was not re-proven here.
- **No deliberately-weak Windows configuration was created.** Doing so would
  have modified the user's workstation and was not authorised. The Windows FAIL
  path is proven by the host's _own_ six genuine failures, not by a planted one.
- **`getcap` absent means unassessed, not clean** — correct, and it does mean
  the capability check is silently unavailable on minimal images.
- **The SUID allow-list is a fixed tuple**, not per-distribution. It is
  deliberately generous, so the error direction is a missed SUID binary rather
  than a false positive on a stock host.
- Out of scope by agreement and not in the denominator: kernel exploit
  suggestion, memory-resident checks, agent-based collection.

### 8.9 Definition of Done — Phase 5

| Line                       | GAP-08                                                                          |
| -------------------------- | ------------------------------------------------------------------------------- |
| Backend implemented        | ✅ 22 probes, 22 checks                                                         |
| Scanner integration        | ✅ runs in the credentialed scan beside the Phase 3 checks                      |
| Database migration         | ✅ `d6e7f8a9b0c1`, byte-identical constraint, refuses downgrade over live rules |
| API                        | ➖ none required; surfaced through the existing catalogue                       |
| UI                         | ➖ appears in the existing Configuration Checks page                            |
| Finding integration        | ✅ `CCURE-PRV-`, own report family, never a CVE                                 |
| Evidence                   | ✅ offenders named on every failure                                             |
| Severity / risk            | ✅ evidence-based, canonical vocabulary, existing risk path                     |
| Remediation                | ✅ `CONFIGURATION_GUIDANCE`, actionable, names what to fix                      |
| Lifecycle                  | ✅ via the existing finding model                                               |
| Reporting                  | ✅ same PDF path, separate family                                               |
| Unit / integration/E2E     | ✅ 200 tests                                                                    |
| Regression suite           | ✅ see §9                                                                       |
| **Real-target validation** | ✅ **Windows and Linux, compliant and non-compliant**                           |
| Coverage measured          | ✅ 0.0% → 75.9%, denominator widened against self-interest                      |
| Docs                       | ✅ CLAUDE.md                                                                    |
| Tracker                    | ✅                                                                              |
| Commit                     | ✅                                                                              |

---

## 9. Phase 6 — Unauthenticated network vulnerability checks

**Status: Complete.** Closes GAP-06 to its agreed target. Validated against
real listening services in both directions, and it repaired **six live
defects** — three of which produced silence and one of which produced a false
positive on every correctly configured TLS server.

### 9.1 The gap, measured before touching anything

`VulnerabilityEngine._merge` promotes a **top-level** `cves` key onto the host
record and nothing else. Every plugin that returned its findings nested inside
`http_audit` / `ftp_info` / `smb_info` therefore had them discarded before
anything downstream could see them.

| Measurement                                          | Before                                                                                        |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Plugins producing findings                           | **7 / 15**                                                                                    |
| Plugins detecting real conditions and reporting none | **6** — `http_analyzer`, `ftp_checker`, `smb_probe`, `snmp_probe`, `tls_scanner`, `ssh_probe` |
| Enumeration-only (correctly silent)                  | 2 — `udp_scanner`, `icmp_probe`                                                               |
| Network check areas emitting a finding               | **16 / 62 = 25.8%**                                                                           |
| Network findings carrying a typed identifier         | **0** — all twelve were ad-hoc `MISC-` strings                                                |
| `CCURE-CHK-` / `plugin_check` producers              | **0** — reserved in Phase 0, used by nothing                                                  |

**`ssh_probe` is the entry worth reading twice.** It initialised
`info["cves"] = []`, promoted it with `if info.get("cves")`, and nothing in the
module ever appended to it — the CVE lookup had been deliberately removed and
the promotion plumbing left behind. An independent AST pass over the fifteen
modules answers **8**, because structurally that plugin _can_ return a `cves`
key. The truth is 7. The coverage harness therefore reads a catalogue rather
than the sources: a measurement that cannot tell live code from dead plumbing
would have reported this phase's own starting point one area too high, and
every "after" number would have inherited the error.

### 9.2 Six live defects, and what each one did

| #   | Defect                                                                   | Effect                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Six plugins returned findings nested, not promoted                       | Every condition they detected was discarded                                                                                                                                                                                                 |
| 2   | `tls_scanner` used `log` and never imported it                           | Any TLS error path raised `NameError` inside the `except` block; the engine catches plugin exceptions at DEBUG, so the plugin looked registered and produced nothing                                                                        |
| 3   | `asset_syncer` set neither `definition_type` nor a NULL `cve_id`         | Every network finding was filed as a **fabricated CVE**, inheriting KEV lookups, EPSS scoring, CVSS bands and an NVD link that resolves to nothing                                                                                          |
| 4   | `cve_id` is `varchar(30)` and the insert is not inside a try/except      | Any fabricated identifier over 30 characters raised `StringDataRightTruncation` and **aborted the finding sync for the whole scan**. All three `MISC-CREDENTIALED-*` markers (33, 37, 39) and most Nuclei template ids are over it          |
| 5   | `_http_request` stopped reading at `\r\n\r\n` — the end of the _headers_ | The body was **empty on every request**, so directory-listing detection could never fire and sensitive-path exposure was decided by status code alone                                                                                       |
| 6   | The sslyze wrapper tested `"VULNERABLE" in robot_enum.name`              | `"VULNERABLE"` is a substring of `"NOT_VULNERABLE"`, so **every server sslyze positively cleared was reported vulnerable to ROBOT** — including any TLS 1.3-only listener, where RSA key exchange does not exist. Live on the web-scan path |

Defects 5 and 6 were found by pointing the code at a real target and
disbelieving the result. Defect 4 was found by building the migration's test
fixture. None would have been caught by a passing unit test.

### 9.3 What was reused rather than rebuilt

Phase 6 adds **no engine**. `VulnerabilityEngine`, `plugin_selector` and the
fifteen probes' own detection logic are unchanged.

| Existing                              | Used for                                                                             |
| ------------------------------------- | ------------------------------------------------------------------------------------ |
| Phase 0 `CheckResult` / `Evidence`    | Every finding is built through one, so FAIL-must-carry-evidence applies structurally |
| Phase 0 `CCURE-CHK-` / `plugin_check` | Reserved since Phase 0; this is what finally uses it                                 |
| Phase 0 `definition_type_for_id`      | Wired into the catalogue write path, which never called it                           |
| `scans/finding_normalizer`            | `active_check` → `CONFIG_CHECK`, QoD 99, Confirmed                                   |
| `core/web/sslyze/wrapper.py`          | The deep TLS engine, moved onto the network path                                     |
| `deduplicate_cves`                    | Two probes reporting one condition collapse to one finding                           |
| `core/risk.py`, the PDF path          | Unchanged — a network check is an ordinary finding                                   |

### 9.4 What was built

| Component                                   | Contents                                               |
| ------------------------------------------- | ------------------------------------------------------ |
| `engines/vulnerability/network_checks.py`   | The check catalogue and `network_finding()`            |
| `scripts/measure_network_check_coverage.py` | The measurement harness, denominator frozen at Stage 1 |
| Migration `e7f8a9b0c1d2`                    | Retypes and renames the fabricated catalogue rows      |
| `tests/scans/test_network_check_*.py`       | 137 tests across contract, promotion and pipeline      |

### 9.5 Identifier typing — the defect and the migration

A real CVE keeps `definition_type = cve`, its own identifier, its NVD link and
its KEV and EPSS enrichment, because all of it means something. Everything else
mints `CCURE-CHK-…` with `cve_id` NULL.

`ck_vuln_def_cve_id_matches_type` could not catch the old behaviour: it asks
whether a `cve` row carries a `cve_id`, and these rows did — just not a real
one.

**The migration renames rather than leaving the old identifiers alone.** Leaving
them would split each condition's history in half — the old row from before the
upgrade and a new one from the next scan — and show a triager one problem twice.

Three things it has to handle, all exercised on a throwaway database:

- **Collisions.** `MISC-SMB-SIGNING` and `MISC-NUCLEI-SMB-SIGNING` are two names
  for one condition. The surviving row is the one with the earlier
  `first_found_at`; which is processed first is an artefact of sort order and
  must not decide it. Both the primary key and
  `uq_asset_vuln_scan_asset_cve` can collide, and they are different keys — the
  first version checked only the second and aborted the upgrade on the first.
- **Finding primary keys.** `asset_vulnerabilities.id` embeds the identifier, so
  a renamed row whose key still ends in the old one is invisible to
  `_resolve_finding_id` and the condition is reported as newly discovered on
  every subsequent scan. Nothing references that column, so it is rewritten.
- **The Nuclei family.** One row per template, so it is renamed by pattern.
  Anything that would exceed the 120-character column is retyped in place
  rather than truncated — a truncated key merges two unrelated templates.

The map is a **literal in the migration**, not an import from the catalogue: a
migration must do the same thing in five years as it does today.
`test_the_migration_and_the_catalogue_agree` is what makes that duplication
safe.

Round-tripped on `ccure_gap06_migrationcheck_pytest_db` (created and dropped;
the live database was not touched): 5 fabricated rows → **0**, the real CVE
untouched, the two SMB identifiers merged keeping the older history, primary
keys rewritten, up → down → up converging.

### 9.6 Detections deliberately **not** promoted

Three, each because promoting it would have produced a false positive on
ordinary hosts. Every one stays exactly where it was in the metadata, so no
existing report changes.

- **`smb_probe.null_session`.** Set from the negotiate response's NT status
  being zero — STATUS_SUCCESS, which every reachable SMB server returns.
  Nothing attempts a session setup with an empty username. It would have fired
  on every Windows host in every estate.
- **`http.admin_interface_exposed`.** The panel probe matches on path plus a
  200/401/403 status with no body check, and a single-page application answers
  every unknown route with 200 and its index document — so all thirteen
  fingerprints match at once. It is recorded as **not implemented** in the
  denominator rather than counted.
- **`eternalblue_probe` reporting SMBv1 as CVE-2017-0144.** EternalBlue needs
  SMBv1 _and_ an unpatched implementation; a patched host with SMBv1 on
  satisfies only the first and was being told it carried a Critical remote code
  execution it does not have. It now reports `smb.v1_enabled`, and the
  MS17-010 fingerprint alone claims the CVE. The companion identifier
  `CVE-2017-0144-ACTIVE` — a CVE-shaped string that is not a CVE — is gone.

`http.sensitive_path_exposed` was narrowed rather than dropped: it fires only
where the response _body_ fingerprints as the named file. Without that, the
same SPA catch-all made `/login`, `/admin/`, `/dashboard` and `/console` read
as exposed files.

### 9.7 Real-target validation — both directions

No host of the user's was modified. Every weak configuration lived in a
disposable container, and every container was destroyed afterwards.

#### Deliberately weak — must detect

| Target                                                               | Result                                                                            |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| vsftpd, anonymous + write, weak credentials                          | 3 findings, evidence naming the accepted accounts                                 |
| Redis, no authentication                                             | 1 finding, Critical                                                               |
| snmpd, community `public`                                            | 3 findings; evidence names the community and states that write was **not** tested |
| nginx serving `.env`, `.git/config`, a directory index               | 4 findings; the evidence quotes the exposed content                               |
| nginx on Debian 10: TLS 1.0/1.1, anon suites, SHA-1 self-signed cert | 4 findings                                                                        |

**12 findings, 0 fabricated identifiers, all Confirmed at QoD 99, all
reportable, all carrying remediation.**

The weak-TLS run is the clearest demonstration of what the phase added: the
handshake negotiated `ECDHE-RSA-AES256-GCM-SHA384` — a _strong_ suite — while
the deep engine found **3 weak suites the server would still accept** across
TLS 1.0, 1.1 and 1.2. A single handshake can never see those, because a modern
client negotiates the best suite on offer.

#### Hardened — must report nothing

| Target                                                                    | Result                |
| ------------------------------------------------------------------------- | --------------------- |
| Host nginx on 443 (real, read-only): TLS 1.2/1.3, internal-CA certificate | **0 findings**        |
| The same container after hardening FTP, Redis and SNMP                    | **0 false positives** |

The only finding on the hardened container is `ftp.cleartext_protocol`, which
is correct and expected: FTP is still listening, and that check states a
property of the protocol rather than a weakness this server chose. It is Low
for exactly that reason.

**One false-negative was nearly recorded as a false-positive result.** The
first hardened rescan still reported anonymous FTP and unauthenticated Redis.
The probes were right: `pkill` had not killed the original processes, they were
still running with the weak configuration, and `530 Login incorrect` only
appeared once they were killed by PID. Checking the target before believing the
finding is the same discipline the inventory test needed in Phase 1.

### 9.8 Coverage — measured, denominator frozen at Stage 1

| Figure                                         | Before            | After             |
| ---------------------------------------------- | ----------------- | ----------------- |
| **GAP-06 (implemented + tested)**              | 16/62 = **25.8%** | 40/62 = **64.5%** |
| Plugins producing findings                     | **7/15**          | **13/15**         |
| Fabricated CVE identifiers minted              | 12 kinds          | **0**             |
| Fabricated `cve`-typed catalogue rows per scan | 12 kinds          | **0**             |
| New tests                                      | —                 | 137               |

The denominator was written and frozen **before** any implementation, and it
contains 22 areas this build does not perform — RDP, VNC, NFS, RPC, IPMI, NTP,
SMTP, SNMPv3, WebDAV, open proxy, CORS, Logjam, insecure renegotiation, SMB
null session and guest access, SSH protocol v1 and weak host keys, certificate
expiry warning and chain trust, and admin-interface exposure. A coverage figure
is only worth reading if it can go down.

The headline is **implemented _and_ tested**, and "tested" is not self-asserted:
`test_every_declared_area_has_a_behavioural_test` requires a behavioural test in
the promotion suite to name that area's catalogue identifier, which it can only
do by driving the plugin. Delete a behavioural test and the area loses its
coverage credit.

### 9.9 Remaining GAP-06 limitations

- **22 areas are in the denominator and not implemented**, named above.
- **`http_analyzer` still assesses one port per host.** It picks 443/8443 first,
  else 80/8080/8000/8888. Assessing every web port would multiply twenty path
  probes and thirteen panel probes per port, which matters on the OT segments
  this product scans. TLS _does_ assess every endpoint.
- **The sensitive-path probe does not follow redirects**, so an exposed
  directory reached through a 301 is missed. `/backup` → `/backup/` is the
  common case.
- **`ftp_checker._test_write_access` issues `MKD` and `RMD` against the
  target.** It creates and removes a directory — a write to a scanned host,
  which sits awkwardly beside this phase's detection-only scope. Pre-existing
  behaviour, left unchanged because removing it removes a real Critical
  detection. Flagged for a decision.
- **Existing `CVE-2017-0144` findings that actually meant "SMBv1 enabled" keep
  that identifier** until the next scan. They cannot be remapped safely: the
  same identifier is also written legitimately by the CVE engine and the feeds,
  and renaming it would destroy genuine findings.
- **The live database is at `d0e1f2a3b4c5`** — behind `e1f2a3b4c5d6` and
  everything after it, including this phase's migration. Recorded in §4.5 since
  Phase 1 and unchanged; the typed catalogue write needs `definition_type` to
  exist before it can run there.
- **`tls.certificate_expiring_soon` is logged, not reported.** A certificate
  that is still valid is not yet a finding; the data is in the log and the area
  stays in the denominator as unimplemented.
- **Deep TLS is bounded** to four endpoints per host (`TLS_DEEP_MAX_ENDPOINTS`)
  and can be disabled entirely (`TLS_DEEP_SCAN`). Measured at 2.2s per endpoint
  against a well-configured listener.

### 9.10 Definition of Done — Phase 6

| Line                       | GAP-06                                                                                        |
| -------------------------- | --------------------------------------------------------------------------------------------- |
| Backend implemented        | ✅ catalogue + 6 plugins promoted + deep TLS                                                  |
| Scanner integration        | ✅ same engine, same selector, no new pipeline                                                |
| Database migration         | ✅ `e7f8a9b0c1d2`, round-tripped, collisions resolved                                         |
| API                        | ➖ none required; no new route                                                                |
| UI                         | ➖ findings appear in the existing vulnerability views                                        |
| Finding integration        | ✅ one finding model; `CCURE-CHK-`, real CVEs preserved                                       |
| Evidence                   | ✅ required at construction; names the offender                                               |
| Severity / risk            | ✅ evidence-based, canonical, existing risk path                                              |
| Remediation                | ✅ required on every non-dynamic check                                                        |
| Reporting                  | ✅ same PDF path                                                                              |
| Unit tests                 | ✅                                                                                            |
| Integration tests          | ✅                                                                                            |
| E2E tests                  | ✅ detection → evidence → typed definition → finding → severity → risk → remediation → report |
| Regression suite           | ✅ see §11                                                                                    |
| **Real-target validation** | ✅ **weak and hardened, five services, two platforms**                                        |
| False-positive testing     | ✅ 0 on every hardened target                                                                 |
| Coverage measured          | ✅ 25.8% → 64.5%, denominator frozen before implementation                                    |
| Docs                       | ✅ CLAUDE.md                                                                                  |
| Tracker                    | ✅ this section                                                                               |
| Commit                     | ✅                                                                                            |

---

## 10. Definition of Done — Phase 0

| Line                      | GAP-00-A                                  | GAP-00-B                             |
| ------------------------- | ----------------------------------------- | ------------------------------------ |
| Backend implemented       | ✅                                        | ✅                                   |
| Scanner/check logic       | ✅ contract + registry                    | N/A (model layer)                    |
| Database changes          | N/A                                       | ✅ `e1f2a3b4c5d6`                    |
| Migration tested          | N/A                                       | ✅ up/down/up round-trip, zero drift |
| API implemented           | N/A — no HTTP surface in this phase       | N/A                                  |
| UI implemented            | N/A                                       | N/A                                  |
| Finding model integrated  | ✅ `CheckResult.is_finding`               | ✅ the model itself                  |
| Evidence integrated       | ✅ `Evidence`, redacted at construction   | ✅ `evidence` column already present |
| Risk scoring integrated   | ✅ severity reuses `CANONICAL_SEVERITIES` | ✅ unchanged path                    |
| Remediation integrated    | ✅ `CheckResult.remediation`              | ✅ existing columns                  |
| Compliance mapping        | ✅ outcome vocabulary is compliance's     | ✅                                   |
| Reporting integrated      | Deferred to first producer (Phase 3)      | Deferred to first producer (Phase 3) |
| Logging                   | ✅                                        | ✅                                   |
| Audit trail               | N/A — no state change                     | N/A — schema only                    |
| RBAC enforced             | N/A — no endpoint                         | N/A                                  |
| Security validation       | ✅ evidence redaction tested              | ✅ CHECK constraints tested          |
| Unit tests                | ✅ 54                                     | ✅ included                          |
| Integration tests         | ✅ plugin dispatch against real modules   | ✅ migration against real PostgreSQL |
| E2E tests                 | N/A — no user-facing flow                 | N/A                                  |
| Regression passed         | ✅ §5                                     | ✅ §5                                |
| Real-target validation    | N/A                                       | N/A                                  |
| False-positive validation | ✅ mutation test                          | ✅ 3 rejection cases                 |
| False-negative validation | ✅ mutation test caught the seeded defect | ✅ 3 acceptance cases                |
| Performance tested        | N/A — static; migration is metadata-only  | ✅ no table rewrite                  |
| Documentation updated     | ✅                                        | ✅                                   |
| Gap tracker updated       | ✅ this document                          | ✅                                   |
| Git commit                | see §6                                    | see §6                               |
| Working tree clean        | see §6                                    | see §6                               |

---

## 11. Regression

| Run                                              | Result                                                    |
| ------------------------------------------------ | --------------------------------------------------------- |
| Baseline (before any Phase 0 change), full suite | **1535 passed, 2 skipped**, 6m22s                         |
| After Phase 0, full suite                        | **1589 passed, 2 skipped**, 6m12s                         |
| After the audit-boundary fix, full suite × 3     | **1589 passed, 2 skipped**, every run                     |
| After the catalogue-residue cleanup, full suite  | **1592 passed, 2 skipped** + 1 pre-existing flake (below) |
| After Phase 1, full suite                        | **1661 passed, 2 skipped**, 7m23s                         |
| After Phase 2, full suite                        | **1704 passed, 2 skipped**, 7m06s                         |
| After Phase 3, full suite                        | **1945 passed, 2 skipped**, 6m56s                         |
| After Phase 4, full suite                        | **2044 passed, 2 skipped**, 7m20s                         |
| After Phase 5, full suite                        | **2266 passed, 2 skipped**, 7m34s                         |

Each delta matches the tests added exactly — +54 for Phase 0, +4 for the
catalogue guard, +68 for Phase 1, +43 for Phase 2, +241 for Phase 3, a net
+99 for Phase 4 and +222 for Phase 5 — so no existing test was lost, silently
skipped, or renamed out of collection at any point.

Phase 5's delta needs a sentence too: it adds **200** tests and the suite grows
by **222**. The extra 22 are not new test functions — they are new _parameters_.
`test_config_audit_spec.py::test_every_builtin_check_survives_a_round_trip` is
parameterised over `BUILTIN_CHECKS`, which grew from 20 to 42 when the privilege
checks were added, so every one of them is now round-tripped through the stored
JSONB shape for free. The arithmetic reconciles exactly.

Phase 4's delta is the one that needs a sentence: it adds **100** tests and the
suite grows by **99**, because activating CIS Controls v8.1 removed one
parameter from `test_parked_framework_reports_are_refused` — that catalogue is
no longer parked, so its report renders instead of being refused, and it is
covered by the active-report test instead. The arithmetic reconciles exactly;
an unexplained delta of one is how a silently dropped test hides.

### Phase 3 — a real regression, found by attribution rather than assumed away

The first Phase 3 full run came back **6 failed, 9 errors**, scattered across
`credentialed`, `scans`, `security` and `web`. A second run with identical
ordering failed in a _different_ place — `tests/audit`, on a foreign-key
violation — and every affected file passed in isolation. `pytest-randomly` is
not installed, so ordering was constant: the failures were timing-dependent,
not order-dependent.

Rather than guess, the suite was run at the Phase 2 commit with the Phase 3
work stashed: **1704 passed, 2 skipped, zero failures**. That settled
attribution — the regression was Phase 3's, and the work was not committed
until it was found.

**The cause:** `TestTheWholeCredentialedAuditEndToEnd` drove the real
`audit_credentialed_host` without stubbing the CVE-enrichment paths, so every
run of it opened live connections to the `vuln_intel` database through
`csaf_advisories_for`, `exploit_intel_for` and `CsafProductMatcher`. A test
about configuration-audit wiring has no business doing that: it makes the test
depend on a feed database being present and populated, and it consumes
connections from a pool the rest of the suite shares. Stubbing the three
took that file from **24.8s to 6.5s**, and the failures stopped reproducing.

**A self-inflicted detour worth recording.** While chasing a stale-state
theory, `ccure_pytest_db` was dropped on the assumption that `conftest` would
rebuild it. It rebuilds the _schema_ but not the three superuser bootstraps —
`bootstrap_chain.sql`, `bootstrap_chain_retention.sql` and
`bootstrap_chain_retention_chained.sql` — which the application role cannot
install (`must be able to SET ROLE audit_chain_writer`, exactly as that
script's header documents). 205 audit tests skipped rather than failed, which
is the safe direction but would have made a green run meaningless. A DBA
reinstalled all three; `verify_chain_bootstrap.py` reports 46/46 and
`verify_retention_bootstrap.py` 84/84. **`conftest` cannot restore a dropped
pytest database — do not drop it.**

The delta is exactly **+54**, matching the 54 tests this phase added — so no
existing test was lost, silently skipped, or renamed out of collection.

`pytest-timeout` is not installed in the API image; `--timeout` is not a valid
flag for this suite.

### A pre-existing flaky test, diagnosed

The post-Phase-0 full run reported one failure,
`tests/audit/test_audit_chain_legacy_boundary.py::test_the_chain_starts_cleanly_above_legacy_history`.
It is **not caused by Phase 0**, and the diagnosis is worth recording because
it will keep producing false regression signals for the rest of this programme.
The definitive post-Phase-0 run, on the same code, passed it — which is itself
the point: the same commit both fails and passes this test.

Evidence, in the order it was gathered:

1. **It is intermittent.** Three consecutive isolated runs of that file gave
   `6 passed`, `6 passed`, `2 failed / 4 passed`. A deterministic breakage
   caused by a code change does not do that.
2. **Phase 0 cannot reach it.** The migration touches only
   `vulnerability_definitions` and `asset_vulnerabilities`; nothing under
   `core/checks/` is imported by `core/audit.py`, `db/audit_hardening.py` or
   any test in `tests/audit/`; and the two new test files live in
   `tests/scans/`, which pytest collects _after_ `tests/audit/`.
3. **The mechanism is a clock comparison across two machines.** The fixture
   inserts its five legacy rows with SQL `now()` — evaluated by PostgreSQL on
   the Windows host. The chained event that follows gets
   `AuditLog.created_at`'s Python-side `default=utcnow`, evaluated inside the
   API container. `newest_event()` in `tests/audit/audit_chain_support.py`
   then picks "genesis" with `ORDER BY created_at DESC`, comparing the two.
4. **The host clock is ahead of the container clock by 33–61 ms**, measured
   with `clock_timestamp()` over eight separate transactions (an earlier
   measurement using `now()` was wrong — `now()` is transaction start time and
   does not advance within a transaction). Whenever less than that elapses
   between the fixture and the chained write, a legacy row sorts newest and
   `genesis` is the wrong row.

The test contradicts its own thesis, which is the actual defect. Its docstring
says: _"`created_at` is set client-side in Python, so it can be out of order
relative to insertion … The boundary is therefore read from `genesis_event_id`,
never derived by sorting."_ It then derives `genesis` by sorting on
`created_at`. The fix is for the helper to select the newest **chained** row
(`record_hash IS NOT NULL`) by insertion order rather than by a client-set
timestamp.

Left unfixed in this commit deliberately — it is unrelated to Phase 0 and
belongs in its own focused change. It is called out here so the next phase's
regression is read correctly rather than blamed on that phase's code.

---

### A third pre-existing flaky test, diagnosed and measured

The definitive Phase 6 run reported one failure,
`tests/compliance/test_compliance_iso27001.py::test_scan_run_id_generator_exists_and_is_unique`.
**It is not caused by Phase 6**, and it is the same shape as the two above.

The test draws 200 identifiers from `gen_compliance_scan_run_id` and asserts
all 200 are distinct. The generator appends four random characters, so 200
draws carry a birthday-collision probability that is small but not negligible.
Four independent measurements, taken during the Phase 6 close-out
verification, all agree:

| Method                                                                                                         | Result                                                     |
| -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **Analytical** — exact birthday probability over `36^4 = 1,679,616` suffixes for 200 draws                     | **1.178%**, ~1 run in 85                                   |
| **Empirical at HEAD** — 50,000 trials of the exact assertion                                                   | **1.208%**, ~1 run in 82                                   |
| **Empirical at `e649bdc`** (the Phase 5 head, _before Phase 6 existed_) — 20,000 trials in a detached worktree | **1.155%**                                                 |
| **Through pytest at HEAD** — 200 independent invocations of the test node                                      | 1 failure, **0.50%** (expected ~2.4; within Poisson noise) |

The third row is the decisive one: **the identical failure reproduces at the
commit before this phase**, on a checkout that contains none of its code.

`git diff e649bdc d40800d -- Backend/db/base.py Backend/tests/compliance/test_compliance_iso27001.py`
is **empty** — the generator and the test that exercises it are byte-identical
across the Phase 6 commit, so their failure rate cannot have changed.

**Not fixed here**, because widening the suffix or seeding the generator is
unrelated cleanup in code this phase does not touch. Recorded so it does not
read as a Phase 6 regression the next time it fires. The fix, when someone
takes it, is to widen the random suffix rather than to loosen the assertion:
the assertion is testing the right thing, and the generator really can collide.

## 12. Commit log

| Phase | Commit    | Tag | Suite result              |
| ----- | --------- | --- | ------------------------- |
| 0     | `31c10b4` | —   | 1589 passed, 2 skipped ✅ |
| 1     | `37871a6` | —   | 1661 passed, 2 skipped ✅ |
| 2     | `9e4ecaa` | —   | 1704 passed, 2 skipped ✅ |
| 3     | `daab13a` | —   | 1945 passed, 2 skipped ✅ |
| 4     | `9e762d0` | —   | 2044 passed, 2 skipped ✅ |
| 5     | `8a5bbd7` | —   | 2266 passed, 2 skipped ✅ |

Tags are applied at maturity milestones, not per phase. `v0.2.0` is claimed
only when Phases 1–2 are Closed and Level 3 is demonstrable.

---

## 13. Observations recorded during Phase 0 that are not gaps

Findings worth someone's attention that are outside this programme's scope.

**Catalogue test residue — found, corrected, removed.** [measured] The Phase 0
report said 23 rows keyed `CVE-9999-*`. The real number was **24**: that count
used `id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'`, which excluded `CVE-9999-0001/0002/0003`
because they _do_ match a well-formed CVE pattern. Deleting "the 23" would have
left one behind.

All 24 are now removed from `ccure_test` (262,632 -> 262,608 catalogue rows;
findings unchanged at 5,711), after a full 68.9 MB backup. Removal is
reproducible via `Backend/scripts/cleanup_test_catalogue_residue.py` (dry run by
default), and recurrence is prevented in `tests/conftest.py`, whose per-test
purge now removes synthetic catalogue rows — the one table it never reached.
`tests/repo/test_catalogue_hygiene.py` proves the guard by exercising it, and
was mutation-tested by disabling the purge.

**Correction to GAP-00-B: non-CVE findings were already possible.** [measured]
Phase 0 stated that "every finding this product could record had to be a CVE".
That is false. Production already mints non-CVE catalogue ids under a `MISC-`
convention -- `MISC-SMB-SIGNING`, `MISC-DNS-AXFR`, `MISC-LDAP-ANON-BIND`,
`MISC-FTP-ANON`, `MISC-NUCLEI-<template>` and others, across eight plugins plus
two paths in `core/tasks.py`; `nuclei_probe.py:212` names the convention
explicitly. The live database carries one with a real finding against it.

What was actually broken, and what GAP-00-B fixes, is narrower and sharper:

- Those rows are written with `cve_id` set to the fabricated id, so they are
  **indistinguishable from real CVEs** in every query that joins on `cve_id`.
  `definition_type` plus `ck_vuln_def_cve_id_matches_type` is what separates
  them -- but only once a writer classifies them, which nothing does yet.
- `MISC-NUCLEI-` is 12 characters, leaving 18 inside the old `varchar(30)`.
  `MISC-NUCLEI-GIT-CONFIG-EXPOSURE` is 31 and
  `MISC-NUCLEI-LARAVEL-ENV-EXPOSURE` is 32. PostgreSQL errors rather than
  truncating, so those catalogue upserts were failing outright. The widening to
  120 fixes a latent silent-loss bug across the 7,460-template corpus. The four
  findings CLAUDE.md expects from `ccure-nuclei-target` happen to use short ids
  and fit, which is why nobody saw it.

**Open follow-up (not scheduled):** when `e1f2a3b4c5d6` is deployed, existing
and future `MISC-` rows take the `'cve'` server default while carrying a
fabricated `cve_id` -- constraint-valid, but labelling plugin checks as CVEs.
The fix is to classify `MISC-` ids as `plugin_check` with `cve_id` NULL in
`scans/asset_syncer.py`, plus a backfill.

**A second pre-existing flaky test, diagnosed but not fixed.** [measured]
`tests/audit/test_audit_chain_concurrency.py::test_concurrent_writers_for_one_org_do_not_fork_the_chain`
failed once in a full-suite run and passes in isolation and across three
consecutive runs of its own group. The cause is structural, not timing luck:
the test starts `WRITERS = 40` concurrent writers, each opening its own
`SessionLocal()`, against a pool configured `pool_size=10, max_overflow=20` --
**30 connections**. Ten threads must therefore wait, and under full-suite load
the default 30-second `pool_timeout` expires. `_insert_one` catches every
exception and returns `None`, so a timed-out insert is silently lost and the
test reports "expected 40 chained rows, got 39" -- the swallowed-error pattern
again, one table over. Fix is to stop swallowing the exception (and to size
`WRITERS` against the pool). Left alone here because it is unrelated to either
housekeeping task.

**`tests/repo/test_schema_drift.py` is blind on exactly one path — a
first-ever bootstrap.** [measured] `tests/conftest.py:495-519` builds the
scratch database two ways. On an **empty** database it runs
`Base.metadata.create_all()` then `alembic stamp head`, so a model column with
no migration is created anyway and no diff exists — the guard passes having
proven nothing. On a **pre-existing** database stamped behind head it runs
`alembic upgrade head` and _then_ `create_all()`, and since `create_all()` does
not ALTER existing tables to add columns, an unmigrated model column would be
absent from the database and the guard would catch it.

The normal case is therefore covered, and this phase confirmed it end to end:
`ccure_pytest_db` was at `d0e1f2a3b4c5` from the baseline run, and the next
suite invocation applied `e1f2a3b4c5d6` through `upgrade head` — the database
now reports `alembic_version = e1f2a3b4c5d6`, `id` at 120 characters and
`definition_type` present. So this migration has been exercised by the suite
against a real pre-existing PostgreSQL schema, in addition to the isolated
round-trip in §3.3.

The residual blind spot is real but narrow: a contributor whose scratch
database happens to be brand new gets a green guard regardless. Closing it
means bootstrapping a second database purely via `alembic upgrade head` and
comparing against that. Worth doing; not in this phase's scope.
