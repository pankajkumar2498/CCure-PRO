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

### A gap is not closed until its results are in the reports

**Mandatory for every phase from Phase 15 onward, and applied retrospectively
where a phase is revisited.** A capability that produces correct verdicts the
reports do not show is not delivered — the operator's evidence is the report,
not the database.

Closing a gap therefore means tracing, on a real target:

    backend check → evidence → finding / compliance result → risk & status
      → API and reporting data → generated PDF / HTML / UI

and confirming the control identifier, title, verdict, evidence, remediation,
severity, benchmark mapping and affected host all arrive intact — including
that an unsupported or unavailable check is represented as such and **not** as
a PASS or a FAIL. Where the backend is right and the reporting is not, the
reporting is fixed in the same phase rather than deferred, and a test is added
that proves a representative result reaches the report.

Phase 15 is the worked example: the backend produced correct Windows STIG
verdicts while the finding carried only the word "non_compliant", and the
evidence was never refreshed on re-detection. Both were reporting defects, both
were fixed in-phase, and §9N.6 records them.

---

## 2. Summary matrix

| Gap ID       | Capability                               | Domain         | Phase | Priority | Coverage before  | Target | Status                                                                            | Commit    |
| ------------ | ---------------------------------------- | -------------- | ----- | -------- | ---------------- | ------ | --------------------------------------------------------------------------------- | --------- |
| **GAP-00-A** | Common check/plugin framework            | Architecture   | 0     | Critical | 20% [measured]   | 90%    | **Closed**                                                                        | `31c10b4` |
| **GAP-00-B** | Finding model admits non-CVE findings    | Architecture   | 0     | Critical | 0% [measured]    | 100%   | **Closed**                                                                        | `31c10b4` |
| **GAP-00-C** | Generalized credential model             | Architecture   | 0     | High     | 25% [measured]   | 90%    | **Closed** (95% measured)                                                         | `9e4ecaa` |
| **GAP-01**   | Network & credentialed scan scheduling   | Orchestration  | 1     | Critical | 30% [measured]   | 95%    | **Closed**                                                                        | `37871a6` |
| **GAP-02**   | Native Windows credentialed scanning     | Credentialed   | 2, 12 | Critical | 40% [estimated]  | 90%    | **Closed** — WinRM (85%) + SMB/RemoteReg/WMI                                      | `9e4ecaa` |
| **GAP-03**   | Generic configuration audit engine       | Config audit   | 3     | Critical | 35% [measured]   | 90%    | **Closed** (90% measured)                                                         | `daab13a` |
| **GAP-04**   | CIS benchmark content                    | Config audit   | 4     | High     | 0% [measured]    | 70%    | **Partial** — capability built, content absent                                    | `9e762d0` |
| **GAP-05**   | DISA STIG / SCAP ingestion               | Config audit   | 10,15 | Medium   | 0% [measured]    | 60%    | **Closed** (63.5% reader; Windows OVAL 60%, 90.4% of the DISA Win11 STIG's rules) | `6b4c06e` |
| **GAP-06**   | Active vulnerability check expansion     | Network checks | 6     | High     | 25.8% [measured] | 65%    | **Closed** (69.4% measured, raised by Phase 11)                                   | `d40800d` |
| **GAP-07**   | Deep TLS/SSL assessment in main path     | TLS            | 11    | Medium   | 0% [measured]    | 90%    | **Closed** (71.4% measured, real-target validated)                                | `426c282` |
| **GAP-08**   | Local OS privilege & host exposure       | Credentialed   | 5     | High     | 0% [measured]    | 75%    | **Closed** (75.9% measured, real-target validated)                                | `8a5bbd7` |
| **GAP-09**   | Application/middleware config assessment | Config audit   | 8     | Medium   | ~3% [measured]   | 70%    | **Closed** (66.7% measured, real-target validated)                                | `7520e90` |
| **GAP-10**   | Database assessment                      | Database       | 7     | High     | 0% [measured]    | 70%    | **Closed** (74.2% measured, real-target validated)                                | `9d74a0c` |
| GAP-11       | Network device assessment                | Network device | 11    | Medium   | 15% [estimated]  | 65%    | Open                                                                              | —         |
| GAP-12       | Configurable scan policy engine          | Orchestration  | 12    | High     | 20% [measured]   | 85%    | Open                                                                              | —         |
| **GAP-13**   | Scan comparison & finding lifecycle      | Findings       | 16    | High     | 25% [measured]   | 90%    | **Partial** (71.4% measured, real-target validated)                               | `3b8ac56` |
| GAP-14       | Remediation & SLA management             | Remediation    | 14    | High     | 30% [measured]   | 85%    | Open                                                                              | —         |
| GAP-15       | Reporting & export expansion             | Reporting      | 15    | Medium   | 50% [measured]   | 85%    | Open                                                                              | —         |
| GAP-16       | Cloud security assessment                | Cloud          | 16    | Low      | 0% [measured]    | 60%    | Open                                                                              | —         |
| **GAP-17**   | Virtualization / container / Kubernetes  | Container      | 9     | Low      | ~4% [measured]   | 60%    | **Closed** (57.1% measured, real-target validated)                                | `13d6854` |
| GAP-18       | Distributed scanner / agent architecture | Architecture   | 18    | Low      | 10% [estimated]  | 60%    | Open                                                                              | —         |
| GAP-19       | Continuous security assessment           | Orchestration  | 19    | Low      | 10% [estimated]  | 70%    | Open                                                                              | —         |

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

  **Superseded, 30 Aug 2026.** `ccure_test` is at `c1d2e3f4a5b6`, the head of
  the chain, so both of those and everything after them are applied. See §9E.

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
- **The live database was at `d0e1f2a3b4c5` when Phase 6 shipped** — behind
  `e1f2a3b4c5d6` and everything after it, including that phase's migration.
  Recorded in §4.5 since Phase 1; the typed catalogue write needs
  `definition_type` to exist before it can run there.

  **Superseded, 30 Aug 2026.** `ccure_test` is at `c1d2e3f4a5b6` — head. It was
  measured at `b0c1d2e3f4a5` during the Phase 10 carry-forward audit and
  brought to head in the stabilization that followed. `definition_type`,
  `scan_schedules` and `scan_schedule_runs` are all present, so the limitation
  this line records no longer holds. The original is kept because §1 says a
  contradicted measurement is recorded rather than quietly reconciled.

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

## 9A. Phase 7 — Authenticated database assessment

Closes **GAP-10**. Commit `9d74a0c`.

### 9A.1 The gap, measured before touching anything

The denominator was frozen in `Backend/scripts/measure_database_coverage.py`
before a line of the phase was written, and it contains **eight areas this
phase did not set out to implement**, each with a recorded reason. A coverage
figure that cannot go down is not a measurement.

| Figure                                       | Value             |
| -------------------------------------------- | ----------------- |
| Authenticated database assessment, before    | **0 / 31 = 0.0%** |
| Database configuration checks in the product | **0**             |
| Database transports                          | **0**             |
| `database_query` collectors                  | **0**             |
| Automated tests naming database assessment   | **0**             |

**The matrix said 5% [measured] and that figure was misattributed.** [measured]
It was counting the _unauthenticated_ view of a database service — port and
version detection on 1433/1521/3306/5432, the CPE→CVE match on a detected
banner, and the no-authentication checks for Redis, MongoDB and Memcached. All
of that exists, all of it works, and all of it is already counted in **GAP-06**,
whose own frozen denominator names "database service assessment — GAP-10, not
this phase" as the boundary. Counting it twice is how a programme's numbers
stop meaning anything, so GAP-10's denominator covers authenticated assessment
only and starts at zero.

### 9A.2 What was reused rather than rebuilt

Nothing in the assessment pipeline is new. The phase adds a transport and
content, and both plug into machinery Phases 0–4 already built:

- **`ConfigAuditEngine`** — unchanged. A database check is an ordinary
  `ConfigCheck`; the four collection states, `AbsencePolicy`, the operator
  vocabulary and the outcome table all apply as written.
- **`CollectionContext.scope`** — Phase 3 wrote its docstring as "resolved
  against a sub-target (**a database instance**, a virtual host)". This is the
  phase that reservation was for.
- **`os_match`** — Phase 4's OS targeting, written for "CIS Ubuntu 22.04 versus
  CIS RHEL 9", applies unchanged to "PostgreSQL 16 versus MySQL 8". The
  instance's product string becomes `os_name` and its version `os_version_id`.
  **No second targeting mechanism was added**, which was the main design goal.
- **`compliance_credentials`** — `credential_type = 'database'` has been
  reserved since Phase 2, and `compliance_rules` has admitted `database_query`
  and `target_platform = 'database'` since Phase 3's `b4c5d6e7f8a9`. So the
  entire persistence cost of GAP-10 is **one CHECK constraint** on
  `transport`.
- **The finding path** — `CCURE-CFG-…` through `StandardizedFinding`, the
  normalizer, risk, remediation and both PDFs. No second finding model.
- **The dispatch path** — `POST /scan/credentialed` and
  `core/scheduling/dispatcher.py` are **unchanged**. A schedule stores a
  credential reference, the credential carries its type, and
  `run_credentialed_scan_task` branches on it. Scheduling a recurring database
  audit therefore works today with no new route, no new task and no new
  dispatcher branch.

### 9A.3 What was built

| Component                                                          | What it is                                                       |
| ------------------------------------------------------------------ | ---------------------------------------------------------------- |
| `engines/credentialed/database_executor.py`                        | The transport: sessions, read-only enforcement, four error types |
| `core/config_audit/collectors/database.py`                         | The `database_query` collector — three result shapes             |
| `core/config_audit/builtin/database_postgresql.py`                 | 21 checks                                                        |
| `core/config_audit/builtin/database_mysql.py`                      | 15 checks                                                        |
| `core/config_audit/builtin/database_mssql.py`                      | 13 checks                                                        |
| `core/tasks.audit_database_target`                                 | The per-instance audit, sibling of `audit_credentialed_host`     |
| `alembic/versions/f8a9b0c1d2e3_…`                                  | Five transport values on one CHECK constraint                    |
| `scripts/measure_database_coverage.py`                             | The frozen denominator                                           |
| `tests/scans/test_database_{transport,collector,content,areas}.py` | 652 tests                                                        |

**49 checks across three engines.** PostgreSQL, MySQL/MariaDB and Microsoft SQL
Server. Oracle and MongoDB are reserved in the transport vocabulary and
implemented by nothing — see §9A.7.

### 9A.4 Read-only is enforced, not intended

Rules are administrator-editable, so the SQL in a rule is an injection boundary
_inside the product_ — the same position Phase 3 took on `ps_quote` and
`shlex.quote`. Three layers, and `tests/scans/test_database_content.py` asserts
that **every one of the 49 shipped rules** passes the guard:

1. `assert_read_only` admits only a single statement beginning SELECT, SHOW,
   WITH or VALUES, with comments and string literals stripped first so a
   literal `'delete'` is data and a `-- ; DROP` comment is not a statement.
2. Rule-supplied values are bound parameters. A rule handing over anything but
   a sequence is refused rather than interpolated.
3. The session itself is opened read-only where the engine can express it —
   `set_session(readonly=True)`, `SET SESSION TRANSACTION READ ONLY`,
   pymssql's `read_only=True`.

A refused statement is **UNAVAILABLE → ERROR**, never a verdict. A defect in a
rule must not manufacture a finding about a customer's database.

### 9A.5 Six defects found by pointing it at real databases

Every one would have shipped looking correct, and four of them produce a
_confidently wrong_ result rather than an obvious failure.

- **Engine targeting was inert on MySQL.** `SELECT version()` returns
  `PostgreSQL 16.15 on x86_64…` on PostgreSQL but a bare `8.0.46` on MySQL, so
  `os_name_contains: ["mysql"]` matched nothing and **all 15 MySQL rules
  reported NOT_APPLICABLE** — a complete rule set that silently never ran. On
  PostgreSQL alone it looked perfect. `DatabaseSession.product_name` now always
  names the engine, and labels MariaDB separately so a "MySQL 8.0 or later"
  rule cannot read MariaDB 10.11 as ancient.

- **`PGSSLROOTCERT` from `Backend/.env` was applied to every scan target.**
  The variable exists for the application's own database and points at this
  deployment's private CA. Loading config puts it in the environment, and libpq
  applies it to any connection that does not set it — so every PostgreSQL
  _target_ was verified against our CA and failed with "certificate verify
  failed", which reads as a fault on the target. The asymmetry that hid it:
  passing `sslmode` explicitly _does_ override `PGSSLMODE`, so the mode was
  right and only the trust anchor was wrong, and under `prefer` libpq still
  verifies once a root certificate is configured. `sslrootcert` is now passed
  explicitly on every connection.

- **A failed statement on a healthy session was reported as an unreachable
  database.** The classifier's fallback was `DatabaseConnectionError`, so a
  catalogue view absent from an engine version produced "nothing answered …
  confirm the instance is listening" while the scanner held an open connection
  to it. Classification now takes a `context`, and only a _positive_
  connectivity match becomes a transport error.

- **PostgreSQL's `no pg_hba.conf entry` was classified as a connection
  failure.** The instance answered and declined; calling it unreachable sends
  the reader to the firewall for a server that is listening and deliberately
  refusing. It is an authentication refusal.

- **MySQL's `validate_password` check was a false positive on hardened
  servers.** It read `information_schema.plugins`, but MySQL 8 installs
  `validate_password` as a **component** in `mysql.component`. Measured against an
  instance whose policy had, minutes earlier, rejected a generated password for
  not meeting it. The query now covers both forms.

- **`secure_file_priv` inverted its own verdict.** `not_empty` treats SQL NULL
  as empty, and NULL is the _most hardened_ state — server-side file access
  disabled outright. So a locked-down instance and a completely unrestricted
  one (`''`) both failed identically. NULL is folded to a token first.

### 9A.6 Five universal false positives caught before they shipped

Each was a stock default on an untouched instance. A check that fires on every
host is worse than one that misses, because the reader stops looking.

| Would have reported                            | Reality                                                                   |
| ---------------------------------------------- | ------------------------------------------------------------------------- |
| PUBLIC holds CONNECT on `postgres`/`template0` | The default on every PostgreSQL installation                              |
| `trust` on `local` and `127.0.0.1`             | The postgres image default; how `docker exec psql` works                  |
| `guest` holds CONNECT in SQL Server            | Mandatory in `master`; cannot be revoked there                            |
| `BUILTIN\*`, `NT AUTHORITY\*` are sysadmin     | Provisioned by SQL Server itself — two findings on an untouched container |
| `VIEW ANY DATABASE` granted to `public`        | A default grant on every instance                                         |

Three PostgreSQL rules also read `pg_hba_file_rules` with overlapping
predicates, so one permissive line produced three findings and made the
remediation look three times larger than it was. They are now orthogonal: one
asks whether plaintext is admitted, one asks what the server binds to, and the
third was dropped.

`information_schema.user_privileges` returning **132 `is_grantable` rows on a
stock MySQL**, all of them root's, is the measurement behind
`db.priv.grant_option` being excluded from the denominator rather than
implemented badly.

### 9A.7 Real-target validation — three engines, both directions

Disposable containers only, destroyed afterwards. Credentials generated at run
time; none in source, configuration, logs, Celery arguments or git.

| Engine                    | Weakened        | Hardened | Checks proven to fail |
| ------------------------- | --------------- | -------- | --------------------- |
| PostgreSQL 16.15          | **12** findings | **0**    | 20 / 21               |
| MySQL 8.0.46              | **11** findings | **0**    | 13 / 15               |
| Microsoft SQL Server 2022 | **12** findings | **0**    | 12 / 13               |

Both directions matter and the hardened run is the one that catches false
positives — it is what found the `validate_password` and `listen_addresses`
defects above.

**Cross-engine isolation is proven by the same runs.** Scanning MySQL selected
49 checks and reported 34 NOT_APPLICABLE; scanning SQL Server reported 36. A
PostgreSQL catalogue read is never dispatched at another product.

**Degradation under an unprivileged credential was measured, not assumed.**
Against PostgreSQL with a `LOGIN`-only role, `pg_authid` and
`pg_hba_file_rules` returned "permission denied" → UNAVAILABLE → **ERROR**,
while `pg_settings` and `pg_roles` still answered. A low-privilege scan
produces a partial audit that says which parts it could not perform — never a
pass, and never "no offending accounts".

Six checks could not be exercised in the failing direction and are recorded as
such rather than counted:
`ccure.db.postgresql.untrusted_languages` (needs plpython, absent from the
alpine image), the three `version_supported` rules (need an end-of-life
release), `ccure.db.mysql.have_ssl` and `ccure.db.mysql.tls_version` (MySQL 8
generates certificates automatically and has removed TLS 1.0/1.1 entirely).
All six are exercised in both directions by
`tests/scans/test_database_areas.py` against the real engine.

### 9A.8 Coverage — measured, denominator frozen at Stage 1

| Capability                 | Before        | After                | Basis                                           |
| -------------------------- | ------------- | -------------------- | ----------------------------------------------- |
| GAP-10 database assessment | 0% [measured] | **74.2%** [measured] | 23 of 31 frozen areas, implemented _and_ tested |

| Theme         | Proven      |
| ------------- | ----------- |
| auth          | 6/7 (85.7%) |
| privilege     | 5/6 (83.3%) |
| encryption    | 3/5 (60.0%) |
| audit         | 4/5 (80.0%) |
| configuration | 5/8 (62.5%) |

**Engine breadth is reported separately and never folded into the headline.**
An area answered on one engine is implemented; saying so on three does not make
it three areas. PostgreSQL answers 15 areas, MySQL 12, SQL Server 11.

The eight unimplemented areas, each with its reason in `NOT_PLANNED`:
`db.auth.lockout`, `db.priv.grant_option`, `db.tls.cipher_strength`,
`db.crypto.at_rest`, `db.audit.log_permissions`, `db.conf.error_verbosity`,
`db.conf.data_dir_permissions`, `db.conf.backup_configured`.

### 9A.9 Known limitations

- **Oracle and MongoDB are not implemented.** Drivers exist for both
  (`oracledb` thin mode, `pymongo`) and the transport vocabulary reserves them,
  but neither could be stood up as a disposable target here — Oracle needs a
  vendor registry account — so neither was validated and neither ships.
  `USABLE_TRANSPORTS` stops the API creating such a credential.
- **`BUILTIN\Administrators` in sysadmin is not reported.** Excluded because it
  is provisioned on the SQL Server container, which is the only instance this
  phase could validate against. On a Windows deployment it is a genuine
  hardening item, and this build will not report it.
- **SQL Server `guest` access is not assessed.** Correct assessment needs a
  per-user-database sweep, which cannot be expressed as one read-only
  statement.
- **SQL Server login auditing is not read.** The conventional route is
  `EXEC xp_instance_regread`, and widening the read-only guard for one setting
  is worth less than the guard.
- **The audit assesses the instance, not its host.** `coverage.scope` says so
  in words on every database report. Auditing the operating system underneath
  needs a _host_ credential and is GAP-03's existing path.
- **A database target is deliberately excluded from the asset registry sync.**
  Both sync helpers are host-shaped; letting a database audit through would
  overwrite the asset record of the machine hosting it with an audit that never
  looked at the machine.
- **Version-currency boundaries have a shelf life.** PostgreSQL 14, MySQL 8.0
  and SQL Server 2017 were the oldest supported releases as at 29 August 2026.
  Each rule states the date and links the vendor's lifecycle page.
- **The UI can only create a PostgreSQL credential.** `ScanCredentials.jsx`
  renders whatever `/credentials/types` returns, so "Database" appears as a
  selectable type and produces a working credential — but it uses the type's
  defaults, which are PostgreSQL on 5432, and there is no control for choosing
  the engine. The `engines` list the endpoint returns for exactly that purpose
  is currently ignored by the frontend. MySQL and SQL Server credentials must
  be created through the API until that control exists. This is the one
  Definition-of-Done line that is not met.

### 9A.10 Definition of Done — Phase 7

| Line                   | GAP-10                                                         |
| ---------------------- | -------------------------------------------------------------- |
| Backend implemented    | ✅ transport, collector, 49 checks, dispatch                   |
| Scanner integration    | ✅ runs inside the credentialed scan task                      |
| Database migration     | ✅ `f8a9b0c1d2e3`, downgrade refuses safely and names the rows |
| API                    | ✅ credential type unlocked; no new route needed               |
| UI                     | ❌ **not done** — credential and scan composition are API-only |
| Finding integration    | ✅ `CCURE-CFG-…`, same `cve_list`, no second model             |
| Evidence               | ✅ expected, observed, the statement, and the rows it returned |
| Risk                   | ✅ existing canonical severity scale                           |
| Remediation            | ✅ `CONFIGURATION_GUIDANCE`, asserted present on every rule    |
| Compliance result      | ✅ through the Phase 3 verdict path                            |
| Reporting              | ✅ executive and technical PDFs, unchanged                     |
| Scheduling             | ✅ works through the existing credentialed schedule kind       |
| Unit / integration     | ✅ 652 tests                                                   |
| Regression suite       | ✅ see §11                                                     |
| Real-target validation | ✅ **three engines, both directions**                          |
| Coverage measured      | ✅ 0% → 74.2%, denominator frozen before implementation        |
| Docs                   | ✅ CLAUDE.md, this section                                     |
| Commit                 | ✅                                                             |

---

## 9B. Phase 8 — Application and middleware configuration assessment

Closes **GAP-09**. Commit `7520e90`.

### 9B.1 The gap, measured before touching anything

The denominator was frozen in `Backend/scripts/measure_middleware_coverage.py`
before a line of the phase was written, and it contains **twelve areas this
phase did not set out to implement**, six of them IIS.

| Figure                                               | Value             |
| ---------------------------------------------------- | ----------------- |
| Middleware configuration assessment, before          | **0 / 36 = 0.0%** |
| Middleware configuration rules in the product        | **0**             |
| Check types able to read a nested or structured file | **0**             |
| Automated tests naming middleware assessment         | **0**             |

**The matrix said 5% [estimated]; the honest before-figure is ~3%.** [measured]
The only thing that existed was the ability to detect that the middleware is
_installed_ — the Phase 3 `package` and `service` collectors. Everything else
the matrix might have been counting is the unauthenticated web surface, which
belongs to **GAP-06**: missing security headers, dangerous HTTP methods,
directory listing observed over the wire, version disclosure in a banner,
insecure cookie flags and TLS endpoint assessment are all implemented and
validated there. `test_no_rule_duplicates_a_check_gap06_already_makes` enforces
the boundary in code.

### 9B.2 The measurement that changed the plan

The GAP-09 proposal called this "content only, lowest complexity". Reading the
collector before starting showed that was wrong, and the correction is the
phase's main engineering:

**`config_file` reads one directive out of a flat `key<separator>value` file.**
It has no notion of nested scope, and all four products keep their settings
inside a structure — nginx in `{ }` blocks, Apache in `<Directory>` containers,
Tomcat in XML attributes, the Docker daemon in JSON. There was **no XML or JSON
reading anywhere in `core/config_audit/`**.

So a flat reader does not merely miss these. `AllowOverride None` under
`<Directory />` and under a document root are different statements about
different parts of the filesystem, and a reader that cannot say which one it
found returns whichever it saw last — confidently.

### 9B.3 What was reused rather than rebuilt

- **`ConfigAuditEngine`** — unchanged. A middleware check is an ordinary
  `ConfigCheck`; the four collection states, `AbsencePolicy`, the operator
  vocabulary and the outcome table all apply as written.
- **The credentialed host audit** — unchanged. These run at
  `platform = linux|windows` inside `_run_configuration_audit`, alongside the
  OS hardening rules. A web server's configuration is part of the host's
  posture, not a separate scan, so there is **no new scan kind, no new route
  and no new task**.
- **The `permission` and `directory` check types** — reused as-is for
  configuration file modes and for "is this bundled application deployed".
  Reaching for the new collector because the phase added one would have been
  the wrong instinct.
- **The finding path** — `CCURE-CFG-…` through `StandardizedFinding`, risk,
  remediation and both PDFs. No second finding model.
- **The sentinel protocol** — `CCURE::VALUE::` / `CCURE::ABSENT::` and
  `_parse_sentinel`, so the new collector inherits the Phase 3 discipline about
  output that carries no sentinel.

### 9B.4 What was built

| Component                                                          | What it is                                        |
| ------------------------------------------------------------------ | ------------------------------------------------- |
| `core/config_audit/structured.py`                                  | The parsers: nginx, Apache, XPath, JSON pointer   |
| `core/config_audit/collectors/middleware.py`                       | The `structured_config` collector, both platforms |
| `core/config_audit/builtin/middleware_nginx.py`                    | 10 checks                                         |
| `core/config_audit/builtin/middleware_apache.py`                   | 8 checks                                          |
| `core/config_audit/builtin/middleware_tomcat.py`                   | 9 checks                                          |
| `core/config_audit/builtin/middleware_docker.py`                   | 9 checks                                          |
| `core/config_audit/builtin/middleware_common.py`                   | 4 configuration-file permission checks            |
| `alembic/versions/a9b0c1d2e3f4_…`                                  | One value on one CHECK constraint                 |
| `scripts/measure_middleware_coverage.py`                           | The frozen denominator                            |
| `tests/scans/test_middleware_{parsers,collector,content,areas}.py` | 200 tests                                         |

**One check type for four formats.** `format` is a parameter. From the engine's
point of view the four are one shape — name a file and an address, get back
COLLECTED, ABSENT or UNAVAILABLE — and four types would have meant four
CHECK-constraint values on a table holding customer rules for a distinction the
engine cannot act on.

### 9B.5 Two states this phase had to get right

**A missing configuration file is UNSUPPORTED, not ABSENT.** A Linux host that
does not run Apache is not _failing_ Apache's hardening rules; the check was
never in scope for it. Getting this wrong hands every host in the estate a pile
of findings about software it does not have, which is how a configuration
report gets ignored wholesale. `test_configuration_rules_leave_the_score_on_a_
host_without_the_product` pins it.

**Except for the Docker daemon, where a missing file is a reading.** Most
Docker installations have no `daemon.json` at all — the dind image ships
without one and so do the distribution packages — and that means every setting
is at its built-in default. Those defaults are a mixture, so each rule declares
what its own absence means: no `hosts` entry is the secure state (PASS), no
`icc` entry means inter-container traffic is _on_ (MANUAL_REVIEW, because
failing it would fire on every Docker host in the estate). `missing_file:
absent` is set on those rules and nowhere else.

**An unresolved include poisons an absence.** Both nginx and Apache put the
interesting settings in _included_ files by default, so a directive missing
from the file the rule names may simply be somewhere the collector did not
look. When expansion is incomplete the absence is reported UNAVAILABLE, and
only a _found_ value is trusted.

### 9B.6 Six defects found by pointing it at real containers

Four of them silently produce a wrong answer rather than an obvious failure.

- **Included files lost their enclosing scope.** nginx ships its `server`
  blocks in `conf.d/*.conf`, included from inside `http`. Parsed on their own
  they scope as `server`, so every rule about `http > server` found nothing and
  reported it as not configured. `rescope()` grafts a child onto the branch its
  `include` sat on.

- **Apache resolves a relative `Include` against `ServerRoot`, not against the
  config file's directory.** Assuming the latter turned
  `Include conf/extra/proxy-html.conf` into `…/conf/conf/extra/…`, which does
  not exist, which left the include unexpanded, which downgraded **every absent
  directive in the file** from a verdict to "could not assess". The collector
  reads `ServerRoot` out of the configuration itself.

- **A default XML namespace made every Tomcat selection return nothing.**
  Tomcat 10 declares `xmlns="http://tomcat.apache.org/xml"` on
  `tomcat-users.xml`, and ElementTree then requires the URI in the path — a
  plain `.//user` matches nothing at all. Nothing about that looks like a
  failure: the parse succeeds, the selection is empty, the collector reports
  ABSENT, and the rule's `AbsencePolicy.PASS` **declares the server clean**.
  A namespace declaration produced a false negative on a real container.

- **`not_contains` on a list is membership, not substring.** The Tomcat
  Server-header rule compared `["apache-coyote"]` against
  `['Apache-Coyote/1.1']`, found no equal element, and passed — a server
  advertising itself, reported clean. The rule uses the scalar path and a
  regex now.

- **An include glob that resolved to nothing was silently dropped.** If the
  directory could not be listed, `_resolve` returned an empty list and the
  include was never recorded as unresolved, so the absence was trusted against
  files that were never read. `_list_directory` now distinguishes "empty
  directory" from "could not list", which are different facts.

- **ElementTree expands internal entities**, contrary to what this module's
  first docstring asserted. Measured: a ten-line document expands in the
  interpreter. The XML parsed here comes off a target being audited, so an
  entity bomb in a `server.xml` is a denial-of-service route into the scanner.
  Any DOCTYPE is now refused before the parser sees it — no new dependency, and
  no configuration file this phase reads carries a DTD.

### 9B.7 Two false positives avoided by reading the stock files first

- **`User` is not a top-level Apache directive.** The stock layout puts `User`
  and `Group` inside `<IfModule unixd_module>`. A rule asserting them at the
  top level reports ABSENT on an entirely normal server. The shipped rule
  matches at any depth.

- **A directive missing from a config file means the compiled-in default**, and
  those differ between builds and distributions. Following the Phase 3
  precedent for `sshd_config`, those rules are MANUAL_REVIEW — and
  `test_a_rule_that_defers_on_absence_says_what_the_default_is` requires each
  one to name the vendor default in its description, so the reviewer settles it
  in one step instead of going to look it up.

### 9B.8 Real-target validation — four products, both directions

Disposable containers only, destroyed afterwards.

| Product          | Weakened        | Hardened | Checks proven to fail |
| ---------------- | --------------- | -------- | --------------------- |
| nginx 1.27       | **11** findings | **0**    | 11 / 11               |
| Apache httpd 2.4 | **8** findings  | **0**    | 8 / 9                 |
| Tomcat 10.1      | **10** findings | **0**    | 10 / 10               |
| Docker 27 (dind) | **10** findings | **0**    | 10 / 10               |

Apache's `config_permissions` check is the one not exercised on a real target:
it reads `/etc/apache2/apache2.conf` and the official image uses
`/usr/local/apache2/conf/`, so it reported NOT_APPLICABLE — which is the
correct behaviour for a differently packaged install. The identical rule shape
is validated on nginx, Tomcat and Docker.

**The mixed-estate property was validated too**, and it is what makes this rule
set usable: pointed at a container running none of the four products, every
configuration rule reports NOT_APPLICABLE and **no rule produces a finding**.

### 9B.9 Coverage — measured, denominator frozen at Stage 1

| Capability                      | Before         | After                | Basis                                           |
| ------------------------------- | -------------- | -------------------- | ----------------------------------------------- |
| GAP-09 middleware configuration | ~3% [measured] | **66.7%** [measured] | 24 of 36 frozen areas, implemented _and_ tested |

| Theme      | Proven       |
| ---------- | ------------ |
| disclosure | 3/4 (75.0%)  |
| access     | 3/4 (75.0%)  |
| process    | 3/4 (75.0%)  |
| tls        | 4/5 (80.0%)  |
| logging    | 4/4 (100.0%) |
| limits     | 3/4 (75.0%)  |
| exposure   | 4/4 (100.0%) |
| currency   | 0/1 (0.0%)   |
| iis        | 0/6 (0.0%)   |

**66.7% is the ceiling this denominator allows**, because twelve areas are
declared and not implemented. That is the point of freezing it first.

Product breadth is reported separately and never folded into the headline:
nginx answers 11 areas, Apache 9, Docker 9, Tomcat 7.

### 9B.10 Known limitations

- **IIS is not implemented** — six areas, declared in the denominator and left
  unbuilt because there is no Windows Server target here to validate against.
  This programme does not ship an engine it has not validated.
- **Include expansion is one level deep.** It covers every default layout these
  products ship; an include inside an included file is recorded as unresolved,
  which downgrades an absence to UNAVAILABLE rather than answering from a
  partial read.
- **The four "is this bundled Tomcat application deployed" rules pass
  vacuously on a host with no Tomcat.** A directory that is not there looks the
  same whether Tomcat is installed without the manager application or not
  installed at all. Making absence NOT_APPLICABLE would discard the genuine
  pass on a real Tomcat host that has correctly removed them, which is the
  verdict most worth having. Asserted, so it stays visible.
- **The `permission` rules take one path**, unlike the structured rules which
  take a candidate list, so they miss differently packaged installs.
- **A server with several nginx `server` blocks or Tomcat `Connector`
  elements is judged on the last one** for scalar rules.
- **`mw.version.supported_release` is unimplemented**: no middleware here
  publishes its version through its configuration file. Reading it needs the
  package collector (GAP-03's path) or the network banner (GAP-06's).
- **No UI.** These rules run inside the existing credentialed scan and appear
  in the existing reports; nothing in the frontend distinguishes a middleware
  finding from an OS hardening one.

### 9B.11 Definition of Done — Phase 8

| Line                   | GAP-09                                                           |
| ---------------------- | ---------------------------------------------------------------- |
| Backend implemented    | ✅ parsers, collector, 40 checks                                 |
| Scanner integration    | ✅ runs inside the existing credentialed host audit              |
| Database migration     | ✅ `a9b0c1d2e3f4`, downgrade refuses safely and names the rules  |
| API                    | ➖ none required; no new route or scan kind                      |
| UI                     | ❌ **not done** — findings render as ordinary configuration ones |
| Finding integration    | ✅ `CCURE-CFG-…`, same `cve_list`, no second model               |
| Evidence               | ✅ expected, observed, the file, the block path, includes read   |
| Risk                   | ✅ existing canonical severity scale                             |
| Remediation            | ✅ asserted present on every rule                                |
| Reporting              | ✅ executive and technical PDFs, unchanged                       |
| Unit / integration     | ✅ 200 tests                                                     |
| Regression suite       | ✅ see §11                                                       |
| Real-target validation | ✅ **four products, both directions**                            |
| Coverage measured      | ✅ ~3% → 66.7%, denominator frozen before implementation         |
| IIS                    | ❌ **declared, not implemented** — no Windows Server target      |
| Docs                   | ✅ CLAUDE.md, this section                                       |
| Commit                 | ✅                                                               |

---

## 9C. Phase 9 — Container and Kubernetes configuration assessment

Closes **GAP-17**. Commit `13d6854`.

### 9C.1 The gap, measured before touching anything

The denominator was frozen in `Backend/scripts/measure_container_coverage.py`
before a line of the phase was written, and it contains **eighteen areas this
phase did not set out to implement**, each with a recorded reason.

| Figure                                      | Value             |
| ------------------------------------------- | ----------------- |
| Container / Kubernetes assessment, before   | **0 / 42 = 0.0%** |
| Container runtime checks in the product     | **0**             |
| Kubernetes checks in the product            | **0**             |
| YAML or TOML reading anywhere in the engine | **0**             |
| Automated tests naming container assessment | **0**             |

**The Docker daemon configuration is not counted here, and that is the most
important line in this section.** [measured] GAP-09 built and validated ten
checks over `daemon.json` — the TCP socket, `icc`, `userns-remap`, insecure
registries, the log driver. Counting them again would have inflated GAP-17 by a
quarter before any work started. `test_the_docker_daemon_checks_stay_with_gap09`
and `test_no_container_rule_reads_daemon_json` enforce the boundary in code.

So the honest before-figure is **~4%**: the residual credit for detecting that
a container runtime is _installed_, which the Phase 3 `package` and `service`
collectors already do.

### 9C.2 What was reused rather than rebuilt

- **`ConfigAuditEngine`** — unchanged.
- **`structured_config`** — Phase 8's collector, extended with two formats
  rather than replaced. kubelet configuration is YAML, containerd's is TOML,
  and both parse to the same Python shapes JSON already did, so `navigate()` is
  one implementation for all three.
- **The credentialed host audit** — unchanged. These run at `platform = linux`
  because a container runtime is assessed over the _host's_ session. **No new
  scan kind, no new route, no new task.**
- **`ShellRunner` and the sentinel protocol** — the probes inherit the Phase 3
  discipline about output carrying no sentinel.
- **The finding path** — `CCURE-CFG-…`, risk, remediation, both PDFs.

**`tomllib` needed no dependency** — it has been in the standard library since
Python 3.11.

### 9C.3 What was built

| Component                                                    | What it is                                   |
| ------------------------------------------------------------ | -------------------------------------------- |
| `core/config_audit/containers.py`                            | 16 probes: command + pure Python extractor   |
| `core/config_audit/collectors/container.py`                  | The `container` collector                    |
| `core/config_audit/builtin/container_runtime.py`             | 17 checks — Docker runtime and Kubernetes    |
| `core/config_audit/builtin/container_config.py`              | 7 checks — kubelet (YAML), containerd (TOML) |
| `structured.py` — `yaml_pointer`, `toml_pointer`, `navigate` | Two new formats on one navigator             |
| `alembic/versions/b0c1d2e3f4a5_…`                            | One value on one CHECK constraint            |
| `scripts/measure_container_coverage.py`                      | The frozen denominator                       |
| `tests/scans/test_container_{probes,content,areas}.py`       | 316 tests                                    |

**`container` is its own check type, for the Phase 5 reason.**
`structured_config` reads a document and addresses a value; this enumerates
live state and filters it. The collector enumerates, the probe filters _in
Python_, and the rule asserts the list is empty — so a clean host produces
ABSENT and `AbsencePolicy.PASS` makes it a pass. Putting a pipeline of
`docker inspect` text-munging into administrator-editable rule data is exactly
what Phase 5 refused for service-ACL enumeration.

**The reserved `container` platform is deliberately not used.** These rules
target `linux`, because the runtime is reached over the host's shell. That
reservation describes a container _as a target in its own right_, which is a
different idea and one this phase does not implement.

### 9C.4 Two exit statuses where one would have done

This is the phase's central design decision and it differs deliberately from
Phases 3 and 5.

| Exit | Meaning                     | State                        |
| ---- | --------------------------- | ---------------------------- |
| 97   | The tool is not installed   | UNSUPPORTED → NOT_APPLICABLE |
| 96   | Installed but not answering | UNAVAILABLE → ERROR          |

Phases 3 and 5 treat exit 97 as an **error**, because a host with no `find` has
established nothing about its SUID binaries. That reasoning does not carry
here: every Linux host has SUID binaries, but **most hosts run no Kubernetes**.
Reporting ERROR for them would hand every host in an estate eight
findings-shaped errors about software it does not have — the same failure GAP-09
avoided by making a missing configuration file UNSUPPORTED.

The second status is what keeps that safe. The probes require `docker info` and
`kubectl version` to _succeed_, not merely that a binary exists, because
`docker ps` against an unreachable daemon returns an empty container list that
is byte-identical to a clean host. `test_a_host_with_no_runtime_produces_no_findings`
asserts the whole set produces neither a FAIL nor an ERROR on a bare host.

### 9C.5 Three defects found by pointing it at real targets

- **`cluster-admin` was reported on every cluster.** The wildcard-role probe
  looked for `*` verbs on `*` resources and excluded roles named `system:*` —
  but `cluster-admin` does not start with `system:` and is _the_ role that
  legitimately holds exactly that. The fix is the
  `kubernetes.io/bootstrapping: rbac-defaults` label, which 65 of the 69
  ClusterRoles on a stock k3s carry. Without it the check fires on every
  cluster ever built, which is the "37 SUID binaries" failure in a new runtime.

- **The collector stringified list pointers, silently.** `_from_mapping` called
  `str(pointer)`, so the list form added for containerd became
  `"['plugins', 'io.containerd…']"`, which `navigate()` then split on dots into
  segments matching nothing. The result was ABSENT — which for these rules
  means "at the product default" — so **containerd reported clean however it
  was configured**. Caught only because a deliberately weakened
  `config.toml` failed to produce the finding it should have.

- **containerd's keys contain dots.** `[plugins."io.containerd.grpc.v1.cri"]`
  parses to a key literally named `io.containerd.grpc.v1.cri`, which a dotted
  path cannot address at all. `navigate()` accepts a list of segments for
  exactly this, and the module docstring's original claim that "the formats
  this reaches have no keys containing dots" was simply false.

### 9C.6 Real-target validation — three runtimes, both directions

Disposable containers only, destroyed afterwards.

| Target                         | Weakened       | Hardened | Checks proven to fail |
| ------------------------------ | -------------- | -------- | --------------------- |
| Docker 27 (dind)               | **9** findings | **0**    | 9 / 9                 |
| k3s v1.31.4 — workloads/RBAC   | **7** findings | **0**    | 7 / 8                 |
| kubelet config (kubeadm shape) | **4** findings | **0**    | 4 / 5                 |
| containerd (k3s)               | **1** finding  | **0**    | 1 / 2                 |

The hardened Docker host kept one deliberately well-configured container
running — `--user 1000 --read-only --security-opt no-new-privileges
--cap-drop ALL` — so the clean run proves the probes stay silent on a real
container rather than on an empty host.

**Cross-runtime isolation was validated in the same runs**: pointed at the k3s
host, all nine Docker checks reported NOT_APPLICABLE; pointed at the Docker
host, all eight Kubernetes checks did.

Three checks could not be exercised in the failing direction and are recorded
rather than counted as proven-by-target: `k8s.rbac_enabled` (needs a cluster
with RBAC disabled, which k3s will not do), `ctr.containerd.config_readable`
(needs a schema-version-1 containerd), and `k8s.kubelet.client_ca` in its
_absent_ form. All three are exercised in both directions by
`tests/scans/test_container_areas.py`.

### 9C.7 Coverage — measured, denominator frozen at Stage 1

| Capability                    | Before         | After                | Basis                                           |
| ----------------------------- | -------------- | -------------------- | ----------------------------------------------- |
| GAP-17 container / Kubernetes | ~4% [measured] | **57.1%** [measured] | 24 of 42 frozen areas, implemented _and_ tested |

| Theme        | Proven       |
| ------------ | ------------ |
| runtime      | 9/14 (64.3%) |
| containerd   | 2/4 (50.0%)  |
| kubelet      | 5/8 (62.5%)  |
| controlplane | 1/6 (16.7%)  |
| rbac         | 3/4 (75.0%)  |
| workload     | 4/6 (66.7%)  |

**57.1% is the ceiling this denominator allows**, because eighteen areas are
declared and not implemented. That is the point of freezing it first.

Runtime breadth is reported separately: Kubernetes answers 13 areas, Docker 9,
containerd 2.

### 9C.8 Known limitations

- **The Kubernetes control plane is largely unassessed** — five of six areas.
  k3s runs the API server from process flags rather than
  `/etc/kubernetes/manifests/*.yaml`, and k3s is the only cluster that could be
  stood up disposably here. Writing kubeadm-shaped manifest checks blind is
  what this refuses. The sixth, RBAC enablement, is answered without a manifest
  by asking whether the API server serves `rbac.authorization.k8s.io`.
- **The kubelet rules were validated against a synthesised config file**, not a
  live kubelet consuming one — k3s does not use a kubelet config file at all.
  The rule, path, parser and verdict are proven; that a kubeadm kubelet reads
  the file as these rules assume is not.
- **Image and registry scanning are out of the denominator entirely**, as the
  brief directed. They are a different product shape needing a Trivy/Grype-class
  toolchain.
- **Managed-cloud Kubernetes is out of scope** — EKS, AKS and GKE control
  planes are not reachable this way.
- **Only running containers are examined.** A stopped container with a
  dangerous configuration is not reported, because `docker ps` lists running
  ones — which is the right default for "what is exposed now" and a gap for
  "what could be started".
- **No UI.** Findings render as ordinary configuration findings.

### 9C.9 Definition of Done — Phase 9

| Line                   | GAP-17                                                           |
| ---------------------- | ---------------------------------------------------------------- |
| Backend implemented    | ✅ 16 probes, 1 collector, 2 formats, 24 checks                  |
| Scanner integration    | ✅ runs inside the existing credentialed host audit              |
| Database migration     | ✅ `b0c1d2e3f4a5`, downgrade refuses safely and names the rules  |
| API                    | ➖ none required; no new route or scan kind                      |
| UI                     | ❌ **not done** — findings render as ordinary configuration ones |
| Finding integration    | ✅ `CCURE-CFG-…`, same `cve_list`, no second model               |
| Evidence               | ✅ offenders named, plus raw output on a clean enumeration       |
| Risk                   | ✅ existing canonical severity scale                             |
| Remediation            | ✅ asserted present on every rule                                |
| Reporting              | ✅ executive and technical PDFs, unchanged                       |
| Unit / integration     | ✅ 316 tests                                                     |
| Regression suite       | ✅ see §11                                                       |
| Real-target validation | ✅ **three runtimes, both directions**                           |
| Coverage measured      | ✅ ~4% → 57.1%, denominator frozen before implementation         |
| Control plane          | ❌ **declared, largely unimplemented** — no kubeadm cluster      |
| Docs                   | ✅ CLAUDE.md, this section                                       |
| Commit                 | ✅                                                               |

---

## 9D. Phase 10 — DISA STIG / SCAP ingestion and evaluation

**Gap:** GAP-05. **Status: Closed** — 63.5% measured, real-target validated
against two operating systems and cross-checked against `oscap`.

**No new engine, no new finding model, no new scan kind, no new route.** The
persistence cost of the entire phase is one value on one CHECK constraint
(migration `c1d2e3f4a5b6`). That is the fourth phase in a row for which it is
true, and it is the return on Phase 0's and Phase 3's reservations:

    SCAP datastream → XCCDF rules + OVAL definitions
      → compiled definition → ConfigCheck (check_type="scap_rule")
      → BenchmarkPack → compliance_frameworks/_controls/_rules
      → ConfigAuditEngine → PASS / FAIL / NOT_APPLICABLE / ERROR
      → finding → risk → remediation → report

### 9D.1 Why this gap and not another

GAP-04 has been **Partial** since Phase 4 — "capability built, content absent" —
and the blocker is licensing, not engineering: CIS Benchmark text may not be
committed to this repository. GAP-05 is the same capability shape with the
opposite content position, and that was verified rather than recalled:

- **SCAP Security Guide is BSD-3-Clause** (`LICENSE`, fetched from the project
  during Stage 0: `SPDX license identifier: BSD-3-Clause`). It publishes an
  `xccdf_org.ssgproject.content_profile_stig` profile per operating system.
- **DISA publishes its own SCAP benchmarks** as US Government works.

So the deliverable is the **reader**, not the text. Nothing is committed here
and nothing needs to be.

### 9D.2 Denominator, frozen before implementation

`scripts/measure_scap_coverage.py`, **52 areas**, frozen at Stage 1 and not
edited afterwards. The list was set from what the available content _actually
uses_, measured before any code was written against SCAP Security Guide 0.1.81:
713 OVAL fragments, 1,318 test elements.

That measurement is what made the phase tractable. Five OVAL test types are
**92.2%** of every test element in the corpus:

| OVAL test                            | Share | Answered by                            |
| ------------------------------------ | ----- | -------------------------------------- |
| `textfilecontent54`                  | 68.2% | new probe — regex over a text file     |
| `file`                               | 13.2% | new probe — mode bits, uid, type       |
| `variable`                           | 5.8%  | XCCDF Values bound at compile time     |
| `rpminfo` / `dpkginfo`               | 5.4%  | new probes                             |
| `xmlfilecontent` / `yamlfilecontent` | 2.2%  | **Phase 8 and 9's readers, unchanged** |

Nineteen areas are declared and **not** implemented, each with its reason. The
baseline was **0%** — grep confirms no XCCDF, OVAL or datastream code existed
anywhere outside vendored dependencies.

### 9D.3 What was built

| Component                               | What it is                                            |
| --------------------------------------- | ----------------------------------------------------- |
| `core/scap/xccdf.py`                    | XCCDF 1.2 + SCAP 1.3 source datastream, CPE platforms |
| `core/scap/oval.py`                     | OVAL 5.11 reading, and the compiler that refuses      |
| `core/scap/probes.py`                   | Ten object probes against a live target               |
| `core/scap/evaluate.py`                 | Three-valued criteria evaluation, applicability       |
| `core/scap/translate.py`                | SCAP content → Phase 4 benchmark pack                 |
| `core/scap/cci.py`                      | CCI → NIST SP 800-53 crosswalk                        |
| `core/config_audit/collectors/scap.py`  | The `scap_rule` collector                             |
| `scripts/benchmarks/load_stig.py`       | Convert, report, write a pack, or load it             |
| `core/benchmarks/pack.py` — `dump_pack` | The inverse of `parse_pack`, which this phase needed  |

**A definition is compiled, not referenced.** The rule row carries the tests,
objects, states and resolved variables it needs and nothing else. That matters
for more than tidiness: the datastream is a 28 MB file on an operator's
workstation, and the rule is evaluated on a Celery worker months later.

**`UnsupportedConstruct` is where the honesty lives.** OVAL 5.11 defines well
over a hundred tests; this build evaluates ten. A definition using anything
else fails to compile and the converter records that control as
`unimplemented` **with the reason**, so it appears in the register, counts
against the coverage figure, and can never be mistaken for a control that
passed.

### 9D.4 Six defects found by running real content, and one by a warning

Every one produced a plausible-looking result. None raised.

1. **`<Value>` elements were read only from the Benchmark's direct children.**
   XCCDF permits them inside a `<Group>` and SSG puts nearly all of them there,
   so the real RHEL 9 datastream yielded **zero values** — every parameterised
   rule then failed to compile for want of a variable binding and loaded as
   `unimplemented` with a plausible reason. Nothing looked broken.
2. **Reference _values_ were discarded in favour of their href.** SSG writes
   `<reference href="…/cci/">CCI-000366</reference>`; keeping only the href
   throws away every CCI and every NIST control in the benchmark and leaves a
   list of URLs repeated across hundreds of rules.
3. **No SSG rule carries `<version>`**, so every control id fell back to the
   full XCCDF rule URI and dozens exceeded the catalogue-key ceiling — dropped
   as unconvertible, which reads as a coverage limitation and is not one.
   Stripping the XCCDF 1.2 identifier scaffolding is defined by the
   specification, not by one publisher's convention.
4. **The NIST crosswalk emitted controls that do not exist.** `PR.DS-01` — a
   NIST _CSF_ identifier — yielded `DS-1`, and the reference's href says
   "nist", so a source filter alone let it through. Crosswalk entries are now
   validated against the seeded 800-53 catalogue, so a dangling entry is
   structurally impossible. This is the defect CLAUDE.md records against
   thirteen ISO crosswalks, caught before it shipped.
5. **`known_controls()` returned nothing, silently.** `seed_path` returns a
   `str`; calling `.read_text()` on it raised `AttributeError` into a broad
   `except`, and the symptom was every crosswalk vanishing while the load
   reported success. Failing open is right there; failing open _quietly_ is
   not, and it now warns.
6. **POSIX bracket expressions.** The content writes `[[:blank:]]`; **Python's
   `re` does not support it and does not say so** — it parses as a set of the
   literal characters `[ : b l a n k`. A pattern written to match whitespace
   matches punctuation instead, the rule collects no items, `all_exist` reads
   that as FALSE, and the host acquires a finding about a line that is present
   and correct. Found only because a `FutureWarning` about a nested set
   appeared in scan output nobody would normally read.

Two more were dialect differences, both fixed by translating the escape's
documented meaning rather than declining it: **inline global flags must lead**
in Python (`^\s*(?i)PermitRootLogin` raises), and **`\N` and `\h` do not
exist** — `\N` is read as the start of a named-Unicode escape.

### 9D.5 Applicability — the phase's largest defect, found by `oscap`

A STIG rule is frequently conditional: "if PAM is installed", "if this is a
real system with a kernel rather than a container". Those conditions are XCCDF
`<platform>` elements resolving to CPE 2.0 logical tests over OVAL _inventory_
definitions.

The frozen denominator recorded `scap.ingest.cpe_applicability` as **not
planned**, on the reasoning that benchmark-level `applies_to` targeting already
answered it. **The cross-check against `oscap` showed that reasoning was
wrong.** On the same host, with the same content:

| Without applicability                                                            | With applicability                                  |
| -------------------------------------------------------------------------------- | --------------------------------------------------- |
| 128 rules produced verdicts `oscap` correctly skipped — **102 of them failures** | 127 report NOT_APPLICABLE, matching `oscap` exactly |

Those 102 were findings about a kernel, a display manager and a PAM stack the
target does not have. Every one would have reached a customer. It was
implemented — the area was always _in_ the denominator; only its reason moved.

**The nesting is the semantics, and it was wrong twice.** Platforms declared
side by side are alternatives; platforms inherited from different levels are
cumulative. Reading the second as the first left **17** rules applicable that
`oscap` skipped — each a Group saying "a system with a kernel" and a Rule
saying "and PAM is installed", which in a container are false and true.

### 9D.6 Real-target validation

Two disposable containers, rebuilt for this phase and destroyed after it. The
root credential was generated at run time into the session scratchpad and never
written to source, configuration, logs, Celery arguments or Git.

```powershell
docker run -d --name ccure-rocky-target  -p 127.0.0.1:2222:22 rockylinux/rockylinux:9 sleep infinity
docker run -d --name ccure-ubuntu-target -p 127.0.0.1:2223:22 ubuntu:24.04           sleep infinity
```

| Content                       | Target       | Automated | pass | fail | n/a | **error** |
| ----------------------------- | ------------ | --------- | ---- | ---- | --- | --------- |
| SSG RHEL 9 STIG profile       | Rocky 9      | 257       | 63   | 147  | 47  | **0**     |
| SSG Ubuntu 24.04 STIG profile | Ubuntu 24.04 | 144       | 22   | 37   | 85  | **0**     |

**Zero scan-time errors on either target.** Every rule that converts produces a
real verdict; every rule that cannot be evaluated is declared `unimplemented`
at _load_ time with a reason. That property is deliberate and was reached by
moving each refusal from the probe to the compiler as it was found — a shape
knowable from the content should be reported once, in the load tally, not on
every host the benchmark ever runs against.

Weakened → hardened, both directions, across all four probe families:

| Control                              | Weakened | Hardened | Probe family                                   |
| ------------------------------------ | -------- | -------- | ---------------------------------------------- |
| `file_permissions_etc_shadow`        | fail     | pass     | `unix:file`                                    |
| `file_permissions_etc_passwd`        | fail     | pass     | `unix:file`                                    |
| `accounts_password_pam_minlen`       | fail     | pass     | `textfilecontent54` + profile-refined variable |
| `accounts_password_pam_dcredit`      | fail     | pass     | `textfilecontent54`                            |
| `accounts_logon_fail_delay`          | fail     | pass     | `textfilecontent54`                            |
| `auditd_data_disk_error_action_stig` | fail     | pass     | `textfilecontent54`                            |
| `auditd_data_disk_full_action_stig`  | fail     | pass     | `textfilecontent54`                            |
| `package_aide_installed` (Ubuntu)    | fail     | pass     | `linux:dpkginfo`                               |
| `aide_check_audit_tools` (Ubuntu)    | fail     | pass     | six ANDed tests, each with a capture group     |

The two `auditd` rules gave the **full three-state demonstration**: with the
`audit` package absent they reported NOT_APPLICABLE — correctly, because the
benchmark makes them conditional on it — then failed with a weak
`auditd.conf` once it was installed, then passed when hardened. Writing the
config file by hand does not make the rule apply, and it did not.

Error and applicability directions, each proven against a real host:

| Condition                                     | Result                           |
| --------------------------------------------- | -------------------------------- |
| RHEL 9 content against the Ubuntu host        | 60/60 **NOT_APPLICABLE**         |
| Host OS not identified                        | 20/20 **ERROR**, never a verdict |
| Config file unreadable (unprivileged session) | 2/2 **ERROR**, never a verdict   |

### 9D.7 Independent cross-check against `oscap`

`openscap-scanner` 1.3.9 was installed on the Ubuntu target and run against the
**same datastream, same profile, same host**. This build's results were then
collected over SSH with nothing changed in between.

| `oscap`       | this build     | rules                                        |
| ------------- | -------------- | -------------------------------------------- |
| notapplicable | not_applicable | **85**                                       |
| fail          | fail           | **36**                                       |
| pass          | pass           | **22**                                       |
| error         | fail           | **1** — `oscap` itself could not evaluate it |
| —             | disagreement   | **0**                                        |

**144 of 144 in agreement, on every rule this build evaluates.** No previous
phase in this programme has had an independent implementation of the same
standard to check against; this one did, and it is the strongest evidence any
phase has produced.

The first attempt at this comparison ran against Rocky and returned
`notapplicable` for all 1,532 rules — `oscap` correctly refusing RHEL content
on a rebuild. That is not a defect in either tool, and it is why the
cross-check moved to the target whose CPE genuinely matches.

### 9D.8 Coverage — measured, denominator frozen at Stage 1

| Capability         | Before        | After                | Basis                                           |
| ------------------ | ------------- | -------------------- | ----------------------------------------------- |
| GAP-05 STIG / SCAP | 0% [measured] | **63.5%** [measured] | 33 of 52 frozen areas, implemented _and_ tested |

| Theme  | Proven        |
| ------ | ------------- |
| ingest | 10/12 (83.3%) |
| oval   | 15/29 (51.7%) |
| run    | 7/7 (100%)    |
| report | 1/4 (25.0%)   |

**Two areas were found after the denominator was frozen** and are recorded
separately rather than added to it: `linux:systemdunitdependency_test` (14
rules across the two profiles) and the OpenSCAP Script Check Engine (2 rules).
Against the corrected denominator of 54 the figure is **61.1%**. The frozen
list is what was predicted before implementation; editing it afterwards
destroys the only thing it is for.

Content breadth is reported separately and never folded in: two operating
systems were validated, and the reader is content-agnostic.

### 9D.9 What the content itself says about the remaining gap

The converter's tally is the phase's own gap list, produced from real content
rather than guessed at:

| Reason a rule did not convert                      | RHEL 9 | Ubuntu 24.04 |
| -------------------------------------------------- | ------ | ------------ |
| references a `local_variable`                      | 111    | 56           |
| object composes others with `<set>`                | 52     | 17           |
| `linux:partition_test`                             | 29     | 1            |
| unit selected by pattern (`systemdunitproperty`)   | 13     | 7            |
| `linux:systemdunitdependency_test`                 | 9      | 5            |
| everything else (6 test types, SCE, CPE, long ids) | 9      | 5            |

`local_variable` and `<set>` are one problem wearing two hats: both need a
second collection pass whose results feed the first. 191 of the 276
`local_variable`s in the measured corpus use `object_component`. That is the
single change that would move this figure most, and it is a real piece of
engineering rather than one more probe.

### 9D.10 Known limitations

- **No multi-pass collection**, so `local_variable` and object `<set>` are
  unimplemented. Between them they account for 163 of the 223 unconverted RHEL
  9 rules.
- **Ten OVAL test types of the hundred-plus the standard defines.** The nine
  unimplemented Unix ones are named in the denominator with reasons; the whole
  Windows schema is out, because no Windows STIG was validated and shipping it
  unvalidated is what Phase 8 recorded as refused for IIS.
- **Both targets are containers.** They are legitimate Linux hosts for the file,
  package and configuration probes, and applicability correctly suppresses the
  rules that need a kernel — but a bare-metal or VM target would exercise more
  of the benchmark. The `system_with_kernel` platform was satisfied deliberately
  (`kernel-core`, `linux-base`) to reach the rules behind it.
- **`oscap` agreement is measured on Ubuntu only.** The Rocky comparison is not
  available, because `oscap` declines RHEL content on a rebuild — correctly.
- **No result export.** ARF, XCCDF `TestResult` and DISA `.ckl` are declared and
  unimplemented; results reach this product's own register, findings queue and
  reports instead.
- **A rule whose severity a publisher left `unknown` is loaded as `medium`.**
  Rating it lowest would quietly remove it from every report ordered by
  severity.
- **No UI.** A STIG loads as a benchmark framework and renders through the
  existing compliance register.

### 9D.11 One pre-existing defect fixed, because this phase depends on it

`ConfigCheck.from_check_definition` takes severity as an argument and defaults
it to `medium`, and `_parse_control` passed none — so **every check loaded from
a benchmark pack file came back `medium`** regardless of what the control said.
The database path was unaffected (`_upsert_rule` writes `control.severity`), so
the loss showed only for a check evaluated straight from a pack, which is
exactly how a converted STIG is validated before it is loaded. The control's
severity now flows onto the check on load, as `to_pack` already does on build.

### 9D.12 Definition of Done — Phase 10

| Line                  | GAP-05                                                                      |
| --------------------- | --------------------------------------------------------------------------- |
| Denominator frozen    | ✅ 52 areas, before implementation, 19 declared unimplemented               |
| Implemented           | ✅ 33 areas                                                                 |
| Automated tests       | ✅ 135 tests in four files, every implemented area named                    |
| Real-target validated | ✅ two operating systems, both directions, zero scan-time errors            |
| Independent reference | ✅ 144/144 agreement with `oscap` 1.3.9                                     |
| Coverage measured     | ✅ 0% → **63.5%** (61.1% corrected)                                         |
| Regression            | ✅ full suite, see §11                                                      |
| No parallel engine    | ✅ one CHECK-constraint value; no new table, route or scan kind             |
| No fabricated content | ✅ nothing committed; publisher and licence required on every pack          |
| Targets destroyed     | ✅ both containers removed, credential never written outside the scratchpad |

## 9E. Stabilization after Phase 10 — carry-forward remediation

**Not a capability phase.** A read-only audit of every unresolved item from
Phases 0–10 concluded STABILIZATION REQUIRED, on three grounds. This section
records what was fixed and what deliberately was not.

No gap moved. No detection was added. The one behavioural change removes a
write to customer hosts.

### 9E.1 The scanner no longer writes to targets by default

`ftp_checker._test_write_access` issued `MKD` then `RMD` against every scanned
FTP server that accepted an anonymous login. It is the only place in the
product that changes a host it is assessing, and this product scans production
networks and OT segments. Phase 6 flagged it "for a decision" (§9.9); four
phases later there was still no gate.

The detection is worth keeping — a writable anonymous root on a host that also
serves those files over HTTP is remote code execution, and there is no
read-only way to establish it. So it is kept and made **opt-in**:

- `core/checks/intrusive.py` owns the decision. Off by default, and it fails to
  off: configuration that cannot be read means the operator has not turned this
  on, and the safe reading of "we do not know" is "do not touch the target".
- `SCAN_ALLOW_INTRUSIVE` turns it on. Deployment-wide rather than per-scan,
  deliberately: there is no scan-policy engine yet (GAP-12), and inventing half
  of one here would leave two mechanisms to reconcile. That module is the seam
  GAP-12 replaces.
- `NetworkCheck` gained a real `intrusive` field — `spec()` previously
  hardcoded `intrusive=False` for every check — and `ftp.anonymous_write`
  declares it. That connects the probe to the policy vocabulary the rest of the
  product already speaks: `CheckSpec.intrusive`,
  `CheckRegistry.select(allow_intrusive=...)`,
  `select_checks(include_intrusive=...)`. One switch, not two.

**Why the policy is not a parameter.** The engine dispatches parallel plugins
as `run(ip, open_ports)` and `test_plugin_contract.py` pins that arity — a
plugin with the wrong one raises `TypeError` on every host, is swallowed at
DEBUG, and produces zero findings indefinitely. Threading a parameter through
would change the contract that exists to prevent exactly that.

**"Not tested" is not "not writable".** `write_access` is now tri-state, and
this is the half that matters more than the gate. A skipped test previously
left the initial `False`, which reports "no write access" about a server nobody
looked at — a false negative on the most severe condition this plugin can find.
`None` means nobody looked; the finding is emitted on `is True` only; and the
probe's `issues` say the test was skipped and name the switch that enables it,
because a silently omitted check is indistinguishable from one that passed.

Two more corrections fell out of reading it:

- **A failed cleanup is logged, not swallowed.** If `RMD` does not confirm, a
  directory has been left on somebody's host and they need to know which.
- **The evidence described a test that never ran.** The finding said "a STOR
  was allowed to begin" and the catalogue said "able to begin a file upload";
  the probe sends `MKD`. Both now describe what actually happened.

`tests/scans/test_ftp_write_safety.py` — 15 tests, and they assert on the
**command transcript**, not only the verdict. A bypassed gate still produces
the right verdict; only the transcript shows it was bypassed. Verified by
mutation: replacing the guard with `if False:` fails three of them.

### 9E.2 Three stale statements corrected

The audit found the tracker asserting things that measurement contradicts. §1
says the measurement wins and the disagreement is recorded rather than quietly
reconciled, so the originals are kept and marked superseded.

| Where          | Said                                       | Measured, 30 Aug 2026                                    |
| -------------- | ------------------------------------------ | -------------------------------------------------------- |
| Matrix, GAP-07 | `Open`, no commit                          | Deep TLS shipped in Phase 6 (`d40800d`); now **Partial** |
| §9.9 and §4.5  | live DB at `d0e1f2a3b4c5`                  | `b0c1d2e3f4a5` at audit, `c1d2e3f4a5b6` after §9E.3      |
| `CLAUDE.md`    | 23 `CVE-9999-*` rows in the live catalogue | **0**                                                    |

GAP-07 is marked **Partial**, not Closed, and carries **no new percentage**.
Phase 6 delivered the gap's own title — deep TLS in the main scan path — but no
denominator was ever frozen for it, so there is nothing to measure against.
Claiming a figure would be inventing one; the row now says what is true and
what is unknown.

The GAP-07 row was the item with real cost: the next capability gap is chosen
from that matrix, and a delivered capability reading `Open` invites a phase
that redoes it.

### 9E.3 The live database brought to head

`ccure_test` was at `b0c1d2e3f4a5`, so `ck_rule_check_type` did not admit
`scap_rule` and **loading a STIG into the deployment would have failed at the
constraint**. Phase 10 was recorded Closed and was inert where it runs.

A dump was taken immediately before (`ccure_test_20260830_135628_ops.dump`,
5.7 MB, operational data) on top of the scheduled six-hourly backup, because
`archive_mode` is still `off` and recovery granularity is "since the last dump".

```
b0c1d2e3f4a5 -> c1d2e3f4a5b6   compliance_rules: admit the compiled SCAP/OVAL check type
```

Verified afterwards: `alembic_version` is `c1d2e3f4a5b6`; the constraint admits
`scap_rule`, and still admits `container`, `structured_config`, `privilege` and
`database_query` — a hand-rendered CHECK list is exactly where a value gets
dropped in passing. Data intact: 1,357 compliance rules, 263,938 catalogue
rows, 6 users, 4 organisations, 39 scans.

### 9E.4 Deliberately not fixed

Named so they are not mistaken for oversights. Each was assessed and is
recorded in the carry-forward list rather than actioned.

- **Silent truncation** in the Phase 8 and Phase 10 collectors (`head -c 512K`,
  `head -n 500`). A truncated read is indistinguishable from a complete one, so
  a directive past the cut yields a wrong verdict. Measured **latent**: the only
  file over the cap on a stock Rocky 9 is `/etc/services` (692,252 bytes), which
  no rule reads, and `find /etc -maxdepth 2` is 244 entries against a cap of 500. It becomes real on large nginx or Apache estates. The fix — read
  `cap + 1` and report UNAVAILABLE when the extra byte appears — is a change to
  two collectors and belongs with a phase that can validate it against content
  that triggers it.
- **The "tested" half of every coverage figure is a substring match** on test
  sources, in every measurement script since Phase 5. Better than a
  hand-maintained list, and not proof that an assertion ran.
- **587 archived compliance rules with no successor.** Measured: **0 controls
  have all their rules inactive**, so nothing is switched off today. Same shape
  as the ISO defect that disabled 24 controls; `cleanup_nist_csf_v2.py` repairs
  only NIST CSF.
- **`compliance_frameworks.is_active` is `true` for all 13 rows** while the
  authoritative list names two. Read by no query and guarded by
  `test_framework_activation.py`, so inert — but misleading data.
- **`LinuxPermissionCollector` uses `stat -c` without `-L`.** Verified latent:
  all seven `permission` checks target regular files.

## 9F. Phase 11 — Deep TLS assessment on the main scan path

**Gap:** GAP-07. **Status: Closed** — 71.4% measured, real-target validated
across six listeners and five opportunistic-TLS transports.

**No new TLS engine.** `core/web/sslyze/wrapper.py` has driven full TLS audits
since before Phase 6; Phase 6 pointed the network path at it, and this phase
reads what it was already collecting and teaches it to negotiate STARTTLS. The
whole phase is one wrapper extension, seventeen catalogue entries and a plugin
that reaches six more transports. No migration, no route, no scan kind, no new
finding model.

### 9F.1 The two things that were missing

**Reach.** The assessment only looked at ports speaking TLS from the first byte
— 443, 8443, 993, 995 and a few more. A mail server with an expired certificate
on port 25, a directory server with a weak key on 389, a database offering TLS
1.0 on 5432: none were assessed at all, on hosts whose web port was assessed
thoroughly.

**Results already being discarded.** Three sslyze commands were requested and
their results thrown away — `TLS_FALLBACK_SCSV` and `SESSION_RENEGOTIATION`
since before Phase 6, and `path_validation_results` was parsed into a
`chain_trusted` boolean nothing read. The scan was paying for them already.
That is why fourteen findings arrive for very little extra time on the wire.

### 9F.2 Denominator, frozen before implementation

`scripts/measure_tls_coverage.py`, **28 areas**, frozen at Stage 1. Eight are
declared and not implemented, each with its reason.

**The thirteen `tls.*` areas GAP-06 froze are deliberately excluded.** Ten were
delivered in Phase 6; three were not, and this phase implements them —
`tls.certificate_expiring_soon`, `tls.weak_dh_parameters`,
`tls.insecure_renegotiation`. Their coverage credit is **GAP-06's**, whose
harness reads the same live catalogue and moved from **64.5% to 69.4%**
accordingly. Counting them here as well would have inflated this phase by an
eighth before a line of it was written — the mistake Phase 8 and Phase 9 each
had to correct. `OWNED_BY_GAP06` names the boundary from this side;
`measure_network_check_coverage.py` names it from the other, and a test asserts
the two denominators do not intersect.

### 9F.3 What was built

| Area                        | Count                                       |
| --------------------------- | ------------------------------------------- |
| STARTTLS transports reached | 6 — SMTP, IMAP, POP3, LDAP, PostgreSQL, FTP |
| New finding conditions      | 14                                          |
| GAP-06 areas completed      | 3                                           |
| New catalogue entries       | 17                                          |

Two carry a **real published CVE** — Heartbleed's `CVE-2014-0160` was already
there, and CCS injection is `CVE-2014-0224`. Everything else mints a
`CCURE-CHK-…` identifier. No CVE is fabricated, and a test pins that exactly
two TLS checks carry one.

**A STARTTLS endpoint never becomes `tls_info`.** That key means "the first
_implicit_-TLS endpoint that answered"; `asset_syncer` writes the asset's TLS
record from it and `core/risk.py` scores from it. A mail server appearing there
would rewrite an asset's TLS identity with a certificate no browser negotiates.
STARTTLS results go to `tls_endpoints` with a `starttls` marker, and a test
asserts both directions.

**One budget covers both kinds of endpoint.** `TLS_DEEP_MAX_ENDPOINTS` already
bounded deep assessment; STARTTLS consumes the same allowance rather than
adding to it, so a host exposing six opportunistic services cannot silently
cost six more cipher-suite enumerations. `TLS_STARTTLS_SCAN` disables the
transport entirely.

### 9F.4 Three defects real listeners found

- **EC certificates could never be reported as weak.** `_describe_public_key`
  classified by class _name_, and this build of `cryptography` returns
  `ECPublicKey` where older ones return `_EllipticCurvePublicKey`. The name
  test missed, the function returned `{}`, and the key-strength check was
  silently withheld for the entire algorithm. Found against a real LDAP
  listener whose key came back unclassified; it is `isinstance` against the
  abstract types now, which is version-proof.
- **A connectivity failure surfaced as `'NoneType' object has no attribute
'certificate_info'`.** sslyze leaves `scan_result` as None when it cannot
  complete a handshake — which is the _normal_ outcome for a STARTTLS probe of
  a service that does not offer it. Reaching through it produced an opaque
  AttributeError that read as a broken scanner rather than as a service which
  does not speak TLS.
- **PostgreSQL's port-map entry was dead.** `_PORT_MAP` already had
  `5432: ["default_creds"]`, and the new `5432: ["tls_scanner"]` sat earlier in
  the same dict literal — where a repeated key keeps only the _last_ value. The
  transport looked supported and reached nothing. Caught by asserting selection
  for every port in `STARTTLS_SERVICES`; a test now also refuses any duplicate
  key in that map.

### 9F.5 Real-target validation

Six disposable listeners, destroyed after use. Certificates generated at run
time; no credential written to source, configuration, logs or Git.

| Target                        | Purpose                                                   |
| ----------------------------- | --------------------------------------------------------- |
| nginx 1.24, deliberately weak | 1024-bit SHA-1 self-signed cert, 1024-bit DH, TLS 1.0/1.1 |
| nginx 1.24, hardened          | 2048-bit SHA-256, TLS 1.2/1.3, ECDHE only                 |
| Postfix                       | SMTP STARTTLS                                             |
| Dovecot 2.3                   | IMAP and POP3 STARTTLS                                    |
| OpenLDAP (osixia)             | LDAP STARTTLS, EC P-384 key                               |
| PostgreSQL 16                 | SSLRequest negotiation                                    |

**Weakened → hardened** on the nginx pair:

| Condition                                | Weak  | Hardened |
| ---------------------------------------- | ----- | -------- |
| `tls.certificate_weak_key` (RSA 1024)    | ✅    | —        |
| `tls.certificate_weak_signature` (SHA-1) | ✅    | —        |
| `tls.deprecated_protocol` (TLS 1.0/1.1)  | ✅    | —        |
| `tls.weak_dh_parameters` (1024-bit)      | ✅    | —        |
| **total findings**                       | **7** | **3**    |

The three that remain on the hardened listener are correct: it still serves a
self-signed certificate and staples no OCSP response. Only the four conditions
actually remediated disappeared — a check that cleared everything would mean
the assessment had stopped looking.

**STARTTLS, five transports in one run: 19 findings on services the previous
scanner could not see at all.**

| Service         | Port | Findings                                                                                   |
| --------------- | ---- | ------------------------------------------------------------------------------------------ |
| SMTP (Postfix)  | 25   | deprecated protocol, weak cipher suite, weak DH, self-signed, untrusted chain, no stapling |
| IMAP (Dovecot)  | 143  | client renegotiation DoS, self-signed, untrusted chain, no stapling                        |
| POP3 (Dovecot)  | 110  | client renegotiation DoS, self-signed, untrusted chain, no stapling                        |
| LDAP (OpenLDAP) | 389  | untrusted chain, no stapling                                                               |
| PostgreSQL 16   | 5432 | self-signed, untrusted chain, no stapling                                                  |

`tls.client_renegotiation_dos` is a discriminating result rather than a blanket
true: Dovecot accepted **10** client-initiated renegotiations, Postfix and
nginx **zero**. The LDAP listener's EC P-384 key was correctly _not_ reported —
384 is above the 224 floor.

### 9F.6 Coverage — measured, denominator frozen at Stage 1

| Capability           | Before        | After                | Basis                                                  |
| -------------------- | ------------- | -------------------- | ------------------------------------------------------ |
| GAP-07 deep TLS      | 0% [measured] | **71.4%** [measured] | 20 of 28 frozen areas, implemented _and_ tested        |
| GAP-06 (side effect) | 64.5%         | **69.4%**            | the three `tls.*` areas it froze and never implemented |

| Theme     | Proven      |
| --------- | ----------- |
| starttls  | 6/9 (66.7%) |
| chain     | 3/5 (60.0%) |
| cert      | 4/5 (80.0%) |
| downgrade | 2/2 (100%)  |
| kex       | 2/3 (66.7%) |
| protocol  | 3/4 (75.0%) |

The 45% [estimated] the matrix carried for GAP-07 was never measured against a
frozen denominator, so it is not comparable and the _before_ is recorded as 0%
against this one. That is the same treatment Phase 8 gave GAP-09's "~3%".

### 9F.7 Known limitations

- **FTP AUTH TLS is implemented and not target-validated.** The code path is
  identical to the five that were — same sslyze enum, same wrapper call — but
  vsftpd would not stay up long enough to prove it, and "the mechanism is the
  same" is an argument, not a measurement. Recorded as implemented, not as
  validated.
- **XMPP, RDP and MySQL are declared unimplemented**, each with a reason:
  XMPP needs a `to` hostname the scanner cannot infer; RDP's port is
  overwhelmingly self-signed-by-design Windows hosts; sslyze 6.3.1 has no MySQL
  opportunistic-TLS handler at all, and writing one would be the second TLS
  implementation this phase exists not to build. MySQL's TLS posture is
  assessed by GAP-10 over an authenticated session.
- **Revocation is not checked.** Only the _stapled_ response is read. A live
  CRL or OCSP fetch from the scanner needs egress OT segments do not have, and
  turns a network outage into a finding about somebody's certificate.
- **Session resumption is not assessed.** sslyze reports resumption _support_,
  which is the desirable state; telling a weak ticket key from a healthy one
  needs two scans separated in time.
- **The deep assessment remains bounded** at four endpoints per host. On a host
  exposing both a web tier and several mail services, some endpoints are not
  deeply assessed — and the skip is logged with the setting that raises it,
  rather than passing silently.
- **`/web-scans` output is unchanged.** The wrapper's own `findings` list was
  deliberately not extended; that path renders it, and altering what an
  existing report says is not this phase's business. The network path builds
  its own findings from the structured data.

### 9F.8 Definition of Done — Phase 11

| Line                    | GAP-07                                                         |
| ----------------------- | -------------------------------------------------------------- |
| Denominator frozen      | ✅ 28 areas, before implementation, 8 declared unimplemented   |
| Implemented             | ✅ 20 areas — 6 transports, 14 conditions                      |
| No parallel engine      | ✅ one sslyze wrapper, extended; no new TLS implementation     |
| No duplicate of Phase 6 | ✅ GAP-06's thirteen areas excluded, boundary asserted by test |
| No fabricated CVEs      | ✅ two real published CVEs, everything else `CCURE-CHK-…`      |
| No false PASS           | ✅ every reading tri-state; absent commands produce no finding |
| Automated tests         | ✅ 124 tests in two files                                      |
| Real-target validated   | ✅ six listeners, weak→hardened, five transports               |
| Coverage measured       | ✅ 0% → **71.4%**; GAP-06 64.5% → 69.4%                        |
| Regression              | ✅ full suite, see §11                                         |
| Targets destroyed       | ✅ all six containers removed                                  |

## 9G. Stabilization after Phase 11 — credentialed transport and port resolution

**Not a capability phase, and no gap moved.** No check, rule, probe or finding
was added. What changed is where an authenticated session is opened, which had
been decided by a constant since before Phase 1.

### 9G.1 Root cause

`compliance_credentials.port` is `NOT NULL` with a model-level default of `22`.
So "the operator chose 22" and "nobody said anything" are the same row, and
until this fix that row was the _only_ input to the decision. Four consequences,
each of which produced a plausible failure a support ticket would have blamed on
the target:

- **The phase-3.5 enrichment path dropped the transport entirely.** It resolved
  the stored credential — reading `transport`, `auth_method`, `domain` and
  `options` — and then called `audit_credentialed_host` **without any of them**,
  so the auditor's `transport="ssh"` default applied to every credential on the
  main scan path. A Windows credential opened an SSH handshake against a WinRM
  listener and the host was recorded as a connection failure. The standalone
  `/scan/credentialed` route passed them correctly, so the defect was invisible
  to anyone testing that route.

- **`port = int(material.get("port") or 22)`** in the same path: an SSH port
  standing in for every credential type. Combined with the open-port guard
  (`if open_numbers and port not in open_numbers: skip`), a host running sshd on
  2222 was skipped with "Port 22/tcp not open" **on a scan that had already
  discovered and identified sshd on 2222 two phases earlier**. The evidence was
  in the same dictionary the guard was reading.

- **`audit_credentialed_host(port: int = 22)`** and
  `run_credentialed_scan_task(port: int = 22)` — the same SSH constant as a
  signature default for a function that dispatches two transports.

- **`use_tls` was re-derived from `port == 5986`.** Right for the conventional
  layout, wrong for every other one: an HTTPS WinRM listener on any other port
  would be addressed as `http://` and fail with a handshake error that reads as
  a broken host.

Two further sites carried the same constant: `core/scheduling/dispatcher.py`
passed `port=credential.port or 22` (inert, because the task re-reads the
credential, but wrong-looking and one refactor away from mattering), and the
enrichment path did not branch on `credential_type`, so a **database credential
in a scan's credential list was handed to the host auditor** — the exact defect
the standalone task documents itself as avoiding.

### 9G.2 The fix — one resolver, no new engine

`engines/credentialed/transport_resolver.py`. No new scan kind, no new route, no
migration, no change to any collector. Both call sites resolve; everything
downstream is unchanged.

**The port scan's service identification is evidence, and the resolver reads
it.** Candidates are the stated port plus every open TCP port the scan
_positively identified_ as that transport's service — `ssh` by service token,
RFC 4253 banner or product string; WinRM by `wsman`/`winrm` token or the
`Microsoft HTTPAPI` product string that is the only thing identifying a listener
moved off 5985.

Three properties hold the design, and each is asserted by test:

- **A credential is only ever offered a port that is stated on it or identified
  as that transport.** Walking every open port until something authenticates is
  credential spraying against the customer's own estate, and it is what a "try
  harder" resolver becomes the moment identification is dropped.

- **Selection is by TCP reachability, never by attempting authentication.** Both
  executors already expose `test_connectivity`, which opens a socket and closes
  it. Exactly one authentication attempt is made however many candidates were
  considered, so resolution can never become the account lockout this product
  documents as a control it must not trip. A **rejected** credential is never
  retried elsewhere; only a _transport_ failure — nothing answered — advances.

- **`use_tls` is carried, not re-derived.** 5985 and 5986 are settled by
  convention; anything else carries `None`, because nmap keeps the TLS fact in a
  `tunnel` attribute this product does not parse and a guess there addresses an
  HTTPS listener as `http://`.

**Discovery is authoritative where it exists; a TCP probe is the fallback where
it does not.** The enrichment path has the port scan's view, so it opens no
socket — the rule it already had, kept deliberately, because a 5-second connect
per host is minutes across a large scan. The standalone scan runs no discovery,
so it attempts the stated port directly (unchanged cost for a conventional host)
and probes the conventional alternates only after a transport failure.

**The stated port leads, except when discovery contradicts it.** Because 22 can
be on a Windows credential without anyone having chosen it, a stated port that
the scan positively identified as _some other_ service goes second rather than
first. It is never dropped — service detection can be wrong.

### 9G.3 Real-target validation — VALIDATED

Two live hosts supplied for the purpose, plus one disposable container.
Credentials were held in the environment for the duration and written nowhere.
**Nothing on either host was modified**; every check is a resolution followed by
one authenticated session.

`10.180.6.14` is the case the demotion rule exists for: it runs **sshd on 22 and
WinRM on 5985 simultaneously**, so a Windows credential carrying the model
default would have authenticated against the wrong service.

| #   | Case                                                           | Result                          |
| --- | -------------------------------------------------------------- | ------------------------------- |
| 1   | Linux, credential states 22, discovery agrees                  | 22 (`credential`)               |
| 2   | Linux, credential states 2222, discovery identified sshd on 22 | 22 (`discovered`)               |
| 3   | Linux, no discovery, stated 2222 closed                        | 22 (`fallback`)                 |
| 4   | Linux, authenticated session on the resolved port              | `Linux 6.8.0-138-generic`       |
| 5   | **Windows, WinRM credential carrying the model default 22**    | **5985, not 22** (`discovered`) |
| 6   | Windows, WinRM credential states 5985                          | 5985 (`credential`)             |
| 7   | Windows, SSH credential on the same host                       | 22, not 5985                    |
| 8   | Windows, WinRM authenticated                                   | `Microsoft Windows 11 Pro`      |
| 9   | Windows, SSH-on-Windows authenticated                          | hostname returned               |
| 10  | SSH credential where no sshd was discovered                    | refused, no attempt             |

**Non-default port, proven end to end** against a disposable Ubuntu 24.04
container running sshd on 2222 (`sshd -T` reported `port 2222`), destroyed
afterwards:

| Case                                                    | Result                       |
| ------------------------------------------------------- | ---------------------------- |
| Credential states 22, discovery identified sshd on 2222 | resolved 2222 (`discovered`) |
| **Authenticated on the resolved non-default port**      | ✅ `root` on Ubuntu 24.04    |
| Credential configured for 2222, no discovery            | resolved 2222 (`credential`) |
| **Authenticated on the configured non-default port**    | ✅                           |

**Non-standard WinRM port, authenticated.** Neither host could be reconfigured
to move its listener, so the session was opened through a local TCP relay on
`127.0.0.1:15985` forwarding to the target's 5985 — nothing on the Windows host
changed. Discovery described the relay port only by its `Microsoft HTTPAPI`
product string, which is the sole identifying evidence for a WinRM listener off
5985:

| Case                                       | Result                               |
| ------------------------------------------ | ------------------------------------ |
| Resolved from the product string alone     | 15985 (`discovered`), `use_tls=None` |
| **Authenticated over WinRM on port 15985** | ✅ `Microsoft Windows 11 Pro`        |

`use_tls` was correctly left `None` — the port is in no convention table and
nothing established TLS — so the executor applied its plaintext default, which
is what the listener speaks.

Two results recorded as _not_ validated:

- **WinRM over TLS on 5986** is resolved correctly (case 6 variants) but neither
  host exposes an HTTPS listener, so no authenticated session proves it.
- `10.180.6.14` also has **47001** open, and the resolver correctly identified it
  as WinRM from the same product string — but a WS-Management request there
  returned **HTTP 404**, classified as `WinRMConfigurationError` ("answered, but
  configured in a way that prevents the scan"). That is the right outcome: the
  listener is real, the endpoint is not served at `/wsman` on that host, and
  nothing was reported as a pass.

### 9G.4 Tests

49 new tests across two files, both mutation-verified:

- `tests/credentialed/test_transport_resolution.py` (54 cases) — identification,
  the spraying guard, TLS carriage, ordering, and the required port matrix.
- `tests/credentialed/test_transport_selection_pipeline.py` (26 cases) — the two
  call sites, the database-credential skip, the retry discipline, and the API's
  port override.

Mutation-verified in both directions: restoring `port = int(... or 22)` fails
three tests by name; removing `transport=transport` from the enrichment call
fails two.

Three existing tests in `test_credentialed_pipeline.py` were repointed. They
patched `routers.credentialed.SSHScanner.test_connectivity` to stand the
pre-flight socket down; the router no longer imports that class, so they now
name it directly from `engines.credentialed.ssh_scanner`. Same class attribute,
same intent, nothing relaxed.

### 9G.5 Coverage

**No coverage figure moves, and none should.** This is a correctness fix on the
path every credentialed capability runs through, not a new check. What it
changes is how often the existing capabilities are _reachable_: GAP-02, GAP-03,
GAP-04, GAP-05, GAP-08, GAP-09 and GAP-17 all execute over this transport, and
on a host with a non-conventional listener every one of them previously scored
zero for reasons that had nothing to do with the check.

### 9G.6 Recorded, not fixed

- **`compliance_credentials.port` still defaults to 22 at the model level.**
  The API applies the correct per-type default (`22`/`5985`/`5432`), so a
  credential created through the product is right; a row created directly by ORM
  is not. Changing the column means a migration on live encrypted credentials
  for a default the resolver now compensates for.
- **Compliance remediation is SSH-only.** `_execute_ssh_remediation` wraps
  PowerShell over SSH and has no WinRM branch, so a Windows host reachable only
  by WinRM can be assessed but not remediated. That is a capability gap in the
  remediation path, not a port defect, and adding the branch is new work.
- **`POST /scan/credentialed` refuses when paramiko is missing**, even for a
  WinRM credential that does not need it.

---

## 9H. Credentialed security defects — remediation

**Not a capability phase, and no gap moved.** Three defects on the authenticated
path, found by the code-level verification in §9G's follow-up assessment. Two
were security defects in this product's own handling of a customer's
credentials; one under-reported compliance automation the scan had already
earned.

### 9H.1 The sudo password was placed in the target's argv

`LinuxCollector._run` built `echo 'PASSWORD' | sudo -S …` and handed it to
`SSHScanner.run`, which passes the string to paramiko's `exec_command`. The
shell sshd spawns on the target therefore carried the customer's password in
its **argv**:

- visible in `ps` to every local user on the scanned host, for the life of the
  command;
- captured permanently by any `execve` audit rule, which is precisely what a
  hardened host being assessed for compliance is most likely to have; and
- written to this scanner's own log — `run` logged the full command string on
  failure at DEBUG.

The irony is complete: the scanner leaked the credential most reliably on the
hosts most carefully configured to record what runs on them.

**The fix is stdin.** `sudo -S` reads its password there, so
`SSHScanner.run_sudo()` rewrites each invocation to `sudo -S -p ''` and writes
the password to the remote command's standard input. Nothing outside that class
sees the secret: the collector asks `has_password` and calls `run_sudo`, where
it previously read `ssh._password` and did the interpolation itself.

Three details that are not obvious and are each pinned by a test:

- **`-p ''` is required.** Without it sudo writes `[sudo] password for …` to
  stderr, where the collector reads it as command output.
- **`-n` must be stripped, bundled forms included.** It means "never prompt"
  and sudo honours it over `-S`. Left in place — and `sudo -ln` in the real
  catalogue contains it — sudo refuses the password this rewrite exists to
  deliver, and the failure reads on the target as a permissions problem.
- **One password line per invocation.** `sudo -l || sudo -l` runs at most one
  of them, but which is decided on the target: a second that runs because the
  first failed must find another line waiting. Relying on sudo's credential
  cache instead breaks wherever `timestamp_timeout=0` is set.

`_redact()` masks the session password in anything logged. With the stdin fix
the command no longer carries it, so this is defence in depth — but a log line
is the one place a regression here would be written to disk and kept.

**Validated on a live Linux host.** `sudo -n id -u` returned `0`; the real
`sudo_rules` command returned `(ALL : ALL) ALL`; and a **32 KB process table
captured from a second session while the elevated command was running** —
proven to be the right moment by the presence of `sleep 3` — contains neither
the password nor the `| sudo` shape.

### 9H.2 An authenticated host was not recorded as authenticated

`credentialed_status` was written by the standalone audit and by nothing else.
The Vulnerability Audit's credentialed pass — the path that actually runs on the
main pipeline — never set it, so a host that was authenticated to, collected
from and configuration-audited still read as `unknown`. `core/compliance_tasks`
routes every rule in `CREDENTIALED_EVIDENCE_SOURCES` to `manual_review` unless
the value is `success`.

Measured on the live database before the fix: **zero** assets carried the
attribute, despite that path having written eight configuration and privilege
findings against a real Windows 11 host on 31 Aug 2026. The scan had the
evidence; the compliance register reported the control as unassessed.

`asset_syncer.set_credentialed_status()` is now the single writer and both paths
call it. Three states, deliberately: `success`, `failed`, and **absent** for a
host nothing was attempted against — "no credential was in scope" and "the
credential was refused" are different facts, and only the second is a statement
about the host.

### 9H.3 Windows elevation — measured, and deliberately not invented

There is no elevation mechanism on the Windows path. WinRM and OpenSSH both run
as whoever authenticated, and escalating by creating a service or a scheduled
task changes a host this product is only meant to read. **None was added.**

What the code-level assessment claimed — that Windows checks "read partial
state" for want of elevation — was not borne out by measurement. Against a real
Windows 11 Pro host over WinRM as a member of Administrators:

| Outcome       | Count |
| ------------- | ----- |
| PASS          | 11    |
| FAIL          | 8     |
| MANUAL_REVIEW | 1     |
| **ERROR**     | **0** |

All 20 Windows built-in checks completed. No check in the current set needs
SYSTEM: every one reads `HKLM\SOFTWARE`, `HKLM\SYSTEM`, a service or task ACL,
or `net accounts`, all of which a member of Administrators can read. The three
empty fields in the Windows collector — `arp_table_raw`, `env_vars_summary`,
`login_history_raw` — are **hardcoded placeholders** in `_collect_network` and
`_collect_login_history`, not privilege failures. That corrects the assessment.

What was added is provenance, not elevation: `system_data["privilege_context"]`
records `account`, `is_administrator` and `is_system`. A failed probe yields
`None`, never `False` — reading it as "not an administrator" would attribute a
complete audit's findings to a partial one. The role test goes through
`WindowsBuiltInRole.Administrator`, which resolves to S-1-5-32-544, because
matching the group's _name_ fails on a non-English install.

**What remains partial, and why:** a scan run as a standard user. Such an
account cannot read service ACLs, the LSA policy or `net accounts`, so those
checks report ERROR — correctly, and now with a recorded reason. This was not
measured, because measuring it means creating a non-administrator account on a
machine this programme does not own.

### 9H.4 Definition of Done

| Line                                               | Result                                              |
| -------------------------------------------------- | --------------------------------------------------- |
| Sudo password out of argv, `ps`, logs, exceptions  | ✅ stdin; validated against a live process table    |
| Existing sudo functionality preserved              | ✅ `uid=0`, real catalogue commands work            |
| `credentialed_status` written by the main path     | ✅ one writer, three states                         |
| Windows elevation                                  | ✅ measured; none invented, absence guarded by test |
| Automated tests                                    | ✅ 50 across three files, all mutation-verified     |
| No new engine, no finding-model change, no SMB/WMI | ✅                                                  |

---

## 9I. Phase 12 — Windows authenticated scanning over SMB / Remote Registry / WMI

**Gap:** the Windows half of GAP-02, reopened by the September assessment.
**Status: Closed for reach, partial for depth** — 58.1% of the Windows
inventory served natively, real-target validated, and cross-checked against
WinRM on the same host with zero disagreements.

### 9I.1 The limitation this closes

WinRM is **off by default on Windows client editions**. Every Windows
capability this product has — package matching, patch assessment, the
configuration and privilege checks — ran only where somebody had turned WinRM
on or installed OpenSSH. On a workstation estate that is a minority of hosts,
and it was the largest remaining functional difference between this product and
the tools it is measured against, whose primary Windows transport has always
been SMB plus Remote Registry plus WMI.

Nothing was wrong with WinRM. The gap was that it was the only door.

### 9I.2 What was built — a transport, not a second collector

    Credential → transport resolver → SMB / RemoteRegistry / WMI
        → WindowsCollector → existing checks → findings → risk → report

`engines/credentialed/smb_executor.py`. **No new collector, no new scan kind,
no new route, no new finding model, and no change to any parser.** The whole
persistence cost is one value on one CHECK constraint (`d2e3f4a5b6c7`).

The seam that made it possible was already there: `WindowsCollector` asked for
data by _name_ — `_run("os_info")`, `_run_json("services")` — not by command.
So a transport that can answer a name from WMI or the registry answers it, and
one that cannot falls through to the PowerShell it always ran. `_run` gained
that branch; every parser below it is untouched. That is the difference between
a transport and a duplicate collector, and it is why WinRM needed no change.

| Subsystem                       | Used for                                                  |
| ------------------------------- | --------------------------------------------------------- |
| SMB (445/139)                   | session, share enumeration, server identity               |
| Remote Registry (`winreg` pipe) | OS build + UBR, package inventory, security values        |
| WMI/DCOM (`root/cimv2`)         | OS, services, users, groups, hardware, hotfixes, adapters |
| SCMR (`svcctl` pipe)            | service fallback when DCOM is blocked                     |

**It deliberately cannot execute commands.** `run()` refuses. Remote execution
over SMB means creating a service or a scheduled task on the target — which is
what psexec does, writes to a host this product only reads, and is exactly the
elevation mechanism §9H recorded the Windows path as forbidden to invent. So a
command-shaped check reports UNAVAILABLE, the engine renders it ERROR, and no
check ever returns a verdict this transport did not establish. A narrower
honest transport beats a broader dishonest one, and a test guards the refusal
by name.

### 9I.3 Three defects real hardware found, all of which had shipped looking right

- **Shared handles corrupted the session.** `collect_all` runs its sections in a
  thread pool, and neither an impacket `SMBConnection` nor a bound DCE/RPC
  handle is thread-safe. Sharing one made the target reset the connection
  (WinError 10054) part-way through: the software inventory, the OS revision
  and the share list were all lost while the WMI sections that happened to
  finish first succeeded — a _partial_ result that looked like a small host
  rather than a broken scan. Handles are per-thread now. This is the same trap
  the WinRM executor documents for pywinrm sessions, one protocol over, and it
  cost the most valuable field on the host: without the registry read there is
  no UBR, and **without the UBR every Windows host looks like the day-zero
  release of its version and every patch since launch reads as missing.**
- **Remote Registry answers, but not immediately.** The service is
  trigger-started on client SKUs, so the first pipe bind can lose a race with
  its own startup and return `STATUS_PIPE_NOT_AVAILABLE` while a bind two
  seconds later succeeds. Reported as "not supported" on the first attempt, it
  would have silently halved this transport's value.
- **impacket returns structures, not dicts.** `SHARE_INFO_1` supports `[]` and
  has no `.get`, and the remark field is absent rather than empty on some
  servers. The share list failed on a call that reads correct.

### 9I.4 The scanner must not report a condition it created

Binding the registry pipe can **trigger-start the Remote Registry service** —
and this product's own `ccure.win.remote_registry.not_running` check treats a
running Remote Registry as a finding. Left alone, an SMB scan could start the
service and then report the host for having it running.

The service's state is therefore read over SCMR **before** the transport binds
the pipe, once per session, and recorded as
`SMBExecutor.remote_registry_was_running`. On the validation host it was
`StartType: Automatic` and already running, so the finding is genuine there —
but that was established rather than assumed, which is the point.

### 9I.5 Real-target validation — VALIDATED

One live Windows 11 Pro host, read-only throughout: WMI SELECTs, registry
reads, share enumeration. No disposable Windows target was available, and none
was weakened.

**Authentication states, all four distinguished:**

| Case               | Result                                                       |
| ------------------ | ------------------------------------------------------------ |
| Correct credential | authenticated — `PankajM-HPNew` / `Windows 10.0 Build 26100` |
| Wrong password     | `SMBAuthenticationError`                                     |
| Unknown user       | `SMBAuthenticationError`                                     |
| Closed port        | `SMBConnectionError`, _not_ an auth failure                  |

**Port resolution, including non-standard:**

| Case                              | Resolved                               |
| --------------------------------- | -------------------------------------- |
| 445 stated                        | 445 (`credential`)                     |
| discovered on 139 (`netbios-ssn`) | 139 (`discovered`)                     |
| Samba identified on 4445          | 4445 (`discovered`)                    |
| a non-SMB open port (3389)        | refused — never offered the credential |

**Collection through the unmodified `WindowsCollector`:**

| Evidence             | Result                                   |
| -------------------- | ---------------------------------------- |
| OS                   | Microsoft Windows 11 Pro                 |
| Build + UBR          | `10.0.26200.9278` — patch matching works |
| Release              | 25H2                                     |
| Packages             | **419**                                  |
| Running services     | 175                                      |
| Users / groups       | 7 / 1                                    |
| Shares               | 4                                        |
| Recorded as unserved | 10, each with a reason                   |
| Elapsed              | ~60s per host                            |

**Cross-transport agreement — the strongest evidence available.** The same
host, the same checks, both transports, nothing changed in between:

| Measure                              | Result               |
| ------------------------------------ | -------------------- |
| Identity fields compared             | **6 of 6 identical** |
| Checks where both produced a verdict | 6                    |
| **Disagreements**                    | **0**                |

No previous transport in this programme has had an independent implementation
of the same collection to check against.

### 9I.6 Coverage — measured

| Capability                                          | Before                | After                     | Basis                                                                                          |
| --------------------------------------------------- | --------------------- | ------------------------- | ---------------------------------------------------------------------------------------------- |
| Windows hosts reachable                             | WinRM or OpenSSH only | **+ every host with SMB** | SMB is on by default; WinRM is not, on client SKUs                                             |
| Collector items served natively                     | 0                     | **18 of 31 (58.1%)**      | live dispatch table, not a hand list                                                           |
| Unserved items with a stated reason                 | —                     | **13 of 13 (100%)**       | pinned by test                                                                                 |
| Windows checks producing a verdict over SMB         | 0                     | **6 of 20**               | measured on the real host                                                                      |
| Windows checks producing a _wrong_ verdict over SMB | 0                     | **0**                     | the other 13 are ERROR, never PASS — three posture defects found in review and fixed, see 9I.9 |

The honest framing: **SMB widens reach, WinRM keeps depth.** WinRM produced 19
verdicts on the same host to SMB's 6, because it can run commands and SMB
cannot. Neither is a superset of the other and the operator chooses; WinRM
remains the default in `_TYPE_DEFAULTS`.

### 9I.7 A dependency conflict the regression caught, not the unit tests

`impacket` depends on `pyasn1` **without an upper bound**, and installing it
pulled pyasn1 6.x over the `>=0.4.8,<0.6.0` pin this repository already carried
for `pysnmp-lextudio`. That broke SNMP topology discovery — and not with an
import error, which is what makes it worth recording: the FDB table silently
decoded to **one entry instead of three**, so a switch's MAC table came back
nearly empty and the topology read as sparse rather than as broken.

Nothing in the SMB work touched SNMP. It surfaced only because the full
regression runs the topology suite, and it is the argument for running the whole
suite rather than the tests for the thing being built.

impacket 0.12.0 works correctly on pyasn1 0.5.1 — verified against the live
Windows host after the downgrade, WMI and Remote Registry both — so the existing
pin holds and the conflict is recorded beside the new requirement.

### 9I.8 Known limitations

- **13 of 20 Windows built-in checks cannot run over SMB** — the `privilege`,
  `security_policy` and `command` types are PowerShell probes with no registry
  or WMI equivalent. They report ERROR, which is a recorded gap and never a
  pass.
- **13 of 31 collector items are unserved**, each with a stated reason: open
  ports (needs netstat), scheduled tasks (task-scheduler RPC), failed logins
  (event log), password policy (`net accounts`/SAMR), audit policy
  (`auditpol`), firewall profiles, and the privilege context.
- **DCOM needs more than port 445.** WMI negotiates a dynamic high port after
  the endpoint mapper on 135, so a firewall permitting SMB alone yields SMB and
  Remote Registry and no WMI. Each subsystem is opened independently so losing
  one does not lose the others, but the coverage on such a host is smaller and
  the record says so.
- **~60s per host** against ~35s for WinRM. The package inventory is the cost:
  419 packages is roughly 1,250 registry round trips. Correct first; batching
  is available if it matters.
- **One SMB logon per collecting thread.** The price of a transport whose
  handles cannot be shared. Bounded by the collector's thread pool, but it is
  more authentication events in the target's security log than WinRM produces.
- **Kerberos is not wired on this transport.** The credential model admits it
  and impacket supports it; only NTLM is exercised, so a Kerberos-only domain
  is not yet reachable this way.
- **No disposable Windows target exists.** Validation used one live host, so
  the domain-joined case, the standard-user case and Server SKUs are unproven.

### 9I.9 Post-phase review — three integrity defects, found and fixed

A focused read-only review of Phase 12 found two defects, and fixing the first
uncovered a third of the same kind. None could have been caught by the phase's
own tests, which asserted the executor's behaviour rather than the path through
it.

**1. An unserved item became a security verdict.** `_run_json` returns `{}` both
for "the host answered with nothing" and for "this transport never asked", and
the posture code read `{}` as data. Over SMB that meant:

| Unserved input   | Derived                       | Effect                                                                                            |
| ---------------- | ----------------------------- | ------------------------------------------------------------------------------------------------- |
| `telnet_status`  | `telnet_disabled = True`      | **unearned PASS**, reaching compliance rule `crl_telnet_disabled_v1` and a PASS row in the report |
| `netbios_status` | `netbios_disabled = False`    | fabricated finding on every SMB host                                                              |
| `tls_status`     | `legacy_tls_disabled = False` | fabricated finding, with `None` in the message text                                               |

This is the "Never synthesise evidence" defect the compliance engine records for
the hardcoded `password_policy`, reintroduced for one transport.

`WindowsCollector._reading()` now returns `None` for an item the transport did
not serve, and each derivation **omits its key** rather than defaulting it.
Absence then travels the whole path: `registry_hardening` and the evidence
adapter stopped defaulting these keys to `False` — which was the same defect
pointing the other way, a FAIL nothing established — and `None` is dropped by
the adapter's existing `if v is not None`, which the engine reads as unassessed.
`_hardening_row()` gives the report a third state, `NOT_ASSESSED`.

Measured on the real host: `security_issues` went from two fabricated entries to
two genuine ones (a non-default `D$` share, RDP enabled), the three rows render
NOT_ASSESSED, and `smbv1` still returns a real PASS.

**2. A type lost a real verdict.** Found while fixing the first, in the same
function. `read_registry_value` returns text — correctly, because the
configuration-audit collector compares against the string the WinRM path yields
— so `_smbv1_status` handed the collector `"1"` where PowerShell yields `1`. The
collector tests `smb1_raw.get("SMB1", 0) == 1`, and `"1" == 1` is False, so **a
host with SMBv1 genuinely enabled read as SMBv1 disabled**. A false PASS on a
real control, caused entirely by a type. The three registry-flag handlers coerce
with `_as_int` now.

**3. The SCMR fallback was half-built.** `_services` guarded its WMI call and
fell back to SCMR; `query_service` did not. So on a host permitting 445 alone —
the exact firewall shape the fallback exists for — every service _check_
reported ERROR while the service _inventory_ succeeded. SCMR was plumbing with
no assessment value on the check path.

Validated against the live host with DCOM blocked client-side, nothing on the
target changed:

| Check                             | Result                                         |
| --------------------------------- | ---------------------------------------------- |
| Remote Registry still reachable   | UBR read                                       |
| `query_service` real state        | `Running`, `source: scmr`                      |
| Absent service                    | absent, not an error                           |
| Inventory fallback                | **387** services via SCMR against 175 via WMI  |
| Service checks producing verdicts | **3 verdicts, 0 errors** (previously 3 errors) |

SCMR sees more than WMI because WMI omits driver services — the difference this
transport documented from the start and could not previously act on.

All three fixes are mutation-verified, and the tests now walk
`SMBExecutor → WindowsCollector → registry_hardening → evidence adapter →
report row` rather than the executor alone.

### 9I.10 Definition of Done — Phase 12

| Line                                                                             | Result                                                 |
| -------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Reuses credential model, resolver, `BaseExecutor`, `WindowsCollector`, scan flow | ✅ one seam in `_run`; nothing else changed            |
| No parallel Windows engine                                                       | ✅ no new collector, scan kind, route or finding model |
| SMB / Remote Registry / WMI                                                      | ✅ all three, plus SCMR as the service fallback        |
| Non-standard ports                                                               | ✅ 139 and a Samba port resolved from discovery        |
| WinRM preserved                                                                  | ✅ untouched and still the default; pinned by test     |
| Auth success / failure / unavailable distinguished                               | ✅ four error types, validated on real hardware        |
| Unavailable never becomes PASS                                                   | ✅ mutation-verified                                   |
| Automated tests                                                                  | ✅ 36, mutation-verified in two directions             |
| Real-target validated                                                            | ✅ 18/18 checks; 0 disagreements with WinRM            |
| Migration round-trip                                                             | ✅ upgrade → downgrade → upgrade on the live schema    |

---

## 9J. Phase 13 — Credential authentication methods

**Not a capability phase and no coverage figure moves.** Authentication methods
decide _how many hosts can be logged into_, not what is assessed on them. Three
methods were added, three were refused with reasons, and two pre-existing
defects were found while doing it. Not one check was added, and no gap
percentage changes as a result — saying otherwise would be exactly the coverage
inflation this tracker exists to prevent.

### 9J.1 The rule this phase applies

The credential store already had it, for transports and credential types:
**the column admits a reserved value so a later phase adds a mechanism rather
than a migration, and the API refuses it so nobody saves a credential that
cannot authenticate.** `USABLE_TRANSPORTS` and `USABLE_CREDENTIAL_TYPES` are
that rule. `auth_method` never had an equivalent, and Kerberos is what happens
without one.

### 9J.2 Kerberos — refused, not half-implemented

`auth_method = "kerberos"` was accepted by the API, by the credential model and
by `WinRMExecutor`. The runtime had no Kerberos at all: pywinrm raises
`requested auth method is kerberos, but pykerberos is not installed` at the
**first command**, so the credential authenticated nothing and failed on the
customer's network rather than at the moment somebody saved it.

Implementing it properly needs a GSSAPI stack, a ticket cache and a domain
controller to validate against. None was available, and shipping an unvalidated
Kerberos path would be the fake support this programme refuses. So:

- `USABLE_AUTH_METHODS` is added and excludes it; the API validates against that
  rather than against the column's vocabulary.
- It is **not** removed from the CHECK constraint — narrowing it would mean an
  ALTER on a table of live encrypted credentials to delete a value nothing can
  create, and would make the phase that implements Kerberos need a migration.
- `WinRMExecutor` refuses it **at construction**, naming a method that does
  work, instead of at the first command.

Verified before removing it: zero stored credentials used it.

**CredSSP was explicitly out of scope and is not present anywhere.**

### 9J.3 Pass-the-Hash — implemented and real-target validated

`auth_method = "ntlm_hash"`. The NT hash is presented where a password would be,
so a domain estate need not store a reversible plaintext password in this table
to be scanned — a security improvement to the credential store, not only a reach
improvement.

- The hash lives in `encrypted_password`, encrypted at rest exactly as a
  password is. A column of its own would be a migration for no gain.
- **It never leaves `_resolve_stored_credential` as a `password`.** The material
  dict feeds every transport, and a hash arriving as a password would be
  presented as plaintext against the account by any of them.
- **The password is not sent alongside it.** `login(user, "", domain,
lmhash=…, nthash=…)`: passing both would let impacket fall back to the
  password if the hash were refused — two failed logons instead of one, and no
  way to tell which material the target rejected.
- The LM half is the documented all-zero placeholder. Computing a real one would
  mean holding the plaintext this method exists to avoid, and modern Windows
  does not accept LM authentication.
- `LM:NT` is accepted as well as a bare NT hash, because that is the form every
  dumping tool prints. Anything that is not 32 hex characters is **refused
  rather than sent**: an unparsed value would be presented as though it were a
  hash and produce a failed logon against a real account — a lockout caused by a
  typo. The refusal does not quote the value.

**Validated against a live Windows 11 Pro host**, hash derived in memory from
the known password and never written anywhere:

| Case                                              | Result                                          |
| ------------------------------------------------- | ----------------------------------------------- |
| Authenticate by hash, no password supplied        | ✅ `PankajM-HPNew` / `Windows 10.0 Build 26100` |
| Remote Registry over the PtH session              | ✅ UBR read                                     |
| Wrong hash **with a valid password also present** | ✅ refused — no fallback                        |
| `LM:NT` paste form                                | ✅ NT half used                                 |

### 9J.4 Encrypted SSH keys — and a pre-existing defect they uncovered

Passphrase-protected private keys are supported: `encrypted_key_passphrase`, its
own column because overloading `encrypted_password` would make
`AUTH_REQUIRES_PASSWORD` — a data-integrity rule — mean two incompatible things
at once. It is held privately on the session, wiped by `disconnect`, redacted
from anything logged, and kept out of raised exceptions.

**Adding it revealed that key-content authentication was broken outright.**
`SSHScanner.connect` called `paramiko.pkey.load_private_key`, **which does not
exist in paramiko 4**. Every key-content credential therefore failed with
`module 'paramiko.pkey' has no attribute 'load_private_key'`, re-raised as
"Failed to parse private key content" — so the fault read as a malformed key
supplied by the operator rather than as a call to a function that was never
there. Nothing exercised the path, because nobody in this deployment uses key
auth: all three stored credentials are passwords.

`_load_private_key` replaces it, trying Ed25519, RSA and ECDSA in turn because
paramiko has no auto-detecting loader for a string. An encrypted key with no
passphrase reports exactly that, which is a different thing to tell an operator
than "not a key I recognise".

### 9J.5 Linux elevation — two added, three refused

The command catalogue is written in terms of `sudo`; `_rewrite_sudo_for_stdin`
now substitutes the configured program, so a host using another needs no second
catalogue. The method is a per-credential setting in `options`, not a column: it
is not a secret, and `options` is already where per-credential transport
settings live.

| Method   | Status                                 | Basis                                                                                                                                                                                                                                                                         |
| -------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo`   | implemented, **real-target validated** | unchanged; validated in §9H                                                                                                                                                                                                                                                   |
| `dzdo`   | **implemented, not validated**         | Delinea/Centrify document it as a drop-in sudo replacement with compatible options, so the same rewrite drives it. No Centrify instance was available.                                                                                                                        |
| `pfexec` | **implemented, not validated**         | Solaris RBAC authorises from the account's profile, so no password is written — one would sit unread in the command's stdin where the command could consume it. It accepts none of sudo's options, so they are dropped rather than translated. No Solaris host was available. |
| `su`     | **unsupported**                        | reads its password from the controlling terminal, not stdin, so driving it needs a PTY — which merges stderr into stdout and echoes the prompt into the output every command in the catalogue is parsed from                                                                  |
| `pbrun`  | **unsupported**                        | BeyondTrust's option syntax is not sudo's, it is policy-server driven, and no instance was available. Shipping an untested translation of somebody's privilege-escalation command is how a scanner runs the wrong thing as root.                                              |
| `ksu`    | **unsupported**                        | authenticates with a Kerberos ticket, and Kerberos is not supported on any transport in this build                                                                                                                                                                            |

An unsupported method **elevates nothing rather than guessing**: the command
runs unprivileged and whatever it could not read is recorded as unavailable,
never as a clean result.

### 9J.6 SMB remote execution — still refused

Unchanged and deliberately so. No `New-Service`, no scheduled task, no
PsExec-shaped execution, no remote service creation. `SMBExecutor.run()` still
returns UNAVAILABLE and the guard test still names each mechanism. The
`SCAN_ALLOW_INTRUSIVE` policy remains available for genuinely intrusive checks
and was not used to smuggle this in.

### 9J.7 Security validation

Every new secret was checked against the surfaces it could reach — 9 of 9:

| Surface                    | Passphrase                                | NT hash        |
| -------------------------- | ----------------------------------------- | -------------- |
| Raised exceptions          | ✅ absent                                 | ✅ absent      |
| Log records (DEBUG and up) | ✅ absent                                 | ✅ absent      |
| `repr()` of the session    | ✅ absent                                 | ✅ absent      |
| Wiped on `disconnect`      | ✅                                        | ✅             |
| Command line / argv        | never placed there — stdin only           | not applicable |
| Celery arguments           | resolved worker-side from `credential_id` | same           |

gitleaks passes on the commit, as do black, ruff and bandit.

### 9J.8 Coverage impact — none, deliberately

No check was added, so no capability percentage moves. What changed is the set
of hosts those checks can reach: an estate on passphrase-protected keys, or one
that will not release plaintext domain passwords, was previously unreachable and
now is not. That is worth recording and is **not** a coverage number.

### 9J.9 Two defects the full regression caught that the targeted tests did not

Both were mine, and both are worth recording because the targeted tests passed
while the code was broken.

**A constant that was referenced and never defined.** `_resolve_stored_credential`
branches on `AUTH_METHOD_NTLM_HASH`, which was imported but never added to the
model — so the resolver raised `ImportError` on **every** credential, not only
hash ones. The credential-validation endpoint catches broadly and reported it as
a generic `failed`, which is how it surfaced: as a Phase 2 test asserting
`authentication_failed`.

The targeted test for this missed it because it reads the source with
`inspect.getsource` and asserts the line is written. Reading the source proves
the line exists; only calling it proves the line runs. Two behavioural tests
were added that construct a real credential and resolve it.

**A second constraint naming the same vocabulary.** `ck_compliance_credential_auth`
renders `AUTH_REQUIRES_PASSWORD`, so adding `ntlm_hash` to the model's tuple
without moving that constraint left a schema that admits the method in one
constraint and rejects every row using it in the other. The migration moves
both now.

The scratch test database needed the change applied directly, for the reason
CLAUDE.md already records: `_build_test_schema` bootstraps from the models and
stamps head, and **CHECK constraint changes are not gap-filled**.

### 9J.10 Definition of Done — Phase 13

| Line                              | Result                                                         |
| --------------------------------- | -------------------------------------------------------------- |
| Kerberos resolved                 | ✅ refused at API, model and executor; reserved in the column  |
| CredSSP                           | ✅ not implemented, and absent everywhere                      |
| SSH key passphrase                | ✅ implemented, tested; uncovered and fixed a broken key path  |
| Pass-the-Hash                     | ✅ implemented, tested, **real-target validated**              |
| No fallback from hash to password | ✅ mutation-verified                                           |
| Elevation methods                 | ✅ 2 implemented (unvalidated, stated), 3 refused with reasons |
| SMB remote execution              | ✅ still refused, guard intact                                 |
| No parallel auth framework        | ✅ same model, resolver, executors and scan path               |
| Secrets contained                 | ✅ 9 of 9 surfaces                                             |
| Migration round-trip              | ✅ upgrade → downgrade → upgrade on the live schema            |
| Coverage inflated                 | ✅ no — no figure moved                                        |

---

## 9K. Loading published STIG content — the Phase 10 reader applied to real benchmarks

**Content, not code.** Phase 10 built the SCAP reader and validated it against
two live hosts and against `oscap`. Nothing was ever loaded. Measured on the
live catalogue immediately before this work:

| Measure                                          | Before |
| ------------------------------------------------ | ------ |
| Frameworks with the `cfw_bm_` prefix             | **0**  |
| `compliance_rules` with `check_type='scap_rule'` | **0**  |
| `compliance_rules` carrying a `config_check`     | **0**  |

So the Phase 3 engine, the Phase 4 pack loader and the Phase 10 converter were
all present, tested and loading nothing. The product's assessable content was
the 155 Python built-ins. This section is the record of closing that, and of
the one defect that made it impossible.

### 9K.1 What was loaded, and what was deliberately not

Source: **SCAP Security Guide v0.1.81**, published 2026-06-01, BSD-3-Clause,
from the ComplianceAsCode release page. **Nothing is committed to this
repository** — the datastreams and the converted packs live outside the tree
under `D:/ccure-feeds/scap/`, which is also why `Backend/data/benchmarks/` was
left alone: it is not gitignored, so a pack written there is one `git add -A`
away from committing content.

The release ships **38 datastreams and every one is Linux**. SSG publishes no
Windows content at all, which is independent confirmation of Phase 10's
decision to declare the whole Windows OVAL schema out of scope rather than ship
it unvalidated.

Six were extracted as candidates; **only four carry an
`xccdf_org.ssgproject.content_profile_stig` profile**. Debian 12 and AlmaLinux 9
publish CIS and ANSSI profiles but no STIG, so they are not STIG content and
were not converted as though they were.

| Benchmark         | Controls | Automated       | Manual | Unimplemented | NIST crosswalk |
| ----------------- | -------- | --------------- | ------ | ------------- | -------------- |
| `STIG_RHEL9`      | 488      | **257** (52.7%) | 8      | 223           | 409            |
| `STIG_RHEL8`      | 392      | **218** (55.6%) | 9      | 165           | 315            |
| `STIG_UBUNTU2404` | 240      | **144** (60.0%) | 5      | 91            | 151            |
| `STIG_UBUNTU2204` | 230      | **138** (60.0%) | 5      | 87            | 146            |
| **Total**         | **1350** | **757**         | 27     | 566           | 1021           |

RHEL 9's **257** and Ubuntu 24.04's **144** reproduce Phase 10's recorded
validation figures exactly, including the 144 that `oscap` 1.3.9 agreed with
144/144 — and the `local_variable` gap comes back as 97 + 14 = **111** rules on
RHEL 9, the precise number §9D.9 names. The converter is deterministic against
the same content, which is what those numbers being reproducible proves.

Content digests, recorded because `--expected-digest` was supplied on every
conversion and a mismatch is refused:

| Datastream              | SHA-256                                                            |
| ----------------------- | ------------------------------------------------------------------ |
| `ssg-rhel9-ds.xml`      | `c5399594781184f6a0b223dbc74b3bb2730dfdb0a6791ba8b233e3c9b7c36252` |
| `ssg-rhel8-ds.xml`      | `92106d0a737b2f9ad5d1db77f4a41635c31faf519cc27f4d0eab456a864eb5be` |
| `ssg-ubuntu2404-ds.xml` | `1e0a80f096a0c4ae86bbc6374b5897c33d303c585c681ae6fbc1f760d9c08742` |
| `ssg-ubuntu2204-ds.xml` | `e85f31b6780821a1b27dce6d9865a41a2c7985e12fc14df1070143401db4ab53` |

`--publisher "SCAP Security Guide"` and `--licence BSD-3-Clause` were supplied
on every load and are on all four framework records. **An SSG result is not a
DISA certification** and the record has to be able to say so.

### 9K.2 The ceiling that made the load impossible

The first load failed outright:

    load failed, nothing written: value too long for type character varying(50)
      control_number: harden_sshd_ciphers_opensshserver_conf_crypto_policy   (52 chars)

`compliance_controls.control_number` was `varchar(50)`, and its comment says
what it was sized for: `# e.g. "8.24"`. Every one of the thirteen catalogues
that ships in this repository numbers its controls — `8.24`, `A.5.1`,
`PR.AA-05` — so the ceiling was invisible for thirteen frameworks and for both
CCURE baseline packs.

**A benchmark recommendation is not numbered, it is named.** Measured across
the four packs: 1,350 controls, of which **24 exceed 50 characters**, longest
**62**.

Two things make this worth recording rather than just fixing:

- **It is the `cve_id varchar(30)` defect again**, one table over. There too a
  minted identifier overflowed a column sized for a different kind of
  identifier, and there too the failure was not local: the load is one
  transaction, so seven over-long controls rejected all 488 of RHEL 9's.
- **Phase 10 could not have caught it.** Its validation evaluated converted
  packs against live hosts — the path that proves the OVAL probes work. The
  path from a converted pack _into the catalogue_ was only ever exercised with
  the two CCURE baseline packs, whose control numbers are short. A reader can
  be fully validated and still have never written a row.

Migration **`f4a5b6c7d8e9`** widens the column to 100, matching the sibling
`compliance_controls.id` this value is slugged into. Round-tripped on the live
schema: 50 → 100 → 50 → 100.

**Truncating to fit was rejected**, and the constraint is the argument:
`uq_framework_control_number` is UNIQUE on `(framework_id, control_number)`, so
two sibling recommendations sharing a 50-character prefix would collide — one
row standing for two different requirements in a compliance report. That is the
rule `definition_id_for_check` already applies to catalogue identifiers, and the
reason it refuses an over-long id rather than shortening it.

Measured after the load: longest stored `control_number` is **62**, with **24
rows over 50** — the migration is load-bearing, not precautionary.

### 9K.3 Two failures that were not data failures

Both rolled back cleanly, and both are recorded because they look alarming in a
log and are not.

- **The truncation above.** `load_stig --load` wraps the write and reported
  `load failed, nothing written`. Verified against the database: 0 benchmark
  frameworks, `compliance_controls` still 956. The handling is correct.
- **A `UnicodeEncodeError` on the Windows console.** `load_benchmark.py` prints
  an em-dash in its per-pack summary; the default cp1252 console cannot encode
  it, and the resulting exception reached the script's own rollback. The
  transaction protection worked — nothing was written — but **the operation
  failed for a reason that has nothing to do with the data**. Worked around
  with `PYTHONIOENCODING=utf-8`. Recorded in the carry-forward list, not fixed
  here: it is a portability defect in a script this section merely used.

### 9K.4 Result

| Measure                   | Before | After    | Δ         |
| ------------------------- | ------ | -------- | --------- |
| Frameworks                | 13     | 17       | +4        |
| Benchmark frameworks      | 0      | **4**    | +4        |
| `compliance_controls`     | 956    | **2306** | **+1350** |
| `compliance_rules`        | 1357   | **2114** | **+757**  |
| …active                   | 770    | 1527     | +757      |
| …`check_type='scap_rule'` | 0      | **757**  | +757      |
| Rule → control links      | 2773   | 3530     | +757      |

All four load as `tenant_id IS NULL` global frameworks, and `is_active()`
returns True for each through `BENCHMARK_FRAMEWORK_PREFIX` — loading a benchmark
_is_ the decision to use it, so no second installation-wide activation step
exists or is needed.

### 9K.5 The tenant gate — and the install that made the content live

`benchmark_checks_for_org` applies **two** gates, and loading satisfies only
one. The second is `ComplianceTenantFramework.is_enabled`. Immediately after
the load, **0 tenant rows existed for `cfw_bm_%`** against 52 for the shipped
catalogues — so all 757 rules would have selected **nothing** on a scan.
Content that loads cleanly and then silently scores nothing is precisely the
failure the `cfw_bm_` prefix exists to prevent one layer up, and it is
reachable again at the tenant layer.

That is the designed two-layer model rather than a defect:
`POST /compliance/marketplace/{id}/install` is the path,
`require_active_framework` admits a `cfw_bm_` id, and
`GET /compliance/marketplace` discovers loaded benchmarks from the catalogue
precisely because they can never appear in a hardcoded tuple.

All four were installed for **`org_default`** by calling the product's own
`install_marketplace_framework` handler rather than writing tenant rows by
hand. That distinction matters: the handler also bootstraps the framework's
default policy baseline and links every active rule into it, so an install
assembled from SQL would have produced a tenant row with no policy behind it.
It also writes an audit event, so the install is on the record.

**`org_king` is empty** — no users at all. Its _name_ is "superadmin", which
makes it read as the administrator's organisation in any listing; the
superadmin account `admin@ccurepro.com` is in `org_default`, together with the
org_admin and both analysts. Recorded because the name will mislead the next
person too.

Verified after installing:

| Measure                                              | Result                                               |
| ---------------------------------------------------- | ---------------------------------------------------- |
| Frameworks in scope for `org_default`                | 6 — ISO 27001, NIST CSF 2.0, and the four benchmarks |
| Executable checks `benchmark_checks_for_org` returns | **757**                                              |
| Their `check_type`                                   | `scap_rule`, all 757                                 |
| Their platform targeting                             | `linux`, all 757                                     |
| Severity spread                                      | 55 high, 646 medium, 56 low                          |

The other three organisations were deliberately left alone. Installing is one
reversible boolean per (tenant, framework) and `POST …/uninstall` is the path
back.

What is worth recording is that **`scripts/set_active_frameworks.py` cannot do
this.** It iterates `ALL_FRAMEWORK_IDS`, the thirteen shipped catalogues, so a
loaded benchmark has no command-line installation path — only the API. That is
a real gap in the Phase 4 loading story and is left as a recorded decision
rather than patched in passing.

### 9K.6 Validation status — stated precisely

The programme's rule is that content loading is not capability. Distinguishing
what this actually establishes:

| Claim                                                                     | Status                                          |
| ------------------------------------------------------------------------- | ----------------------------------------------- |
| Content converts with zero errors                                         | ✅ all four, digests pinned                     |
| Conversion reproduces Phase 10's validated figures                        | ✅ RHEL 9 257, Ubuntu 24.04 144, exactly        |
| Content loads into the catalogue                                          | ✅ 1350 controls, 757 rules, one transaction    |
| Frameworks are active and installable                                     | ✅ verified in code and against the database    |
| Installed for a tenant, via the product's own handler                     | ✅ `org_default`, default policy baseline built |
| Catalogue → selection returns executable checks                           | ✅ **757**, all `scap_rule`, all `linux`        |
| Ubuntu 24.04 rules evaluate against a live host, from the catalogue       | ✅ **§9L** — 144 rules, real host, 0 errors     |
| RHEL 8 / Ubuntu 22.04 rules evaluate against a live host                  | ❌ **never target-validated**                   |
| A credentialed scan evaluates these **catalogue-loaded** rules end to end | ✅ **real-target validated — see §9L**          |

The last two rows were the honest limit of this section when it was written,
and the final one has since been closed. Phase 10 proved
pack → engine → verdict against Rocky 9 and Ubuntu;
catalogue → `benchmark_checks_for_org` → engine → verdict against a live host
was left unproven because it needs a tenant install and a credentialed scan.
**§9L is that run** — 144 Ubuntu 24.04 rules evaluated on real hardware, zero
errors, three verdicts cross-checked against the machine's own configuration,
and one defect found and fixed in the process.

RHEL 8 and Ubuntu 22.04 remain target-unvalidated: the Ubuntu 24.04 host
correctly reported all 356 of their rules NOT_APPLICABLE, which exercises the
targeting but says nothing about their checks.

RHEL 8 and Ubuntu 22.04 introduce **no OVAL test type** that RHEL 9 and Ubuntu
24.04 did not already exercise, so the conversion is on proven ground — but
"the mechanism is the same" is an argument, not a measurement, exactly as
§9F.7 records for FTP AUTH TLS.

### 9K.7 Coverage — no figure moves, deliberately

`scripts/measure_scap_coverage.py` measures the **reader** against the SCAP
surface: 52 frozen areas, 33 implemented, 63.5%. Loading content does not
implement an OVAL test type, so the figure is unchanged and must be.

What changed is not a percentage but the denominator of the product's useful
work: assessable Linux hardening content went from **155 built-in checks** to
**155 + 757 = 912**, of which the 757 are published, attributable, versioned
and crosswalked to NIST SP 800-53 on 1,021 controls. That is the largest single
increase in assessable content in the programme, and it required one migration
and no new engine.

---

## 9L. Real-target validation of the catalogue → credentialed scan → verdict path

§9K.6 recorded one unproven link and named it precisely: no credentialed scan
had run a **catalogue-loaded** STIG rule against a real Linux host and produced
a verdict. Phase 10 proved pack → engine → verdict against containers; this
closes the remaining arrow, on real hardware, and found one defect doing it.

### 9L.1 Target and method

`10.180.6.45` — **Ubuntu 24.04.4 LTS, kernel 6.8.0-138-generic**. A real kernel
rather than a container, so the `system_with_kernel` platform that suppressed
most rules in Phase 10's validation is satisfied here and the rules behind it
are reachable.

The credential was created through the product's own encrypted store
(`POST /compliance/credentials` → `encrypt_credential`), and the scan was
dispatched exactly as `routers/credentialed.py` dispatches it —
`run_credentialed_scan_task.delay(..., credential_id=…, password=None)`. The
worker resolves the secret itself, so **no credential appears in the broker
payload, the task arguments, the logs or this repository**. The account is an
ordinary unprivileged user: `id -u` 1000, sudo present but password-gated.

### 9L.2 The defect this found, on the first run

Scan 47 authenticated, collected for 615 seconds, and then **failed**:

    StringDataRightTruncation: value too long for type character varying(30)
      id:              CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING   (37 characters)
      cve_id:          CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING
      definition_type: cve

`core/tasks._sync_credentialed_vulnerabilities` wrote `cve_id=cve_id`
unconditionally and set no `definition_type`, so every entry took the column
default `'cve'`. `cve_list` deliberately carries configuration and privilege
findings alongside package CVEs — `_run_configuration_audit` documents that as
the design — so the assumption that every entry is a CVE was wrong for all of
them.

**This is the `cve_id varchar(30)` defect CLAUDE.md already records, on a second
write path.** The network path was fixed in Phase 6 via `definition_type_for_id`;
`asset_syncer` carries the fix and a comment explaining it. The credentialed
path never got it.

Two consequences, one loud and one silent:

- **Loud.** The catalogue insert is inside the finding sync, so the first
  over-long identifier **aborted the sync for the entire scan** — the 833
  package CVE findings were lost along with the configuration findings, and the
  scan reported `failed` after having done all the work correctly.
- **Silent.** Where a minted id _did_ fit in 30 characters, the row was filed as
  a `cve`: inheriting KEV lookups, EPSS scores, CVSS bands and an NVD link that
  resolves to nothing. `ck_vuln_def_cve_id_matches_type` could not catch it,
  because the row did carry a `cve_id` — just not a real one.

Note what this says about the built-in content: the failure is triggered by
`ccure.linux.auditd.running`, a **Phase 3 built-in**, not by STIG content. Any
credentialed Linux scan producing a configuration finding with an identifier
over 30 characters failed this way. It was not found earlier because Phases 3
and 5 validated the _engine_ against containers rather than the full scan →
sync → finding path — the same shape of gap as §9K.2, where a fully validated
reader had never written a catalogue row.

**The fix** mirrors `asset_syncer` exactly rather than inventing a variant:
derive `definition_type` from the identifier, NULL `cve_id` for anything that is
not a published CVE, skip the CVE-feed lookup for check identifiers, take the
title from the shared `_catalog_title`, and replace the package-shaped evidence
block — which for a check read "Package: unknown", "Fixed in: no fixed version
published" and a dead NVD link — with the check's own expected-versus-observed
reading.

**Guarded by three tests** in `tests/credentialed/test_config_audit_findings.py`,
all mutation-verified — reverted against the unfixed function, all three fail;
restored, all three pass. They drive the real `_sync_credentialed_vulnerabilities`
against a real session rather than reading its source, which is the lesson
§9J.9 records: a line that exists is not a line that runs. Nothing had covered
this function at all before.

### 9L.3 Result — scan 48

Completed in **184.5 seconds**, `hosts_failed: 0`, **902 findings**: 833 `cve`,
62 `config_check`, 7 `privilege_check`. Catalogue integrity over every row the
scan wrote: **0 non-CVE rows carrying a `cve_id`, 0 `cve` rows with a NULL
one.**

All **757** catalogue-loaded STIG rules were evaluated, and the distribution is
exactly what the content and the target predict:

| Framework                | pass | fail | not_applicable | manual_review | error |
| ------------------------ | ---: | ---: | -------------: | ------------: | ----: |
| `cfw_bm_stig_ubuntu2404` |   22 |   58 |             59 |             5 | **0** |
| `cfw_bm_stig_ubuntu2204` |    — |    — |            138 |             — | **0** |
| `cfw_bm_stig_rhel9`      |    — |    — |            257 |             — | **0** |
| `cfw_bm_stig_rhel8`      |    — |    — |            218 |             — | **0** |
| **Total**                |   22 |   58 |            672 |             5 | **0** |

Two things to read off that table. The four numbers for Ubuntu 24.04 sum to
**144**, which is exactly that benchmark's automated rule count — every rule
reached a state, none was skipped. And the other three benchmarks are
**entirely NOT_APPLICABLE**: the Phase 4 `applies_to` targeting correctly
withheld 613 RHEL and Ubuntu 22.04 rules from an Ubuntu 24.04 host, rather than
running them and reporting their absence as a verdict.

**Zero errors**, which is what §9D claimed for the pack path and is now shown
for the catalogue path.

### 9L.4 Evidence checked against the host, not taken on trust

Three verdicts were cross-checked directly against the machine:

| Rule                           | Verdict | Evidence recorded                                           | Host                                         |
| ------------------------------ | ------- | ----------------------------------------------------------- | -------------------------------------------- |
| `package_audit_installed`      | FAIL    | `linux:dpkginfo_object: 0 item(s) collected … all_exist`    | `unknown ok not-installed` ✅                |
| `package_telnetd_removed`      | PASS    | `the host is in the state the rule requires`                | not installed ✅                             |
| `accounts_password_pam_minlen` | FAIL    | `textfilecontent54_object: 0 item(s) … at_least_one_exists` | no active `minlen`; file wholly commented ✅ |

The evidence is diagnostic rather than decorative: it names the OVAL object and
the existence check that was not satisfied, which is what makes a FAIL
actionable without re-running the scan by hand. 56 of the 58 FAILs also carry
SSG's own remediation text.

`oscap` was **not** used as a cross-check here. It is absent from the target and
installing it means adding software to a machine this exercise is not permitted
to modify. Phase 10 already established 144/144 agreement with `oscap` on this
exact Ubuntu 24.04 content, so what was unproven was the catalogue path, not the
rule semantics — and the host's own configuration is a more direct check of
those three verdicts than a second scanner would have been.

### 9L.5 The most important result: privilege degraded safely

Five rules returned **MANUAL_REVIEW**, and every one is an unprivileged read:

    /etc/sudoers  Permission denied  — sudo_remove_nopasswd,
                                       sudo_require_authentication,
                                       sudo_restrict_privilege_elevation_to_authorized
    /etc/shadow   Permission denied  — no_empty_passwords_etc_shadow,
                                       prevent_direct_root_logins

CLAUDE.md records that the configuration-audit collectors **do not elevate** —
`ShellRunner` has no sudo path, so every check reads what the scanning account
can read. This is that limitation meeting a real host, and the outcome is the
one the architecture exists to produce: a read that failed became
**MANUAL_REVIEW, not PASS and not FAIL**.

`no_empty_passwords_etc_shadow` is the case worth stating plainly. The collector
saw zero items. A scanner that treated "0 items collected" as "no empty
passwords found" would report a **PASS on one of the most security-critical
checks in the benchmark**, on a file it never read. The four collection states
were not collapsed, under real insufficient privilege, on real hardware. That is
the invariant `core/checks/contract.py` was written for, demonstrated rather
than asserted.

### 9L.6 Finding and report linkage

The 58 STIG FAILs reach `asset_vulnerabilities` with correctly minted
`CCURE-CFG-RULE-STIG-UBUNTU2404-…` identifiers, `definition_type =
config_check` and `cve_id` NULL. A technical PDF was generated
(`credentialed_scan_01-09-2026_20-29-40_technical.pdf`, 891 KB) from the same
902-finding payload the phase summary records, and `pdf_generator.py:1256`
resolves a finding's identifier as `primary_cve or plugin_id`, so a finding with
no CVE renders under its minted id rather than blank.

**Stated as a limit rather than a claim:** the rendered PDF text was not read.
No PDF text-extraction library is present and installing one would modify the
environment. The linkage is therefore verified at the data layer and in the
generator's code, not by reading the artefact.

### 9L.7 Recorded, not fixed

- **`compliance_findings.scan_run_id` is empty for configuration verdicts**, and
  `source` is `auto_scan` for all 757. The verdicts carry `last_seen` and
  nothing else tying them to the scan that produced them, so "which run
  established this" is answerable only by timestamp. Findings on the
  vulnerability side do carry `scan_id`.
- **NOT_APPLICABLE carries no `not_assessed_reason`** — for all 672, including
  the 613 withheld by OS targeting. The verdict is right and the reason is
  correct, but a reader cannot tell "wrong operating system" from any other
  cause without going to the benchmark.
- **The minted identifiers double a prefix**:
  `CCURE-CFG-RULE-STIG-UBUNTU2404-…`, because the rule row id already begins
  `rule_stig_…`. Cosmetic, stable, and not worth a migration on live findings.
- **Two of the 58 FAILs carry no remediation text**, which is a property of the
  SSG content rather than of the conversion.
- **The project virtualenv had no `impacket`, so Phase 12's SMB transport could
  not run in the worker at all.** Found here because this section's regression
  used the venv interpreter while every earlier baseline in this tracker used
  the global Python 3.12, where an earlier session had installed impacket by
  hand — so `test_smb_transport.py` passed there and failed here. **Fixed in
  §9M**, which also corrects the diagnosis recorded at the time: the hazard is
  not `pyasn1` but `pyOpenSSL`/`cryptography`, and the cause was a stale
  environment rather than a dependency conflict.

- **`detection_method` is `credentialed_package` and `source_family` is
  `credentialed_package` on configuration findings**, because the write path is
  shared with package matching. Pre-existing, unchanged by this work, and it
  affects how those findings group in a report. Changing it moves finding
  grading and deserves its own decision.

### 9L.8 Coverage

**No coverage figure moves, and none should.** `measure_scap_coverage.py`
measures the reader against the SCAP surface — 52 frozen areas, 33 implemented,
**63.5%**. This exercise implemented no OVAL test type and loaded no content;
it proved a path. GAP-05 stays **Closed at 63.5%**, now with the
catalogue → credentialed scan → verdict link validated on a real host rather
than declared.

---

## 9M. The worker runtime did not have the SMB dependency

§9L.7 recorded that `Backend/.venv` had no `impacket`, so Phase 12's Windows
transport could not run in the process that actually runs scans, and left it
unfixed on the stated grounds that installing it would break SNMP. **That
reasoning was wrong**, and the real conflict turned out to be somewhere else
entirely. This section is the correction and the fix.

### 9M.1 Root cause: a stale environment, not a conflict

`requirements.txt` has declared `impacket==0.12.0` since **`4a88723`** — the
Phase 12 commit that added the transport. Nothing was missing from the
declaration. The virtualenv was simply never reinstalled afterwards.

Measured before the fix: **44 of the 45 declared distributions were present and
`impacket` was the only one absent.** Not dependency resolution, not a conflict
— an environment that had drifted from the file that describes it.

It survived a day and two phases because the _developer's global_ Python 3.12
had been given impacket by hand in an earlier session. Every regression figure
in §12 was produced there. So `tests/credentialed/test_smb_transport.py` passed
in the interpreter nobody deploys and failed in the one the worker runs, and a
green suite said nothing about the runtime.

### 9M.2 The conflict that is real, and it is not pyasn1

The recorded fear was that `impacket` would drag `pyasn1` past the
`<0.6.0` pin that `pysnmp-lextudio` needs. A dry run settles it: with both
requirements named, **pip does not touch `pyasn1` at all** — impacket asks for
`>=0.2.3` and 0.5.1 satisfies it. The pin does its job.

The actual conflict was one layer down and had already done damage:

| Package          | Requires                    |
| ---------------- | --------------------------- |
| impacket 0.12.0  | `pyOpenSSL==24.0.0` (exact) |
| pyOpenSSL 24.0.0 | `cryptography<43,>=41.0.5`  |
| **sslyze 6.3.1** | **`cryptography>=43,<47`**  |

These cannot both hold. Installing impacket 0.12.0 downgrades `cryptography`
to 42.0.8 and leaves sslyze out of contract — which is exactly the state the
global interpreter was already in, and `pip check` says so in those words:

    sslyze 6.3.1 has requirement cryptography<47,>=43, but you have cryptography 42.0.8

That reaches further than TLS scanning. `cryptography` is also depended on by
`paramiko`, `pysnmpcrypto`, `pyspnego` and `requests_ntlm` — so the downgrade
touches SSH, SNMPv3 and WinRM NTLM as well. **The earlier session that
installed impacket globally silently broke sslyze's dependency contract**, and
the tracker recorded the wrong package as the hazard.

`requirements.txt` did not prevent it because its `cryptography` range was
`>=41.0.0,<48`, which _permits_ 42.0.8. The lower bound is now `>=43`, sslyze's
own, so a dependency that caps cryptography below it fails resolution instead
of silently winning.

### 9M.3 Version chosen: impacket 0.13.1

**impacket 0.13.1 declares `pyOpenSSL` with no version constraint**, where
0.12.0 pins it exactly. Dry-run with both project pins held names what it
would install:

    Flask Werkzeug blinker impacket-0.13.1 itsdangerous ldap3
    ldapdomaindump pyOpenSSL-26.2.0 pyasn1_modules pycryptodomex pyreadline3

`cryptography` and `pyasn1` are **absent from that list** — neither is
displaced. 0.13.1 also drops 0.12.0's `setuptools` dependency.

Measured in `Backend/.venv` after installing:

| Package         | Before   | After      |
| --------------- | -------- | ---------- |
| cryptography    | 46.0.7   | **46.0.7** |
| pyasn1          | 0.5.1    | **0.5.1**  |
| pysnmp-lextudio | 6.1.2    | 6.1.2      |
| sslyze          | 6.3.1    | 6.3.1      |
| impacket        | _absent_ | **0.13.1** |
| pyOpenSSL       | _absent_ | 26.2.0     |

`pip check` in the venv reports no impacket, cryptography or pyasn1 conflict —
only a pre-existing `pytest-asyncio` note unrelated to this work. The sslyze
violation that exists in the global interpreter does **not** exist here.

**No second environment was created.** `Backend/.venv` is the one the worker
launches from and the one that was fixed.

### 9M.4 Verified in the worker process, not just an interpreter

Importing impacket in a shell proves the site-packages, not the runtime. The
worker was restarted (it caches `IMPACKET_AVAILABLE` at import) and an SMB-transport
credential was dispatched through Celery at **192.0.2.1** — RFC 5737 TEST-NET-1,
so no real host is touched and no real credential exists. The distinction is the
whole point:

- impacket missing → `SMBConfigurationError: impacket is not installed`
- impacket present → a _connection_ error, because the transport got as far as
  a socket

The worker logged:

    Credentialed audit of 192.0.2.1 failed:
      Cannot reach SMB: [Errno Connection error (192.0.2.1:445)] timed out

That is impacket's own error. The probe credential and scan row were deleted
afterwards.

**Containers were already correct.** `Backend/Dockerfile` runs
`pip install --user -r requirements.txt`, so every container build has had
impacket since Phase 12. Only the host worker's virtualenv — the one built by
hand and never refreshed — was affected.

### 9M.5 SNMP proven, not assumed

The documented failure is silent: an FDB table decoding to one entry instead of
three, so a switch's MAC table looks sparse rather than broken. Passing tests
alone would not settle that, so three things were checked:

- `pyasn1` is **unchanged at 0.5.1** — the SNMP chain was not modified at all,
  so no behaviour in it can have changed.
- `pysnmp` references `pyasn1_modules` **nowhere**, so the one newly-arrived
  package in that family cannot reach it.
- A three-entry FDB-shaped walk was encoded and decoded through
  `pysnmp.proto.rfc1902` and returned **3 of 3**, with `Integer32` and
  `Counter32` round-tripping. `tests/repo/test_runtime_dependencies.py` keeps
  that assertion.

`tests/topology/` — 69 tests — passes in the venv.

### 9M.6 The guard

`tests/repo/test_runtime_dependencies.py` walks `requirements.txt` and asserts
every declared distribution is installed **in whichever interpreter is running
the suite**, which is what makes a stale environment fail where it is stale
rather than where it is not. Mutation-verified: a bogus requirement line makes
it fail, naming the package.

It checks **presence, not versions**, deliberately. `pytest` (9.1.1 against a
7.4.4 pin) and `python-docx` (1.2.0 against 1.1.2) are both installed _newer_
than pinned, and downgrading the test runner that produced every figure in §12
is a larger and riskier change than the drift it would fix. Those are recorded
below, not actioned. The defect worth failing a build over is a declared
distribution that is entirely absent, because that turns a shipped capability
into a runtime error.

It resolves distribution names rather than import names: `python-docx` imports
as `docx` and `pysnmp-lextudio` as `pysnmp`, so importing by declared name
would invent failures.

### 9M.7 Dependency security check

No `pip-audit` or `safety` is installed and neither was added. `ccure_user`
lacks privileges on `vuln_intel.osv_ranges`, and that was not escalated for a
convenience query. Every package this change installed or preserved was checked
against **OSV.dev** at its exact installed version:

| Package                                                                    | Result       |
| -------------------------------------------------------------------------- | ------------ |
| impacket, Flask, Werkzeug, ldap3, pyOpenSSL, pycryptodomex, ldapdomaindump | **clean**    |
| cryptography 46.0.7                                                        | 4 advisories |
| pyasn1 0.5.1                                                               | 4 advisories |

**Everything this change added is clean.** The two that are not are packages it
deliberately did _not_ move, and both are blocked by pins that exist for
functional reasons:

- `cryptography` — fixed in **48.0.1** / **49.0.0**; `requirements.txt` caps
  `<48` to avoid the TripleDES deprecation.
- `pyasn1` — fixed in **0.6.4**; pinned `<0.6.0` because `pysnmp-lextudio`
  6.1.2 imports `pyasn1.compat.octets`, which 0.6 removed.

Both are denial-of-service class (quadratic OID parsing, unbounded REAL
conversion, exponential certificate path-building), not remote code execution.
Each needs its own decision — raising either cap means retiring a functional
constraint — so both are recorded here rather than changed under a dependency
fix.

### 9M.8 Result

| Check                                    | Result                                       |
| ---------------------------------------- | -------------------------------------------- |
| `impacket` imports in the worker venv    | ✅ `IMPACKET_AVAILABLE = True`               |
| SMB transport in the live worker process | ✅ connection error, not configuration error |
| SMB tests (venv)                         | ✅ **63 passed** (was 1 failed)              |
| Topology / SNMP tests (venv)             | ✅ **69 passed**                             |
| FDB three-entry decode                   | ✅ 3 of 3                                    |
| `pyasn1` / `cryptography` displaced      | ✅ neither                                   |
| Full regression (venv)                   | ✅ **4606 passed, 2 skipped, 0 failed**      |
| Second environment created               | ✅ no                                        |

**No capability figure moves.** GAP-02 was already Closed and Phase 12 was
already real-target validated; this restores the runtime's ability to execute
what was built, and a dependency fix is not new capability.

### 9M.9 Recorded, not fixed

- **`pytest` 9.1.1 against a `==7.4.4` pin**, and `pytest-asyncio` 0.23.8
  requires `pytest<9`. Every regression figure in this tracker was produced on
  9.1.1, so the pin is what is stale, not the environment. Correcting it means
  choosing between raising the pin and downgrading the runner, and the second
  would revalidate nothing.
- **`python-docx` 1.2.0 against a `==1.1.2` pin.** Newer than declared; the
  compliance DOCX exports are exercised by the suite and pass.
- **The global Python 3.12 still has `cryptography` 42.0.8 and a violated
  sslyze requirement**, from the earlier by-hand impacket install. It is not a
  deployment target, but it is where §12's figures were produced. Aligning it
  is `pip install "impacket==0.13.1" "cryptography>=43,<47"`; not done here
  because it is a developer machine's environment rather than the runtime, and
  changing `cryptography` there reaches unrelated global tooling.

---

## 9N. Phase 15 — Windows STIG/SCAP: the Windows OVAL schema

Phase 10 built the SCAP reader and §9D.10 recorded a deliberate exclusion: _"the
whole Windows schema is out, because no Windows STIG was validated and shipping
it unvalidated is what Phase 8 recorded as refused for IIS."_ §9K then loaded
757 Linux STIG rules and left the product with **929 assessable checks on Linux
against 112 on Windows** — an 8:1 asymmetry in a product whose customers are
mostly Windows estates. This phase closes it.

**No new engine, no new scan kind, no new route, no migration.** Six OVAL test
types, one collector platform tuple, and a platform that is now read rather
than assumed.

### 9N.1 The denominator, frozen from real content before anything was built

Source: **DISA Microsoft Windows 11 STIG V2R10, SCAP 1.3**, downloaded from
`dl.dod.cyber.mil` and corroborated against NIST's National Checklist Program,
which names DISA as the author and carries the same URL. A US Government work,
which is the same licensing position that made GAP-05 possible where GAP-04
(CIS) remains blocked. **Nothing is committed to this repository** — the
datastream and the converted pack live outside the tree.

Converted first, with the reader exactly as Phase 10 left it:

    controls  : 219
      automated     : 0  (0.0%)
      unimplemented : 219

and the tally named the ten Windows OVAL test types the rules use, with what
each costs:

| Test type                                    | Rules | Share |
| -------------------------------------------- | ----: | ----: |
| `windows:registry_test`                      |   117 | 53.4% |
| `windows:auditeventpolicysubcategories_test` |    43 | 19.6% |
| `windows:userright_test`                     |    25 | 11.4% |
| `windows:wmi57_test`                         |    15 |  6.8% |
| `windows:passwordpolicy_test`                |     7 |  3.2% |
| `windows:lockoutpolicy_test`                 |     3 |  1.4% |
| `windows:fileeffectiverights53_test`         |     3 |  1.4% |
| `windows:ntuser_test`                        |     3 |  1.4% |
| `windows:sid_sid_test`                       |     2 |  0.9% |
| `windows:user_sid55_test`                    |     1 |  0.5% |

Those ten are the denominator, in `WINDOWS_SCOPE`. It is separate from Phase
10's `SCOPE`, which says in the file that it is frozen and must not be edited
to match what was built — so Windows is declared alongside it rather than
appended to it. **The measurement above was taken before a line was written**,
which is what makes the figure a prediction rather than a description.

Note the brief's expected priorities and the corpus differ, and the corpus won:
there is no `windows:file_test` in this content, and the audit type is
`auditeventpolicysubcategories_test` rather than `auditeventpolicy_test`.

### 9N.2 What was built

Six probes in `core/scap/probes.py`, registered in the one `PROBES` table
beside the Unix ones. No parallel registry, no second module of Windows
collectors.

- **`registry`** — prefers the SMB transport's own `read_registry_value` over
  Remote Registry and falls back to PowerShell. Keeps three outcomes apart:
  no key, no value under an existing key, and a value read.
- **`auditeventpolicysubcategories`** — one `auditpol /get /category:* /r` per
  audit, memoised, rendered as a single item whose entities are the
  subcategories.
- **`userright`**, **`passwordpolicy`**, **`lockoutpolicy`** — one `secedit`
  export of `SECURITYPOLICY USER_RIGHTS`, memoised, shared by all three. This
  is the only write any probe performs: a GUID-named file in `$env:TEMP`,
  removed in the same command, which is the shape
  `WindowsSecurityPolicyCollector._run_secedit` already established.
- **`wmi57`** — a WQL query returning rows as records. Prefers
  `SMBExecutor.wmi_query`, but **only for `root/cimv2`**, the namespace that
  method is bound to; a BitLocker query against
  `root/cimv2/security/microsoftvolumeencryption` falls through to PowerShell
  rather than being answered confidently about the wrong namespace.

Three things around them:

- **`record` is a new OVAL datatype.** `wmi57_state` compares a WMI row against
  `<field name=…>` children, so the entity's value is a mapping rather than
  text. `oval._entity` reads the fields and `evaluate._compare` compares them
  field by field — and a column the row does not carry is **UNKNOWN, never
  False**, because "this build did not collect that" is not "the host
  disagrees".
- **The pack's platform is read, not assumed.** `translate.to_pack` hardcoded
  `platform="linux"`, true of every benchmark loaded until now. Left alone, the
  Windows benchmark would have been offered to Linux hosts, where not one rule
  can be evaluated, and withheld from the Windows hosts it describes.
  `platform_from_content` reads OVAL's own `<affected family>`, and
  `BenchmarkPack`'s existing guard caught the mismatch the moment the platform
  changed but the checks did not.
- **`ScapRuleCollector.platforms` gained `windows`.** Until it did, a Windows
  context selected no collector and every rule reported ERROR — the correct
  direction, and the reason the first live run produced 25 errors and not 25
  false passes.

### 9N.3 Coverage — measured, and two figures that answer different questions

| Measure                                |  Before | After                 |
| -------------------------------------- | ------: | --------------------- |
| Windows OVAL test types (frozen at 10) |       0 | **6 — 60.0%**         |
| DISA Windows 11 STIG rules automated   | 0 / 219 | **198 / 219 — 90.4%** |

Both are reported because neither alone is honest. 60% is the share of the
Windows OVAL _surface_ this build evaluates; 90.4% is the share of the real
benchmark's _rules_ it can answer, and it is higher because the four
unimplemented types are the rare ones. Each of the four carries its reason in
`WINDOWS_NOT_IMPLEMENTED` and what it costs: `fileeffectiverights53` 3 rules,
`ntuser` 3, `sid_sid` 2, `user_sid55` 1. The remaining 21 unautomated rules are
those four types (9 rules), object `<set>` composition (11 — the same
second-pass gap Linux has), and one registry object selecting its key by
pattern match.

**GAP-05's own figure does not move.** `measure_scap_coverage`'s Phase 10
denominator is 52 areas, 33 implemented, **63.5%**, and it measures the reader
against the SCAP surface. Windows is a second denominator beside it, not an
addition to it.

### 9N.4 Real-target validation — 10.180.6.14, Windows 11 Pro

Authenticated over WinRM as a local administrator. All 198 automated rules
evaluated against the live host:

| Verdict        | Count |
| -------------- | ----: |
| pass           |    63 |
| fail           |   126 |
| not_applicable |     9 |
| **error**      | **0** |

Zero errors, which is what §9D claimed for Linux and is now shown for Windows.
Every implemented test type produced verdicts in both directions.

**Verdicts cross-checked against the host's own configuration**, not merely
against each other:

| Rule             | Verdict | Host                               |
| ---------------- | ------- | ---------------------------------- |
| `WN11-AU-000500` | FAIL    | `MaxSize` — key absent             |
| `WN11-CC-000215` | PASS    | `NoDataExecutionPrevention` absent |
| `WN11-00-000150` | FAIL    | value absent under an existing key |

Those first two are the whole four-state argument in one pair: the _same_
absence is a FAIL under `at_least_one_exists` and a PASS under `none_exist`.
A probe that reported an absence when a read had failed would declare the host
compliant on the strength of a command that never ran.

`oscap` was not used as a cross-check. It does not run on Windows, so unlike
§9D there is no independent implementation to compare against — the host's own
registry, `secedit` export and `auditpol` output are the reference, and they
were read directly.

### 9N.5 Four defects real hardware found, every one of which had shipped looking right

None could have been caught without the live host, and each produced confident
wrong answers rather than errors.

- **`auditpol /r` reports a phrase, not a number.** The setting column holds
  "Success and Failure", not `3`. The first table was keyed on `"0".."3"`,
  matched no row, emptied the policy, and turned **all 43 audit rules into
  errors**.
- **`pnp_activity` is the one subcategory whose OVAL name is not the host's.**
  27 of 28 normalise straight from `auditpol`'s own text; Windows calls that
  one "Plug and Play Events".
- **Windows qualifies built-in trustees and the content does not.**
  `S-1-5-32-544` resolves to `BUILTIN\Administrators` while the STIG compares
  against bare `Administrators`. Left qualified, **every user-right rule fails
  on a correctly configured host**. Only `BUILTIN\` and `NT AUTHORITY\` are
  stripped — the content writes `RESTRICTED SERVICES\PrintSpoolerService`
  qualified, and its own optional-prefix patterns match a domain account either
  way. Emitting both spellings is not available: `entity_check` defaults to
  "all", so the second would have to match too.
- **A right nobody holds is one item with an empty trustee, not zero items.**
  Every userright rule in this content uses `at_least_one_exists`, and the
  rules meaning "this must not be assigned" compare against
  `trustee_name equals ''`. Returning zero items made `at_least_one_exists`
  fail, so a host that correctly grants the right to nobody was reported as
  violating the rule it satisfies: **0 of 25 userright rules could pass**. With
  the empty-trustee item, 6 pass — exactly the six privileges genuinely
  unassigned on the host.

A fifth was found by the corpus rather than the host: OVAL's
`passwordpolicy_item` is wider than its name and carries the LSA anonymous
SID/name translation flag, which `WN11-SO-000140` reads. Without it that rule
reported ERROR.

### 9N.6 Reporting — traced end to end, and two defects fixed on the way

The phase brief makes reporting part of done, so the whole path was driven on
the real host rather than assumed:

    OVAL probe → CheckResult → finding_from_result → cve_list
      → _sync_credentialed_vulnerabilities → asset_vulnerabilities
      → compliance_findings → technical PDF

Measured on scan #51 against 10.180.6.14: **126 findings** written with
`CCURE-CFG-RULE-STIG-WIN11-…` identifiers, `definition_type = config_check`,
**`cve_id` NULL on all 126**, real STIG titles, severities mapped, and a
technical PDF generated. The compliance side carries 63 pass / 126 fail /
9 not-applicable for `cfw_bm_stig_win11`.

Two things were wrong and are fixed here rather than deferred:

- **The OVAL reading did not reach the finding.** The evidence written to a
  configuration finding was `Expected: … / Observed: non_compliant` — the
  verdict word and nothing else. What makes it actionable is
  `observation.raw`, which names the OVAL object and the existence check it
  failed. It is appended now, with duplicate lines collapsed: a rule with seven
  registry objects that all found nothing produced the same sentence seven
  times, which pushes the useful part off the page.
- **Evidence was never refreshed on re-detection.** `evidence` was absent from
  the finding upsert's `set_`, so a finding that stayed open kept the text from
  the day it was first seen — the identical defect the block immediately above
  it fixes for version fields, where a host upgraded from Chrome 138 to 139
  went on reporting 138. On a configuration check the evidence _is_ the
  finding, so a partial remediation from `Observed: 0` to `Observed: 8` went
  unreported. Both sites now share one hoisted `evidence_text`.

`tests/scans/test_scap_windows.py` drives the real `_finding_card` the
technical PDF renders each finding with, and asserts the identifier, title and
OVAL evidence all appear — plus, parametrised over PASS, NOT_APPLICABLE, ERROR
and MANUAL_REVIEW, that **only a FAIL becomes a finding at all**.

### 9N.7 Tests

**50 tests** in `tests/scans/test_scap_windows.py`, covering each probe for a
value read, a genuine absence, an unavailable read, malformed output, and no
session; the record datatype's three-valued comparison; the collector's
platform tuple; and the report path. The three host-found defects each have a
test whose failure message says what the defect cost.

### 9N.8 Known limitations

- **One host, one SKU.** Windows 11 Pro, workgroup, local administrator. A
  domain-joined machine, a Server SKU and a standard-user session are unproven,
  and the domain case matters most: `userright` trustees, `sid_sid` and the
  applicability rules that ask whether the host is a member workstation all
  behave differently there.
- **No independent reference.** `oscap` does not run on Windows, so unlike the
  Linux STIG work there is no second implementation of the standard to
  cross-check against. The host's own configuration is the reference.
- **`secedit` writes a temporary file.** In `$env:TEMP`, GUID-named, removed in
  the same command. It is the only write in the phase and it follows the
  existing Phase 3 collector, but it is a write, and a host that forbids it
  reports ERROR rather than a verdict.
- **Non-English installs are untested.** The audit-policy probe matches
  `auditpol`'s subcategory _text_, so a localised host would resolve fewer
  subcategories — the entity would be absent from the item and the rule would
  read UNKNOWN, which is the safe direction but is not coverage. The GUID
  column is captured and would be the robust key; binding OVAL entities to
  GUIDs needs a table this phase would have had to invent.
- **21 rules remain unautomated**, listed with reasons in §9N.3.
- **`profiles`**: the eleven MAC-\*/CAT-\* profiles this content ships are not
  selectable per organisation; the loader takes one and `BenchmarkControl.profiles`
  carries it. Choosing one per tenant is GAP-12's business.

---

## 9O. Phase 16 — GAP-13: scan comparison and finding lifecycle

Phase 15 and the two content loads took this product from 155 assessable checks
to 955 benchmark rules plus the built-ins. Measured consequence: **4,633
findings on one Linux host and 3,873 on one Windows host**. The full list
stopped being something a person can read, and the product had no way to say
what had changed. This adds one.

**No new finding model, no second store, no migration.**

### 9O.1 Reconstructing a baseline without a per-scan occurrence table

The obvious design is a row per finding per scan. At the scale above that is
thousands of rows per host per scan, and it is not needed:
`asset_vulnerabilities` already carries `first_found_at`, `last_found_at`,
`fixed_at` and `status`, and those answer the question for **any** point in
time —

    a finding was open at time T
      iff  first_found_at <= T  and  (fixed_at is null or fixed_at > T)

— because a baseline scan is just a T. The comparison therefore ships as a
query rather than a schema change.

Identity is the existing one: `AssetVulnerability.id` is minted from
`(asset_id, vuln_id, source_family)`, so the same logical finding keeps one
row across scans and re-detections. Note what the schema does _not_ say —
`uq_asset_vuln_scan_asset_cve` is UNIQUE on
`(org_id, scan_id, asset_id, vuln_id)` and excludes the family, so two
families cannot share a `scan_id`.

### 9O.2 The rule the phase exists for: absence is not a fix

Both fixed-sweeps already marked _every_ open finding absent from a scan as
fixed. For package findings that is defensible — the matcher runs over the
whole inventory. For a configuration check it is not: 126 Windows STIG findings
are absent from `cve_list` when the audit passes **and** when the audit never
ran, and nothing distinguished the two. A credential that expired would have
been reported as 126 remediated controls.

Two things now prevent that:

- **A per-scan assessment scope.** `record_assessment_scope` writes what a
  scan actually looked at — asset ids and `source_family` values — into
  `scans.options`, which is JSONB, already carries `options.origin`, and is
  the smallest honest record. A dedicated column was rejected: it is a
  migration on a live table for something with no query predicate of its own,
  and GAP-12's policy record is where this should eventually fold in rather
  than compete with. Scope **merges** rather than replaces, because one scan
  writes findings from several paths.
- **A guarded sweep.** `_assessed_config_definition_ids` builds the set of
  checks that reached a verdict — PASS or FAIL only; ERROR and NOT_APPLICABLE
  establish nothing — and a configuration finding is marked fixed only if its
  check is in it.

A scan with no recorded scope can **never** report a fix. Unknown reach is not
"assessed everything"; it degrades to `NOT_ASSESSED`, which is a class of its
own, counted separately and named in the summary line. A reader told "8 fixed"
and not told "40 not assessed" has been handed a number implying progress the
scan did not establish.

### 9O.3 Two defects real hardware found

Both produced confident, plausible, wrong answers, and neither was reachable
from unit tests.

- **A scan was stamped complete before its own findings existed.**
  `create_completed_scan` sets `completed_at` when the scan row is built,
  which is before the sync runs. Measured on the disposable target: baseline
  completed **18:48:44**, its earliest finding first seen **18:48:45**. Every
  finding a scan produced therefore post-dated the scan, so a comparison
  anchored on that boundary judged all of them newer than the baseline and
  reported **50 new, 0 unchanged** on two scans of an almost unchanged host.
  `completed_at` is now stamped after the sync, which also makes it true.
- **A regression was reported for ever.** `fixed_at` holds only the most
  recent fix and is not cleared when a finding returns, so four curl CVEs fixed
  in scan B and back in scan C were correctly flagged reappeared for C-against-B
  and then **wrongly flagged again for D-against-C**, when by then they had
  simply been open the whole time. A fix predating the baseline's own start, on
  a finding that is open now, means the finding returned at or before the
  baseline — so the baseline saw it open and it is unchanged. The cost is
  stated rather than hidden: a regression occurring between an old fix and the
  baseline reads as unchanged. One under-report against crying wolf
  indefinitely.

The report is also generated **after** the sync now, because a delta cannot be
computed from findings that do not yet exist. Report paths are set on the scan
row before the same commit, so nothing else changes.

### 9O.4 Real-target validation — disposable Ubuntu 24.04, five scans

Built, changed, scanned and destroyed, per the standing rule; the root
credential was generated at run time and never written to source, configuration
or Git, and both it and the container are gone.

| #   | Change made before the scan        | Comparison | Result                                                          |
| --- | ---------------------------------- | ---------- | --------------------------------------------------------------- |
| A   | — (baseline)                       | —          | baseline established                                            |
| B   | removed `libpam-pwquality`, `curl` | B vs A     | **4 fixed** — exactly the four curl CVEs                        |
| C   | reinstalled `curl`, added `wget`   | C vs B     | **5 reappeared** — the four curl CVEs and the pwquality control |
| D   | installed `nginx`                  | D vs C     | **3 new** — an nginx CVE and two nginx middleware controls      |
| E   | **nothing**                        | E vs D     | **0 new, 54 unchanged, 0 fixed, 0 reappeared**                  |

Scan E is the one that matters most. An unchanged host rescanned produces no
spurious delta at all: no invented fix, no invented regression. Every figure
above was computed by the scan itself and is in the worker log.

Note the pwquality control appears as **reappeared**, not new — it had been
fixed by installing the package and came back when it was removed. Folding that
into "new" would have hidden a regression.

### 9O.5 API

`GET /scans/{scan_id}/comparison` — `baseline` (defaults to the previous
completed scan of the same `pipeline_mode`), `asset_id`, `severity`,
`limit`, `include_findings`.

Both scans are fetched through `_get_scan_or_404`, so the organisation
scoping and per-user visibility rule governing every other scan route govern
this one: a caller cannot compare against a scan they could not read, and
naming another tenant's scan id returns 404 rather than its findings. The
comparison query filters on `org_id` again regardless.

`limit` bounds the returned rows and **never the counts** — a truncated count
is a wrong number, a short list is a sample. A first scan with no baseline
returns the normal shape with `comparable: false` and a reason, so a report
can render "no baseline" instead of an error.

### 9O.6 Reporting

    scan → sync → compare_scans → report payload → PDF

The technical report gains a **Change since the previous scan** section: the
baseline and current scan ids, the summary line, a table of the five classes
with severity breakdown, the assessment scope, and up to fifteen representative
new/fixed/reappeared rows. The executive report gains one line —
_Since the previous scan: 12 new, 340 unchanged, 8 fixed, 2 reappeared._

Two properties are pinned by tests. `_comparison_section` returns an empty
list when there is no comparison, so **a report generated without one is
byte-for-byte what it was before**. And an incomparable pair prints _Not
comparable_ with the reason rather than a table of zeroes, which would read as
"nothing changed" — a very different and much more reassuring claim.

The `not_assessed` row is labelled in the table as _"Was open; this scan did
not assess the check, so it is NOT reported fixed"_, so the distinction survives
into the artefact a customer actually reads.

### 9O.7 Coverage

Denominator frozen before implementation at **14 areas**, from what a
Nessus-class comparison offers:

| Implemented (10)                              | Not implemented (4)                                 |
| --------------------------------------------- | --------------------------------------------------- |
| NEW classification                            | Per-scan finding occurrence history                 |
| STILL_OPEN classification                     | Accurate comparison of arbitrary _historical_ pairs |
| FIXED classification                          | Remediation-verification workflow (GAP-14)          |
| REAPPEARED classification                     | UI presentation                                     |
| NOT_ASSESSED (absence ≠ fix)                  |                                                     |
| Per-scan assessment scope                     |                                                     |
| Comparison API with RBAC and tenant isolation |                                                     |
| Severity breakdown                            |                                                     |
| Asset and severity filtering                  |                                                     |
| Technical + executive report integration      |                                                     |

**GAP-13: 25% → 71.4%** (10/14), implemented _and_ tested _and_ real-target
validated. The four gaps are recorded below rather than rounded away.

### 9O.8 Known limitations

- **A comparison is accurate while it is the latest scan.** It reconstructs
  from current row state, so once later scans move `fixed_at` and
  `last_found_at` an older pair degrades. Measured: B-against-A gave "4 fixed,
  1 reappeared" when B was current and a different answer once D had run. This
  is why the report embeds the comparison **at scan time**, when it is right.
  Accurate historical pairs need per-scan occurrence rows, which is the first
  item in the not-implemented column.
- **Multi-cycle findings reconstruct approximately.** Only the most recent
  `fixed_at` survives; see §9O.3.
- **Only the credentialed path records scope in full.** The network path
  records assets and family; the configuration-audit detail
  (`config_audit_assessed`, `checks_assessed`) is credentialed-only, which
  is where the false-fix risk actually lives.
- **Comparability is checked, not enforced.** Two scans of the same host with
  different `sections` are compared and the scope is reported, but nothing
  refuses the comparison — the real fix is GAP-12's policy record, deliberately
  not built here.
- **No UI.** API and reports only.

### 9O.9 The pytest scratch database needs a superuser repair

**Recorded because it is mine and it is not fixed.** The suite reports
**4,510 passed, 17 failed, 6 errors, 168 skipped**, and every failure and error
is in `tests/audit/` — `test_audit_retention_safety`,
`test_audit_retention_concurrency`, `test_audit_retention_holds`. Nothing else
fails, including every test added by this phase.

The cause is not the product. While clearing test pollution of my own making —
API tests that went through `TestClient`, whose login commits and so committed
the uncommitted fixture rows with it — I ran `DROP SCHEMA public CASCADE` on
`ccure_pytest_db`. `conftest` rebuilt the tables, but the audit tamper-evidence
and retention objects are installed by **privileged DBA scripts**, not by the
suite:

    scripts/audit/bootstrap_chain.sql
    scripts/audit/bootstrap_chain_retention.sql

Those create the `audit_chain_writer` and `audit_maintenance` roles and the
append-only triggers and grants on `audit_logs`, and they require SUPERUSER —
`ccure_user` gets `ERROR: must be able to SET ROLE "audit_chain_writer"`. The
schemas themselves survived; the triggers and grants on the recreated
`public.audit_logs` did not, which is why those tests fail rather than skip.

Repair, as a database administrator, against the scratch database only:

```
psql "postgresql://postgres@127.0.0.1:5432/ccure_pytest_db" -f Backend/scripts/audit/bootstrap_chain.sql
psql "postgresql://postgres@127.0.0.1:5432/ccure_pytest_db" -f Backend/scripts/audit/bootstrap_chain_retention.sql
python Backend/scripts/audit/verify_retention_bootstrap.py
```

**`ccure_test`, the live database, was never touched by any of this.** The
lesson worth keeping is the one that started it: do not drive this suite's API
routes through `TestClient` with `auth_headers` while holding uncommitted
fixture rows — the login commits them, they survive the per-test rollback, and
the cleanup is worse than the pollution.

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
| After Phase 6, full suite                        | **2405 passed, 2 skipped**, 7m29s                         |
| After Phase 7, full suite                        | **3108 passed, 2 skipped**, 8m06s                         |
| After Phase 8, full suite                        | **3647 passed, 2 skipped**, 8m43s                         |
| After Phase 9, full suite                        | **3987 passed, 2 skipped**, 8m37s                         |
| After Phase 10, full suite                       | **4123 passed, 2 skipped**, 9m42s                         |
| After stabilization                              | **4138 passed, 2 skipped**, 11m00s                        |
| After Phase 11, full suite                       | **4279 passed, 2 skipped**, 11m12s                        |

Each delta matches the tests added exactly — +54 for Phase 0, +4 for the
catalogue guard, +68 for Phase 1, +43 for Phase 2, +241 for Phase 3, a net
+99 for Phase 4, +222 for Phase 5, +139 for Phase 6, +703 for Phase 7,
+539 for Phase 8, +340 for Phase 9 and +136 for Phase 10 — so no existing
test was lost, silently skipped, or renamed out of collection at any point.

Phase 10's delta needs no reconciliation beyond the count: **136** tests in
four new files, and no parametrised growth, because GAP-05 ships no
built-in checks. A STIG is _loaded_ content, not part of the engine's own
pack — which is what keeps `BUILTIN_CHECKS` a fixture rather than becoming
a benchmark, and a test pins it.

**One pre-existing test was amended, and it is the same amendment Phase 9
made.** `test_container_content.test_the_check_type_matches_the_migration`
asserted that migration `b0c1d2e3f4a5`'s hand-rendered vocabulary _equals_
the model's; Phase 10 added `scap_rule` and broke it. A migration renders
the vocabulary as of that migration, so the exact-equality assertion always
belongs to the newest one — it now lives in `test_scap_content.py`, and the
Phase 9 test asserts the subset relation instead. That this correction was
needed twice in a row is the argument for writing it that way the first
time.

Phase 9's delta reconciles in two parts: **316** tests in three new files,
and **+24** from `BUILTIN_CHECKS` growing 131 → 155, which
`test_every_builtin_check_survives_a_round_trip` is parameterised over.
316 + 24 = 340, exactly the observed growth.

**One pre-existing test was amended, and the reason generalises.** Phase
8's `test_the_check_type_matches_the_migration` asserted that migration
`a9b0c1d2e3f4`'s hand-rendered vocabulary _equals_ the model's. Phase 9
added `container` to the model and broke it — correctly, in the sense that
the test noticed, but the assertion was wrong: a migration renders the
vocabulary **as of that migration**, so pinning a historical one to the
current model makes every future check type a failing test in a phase it
has nothing to do with. It now asserts the subset relation and that it
adds the value it exists to add; the exact-equality assertion belongs to
the _newest_ migration and lives with it in `test_container_content.py`.

Phase 8's delta reconciles in two parts: **499** tests in four new files,
and **+40** that are not new test functions —
`test_config_audit_spec.py::test_every_builtin_check_survives_a_round_trip`
is parameterised over `BUILTIN_CHECKS`, which grew from 91 to 131 when the
middleware rules were added. 499 + 40 = 539, exactly the observed growth.

**Three pre-existing tests were amended, and two of them were brittle in a
way worth recording.** `test_privilege_checks.py` asserted `checks_run ==
20` and `== 22` — hardcoded totals of the built-in catalogue, which break on
every content phase and are the _weaker_ assertion anyway: a total of 20 is
equally satisfied by 20 hardening checks and no privilege ones, which is the
regression the test exists to catch. Both now assert by check-id family.
The third, `test_platform_filtering_uses_the_checks_own_targeting`, asserted
that the Windows and Linux check sets are disjoint; that held only because
every check before Phase 8 targeted exactly one platform, and Apache, Tomcat
and the Docker daemon legitimately run on both. It now asserts what its name
says — that filtering respects each check's own declaration — and keeps a
disjointness assertion for single-platform checks.

Phase 7's delta reconciles in three parts. It adds **652** tests in four new
files, **+2** in files it amended, and **+49** that are not new test
functions at all: `test_config_audit_spec.py::test_every_builtin_check_survives_a_round_trip` is parameterised over
`BUILTIN_CHECKS`, which grew from 42 to 91 when the database rules were
added, so every one of them is round-tripped through the stored JSONB shape
for free. 652 + 2 + 49 = 703, exactly the observed growth.

**Three pre-existing tests were amended rather than deleted, and the reason
matters.** All three asserted that `database_query`, the `database` platform
or the `database` credential type were _reserved and unimplemented_ — which
was true until this phase and is the fact it changed. Each was updated to
keep the property it was guarding while pointing at something that is still
unimplemented (`api` on `container`, `network_device` and `snmp`), and each
gained a companion asserting the new capability from the other side. Deleting
them would have removed the guard; loosening them would have removed the
evidence that the endpoint reports capability from the live registry rather
than from a list.

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

| Phase | Commit    | Tag | Suite result                                           |
| ----- | --------- | --- | ------------------------------------------------------ |
| 0     | `31c10b4` | —   | 1589 passed, 2 skipped ✅                              |
| 1     | `37871a6` | —   | 1661 passed, 2 skipped ✅                              |
| 2     | `9e4ecaa` | —   | 1704 passed, 2 skipped ✅                              |
| 3     | `daab13a` | —   | 1945 passed, 2 skipped ✅                              |
| 4     | `9e762d0` | —   | 2044 passed, 2 skipped ✅                              |
| 5     | `8a5bbd7` | —   | 2266 passed, 2 skipped ✅                              |
| 6     | `d40800d` | —   | 2405 passed, 2 skipped ✅                              |
| 7     | `9d74a0c` | —   | 3108 passed, 2 skipped ✅                              |
| 8     | `7520e90` | —   | 3647 passed, 2 skipped ✅                              |
| 9     | `13d6854` | —   | 3987 passed, 2 skipped ✅                              |
| 10    | `6b4c06e` | —   | 4123 passed, 2 skipped ✅                              |
| 10s   | `04a725e` | —   | 4138 passed, 2 skipped ✅                              |
| 11    | `426c282` | —   | 4279 passed, 2 skipped ✅                              |
| 11s   | `dd79bee` | —   | 4359 passed, 2 skipped ✅                              |
| 11s2  | `c5ec7b7` | —   | 4412 passed, 2 skipped ✅                              |
| 12    | `4a88723` | —   | 4462 passed, 2 skipped ✅                              |
| 12f   | `adf88c7` | —   | 4475 passed, 2 skipped ✅                              |
| 13    | `7fd2f17` | —   | 4515 passed, 2 skipped ✅                              |
| 13c   | `ff5237a` | —   | 4515 passed, 2 skipped ✅                              |
| 13v   | `7ad2b9a` | —   | 4555 passed, 2 skipped ✅                              |
| 13d   | `bb8b6ed` | —   | 4606 passed, 2 skipped ✅                              |
| 15    | `d7ec271` | —   | 4670 passed, 2 skipped ✅                              |
| 16    | `3b8ac56` | —   | 4510 passed, 17 failed ⚠ (audit bootstrap, see §9O.9) |

A suffixed row is not a new phase: `s` is a stabilization commit, `f` a
post-phase fix, `c` a content load against a reader an earlier phase built,
`v` a real-target validation of a path an earlier phase left unproven, and
`d` a runtime dependency fix. Figures from `13d` onward are measured in
`Backend/.venv`, the interpreter the worker runs; earlier rows were measured
in a developer's global Python, so the two are not strictly comparable.

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
