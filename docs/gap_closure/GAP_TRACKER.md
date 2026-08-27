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

| Gap ID       | Capability                               | Domain         | Phase | Priority | Coverage before | Target | Status                 | Commit    |
| ------------ | ---------------------------------------- | -------------- | ----- | -------- | --------------- | ------ | ---------------------- | --------- |
| **GAP-00-A** | Common check/plugin framework            | Architecture   | 0     | Critical | 20% [measured]  | 90%    | **Closed**             | `31c10b4` |
| **GAP-00-B** | Finding model admits non-CVE findings    | Architecture   | 0     | Critical | 0% [measured]   | 100%   | **Closed**             | `31c10b4` |
| **GAP-00-C** | Generalized credential model             | Architecture   | 0     | High     | 25% [measured]  | 90%    | **Deferred → Phase 2** | —         |
| GAP-01       | Network & credentialed scan scheduling   | Orchestration  | 1     | Critical | 30% [measured]  | 95%    | Open                   | —         |
| GAP-02       | Native Windows credentialed scanning     | Credentialed   | 2     | Critical | 40% [estimated] | 90%    | Open                   | —         |
| GAP-03       | Generic configuration audit engine       | Config audit   | 3     | Critical | 35% [measured]  | 90%    | Open                   | —         |
| GAP-04       | CIS benchmark content                    | Config audit   | 4     | High     | 0% [measured]   | 70%    | Open                   | —         |
| GAP-05       | DISA STIG / SCAP ingestion               | Config audit   | 5     | Medium   | 0% [measured]   | 60%    | Open                   | —         |
| GAP-06       | Active vulnerability check expansion     | Network checks | 6     | High     | 30% [measured]  | 70%    | Open                   | —         |
| GAP-07       | Deep TLS/SSL assessment in main path     | TLS            | 7     | Medium   | 45% [estimated] | 90%    | Open                   | —         |
| GAP-08       | Local OS vulnerability assessment        | Credentialed   | 8     | High     | 10% [estimated] | 80%    | Open                   | —         |
| GAP-09       | Application/middleware config assessment | Config audit   | 9     | Medium   | 5% [estimated]  | 70%    | Open                   | —         |
| GAP-10       | Database assessment                      | Database       | 10    | High     | 5% [measured]   | 70%    | Open                   | —         |
| GAP-11       | Network device assessment                | Network device | 11    | Medium   | 15% [estimated] | 65%    | Open                   | —         |
| GAP-12       | Configurable scan policy engine          | Orchestration  | 12    | High     | 20% [measured]  | 85%    | Open                   | —         |
| GAP-13       | Scan comparison & finding lifecycle      | Findings       | 13    | High     | 25% [measured]  | 90%    | Open                   | —         |
| GAP-14       | Remediation & SLA management             | Remediation    | 14    | High     | 30% [measured]  | 85%    | Open                   | —         |
| GAP-15       | Reporting & export expansion             | Reporting      | 15    | Medium   | 50% [measured]  | 85%    | Open                   | —         |
| GAP-16       | Cloud security assessment                | Cloud          | 16    | Low      | 0% [measured]   | 60%    | Open                   | —         |
| GAP-17       | Virtualization / container / Kubernetes  | Container      | 17    | Low      | 5% [estimated]  | 60%    | Open                   | —         |
| GAP-18       | Distributed scanner / agent architecture | Architecture   | 18    | Low      | 10% [estimated] | 60%    | Open                   | —         |
| GAP-19       | Continuous security assessment           | Orchestration  | 19    | Low      | 10% [estimated] | 70%    | Open                   | —         |

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

## 4. Definition of Done — Phase 0

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

## 5. Regression

| Run                                              | Result                            |
| ------------------------------------------------ | --------------------------------- |
| Baseline (before any Phase 0 change), full suite | **1535 passed, 2 skipped**, 6m22s |
| After Phase 0, full suite                        | **1589 passed, 2 skipped**, 6m12s |

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

## 6. Commit log

| Phase | Commit    | Tag | Suite result              |
| ----- | --------- | --- | ------------------------- |
| 0     | `31c10b4` | —   | 1589 passed, 2 skipped ✅ |

Tags are applied at maturity milestones, not per phase. `v0.2.0` is claimed
only when Phases 1–2 are Closed and Level 3 is demonstrable.

---

## 7. Observations recorded during Phase 0 that are not gaps

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
