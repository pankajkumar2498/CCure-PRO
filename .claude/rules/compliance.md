---
paths:
  - "Backend/core/compliance*.py"
  - "Backend/core/compliance_catalogue/**"
  - "Backend/core/nist_csf*.py"
  - "Backend/core/asset_evidence.py"
  - "Backend/ccure_audit/evidence_providers.py"
  - "Backend/routers/compliance*.py"
  - "Backend/reporting/compliance/**"
  - "Backend/data/compliance_seeds/**"
  - "Backend/scripts/seed_*.py"
  - "Backend/scripts/enrich_*.py"
  - "Backend/scripts/set_active_frameworks.py"
  - "Backend/scripts/cleanup_*.py"
  - "Backend/scripts/fix_csf_11_crosswalks.py"
  - "Backend/tests/compliance/**"
---

# Policy Compliance Engine, ISO 27001, active frameworks and NIST CSF 2.0

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 4576–4913) and is maintained here. Frozen original: `docs/archive/engineering-record/policy-compliance.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Policy Compliance Engine

The engine is an orchestration layer over the existing scan modules, not a
scanner: each producing module answers for its evidence sources with a
normalised payload, registered with `core/compliance_evidence.py` (G4, see
"Architecture guardrails"), `core/compliance_tasks.py` evaluates rules against
it, and both machine verdicts and human attestations land in one finding model.

Six things that were wrong for a long time and must not be reintroduced:

- **A rule resolves to a control _within the scan's framework_.** Rules are
  deliberately crosswalked across standards, so `.first()` on
  `compliance_rule_controls` has no defined answer — measured on the shipped
  catalogue, 57 of the 114 rules in the ISO default policy resolved to a
  control belonging to a _different_ framework, so an ISO scan wrote half its
  findings onto DPDP, GDPR and IEC 62443 and ISO itself scored as unassessed.
  Use `resolve_controls_for_rule(db, rule_id, framework_id)`, which is ordered
  and returns _every_ matching control. There is no fallback control; a rule
  that maps to nothing in this framework is skipped.

- **Every status rollup goes through `roll_up_statuses()`.** Four call sites
  each built `{f.control_id: f for f in findings}` — an unordered dict
  comprehension in which the last row won — so a control carrying twelve rules
  reported whichever verdict the database happened to return last. A host with
  SSH closed and SMB open could score `pass` on a control covering both.
  `RolledFinding` / `rolled_up_control_findings()` in the router exist so report
  generators get the rolled-up verdict without changing their `.status` access.

- **An attestation outranks the engine's own placeholder.** The scan writes one
  org-level `manual_review` finding per manual control, at
  `org_finding_id_for(org, control)`; the attestation endpoint writes to that
  same id. They used to be different ids _and_ `manual_review` outranked `pass`
  in the rollup, so attesting a control never moved the score — which disabled
  63 of ISO 27001's 93 controls.

- **A rule's evidence key must be one its provider actually emits.**
  `tests/compliance/test_compliance_rule_wiring.py` asserts this statically and would have
  caught the two defects it exists for: 35 rules named `auto_scan`, an evidence
  source with no adapter, and 14 more read `offline_configuration` keys that
  were computed and then left out of the return dict. Between them, 49 of 79
  rules could never produce a pass or a fail. When adding a key to a provider
  (since G4 they live with their tables, `core/asset_evidence.py` for
  `offline_configuration`), put it in the returned dict _literal_ — the guard
  reads the key surface statically — and drop `None` values at the end so
  uncollected keys become `manual_review`.

- **Never synthesise evidence.** `attrs["password_policy"]` was a hard-coded
  `{complexity: True, history_length: 24, min_length: 14}` written for every
  host, so any rule reading it passed unconditionally everywhere. It is
  collected now (`net accounts` on Windows, login.defs + pwquality + the PAM
  stack on Linux) and keys that could not be read are omitted, which the engine
  renders as not assessed. The Windows parser matches on labels, not line
  position — an earlier positional version silently reported one setting's
  number as another's when a line was missing.

- **`credential_validation` is a credentialed source.** It belongs in
  `CREDENTIALED_EVIDENCE_SOURCES` with the other three. Without it, a host the
  scanner could not authenticate to reported ISO A.8.2 as _failed_ rather than
  unassessed.

Scheduling: `compliance_scan_schedules` is driven by
`compliance.run_scheduled_scans` on beat every 60s. That task passed
`created_at=` to `ComplianceScanRun` before the column existed, so it raised
`TypeError` on every tick, was swallowed by a bare `except`, and reported
`success: False` — no scheduled scan had ever run. The CRUD endpoints under
`/compliance/schedules` did not exist either.

**The `compliance` queue needs a consumer.** On the Windows deployment the only
container subscribed to it sat behind the `container-scanner` profile and was not
started, so beat published 1,440 messages a day into a queue nothing read. On
the VM the `worker` service consumes `scanner,default,compliance`
(`docker-compose.yml`); it is behind the same profile, so
`COMPOSE_PROFILES=container-scanner` must be set. If you see the queue growing,
that worker is not running.

Seeding: `python -m scripts.seed_compliance` globs `*_controls_seed.json`
rather than naming files — two frameworks existed as seed files and were never
loaded. `scripts/enrich_iso27001_seed.py` owns the ISO Annex A descriptions,
evidence checklists and crosswalks; edit the enrichment table there, not the
generated JSON. `scripts/seed_real_rules.py` generates a manual attestation
placeholder for every control that has no explicit rule — the membership test
must normalise dotted vs underscored control ids, or every control gets a
placeholder including the ones that are fully automated.

### ISO/IEC 27001:2022

`scripts/enrich_iso27001_seed.py` owns the Annex A descriptions, evidence
checklists, crosswalks, scannability and module hints; edit the tables there,
never the generated JSON.

**The catalogue holds the management-system clauses 4.1–10.2 as well as Annex
A** (118 controls, since 28 Sep 2026). They are attestation controls under
their own theme, `ISMS` (migration `e9a1c3d5f7b2`), and `ISMS_CLAUSES` in the
same script owns them. Three things keep them apart from Annex A, and each is
tested:

- **Their numbers.** Clause 5.1 and control A.5.1 are different requirements.
  Seed ids are `clause_<n>` with an explicit `control_number`, which
  `seed_compliance._control_number` honours for the catalogues in
  `EXPLICIT_NUMBER_FRAMEWORKS`.
- **Their order.** `control_sort_key` puts Annex A after the clauses rather
  than interleaving `5.1` with `A.5.1`.
- **The SoA.** The Statement of Applicability excludes them: clause 6.1.3(d)
  makes it a statement about Annex A, and clauses 4–10 are mandatory.

Four things that were wrong and are now guarded by
`tests/compliance/test_compliance_iso27001.py`:

- **An `archived` rule with no successor is a control switched off by
  accident.** `run_scan_task` evaluates `active` only, which is right — but 24
  of the 93 had a single rule and it was archived, so they produced no finding
  on any run, never reached the reviewer's findings queue, and the SoA printed
  them as "Not assessed": A.5.1, A.5.2, A.5.24, A.5.26, A.5.29, A.5.35, A.5.36
  among them. They stayed attestable the whole time, which is why it looked
  cosmetic. The seeder converges its own placeholders now;
  `scripts/cleanup_iso27001.py` reports and repairs anything it cannot reach.

- **`semi_auto` is a claim of automation.** Eighteen controls carried it with no
  automated rule at all. The register, the coverage figures and the SoA's
  scan-mode column all read it as partial automation.
  `test_scannability_only_claims_automation_that_exists` covers `semi_auto` as
  well as `auto`, and a `scan_module_hint` is set only where something runs.

- **Four controls could already be answered** and simply were not wired:
  A.5.18 ← `account_review_completed`, A.8.13 ← `backup_frequency_days`,
  A.8.18 ← `uac_enabled`, A.8.1 ← `session_timeout_minutes`. When a control
  gains a real check its old attestation placeholder must be _unlinked_ —
  `manual_review` outranks `pass`, so leaving it suppresses the verdict the new
  check produces. A.8.13 and A.8.18 landed in that state immediately.

- **A crosswalk must name an id the target catalogue actually uses.** Thirteen
  did not: `GDPR:5-1` against an id of `GDPR_5_1`, `DPDP_2023:1-1` against
  `DPDP_1_1`, `CERT_IN_2022:IR-1` against `cert_in_ir_1`, `IEC_62443:SR 5.1`
  against `SR-5.1`. Each silently resolved to nothing in gap analysis and in
  cross-framework rule inheritance.

**ISO automation is NIST's automation.** `AUTOMATED_ISO_CONTROLS` in
`core/nist_csf_catalogue.py` is the list of Annex A controls carrying a real
check, and NIST CSF derives its own `scannability` from it. Wiring a new ISO
rule therefore means adding that control there and regenerating the CSF seed,
or NIST is left claiming `manual` for a Subcategory that now inherits an
automated rule. A.8.13 did exactly that to PR.DS-11 and RC.RP-03.

### Which frameworks are switched on

Fourteen catalogues ship. Three are active:

- ISO/IEC 27001:2022;
- NIST CSF 2.0;
- CIS Controls v8.1 (since Phase 4).

**The work is focused on ISO until the modular refactoring completes**
(project owner, 28 Sep 2026). PCI DSS v4.0.1 was switched on and parked again
the same day. Its fixes below stay in place, so re-activating it is one entry
in the list plus the command below.

The rest are **parked**: still seeded and still crosswalk-reachable, but not
offered, scannable, reportable or installable. `core/compliance_frameworks.py`
is the list, overridable with `COMPLIANCE_ACTIVE_FRAMEWORKS`.

Turning one back on is one entry there plus
`python -m scripts.set_active_frameworks --framework <id> --apply`. Run the dry
run first and read it:

- **`--framework` limits the run to that catalogue.** Without it, the script
  also realigns every other flag that has drifted. On 28 Sep 2026 that would
  have enabled CIS for three organisations where it is installed but off —
  still unresolved, and a decision of its own.
- **Loaded benchmarks (`cfw_bm_…`) are never touched.** The script used to
  read "not in the shipped list" as "parked", so its first `--apply` would
  have switched off all five STIG benchmarks for `org_default`.

**PCI DSS was put right on 28 Sep 2026**, and
`tests/compliance/test_pci_dss_catalogue.py` pins each fix:

- **Requirement numbers.** 16 of the 62 described one requirement under
  another's number. Every "Roles and responsibilities" entry sat at X.1.1,
  which is policies and procedures; the standard puts roles at X.1.2. The
  others were 2.2.5→2.2.4, 8.3.9→8.3.7, 9.4.5→9.4.7, 10.3.3→10.3.2 and
  11.5.1.1→11.5.2.
- **Stored numbers.** The stored number was the internal id (`pci_10_1_1`).
  It is the standard's (`10.1.1`) now, via `EXPLICIT_NUMBER_FRAMEWORKS`.
  Row and rule ids are unchanged.
- **Rule inheritance.** Its rules inherited ISO's attestation placeholders
  through the crosswalk: 21 were unlinked. Only rules that evaluate something
  cross, as for NIST CSF. Placeholder rule ids now come from the control id,
  not its number.
- **Evidence defaults.** Five evidence keys read only by PCI rules
  (`pam_mfa_enforced`, `asv_scan_fresh`, `pci_log_daily_reviewed`,
  `ir_test_fresh_365d`, `fim_active`) defaulted to `False`. Every host nobody
  had checked therefore _failed_ the requirement. They are `None` now, which
  renders as not assessed.
- **Name.** It is "PCI DSS v4.0.1 (62 selected requirements)", because a
  score over 62 requirements must not read as a score over the standard.
  Expanding it needs the standard's text, which is licensed: the supplied PDF
  is a reference and is not in the repository.
- **Unverified.** The SAQ profiles on each entry were not verified; that needs
  the SAQ documents.

**The HIPAA Security Rule is the fourteenth** (28 Sep 2026, parked). Its
content and wiring:

- **Controls.** 65: the 22 standards and 43 implementation specifications of
  45 CFR 164.308–316.
- **Numbering.** Each is named by its CFR citation (`164.312(a)(2)(iii)`).
- **Descriptions.** Each carries the regulation's own text, which is US
  federal law and public domain.
- **Themes.** One per section, `HIPAA_ADM` … `HIPAA_DOC` (migration
  `f3b5d7e9a1c4`).
- **Tests.** `tests/compliance/test_hipaa_security_rule_catalogue.py` pins
  the Required/Addressable tags to the regulation's own markers and to the
  published Security Standards Matrix's totals.
- **Rules.** Every control is an attestation placeholder. Its rule id is
  derived from the control's id, never its number.

- **Parking is never a data decision.** Do not delete or un-seed a parked
  catalogue. `main.py`'s bootstrap condition names all fourteen, so a missing
  seed file makes it permanently true and the whole seeder runs on every
  container start without ever satisfying itself. The parked catalogues are
  also the _targets_ of ISO's and NIST's crosswalks, which
  `/compliance/gap-analysis` and the rule mapper both read.

- **`ComplianceFramework.is_active` is a trap.** It is set at seed time and read
  by no query anywhere, so setting it looks like it worked and changes nothing.
  `tests/compliance/test_framework_activation.py` fails if anything starts reading it.

- **Two layers, both needed.** `ComplianceTenantFramework.is_enabled` already
  gated the register, policies, scans, findings, attestation, evidence,
  schedules and the dashboard. It did not gate **any** of the thirteen report
  endpoints — `/compliance/reports/nis2` rendered a full PDF for a framework no
  tenant had installed — and it could not stop a tenant admin re-installing
  from the marketplace. `require_active_framework()` covers both, answering 403
  for a parked catalogue and 404 only for one that does not exist.

- **The scheduler is the only path that starts a scan without a request**, and
  it checked neither the installation list nor the tenant flag.
  `POST /compliance/schedules` requires the framework to be enabled _at the
  moment the schedule is created_; nothing re-checked it afterwards, so a
  framework uninstalled or parked later kept being scanned every five minutes
  on beat. `run_scheduled_scans` now checks both.

- **`compliance.run_reverify` checks the framework itself**, though nothing can
  currently hand it a parked one — it is reachable only from
  `run_reremediation_task`, itself reachable only from the two remediation
  endpoints, and both refuse a framework the tenant has not enabled. That is a
  property of the call chain, not of the function: it takes a finding id and
  writes a verdict, so a caller added later would rewrite a parked framework's
  finding with no check anywhere in between. It refuses without touching the
  finding or writing a history row.

- **Listing endpoints outlive their framework.** `/compliance/scans`,
  `/compliance/scans/{id}` and `/compliance/schedules` were tenant-scoped only,
  so a run or schedule for a parked framework stayed visible with a score the
  workspace can no longer open. All three are scoped to the active list now.

- **A parked framework's tests still run.** They activate themselves with the
  `activate_frameworks` fixture rather than the session switching everything
  on, so the parked path stays exercised and the parked suites do not rot.

### NIST CSF 2.0

`core/nist_csf_catalogue.py` is the catalogue — six Functions, 22 Categories,
106 Subcategories — and `scripts/enrich_nist_csf_v2_seed.py` renders it into
`nist_csf_v2_controls_seed.json`. Edit the core module, never the JSON;
`tests/compliance/test_nist_csf_v2_framework_integration.py` fails if they diverge.

Six things that were wrong and must not come back:

- **Count the distribution, not the total.** The catalogue had exactly 106 rows
  and the wrong ones: `RS.AN-08` was missing and `RC.RP-07` was invented, so
  Respond carried 12 against the standard's 13 and Recover 9 against 8. The two
  errors cancelled and 106 looked correct. The real shape is
  GV 31 / ID 21 / PR 22 / DE 11 / RS 13 / RC 8, and the per-Category counts are
  asserted too.

- **`PR.AC-*`, `PR.PT-*`, `PR.IP-*`, `ID.SC-*`, `DE.CM-04`, `RS.RP-01` are CSF
  1.1.** CSF 2.0 renamed or re-homed all of them — identity moved to `PR.AA`,
  supply chain to the new `GV.SC`. 102 of the 693 references other frameworks make
  named 1.1 identifiers, which resolve to control ids that do not exist, so the
  NIS 2 rule mapper inherited nothing and `/compliance/gap-analysis` computed
  coverage over crosswalks that could never match — 40 of PCI-DSS's 62 CSF
  references were dangling. `scripts/fix_csf_11_crosswalks.py --check` is the
  guard; the mapping table lives in it.

- **`scannability` is derived, never asserted.** A Subcategory is `auto` exactly
  when its crosswalk reaches an ISO control carrying a rule wired to a real
  adapter key (`AUTOMATED_ISO_CONTROLS`). Twelve claimed `auto` against modules
  that do not exist — `sast_dast_scan`, `ha_failover_check`, `app_locker_scan`,
  `ir_triage_matrix` — and five claimed `manual` while inheriting automated
  rules through a crosswalk that had no business carrying them: `ID.AM-07`,
  "inventories of data are maintained", was answered by A.8.8's
  critical-vulnerability count.

- **"Already mapped" must be read from the links that exist, not the ones this
  run inserted.** The flag was set inside `if not n_link:`, so on any second run
  every link already existed, nothing set it, and all 106 Subcategories were
  handed an attestation placeholder — including the 27 with real automated
  checks, which `manual_review` then suppressed in the rollup. It was
  progressive rather than one-off because `main.py`'s bootstrap condition
  (`soc2_ctrl_count < 61` against a 55-control catalogue) was true on every
  container start, so the seeder ran on every restart.

- **Only rules that evaluate something cross a crosswalk.** Inheriting another
  framework's _manual_ placeholders satisfied the mapped test with a rule that
  checks nothing, put ISO's control title into the remediation text a NIST
  reviewer reads, and leaked 20 NIST placeholders onto NIS 2 controls.

- **CSF order is not alphabetical.** `ORDER BY theme, control_number` opens the
  report on Detect and runs Govern as OC, OV, PO, RM, RR, SC; NIST publishes
  GV, ID, PR, DE, RS, RC and OC, RM, RR, PO, OV, SC. `core/nist_csf.py` holds
  the sequence and `control_sort_key` consults it first.

`run_scan_task` evaluates `active` rules only, which is right — but an
`archived` rule with a NULL `superseded_by_rule_id` is not a lifecycle state,
it is a control switched off by accident, and five Subcategories' _only_ rule
was in it. The seeder now reactivates the placeholders it owns.
`scripts/cleanup_nist_csf_v2.py` reports the same condition for every other
framework, where roughly 700 such links remain and are **not** repaired.

`scripts/cleanup_nist_csf_v2.py` (dry run by default, `--apply` to write)
removes Subcategories the standard does not define, placeholders sharing a
Subcategory with an automated rule, and NIST placeholders linked outside NIST
CSF. `seed_compliance.py` only upserts, so a catalogue correction that _removes_
a control needs it.

**The Statement of Applicability is framework-scoped.** ISO/IEC 27001:2022
clause 6.1.3(d) requires applicability, justification for inclusion,
implementation status and justification for exclusion per control; the export
carried none of the four and emitted every installed framework's controls under
an ISO title. `/compliance/reports/soa` takes `framework_id`, sorts numerically
via `control_sort_key` (a string sort gives A.5.1, A.5.10, A.5.11 … A.5.2), and
renders an approval block.

`python-docx` is a real dependency. It was absent from `requirements.txt` while
every `_generate_*_docx` path guarded on the import, so a DOCX request either
returned a PDF or downloaded a 29-byte file reading "python-docx is not
installed."
