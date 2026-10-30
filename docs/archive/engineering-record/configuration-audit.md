# Engineering record: Configuration audit engine, benchmark content, local privilege checks

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 2513–2798, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 2513-2798 -->
## Configuration audit engine (`core/config_audit/`)

The generic engine for configuration and hardening assessment. Phase 3 of the
gap-closure programme; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

    Configuration Rule → Collector → Expected State → Actual State
        → PASS / FAIL / MANUAL / N/A → Finding → Risk → Remediation → Reporting

**No benchmark name appears anywhere in this package, and none may.** CIS
(Phase 4), STIG (Phase 5), application, database, network-device and cloud
content are all just sets of `ConfigCheck` records. The moment the engine knows
which benchmark it is running, adding the next one means editing the engine.

- **Rules live in `compliance_rules`, not a new table.** It already carries
  `check_type`, a JSONB `check_definition`, `target_platform`, `severity`,
  versioning and a junction to every framework control. A second rule table
  would need all of that again, and a second finding table, a second score and
  a second report generator come along behind it — which is exactly why Phase 0
  widened `vulnerability_definitions` rather than adding one.
  `ConfigCheck.to_check_definition()` / `.from_rule()` are the adapter.
  Migration `b4c5d6e7f8a9` widens the two CHECK constraints; the seven
  pre-existing `check_type` names are kept verbatim, and the two rule kinds are
  told apart by `check_definition.config_check`, not by the type name.

- **Four collection states, and collapsing any two is the whole class of bug
  this engine exists to prevent.** `COLLECTED` (a value was read) → compared.
  `ABSENT` (the collector ran and the thing is genuinely not there) → the
  _rule's_ policy. `UNSUPPORTED` (out of scope for this target) →
  NOT_APPLICABLE. `UNAVAILABLE` (collection failed) → **ERROR, never a
  verdict**. "The registry value does not exist" and "the registry value is
  empty" routinely mean opposite things, and a collector returning `""` for
  both has lost the distinction before the engine sees it.

- **`AbsencePolicy` has no default, deliberately.** Absence is a PASS for
  "SMBv1 must not be installed", a FAIL for "auditd must be installed", and
  NOT_APPLICABLE for "if IIS is present it must be configured thus". A default
  would silently pick whichever answer flatters the score, so a rule that does
  not choose is refused at construction. Most Windows rules are
  `MANUAL_REVIEW`: a security setting absent from the registry is at a platform
  default that varies by build and SKU, and neither PASS nor FAIL can be
  asserted from the absence alone.

- **`ShellRunner` keeps the exit code; the collectors' own `_run` does not.**
  `WindowsCollector._run` and `LinuxCollector._run` both end
  `return _clean_output(result.stdout) if result.stdout else ""`. For bulk
  inventory that is defensible. For a check it means a failed command returns
  `""`, the comparison reads `""` as the host's setting, and a verdict is
  reported about a machine that never answered. There is no method on
  `ShellRunner` that returns a bare string.

- **Commands print a sentinel, and a value runs to the end of the output.**
  `CCURE::VALUE::` / `CCURE::ABSENT::`, with a non-zero exit meaning the read
  failed. Only the _first_ line carries the prefix — the first parser returned
  that line alone, so every configuration file was read as its first directive
  and every other directive reported as absent, which surfaces as a fleet-wide
  configuration gap rather than as a parser bug. Output carrying no sentinel is
  UNAVAILABLE, never an empty reading.

- **`grep` exiting 1 is a successful read of "no match", and so is
  `systemctl is-active` on a stopped unit.** The Linux commands are written to
  exit 0 for all three normal outcomes. Exit **97** is the reserved sentinel for
  "the tool I needed is not installed" — a host with no `dpkg-query`, no `rpm`,
  no `ss` or no `systemctl` reports UNAVAILABLE, not ABSENT: nothing was
  established about the package, only about the package manager.

- **Rule parameters are data.** Every one goes through `ps_quote` (doubling
  single quotes) or `shlex.quote`. The rules are administrator-editable, so this
  is an injection boundary inside the product, not defensive style.

- **A FAIL becomes an ordinary `StandardizedFinding`** in the same `cve_list` as
  the CVE findings, minted `CCURE-CFG-…` and filed as
  `definition_type = config_check` with `cve_id` NULL. Only a FAIL: a PASS is a
  compliance verdict, not a vulnerability, and the other three are not verdicts.
  `RemediationConfidence.CONFIGURATION_GUIDANCE` exists because
  `NONE_PUBLISHED` renders as "no published fix — compensating controls only",
  which is true of an unpatched CVE and false of a hardening control.
  **Every `RemediationConfidence` member needs a label in
  `pdf_generator.REMEDIATION_PROVENANCE`**; that lookup used to be a dict
  subscript and a missing member raised KeyError inside PDF generation.

- **The audit runs inside the credentialed scan**, on the session the collectors
  already opened — `core/tasks.audit_credentialed_host`, inside the `with
connection` block. Moving it after that block leaves every check reporting "no
  authenticated session". There is deliberately **no HTTP endpoint that runs
  one**: that would be a second way to start a scan against a caller-named
  target, needing its own scope check, quota check, rate limit and audit entry.
  An audit that could not run is recorded as
  `MISC-CREDENTIALED-CONFIG-NOT-ASSESSED`, because a crashed audit leaves no
  failing checks and that is byte-identical to a host that passed every one.

- **`core/config_audit/operators.py` is the single comparison vocabulary.**
  `core/compliance_tasks._evaluate_operator` delegates to it and
  `_evaluate_operator_legacy` is the pre-Phase-3 implementation, kept as the
  reference `tests/scans/test_config_audit_operators.py` compares against over
  a truth table. Do not add a second evaluator. The shared operators' semantics
  are frozen by the seeded rule catalogue, quirks included. `evaluate_detailed`
  adds a third state, `UNKNOWN_OPERATOR`: the old bare `return False` meant a
  misspelled operator evaluated False and was recorded as a **fail** against
  every host it ran on.

- **`api` is reserved and has no collector.** (`database_query` and the
  `database` platform were reserved here until Phase 7 implemented them;
  Phase 8 added `structured_config` for nested and structured
  configuration files; Phase 9 added `container` for enumerating live
  runtime state; Phase 10 added `scap_rule` for a compiled OVAL definition
  — see the database, middleware, container and SCAP sections below. The `container` _platform_ is still reserved and unused: the
  Phase 9 rules target `linux`, because a runtime is assessed over its
  host's session.) Naming them now means Phases
  9–17 need no CHECK migration on a table holding customer rules. A rule using
  one reports ERROR — "this product cannot perform that check" is a product gap,
  not a property of the host, and must never render as NOT_APPLICABLE or PASS.
  `GET /config-audit/capabilities` reports the gap from the live registry.

- **The built-in pack (`builtin/`) is 20 rules and is not a benchmark.** It
  exists so the engine ships exercised. Growing it does not grow capability.

## Benchmark content (`core/benchmarks/`)

Hardening benchmarks as loadable data on top of the Phase 3 engine. Phase 4 of
the gap-closure programme; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

    pack.json → compliance_frameworks/_controls/_rules → ConfigAuditEngine
      → evidence → verdict → compliance_findings → risk → remediation → report

Format and authoring guide: [`Backend/data/benchmarks/README.md`](Backend/data/benchmarks/README.md).

- **No CIS Benchmark ships in this repository and none may be committed.** CIS
  Benchmark recommendation text, rationale and remediation are the Center for
  Internet Security's, distributed under licence. A customer with a SecureSuite
  membership converts their own export into a pack; nothing in the code changes.
  **Do not write benchmark content from memory** — a rule labelled `2.3.1.1`
  carrying a recalled expected value is a false compliance claim in a
  customer's audit report and is indistinguishable from a correct one until an
  auditor checks. What _does_ ship is `data/benchmarks/*.benchmark.json`, two
  CCURE-authored baselines generated from `core/config_audit/builtin/`, whose
  `licence` says in words that they are not CIS Benchmarks.

- **`assessment` is declared, never inferred** — `automated` (has a check),
  `manual` (the benchmark itself wants a human), `unimplemented` (the benchmark
  automates it, this product does not yet, and it must say why). Reading "has a
  check" as "is automated" is the inference the format refuses; it is the same
  defect as the eighteen ISO controls that claimed `semi_auto` with nothing
  behind them. `unimplemented` is what keeps the coverage figures honest — a
  benchmark that omits what it cannot do reports better coverage than it has.

- **A benchmark _is_ a framework.** No new table. Recommendations are controls,
  automated recommendations are rules, and the register, score, findings queue
  and report all work the moment the rows exist. Framework ids carry the
  `cfw_bm_` prefix, which is load-bearing: `compliance_frameworks.is_active`
  uses it to tell loaded content from a _shipped but parked_ catalogue. Without
  it a loaded benchmark can never appear in the hardcoded active tuple and
  scores nothing. A prefix rather than "anything unknown is active", because
  that reading would make a misspelled framework id active and the guard could
  no longer answer 404.

- **`run_scan_task` skips configuration rules, and must keep skipping them.**
  A benchmark rule has no evidence `key` — it is evaluated against a live host
  by the configuration audit and synced afterwards by
  `core/compliance_sync.py`. If the compliance scan also evaluated
  it, it would read the missing key as missing evidence and write
  `manual_review` **over the real verdict**, silently blanking every benchmark
  result the last credentialed scan established.

- **`platforms` is windows-or-linux and that is not enough for benchmarks.**
  A CIS Ubuntu 22.04 benchmark and a CIS RHEL 9 benchmark are both `linux`;
  running one against the other's host checks paths and package names that
  distribution does not use and reads their absence as a verdict. A pack
  declares `applies_to` once (`os_name_contains`, `os_version_prefix`) and it
  flows onto every check. **An unidentified OS is an ERROR, not
  NOT_APPLICABLE** — "we could not tell what this host runs" and "this host is
  not what the benchmark is for" are different facts, and only the second is a
  legitimate reason for a control to leave the score.

- **Profiles are data on the control**, not engine behaviour:
  `compliance_controls.profiles` (JSONB, GIN-indexed, migration `c5d6e7f8a9b0`).
  Empty means in scope whatever profile was selected, which is what every
  pre-Phase-4 control is. `saq_profiles` expresses the same idea for PCI-DSS
  and is deliberately left alone — the PCI scoping queries read it — so **new
  content uses `profiles`**, pinned by a test. Choosing a profile per
  organisation is a scan-policy question and belongs to Phase 12; the filter
  exists and is tested.

- **One theme list, in `db/models/compliance.CONTROL_THEMES`.** It was
  previously copied five ways — the model twice (`ck_control_theme`,
  `ck_score_theme`), every framework migration, and `tests/conftest.py` — and
  the conftest copy silently won, because it rewrites the constraint on every
  session. A theme added to the model and its migration was still rejected by
  the test database with nothing saying why. Benchmarks use one generic
  `BENCHMARK` theme; minting one per benchmark section would add ~80 values for
  four platforms alone. The section travels in `tags`.

- **`_build_test_schema` bootstraps from the models and stamps heads**, so a
  migration written _after_ a database was bootstrapped never runs against it.
  Column changes are gap-filled; **CHECK constraint changes are not**. If a
  constraint change seems not to have applied, check
  `SELECT pg_get_constraintdef(...)` before assuming the migration is wrong.

- **CIS Controls v8.1 is active as of Phase 4** and is the framework benchmark
  crosswalks target. Note it is the _Controls_ (153 governance safeguards), not
  the _Benchmarks_ — separate publications. It shipped as a seed file, a theme
  migration and an `ALL_FRAMEWORK_IDS` entry since before Phase 4 and
  **`main.py` never seeded it**: parked _and_ unseeded, so the omission was
  invisible. It is in the bootstrap now.

## Local privilege checks (`core/config_audit/collectors/privilege_*.py`)

Local privilege-escalation and host-exposure enumeration. Phase 5 of the
gap-closure programme, closing GAP-08; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine.** These are Phase 3 `ConfigCheck` records with a new check
type, `privilege`, executed by the same `ConfigAuditEngine` and reaching the
same finding, risk, remediation and report paths.

- **The shape is "which items are offending", not "read one value".** A probe
  returns one offender per line; the rule asserts the list is empty. So a clean
  host produces an ABSENT reading and `AbsencePolicy.PASS` makes it a pass,
  while a breached one produces a FAIL naming exactly what to fix. That is why
  these use `absent = PASS` where the Phase 3 Windows rules use
  `MANUAL_REVIEW`: a missing registry value tells you nothing, but a _search_
  that returned nothing is a real result.

- **`privilege` is its own check type, not a `command` rule.** Service-ACL
  parsing is not a shell one-liner and a rule author should not be pasting one.
  Migration `d6e7f8a9b0c1` adds the type; the probes live in code, are tested
  against captured output, and a rule just names one.

- **`ConfigCheck.finding_type` decides the identifier.** `config_check` mints
  `CCURE-CFG-…`, `privilege_check` mints `CCURE-PRV-…`, and they group into
  different report families. "Deviates from a baseline" and "has a path to
  SYSTEM" are different piles to a triager. The engine carries `finding_type`
  on every result, because `core/tasks._run_configuration_audit` builds findings
  from the _result_ and would otherwise file every privilege finding as CFG.
  `cve` is refused at construction.

- **Three false positives were found by real-target validation, and each is the
  reason to do it.** All three would have shipped looking correct:

  - **`NT SERVICE\*` virtual accounts.** The service-ACL probe reported seven
    services on a stock Windows 11 workstation, because TrustedInstaller
    (`S-1-5-80-956008885-…`) legitimately holds full control over service
    configuration and each service's own account holds ChangeConfig over
    itself. `S-1-5-80-*` is now trusted.
  - **`stat` does not dereference symlinks.** `/bin`, `/sbin` and `/lib` are
    symlinks into `/usr` on every modern distribution, and a symlink's own mode
    is always 777 — so the writable-PATH probe reported them as world-writable
    on every host. It uses `stat -L` now. **The Phase 3
    `LinuxPermissionCollector` has the same `stat -c` without `-L`**; it is only
    pointed at regular files today, so it is not currently wrong, but a symlink
    target would fool it.
  - **`ssh-keysign` is legitimately SUID** on Debian and Ubuntu.

- **A count is not a check.** "37 SUID binaries found" says nothing — a stock
  distribution ships about thirty. `EXPECTED_SUID` is the allow-list and the
  probe reports the _difference_. The list is deliberately generous: a missing
  legitimate binary is a false positive, and a check that cries wolf is worse
  than one that misses, because the reader stops looking.

- **Exit 97 means "the tool I needed is not installed".** A host with no `find`
  has established nothing about its SUID binaries, and `getcap` is absent on
  many images. That is UNAVAILABLE → ERROR, never "none found". Proven on a real
  target, where `file_capabilities` correctly reported not-assessed.

- **These replace prose, and the prose stays.**
  `LinuxCollector._collect_security_audit` still emits its `security_issues`
  sentences — the report's posture section reads them and nothing should change
  what an existing report says. The _finding_ is now the authoritative form,
  because a sentence in a PDF has no severity, no risk score, no remediation, no
  lifecycle and cannot be triaged or exported.

- **The account-file probe is scoped around the Phase 3 checks.**
  `ccure.linux.passwd.permissions` and `.shadow.permissions` already assert
  those two files' modes, so the probe checks _ownership_ of all four and the
  _modes_ of `/etc/group` and `/etc/gshadow` only. Repeating them would report
  one condition twice and make the remediation look twice as large.

- **Coverage is measured by `scripts/measure_privilege_coverage.py`, and its
  denominator deliberately includes eight areas this build does not implement.**
  The first version listed twenty areas, all of which the phase then
  implemented, and reported 100% — a tautology wearing a percentage. The
  headline figure is _implemented and tested_: an area whose test is deleted
  loses its coverage credit, because the script reads the test sources rather
  than a hand-maintained list.

<!-- /verbatim -->
