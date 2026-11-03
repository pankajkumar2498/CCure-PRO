# Engineering record: Scan policy

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 3371–3491, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 3371-3491 -->
## Scan policy (`core/scan_policy/`)

What a scan assesses, as a reusable named configuration. GAP-12; tracker §9P.
**No new scan engine and no second policy model** — the whole persistence cost
is one table (`scan_policies`) and one nullable column
(`scan_schedules.policy_id`), migration `c7d8e9f0a1b2`.

- **The snapshot is not a copy of what ran. It is what runs.** The dispatching
  side resolves the policy once, writes the resolved `EffectivePolicy` into
  `scans.options["scan_policy"]`, and **the worker reads it back from there**
  rather than being handed it in the task arguments. So the historical record
  and the execution cannot disagree, because there is only one of them. Passing
  the settings to the task _and_ storing a copy for the report is two sources
  that agree until the day they do not, and that is the day an auditor is
  reading the report.

- **`record_policy_snapshot` refuses to overwrite.** A completed scan's
  configuration is settled once, at dispatch; a second write with a different
  fingerprint is logged at WARNING naming both. That is what makes "editing a
  policy does not alter Scan A" a property of the code. `overwrite=True` exists
  for exactly one thing: both dispatch paths rebuild `scan.options` from a dict
  literal, which drops a snapshot written before it, so it is re-applied
  afterwards. Forget that call and the record is lost invisibly until somebody
  reads the report.

- **A field either changes assessment behaviour or it is not in
  `EffectivePolicy`.** Every attribute is read by benchmark selection,
  `select_checks`, the section list, the port arguments, the intrusive gate or
  validation. A knob nobody honours is worse than a missing one. Seven areas
  are recorded unimplemented in the tracker rather than accepted and ignored —
  including rate limit and concurrency, which bound the _scanner_ rather than
  what is assessed.

- **An empty collection means "no restriction", never "nothing".** `()` for
  `framework_ids` selects every framework the tenant has installed, which is
  the pre-policy behaviour. Read the other way, an under-specified policy
  reduces a scan to zero checks while still reporting success — a clean report
  on a host nobody assessed. Every call site passes `list(...) or None` for
  this reason; an empty list would reach the query as `IN ()`.

- **A check family is a `ConfigCheck.domain`, and the vocabulary is imported
  from `core.checks.contract`, never restated.** The first version enumerated
  its own list including `benchmark` and `middleware`, neither of which is a
  domain — so a policy naming one validated happily and then selected zero
  checks. `ConfigCheck.__post_init__` raises `SpecError` on an unknown domain,
  which is what caught it.

- **The fingerprint hashes the behavioural fields only** — not id, name, family
  code, version or provenance. Renaming a policy must not make a scan
  incomparable with the one before it, and editing what it assesses must. Note
  the recorded quirk: the same frameworks in a different order fingerprint
  differently, because order is preserved for the reader.

- **Where a policy names a setting, the policy wins, and the override is
  reported.** The frontend sends `discovery_intensity: "normal"` on every
  request because that is the field's default, so a request-wins rule would
  silently override every policy asking for `deep`. The API response's
  `policy.overrides` names what was displaced — a scan that assessed something
  other than what was asked for must say so when it is accepted, not only in a
  report afterwards. Where the policy says nothing, the request's value is
  carried through, so a policy setting only a severity floor does not reset the
  port range.

- **A scan with no policy still gets a snapshot**, built from its own request
  parameters, `source = "request"`, no policy name. That is what lets GAP-13
  tell two such scans apart when the port range changed between them, and no
  report can imply a policy was chosen when none was.

- **Resolution happens before the scan row exists on the scheduled path.**
  `create_scan` commits, so resolving afterwards and refusing left a committed
  scan stuck in `running` that nothing dispatched — every night, for a schedule
  whose policy had been archived. The HTTP path creates the row first (it
  carries the scan number and the quota) and deletes it on refusal instead.

- **Validation refuses; it never falls back.** Static validation
  (`validate_policy`) runs at write time; contextual validation
  (`validate_for_dispatch`) re-runs at **every** dispatch, so a framework
  uninstalled in June stops being scanned in July — the rule the schedule
  dispatcher already applies to scope and quota. A framework that does not
  exist, is parked here, or is not installed for this tenant give three
  different messages, because they need three different actions. Excluding the
  built-in pack while naming no framework is **refused**, not warned: it
  resolves nothing, and a scan reporting success having assessed no
  configuration is byte-identical to a clean host.

- **`config` never holds a secret**, structurally. It is returned by the policy
  API, copied into `scans.options` (client-visible) and printed in the report. A
  credential is referenced by `compliance_credentials.id` on the scan or the
  schedule. `require_credential` names a credential and holds a _bool_ — it
  says an authenticated session is required, it cannot contain one.

- **`sync_config_audit_findings` takes `framework_ids` and passing it is not
  optional for correctness.** A policy that selected the Ubuntu 24.04 STIG
  resolves only that benchmark's checks, but a rule crosswalked into a second
  framework would otherwise write a verdict onto that framework's control too,
  from a scan that never assessed the rest of it — a score over a handful of
  controls that reads as a near-complete assessment.

- **`scan_policies` is deliberately not `compliance_policies`.** That table's
  `framework_id` is a NOT NULL FK into the compliance catalogue and a network
  scan has no framework; its rule bridge enumerates rule versions where a scan
  policy needs a _predicate_, and freezing the resolved set would stop a
  benchmark reloaded next month reaching a policy written today. The lifecycle
  _is_ copied — family code, version number, draft/active/archived,
  `superseded_by_policy_id`. Two divergences: `org_id` is NOT NULL (a global
  scan policy would let one workspace's edit change another's scans) and the
  UNIQUE constraint is tenant-scoped.

- **Measured on this installation.** `org_default` has five STIG benchmarks
  installed, so every credentialed scan resolved all **955** rules regardless
  of target; against a real Ubuntu 24.04 host that is **792 NOT_APPLICABLE**. A
  policy naming `cfw_bm_stig_ubuntu2404` at severity `high` resolves **8** and
  reports **4**. That difference is what the phase is for.

- **API**: `/scan-policies` (11 operations, own RBAC atoms — "may this person
  run a scan" and "may this person decide what every scan assesses" are
  different authorisations), plus `GET /scans/{id}/policy`, which reads the
  snapshot and **not** the policy row: the policy may since have been edited,
  versioned, archived or deleted, and none of that changes what the scan
  assessed. It reports the divergence rather than resolving it.

<!-- /verbatim -->
