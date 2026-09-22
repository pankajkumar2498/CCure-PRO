# API → UI coverage baseline — credentialed scanning

Captured **22 Sep 2026**, before any Phase 1 UI work. This is the measurement the
phases are graded against; it is deliberately a snapshot of the _starting_
state, and editing it afterwards destroys the only thing it is for.

Method, so it can be repeated rather than re-argued:

- The schema is walked from a **live response** for a real scan
  (`scn_defa_c522b539_22sep26_d0td`, a Windows 11 host over WinRM), not from a
  model class — a declared field that is never populated and a populated field
  that is never declared both mislead.
- The grep is scoped to `pages/scan/CredentialedResults.jsx`, the one page that
  renders this payload. A whole-frontend grep gives false positives for common
  names (`target`, `users`, `coverage`, `packages`) and reports coverage the
  operator does not have.
- Three states are distinguished, because "destructured" is not "rendered":
  **RENDERED** (read _and_ referenced below the destructure block),
  **BOUND-ONLY** (read and thrown away), **MISSING** (never referenced).

Reproduce with `scripts/audit/api_ui_coverage.py` (see below).

## Endpoints in the credentialed workflow

| Endpoint                          | Purpose                    | Frontend at baseline      |
| --------------------------------- | -------------------------- | ------------------------- |
| `POST /scan/credentialed`         | dispatch a scan            | `api/credentialedScan.js` |
| `GET /scans/{id}`                 | the results payload        | `CredentialedResults.jsx` |
| `GET /scans/{id}/policy`          | GAP-12 policy snapshot     | **none**                  |
| `GET /scans/{id}/comparison`      | GAP-13 comparison          | **none**                  |
| `GET /reports/download/{id}?fmt=` | PDF / CSV / **XLSX**       | PDF and CSV only          |
| `GET /reports/export/{id}`        | GAP-15 filterable export   | **none**                  |
| `/scan-policies` (11 operations)  | GAP-12 policy management   | **none**                  |
| `/remediation` (12 operations)    | GAP-14 remediation and SLA | **none**                  |
| `/config-audit/*` (4 operations)  | the **rule catalogue**     | `ConfigurationChecks.jsx` |

`/config-audit/checks` is the rule library, **not** a scan's results. It cannot
be extended to show `credentialed.report.config_audit`; the two are different
objects and the page that shows one cannot show the other.

## Field coverage of `GET /scans/{id}` → `credentialed.report`

    Top-level fields : 38
    RENDERED         : 32
    BOUND-ONLY       :  0
    MISSING          :  6

Rendered (reference count in the page body, for the record): `system_info` 25,
`coverage` 17, `detected_os` 10, `target` 10, `packages` 9, `username` 9,
`severity_summary` 8, `network_interfaces_raw` 7, `brute_force_warning` 6,
`cve_count` 6, `users` 6, `cves` 5, `exposure_summary` 5, `env_vars_flagged` 4,
`suid_binaries` 4, `failed_login_count` 3, `failed_logins_recent` 3,
`local_groups` 3, `open_ports_credentialed` 3, `package_count` 3,
`running_services` 3, `security_issues` 3, `sudo_nopasswd` 3,
`sudo_rules_raw` 3, `suspicious_scheduled_tasks` 3, `collection_errors` 2,
`cron_info_raw` 2, `hardening_audits` 2, `inventory_complete` 2,
`scan_duration` 2, `world_writable_dirs` 2, `os_type_was_auto` 1.

Missing at baseline:

| Field                  | Behaviour at baseline                                                                    | Phase 1 destination         |
| ---------------------- | ---------------------------------------------------------------------------------------- | --------------------------- |
| `config_audit`         | never referenced; only its FAILs leak out as `CCURE-CFG-*` / `CCURE-PRV-*` inside `cves` | Configuration Audit section |
| `package_coverage`     | never referenced                                                                         | Package Coverage section    |
| `packages_enumerated`  | never referenced                                                                         | Package Inventory header    |
| `candidates_evaluated` | never referenced                                                                         | summary strip               |
| `suppressed_cves`      | referenced only by `ScanHistory.jsx`                                                     | Suppressed Findings section |
| `scan_type`            | never referenced                                                                         | scan metadata               |

`scan_type` was found by this audit rather than supplied to it, which is the
argument for walking the response instead of working from a list.

## Two findings beyond the field count

**`packages` is partially rendered.** The existing section is _Packages with
Vulnerabilities_ and filters to the subset matching a CVE — on this scan 20 of 191. The other 171 packages are collected, returned and invisible. Counting the
field as RENDERED is correct and still understates the gap, which is why this
note exists beside the number.

**The CVE table renders every row.** `filteredCves.map(...)` with no slice and
no `CcurePagination`, against 1,871 findings on this scan. Recorded here as a
pre-existing condition so that fixing it is not mistaken for a regression.

## What the missing structures contain

`config_audit` — `counts{pass,fail,not_applicable,manual_review,error}`,
`score_pct`, `checks_run`, `checks_assessed`, `benchmark_checks`, `assessed`,
`platform`, `policy_name`, `policy_fingerprint`, and `results[]` (254 on this
scan), each carrying `check_id, title, outcome, severity, remediation, qod,
confidence, detection_method, target, cve_ids[], references[], error`, an
`evidence[]` of `{raw, expected, observed, collector, description,
collected_at}` and `metadata{domain, check_type, finding_type,
collection_status, asset_id}`.

`package_coverage` — `coverage_pct`, `coverage_pct_software`,
`coverage_pct_assessed`, `packages_collected`, `packages_assessable`,
`packages_assessable_software`, `packages_cpe_resolved`,
`packages_assessed_total`, `packages_toolchain_components`, `advisory_source`.

`suppressed_cves[]` — `{identifier, host, reason}`, built as `ExcludedFinding`
with wording from `finding_normalizer.suppression_reason()`. **Empty on this
scan**, which is the case the empty-state rule exists for: the section must say
nothing was withheld, not show an empty table.

`packages[]` — `{name, version, arch, vendor, manager}` only. There is no
per-package CVE list or repository field; the association is derived by joining
`cves[].package`, which the page already does. A "vulnerability status" column
is therefore a join, not an API field, and must not be presented as one.

## Baseline counts for the acceptance criteria

    credentialed report top-level fields ....... 38 (rendered 32, missing 6)
    config_audit results ...................... 254
    cves ..................................... 1871
    packages .................................. 191
    suppressed_cves ............................. 0
    operator-facing endpoints in scope ......... 9 surfaces
    of those with no frontend at all ........... 5
