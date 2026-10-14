# CCure-Audit-PRO — Scan Module Review

> End-to-end review of the four scan modules, input to output. Companion to
> `PIPELINE_DATA_INTEGRITY_AUDIT.md`, which covers the shared data pipeline those modules run on.
> Sources verified from `Backend/orchestrator/scan_orchestrator.py`, `Backend/core/tasks.py`,
> `Backend/scan_helpers.py`, `Backend/engines/`, `Backend/scans/`, `Backend/reporting/pdf_generator.py`.

## What was reviewed

| Module               | Pipeline mode         | Phases     | Entry point                    |
| -------------------- | --------------------- | ---------- | ------------------------------ |
| Basic Network Scan   | `basic`               | 1, 4       | `run_host_discovery_task`      |
| Asset Discovery Scan | `asset`               | 1, 2, 4    | `run_asset_discovery_task`     |
| Vulnerability Audit  | `vulnerability_audit` | 1, 2, 3, 4 | `run_vulnerability_audit_task` |
| Credentialed Scan    | (standalone)          | 5          | `run_credentialed_scan`        |

Each was traced from request options through phase chaining, engine execution, verification,
persistence and report generation, and checked against what a commercial scanner is expected to do:
state its coverage, distinguish "not checked" from "checked and clean", and never present an
inference as an observation.

## Findings

### C1 — Scan coverage was never recorded (all four modules) · **fixed**

The methodology appendix opens by telling the reader that coverage bounds every conclusion — "a
service on a port outside the scanned range cannot produce a finding here" — and then printed
**"Not recorded"** for port selection, timing profile and scanner engine, because nothing in the
pipeline ever recorded them. A report that cannot state what it examined is not reproducible and
cannot be defended in an audit.

**Fixed at source.** `PortEngine.scan_configuration()` publishes the parameters the scan actually ran
with — resolved port list, exclusions, timing template, engine and version, and whether service and
OS detection were performed. The orchestrator writes them to the phase summary (which is persisted)
and the metadata (which the fresh report reads), and `carry_scan_coverage()` moves them forward from
asset discovery to the vulnerability assessment, which does not choose ports but must still report
which ones were examined.

### C2 — The report asserted configuration it had not been given · **fixed**

`_scan_configuration` defaulted **Service detection** to `"Enabled (banner and probe
fingerprinting)"` and inferred **OS fingerprinting** from whether any host happened to have an OS
string. A LIGHT-intensity scan performs no service detection at all, and a Basic Network Scan scans
no ports — both produced reports claiming otherwise. This directly contradicted the generator's own
stated contract, that an unrecorded parameter is shown as unrecorded.

**Fixed at source.** Both defaults removed. With C1 in place the values are real; where a scan
genuinely records nothing, the report now says so.

### C3 — A credentialed audit that could not read the inventory reported a clean host · **fixed**

Both collectors ran their sections concurrently and swallowed per-section failures with a log
warning. If the `packages` section failed — insufficient rights, an unsupported package manager, a
timeout — `system_data["packages"]` was simply absent, `match_packages([])` returned nothing, and the
audit produced a report showing **zero vulnerabilities** for a host it had not assessed. An empty
result was indistinguishable from a clean one, which is the most dangerous failure a scanner has.

**Fixed at source.** Collectors record `collection_errors` per section and the sections they
attempted. When the inventory is empty the audit emits an explicit finding —
`MISC-CREDENTIALED-INVENTORY-UNAVAILABLE`, "This host is unassessed, not clean" — carrying the
failure reason, tagged as an active check so verification keeps it. The stored report also records
`packages_enumerated`, `collection_errors` and `inventory_complete`. This mirrors how Nessus surfaces
credentialed-check failures rather than reporting an empty result.

### C4 — Host discovery reported its coverage as "not recorded" · **fixed**

A Basic Network Scan legitimately performs no port scan, but its report said "Port selection: Not
recorded", which invites the reader to assume ports were scanned and nothing was found. Phase 1 now
records explicitly that ports were not scanned under this policy, that service detection was not
performed, and whether the OS was passively inferred.

## Module verdicts

### Basic Network Scan — sound

Purpose is host liveness, and it now says so in its own report. Discovery no longer emits CVE
candidates (fixed in the pipeline audit), so a basic scan cannot produce vulnerability claims it has
no evidence for. Ports registered incidentally by discovery probes are labelled `connect_probe` and
are outranked by any later service detection.

### Asset Discovery Scan — sound

Phase 1 → phase 2 chaining preserves phase-1 identity and ports (`host_backup` restore in the
orchestrator, `_merge_host_identity` in the task). Port records now merge by evidence strength, so
the richer Nmap fingerprint replaces the discovery guess instead of being skipped. Asset sync writes
services and identity; it derives nothing of its own.

### Vulnerability Audit — sound

Candidate generation happens once, keyed on the scanner's CPE where available; verification runs in
the vulnerability phase, so risk scoring, asset sync, API and reports all consume verified findings.
Suppressed candidates are retained with accurate reasons. Coverage now travels forward from phase 2.

### Credentialed Scan — sound after C3

Verification runs where the audit produces findings (previously only at report time), package
findings are no longer misclassified as network findings on hosts with listening services, and an
incomplete inventory is now stated rather than being reported as an absence of vulnerabilities.

## Remaining, by decision rather than defect

- **Which vulnerability store is canonical** (`cve`/`cpe` tables versus `vulnerability_definitions`) —
  the drift is now visible in the sync telemetry; picking one as the source of record is an
  architectural decision.
- **Per-candidate suppression persistence** — counts are stored; the per-item list is not, to avoid
  writing ~1870 rows per host per scan.
- **Web-scanning module** — a separate pipeline with its own scanner and report path, not covered by
  this review.
