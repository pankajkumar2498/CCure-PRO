---
paths:
  - "Backend/reporting/**"
  - "Backend/routers/reports.py"
  - "Backend/scripts/measure_export_coverage.py"
---

# Exports and reports

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 3607–3720, 5145–5157) and is maintained here. Frozen original: `docs/archive/engineering-record/reporting-and-exports.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Exports (`reporting/exports.py`, `reporting/xlsx_generator.py`)

Assessment results in a form something other than a person can read. GAP-15;
tracker §9R. **No second reporting architecture** — the PDFs, the thirteen
compliance framework documents, the host-inventory CSV and the
suppressed-candidate sidecar are untouched, the findings CSV gained nine
_appended_ columns and not one reordered one, and the whole persistence cost is
one extra key inside a JSONB column that already existed. **No migration.**

- **`exports.py` produces rows; the format layer writes files.** The XLSX, the
  CSV and the JSON all render the same `export_payload`, so they cannot
  disagree about a scan — which is what makes the reconciliation requirement
  satisfiable at all rather than three code paths kept in step by hand.

- **The verdicts come from the scan payload, not `compliance_findings`, and
  that is the phase's main modelling decision.** `compliance_findings.status`
  has no `error` member and must not gain one, so `compliance_sync` maps ERROR
  onto `manual_review` with the reason in the evidence payload — right for a
  compliance register, wrong for an export whose stated requirement is that the
  states stay distinct. Read from the register, a check that _could not run_ is
  indistinguishable from one a human is meant to review. The authoritative
  record is `config_audit.results`, one entry per check carrying its own
  `CheckOutcome`; the control and framework mapping is layered on afterwards
  through the same enabled-and-active intersection `compliance_sync` writes
  through, so an export can never name a framework the tenant never installed.

- **Six labels, none of them blank.** PASS, FAIL, NOT_APPLICABLE,
  MANUAL_REVIEW, ERROR, and NOT_ASSESSED — the last being the only one that is
  not a stored outcome. A host whose configuration audit never ran gets one
  explicit row carrying the engine's own reason, because an empty sheet reads
  as a clean host.

- **`_collect_host_audits` walks the payload rather than reading a fixed
  path.** The same record reaches three shapes — nested under
  `_phase_data[i].credentialed_report` on the vulnerability-audit pipeline, in
  `options["credentialed_report"]` on the standalone credentialed scan, and as
  a list beside a single `report` on a multi-host run. A fixed path exports one
  and returns nothing for the other two. The host is taken from the record's
  own container, so a walk cannot attribute one machine's verdicts to another,
  and `_dedupe_host_audits` stops the first-host-stored-twice arrangement
  doubling that host's verdicts.

- **A check that maps to no installed framework control still gets a row.**
  Dropping it would silently lose every built-in check and every uncrosswalked
  benchmark rule — real assessment results. An empty mapping column is not a
  missing row.

- **`sanitize_cell` is the only place a cell is made safe, and it does three
  things in order**: strip the C0 control characters openpyxl refuses (one NUL
  from an SNMP banner otherwise fails the whole export), prefix a formula
  leader with an apostrophe, then truncate past Excel's 32,767-character
  ceiling **with a visible marker**. `+`, `-`, `@` and the two whitespace
  leaders are in the table as well as `=`: a title beginning `-Xmx` is text to
  whoever wrote it and a formula to whatever opens it, and a leading tab before
  `=` is the documented bypass for a naive first-character test.

- **openpyxl is always `write_only=True`**, and that is why sheets are built
  from row _iterables_. Normal mode keeps a `Cell` object per cell for the life
  of the workbook. Freeze panes and column widths must be set **before** the
  first `append` — appending flushes the sheet's opening XML, so a pane frozen
  afterwards is never written — and the autofilter **after**, because its range
  needs the row count and it is serialised in the tail.

- **`?fmt=XLSX` is a real workbook and every other unknown format is still a 400.** It used to fall through to the executive PDF with HTTP 200, so an
  Excel export looked successful and produced a file Excel refuses to open. A
  deployment missing openpyxl answers **503 naming the dependency** —
  `XlsxUnavailable` is its own type for exactly that reason, and it must never
  degrade into another format.

- **openpyxl belongs in both runtimes.** Same rule as pywinrm and the database
  drivers: the API container renders the export and a worker regenerating a
  missing report reaches the same code. Installed in one only is how an export
  succeeds in the UI and fails from the worker.

- **`_flatten_credentialed_payload` exists because the CSV download returned
  the host inventory.** `build_legacy_scan_results` renders the credentialed
  phase as `{"data": [{"ip_address": …}], "report": {…, "cves": […]}}`; the
  normalizer reads findings off the entries in `data`, found an address and
  nothing else, and returned zero — so `scan_has_findings` was False and the
  branch fell through to `generate_host_inventory_csv`. Measured: **1,887
  findings in the database, 1,887 in the workbook, 0 in the CSV**, HTTP 200
  either way. It must also refuse to merge over a host entry that already
  carries findings: the builder synthesises a _stub_ report with an empty
  `cves` when it finds no stored one, and merging that deletes everything the
  scan reported.

- **The findings CSV's new columns are appended, never interleaved.** A
  consumer reading by index — a spreadsheet macro, most ETL — keeps working.
  A configuration finding joins to its remediation record **by title**, and
  that is not belt and braces: the credentialed pipeline puts the minted
  `CCURE-CFG-…` identifier in `cve_id`, which the normalizer correctly refuses
  to read as a CVE, so `cve_ids` is empty and `plugin_id` falls back to the
  title. Match on the CVE alone and every benchmark finding in the product —
  which is most of them — exports an empty remediation record.

- **`reporting/csv_generator.py` deliberately does not escape formula
  leaders.** The XLSX writer and the new export endpoint both do. Changing what
  the existing findings CSV writes would change every findings CSV this product
  has produced, and altering an existing deliverable was not that phase's
  business. It is recorded in the tracker rather than fixed in passing.

- **The export is scan-scoped and reads the scan's own immutable snapshot.**
  The current policy row is never consulted — it may have been edited since, and
  that changes nothing about what the scan assessed. Filters only ever narrow: a
  framework the scan's policy excluded cannot be named back in, because the rest
  of it was never assessed.

- **API**: `GET /reports/download/{id}?fmt=XLSX` for the whole-scan workbook,
  and `GET /reports/export/{id}` for the filterable form (`xlsx|csv|json` ×
  `all|compliance|findings|comparison`). `fmt=csv` with `dataset=all` is
  refused — a CSV is one table, and picking whichever came first would be a
  silent choice about what the caller receives. A named comparison baseline goes
  through the same visibility check as the scan itself.


## Reports

- `GET /reports/download/{scan_id}?fmt=…` — `JSON`/`executive` → executive PDF,
  `XML`/`technical` → technical PDF, `CSV` → host inventory. All PDF; the
  `JSON`/`XML` names are historical.
- Reports are generated at scan completion and stored on
  `scans.report_executive_path` / `report_technical_path`. The download endpoint
  serves the stored file and only regenerates when it is missing — do not make
  generation unconditional again (it orphaned a PDF pair per download and bumped
  `scans.updated_at`, which corrupted the Scan History date).
- XLSX is `?fmt=XLSX` on the download route and `GET /reports/export/{id}`
  (`reporting/xlsx_generator.py`; see "Exports"). DOCX exists only in
  Compliance.
