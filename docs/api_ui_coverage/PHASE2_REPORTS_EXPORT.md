# Phase 2 — Reports and export: API → UI coverage

Audited and implemented 22 Sep 2026. Every row below was measured against the
running API with a real scan (`scn_defa_c522b539_22sep26_d0td`, 254
configuration checks and 1,871 findings), not read off the route signatures.

## Endpoints

| Endpoint                 | Method | Permission       | Rate limit | UI                                            |
| ------------------------ | ------ | ---------------- | ---------- | --------------------------------------------- |
| `/reports/download/{id}` | GET    | `reports:read`   | 20/min     | Reports & Export panel; SecurityReports cards |
| `/reports/export/{id}`   | GET    | `reports:read`   | 10/min     | Reports & Export panel                        |
| `/reports/{id}`          | DELETE | `reports:delete` | —          | SecurityReports (pre-existing)                |

**Export is not implied by being able to see a scan.** Both read routes check
`reports:read`, which is a separate grant from `scans:read`; delete checks
`reports:delete`. Superadmin bypasses both. The panel renders an explanation
rather than disabled controls when the permission is absent, because a row of
dead buttons does not tell anyone what they are missing.

## `/reports/download` — eleven aliases, four artefacts

`_FORMAT_ALIASES` maps eleven spellings onto four outputs. Measured:

| Alias                                       | Artefact       | Content type              |
| ------------------------------------------- | -------------- | ------------------------- |
| `JSON`, `PDF`, `EXECUTIVE`, `EXECUTIVE_PDF` | executive PDF  | `application/pdf`         |
| `XML`, `TECHNICAL`, `TECHNICAL_PDF`         | technical PDF  | `application/pdf`         |
| `CSV`                                       | host inventory | `text/csv; charset=utf-8` |
| `XLSX`, `EXCEL`, `WORKBOOK`                 | workbook       | `…spreadsheetml.sheet`    |

An unknown value is a 400 naming the supported set. **`fmt=JSON` is the
executive PDF and `fmt=XML` is the technical PDF** — historical names the API
still speaks, and the reason `api/reports.js` owns the mapping so no caller has
to know it and nobody "corrects" a label into something the backend refuses.

Before this phase the UI reached two of the four. CSV and XLSX had never been
callable from anywhere in the application.

## `/reports/export` — the supported matrix

Measured, every cell:

| Format   | all               | compliance | findings | comparison |
| -------- | ----------------- | ---------- | -------- | ---------- |
| **xlsx** | ✓                 | ✓          | ✓        | ✓          |
| **csv**  | **refused (400)** | ✓          | ✓        | ✓          |
| **json** | ✓                 | ✓          | ✓        | ✓          |

`csv` + `all` is refused with _"A CSV holds one table."_ The UI disables that
option and shows the reason rather than letting the operator earn the 400.

Dataset semantics, from the handler rather than the names:

- **compliance** — the per-check verdicts the Phase 3 engine produced _during
  this scan_, read back unchanged. Nothing is re-evaluated at export time, so
  the six states stay six states.
- **findings** — vulnerability and configuration findings with their GAP-14
  remediation record.
- **comparison** — the GAP-13 change set against a baseline scan.
- **all** — the three above as separate worksheets. XLSX only.

Every row carries the scan's own immutable GAP-12 policy snapshot. The
_current_ policy row is deliberately not consulted: it may have been edited
since, and that changes nothing about what this scan assessed.

## Filters

Eleven query parameters exist. Six are exposed, and the choice is recorded
rather than left implicit.

| Parameter                 | Exposed | Reason                                                                                                                                                       |
| ------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `severity[]`              | yes     | checkbox group                                                                                                                                               |
| `verdict[]`               | yes     | checkbox group                                                                                                                                               |
| `status[]`                | yes     | checkbox group                                                                                                                                               |
| `overdue_only`            | yes     | checkbox                                                                                                                                                     |
| `scope` (`scan｜asset`)   | yes     | select; widens to every finding held against the assets this scan touched                                                                                    |
| `dataset`, `fmt`          | yes     | the two selects                                                                                                                                              |
| `include_comparison`      | no      | only meaningful with `dataset=comparison`, where turning it off empties the export — a control whose only effect is to produce nothing                       |
| `baseline`                | no      | needs a scan picker, which is Phase 3's comparison UI; the API's default (most recent completed scan of the same pipeline mode) is the one an operator wants |
| `asset_id`, `host`        | no      | this panel is scan-scoped and the scan's hosts are already on the page; a host filter belongs with a multi-host view                                         |
| `framework_id`, `profile` | no      | needs the tenant's installed-framework list, which this panel does not load; filters narrow, so omitting them exports more rather than less                  |
| `org_id`                  | no      | cross-tenant addressing, superadmin-shaped, not an operator control                                                                                          |

**`min_severity` on `/reports/download` is a dead parameter.** It is declared
in the signature and appears exactly once in `routers/reports.py` — its own
declaration. It is accepted and never read. Exposing it would be a filter that
silently does nothing, so it is not exposed, and this note is the record of why
rather than an omission somebody has to rediscover.

## The serialization defect this phase nearly shipped

Measured against the live API:

    ?fmt=json&dataset=findings&severity=critical     -> 154 rows
    ?fmt=json&dataset=findings&severity[]=critical   -> 1862 rows

FastAPI binds a `list[str]` Query from **repeated bare names**. The bracketed
form arrives as one parameter literally named `severity[]`, matches nothing in
the signature, and is dropped — so the export succeeds, downloads, and contains
everything. That is the worst failure shape available on this path: it is
indistinguishable from a correct filtered export until somebody counts the
rows.

**Axios's default is the bracketed form.** `exportScanDataset` therefore passes
`paramsSerializer: { indexes: null }`, and
`__tests__/api/reportsQuerySerialization.test.js` asserts the emitted query
string against a real HTTP server, in the node environment, rather than
asserting the option is present.

## Error contract

Uniform envelope: `{success, error_code, message, detail, request_id}`. The
panel prefers the backend's own wording and only special-cases where the status
carries meaning the message does not.

| Status    | Handling                                                                                                                                                          |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400 / 422 | the API's message (e.g. the CSV refusal)                                                                                                                          |
| 401       | session expired — sign in again                                                                                                                                   |
| 403       | the API's message, else the standard denial                                                                                                                       |
| 404       | scan gone, or produced no results                                                                                                                                 |
| 429       | names the wait from `retry_after_seconds` (measured: 60)                                                                                                          |
| 503       | `XlsxUnavailable` — openpyxl missing on the deployment. Never degraded into another format: an export that silently changes shape is worse than one that refuses. |

A 4xx body arrives as a Blob because the request sets `responseType: "blob"`,
so it is read back and parsed before the message is used. Without that the
operator sees a generic failure while the server's explanation sits unread in
the response.

## Files

Added: `src/api/reports.js`, `src/utils/download.js`,
`src/components/scan/ReportExportPanel.jsx`,
`src/__tests__/components/scan/ReportExportPanel.test.jsx`,
`src/__tests__/api/reportsQuerySerialization.test.js`,
`src/__tests__/utils/download.test.js`.

Changed: `src/pages/scan/CredentialedResults.jsx` (panel + toast provider),
`src/pages/SecurityReports.jsx` (all four formats, on the shared helpers),
`src/styles/credentialed-results.css`, and three test files whose contracts
changed deliberately — noted in place.

## Known limitations

- **Seven of the eleven export filters are unexposed**, each for the reason in
  the table above. All are reachable from the API.
- **`saveResponseAsFile` is used by two callers, not eight.** Six other places
  still hand-roll a blob download. Consolidating them is a separate change and
  would put unrelated pages in this diff.
- **`fmt=json` returns a body, not an attachment.** It carries no
  `Content-Disposition`, so the saved file is named by the client. Documented
  in `utils/download.js` as the one case where the fallback name is the only
  name available.
