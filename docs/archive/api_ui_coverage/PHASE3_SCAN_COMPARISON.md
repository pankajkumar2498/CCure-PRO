# Phase 3 — Scan comparison: API → UI coverage

Audited and implemented 22 Sep 2026 against the running API, using the two
credentialed scans of the same Windows 11 host either side of the
`state_operator` fix. That pair is an unusually good subject: the 24 findings
it reports as _fixed_ are the 24 false FAILs that fix removed, so the numbers
mean something rather than merely being non-zero.

## Endpoint

`GET /scans/{scan_id}/comparison` — the only endpoint in this feature.

| Property   | Value                                                                                                  |
| ---------- | ------------------------------------------------------------------------------------------------------ |
| Permission | **`scans:read`** — not the `reports:read` Phase 2's exports need                                       |
| Rate limit | 30/minute                                                                                              |
| Scoping    | both scans through `_get_scan_or_404`, so a baseline in another tenant is unreachable by naming its id |

| Parameter          | Default                                                | Verified behaviour                                          |
| ------------------ | ------------------------------------------------------ | ----------------------------------------------------------- |
| `baseline`         | most recent completed scan of the same `pipeline_mode` | changes the delta and is recorded in exports                |
| `asset_id[]`       | none                                                   | intersected with shared assets — **see the quirk below**    |
| `severity[]`       | none                                                   | narrows: 3,755 → 312 changes                                |
| `limit`            | 500 (1–5000)                                           | bounds **rows, never counts** — verified at `limit=1`       |
| `include_findings` | true                                                   | false → 0 rows, counts intact                               |
| `org_id`           | none                                                   | superadmin cross-tenant addressing; not an operator control |

## Response → UI

| Field                                                   | Live shape                                                                                               | UI                                                                     |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `comparable`, `reason`                                  | bool + text                                                                                              | "Not comparable" panel; a caveat banner when comparable _and_ reasoned |
| `summary`                                               | `"0 new, 1862 unchanged, 24 fixed, 0 reappeared, 1869 not assessed"`                                     | headline, rendered verbatim                                            |
| `counts`                                                | five classes                                                                                             | five summary cards                                                     |
| `severity_counts`                                       | per class × severity                                                                                     | severity bands inside each card                                        |
| `findings[]`                                            | 12 fields incl. multi-line `evidence`                                                                    | filterable, searchable, paginated table with expandable detail         |
| `current_scope` / `baseline_scope`                      | `recorded`, `families`, `assets`, `detail{checks_assessed, config_audit_assessed, assessed_checks[216]}` | side-by-side scope panels                                              |
| `current_policy` / `baseline_policy` + `policies_match` | `{recorded:false}` × 2, `false`                                                                          | **three-state** agreement banner                                       |
| `assets[]`                                              | real ids                                                                                                 | asset picker, constrained to these                                     |

## Three decisions the data forced

**The vocabulary is exactly five, and the UI invents no sixth.** `new`,
`still_open`, `fixed`, `reappeared`, `not_assessed`. There is no `changed`
class and no separate `unchanged` — `still_open` _is_ unchanged. There is no
severity-transition record either, so "severity changes" exists only as
`severity_counts` per class, which is what is rendered.

**`not_assessed` is a summary card, not a footnote.** On this pair it is 1,869
against 24 fixed. A finding absent from a scan that never looked for it is not
fixed, and a page that showed the second number without the first would report
progress nothing established.

**Policy agreement is three states.** `policies_match` is a boolean over a
three-valued question: the backend returns `false` both when fingerprints
differ and when either snapshot was never recorded, and `policies_comparable`'s
own docstring says the unrecorded case is _"reported as unknown rather than as
equivalent"_. Both scans here are `{recorded: false}`, which is the common case
for anything predating GAP-12. Rendering that as "the policies differ" would
assert exactly what the backend refused to, so the UI reads `recorded` and
`policies_match` together and renders **Same / Different / Not recorded**.

## A backend quirk the UI routes around

An asset filter that matches nothing **becomes no filter at all**.
`comparison.assets = shared & wanted`; when that intersection is empty the
query is never narrowed, because the code guards on `if comparison.assets:`.
Measured:

    (no filter)          not_assessed = 1869,  assets = [ast_org_…]
    asset_id=<real>      not_assessed = 1869,  assets = [ast_org_…]
    asset_id=nope        not_assessed = 2878,  assets = []

So a nonexistent id returns _more_ rows, reclassified into `not_assessed`
because the scope no longer covers them. The picker offers only ids the
response itself returned, which makes the case unreachable from the UI. It is
documented here rather than worked around in the backend — that would be a
change this phase was not asked to make, and the classification itself is not
wrong, only surprising.

## Phase 2's deferred `baseline`, now closed

Phase 2 left `/reports/export?baseline=` unexposed for want of a scan picker.
The comparison page has one, so the export panel embedded there passes the
baseline being viewed. Verified against the live API:

    dataset=comparison                     -> Baseline Scan ID = …_j4w3  (backend default)
    dataset=comparison&baseline=…_1tym     -> Baseline Scan ID = …_1tym  (operator's choice)

Without it an exported comparison would silently be against a different
baseline from the one on screen.

## Entry points

One coherent feature, not a page per endpoint: `/scan/comparison?scan_id=…`,
reached from the credentialed results header and from each eligible row in Scan
History. The Scan History control is hidden for running scans — a scan with no
findings has no comparison — and its accessible name carries the scan number,
because every action in that list must be distinguishable across rows.

## Known limitations

- **`include_findings=false`** is not exposed. It exists to let a caller fetch
  counts without rows; the page always wants both, and a control whose only
  effect is to empty the table is not an operator feature.
- **`limit` is not exposed.** It is fixed at the API default of 500. Raising it
  trades page weight for a longer sample and never changes a count; the page
  says when the list is a sample instead.
- **`org_id`** is superadmin cross-tenant addressing, not an operator control.
- **No export of the comparison view's own filters.** The embedded export panel
  carries the baseline but not the page's severity or asset selection — the two
  filter sets are independent and the export endpoint's own filters are the
  ones it applies.
