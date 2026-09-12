# Checkpoint 3C — Batch 11: Dashboard, AssetDetail, AuditTimeline

**Recommendation: GO — Batch 11 complete. STOP before Batch 12.**

Companion documents: [03c-batch11-plan.md](03c-batch11-plan.md) (inventory,
reassessment, baseline design) and [03c-batch11-harness.md](03c-batch11-harness.md)
(instrument changes and every gate result).

---

## 1. What was migrated, and what was not touched

| Surface                   | File                                                                                                                        | Action                                                                                                                                                                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard `/scan`         | `src/pages/Dashboard.jsx`                                                                                                   | rewritten on `CcureModal`, `CcureInput`, `CcureEmptyState`, `CcureBadge`; new `src/styles/scan-templates.css`                                                                                                                            |
| AssetDetail `/assets/:id` | `src/pages/AssetDetail.jsx`                                                                                                 | rewritten on `CcureTabs`/`CcureTabPanel`, `CcureCard`, `CcureBadge`, `CcureSeverityBadge`, `CcureButton`, `CcureInput`/`CcureField`, `CcureSkeleton`, `CcureEmptyState`, `CcureAlert`, `useFocusTrap`; new `src/styles/asset-detail.css` |
| AuditTimeline             | `src/components/assets/AuditTimeline.jsx`                                                                                   | rewritten on `CcureTabs`, `CcureBadge`, `CcureSeverityBadge`, `CcureButton`, `CcureEmptyState`; `src/styles/audit-timeline.css` rewritten on tokens (page-owned; AssetDetail is the only consumer)                                       |
| Tests                     | `__tests__/pages/Dashboard.test.jsx`, `__tests__/pages/AssetDetail.test.jsx`, `__tests__/components/AuditTimeline.test.jsx` | baseline suites carried; 6 failure-feedback tests and a 14-test AuditTimeline suite added                                                                                                                                                |

**Untouched, verified by `git diff` against HEAD:** `dashboard.css` (still 7
consumers — 6 after this batch stops using it, without editing the file),
`scan.css`, `layout.css`, every legacy shared component (`Modal`, `CVELink`,
`Toast`, …), every other page, `nginx.conf`, `PreferencesContext`, the
design-system directory (no new primitive was created), `api/*`.

The legacy `.scan-card*` / `.modal-panel-grid` rules in `scan.css` now have
**zero consumers** and were **not pruned** (no pruning was approved).

## 2. Metrics

|                                         | before |                                                                                  after |
| --------------------------------------- | -----: | -------------------------------------------------------------------------------------: |
| Dashboard LOC                           |    537 |                                                                                    467 |
| AssetDetail LOC                         |  2,417 |                                                                                  1,484 |
| AuditTimeline LOC                       |    400 |                                                                                    377 |
| Inline styles (three files)             |    202 |                                                                                  **0** |
| Colour literals in JSX                  |     99 |                                                                                  **0** |
| Colour literals in `audit-timeline.css` |     11 |                                                                                  **0** |
| `dashboard.css` classes consumed        |     36 |                                                                                  **0** |
| New page-owned CSS                      |      – | 1,285 lines, 0 literals (`asset-detail.css` names three removed literals in a comment) |

Harness census across the 34 states, pre → post: inline-styled elements
**1,193 → 7** (all seven are `CVELink`'s own anchor style — recorded debt),
unlabelled controls **27 → 0**, tables with captions **0 → 6**, fully scoped
headers **0 → 6**, elements with roles **0 → 101**, ARIA states **0 → 74**,
live regions **0 → 5**, h1 present **4 → 16** (every AssetDetail state except
the error state; Dashboard already had one). Duplicate button names stay
**13 → 13**: the Dashboard modal lists the same thirteen cards as the grid
behind it; `CcureModal` marks the rest of the application `aria-hidden` while
it is open, so the duplicates are never exposed at once.

## 3. Tests

| Suite                                 | Result                                                   |
| ------------------------------------- | -------------------------------------------------------- |
| Dashboard                             | 27 / 27 (22 baseline + 5 spec, all now passing)          |
| AssetDetail                           | 81 / 81 (63 baseline + 12 spec + 6 new failure-feedback) |
| AuditTimeline                         | 14 / 14 (new)                                            |
| Full suite                            | **1,275 / 1,275**, 0 unhandled                           |
| Lint (`--max-warnings=0`, whole tree) | 0                                                        |

Four baseline tests were adjusted for controls whose _shape_ changed, using
the dual-path convention (find the control as it was, else as it is now):
the views are `role="tab"` rather than buttons; the drawer close is named
"Close finding details" rather than "✕"; the tag submit is named "Add tag"
rather than "+"; the category filter icons are decorative so a pill is named
"Services" rather than "🔌 Services". One baseline assertion was inverted on
purpose — the status-save success message is now asserted **present** in a
live region (approved change 1); its previous form asserted it absent and
documented why.

## 4. Contracts — verified unchanged, by test

- Four reads on mount, `{ params: {} }`, nothing else; one `GET /findings/{id}`
  per drawer open (harness: exactly 6 across 3 drawer states × 2 themes).
- `PATCH /assets/{id} { is_managed }` optimistic, reverts on failure.
- `PATCH /assets/{id} { owner }`, cancel restores, failure keeps edit mode.
- `POST /assets/{id}/tags { tag }` then re-read; whitespace ignored.
- `DELETE /assets/{id}/tags/dmz%2Fprod` — encoding preserved, no confirmation
  (as before).
- `POST /assets/{id}/notes { content }` then re-read; newest first.
- `PATCH /findings/{id}/status { status, accepted_risk_reason, remediation_notes }`
  only after Confirm; choosing an action writes nothing; re-read afterwards;
  row status updated; failure keeps the panel.
- `assets:update` gates every write control, **including the finding-status
  actions** — the backend's different rule is recorded debt and was not
  changed (§8).
- Dashboard: `resetScan()` → `setPipelineMode(mode)` → `navigate("/scan/new")`
  in that order; direct routes touch nothing; unmapped cards inert; zero
  requests.
- Harness no-write gate on the migrated build: 34 non-GET, all the session
  stub; 0 PATCH/PUT/DELETE; 0 downloads; 0 off-origin.

## 5. Accessibility corrections

Dashboard: named search control; picker is a `role="dialog"` with
`aria-modal`, title as name, focus trap and Escape (`CcureModal`); the
fourteen icons are `aria-hidden`; the empty-search result is a `role="status"`;
badges follow the title so a card is "Malware Scan … Soon, coming soon" rather
than "Soon Malware Scan …"; the "coming soon" reason is announced text, not a
tooltip alone; card titles are spans (a heading inside a `<button>` violates
the content model and announces as a heading, not a name).

AssetDetail: one h1 (the address); `tablist`/`tab`/`aria-selected`/`tabpanel`;
captions and `scope="col"` on both tables; `aria-pressed` on the managed
toggle; expandable service rows are buttons with `aria-expanded`/`aria-controls`;
each finding row has a "Details for {id}" button; the drawer is a named modal
dialog with a real focus trap (correct `useFocusTrap(ref, active)` usage),
Escape, and a named close control; remove-tag and add-tag are named buttons;
owner, tag, note, reason and remediation inputs have labels; load failure is a
`role="alert"`; the risk ring is a `role="img"` with "Risk score 82 out of
100"; status feedback in a `role="status"` live region.

AuditTimeline: the view switch is a tab list; category filters are
`aria-pressed` toggles in a labelled group; group headers are buttons with
`aria-expanded`/`aria-controls`; the technical-details toggle carries
`aria-expanded`; the new-discovery dot has a text equivalent; old/new values
are prefixed for readers; decorative icons hidden.

## 6. Intentional behaviour changes

1. **Approved change 1 — status-save success is visible.** The message lives
   in a persistent live region in the drawer; the PATCH → re-read sequence is
   unchanged. Test: "Accept Risk sends PATCH … then re-reads" asserts the
   message in `role="status"`.
2. **Approved change 2 — write failures are reported.** Owner save, managed
   toggle, tag add, tag remove and note add show a dismissible danger alert
   naming what did not happen; state behaviour (revert / stay in edit mode /
   keep the tag / keep the draft) is unchanged; nothing retries; a later
   success clears the message. Six tests, each asserting exactly one request.
3. The finding row is no longer clickable as a whole; the "Details" button
   opens the drawer. The service row expands from its port button rather than
   the whole row.
4. Control names: "Close finding details", "Add tag", "Services" (icon
   decorative) — each recorded by the harness as a named button delta.
5. `CcureSeverityBadge` labels severities in title case ("High") where the
   timeline previously printed the raw value ("high"). AssetDetail's findings
   already arrived capitalised.
6. The main grid no longer has a fixed `calc(100vh - 250px)` height with an
   inner-scrolling sidebar; it flows naturally and stacks under 960 px.
7. Dashboard card icon colours come from six semantic tones (success, info,
   warning, danger, primary, neutral) instead of twenty-two literals; disabled
   cards dim the tile rather than the text.

## 7. Harness, contrast, bundle, security

See [03c-batch11-harness.md](03c-batch11-harness.md) §3–4 for every gate:
determinism byte-identical (pre ×3, post ×4), sensitivity 4/4 named on both
builds, unchanged control **91 states across 23 pages identical**, portal
and ARIA census measured live, viewer/superadmin distinction proven, prepare
steps guarded and asserted, no writes, no off-origin, 34/34 coverage.

**Contrast** (`contrast-batch11.mjs`, portal-aware): **332 → 7 sub-AA**
readings across the 34 states; **0 new colour pairs**. All seven remaining are
`CVELink`'s inline `color: var(--accent)` (#0ea5e9 on white, 2.77:1) — the
recorded debt, hosted in the findings table and the drawer title. The 32
light-shade literals the page carried are gone.

**Bundle:** CSS 313.33 kB → 331.36 kB (52.97 → 54.85 gz); JS 1,665.47 kB →
1,654.63 kB (421.10 → 419.96 gz). The CSS growth is the three page-owned
sheets; nothing was pruned.

**CSP** header byte-identical pre/post. **Air-gap:** 0 external requests in
506 logged; the only off-origin _strings_ in the bundle are SVG namespaces,
library documentation URLs and the NVD link template (an anchor, never
fetched). No UX4G runtime, no CDN, no fonts, no telemetry. No `ux4g-*` class in
application code; no `prefers-color-scheme`; `data-theme` remains the theme
mechanism. No credential or secret reaches the DOM — the drawer and panels
render OS metadata and finding data already on screen.

## 8. Newly discovered defects (recorded, NOT fixed)

1. **AssetRegistry's focus trap is inert (batch 10 regression).**
   `AssetRegistry.jsx:146` calls `useFocusTrap(Boolean(activeService))`; the
   hook's signature is `(ref, active)`, so it receives a boolean as the ref, an
   undefined `active`, returns nothing, and the dialog's `ref` is `undefined`.
   The batch 10 dialog has `role`, `aria-modal`, a name and Escape — and no
   focus containment or restoration. One-line fix
   (`const ref = useRef(null); useFocusTrap(ref, Boolean(activeService))`),
   outside this batch's scope by instruction. Flagged for a decision.
2. `scan.css` `.scan-card*`, `.badge-*`, `.modal-panel-grid` (≈13 rules) now
   have zero consumers.
3. `CVELink` is now the sole source of inline styles and sub-AA readings on
   three migrated pages (VulnerabilityBrowser, AssetRegistry, AssetDetail);
   the `CcureCveLink` pattern is the fix.

## 9. Deferred debt — confirmed untouched

`cvss_v3_score.toFixed()` (VulnerabilityBrowser:985, SecurityDashboard:1049),
ScanSchedules toast destructure, `useScanPolling`, ScanDetail `alert()`,
`CVELink`, AssetRegistry click-only sortable headers, `dashboard.css`,
`Skeleton.jsx`, `web-scanning.css`, `.page-subtitle`, NewWebScan items,
CredentialedScan OpenSSH copy, the AssetDetail finding-status UI gate
(`assets:update` vs backend `findings:accept_risk`), `AuditLogDetailsModal`
inline styles inside AuditLogs. All present; none modified.

## 10. Engineering gate

| Check                              | Result                            |
| ---------------------------------- | --------------------------------- |
| Batch suites                       | 27 + 81 + 14, all passing         |
| Full suite                         | 1,275 / 1,275, 0 unhandled        |
| Lint                               | 0                                 |
| Production build                   | succeeds                          |
| Docker build + serve               | HTTP 200                          |
| Harness determinism                | byte-identical, both builds       |
| Harness sensitivity                | 4/4 named, both builds            |
| Unchanged control                  | 91 / 91 states identical          |
| Portal / ARIA / names / viewer     | proven live                       |
| No writes / downloads / off-origin | 0 / 0 / 0                         |
| CSP                                | byte-identical                    |
| Air-gap                            | 0 external requests               |
| Contrast                           | 0 new pairs; 332 → 7, all CVELink |
| Previously migrated pages          | unchanged (91 states)             |

No STOP condition was triggered.

```
GO — Batch 11 complete
```

**STOP** — awaiting review before Batch 12.

---

## 11. Stage 1 remediation — AssetRegistry focus trap (post-checkpoint)

**Files changed:** `Frontend/src/pages/AssetRegistry.jsx` (2 lines + comment),
`Frontend/src/__tests__/pages/AssetRegistry.test.jsx` (6 tests, `within`
import). Nothing else; the hook itself is untouched.

**Code change:**

```diff
-  const serviceDialogRef = useFocusTrap(Boolean(activeService));
+  const serviceDialogRef = useRef(null);
+  useFocusTrap(serviceDialogRef, Boolean(activeService));
…
               aria-labelledby="ar-service-dialog-title"
               ref={serviceDialogRef}
+              tabIndex={-1}
```

`tabIndex={-1}` is part of the hook's contract, not styling: its documented
fallback focuses the container when no focusable child is found, "the last
needing tabindex="-1" on the container, which CcureModal sets". Under jsdom
no child has layout, so without it the fix was correct in a browser and
unverifiable in a test — which is how the original defect survived batch 10.

**Tests (all in the AssetRegistry suite):** focus enters the dialog on open;
12 × Tab and 12 × Shift+Tab stay inside; Escape closes; focus returns to the
"View Assets" opener; close control and backdrop still close; opening reads
`/assets/services/assets` exactly once and the trap adds no request (no GET,
PATCH, POST or DELETE). Focused suite **38 / 38**; full suite **1,281 / 1,281**,
0 unhandled; whole-tree lint 0.

**Harness:** batch 10's 19 routes (38 states, including the five AssetRegistry
states and `assetSvcDetail`, the dialog) captured on the approved batch 11
image and on the remediated build: **IDENTICAL**; the remediated build
captured twice, **byte-identical**. The dialog's role and name are unchanged
(`dialog|Associated Assets for ssh on Port 22/TCP`). The instrument does not
measure focus position, so the identical result proves _no regression_, not
the fix — the six unit tests prove the fix.

**Contracts:** no API, permission, business or visual behaviour changed;
`useFocusTrap` unchanged; no other deferred item touched.
