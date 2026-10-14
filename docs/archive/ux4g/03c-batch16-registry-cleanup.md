# Checkpoint 3C — Batch 16: AssetRegistry and VulnerabilityBrowser off dashboard.css

This batch moves `AssetRegistry` and `VulnerabilityBrowser` onto the design
system's primitives: CcureTable, CcureButton, CcureAlert, CcureBadge,
CcureSeverityBadge, CcureSkeleton and CcureEmptyState.

- Both pages stop importing `dashboard.css`. What they still borrowed from it
  is restated in their own token-only stylesheets.
- The VulnerabilityBrowser CVSS `toFixed()` crash is fixed.
- The keyboard barriers on both pages are fixed.

The validation harness was restored in the repository first and proven on the
pre-batch build before these results were measured. That work is described in
[`03c-batch16-harness.md`](03c-batch16-harness.md).

**Not touched:**

- SecurityDashboard and ComplianceWorkspace. The harness shows them identical,
  §0.
- `dashboard.css`: no diff against HEAD.
- The ten unmigrated pages.
- CcureRiskRing and the NetworkMap token resolver.
- Phase3 auto-start and the AMT confirmation.
- The Toast shim, RiskBadge, and the global legacy CSS chain.
- WebSocket tickets, CSV formula injection, the unknown `pipelineMode` crash,
  and GHSA/OSV linking.
- AuditTimeline.
- The design-system directory: no new primitive.
- `api/*`, `auth/permissions`, `nginx.conf` and CSP.
- Every Batch 15 file.

Nothing is committed. Batch 15 is still uncommitted as well.

---

## 0. How this batch was verified

| Gate                                   | Result                                                                                                                                                                                                                                                                                       |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Harness first, on the pre-batch build  | Determinism **43 / 43**, sensitivity **20 / 20** ([harness §2](03c-batch16-harness.md#2-proof-on-the-pre-batch-16-build))                                                                                                                                                                    |
| Tests first, on the legacy pages       | 23 new tests: 22 failed on the pre-batch pages and 1 passed (see the note below the table)                                                                                                                                                                                                   |
| Same tests, migrated                   | **90 / 90** across the two page test files (67 existing + 23 new)                                                                                                                                                                                                                            |
| Corrections to the new tests           | 3, none weakening an assertion (§0.1)                                                                                                                                                                                                                                                        |
| Full frontend suite                    | 50 files, **1586** tests, all passing (1563 after Batch 15, plus 23)                                                                                                                                                                                                                         |
| Lint                                   | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                          |
| Build                                  | `vite build` succeeds. Vite's chunk-size warning predates this batch                                                                                                                                                                                                                         |
| Post determinism                       | post-a vs post-b **43 / 43** identical, on the final build                                                                                                                                                                                                                                   |
| SecurityDashboard, ComplianceWorkspace | **18 / 18** captures identical pre → post in every category, on both capture pairs: pre-a vs post-a with `--identical sd-,cw-`, and pre-b vs post-b                                                                                                                                          |
| `dashboard.css`                        | No diff against HEAD. Importers **4 → 2**: SecurityDashboard and ComplianceWorkspace remain                                                                                                                                                                                                  |
| CSP and security headers               | All six security headers, CSP included, identical on the pre and post images                                                                                                                                                                                                                 |
| Air gap                                | The served web roots of the pre and post images reference the same set of absolute hosts (library and error-message strings, and the NVD link target). 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                      |
| Contrast (harness, measured)           | Failing text pairs per migrated state, pre → post: 8–24 → **0** (8–24 on every state that rendered; the null-CVSS state crashed before it could be measured). Measured pairs did not fall (113 → 117 on `ar-assets.light`, 84 → 85 on `vb-cve.light`). The token contrast suite still passes |
| Isolation, every post capture          | 86 captures (43 × 2): 0 refused writes, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 error boundaries, 0 unready states, 0 horizontal overflow. The pre build had 1 console error and 1 unready state, both the null-CVSS crash                                    |

The one new test that passed on the legacy page was "offers no managed toggle
without assets:update". The legacy page had no toggle buttons at all, so its
first assertion held vacuously. Its second assertion, that the managed value is
still stated, is a real check.

### 0.1 Corrections to the new tests

- **Two source-file reads.** They built a path with
  `new URL(rel, import.meta.url)`. Vite rewrites that pattern into an asset URL,
  which is not a file path. They now use the `fileURLToPath` idiom
  `CVELink.test.jsx` already used.
- **One fixture.** The services-dialog test answered `/assets/services/assets`
  with asset-registry rows (`id`, `hostname`). That endpoint returns
  `asset_id`, `asset_hostname` and `asset_ip` (`Backend/routers/assets.py`),
  which is what the page reads, both before and after this batch. With the
  wrong shape the link had no name, and the test failed for a reason unrelated
  to the change.

### 0.2 A defect this batch caused, found by the harness and fixed

**The mobile state scrolled sideways.** `ar-assets-mobile.light` measured
`overflowX` false on the pre build and true on the post build: at 390px the
document was 705px wide. Nothing in the screenshot showed it.

**How it was found.** The first guess was the page header. `dashboard.css`
stacks `.db-page-header` below 768px, and that media query had not been carried
over. It is now carried over on both pages, which restores the legacy mobile
header layout, and it is kept. But the rebuilt image still measured the
overflow.

The DOM was then bisected in the browser: hide each child in turn, keep the
one whose removal ends the overflow, and descend into it. The search ended at
the asset table's header row.

**The cause.** The C, H and M headers carry their full word in a `cc-sr-only`
span, and that class is `position: absolute`.

- The legacy `.db-table th` was `position: sticky`, so the header cell was the
  span's containing block, and the span stayed inside the table.
- CcureTable's header cells are not positioned. The span's containing block
  became the viewport, so it escaped both the card's `overflow: hidden` and the
  table's scroll container.

**The fix.** `.ar-card` is now `position: relative`. So is `.vb-card`, which
had no such span but the same exposure. On the image rebuilt with the fix,
`overflowX` is false for both `ar-assets-mobile.light` and
`vb-cve-mobile.light`.

---

## 1. Files changed

| File                                                | Change                                                                                                                      | LOC         |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `src/pages/AssetRegistry.jsx`                       | CcureTable ×4, CcureButton, CcureAlert, CcureSeverityBadge; links and a toggle button; `dashboard.css` import removed       | 1518 → 1463 |
| `src/pages/VulnerabilityBrowser.jsx`                | CcureTable ×2, CcureButton, CcureAlert, CcureBadge, CcureSeverityBadge; drawer is a modal dialog; null CVSS; import removed | 984 → 1038  |
| `src/styles/asset-registry.css`                     | Page frame, card, chip, risk bar, link and toggle focus, mobile header, in tokens; three dead rules removed                 | 470 → 598   |
| `src/styles/vulnerability-browser.css`              | Page frame, card, row controls, `--none` CVSS, focus ring fixed, mobile header; three dead rules removed                    | 466 → 568   |
| `src/__tests__/pages/AssetRegistry.test.jsx`        | +10 tests                                                                                                                   | 38 → 48     |
| `src/__tests__/pages/VulnerabilityBrowser.test.jsx` | +13 tests                                                                                                                   | 29 → 42     |
| `scripts/ux4g-harness/**`                           | New: the harness, [harness doc](03c-batch16-harness.md)                                                                     | 13 files    |

| Measure                                          | AssetRegistry                                                                   | VulnerabilityBrowser                                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `db-*` class tokens                              | 81 → **0**                                                                      | 59 → **0**                                                                                                 |
| Click handlers on elements that are not controls | 19 → **3**: the row, the dialog backdrop, the dialog's stop-propagation wrapper | 4 → 4: two rows, the actions cell's stop-propagation, the drawer scrim; each now has a keyboard route (§2) |
| `<th onClick>` sort headers                      | 13 → **0**                                                                      | —                                                                                                          |
| Tables with exactly one caption, as first child  | 0 of 1 → **4 of 4** (assets, services, certificates, dialog)                    | 1 of 2 → **2 of 2**                                                                                        |
| Inline `style` attributes                        | 1 → 1 (the risk bar's width, which is per-row data)                             | 0 → 0                                                                                                      |
| Colour literals in code                          | 0 → 0                                                                           | 0 → 0                                                                                                      |

---

## 2. Accessibility

Each item below was a barrier on the pre build and is measured fixed on the
post build by a harness keyboard probe (real key events in Chrome) as well as
by a unit test.

### AssetRegistry

- **Thirteen sort headers were click-only.** They were `<th onClick>`: three on
  assets, five on services, five on certificates. Each is now a button inside
  the header, and the header carries `aria-sort`. The page's own direction rules
  are unchanged:

  - a newly chosen asset column starts descending;
  - a newly chosen service or certificate column starts ascending;
  - choosing the current column again flips it.

  CcureTable proposes a direction, and it is ignored: only the column key is
  passed to the existing handlers.

  _Probes:_ sort by IP and sort by port went from not reached to reached. The
  requests carried `sort_by=ip_address&sort_dir=desc` and
  `sort_by=port&sort_dir=asc`.

- **The asset drill-down was a row click.** The address is now a link to
  `/assets/:id`, and the row keeps its click. _Probe:_ Enter on the link lands
  on `/assets/a-1`.
- **The managed state was a click handler on a cell.** With `assets:update` it
  is now a `button` with `aria-pressed`, named `Managed: <host>`. Without the
  permission it is a plain chip, and nothing is offered. The PATCH body is still
  `{ is_managed: !current }`.

  _Label in name:_ the visible text is the value ("✔ Managed" or "✗
  Unmanaged"), and the name stays constant while `aria-pressed` carries the
  state. This follows the toggle-button pattern: a name that flips alongside
  `aria-pressed` would announce a double negative. The cost is that "Unmanaged"
  is not contained in the accessible name.

- **The certificate asset was a `<div onClick>`.** It is now a link. _Probe:_
  went from not reached to reached.
- **The asset in the services dialog was a `<span onClick>`.** It is now a link,
  and following it closes the dialog.
- **Captions were wrong.** The asset table carried three captions: its own and
  those of the services and certificate tables, which were not on screen. The
  other three tables had none. Each of the four now has exactly one.

### VulnerabilityBrowser

- **Only some findings could be opened from the keyboard.** The only keyboard
  route to a finding was the "Details" button, which exists only for an open
  finding and only with `findings:update`. The finding's title is now a button
  that opens the drawer for every finding and every persona. _Probe, read-only
  persona:_ went from not reached to reached; the dialog opened and Escape
  closed it.
- **The component drill-down was a row click.** The component name is now a
  button that does the same thing. _Probe:_ went from not reached to reached,
  and the `search=google-chrome` request was sent.
- **The drawer was not a dialog.** It is now `role="dialog"` with
  `aria-modal`, named by its CVE through the heading.
  - Focus is trapped with `useFocusTrap`, the same hook as AssetDetail's drawer.
  - Escape closes it, and focus returns to the control that opened it.
  - The close button was a bare "✕", which the harness recorded as a glyph-only
    button. It is now named "Close finding details".
  - The two triage text boxes had no names. They are now named.
  - _Probe, before:_ Escape did not close the drawer.
- **The view toggle showed no focus indicator.** Its rule set
  `outline: var(--ccure-focus-ring)`, but that token is a box-shadow value, so
  the declaration was invalid. The ring is now an inset box-shadow with a band
  of page colour, so it shows on the selected button's primary fill too.
  _Probe:_ the ring went from absent to present in both themes.
- **The CVE table's caption was inside `<thead>`.** The harness flagged it as
  misplaced. It is now the table's first child.
- **The triage save message is a status region** (§4).

### Contrast

The pre-batch failures were legacy `dashboard.css` colours:

| Legacy rule        | Contrast                  |
| ------------------ | ------------------------- |
| `.db-table th`     | 2.56:1 light, 3.07:1 dark |
| `.db-btn--primary` | 2.77:1 on "+ New Scan"    |
| `.db-tag`          | 3.86:1                    |

With the pages on tokens, no measured text pair fails.

---

## 3. Security validation

- **No request changed.** In every migrated state where no keyboard probe
  newly succeeds, the pre and post request logs are identical. The added
  requests all come from probes that now reach their target:

  - the two sort requests above;
  - the component drill-down (the grouped view's reload, then the debounced
    search);
  - the drawer's `GET /findings/f-1` on the read-only persona;
  - the AssetDetail page loaded after the row link.

  All of these are reads with the parameters a mouse click sends. No request
  disappeared. No capture made a write.

- **RBAC is unchanged.**
  - `findings:update` still gates the Actions column and the triage form.
  - `assets:update` still gates the managed toggle.
  - The read-only personas were captured: `ar-assets-readonly` has no toggle,
    and `vb-cve-readonly` has no Actions column or triage, but can open and read
    the drawer.
  - The 67 existing tests pin the endpoints, parameters, PATCH body and gates,
    and pass unchanged.
- **Nothing new executes or navigates off site.**
  - No new dependency and no `dangerouslySetInnerHTML`.
  - The new links are router links to `/assets/:id`, built from API ids, which
    is the destination `navigate()` already used.
  - The drawer's reference links are unchanged: `target="_blank"` with
    `rel="noopener noreferrer"`.
- **CSP, security headers and air gap:** identical between the pre and post images (§0).

---

## 4. Intentional behaviour changes

1. **An absent CVSS v3 score shows "—".** This applies to the finding row, a
   component's worst CVSS, and the drawer. It is not painted in any band.
   Before:

   - the row threw on `null.toFixed()` and the whole page went to the error
     boundary;
   - the group showed `Number(null).toFixed(1)` = "0.0" in the medium band;
   - the drawer showed `(null || 0).toFixed(1)` = "0.0".

   Thresholds are unchanged (≥ 9 critical, ≥ 7 high).

2. **The triage save message stays visible.** It sat inside the form, which a
   successful save closes, so it was removed in the same render that set it. It
   now sits outside the form and outside the open-status gate, as a status
   region.
3. **The drawer takes focus when it opens,** on its first control (the close
   button). Escape closes it, and focus returns to the opener.
4. **Status, priority and severity chips are design-system badges.**
   - Status uses CcureBadge: open danger, accepted warning, fixed success. These
     are the same colour families as before.
   - Priority uses CcureBadge: P0 danger, P1 and P2 warning, P3 info, P4
     neutral. P1 and P2 now share a colour, and the label tells them apart.
   - A missing priority renders nothing; before, it rendered an empty chip.
   - Severity uses CcureSeverityBadge. Labels are normalised ("critical" shows
     as "Critical"), and an unrecognised value reads "Unscored"; before, the raw
     value was shown in info colours.
5. **A certificate with no `asset_id` shows its host as text.** Before, clicking
   it navigated to `/assets/undefined`.
6. **Buttons and table headers follow the design system.**
   - The legacy bordered ghost button is now CcureButton `secondary` (32px
     minimum height).
   - Legacy uppercase 0.65rem letter-spaced faint headers are now CcureTable's
     sentence-case semibold headers. This is also what cleared the header
     contrast failures.
7. **Dark theme page background** is now `--ccure-bg`, which matches the
   application shell. Before, it was `dashboard.css`'s navy `--bg-app`.
8. **The asset address is link-coloured,** because it is a link.
9. **Below 768px the page header stacks,** as `dashboard.css` did (§0.2).

---

## 5. Retirement

- **`dashboard.css` importers go from 4 to 2.** SecurityDashboard and
  ComplianceWorkspace remain. The file is unedited and unpruned, as scoped.
- **Page rules this batch made dead are removed:**

  - `.vb-skel` and `.vb-skel--title`, replaced by CcureSkeleton;
  - `.vb-status--open`, `--accepted` and `--fixed`, replaced by CcureBadge;
  - `.ar-skel`, replaced by CcureTable's skeleton rows;
  - `.ar-pagebtn`, replaced by CcureButton;
  - `.ar-managed--actionable`, whose role the button now plays.

  `.vb-checkline` was already dead before this batch and is left alone.

- **The two pages no longer use `.mono` or `.cve-id`** (`scan.css`); `.ar-mono`,
  `.vb-mono` and `.vb-cve-cell` replace them. The services dialog still uses
  `scan.css`'s `.modal*` classes. Nothing in `scan.css` was changed.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical sd-,cw-` exits 0. All 18 SecurityDashboard and ComplianceWorkspace captures are identical, and pre-b vs post-b is likewise 18 / 18. All 25 AssetRegistry and VulnerabilityBrowser captures changed, and no request disappeared from any of them.

For AssetRegistry and VulnerabilityBrowser, every changed category is
accounted for:

| Category                                    | Why it changed                                                                                                                               |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| names, ariaStates, tables, tabOrder, probes | The fixes in §2: named controls, `aria-sort`, `aria-pressed`, one caption per table, new tab stops for links and buttons, probes now reached |
| headings, dialogs, live                     | The drawer's `<h2>`, the modal dialog, the save-message status region                                                                        |
| classes                                     | `db-*` elements go to 0 on every state; `cc-*` elements rise                                                                                 |
| contrast                                    | Failing pairs go to 0 (§2)                                                                                                                   |
| text                                        | Sentence-case headers, normalised badge labels, "—" for an absent CVSS, the null-CVSS page rendering at all                                  |
| styles, rects, screenshot                   | The restyle                                                                                                                                  |
| inline                                      | The risk bar's inline width is unchanged; its class signature changed                                                                        |
| roles (mobile)                              | CcureTable gives its scroll container `role="region"` while the table overflows it                                                           |
| overflow                                    | None on the final build. The first post build's overflow on `ar-assets-mobile` is described in §0.2                                          |
| requests, runtime                           | Probe-caused reads and the AssetDetail navigation (§3); on `vb-cve-nullcvss` the page now becomes ready with 0 console errors                |

---

## 7. Deferred, and found but not fixed

- **Every "View Assets" button has the same name.** A test pins the exact
  name. A later batch can add the service to it, as was done for "Details for
  <CVE>".
- **A failed managed-state PATCH is silent.** The `/* silent */` catch predates
  this batch and is preserved.
- **ComplianceWorkspace has keyboard problems.** Its title is not a heading and
  its tabs are not buttons, which were seen while writing its harness states.
  The page is out of scope.
- **CcureTable does not contain absolutely positioned content in its cells.**
  Its cells and its scroll container are not positioned, so a `cc-sr-only`
  label in a header or cell takes a containing block outside the table. It can
  then widen the page (§0.2). This batch contains it at page level. A fix in
  the primitive, such as `position: relative` on `.cc-table-wrap`, would
  change every CcureTable in the application, and the design system is out of
  scope here.
- **The harness has no AssetDetail fixtures.** The row-link probe lands on
  AssetDetail with unstubbed reads (404). This is a coverage gap, not a page
  defect.
- **The harness's own limits** are in [harness §5](03c-batch16-harness.md#5-limits).

---

## 8. Stop

Batch 16 ends here. Nothing is committed, and no Batch 17 work has started.
