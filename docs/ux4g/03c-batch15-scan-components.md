# Checkpoint 3C — Batch 15: shared scan components

`ScanStepper`, `ScanQuotaBar`, `ExportPanel` and `CVELink` onto CcureBadge,
CcureCard, CcureButton and CcureAlert, each with a token-only stylesheet.
These four are the building blocks the ten remaining legacy pages consume;
none of them holds a socket, dispatches a scan or handles a credential.

**Not touched:** every consumer page — Phase1Results, Phase2Results,
Phase3Results, NewScan, CredentialedResults, ScanHistory, SecurityDashboard,
AssetDetail, VulnerabilityBrowser — plus `ScanContext`, `scanConfig`, `api/*`,
`auth/permissions`, `dashboard.css`, the design-system directory (no new
primitive), CSP and nginx.

---

## 0. How this batch was verified, and what was not run

**The historical capture harness was not run, and cannot be.** The
instruments batches 6–14 used (`capture-batchN.mjs`, `contrast-batchN.mjs`,
`diff-batchN.mjs`, the `bNN-*.py` generators) are in no commit on any branch
and nowhere on this machine; the batch docs place them in a previous session's
scratch directory, which no longer exists. There is therefore **no** screenshot
determinism, sensitivity or diff gate of the batch 6–14 kind for this batch.

Docker was not running when this checkpoint was first written. It became
available during final validation, and a rendered inspection was run then —
production images of HEAD and of this batch, served on loopback, driven in
headless Chrome in both themes. It is not the historical harness and makes
none of its claims; what it did and found is in §8.

**The test environment was broken before any change.** `Frontend/node_modules`
lacked `wawoff2` and `ux4g-web-components` — both declared, both in the
lockfile — so `npm test` died in `pretest` (`ERR_MODULE_NOT_FOUND`) before a
single test ran, and piped through `tail` it still reported exit 0. `npm ci`
restored it; `package.json` and `package-lock.json` are unchanged. Any green
figure recorded from this checkout before that came from a different install.

| Gate                            | Result                                                                                                                                                                                                     |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tests first, on the legacy      | 97 regression tests pass; 22 of 23 spec tests fail. The 23rd passed vacuously and was tightened (§1)                                                                                                       |
| Same tests, migrated            | 120 / 120                                                                                                                                                                                                  |
| Full frontend suite             | 50 files, **1563** tests, all passing (1437 before this batch + 120 + 6 stylesheet guards added in final validation)                                                                                       |
| Test noise                      | the four new files, run alone: 0 jsdom "Not implemented" notices, 0 `act()` warnings, 0 stderr. The suite's 8 notices predate this batch (7 link navigations elsewhere, FindingsExplorer's native `alert`) |
| Lint                            | `eslint --max-warnings=0` clean                                                                                                                                                                            |
| Token contrast suite            | unchanged and passing; `--ccure-text-link` on surface is one of its asserted pairs (4.5:1). Quota fill contrast and `.db-table` link colour are pinned by stylesheet guards in the component tests (§8)    |
| Rendered inspection             | 96 page loads, pre and post, both themes: 0 exceptions, 0 CSP issues, 0 off-origin requests, 0 writes; three defects this batch caused, found and fixed (§8)                                               |
| Build                           | `vite build` on the final tree (after the CSS prune): succeeds, with Vite's chunk-size warning. Not compared against a pre-batch build; this batch adds no dependency                                      |
| Final gate                      | after the final-validation fixes: 50 files, 1563 tests passing; ESLint clean; production build succeeds                                                                                                    |
| Inline styles (four components) | 18 `style={{…}}` blocks, a shared style object and two hover handlers writing `style` → **1** (a meter's measured width)                                                                                   |
| Colour literals                 | 14 (9 hex + 4 rgba in ScanQuotaBar, 1 hex in CVELink) → **0** in code                                                                                                                                      |

---

## 1. Files changed

| File                                                   | Change                                                                      | LOC         | inline / colour literals |
| ------------------------------------------------------ | --------------------------------------------------------------------------- | ----------- | ------------------------ |
| `src/components/layout/ScanStepper.jsx`                | ordered list, `aria-current`, state in words; pipeline logic unchanged      | 142 → 139   | 5 → 0 / 0 → 0            |
| `src/components/scan/ScanQuotaBar.jsx`                 | named meters, band words, CcureBadge/CcureAlert; poll unchanged             | 228 → 185   | 5 → 1¹ / 13 → 0          |
| `src/components/scan/ExportPanel.jsx`                  | render rewritten on CcureCard/Button/Alert; every builder unchanged (§3)    | 625 → 616   | 7 → 0 / 0 → 0            |
| `src/components/common/CVELink.jsx`                    | no own style; `:where` base class; new-tab description                      | 47 → 78     | 1 → 0 / 1 → 0²           |
| `src/styles/scan-stepper.css`                          | **new**, tokens only                                                        | 184         | 0                        |
| `src/styles/scan-quota.css`                            | **new**, tokens only (warning fill and 680px width corrected, §8)           | 124         | 0                        |
| `src/styles/export-panel.css`                          | **new**, layout only                                                        | 52          | 0                        |
| `src/styles/cve-link.css`                              | **new**, zero-specificity, plus one scoped `.db-table` rule (§8)            | 38          | 0³                       |
| `src/styles/scan.css`                                  | census-backed prune, §5                                                     | 3405 → 3264 |                          |
| `src/styles/animations.css`                            | census-backed prune, §5                                                     | 869 → 844   |                          |
| `src/styles/NewScan.css`                               | census-backed prune, §5                                                     | 3052 → 2873 |                          |
| `src/__tests__/components/layout/ScanStepper.test.jsx` | **new**, 22 tests (17 regression + 5 spec)                                  |             |                          |
| `src/__tests__/components/scan/ScanQuotaBar.test.jsx`  | **new**, 30 tests (20 + 6 + 4 stylesheet guards: fill contrast, host width) |             |                          |
| `src/__tests__/components/scan/ExportPanel.test.jsx`   | **new**, 38 tests (29 + 9)                                                  |             |                          |
| `src/__tests__/components/common/CVELink.test.jsx`     | **new**, 36 tests (31 + 3 + 2 stylesheet guards: `.db-table` colour)        |             |                          |
| `src/__tests__/pages/AssetDetail.test.jsx`             | CVELink's inline-style allowance removed — the debt it excused is gone      |             |                          |

¹ `width` on the meter fill, the one per-instance value. ² The remaining
`#3b82f6` in the file is inside the comment recording why it was removed.
³ Likewise: the one `#3b82f6` in `cve-link.css` is in a comment.

The tightened spec test: "marks no step current once the scan is complete"
passed on the legacy stepper because that stepper never set `aria-current` on
anything. It now asserts the list exists first.

---

## 2. Accessibility

| Component    | Pre                                                                                                                                                            | Post                                                                                                                                                                                                                                |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ScanStepper  | bare `div`s; ✓, !, the step number and › read aloud; the whole step, text included, pulsed opacity indefinitely                                                | `<ol aria-label="Scan pipeline">`, `aria-current="step"` on the active step only; glyphs `aria-hidden`; pulse on the marker only, off under `prefers-reduced-motion`                                                                |
| ScanQuotaBar | two **unnamed** `progressbar`s valued in percent; nearing the limit shown by count colour alone (amber ≈2.1:1 on white)                                        | two **named `meter`s** valued in scans with `aria-valuetext` ("3 of 10 scans used"); "Near limit" (≥80%) and "Limit reached" (≥100%) in words; neutral count text                                                                   |
| ExportPanel  | heading a styled `<p>`; names like `{ }JSONFull data` and `📄PDFReport`; errors in an unannounced `div`; copy confirmed visually only; disabled with no reason | `h3` naming a region; names "JSON Full data" … "Technical PDF Detailed report"; errors `role="alert"`; copy confirmed in a polite status region; a note says why exports are disabled; `aria-busy` on the export actually requested |
| CVELink      | own `color: var(--accent)` = `#0ea5e9`, ≈2.8:1 on white, overriding every page class; no focus style                                                           | the host page's class or `--ccure-text-link`; token focus ring; "Opens the NVD record in a new tab" as the accessible **description** — the name is unchanged                                                                       |

Why the new-tab hint is a description and not a name: AssetDetail's finding
drawer is labelled by an `h2` containing only this link, so a hint in the
link's name would be read as part of the dialog title. A test pins that the
dialog's name stays exactly the identifier.

Why the quota bars are meters: a progressbar describes a task advancing
towards completion; quota use is a measurement within a known range. The
design system's own `CcureScanProgress` is documented as scan completion only,
so it was not used here either — the batch 15 recommendation that suggested it
was wrong on that point.

---

## 3. Security validation

- **Export contents are pinned byte for byte, before and after.** Every CSV
  branch as exact text (basic discovery, inferred discovery, asset discovery,
  a single-phase audit, the full audit with all three phase summaries), the
  JSON payload as a structure, the clipboard summary line by line, filenames,
  the PDF request (`GET /reports/download/{id}`, `fmt` JSON or XML,
  `responseType: "blob"`), content-disposition parsing, and error-body parsing
  from a Blob. The builders were not touched; the tests prove it rather than
  the diff.
- **RBAC unchanged.** `can(user, "reports", "read")` still gates all five
  exports; a role without it and a null user get every control disabled;
  clicking a disabled export issues no request, creates no object URL and
  writes nothing to the clipboard; `reports:manage` and superadmin are
  enabled. The server enforces `/reports/download`; nothing client-side was
  added or relied upon.
- **A data leak removed.** The copy handler ran
  `console.log("copySummary debug:", { …, results: results.slice(0, 1) })` on
  every click, writing the first host's address, MAC and hostname to the
  browser console. Gone, and a test asserts no `console.log` / `info` /
  `debug` call.
- **CVE link boundary.** Only an identifier matching `^CVE-\d{4}-\d{4,}$` after
  trimming becomes a URL, and only to `nvd.nist.gov`. Markup, `javascript:`, a
  CVE embedded in other text, a path suffix and a query string all render as
  inert text with no `href` (tests). `rel="noopener noreferrer"` and
  `target="_blank"` asserted; click propagation stopped so a clickable row
  does not also fire.
- **The quota poll has tests for the first time.** NewScan's own test mocks
  the component out. Now asserted: a read on mount and every 30 s; no extra
  request when the page re-renders with a new callback (the defect the ref
  exists to prevent); the current callback receives the result; polling stops
  on unmount; a later failure hides the widget.
- No new external request, no runtime or CDN load. CSP verified at runtime in
  the rendered inspection (§8): zero CSP issues, headers identical to the
  pre-batch build.

---

## 4. Intentional behaviour changes

1. **PDF export labels say what they produce.** "PDF · Report" is now
   "Executive PDF · Summary report"; "PDF/XML · XML report" is now "Technical
   PDF · Detailed report". Both have always downloaded a PDF — `XML` is the
   historical name of the technical format. The requests are unchanged.
2. Only the requested PDF export shows a busy spinner; both are still disabled
   while either is in flight.
3. A clipboard failure is reported ("Could not copy the summary to the
   clipboard."). A refused write used to be an unhandled rejection and a
   missing Clipboard API a TypeError — either way the button did nothing and
   said nothing.
4. A role without `reports:read` is told why the exports are disabled.
5. The debug `console.log` in the copy handler is removed (§3).
6. **Quota widget:** meters instead of progressbars; "Near limit" / "Limit
   reached" badges; plan badges use variants (Community and Free neutral, Pro
   primary, Enterprise info) instead of hex violet and amber; the count is
   neutral text rather than band-coloured; **no meter is drawn when a limit is
   missing or zero** (the legacy bar drew 0%, a measurement nobody took); the
   3 px minimum fill at zero use, the two pill icons and the fade-in are gone.
   The count text is unchanged, including "1 / active" for a missing limit.
   The 80–99% fill is `--ccure-warning-text`, not `--ccure-warning-solid`,
   and the widget keeps the legacy 680px width so it lines up with the
   NewScan card beneath it — both corrected in final validation (§8).
7. **Stepper:** captions carry the state colour (the legacy coloured the whole
   step); the scan number is a CcureBadge; the running pulse is on the marker.
8. **CVELink renders no style of its own.** On each host:
   - AssetDetail (findings column, drawer title) and VulnerabilityBrowser
     (drawer) now take `--ccure-text-link`, which is what those pages'
     stylesheets always specified and never got.
   - Where the legacy `cve-id` class is the link's own class — the hosts that
     pass no `className` — `scan.css`'s bold weight now applies; the legacy
     inline `font-weight: inherit` had been overriding it.
   - Inside `.db-table` (SecurityDashboard; VulnerabilityBrowser's findings
     table) the link keeps `--ccure-text-link` through a scoped
     `.db-table a.cve-link` rule. Without it, `dashboard.css`'s `--db-accent`
     (`#3b82f6`) took over and rendered at 3.98:1 in the dark theme, down
     from 5.28:1 — a regression this batch caused, found in final validation
     (§8). `dashboard.css` itself is untouched.
   - A consumer's inline `style` still wins, so CredentialedResults' severity
     colours are unchanged.
   - Hover underline and a focus ring are new.

---

## 5. Retirement

Whole-tree census of `src/` (tests and build output excluded): zero JSX/JS
consumers of any `stepper*` or `sqb-*` class. The one textual hit is
`CcureBadge.jsx`'s doc comment naming `sqb-pill` as a legacy example.

| Stylesheet       | Removed                                                                                                                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan.css`       | 17 `.stepper*` rules and 2 `@keyframes stepperPulse` — two blocks; the second, near the file's end, restated four rules of the first and redefined the same keyframes                           |
| `animations.css` | section 5, "stepper enhancements": 4 rules (header kept with a pointer to `scan-stepper.css`)                                                                                                   |
| `NewScan.css`    | 20 `.sqb-*` rules and `@keyframes sqbFadeIn`, 179 lines, by `b15_prune_sqb.py`, which asserts every rule in the span selects only `sqb-*` classes and scans `src/` for consumers before writing |

Kept: `@keyframes pulseGlowAccent` (still has a consumer in
`animations.css`); `.cve-id` in `scan.css` and `dashboard.css` (the class five
hosts still rely on); `.section-title` and `.alert--error` (other consumers).

---

## 6. Corrections to the batch 15 recommendation

- "CcureScanProgress … in place of inline styles": wrong for these four. The
  stepper has no percentage and quota use is not scan completion (§2).
- CVELink has **nine** call sites in six files, not six consumers.
- The "1437 green" baseline did not come from this checkout's install (§0).

---

## 7. Deferred, and found but not fixed

- **No pixel-diff gate exists for this batch.** The rendered inspection in §8
  covered every surface and state listed there, in both themes, against a
  HEAD build — but screenshots were compared by eye and no determinism or
  sensitivity gate was run, because the batch 6–14 instruments are gone.
  Phase3Results' Risk Report CVE links were measured rather than screenshotted
  in view: they sit inside the modal's own scroll area.
- **Client-side CSV formula injection.** ExportPanel's CSV writes hostnames,
  vendors and service product/version — NetBIOS and mDNS names and banners,
  all attacker-influenced — without escaping `=`, `+`, `-`, `@` leaders. Same
  position CLAUDE.md records for `reporting/csv_generator.py`: changing a
  deliverable's bytes is not a presentation batch's business. The byte-exact
  tests make the eventual fix a deliberate, visible diff; it belongs with the
  backend CSV.
- `getScanPipeline` throws on an unknown `pipelineMode` (for instance a stale
  sessionStorage value), which takes the stepper's page down. Unchanged.
- CredentialedResults colours its CVE links with its own inline severity
  colours (`#ff4d4d` 3.13:1 and `#f97316` 2.68:1 on its light surface). Those
  are the page's, identical before and after this batch, and go with that
  page's migration.
- `dashboard.css` still carries `.db-table .cve-id`; CVELink now outranks it
  (§4.8). Removing the stylesheet from the pages that import it is
  stylesheet/dependency cleanup, not part of this batch.
- GHSA and OSV identifiers are not linked. Out of scope.

Next, per the audit's priority: **stylesheet/dependency cleanup** of
`dashboard.css`. AssetRegistry, VulnerabilityBrowser and AuditTimeline are
already migrated (batches 10 and 11); what remains is their import of that
shared legacy stylesheet, which it also serves to the unmigrated
SecurityDashboard and ComplianceWorkspace. Removing that dependency is what
closes the `.db-table` link contrast above. Then the P2 pages, starting with
ScanHistory.

---

## 8. Final validation: rendered inspection and remediation

### What was run

- **Production images of HEAD (pre) and of this batch (post)**, built with the
  real `Frontend/Dockerfile` (HEAD from `git archive`, so no untracked file
  reached it), served on `127.0.0.1` with `api` resolving to the container's
  own loopback — no route to the live API existed.
- **Headless Chrome over the DevTools protocol**: 24 states × 2 themes × 2
  builds = **96 page loads**, at 1440×900 plus two states at 390×844. `/api`
  was answered from fixed stubs; every write except the session-refresh stub
  was refused; every off-origin request was blocked. Recorded per load:
  screenshots, computed layout metrics, computed-colour contrast against the
  effective background, console errors, exceptions, CSP issues, and every
  request.
- **It is not the batch 6–14 harness** and makes none of its claims — no
  determinism, sensitivity or diff gate. Screenshots were reviewed by eye.
  Scripts and artefacts stayed in the session scratch directory.

States: Phase1Results export card (permitted, unpermitted, busy, error);
Phase2Results export card; Phase3Results stepper (running, failed, complete,
running at 390px) and the Risk Report's CVE links; NewScan quota (within, near
limit, blocked, unlimited, hidden, near limit at 390px); CredentialedResults
CVE list; ScanHistory detail-modal CVE links; SecurityDashboard top-CVE table;
AssetDetail findings, CVE-link keyboard focus and drawer title;
VulnerabilityBrowser CVE view, keyboard focus and drawer.

### Runtime results, identical for both builds

96/96 ready in the requested theme · 0 exceptions · 0 console errors ·
**0 CSP issues** · **0 off-origin requests** · 434 API requests per build ·
0 writes other than the 48 session-refresh stubs · 0 horizontal overflow at
1440px or 390px. Document and route response headers (CSP included) were
identical to the running pre-batch container on six routes; the CSS and JS
asset headers were identical apart from per-file and per-request values
(`ETag`, `Last-Modified`, `Content-Length`, `Date`, `Expires`).

### Three defects found — each caused by this batch, each fixed

| Defect                                                                                             | Rendered, before fix                               | Fix                                                      | After fix                 | Guard (failed first, passes now)                                |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------- | ------------------------- | --------------------------------------------------------------- |
| Quota 80–99% fill below the 3:1 non-text floor (WCAG 1.4.11)                                       | `#fa8c16` on `#f5f5f5` = 2.18:1 (light)            | fill uses `--ccure-warning-text`                         | 4.98:1 light, 9.98:1 dark | `ScanQuotaBar.test.jsx` reads every fill from the stylesheet    |
| Quota widget narrower than the NewScan card beneath it — `42.5rem` at the 15px root in `theme.css` | 637.5px above a 680px card, visibly misaligned     | `max-width: 680px`                                       | 680px, aligned            | `ScanQuotaBar.test.jsx` compares against `.ns-card`             |
| CVE links in `.db-table` fell below AA in the dark theme once the inline colour was gone           | `#3b82f6` on `#1e293b` = 3.98:1 (pre-batch 5.28:1) | `.db-table a.cve-link { color: var(--ccure-text-link) }` | 5.61:1 dark, 8.69:1 light | `CVELink.test.jsx` checks the rule and the legacy rule it beats |

`dashboard.css` was not touched.

### Component checks (post, both themes)

- **ScanStepper** — done / running / failed / pending read in words; markers
  and separators hidden from assistive technology; lowest text pair 5.07:1
  (active marker, dark), against 2.09–3.89:1 in the pre-batch stepper.
- **ScanQuotaBar** — every band's fill ≥ 3:1 on its track; "Near limit" and
  "Limit reached" badges ≥ 5.09:1; no meter for an unlimited plan; nothing
  rendered when the quota call fails.
- **ExportPanel** — the card, heading, button labels and descriptions all
  ≥ 10.37:1; the error alert 8.94:1 light / 7.64:1 dark; the busy control
  carries `aria-busy="true"` (the pre-batch control had none). The only
  sub-floor readings are **disabled** export controls (1.69:1 light,
  1.99:1 dark), which WCAG 1.4.3 exempts; the note explaining why they are
  disabled reads 10.37:1.
- **CVELink** — `--ccure-text-link` at 7.59–8.69:1 on every host except
  CredentialedResults, which colours its links inline (§7, unchanged by this
  batch). Keyboard focus draws a 2px ring in the link colour in both themes.

### Differences from the legacy UI, kept

Not changed, because none is a migration regression or breaches a CCure or
UX4G requirement; recorded so a reviewer can disagree:

- Stepper bar 45px against 48px, side padding 22.5px against 32px, step label
  11.25px against 12.3px — design-system spacing and type tokens at the 15px
  root.
- Quota widget padding 11.25/15px against 18/22px, radius 11.25px against 14px,
  height 117px against 146px (the pill icons are gone).
- The export card is a bordered CcureCard with a 15px heading, and its buttons
  are 40px tall rather than 84px, having lost their glyph icons.
- CVE identifiers are bold wherever the legacy `cve-id` class applies; the old
  inline `font-weight: inherit` had been overriding it.

**STOP** — awaiting review before Batch 16.
