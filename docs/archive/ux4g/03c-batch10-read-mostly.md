# Checkpoint 3C — Batch 10: the read-mostly five

**Status: complete, awaiting review.**

|                 |                                                                                                                        |
| --------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Pages           | ConfigurationChecks · SecurityReports · AuditLogs · VulnerabilityBrowser · AssetRegistry                               |
| Routes          | `/configuration-checks` · `/reports` · `/admin/audit-logs` · `/vulnerabilities` · `/assets`                            |
| Size            | 5,703 LOC before → 4,641 after (5 pages)                                                                               |
| New tests       | **143**, all passing                                                                                                   |
| Full suite      | **1,153 / 1,153**, 36 files, **0** unhandled errors                                                                    |
| Lint            | `eslint src --ext .js,.jsx --max-warnings=0` → **0**                                                                   |
| Build           | production build succeeds; Docker image builds and serves                                                              |
| Harness         | 19 routes × 2 themes = 38 captures; determinism byte-identical; 4/4 injections named; 0/30 control states moved        |
| Unrelated pages | **53 states across 18 pages — all identical**                                                                          |
| Contrast        | 158 sub-AA → 64; **0 new colour pairs introduced**; every remainder is pre-existing shared CSS or visually hidden text |
| CSP             | unchanged; header byte-identical pre/post                                                                              |
| Air-gap         | 488 requests, 0 off-origin                                                                                             |
| `dashboard.css` | untouched — no batch-10-exclusive selector exists (Phase A census)                                                     |

Harness record: [`03c-batch10-harness.md`](03c-batch10-harness.md) — **six
instrument defects** were found across Phases B and C, each by a gate rather
than by inspection. Read that first; it is what licenses the numbers here.

---

## 1. What was migrated, and what was not touched

Five pages, one subject: read-mostly tables and cards. None dispatches a scan,
handles a credential, changes an authorisation model, or holds a WebSocket.
The complete mutation surface across all five is four calls, every one
pinned by test and unchanged: `DELETE /reports/{id}` (permission-gated,
confirmed), `PATCH /findings/{id}/status` (triage), `PATCH /assets/{id}`
(`{ is_managed }`), and two authenticated exports.

**Not touched, by instruction:** `dashboard.css`, `ScanSchedules`,
`useScanPolling`, the CVSS fallback, `cvss_v3_score.toFixed()`, `AppLayout`
and every shell component, `CVELink`, and every other page.

---

## 2. Metrics

| Page                 | LOC               | Inline styles | Colour literals | Tests   |
| -------------------- | ----------------- | ------------- | --------------- | ------- |
| ConfigurationChecks  | 322 → 316         | 25 → **0**    | 38 → **0**      | 28      |
| SecurityReports      | 622 → 493         | 17 → **0**    | 4 → **0**       | 27      |
| AuditLogs            | 1,234 → 1,101     | 51 → **0**    | 26 → **0**      | 27      |
| VulnerabilityBrowser | 1,507 → 1,116     | 107 → **0**   | 47 → **0**      | 29      |
| AssetRegistry        | 2,018 → 1,615     | 130 → **1**   | 53 → **0**      | 32      |
| **Total**            | **5,703 → 4,641** | **330 → 1**   | **168 → 0**     | **143** |

The one remaining inline style is AssetRegistry's risk-bar **width** — the
score itself, per-instance data rather than a design decision, kept inline for
the same reason `CcureSkeleton` keeps its dimensions inline. Its _colour_, the
part that carried meaning, is a band class.

Measured by the harness across all 38 captures rather than counted in source:

|                                 |    Pre |    Post |
| ------------------------------- | -----: | ------: |
| Inline-styled elements          |  1,024 | **8** ¹ |
| Duplicate button names          |     30 |   **0** |
| Unnamed buttons                 |      0 |       0 |
| Unlabelled form controls        | **96** |   **0** |
| Tables with a caption           |      0 |  **20** |
| Tables with every header scoped |      0 |  **26** |
| Horizontal overflows            |      0 |       0 |

¹ 4 are the risk-bar widths above; 4 are `CVELink`, a legacy shared component
with six consumers, out of scope for this batch (§13).

New page stylesheets: `configuration-checks.css` (146), `audit-logs.css`
(181), `vulnerability-browser.css` (303), `asset-registry.css` (289).
`SecurityReports.css` was converted in place (§7).

---

## 3. Contracts — verified unchanged, by test

**ConfigurationChecks** — two endpoints (`/config-audit/checks?platform=`,
`/config-audit/capabilities`), default platform `windows`, severity ordering,
and the property the page exists to hold: **no mutation, ever**. A test drives
every control on the page and asserts `post`/`patch`/`delete` stay untouched.

**SecurityReports** — the listing spans **all three scopes** (active, archived,
deleted); the download is an authenticated `arraybuffer` fetch, never a bare
link, addressed at the scan's own id; deletion is gated three ways (control not
rendered without `reports:delete`, opener refuses, confirm refuses again) and
its wording — _"cannot be undone … the scan record and its report will be
completely removed"_ — is carried into `CcureConfirmDialog` verbatim. The
`fmt` values `JSON`/`XML` are historical names for the executive and technical
PDFs and are unchanged.

**AuditLogs** — the 5-second poll is application behaviour and was left
entirely alone. Six tests pin it: fires every 5 s once the first page loads,
asks for `{skip: 0, limit: 10}` under the active filters, **never replaces the
table**, runs exactly one timer, swallows a background failure, and stops on
unmount. Export carries the active filters and never pagination. No HTTP path
here writes or deletes an audit row; the retention panel is a preview.

**VulnerabilityBrowser** — the grouped view (`/findings/grouped/by-component`)
and the CVE view (`/findings`) are not interchangeable: the per-CVE filters
(priority, KEV, free text) are **deliberately not sent** to the grouped
endpoint, and a test asserts their absence. Defaults `severity=Critical,High`,
`status=open`, `sort_by=priority`. The triage column is rendered only under
`findings:update`. The page never presents triage as proof a finding was fixed.

**AssetRegistry** — three endpoints for three views, each with its own
pagination; `sort_by=risk_score desc` by default; unset filters omitted rather
than sent blank; the one mutation sends exactly `{ is_managed: !current }` to
exactly `/assets/{id}` and only under `assets:update`; nothing on the page
deletes an asset.

---

## 4. Accessibility corrections

Measured, not asserted: **96 unlabelled controls → 0, 30 duplicate button
names → 0, 0 captions → 20, 0 scoped tables → 26**, and every page now has
an `h1` (three of the five had **no heading element at all**).

The five fixes the brief named, and what each actually was:

| Required                                           | Found                                                                                                                                                                                                                                      | Done                                                                                                                                                         |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ConfigurationChecks toast hook                     | `{ addToast, removeToast }` from a hook returning `{ push, dismiss }` — the page's **only** error surface threw, so a failed load rendered _"No configuration checks for this platform"_: a false statement about the product's capability | Renamed on the way in; the error is now also a persistent `CcureAlert` (live region); regression test `does not render the empty state when the load failed` |
| AssetRegistry tabs                                 | `<div onClick>` — no role, no tabindex, no key handler; Services and Certificates **unreachable by keyboard**                                                                                                                              | `CcureTabs` (WAI-ARIA tabs pattern), URL still the source of truth                                                                                           |
| AssetRegistry drill-down dialog                    | plain `<div>`; the harness recorded `roles: []` with a modal on screen; no Escape, no focus containment, close button a bare ✕                                                                                                             | `role="dialog"`, `aria-modal`, `aria-labelledby` to its heading, `useFocusTrap` (the design system's own hook), Escape closes, named close control           |
| AuditLogs unnamed filter                           | the page-size `<select>` beside the word "Show" — `SELECT:UNLABELLED` in the census                                                                                                                                                        | `aria-label="Events per page"`                                                                                                                               |
| Headings on VulnerabilityBrowser and AssetRegistry | `db-page-title` was a styled `<div>`; `getAllByRole("heading")` found nothing                                                                                                                                                              | real `h1`                                                                                                                                                    |

Beyond those:

- **SecurityReports' tab strip** was the same `<div onClick>` pattern → `CcureTabs`.
- **SecurityReports' delete control** was a bare 🗑️ with only a `title`, and
  three cards each offered identical "Official Report" / "Technical Data"
  names → every card control now names its scan.
- **AuditLogs' "N new events" pill** was a `<div onClick>` with inline hover
  handlers — the only route to the newest events, unreachable by keyboard and
  never announced → a button inside an always-mounted polite region.
- **AuditLogs' table** — caption + `scope="col"` ×7; the refreshing veil states
  `aria-busy`.
- **AssetRegistry's vulnerability columns** were headed "C", "H", "M" — legible
  only next to each other, which a screen reader does not provide → visible
  letter, accessible word.
- **VulnerabilityBrowser's view toggle** stated its selection by weight and
  colour → `aria-pressed`; six unlabelled filters named; both tables captioned
  and scoped; loading and error states in live regions.
- **Colour was the sole carrier of meaning in 47 places on VulnerabilityBrowser
  and 53 on AssetRegistry** — KEV, exploit, ransomware, honeypot, verified,
  CVSS band, risk band, expiry, managed state, exposure, TLS grade, port state.
  Each is now a class named for the fact, and the words beside each marker were
  never removed. One helper existed specifically so that "colour is the only
  thing carrying meaning between" five exploitation badges; that property is
  what was removed.

---

## 5. Intentional behaviour changes

Called out rather than folded into "accessibility improvements". "Byte-for-byte
behaviour preserved" is **not** claimed:

1. **Keyboard reach.** Three tab strips and two `<div onClick>` controls became
   real controls — Services/Certificates on AssetRegistry, three sections on
   SecurityReports, and AuditLogs' new-events pill are reachable without a
   mouse for the first time.
2. **Escape closes the AssetRegistry drill-down**, and focus is contained while
   it is open and restored on close. Previously only click-outside closed it.
3. **ConfigurationChecks has an error state.** It did not before.
4. **`CcureConfirmDialog` focuses Cancel on open** where the in-file dialog it
   replaced focused the destructive button — a stray Enter no longer deletes.
5. **SecurityReports uses `CcureToastProvider`**, not the legacy toaster. Not
   preference: the legacy container renders no `aria-live` at all — its
   successor's own header says so — so a failed download was shown and never
   announced.
6. **AssetRegistry's managed chip no longer changes its cursor from the
   permission.** The permission gate on the handler is what decides; a cursor
   told sighted users only.

---

## 6. Harness

The instrument used to produce every number above was validated against the
eight-step rule before a page was touched, and re-validated from the top after
each of the three Phase C corrections. Six defects in total — each of which
would have produced a clean or mislabelled result for a build that had
demonstrably changed:

| Phase | Defect                              | Consequence if unfixed                                                           |
| ----- | ----------------------------------- | -------------------------------------------------------------------------------- |
| B     | `Date.now()` rendered "3m ago"      | two captures of one container could never agree on three of five pages           |
| B     | `headerScoped` was all-or-nothing   | six-of-seven scoped headers would report clean                                   |
| B     | accessible names counted, not named | a control rename was invisible in the summary                                    |
| B     | prepare that did nothing accepted   | default state captured under a variant's name                                    |
| C     | prepare snapshot blind to portals   | correct build failed the guard                                                   |
| C     | a root's own role invisible         | portalled dialog measured as "no dialog"                                         |
| C     | `\s` inside the template literal    | every `aria-labelledby` id containing an `s` recorded as unnamed — since batch 8 |

The last is worth naming plainly: the batch-8 probe has been silently
recording empty accessible names for any `aria-labelledby` reference whose id
contains the letter `s`. It never produced a false comparison, because an
empty name compares identical on both sides — which is exactly why it was
never noticed.

---

## 7. Contrast

Both themes, 19 states, every `rgba()` composited through its real ancestor
chain, floors 4.5 / 3.0.

|                |         Sub-AA | Worst  |
| -------------- | -------------: | ------ |
| Pre-migration  | **158** of 584 | 1.14:1 |
| Post-migration |  **64** of 660 | 1.56:1 |

The 64 that remain, classified against the pre-migration run by state and
text:

- **50 were failing before, identically** — all from `dashboard.css`
  (`.db-table th` at `#94a3b8`, `.db-btn--primary` white on `#0ea5e9`,
  `.db-sev-badge--*`, `.db-tag`), the shared sheet this batch was instructed
  not to touch. The worst overall, `db-sev-badge--medium` at 1.56:1, is one of
  them.
- **10 are the same fg/bg pairs as those, sampled on a different cell** — the
  same shared rule, not new colouring.
- **4 are `.cc-sr-only` text** — the visually hidden "Critical/High/Medium"
  heading words. WCAG 1.4.3 applies to visible text; the probe measures these
  anyway. Left unexempted so a real failure cannot hide behind the exemption.
- **Genuinely new colour pairs introduced by this migration: 0.**

**One page-owned defect was found and fixed.** `SecurityReports.css` set the
header box to a hardcoded `#1e293b` slate under the shell's `.page-title`,
whose colour is `var(--text)` — near-black in light theme. The page's **h1
rendered at 1.22:1** in light theme before this batch. I had imported that
sheet untouched; it is now tokens throughout, and the four SecurityReports
states report zero sub-AA.

---

## 8. Regression

Pre-batch-10 and post-batch-10 containers, captured with every earlier
harness **unchanged**:

| Harness   | Pages                                                              |                 States |
| --------- | ------------------------------------------------------------------ | ---------------------: |
| auth      | Login, Register, ResetPassword, VerifyEmail, ForgotPassword        |                      5 |
| batch 5   | RecycleBin, DeletedUsers, OrganizationManagement, EmailDomainRules |                      8 |
| batch 6   | WebDashboard, ScanList, FindingsExplorer, AssetInventory           |                      8 |
| batch 7   | NewWebScan                                                         |                      4 |
| batch 8   | ScanDetail                                                         |                     10 |
| batch 9   | ScanCredentials, CredentialedScan                                  |                     16 |
| gated     | ArchivedScans                                                      |                      2 |
| **Total** | **18 pages**                                                       | **53 — all identical** |

Re-run after every rebuild of the post image (four times in Phase C). The
three pages completed before the HOLD were verified unchanged since:
ConfigurationChecks and SecurityReports JSX untouched; AuditLogs
byte-identical to its clean snapshot; the only edit was `SecurityReports.css`
(§7).

`RoleManagement` still has no harness route — a suite gap that predates this
batch.

---

## 9. Bundle impact

|          | Batch 9     | Batch 10    | Δ            |
| -------- | ----------- | ----------- | ------------ |
| CSS raw  | 295.78 kB   | 313.33 kB   | +17.55 kB    |
| CSS gzip | 50.29 kB    | 52.97 kB    | +2.68 kB     |
| JS raw   | 1,674.33 kB | 1,665.47 kB | **−8.86 kB** |
| JS gzip  | 421.18 kB   | 421.10 kB   | −0.08 kB     |

CSS grew by four page stylesheets (919 lines) with nothing removed from the
shared sheets — Phase A's census found no `dashboard.css` selector exclusive
to these pages, so no prune was possible. The JS shrank: 1,062 lines of page
code, most of it inline style objects, became tokens.

---

## 10. Security assessment

**No security-sensitive behaviour changed.** Stated per surface:

- **Endpoints, methods, parameters** — unchanged and pinned by 143 tests
  written against the unmigrated pages.
- **Permissions** — `reports:read`, `reports:delete`, `findings:update`,
  `assets:update`, superadmin on retention preview: same checks, same places.
  Both SecurityReports delete checks (opener and confirm) are still made; the
  suite records that the second is defence across a _re-render_, not against a
  mid-dialog revocation, because both read the same rendered value.
- **Destructive action** — the report-delete wording is verbatim; the dialog
  is a portal now and the harness proves it opens, names the scan, and is
  never confirmed by the instrument.
- **Polling** — AuditLogs' interval, request shape, cleanup and silent-failure
  behaviour untouched and tested.
- **Writes from the instrument** — 0 across 488 requests.
- **CSP** — unchanged; **air-gap** — 0 off-origin requests; no new dependency.
- **Data in the DOM** — nothing sensitive added; the dialog names and captions
  contain scan numbers and counts already on screen.

---

## 11. Deferred — recorded, not fixed

1. **`cvss_v3_score.toFixed(1)` is unguarded** in VulnerabilityBrowser's CVE
   table. NVD publishes v2-only CVEs; one of those crashes the page. The unit
   fixture supplies a score so the suite measures the page, not the defect.
2. **`ScanSchedules` carries the same toast-hook defect** fixed here and in
   batch 9. Untouched; B12.
3. **`CVELink`** — legacy shared component, 6 consumers, inline styles and a
   `#3b82f6` literal. Out of scope; a candidate to become a security pattern.
4. **`dashboard.css`** — 150 selectors, 44 with zero consumers, and the source
   of 60 of the 64 remaining sub-AA readings (`.db-table th`,
   `.db-btn--primary`, severity badges). Untouched by instruction. It will keep
   failing contrast on every page that uses it until it is migrated as a
   unit — AssetDetail, SecurityDashboard, ComplianceWorkspace, AMTIntegration.
5. **Sortable `<th onClick>`** on AssetRegistry (13 headers) — click-only
   sort, not keyboard-operable. Scoped, but not converted to header buttons.
6. **`useScanPolling`, NewWebScan items, ScanDetail `window.alert`,
   `Skeleton.jsx`, `web-scanning.css`, `.page-subtitle`** — all as previously
   recorded, all untouched.
7. **AuditLogs `SELECT:UNLABELLED`** — resolved. **CredentialedScan
   Windows/OpenSSH copy** — still open.

---

## 12. Engineering gate

| Check                                        | Result                                      |
| -------------------------------------------- | ------------------------------------------- |
| Five page suites                             | 143 / 143                                   |
| Full suite                                   | 1,153 / 1,153, 0 unhandled errors           |
| Lint `--max-warnings=0`                      | 0                                           |
| Production build                             | succeeds                                    |
| Docker build + serve                         | HTTP 200                                    |
| Harness determinism                          | byte-identical ×2, final build              |
| Harness sensitivity                          | 4/4 named, migrated build                   |
| Unchanged control                            | 0/30                                        |
| Portal-aware                                 | proven live (§6)                            |
| ARIA-state                                   | proven live                                 |
| No writes / downloads / exports / off-origin | 0 / 0 / 0 / 0                               |
| CSP                                          | unchanged, byte-identical header            |
| Air-gap                                      | 0 external origins                          |
| Contrast                                     | 0 new colour pairs; page-owned 1.22:1 fixed |
| Unrelated pages                              | 53 states, 0 differences                    |
| Three earlier pages                          | unchanged except the documented CSS fix     |

No STOP condition was triggered.

---

## 13. Recommendation

```
GO — Batch 10 complete
```

Three things for an explicit decision rather than assumed:

1. **`dashboard.css` is now the dominant source of contrast failures on every
   page that still uses it**, and it cannot be migrated page by page — Phase A
   proved no page owns any of its selectors. It needs its own slot, likely
   alongside AppLayout.
2. **`CVELink`** is the last legacy component rendering inline styles into
   migrated pages. Six consumers; small; a natural `CcureCveLink` pattern.
3. **The `\s` probe defect has been present since batch 8.** Every earlier
   report's "accessible name" figures for `aria-labelledby` ids containing an
   `s` under-counted. No comparison was wrong; the _absolute_ naming counts
   in batches 8 and 9 may be low.

**STOP** — awaiting review before Batch 11.
