# Checkpoint 3C — Batch 11: planning and baseline (no migration)

**Status: STOP — awaiting approval.** Nothing under `src/pages/`, `src/components/`,
`src/styles/` or `src/design-system/` was modified in this phase. Two test files
were added (`src/__tests__/pages/Dashboard.test.jsx`,
`src/__tests__/pages/AssetDetail.test.jsx`). The harness is designed here and
not built.

Inventory derived from the working tree on 2026-09-11 by two read-only scripts
(`b11-inventory.py`, `b11-css-map.py` — scratchpad) plus a full read of
`Dashboard.jsx` and `AssetDetail.jsx`. Every number below is measured, not
carried forward from the Stage 2 inventory.

---

## 1. Fresh inventory of the unmigrated surface

### 1.1 Status of every page

| Page                                                                                 | Route          | Status                              |
| ------------------------------------------------------------------------------------ | -------------- | ----------------------------------- |
| Login, Register, ForgotPassword, ResetPassword, VerifyEmail                          | auth           | migrated (auth group)               |
| RoleManagement, DeletedUsers, OrganizationManagement, EmailDomainRules               | admin          | migrated (batch 5 / RoleManagement) |
| ArchivedScans, RecycleBin                                                            |                | migrated                            |
| Web-scanning module (6 pages)                                                        | `/web-scans/*` | migrated (batches 6–8)              |
| ScanCredentials, CredentialedScan                                                    |                | migrated (batch 9)                  |
| ConfigurationChecks, SecurityReports, AuditLogs, VulnerabilityBrowser, AssetRegistry |                | migrated (batch 10)                 |
| **14 pages below + shell**                                                           |                | **unmigrated**                      |

The 14 unmigrated pages total **28,777 LOC**; the shell and shared legacy
components add **6,430**. Migrated pages so far: 21 pages, ~10,400 LOC.

### 1.2 Mechanical metrics (measured)

`inline` = `style={` attributes; `colour` = hex/rgb(a)/hsl literals; `th s/c` =
column headers with `scope=` / with `onClick`; `db-` = distinct `dashboard.css`
classes consumed; `legacy` = legacy shared components rendered; `test` = an
existing unit suite.

| Page                                          |   LOC | inline | colour (uniq) | tables | th s/c   | caption |     db- | legacy | aria / role | test    |
| --------------------------------------------- | ----: | -----: | ------------: | -----: | -------- | ------: | ------: | -----: | ----------- | ------- |
| Dashboard `/scan`                             |   538 |      1 |       26 (22) |      0 | –        |       0 |       0 |      1 | 0 / 0       | **new** |
| AssetDetail `/assets/:id`                     | 2,418 |    185 |       73 (39) |      2 | 12 → 0/0 |       0 |      37 |      2 | 0 / 0       | **new** |
| ScanSchedules                                 |   777 |     67 |       33 (14) |      2 | 12 → 0/0 |       0 |       0 |      5 | 0 / 0       | –       |
| UserManagement (+UserForm 255, UserTable 231) | 1,030 |     19 |        12 (9) |     1¹ | 7 → 0/0  |       0 |       0 |      6 | 0 / 0       | –       |
| AMTIntegration                                | 1,317 |    107 |       34 (16) |      1 | 15 → 0/0 |       0 |      15 |      0 | 0 / 0       | –       |
| ScanHistory                                   | 1,719 |     43 |       24 (11) |      1 | 2 → 0/0  |       0 |       0 |      4 | 5 / 1       | –       |
| Phase1Results                                 | 1,595 |     72 |       35 (27) |      1 | 8 → 0/0  |       0 |       0 |      2 | 0 / 0       | –       |
| Phase2Results                                 | 1,505 |     79 |       36 (20) |      4 | 23 → 0/0 |       0 |       0 |      2 | 0 / 0       | –       |
| Phase3Results                                 | 2,532 |    150 |       87 (46) |      4 | 22 → 0/0 |       0 |       0 |      3 | 0 / 0       | –       |
| CredentialedResults                           | 2,369 |    149 |       57 (25) |      1 | 1 → 0/0  |       0 |       0 |      2 | 0 / 0       | –       |
| NetworkMap                                    | 1,906 |     17 |      215 (56) |     0² | –        |       0 |       0 |      1 | 12 / 7      | yes     |
| SecurityDashboard                             | 2,193 |    129 |       88 (27) |      2 | 14 → 0/0 |       0 | **104** |      3 | 0 / 0       | –       |
| NewScan                                       | 2,905 |     46 |       32 (22) |      1 | 4 → 0/0  |       0 |       0 |      1 | 0 / 0       | yes     |
| ComplianceWorkspace                           | 6,094 |    308 |       87 (38) |      8 | 44 → 0/0 |       0 |      35 |      3 | 0 / 0       | –       |

¹ in `UserTable.jsx`. ² NetworkMap uses `role="table"` on divs (7 roles).
No page carries a `<caption>` or a scoped header. No page uses a `ux4g-*`
class. No page uses `prefers-color-scheme`.

### 1.3 Per-page inventory

Each entry: imports · API (method path) · mutations · gates · destructive ·
timers · forms · credentials · dialogs · tables/tabs · visualisation ·
CSS ownership · primitive opportunities · accessibility defects · theme ·
recorded debt · risk.

**Dashboard `/scan`** (538) — imports AppLayout, legacy `Modal`, `useScan`,
`getScanPipeline`. API: **none**. Mutations: none over HTTP; choosing a
pipeline card calls `resetScan()` then `setPipelineMode(mode)` on ScanContext
(both persist to `sessionStorage` `cc_*`) and navigates to `/scan/new`;
direct-route cards navigate only; 7 of 13 cards are disabled placeholders.
Gates: none. Destructive: none (reset discards in-progress scan state
client-side — existing behaviour). Timers: none. Forms: one search input.
Credentials: none. Dialog: legacy `Modal` ("Start New Scan"), opened by the
**shell's** New Scan button through the `onNewScan` prop — the only page that
answers that prop with a modal instead of `navigate("/scan")`. Tables/tabs:
none. Visualisation: 14 inline SVG icon components, not `aria-hidden`.
CSS: `scan.css` (16 classes; the `scan-card*`, `badge-*`, `scan-grid`,
`modal-panel-grid` family has **no other consumer**; `search-*` is shared with
UserManagement/NetworkMap/VulnerabilityBrowser; `empty-state*` is shared with
5 files), `layout.css`, `animations.css`. Primitives: `CcureModal`,
`CcureInput` (search), `CcureEmptyState`, `CcureBadge` (Beta/Soon).
Accessibility: search input has a placeholder and no label; the badge is
rendered before the title so a disabled card's accessible name is
"Soon Malware Scan …" and the beta card's is "Beta Soon Agent …"; the only
explanation of "disabled" is a `title` tooltip; the modal has no
`role`/`aria-modal`/labelling/focus trap (Escape and overlay-click work); the
empty-search state is not announced. Theme: 22 template colours are fixed
literals (pastel tile + stroke) in both themes. Debt: none recorded.
**Risk: LOW.**

**AssetDetail `/assets/:id`** (2,418) — imports AppLayout, `CVELink`,
`AuditTimeline` (401 LOC, **this page is its only consumer**;
SecurityDashboard's `AuditTimeline` is a different local component),
`dashboard.css`, `api/assets`, `api/findings`, `canPermission`.
API on mount, in parallel: `GET /assets/{id}`, `GET /assets/{id}/services`,
`GET /assets/{id}/findings`, `GET /assets/{id}/changelog`; on demand
`GET /findings/{id}`. Mutations (6): `PATCH /assets/{id} {is_managed}`,
`PATCH /assets/{id} {owner}`, `POST /assets/{id}/tags {tag}` (+ re-read),
`DELETE /assets/{id}/tags/{encodeURIComponent(tag)}`,
`POST /assets/{id}/notes {content}` (+ re-read),
`PATCH /findings/{id}/status {status, accepted_risk_reason, remediation_notes}`
(+ re-read). Gates: one — `assets:update` hides/disables every write control
**including the finding-status actions** (the backend gates those on
`findings:update` / `findings:accept_risk`; see §6). Destructive: tag removal
(no confirmation), risk acceptance and mark-fixed (two-step: choose → Confirm;
no dialog). Timers: none — no polling, no WebSocket, no download. Forms:
2 `<form>` (tag, note) + 2 non-form input groups (owner inline edit; drawer
reason/notes). Credentials: none — `custom_attributes.credentialed_system_info`
is OS metadata (domain, build, kernel, hardware, CPU, uptime). Dialog: a
hand-rolled fixed-position drawer (no role, no `aria-modal`, no focus trap, no
Escape; "✕" close has no name). Tables: 2 (findings 6 cols, services 3–6 cols
computed from data), no captions, no scopes, both with `<tr onClick>`; the
services row expands in place with no `aria-expanded`. Tabs: 4 `db-tab`
buttons, no `tablist`/`tab`/`aria-selected`, counts in the labels.
Visualisation: one SVG risk ring (stroke colour and dash offset from
`risk_score`). CSS: `dashboard.css` (30 classes, shared with 6 files),
`scan.css` (2); 185 inline styles carry the layout; 32 of the 39 unique colours
are the _light_ Tailwind shades (`#4ade80`, `#f87171`, `#fbbf24`, `#60a5fa`,
`#c084fc`, `#2dd4bf` …) plus 4 `rgba(255,255,255,…)` overlays — the page was
tuned for the dark theme and those shades sit at 1.6–2.5:1 on the light
surface. Primitives: `CcureTabs`, `CcureCard`, `CcureTable` (caption/scope),
`CcureBadge` + `CcureSeverityBadge`, `CcureButton`, `CcureInput`/`CcureField`,
`CcureSkeleton`, `CcureEmptyState`, `CcureAlert`, `CcureModal` (drawer) or the
`vb-drawer` pattern from batch 10, `useFocusTrap`. Accessibility: no h1 (the
address is a `div`; error state has an h3); 0 `aria-*`, 0 `role`, 0
`<label>`; placeholders are the only names on 5 inputs; remove-tag is a
`<span onClick>`; the managed toggle is a `<button className="db-tag">` with
no `aria-pressed`; drawer and rows as above; no live region — and the
status-save **success** message is set in state but rendered only inside the
panel that the same handler closes, so it is never visible (§6). Theme: as
above. Debt: `CVELink` inline styles render inside this page (recorded).
**Risk: MEDIUM** — six simple, individually testable writes; no timers; one
permission; one security-sensitive write behind an explicit Confirm.

**ScanSchedules** (777) — legacy Button/ConfirmDialog/EmptyState/Loader/Toast.
API: 4 GET, `POST /scan-schedules`, `PATCH /scan-schedules/{id}`,
`DELETE /scan-schedules/{id}`, `POST …/enable`, **`POST …/run-now`**
(dispatches a real scan). Gates: none in the page. Destructive: delete
(ConfirmDialog), run-now (no confirm). Timers: `Date.now`. Forms: the schedule
form (14 inputs). Credentials: a stored-credential _reference_ by id — the
page deliberately never asks for a password. Dialogs: ConfirmDialog. Tables:
2 (12 th). CSS: **none** — 67 inline styles are the entire layout. Debt: the
`{ toasts, addToast, removeToast } = useToasts()` destructure (batch 9's
defect) — every success/failure toast throws. **Risk: MEDIUM-HIGH** (scan
dispatch + CRUD + the toast defect must be fixed to test feedback).

**UserManagement** (1,030 + 517 in UserForm/UserTable/RoleSelector) — API: 4
GET, `POST /admin/users/`, `PUT /admin/users/{id}`, `PATCH …/role`,
`…/status`, `…/organization`, `POST …/approve`, `…/reset-password`,
`…/reset-mfa`, `DELETE /admin/users/{id}`. Gates: `isSuperAdmin`,
`isOrgAdmin`, `can`. Destructive: delete, reset password, reset MFA, status
change — one `window.confirm` plus a ConfirmDialog. Timers: search debounce.
Forms: UserForm (password field), reset-password form. Credentials: a new
password is typed and posted. Dialogs: 2 legacy Modals + ConfirmDialog. CSS:
`scan.css` (19 classes — the admin page borrows scan styling), `admin.css`,
`forms.css`. **Risk: HIGH** (credential operations, admin).

**AMTIntegration** (1,317) — API: `POST /assets/import-amt` (multipart;
**replaces the organisation's AMT inventory** — validated-before-delete on the
backend), `GET /assets/coverage-stats`, `GET /assets/reconciliation/drilldown`
(+ CSV export via blob URL). Destructive: the import. Timers: one
`setTimeout`. Forms: file upload with a size guard. Dialog: none. Tables: 1
(15 th). Visualisation: one SVG ring. CSS: `dashboard.css` (15), 107 inline;
6 `<div onClick>`. **Risk: HIGH** (destructive upload + download).

**ScanHistory** (1,719; two modes `/monitor`, `/history`) — API: `GET /scans`,
`GET /scans/{id}`, `POST /scans/{id}/stop`, `POST /scans/{id}/archive`,
`DELETE /scans/{id}`, **`POST /scan/host-discovery`** (re-run dispatch).
Gates: `can`/`denyMessage`. Destructive: delete, archive, stop, re-run — all
through an in-file ConfirmDialog (it has `role="dialog"` +
`aria-labelledby`) and an in-file toast implementation. Timers: 5
`setTimeout` (toast lifecycle and a monitor refresh wait). Reads
`usePreferences`. CSS: `scan.css` (93 classes — the largest consumer), 43
inline; `CVELink`, `RiskBadge`. **Risk: HIGH** (dispatch + delete).

**Phase1Results** (1,595) — API: `GET /scans/{id}` (two call sites),
**`POST /scan/asset-discovery`** (chains phase 2). ScanContext pipeline state
(sessionStorage). Shared `ScanStepper` (143) + `ExportPanel` (626). 7 inputs
(exclusion tokens). 72 inline, 35 colours, 1 table. **Risk: MEDIUM-HIGH.**

**Phase2Results** (1,505) — API: GET only (`/scans/{id}` ×3 shapes). Pipeline
state; ScanStepper/ExportPanel; 4 tables (23 th); 79 inline; 36 colours; one
`<div onClick>`. **Risk: MEDIUM** (read-only, but coupled to the pipeline
context and to `scan.css` (39 classes)).

**Phase3Results** (2,532) — API: `GET /scans/{id}`, `POST /auth/ticket` +
WebSocket progress, **`POST /scan/asset-discovery`**,
**`POST /scan/vulnerability-audit`**, `POST /scans/{id}/stop`. Legacy Modal.
`Date.now` ×4. 4 tables (22 th); 150 inline; 87 colours (46 unique).
**Risk: HIGH.**

**CredentialedResults** (2,369) — hydrates from router state or
`GET /scans/{id}`; `POST /auth/ticket` + WebSocket; no writes. 149 inline; 57
colours; no h1 (3 h2, 9 h4); `RiskBadge`, `CVELink`. **Risk: MEDIUM-HIGH**
(socket lifecycle in the harness).

**NetworkMap** (1,906) — `vis-network` (bundled dependency); `GET` topology;
`window.confirm`; 2 legacy Modals; 215 colour literals (node palette + SVG
icon definitions), 17 inline; `NetworkMap.css` is page-owned (76 classes);
already carries 12 `aria-*`, 7 roles, an h1 and a unit suite.
**Visualisation page — excluded by instruction.**

**SecurityDashboard** (2,193) — 11 `GET /dashboard/*`; 60-second
`setInterval` refresh + WebSocket live strip; RBAC widgets via
`canPermission` ×5; **104 `dashboard.css` classes** (dominant consumer: the
sheet cannot be migrated until this page is); conic-gradient charts; local
`Skeleton` and `AuditTimeline`; `c.cvss_v3_score.toFixed(1)` unguarded (§6);
tabs without semantics; `<tr onClick>` ×2, `<div onClick>` ×4; no h1.
**Visualisation-heavy — excluded; it is the anchor for the `dashboard.css`
slot.**

**NewScan** (2,905) — **`POST /scan/host-discovery`**, `POST /auth/ticket` +
WebSocket, `POST /scans/{id}/stop`; `setInterval` ×2 (elapsed clock, host
polling); FileReader target import; blob download; two `type="password"`
fields (SNMPv3 auth/privacy passphrases — credentials typed into the form and
sent with the dispatch); `ScanQuotaBar`; `NewScan.css` page-owned (144
classes; 9 classes unowned); existing unit suite. **Risk: HIGH.**

**ComplianceWorkspace** (6,094) — 29 endpoints (13 GET, 13 POST, 2 DELETE,
1 PUT) including compliance **credentials** (`POST` with a password,
`DELETE`), evidence upload (multipart) and delete, report downloads;
`window.confirm` ×3; `setInterval` ×2 (4 s poll); legacy Modal + Toast; 308
inline; 87 colours; 8 tables (44 th); 56 inputs across 5 forms; 26 `activeTab`
references; `dashboard.css` (23) + `compliance.css` (35) + `scan.css`;
`org_admin`/`superadmin` gates. **Risk: VERY HIGH — needs decomposition into
views before any migration batch can be sized.**

**Shell and shared components** —
`AppLayout` (1,166): `GET /notifications/summary` on a 30 s `setInterval`,
`GET /dashboard/summary`, `GET /scan/quota`, `GET /admin/organizations/`
(superadmin org switcher → `localStorage.activeOrgId`); `localStorage`
sidebar state, `sessionStorage` sidebar scroll; global search input; nav gated
by `canAny`/`canPermission`/`isSuperAdmin`/`superadminOnly`; reads
`usePreferences` (theme); `layout.css` (52 classes); 24 inline; 2 `<div
onClick>`; `.page-subtitle` light-theme contrast lives here.
`ProfileModal` (969): MFA enable/confirm/disable (secret shown once), session
list and revoke (`DELETE /user/sessions[/{id}]`), profile `PUT`; has
`role="dialog"`; 37 inline; tabs. `NotificationsPanel` (350): list, mark
read, read-all, `DELETE`; `role="dialog"`. `HelpPanel` (343): static;
`role="dialog"`. `SettingsDrawer` (260): `GET`/`PUT /user/preferences` — **the
theme mechanism**; `role="dialog"`. `ChangePasswordModal` (229): password
change; `role="dialog"`. Legacy `Modal` (60): no semantics (7 consumers:
Dashboard, UserManagement ×2, Phase3Results, NetworkMap ×2,
ComplianceWorkspace, OrganizationManagement, AuditLogDetailsModal).
`Toast` (64): no `aria-live` (12 consumers). `ConfirmDialog` (104),
`Button` (44), `FormField` (20), `Loader` (9), `EmptyState` (18),
`Skeleton` (41, debt), `CVELink` (48, debt, 6 consumers), `RiskBadge` (41),
`ScanStepper` (143), `ExportPanel` (626), `ScanQuotaBar` (229),
`AuditLogDetailsModal` (363, 27 inline — rendered inside the migrated
AuditLogs page), `PanelErrorBoundary`/`RootErrorBoundary` (16 inline
between them). `CcureAppShell` exists in the design system and is consumed
only by the showcase — the shell migration has a landing pattern already.
**Risk: HIGH** (every page; theme mechanism; MFA/password flows). Not for a
page batch.

### 1.4 Shared stylesheet exposure (consumers by distinct classes)

| Sheet            | classes | consumers | heaviest                                                                                                                                          |
| ---------------- | ------: | --------: | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dashboard.css`  |     149 |         7 | SecurityDashboard 90, **AssetDetail 30**, ComplianceWorkspace 23, VulnerabilityBrowser 22*, AssetRegistry 21*, AMTIntegration 15, AuditTimeline 2 |
| `scan.css`       |     344 |        33 | ScanHistory 93, Phase3 45, Phase2 39, CredentialedResults 31, Phase1 26, UserManagement 19, **Dashboard 16**                                      |
| `layout.css`     |      72 |        26 | AppLayout 52; 4 or fewer everywhere else                                                                                                          |
| `compliance.css` |       – |         1 | ComplianceWorkspace                                                                                                                               |

\* residual references on migrated pages (`db-page-title` and similar shell-level
classes), unchanged since batch 10.

---

## 2. Batch 11 reassessment — Dashboard + AssetDetail

The historical classification is confirmed, on today's measurements, with one
correction and one honest caveat.

**Correction.** The brief describes AssetDetail as "four forms / four tables".
Measured: **2 `<form>` elements** (tag, note) plus two non-form input groups
(owner inline edit; drawer reason/notes), and **2 `<table>` elements**
(findings, services) plus four `InfoField` grids. The batch is smaller in
form/table count than the brief assumed and larger in inline-style count
(185, the second-highest on the remaining list after ComplianceWorkspace and
Phase3Results).

**Caveat.** The two pages do **not** share patterns. Dashboard is a card grid
with a legacy modal and no data; AssetDetail is a data page with tabs, tables,
a drawer and six writes. The pairing is justified by _risk budget and flow_,
not by pattern reuse:

1. **They are the two lowest-risk unmigrated non-visualisation pages.** Every
   other candidate dispatches a scan (ScanSchedules run-now, ScanHistory
   re-run, Phase1/Phase3, NewScan), handles a typed credential (UserManagement,
   NewScan, ComplianceWorkspace), performs a destructive import
   (AMTIntegration), or holds a WebSocket (Phase3, CredentialedResults,
   NewScan). AssetDetail has none of those: no timers, no socket, no upload,
   no download, no credential, and six writes that are each one request with
   one body.
2. **Dashboard is close to free and closes a shell contract.** It is the only
   consumer of `AppLayout`'s `onNewScan` modal path and the only consumer of
   the `scan-card` family in `scan.css`. Migrating it retires the legacy
   `Modal` from one of its seven consumers and exercises `CcureModal` on the
   simplest possible dialog before the shell batch needs it.
3. **AssetDetail completes the asset flow batch 10 started.** AssetRegistry →
   AssetDetail is one drill-down; the registry is migrated and the detail is
   not, so the theme, badge and table vocabulary changes across a single
   click today.
4. **AuditTimeline is page-owned in practice.** Its only consumer is
   AssetDetail (verified by import search; SecurityDashboard's
   `AuditTimeline` is a local function). It can be migrated inside this batch
   without a shared-component regression surface — it needs 16 inline styles,
   `db-tabs`/`db-tab`/`db-btn` and two `<div onClick>` headers converted.

**Alternatives considered and rejected.** AssetDetail + Phase2Results (both
table-heavy, read-mostly): Phase2 is bound to the ScanContext pipeline state
and to `ScanStepper`/`ExportPanel`, which Phase1 also renders — a shared
surface this batch would otherwise avoid. Dashboard + ScanSchedules (two small
pages): ScanSchedules dispatches scans and its toast defect makes feedback
untestable until fixed; strictly more risk than AssetDetail for less coverage.
AssetDetail alone: the brief's rule is not to split merely for size, and
Dashboard adds no meaningful risk.

**Security-sensitive behaviour in the pairing.** One item: AssetDetail's
`PATCH /findings/{id}/status` records a risk acceptance. It is reached only
through Accept Risk → reason → **Confirm**; the baseline asserts that choosing
the action writes nothing and that only Confirm sends the exact body. The
harness never reaches Confirm and the stub table refuses every non-GET. The
page's UI gate for this action is `assets:update` rather than the backend's
`findings:accept_risk`; that mismatch is recorded (§6) and **must not be
changed in the migration** — the backend enforces the real rule, and the UI
gate is a display decision to be taken separately. Dashboard's only state
change is `resetScan()` on the client, which discards in-progress scan context
by design; the harness never clicks a card.

**Shared `dashboard.css`.** Untouched. AssetDetail leaves the sheet the way
AssetRegistry and VulnerabilityBrowser did in batch 10 — page-owned `ad-*`
atoms and CCure primitives — so its consumer count drops from 7 to 6 without
editing the file. The dominant consumer (SecurityDashboard, 90 classes) stays;
the sheet's contrast debt therefore also stays and is not this batch's.

**Recommendation: Batch 11 = Dashboard + AssetDetail (+ AuditTimeline as a
directly-owned component).** GO for planning; migration awaits approval.

---

## 3. Why the batch is safe

| Property                      | Dashboard                                                                                   | AssetDetail                                    |
| ----------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Endpoints                     | 0                                                                                           | 5 reads, 6 writes, all enumerated and asserted |
| Scan dispatch                 | no (navigates to the form)                                                                  | no                                             |
| Credentials / secrets         | none                                                                                        | none                                           |
| Timers / sockets / polling    | none                                                                                        | none                                           |
| Uploads / downloads           | none                                                                                        | none                                           |
| Destructive without confirm   | none                                                                                        | tag removal (kept as-is)                       |
| Permission surface            | none                                                                                        | one (`assets:update`)                          |
| Shared component edits needed | legacy `Modal` untouched (page stops using it)                                              | `AuditTimeline` (single consumer)              |
| Shared CSS edits needed       | none (`scan-card*` has no other consumer; it is _left in place_, unpruned, unless approved) | none                                           |
| Theme mechanism               | untouched                                                                                   | untouched                                      |
| CSP / nginx                   | untouched                                                                                   | untouched                                      |

Every write on AssetDetail has a baseline test that asserts the exact method,
path and body, and a "nothing else writes" assertion on every read-only
interaction — so a migration that changes a payload, adds a request or drops
the Confirm step fails the regression gate before the harness runs.

---

## 4. Baseline tests (written, run, not migrated)

| Suite                        |   Tests | Pass (regression gate) |                   Fail (migration spec) |
| ---------------------------- | ------: | ---------------------: | --------------------------------------: |
| `pages/Dashboard.test.jsx`   |      27 |                     22 |                                       5 |
| `pages/AssetDetail.test.jsx` |      75 |                     63 |                                      12 |
| **Batch 11**                 | **102** |                 **85** |                                  **17** |
| Full suite                   |   1,255 |                  1,238 | 17 (exactly the spec set) · 0 unhandled |
| Lint (`--max-warnings=0`)    |         |                      0 |                                         |

**Failing set = the specification.** Dashboard: labelled search control; modal
as a named `role="dialog"` with `aria-modal`; zero inline styles; decorative
SVGs `aria-hidden`; empty-search state as a `role="status"`. AssetDetail:
exactly one h1 carrying the address; `tablist`/`tab`/`aria-selected`/
`tabpanel`; captions and `scope="col"` on both tables; `aria-pressed` on the
managed toggle; expandable service rows as buttons with `aria-expanded`;
finding rows reachable through a "Details for {id}" control; drawer as a named
modal dialog that Escape closes with a named close control; remove-tag as a
named button; labelled owner/tag/note inputs; status-save result in a live
region; load failure as `role="alert"`; zero inline styles outside the
data-driven risk ring.

**Passing set = what must not change.** Dashboard: 13 cards, 6 enabled, badge
text, `resetScan` → `setPipelineMode` → `navigate` **in that order**, direct
routes without touching the context, disabled cards inert, search by title
and description, empty-state wording, modal open/close/Escape/choose-and-close,
zero requests throughout. AssetDetail: the four reads with `{ params: {} }`
and nothing else; loading placeholder; error state with Back to Registry;
header/risk/activity/managed labels; four tabs with live counts, switching
without re-reading; every identity/OS/AMT/discovery field and its hide rules;
owner edit → `PATCH {owner}`, cancel restores, failure leaves edit mode; toggle
→ `PATCH {is_managed}` optimistic, failure reverts; tag add → `POST {tag}` +
re-read, whitespace ignored, remove → `DELETE …/dmz%2Fprod` with no
confirmation, failure keeps the tag; note add → `POST {content}` + re-read,
newest first; services columns derived from data, enrichment hint, expand /
collapse, expired/weak flags; findings rows, CVSS "0.0" for null, NVD link
with `rel="noopener noreferrer"` and a plain CCure identifier; drawer opens
with exactly one `GET /findings/{id}`; scores, EPSS as percentage, at most 5
references; actions only when open **and** permitted; choosing an action
writes nothing; Accept Risk and Mark Fixed send the exact bodies then re-read;
row status updates after commit; failure keeps the panel; changelog empty and
grouped states; the read-only view without `assets:update`.

Two conventions carried from batch 10: fixture field names are the page's own
reads, and the helpers that open the drawer, expand a row and find the
remove-tag control are **dual-path** — they find the control as it exists
today (a clickable `tr`/`span`) and as the migration makes it (a named
button), so the contract they guard does not loosen when the control changes
shape.

---

## 5. Harness design (designed; not built, not run)

Generated by a `b11-parts.py` from `capture-batch10.mjs`, as batch 10 was
generated from batch 9. Every batch 10 capability is carried forward
unchanged: frozen clock (`Page.addScriptToEvaluateOnNewDocument`, 12:00Z),
`/api/` pathname stubbing with longest-path-first ordering, size-stability
readiness on `.page-main`, `data-theme` re-assertion, data-derived markers,
portal-aware `ROOTS`/`qsa`/`qsaSelf`, ARIA-state census, per-header
`headerScopes`, `controlNames` in the summary, prepare-effect guard with a
portal-aware snapshot, `no-select` prepares, `LOGREQ=1` empirical no-write
check, and the byte-level `chr(92)` emission for `\s` (the batch-8-era escape
defect must not be re-introduced by editing the probe as a template literal).

### 5.1 Two instrument changes, to be made **before** any page migration under the HARNESS PROCESS RULE

1. **`ROOTS` gains `.modal-overlay`.** Dashboard renders its legacy `Modal`
   as a _sibling_ of `AppLayout`, outside `.page-main`, with no `role`. The
   batch 10 roots (`.page-main, .cc-modal, [role="dialog"]`) are blind to it,
   so the pre-migration capture of the modal state would record no dialog
   content while the post capture (a portalled `CcureModal` with
   `role="dialog"`) would — a difference that reads as "the modal appeared"
   rather than a comparison of the same state. Validation: self-test twice on
   the same container (byte-identical), sensitivity on a deliberately removed
   card inside the modal (detected and named), unchanged control on the batch
   10 `assetSvcDetail` state (identical).
2. **Per-route user override.** The batch 10 `USER` is a superadmin. The
   permission-sensitive state of AssetDetail (no write controls) needs
   `/auth/me` to answer with a `viewer` for one route. Implemented as
   `overrides.user`, consulted by the `/auth/me` stub; validated by the same
   three checks (the viewer capture must differ from the superadmin capture in
   exactly the write controls, and must be stable).

Both are instrument corrections and are documented in
`03c-batch11-harness.md` §1 before Phase C begins.

### 5.2 Route / state table (34 captures per build)

| Name               | Path          | Prepare                                                        | Marker / settle           | Notes                                                                                                                                     |
| ------------------ | ------------- | -------------------------------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `tplGrid`          | `/scan`       | –                                                              | "Basic Network Scan"      | 13 cards                                                                                                                                  |
| `tplSearch`        | `/scan`       | native-setter `search` ← "malware"                             | 1 card                    | guard: card count 13 → 1                                                                                                                  |
| `tplEmpty`         | `/scan`       | search ← "zzz"                                                 | settle "empty"            | live-region spec                                                                                                                          |
| `tplModal`         | `/scan`       | click the **shell's** New Scan button                          | "Start New Scan"          | scoped to the header, not `.page-main` — the opener lives in the shell by design; never clicks a card (navigates + writes sessionStorage) |
| `adInfo`           | `/assets/a-1` | –                                                              | "10.180.5.10"             | default tab                                                                                                                               |
| `adServices`       | `/assets/a-1` | click tab "Services & Ports"                                   | "443 / tcp"               |                                                                                                                                           |
| `adServiceOpen`    | `/assets/a-1` | tab → open the 443 row (row click today / expand button after) | "TLS Details"             | dual-path prepare                                                                                                                         |
| `adVulns`          | `/assets/a-1` | click tab "Vulnerabilities"                                    | "CVE-2026-1111"           |                                                                                                                                           |
| `adDrawer`         | `/assets/a-1` | tab → open finding (row click / "Details for …")               | "Finding Detail"          | one `GET /findings/f-1`; portal-aware                                                                                                     |
| `adDrawerAction`   | `/assets/a-1` | drawer → click "Accept Risk"                                   | reason textarea           | **never reaches Confirm**; the no-write gate proves it                                                                                    |
| `adOwnerEdit`      | `/assets/a-1` | click "Edit"                                                   | owner input               | never clicks Save                                                                                                                         |
| `adChangelog`      | `/assets/a-1` | click tab "Audit & Changelog"                                  | "Asset Activity Timeline" | fixture: one group                                                                                                                        |
| `adChangelogGroup` | `/assets/a-1` | tab → expand the group                                         | event title               | `<div onClick>` today                                                                                                                     |
| `adEmpty`          | `/assets/a-1` | –                                                              | settle "empty"            | overrides: no services, findings, events, tags, notes                                                                                     |
| `adError`          | `/assets/a-1` | –                                                              | settle "error"            | override: `/assets/a-1` → 500                                                                                                             |
| `adReadOnly`       | `/assets/a-1` | –                                                              | "10.180.5.10"             | override: viewer user; no write controls                                                                                                  |
| `adReadOnlyDrawer` | `/assets/a-1` | tab → open finding                                             | "Finding Detail"          | viewer: no actions                                                                                                                        |

17 states × 2 themes = 34 captures. Stubs: `/assets/a-1/services`,
`/assets/a-1/findings`, `/assets/a-1/changelog` **before** `/assets/a-1`,
and `/assets/a-1` before the batch 10 `/assets$` list stub; `/findings/f-1`
before `/findings$`. Every non-GET is refused (fails closed), as in batch 10.

### 5.3 Gates

| Gate                | Method                                                                                                                                                                              | Pass condition                                                                                                  |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Determinism         | same container, two captures                                                                                                                                                        | byte-identical, both builds                                                                                     |
| Sensitivity         | four injections into the **migrated** build: remove `aria-pressed` from the toggle; drop the findings caption; rename the drawer's accessible name; change the risk-ring band class | 4/4 detected **and named**                                                                                      |
| Unchanged control   | batch 10's 19 routes + the 53 earlier states                                                                                                                                        | 0 differences                                                                                                   |
| Portal / ARIA       | `adDrawer`, `tplModal` roles and names measured live                                                                                                                                | role + name present post; census non-empty pre                                                                  |
| Accessible names    | `controlNames` diff on every state                                                                                                                                                  | 96 → 0 pattern from batch 10 reproduced for this batch's unlabelled set (Dashboard 1, AssetDetail 5 + drawer 2) |
| No writes           | `LOGREQ=1` over all 34 captures                                                                                                                                                     | 0 non-GET beyond the session stub; 0 DELETE/PATCH/PUT; 0 downloads                                              |
| Off-origin          | request log                                                                                                                                                                         | 0 (the NVD links are anchors, never fetched)                                                                    |
| Frozen clock        | `ago()` in AssetDetail and AuditTimeline                                                                                                                                            | "3d ago" stable across runs; a thaw must change it (proved load-bearing as in batch 10)                         |
| Prepare effect      | portal-aware snapshot incl. `.modal-overlay`                                                                                                                                        | every prepare changes the snapshot or throws                                                                    |
| Coverage accounting | states enumerated vs captured                                                                                                                                                       | see §5.4                                                                                                        |
| Contrast            | pre/post on all 34                                                                                                                                                                  | 0 new colour pairs; the 32 light-shade literals on AssetDetail are expected to disappear                        |

### 5.4 Coverage accounting — what the harness deliberately does not capture

| State                             | Why not captured                                           | Covered by                                  |
| --------------------------------- | ---------------------------------------------------------- | ------------------------------------------- |
| Dashboard card click              | navigates away and writes sessionStorage                   | 8 unit tests (mode, order, routes, inert)   |
| Owner Save / Cancel               | Save is a write                                            | 4 unit tests                                |
| Managed toggle click              | write                                                      | 3 unit tests                                |
| Tag add / remove                  | writes                                                     | 5 unit tests                                |
| Note add                          | write                                                      | 3 unit tests                                |
| Status Confirm (accepted / fixed) | write — the security-sensitive one                         | 6 unit tests incl. exact bodies and failure |
| Drawer for a non-open finding     | reachable, but adds a second finding fixture for one badge | 1 unit test                                 |

---

## 6. Newly discovered defects (recorded, NOT fixed)

1. **AssetDetail — status-save success message is never visible.**
   `handleStatusSave` sets `saveMsg` ("Status updated to …") and then
   `setAction(null)`; `saveMsg` is rendered only inside the action panel that
   `setAction(null)` unmounts. The failure message survives because failure
   leaves `action` set. Reproduced by test ("Accept Risk sends PATCH … then
   re-reads": the message is asserted **absent**). Accessibility/correctness:
   proposed as an explicit intentional change in Phase C (live-region spec
   test exists) — not fixed now.
2. **AssetDetail — five silent write failures.** Owner save, managed toggle,
   tag add, tag remove and note add all `catch {}`; a 403 or a network error
   gives the user nothing. The baseline asserts the current behaviour
   (no retry, state reverts or stays). Proposed as an explicit intentional
   change (a `CcureAlert`/toast per failure) for approval; not fixed now.
3. **AssetDetail — UI permission gate for finding status is `assets:update`.**
   The backend requires `findings:update` (and `findings:accept_risk` for
   acceptance). A user with `assets:update` alone sees Accept Risk / Mark
   Fixed and receives "Failed to update status". Not a security hole (server
   enforces); a display-gate decision that the migration must not make
   silently. Recorded; untouched.
4. **SecurityDashboard — `c.cvss_v3_score.toFixed(1)` unguarded** (line
   1049), the same class as the VulnerabilityBrowser defect already on the
   debt list. Untouched; recorded for that page's batch.
5. **Dashboard — badge text leads the accessible name** ("Soon Malware Scan
   …"; "Beta Soon Agent Based Monitoring …") and the only reason a card is
   disabled is a `title` tooltip. Migration item (spec test covers the SVG and
   modal parts; the badge order is a Phase C design note).
6. **`AuditLogDetailsModal` (legacy, 27 inline styles) renders inside the
   migrated AuditLogs page**, like `CVELink` does on four migrated pages.
   Not in batch 10's debt list by name; recorded now.
7. **`AuditTimeline` uses `db-tabs`, a class `dashboard.css` does not
   define** (unowned), so its tab strip has never had that sheet's styling.
   Cosmetic; folds into the AuditTimeline migration if approved.

---

## 7. Deferred debt — confirmed untouched (measured against the working tree)

| Item                                                                                                  | Where                                          | Verified                        |
| ----------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------- |
| `cvss_v3_score.toFixed()`                                                                             | `VulnerabilityBrowser.jsx:985`                 | present                         |
| ScanSchedules toast destructure                                                                       | `ScanSchedules.jsx:130`                        | present; file unchanged vs HEAD |
| `useScanPolling` re-entrant timer                                                                     | `modules/web-scanning/hooks/useScanPolling.js` | unchanged vs HEAD               |
| ScanDetail `alert()` on failed download                                                               | `modules/web-scanning/pages/ScanDetail.jsx:99` | present                         |
| `CVELink` inline styles + `#3b82f6`                                                                   | `components/common/CVELink.jsx`                | 3 `style=`; unchanged vs HEAD   |
| AssetRegistry click-only sortable `<th>`                                                              | `AssetRegistry.jsx`                            | 13 headers with `onClick`       |
| `dashboard.css` contrast debt                                                                         | `styles/dashboard.css`                         | unchanged vs HEAD; 7 consumers  |
| `Skeleton.jsx`, `web-scanning.css`, `.page-subtitle`, NewWebScan items, CredentialedScan OpenSSH copy | as recorded                                    | unchanged                       |

None is required by the proposed batch. `CVELink` will again render inline
styles inside a migrated page (AssetDetail's findings table and drawer); as in
batch 10 this is a documented allowance, not a fix.

---

## 8. HOLD conditions

None triggered. Two decisions are needed before Phase C, neither of which is a
HOLD:

- whether the two AssetDetail feedback defects (§6.1, §6.2) are approved as
  intentional behaviour changes in the migration, or stay recorded debt;
- whether `AuditTimeline` is in scope as a directly-owned component (single
  consumer, measured) or is left rendering 16 inline styles inside the
  migrated changelog tab, CVELink-style.

**STOP** — awaiting approval before Phase B (harness build) and Phase C
(migration).
