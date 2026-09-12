# Checkpoint 3C — Batch 12 harness (the shell)

`capture-batch12.mjs` is generated from `capture-batch11.mjs` by
`b12-parts.py`; `contrast-batch12.mjs` from `contrast-batch11.mjs` by
`b12-contrast-parts.py`; `diff-batch12.mjs` extends `diff-batch11.mjs`. All in
the session scratchpad. Every batch 10/11 instrumentation property is verified
by the generator after patching (frozen clock, two-byte `\s`, `qsaSelf`, ARIA
census, per-header scopes, refusal of every non-GET, per-route user override,
multi-step prepare with settle and `expect`/`reject`).

## 1. Why a new instrument was mandatory

Every earlier census root is `.page-main` (plus portals). A rewritten header,
sidebar, skip link or landmark structure would capture as **identical**. The
brief refused that outcome explicitly; this instrument is the answer.

## 2. Instrument changes (validated on the pre-migration build before Phase C)

| #   | Change                                                                                                                                                                                                       | Why                                                                                                                                                       | Validated by                                                                                                                                           |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | Census roots gain `.app-layout` / `.cc-shell` (the whole chrome) plus `.sd-*`/`.shs-*` drawers; `bodyText` and the `expect`/`reject` text come from the same roots; the prepare snapshot includes the chrome | the subject is the shell                                                                                                                                  | pre capture shows 25/21/8 nav items by persona, 5 unnamed buttons, 4 unnamed landmarks, 14 inline styles — none of which any earlier capture could see |
| 2   | New censuses: `landmarks` (tag\|role\|name), `navItems` in order, `activeNav`, `headerControls`, `firstTabStop`, `activeElement`, `collapsed`, `storage` (the two shell keys)                                | each is a named property of the shell that a reviewer needs spelled out                                                                                   | sensitivity injections below are named through them                                                                                                    |
| 3   | `display` joins the computed-style props; per-route `viewport`; `expectSelector` / `expectActive` beside `expect`/`reject`                                                                                   | responsive states hide chrome; a collapse changes a class, not text; Ctrl+K changes focus, not markup                                                     | `shellMobile` (hamburger `display: none → flex`), `shellCollapsed`, `shellSearchFocus` all pass their own assertion                                    |
| 4   | The prepare snapshot carries `document.activeElement`                                                                                                                                                        | a focus-only prepare (Ctrl+K) changed no markup and the batch 11 guard refused it as "changed nothing"                                                    | `shellSearchFocus` accepted; `activeElement` recorded as `INPUT:Search assets, CVEs, scans...`                                                         |
| 5   | `ORG_ADMIN` persona beside `VIEWER` and superadmin                                                                                                                                                           | `superadminOnly` and the org switcher/global search are role-gated, not permission-gated                                                                  | `shellOrgAdmin`: 21 items, no Email Domain Rules, no org switcher; `/admin/organizations/` requested 22× = 26 − 4 persona captures                     |
| 6   | Stubs for the shell's own reads: `/dashboard/summary`, `/scan/quota`, `/notifications/summary`, `/notifications`, `/admin/organizations/`, `/user/preferences`; the SSE stream stays refused                 | the header and sidebar settle on data (badges 2 and 4, quota 7/50, org name)                                                                              | request census identical pre/post (306 GET, 26 POST refresh)                                                                                           |
| 7   | `aria-haspopup` and `aria-controls` join the ARIA-state census                                                                                                                                               | injecting `aria-haspopup="listbox"` for `"menu"` on the org switcher produced **no named delta** — the same blind-spot class as batch 10's `aria-pressed` | after the change: `haspopup=menu → haspopup=listbox` named; pre and post re-captured twice, byte-identical                                             |
| 8   | `diff-batch12.mjs` names the new censuses                                                                                                                                                                    | a shell delta must be explained, not just flagged                                                                                                         | every injection appears as a named line                                                                                                                |

Two bring-up corrections on the test side, both caught by the instrument
refusing the capture: `shellOrgOpen` first searched for a _button_ (the legacy
switcher is a `<div onClick>`), and the expect text was still page-scoped.

## 3. Route / state table — 13 states × 2 themes = 26 captures

| State                | Persona             | Prepare          | Proves                                                                  |
| -------------------- | ------------------- | ---------------- | ----------------------------------------------------------------------- |
| `shellDefault`       | superadmin          | –                | 25 nav items, active "Scan Templates"                                   |
| `shellCollapsed`     | superadmin          | collapse control | `expectSelector` collapsed; `storage.sidebarCollapsed = "true"`         |
| `shellSearchFocus`   | superadmin          | Ctrl+K keydown   | `expectActive /search/`                                                 |
| `shellOrgOpen`       | superadmin          | org switcher     | `/Switch Organization/`, `reject /Sign Out/`                            |
| `shellNotifsOpen`    | superadmin          | bell             | `/Scan #41 complete/` (the stubbed list)                                |
| `shellHelpOpen`      | superadmin          | Help             | `/Help Center/`                                                         |
| `shellSettingsOpen`  | superadmin          | Settings         | `/Save Settings/`                                                       |
| `shellProfileOpen`   | superadmin          | account button   | `/Sign Out/`                                                            |
| `shellOrgAdmin`      | org_admin           | –                | `/User Management/`, `reject /Email Domain Rules\|Switch Organization/` |
| `shellViewer`        | viewer              | –                | `reject /User Management\|Audit Logs/`                                  |
| `shellMobile`        | superadmin, 390×844 | –                | hamburger visible                                                       |
| `shellMobileNavOpen` | superadmin, 390×844 | hamburger        | `expectSelector` sidebar open                                           |
| `shellOnAssets`      | superadmin          | – (on `/assets`) | active "Asset Registry", badges on a data page                          |

All but the last are measured on `/scan` (Dashboard), which issues no request of
its own, so every delta belongs to the shell.

## 4. Gates

| Gate                                                                                                                     | Pre build                                                                                                 | Migrated build (final image)                                                       |
| ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Determinism                                                                                                              | `b12-pre-c/d`, `b12-pre-e/f` byte-identical                                                               | `b12-post-g/h` byte-identical (and `c/d`, `e/f` on earlier iterations)             |
| Sensitivity (4 injections: New Scan → Start Scan; Audit Logs → Audit Trail; `aria-haspopup` listbox; sidebar background) | 4/4 named (`headerControls`/`buttonNames`, `navItems`, `ariaStates` after change 7, `styles .top-header`) | 4/4 named (`buttonNames`, `navItems`, `ariaStates haspopup`, `styles .cc-sidebar`) |
| Personas                                                                                                                 | 25 / 21 / 8 nav items; org reads 22/26                                                                    | 25 / 21 / 8; org reads 22/26                                                       |
| No writes / downloads                                                                                                    | 306 GET, 26 POST (all `/auth/refresh`), 0 others                                                          | identical census                                                                   |
| Off-origin                                                                                                               | 0                                                                                                         | 0                                                                                  |
| Prepare effect + `expect`                                                                                                | 9 prepared states × 2 pass                                                                                | same                                                                               |
| Coverage                                                                                                                 | 26 / 26                                                                                                   | 26 / 26                                                                            |
| Prune proof                                                                                                              | –                                                                                                         | unpruned vs pruned build: 0 / 26 shell states, 0 / 38 batch-10 states changed      |

## 5. Page regression (the earlier instruments, pre vs post)

125 states across 25 pages, every harness re-run serially. Two explained delta
classes and nothing else, proven by stripping `styles`/`counts` and comparing
the remainder (`reg12-explain.mjs`):

1. **Document-wide `.cc-*` census.** The batch 5–11 instruments count
   `.cc-btn`, `.cc-badge`, `.cc-field*` with `document.querySelectorAll`, and
   the "first element" of each is now a shell element: +6 buttons (nav toggle,
   collapse, New Scan, Help, bell, Settings; +5 without `scans:execute`), +1
   badge (ENTERPRISE), +1 field (global search, with its adornment). No page
   selector (`.page-main`, `.page-inner`, `.ad-*`, `.cc-tabs`, `.cc-table`…)
   differs.
2. **Toast shim.** Pages that render `ToastContainer` gain two persistent
   `aria-live` regions (`liveRegions`/`ariaLive` +2); the batch 10
   `auditError` state's error toast is now inside the assertive region with a
   "Dismiss notification" button.

Auth pages (no shell): **IDENTICAL**, 5 states. One STOP was raised and
resolved during this gate — see the checkpoint report §7.
