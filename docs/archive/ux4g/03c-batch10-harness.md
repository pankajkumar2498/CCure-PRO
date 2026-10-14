# Checkpoint 3C — Batch 10 regression instrument

Documented separately from the migration, per the standing process rule. **No
page was migrated before these gates passed.**

Three defects were found in the instrument during Phase B. All three were found
by the gates rather than by inspection, and **each would have produced a clean
or mislabelled result for a build that had demonstrably changed.**

---

## 1. What was derived, and from what

`capture-batch10.mjs` is generated from the validated `capture-batch9.mjs` by
`scratchpad/b10-parts.py`, so every change is a named, reviewable substitution
rather than a hand edit. Carried forward **unchanged**: one container per
process, pathname-only stubbing under `/api/`, size-stability readiness scoped
to `.page-main`, `data-theme` re-assertion with verification, the empty-page and
marker guards, the **portal-aware census roots** and the **ARIA-state census**.

| Region          | Change                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| Fixtures        | credential fixtures → config-check / report / audit / finding / asset fixtures                          |
| `ROUTES`        | 8 batch-9 states → **19 batch-10 states** across 5 pages                                                |
| Stub table      | `/credentials*` → `/config-audit`, `/scans`, `/admin/audit-logs`, `/findings`, `/assets`                |
| Probe selectors | credential surfaces → batch-10 legacy (`.db-table`, `.report-card`, …) and migrated (`.b10-*`, `.cc-*`) |
| Settle guard    | loading-placeholder check → **empty/error state proof**                                                 |
| **New**         | **frozen clock** (§2)                                                                                   |
| **New**         | **per-header scope census** (§3)                                                                        |
| **New**         | **prepare-effect guard** (§4)                                                                           |

`diff-batch10.mjs` additionally names `controlNames`, `headerScopes`,
`rowHeaderScopes` and `headerTexts` in its summary (§3).

### Markers are data, and one route does not exist

Every marker is fixture-derived (`"SMBv1 must not be installed"`,
`"alice@example.test"`, `"google-chrome"`), never UI copy the migration
rewrites.

**There is deliberately no `cfgError` route.** ConfigurationChecks has no
observable error state before migration: its only error surface is a toast, and
the toast call throws. A failed load therefore renders the EMPTY state — "No
configuration checks for this platform" — a false statement about the product's
capability rather than about the data. A state that exists on only one side
cannot be compared, so it is not in the shared table; its arrival is a migration
outcome asserted by the unit suite. Including it would either fail the pre
capture or force the guard to be relaxed until it passed, **and a guard that
adapts to the build is not a guard.**

---

## 2. Defect 1 — two captures of the same container could never agree

`AssetRegistry` renders relative time from the wall clock:

```js
const ago = (iso) => { const m = Math.floor((Date.now() - new Date(iso)) / 60000); … }
```

so `"3m ago"` becomes `"4m ago"` between two runs minutes apart.
`VulnerabilityBrowser` derives today/yesterday the same way, and
`SecurityReports` counts "New Today" against a rolling 24-hour window. The
instrument could not have been deterministic on three of five pages.

**The rule is that application behaviour is not changed to suit the
instrument**, so the clock is frozen in the _browser_ instead, installed through
`Page.addScriptToEvaluateOnNewDocument` so it is in place before a line of
application code runs and survives every navigation:

```js
const FIXED = Date.UTC(2026, 8, 11, 12, 0, 0);
function F(...a) {
  return a.length === 0 ? new R(FIXED) : new R(...a);
}
F.now = () => FIXED;
```

Only the **zero-argument** form and `Date.now()` are pinned. Replacing the whole
constructor would break every `new Date(iso)` the pages and fixtures depend on.
All fixture timestamps are expressed relative to that instant, so what renders
is stable _and_ meaningful rather than merely stable.

**Proven load-bearing, not assumed.** Real wall clock at capture time was
`03:37Z`; the freeze is at `12:00Z`. Without it the fixture timestamps are in
the future and `ago()` renders `"now"`. The capture contains `"15m ago"` and
`"6h ago"`, which is only reachable through the frozen clock.

---

## 3. Defect 2 — the probe could not see a partial `scope` change

**Gate 2 failed on its first run.** Four deliberate changes were injected into
`AuditLogs`; the instrument reported the page CHANGED and named **two**:

| Injected                                | First run               |
| --------------------------------------- | ----------------------- |
| `<h2>` → `<h3>`                         | named                   |
| `aria-pressed` on the Export CSV button | named                   |
| `scope="col"` on one `<th>`             | **not detected at all** |
| `aria-label` on the search filter       | captured, **not named** |

The two failures are different, and only one is a reporting problem:

- **`scope` was never recorded.** The census was `headerScoped:
[...ths].every(th => scope === "col")` — all-or-nothing. Adding scope to one
  of seven headers moved nothing: `false` before, `false` after. That is exactly
  the wrong blind spot for this batch, whose table work **is** per-header
  `scope`; a partial regression (six of seven scoped) would have reported clean,
  and clean is read as evidence. The probe now records
  `headerScopes: "-,-,-,-,-,-,-"` and `rowHeaderScopes`, plus `headerTexts`.

- **The accessible name was recorded but invisible.** `labelledControls` held
  `INPUT:Search` → `INPUT:Search audit events`, but the summary exposed only the
  unlabelled _count_, which stayed `1 → 1`. The raw comparison flagged the page;
  the summary explained it with the heading change sitting beside it, and a
  reviewer would have credited the delta to that and never seen the rename. **A
  count cannot report a rename.** `controlNames` is now named in the summary.

After the fix, all four are detected **and named** — see §6.

---

## 4. Defect 3 — a prepare step that did nothing was accepted

`assetSvcDetail` clicked a services table **row**; the click handler sits on a
**button inside** the row. The prepare found its target, returned `"ok"`, and
captured a page byte-for-byte identical to `assetSvc` — the default state filed
under the variant's name.

The batch-8 `no-select` guard does not cover this: the control _was_ found. The
failure mode is the one that guard exists to prevent, reached from the other
side, and it is silent.

The driver now snapshots `.page-main` innerHTML before the prepare and **fails
if the prepare changed nothing**:

```
`${name}/${theme}: prepare changed nothing — the capture would be the
 default state under this name`
```

With the target corrected to the button, `assetSvcDetail` now measures the
drill-down: _"Associated Assets for ssh on Port 22/TCP"_, `.db-table 1 → 2`.

---

## 5. Coverage

**19 routes × 2 themes = 38 captures.**

| Page                 | States                                                        |
| -------------------- | ------------------------------------------------------------- |
| ConfigurationChecks  | list, empty                                                   |
| SecurityReports      | list, empty, error, **delete confirmation**                   |
| AuditLogs            | list, **filtered**, empty, error                              |
| VulnerabilityBrowser | grouped, CVE view, empty, error                               |
| AssetRegistry        | assets, services, certificates, empty, **service drill-down** |

Each state proves it is the state it claims: the empty guard refuses a capture
still showing populated rows _and_ one showing no empty message; the error guard
requires an error message; the prepare-effect guard requires a change.

**Not covered, and why:**

- `cfgError` — the state does not exist before migration (§1).
- A triage-submission state on VulnerabilityBrowser — submitting triage is a
  `PATCH`, and no write is stubbed as a success (§6). The permission affordance
  for it is covered by the unit suite instead.
- An export/download state — see §6.

---

## 6. Gate results

All six gates, against `ccure-frontend:ux4g-b10pre` (the pre-migration build)
and `ux4g-b10sens` (the four-injection build).

### Gate 1 — determinism

Two runs of the same container, byte-compared.

|                                 | Result                                         |
| ------------------------------- | ---------------------------------------------- |
| 19 routes × 2 themes, run twice | **byte-identical**, sha256 `34003764ae69b785…` |

Re-run from scratch after **each** of the three instrument fixes, not once at
the end.

### Gate 2 — sensitivity

| Injected change                         | Detected as                                               |
| --------------------------------------- | --------------------------------------------------------- |
| `<h2>` → `<h3>`                         | `headings "H2:Audit Logs" → "H3:Audit Logs"`              |
| `aria-label` added to the search filter | `controlNames … INPUT:Search → INPUT:Search audit events` |
| `scope="col"` on one of seven `<th>`    | `headerScopes "-,-,-,-,-,-,-" → "col,-,-,-,-,-,-"`        |
| `aria-pressed` on a native `<button>`   | `ariaStates "" → "BUTTON\|Export CSV\|pressed=false"`     |

All four named, in **both themes**, across all four AuditLogs states.

### Gate 3 — unchanged control

The injection touched AuditLogs only.

|                                            |                    |
| ------------------------------------------ | ------------------ |
| Injected page states                       | **8 / 8 CHANGED**  |
| Control page states (the other four pages) | **0 / 30 changed** |

### Gate 4 — portal awareness

Carried forward from batch 9 and **exercised live this run**: `repDelete`
records `roles: ["dialog|Permanently Delete Report for Scan No. 41?|"]`, and
`assetSvcDetail` measures the drill-down's table. Ten censuses run through the
portal-aware `qsa()`; **zero remain scoped to `.page-main` alone**. This matters
after migration, when SecurityReports' confirmation becomes a portalled
`CcureConfirmDialog`.

### Gate 5 — ARIA-state awareness

The census keys on state attributes, not on `[role]`. Proven live: the
`aria-pressed` injection on a **native `<button>`** — the exact case batch 9's
role-only census was blind to — was named.

### Gate 6 — no writes, no downloads

Empirical, from a full logged run of all 19 routes including **both dialogs**:

|                                      | Count | Required |
| ------------------------------------ | ----: | -------- |
| Total requests                       |   451 | —        |
| Non-GET, excluding the session stub  | **0** | 0        |
| DELETE / PATCH / PUT                 | **0** | 0        |
| Report downloads / audit-log exports | **0** | 0        |
| Off-origin requests                  | **0** | 0        |

The 30 non-GET requests in the log are all `POST /api/auth/refresh` — the
session stub the instrument itself installs so pages render instead of
redirecting to `/login`. **No application endpoint was written to.**

Three layers hold this, in order: the delete route's prepare drives the opener
and never the confirm control; download and export endpoints answer 503 by
name; and a catch-all refuses every non-GET that reaches it. A mistake in the
first fails closed at the second or third — but the instrument does not rely on
that, which is why the prepare is scoped and the log is checked.

**One prepare had to be corrected for this reason.** The delete-dialog opener
first searched the whole document for a control starting "delete" and clicked
the shell's **"Deleted Users" navigation link**, navigating away mid-capture.
The driver's URL assertion caught it. It is now scoped to `.page-main` and
matched on the control's own `title`/`aria-label`. A prepare step must not be
able to leave the page it is preparing.

---

## 7. Findings recorded during Phase B

Observed by the instrument, not fixed here:

- **AssetRegistry's service drill-down has no `role="dialog"`** — `roles: []`
  while a modal is on screen. It is a hand-rolled div.
- **AuditLogs has one unnamed filter control** — `SELECT:UNLABELLED` in the
  control census, independent of the injected change.
- **AuditLogs' 5-second poll is deterministic by construction here**, and that
  is a property of the fixture rather than of the page: the poll asks for the
  newest 10 rows and compares them against the newest row already on screen, so
  a stable fixture yields no new events and no DOM change. The poll was left
  entirely alone.

---

## 8. Phase C — three further instrument corrections

Phase C found three more defects in the instrument. Each was found by a gate,
each was fixed in the generator (`b10-parts.py`) rather than by hand, and the
full gate set was re-run from the top after each. **None of them changed a
result on the pre-migration build; each was a blind spot for a property the
migration adds.**

### 8.1 The prepare-effect guard did not see a portal

The first capture of the migrated build failed with
`repDelete/light: prepare changed nothing`. The confirmation had opened
correctly — as a `CcureConfirmDialog`, which renders through a portal into
`document.body`. The guard snapshotted `.page-main` before and after the click,
and nothing inside `.page-main` had changed.

A guard that fails on a correct build is as useless as one that passes on a
broken one. The snapshot is now `.page-main` **plus** the outerHTML of every
`.cc-modal, [role="dialog"]` — the same roots the census uses.

### 8.2 A root's own role was invisible

With 8.1 fixed, `repDelete` recorded `roles: ["tablist|…", "tab||", …]` — a
tablist and **no dialog** while a confirmation was on screen. `querySelectorAll`
never returns the element it is called on, and the portalled dialog _is_ a
census root, so its own `role="dialog"` and accessible name were never read.
The inline drill-down on AssetRegistry was measured (it is a descendant of
`.page-main`); the portalled one was not.

`qsaSelf()` now includes any root that itself matches, and the `roles` and
`ariaStates` censuses use it. After the fix:
`roles: ["dialog|Permanently Delete Report for Scan No. 41?|", "tablist|Report sections|", …]`.

### 8.3 `\s` inside the probe's template literal

`assetSvcDetail` then recorded `dialog||` — a dialog with an **empty
accessible name** — although the page sets
`aria-labelledby="ar-service-dialog-title"` and the heading carries that id.

The probe is a JS template literal, and a lone `\s` is not a template escape:
it collapses to a bare `s`. So every `.split(/\s+/)` used to tokenise an
`aria-labelledby` list was really `.split(/s+/)` — splitting on the **letter
s**. `"ar-service-dialog-title".split(/s+/)` is `["ar-", "ervice-dialog-title"]`;
neither resolves; the name is empty. Proven, not inferred:

```
node -e 'console.log(`x.split(/\s+/)`)'   →   x.split(/s+/)
```

Inherited from the batch-8 probe. It never produced a false comparison — an
empty name compares identical on both sides — but every `aria-labelledby`
id containing an `s` had been silently recorded as unnamed since batch 8. Fixed
at byte level in the generator (built from `chr(92)` so no quoting layer can
eat it). After the fix: `dialog|Associated Assets for ssh on Port 22/TCP|`.

### 8.4 Gate results after all three (final build `ux4g-b10`)

| Gate                | Result                                                                                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Determinism         | 19 routes × 2 themes, run twice — **byte-identical**, sha256 `ef0b55aa1f6793c9…`                                                                       |
| Sensitivity         | 4/4 injections into the **migrated** AuditLogs detected and named (`H1→H2`, `Events per page → Rows per page`, `col,col,… → -,col,…`, `pressed=false`) |
| Unchanged control   | injected page 8/8 changed · other four pages **0/30** changed                                                                                          |
| Portal awareness    | `repDelete` records the portalled dialog's role **and name**                                                                                           |
| ARIA-state          | `aria-pressed` on a native `<button>` named                                                                                                            |
| No writes/downloads | 488 requests: **0** non-GET beyond the session stub, **0** DELETE/PATCH/PUT, **0** downloads/exports, **0** off-origin                                 |

### 8.5 Two probe limitations recorded, not fixed

- **The capture probe does not sample `.reports-header-box`.** The
  SecurityReports.css contrast correction (§13 of the migration report) changed
  nothing the capture measures — the capture hash was identical before and
  after it — while the _contrast_ probe saw it. The two instruments sample
  different things by design; noted so nobody reads the identical hash as "the
  CSS change had no effect".
- **The contrast probe measures `.cc-sr-only` text.** Visually hidden text has
  no visual contrast requirement (WCAG 1.4.3 applies to text that is
  perceivable visually), but the probe reports it. Four of the 64 remaining
  sub-AA readings are this. Left as-is rather than silently exempted — an
  exemption is a place for a real failure to hide.
