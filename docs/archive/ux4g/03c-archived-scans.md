# Phase 3C — ArchivedScans

One page. Group A batch 4.

---

## 1. Scope

**Migrated (1):** `src/pages/ArchivedScans.jsx`.

**Added (2):** `src/styles/archived-scans.css`,
`src/__tests__/pages/ArchivedScans.test.jsx`.

**Not touched:** every other page, the application shell (`AppLayout`,
`Toast`), all backend/API code, routing, authorization logic, CSP, nginx,
Docker, `PreferencesContext`, the theme architecture, the design system, the
UX4G package or its version, and `package.json`.

**No CSS was deleted.** See §9 — that is a measured result, not an omission.

---

## 2. Candidate selection

Seven Group A pages remained: `ArchivedScans` 323, `DeletedUsers` 394,
`OrganizationManagement` 425, `RecycleBin` 465, `Dashboard` 537,
`SecurityReports` 622, `EmailDomainRules` 627.

|                        |     LOC | inline | hex | table |  form | inputs | modal refs | API | useEffect |
| ---------------------- | ------: | -----: | --: | ----: | ----: | -----: | ---------: | --: | --------: |
| **ArchivedScans**      | **323** |     11 |   5 |     3 | **0** |  **0** |      **0** |   3 |         2 |
| DeletedUsers           |     394 |      1 |   0 |     3 |     0 |      1 |          2 |   2 |         4 |
| OrganizationManagement |     425 |      3 |   0 |     3 |     0 |      0 |         26 |   7 |         2 |
| RecycleBin             |     465 |     12 |   5 |     3 |     0 |      0 |         24 |   4 |         4 |
| Dashboard              |     537 |      1 |  26 |     0 |     0 |      1 |          9 |   0 |         0 |
| SecurityReports        |     622 |     17 |   1 |     0 |     2 |      6 |         24 |   4 |         4 |
| EmailDomainRules       |     627 |     45 |  13 |     3 |     2 |      6 |          2 |   6 |         4 |

**ArchivedScans is the lowest-risk, smallest-blast-radius candidate**, on four
counts:

1. **Smallest surface.** Fewest lines, and the only remaining candidate with no
   form, no modal, no pagination, no search and no polling. Three API calls.
2. **Fewest shared dependencies.** Its only imported UI is `AppLayout` and
   `Toast` — both shell, both explicitly out of scope and both left untouched.
   `DeletedUsers` and `OrganizationManagement` each pull in four or five legacy
   shared components; `OrganizationManagement` additionally owns 26 modal
   references and a shared `OrganizationForm`.
3. **Zero deletable CSS.** Measured, not assumed — every one of the 23 classes
   it uses has between 2 and 32 other consumers (§9). A migration that cannot
   delete anything cannot break anything by deleting.
4. **The pattern for it already exists and names it.** `CcureScanStatus`, built
   and approved at Checkpoint 3B, cites `ArchivedScans.jsx` **by name** as one
   of the three duplicate scan-status implementations it replaces, and
   documents this page's specific defect:

   > `ArchivedScans.jsx` falls back to the **running** style for any status it
   > does not recognise […] That is not a cosmetic default — it is a false
   > statement about a scan, on a page whose entire job is to report what
   > happened.

   Migrating it consumes a pattern already paid for rather than designing one.

---

## 3. Baseline metrics

|                      | Value                                                                                                                       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Route                | `/archived` (plus a `/archived-scans` → `/archived` redirect)                                                               |
| LOC                  | 323                                                                                                                         |
| Inline `style={{…}}` | 11                                                                                                                          |
| Hardcoded hex        | 5 (`#22c55e`, `#f59e0b`, `#ef4444` ×3 in `STATUS_STYLE`)                                                                    |
| Legacy primitives    | hand-written `<table class="data-table">`, `.btn`, `.action-btn`, `.empty-state`, `.alert`, `.spinner`, local `StatusBadge` |
| Tables / forms       | 1 table, 0 forms, 0 inputs                                                                                                  |
| API calls            | `getScans(0, 200, "archived")`, `restoreScan(id)`, `deleteScan(id)`                                                         |
| Navigation           | `navigate("/history")` from the header and the empty state                                                                  |
| Permissions          | `scans:restore`, `scans:recycle`, each gating its own control                                                               |
| Shared CSS           | 23 classes, **all** shared with 2–32 other files (§9)                                                                       |
| Page-specific CSS    | none — the page had no stylesheet of its own                                                                                |
| Polling              | none                                                                                                                        |

---

## 4. Functional and security contracts

**Data.** `getScans(0, 200, "archived")`. The scope argument is load-bearing:
`getScans` defaults to `scope="active"`, so losing it would list live scans on a
page whose Delete button moves them to the recycle bin. Verified reaching the
wire in a real browser — `GET /api/scans?skip=0&limit=200&scope=archived`.

**Actions.** `restoreScan(id)` and `deleteScan(id)`, each gated on its own
permission at render _and_ inside its handler. A success removes the row
locally and decrements the count; it does **not** re-fetch. A failure leaves the
row in place and surfaces `err.response.data.detail`, falling back to a
per-action generic message.

**Authorization.** The client gate is an affordance, not the boundary — the API
enforces it — but the two must not drift: a control offered to someone who
cannot use it produces a failed request and a confusing error. Neither
permission implies the other, and with neither the page renders "Read only" and
issues no state-changing request.

**Lifecycle.** One load on mount, no polling, and a manual refresh that reissues
the identical query.

---

## 5. Baseline tests and failures

**40 assertions written against the unmigrated page.**

| Group                      | Assertions | Passed | Failed |
| -------------------------- | ---------: | -----: | -----: |
| API contract               |         10 |     10 |      0 |
| Authorization gating       |          5 |      5 |      0 |
| Rendering & business rules |         11 |     11 |      0 |
| Scan status                |          4 |      4 |      0 |
| **Accessibility**          |     **10** |  **2** |  **8** |
| **Total**                  |     **40** | **32** |  **8** |

Full suite at the baseline: **510 tests, 502 passed, 8 failed.** Every
functional, security, authorization and business-rule assertion passed against
the untouched page; **all eight failures were accessibility.** Same shape as the
auth batch, and the same use: the failing set is the specification.

**Two of my own assertions were wrong and were corrected before migration.** I
had written two tests claiming the handlers re-check permission at click time,
mutating the permission set after render and expecting the request to be
refused. `canRestoreScans` is computed during render, so React holds the value
from the last render and the mutation changes nothing — the tests were asserting
behaviour React cannot produce. The handler guards are real and are defence in
depth, but they are **unreachable from outside**: without the permission there
is no control to activate. Rather than fake a state into existence to prove a
branch, the two were replaced by one assertion of what is reachable and what
actually protects the API — that each control appears only with its own
permission and neither implies the other.

---

## 6. Defects discovered

### Four sub-AA contrast values in the status badge — measured on the live page

`STATUS_STYLE` hardcoded three hues chosen for a dark surface, and the page
renders in whichever theme the account selects. Measured in a real browser with
every `rgba()` composited through its actual ancestor chain:

| Status     | Theme |     Before |      After |       |
| ---------- | ----- | ---------: | ---------: | ----- |
| `running`  | light | **1.99:1** | **5.09:1** | ✗ → ✓ |
| `complete` | light | **2.09:1** | **8.89:1** | ✗ → ✓ |
| `failed`   | light | **3.30:1** | **8.94:1** | ✗ → ✓ |
| `failed`   | dark  | **3.57:1** | **7.64:1** | ✗ → ✓ |

The status cell is the single most important column on a page whose job is to
report what happened to a scan, and in the light theme it was the least readable
thing on the page — 1.99:1 for a running scan, against a 4.5 floor.

Post-migration: **0 sub-AA values in either theme**, across 16 measured text
elements per theme.

### An unrecognised status displayed as _running_

```js
const s = STATUS_STYLE[status] || STATUS_STYLE.running;
```

Any status the map does not carry — `partially_completed`, `unreachable`,
`queued`, `pending`, anything added server-side later — rendered in the
in-progress style. Not a cosmetic default: a false statement about a scan.
`CcureScanStatus` renders "Unknown", neutral, and keeps the raw value in a
`title` so an operator can see what the API actually said. Pinned by a test.

### Eight accessibility defects

| Defect                                 | Evidence                                                                     |
| -------------------------------------- | ---------------------------------------------------------------------------- |
| Table had no accessible name           | 0 `<caption>`                                                                |
| No column header carried `scope="col"` | 8 header cells, 0 scoped                                                     |
| No row header                          | 0 `th[scope="row"]`                                                          |
| Loading state announced nothing        | a bare spinning `<div>`                                                      |
| Load failure was not an alert          | `.alert.alert--error` is a plain `<div>`                                     |
| Row actions shared one accessible name | 4 duplicate names among 8 buttons — "Restore", "Delete", "Restore", "Delete" |
| A busy control lost its name           | the label was replaced by `"..."`                                            |
| Colour pinned inline                   | 11 inline styles, 5 hardcoded hex                                            |

All eight are fixed and measured (§8, §10).

---

## 7. Migration changes

Presentation only. Every handler, request, permission check, state transition
and navigation is byte-identical to the original.

| Was                                                                                      | Now                                                        |
| ---------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| hand-written `<table class="data-table">` in `.table-wrap`                               | `CcureTable` with declared columns                         |
| local `StatusBadge` + `STATUS_STYLE` (5 hex)                                             | `CcureScanStatus`                                          |
| `<span class="method-chip">`                                                             | `CcureBadge variant="neutral"`                             |
| `<button class="btn btn--ghost">`, `.btn--primary`, `.action-btn`, `.action-btn--danger` | `CcureButton` (`ghost` / default / `secondary` / `danger`) |
| `<div class="alert alert--error">`                                                       | `CcureAlert variant="danger"`                              |
| `<div class="spinner">` in an inline flex box                                            | `CcureLoader`                                              |
| `.empty-state` block                                                                     | `CcureEmptyState`                                          |
| 4 × inline `fontFamily: var(--mono)`                                                     | the columns' own `mono` flag                               |
| inline `color: var(--text-muted)`                                                        | `.as-muted` → `--ccure-text-secondary`                     |
| `"..."` while busy                                                                       | `CcureButton loading` — keeps the label                    |
| repeated "Restore" / "Delete" names                                                      | `aria-label="Restore scan SCAN-0011"`                      |

The columns are **declared** rather than hand-written as `<tr>`/`<td>`, which is
what lets `CcureTable` own the caption, `scope="col"` on all eight headers and
`scope="row"` on the identifying cell — the three defects a hand-rolled table
cannot fix without repeating the same work on every page.

`useToasts` / `ToastContainer` and `AppLayout` are deliberately **unchanged**:
they are the shell, and the shell is a separate migration. Same decision as the
RoleManagement precedent.

`archived-scans.css` is 58 lines and 7 rules — layout, one font-family, one
semantic colour. Every value is a CCure token.

---

## 8. Accessibility and contrast

Measured on the real rendered page in a real browser, **both themes**, via
`data-theme` on the root — the same attribute the application's own preference
writes. No `prefers-color-scheme` was introduced.

|                                    | Before | After                        |
| ---------------------------------- | ------ | ---------------------------- |
| Table caption                      | absent | `Archived scans — 4 records` |
| Column headers with `scope="col"`  | 0 of 8 | **8 of 8**                   |
| Row headers (`th[scope="row"]`)    | 0      | **3 of 3 rows**              |
| Duplicate button accessible names  | **4**  | **0**                        |
| Inline-styled elements in the page | **21** | **0**                        |
| Sub-AA text (light)                | **3**  | **0**                        |
| Sub-AA text (dark)                 | **1**  | **0**                        |
| Horizontal overflow                | none   | none                         |

Post-migration contrast, both themes, lowest first:

| Element                  |   Light |    Dark |
| ------------------------ | ------: | ------: |
| `.page-subtitle` (shell) |  4.55:1 |  6.96:1 |
| Status · Running         |  5.09:1 |  5.34:1 |
| Status · Failed          |  8.94:1 |  7.64:1 |
| Status · Completed       |  8.89:1 |  7.76:1 |
| Type badge (neutral)     |  9.51:1 | 12.01:1 |
| Archived / Created dates |  9.91:1 | 14.17:1 |
| Column headers           | 10.37:1 | 15.72:1 |
| Target address           | 17.13:1 | 17.10:1 |

**One honest caveat.** `.page-subtitle` measures **4.55:1** in the light theme —
it clears the 4.5 floor by 1%, which is not comfortable margin. It is
**pre-existing and unchanged**: identical in the pre-migration capture, it comes
from the shared shell stylesheet, and 24 other pages use it. This migration
added a `font-family` to that element and nothing else. Correcting it is a shell
change and belongs to whoever migrates the shell, not here.

Keyboard interaction is asserted in the suite: every row action is focusable and
activates on Enter.

---

## 9. CSS deleted, and why none was

**Nothing was deleted, and that is the measured answer rather than a shortcut.**

Before writing any code I searched every `.jsx` outside tests for each of the 23
classes the page used:

| Class                            | Other consumers |     | Class                          | Other consumers |
| -------------------------------- | --------------: | --- | ------------------------------ | --------------: |
| `.muted`                         |              32 |     | `.data-table`                  |               8 |
| `.btn`                           |              31 |     | `.empty-state`                 |               8 |
| `.page-title` / `.page-subtitle` |              24 |     | `.ip-code`                     |               7 |
| `.btn--primary`                  |              21 |     | `.btn-spinner`                 |               6 |
| `.page-inner`                    |              20 |     | `.empty-state-icon` / `-title` |               6 |
| `.btn--ghost`                    |              19 |     | `.action-btn` / `.action-btns` |               5 |
| `.table-wrap`                    |              17 |     | `.method-chip`                 |               3 |
| `.spinner`                       |              15 |     | `.alert--error`                |              13 |
| `.page-title-row`                |              12 |     | `.btn-spinner--dark`           |               2 |
| `.alert`                         |              23 |     | `.action-btn--danger`          |               2 |

**Every class has between 2 and 32 other consumers.** The page stops _using_
them; it does not get to remove them. `.page-inner`, `.page-title-row`,
`.page-title` and `.page-subtitle` are additionally still used by this page —
they are the shell's own layout, kept deliberately.

Two apparent matches were read at the call site rather than trusted from the
grep, exactly as in the auth batch: `CredentialedScan.jsx` uses `cred-auth-btn`
and `ChangePasswordModal.jsx` uses `cpw-strength-bar`, neither of which is the
class the substring matched.

---

## 10. Regression methodology and results

**The auth batch's instrument was reused, and extended to reach an
authenticated page.**

ArchivedScans sits behind `PrivateRoute`, so a browser cannot reach it without a
session. Rather than create an account or use real credentials — neither of
which is mine to do — the three requests the client uses (`/auth/refresh`,
`/auth/me`, `/scans`) are fulfilled at the network layer with CDP `Fetch`. No
backend, container, CSP or application code is touched: the page renders the
same components against the same stylesheets it would in production. Everything
else under `/api` is failed with 503 so the shell settles rather than hanging.

**The instrument was validated before being trusted.** Capturing the same
container twice produces byte-identical output.

**Three harness defects were found and fixed before any result was believed** —
each would have produced a plausible but false reading:

- **End-anchored URL patterns missed every stub.** The client appends
  `?org_id=`, so `/auth/refresh$` matched nothing and the request fell through
  to the 503 catch-all. The page redirected to `/login`, which looks exactly
  like a failed session. Matching on `pathname` fixed it.
- **`user.role` is an object, not a string.** `isSuperAdmin` reads
  `user?.role?.name`, so a bare `role: "superadmin"` resolved every `can()` to
  false and the page rendered "Read only" with no action controls at all. The
  first capture compared two pages neither of which showed the feature being
  migrated.
- **The contrast probe skipped elements with children.** A _running_ badge
  contains a decorative pulse span, so the one status most likely to be
  mis-coloured was silently excluded. Measured separately, it was the worst
  value on the page at **1.99:1**.

**Comparison.** A control image was built from the identical tree with only
`ArchivedScans.jsx` reverted, so the two builds differ in exactly one file.

| Measure                   | pre   | post     |
| ------------------------- | ----- | -------- |
| Table caption             | false | **true** |
| Headers all `scope="col"` | false | **true** |
| Row headers               | 0     | **3**    |
| Body rows                 | 3     | 3        |
| Inline-styled elements    | 21    | **0**    |
| Duplicate button names    | 4     | **0**    |
| Horizontal overflow       | false | false    |

Identical in both themes.

**No unrelated page changed.** All five auth pages captured from both builds are
byte-identical across 27 selectors × 14 properties, plus counts, headings, live
regions and geometry — once the recorded `url` field is excluded, which
necessarily differs because the two containers are on different ports. My first
comparison did not exclude it and reported all five as CHANGED; the diff showed
the port and nothing else.

**Pixel hashing was not used as a gate**, per the standing condition from the
auth batch.

---

## 11. Security, CSP and air-gap

| Check                                   | Result                                                                                 |
| --------------------------------------- | -------------------------------------------------------------------------------------- |
| Content-Security-Policy                 | **byte-identical** to the pre-UX4G baseline                                            |
| Air-gap — page-originated requests      | **0 external origins** (28 requests, all same-origin)                                  |
| `ux4g-*` classes in application JSX     | 0                                                                                      |
| UX4G imports from pages/components      | 0                                                                                      |
| UX4G runtime markers in `dist`          | 0 (`UX4G.js`, `script1.textContent`)                                                   |
| Analytics / telemetry markers           | 0 (`clarity`, `googletagmanager`)                                                      |
| Dev-only showcase in production bundle  | 0                                                                                      |
| New runtime dependency                  | none — the `package.json` diff is Phase 2's approved `ux4g-web-components` + `wawoff2` |
| Backend / API / routing / authorization | not modified                                                                           |
| `scope="archived"` reaching the wire    | verified in a live browser                                                             |

---

## 12. Tests

**510 passed, 19 files** (was 510 at this batch's baseline: 502 passed, 8
failed). The total is unchanged because the 40 new ArchivedScans assertions
replaced no existing file — they were counted in the baseline run too, which is
where the 8 failures came from.

| File                                |        Tests |
| ----------------------------------- | -----------: |
| `pages/ArchivedScans.test.jsx`      | **40** (new) |
| `design-system/contrast.test.js`    |           72 |
| `design-system/primitives.test.jsx` |           53 |
| `pages/Register.test.jsx`           |           47 |
| `pages/Login.test.jsx`              |           46 |
| _(remaining)_                       |          252 |

All 8 baseline failures are green. Nothing regressed — the 502 assertions that
passed before the migration all still pass. Lint clean at `--max-warnings=0`;
production build passes.

**No assertion was weakened to make the migration pass.** The two that changed
were changed _before_ the page was touched, and for the reason given in §5:
they asserted a state React cannot produce.

---

## 13. Bundle impact

|          | Auth-group checkpoint | This checkpoint |            Δ |
| -------- | --------------------: | --------------: | -----------: |
| CSS raw  |             280.63 kB |       281.04 kB |     +0.41 kB |
| CSS gzip |              47.83 kB |        47.90 kB |     +0.07 kB |
| JS raw   |           1,700.36 kB | **1,699.64 kB** | **−0.72 kB** |
| JS gzip  |             421.76 kB |       422.19 kB |     +0.43 kB |

CSS grows by the 58-line page stylesheet and nothing else — no legacy CSS could
be removed (§9). JS shrinks: the page shed a component, a colour map and eleven
inline style objects, and gained only imports.

---

## 14. Files changed

**Modified (1)**

```
Frontend/src/pages/ArchivedScans.jsx        323 → 298   (−25)
                                            inline styles 11 → 0
                                            hardcoded hex  5 → 0
```

**Added (2)**

```
Frontend/src/styles/archived-scans.css                58 lines, 7 rules
Frontend/src/__tests__/pages/ArchivedScans.test.jsx   40 tests
docs/ux4g/03c-archived-scans.md                       this report
```

**Deleted:** nothing.

---

## 15. Release gates

**Engineering: PASS.** 510/510 tests, lint clean, build green, CSP identical,
air-gap clean, zero sub-AA values in either theme, zero horizontal overflow, no
unrelated page changed, no CSS deleted, no new dependency. No stop condition was
met.

**Legal / licence: OPEN — unchanged.**

```
UX4G README declares MIT
package.json has no license field
package has no LICENSE file
package contains no copyright notice to reproduce
embedded Noto Sans carries OFL attribution/redistribution requirements
```

Written confirmation from `support.ux4g@digitalindia.gov.in` remains required
before a production release containing redistributed UX4G-derived assets. **No
legal clearance is claimed and no copyright notice has been invented.**

---

## 16. Recommendation

**GO.**

This is the cleanest batch so far, and the reasons are structural rather than
lucky: the page needed no CSS deleted, touched no shared component, and consumed
a security pattern that had already been designed, reviewed and paid for — one
that names this very file as its motivating case.

The measured outcome is four sub-AA contrast values removed, including a running
scan's status at **1.99:1** in the light theme, and a fallback that reported any
unrecognised status as _running_. Both are the kind of defect that is invisible
until someone measures: the page looked fine in the theme its colours were
chosen for, and the fallback only misreports statuses nobody had thought to add
yet.

One item is worth carrying forward, not blocking: **`.page-subtitle` measures
4.55:1 in the light theme**, clearing AA by 1%. It is pre-existing, shared by 24
pages, and belongs to the shell migration. It is recorded here because this
batch measured it, not because this batch caused it.

The regression instrument now reaches authenticated pages, which every remaining
Group A candidate needs. Its three harness defects are documented in §10 so the
next batch inherits the working version rather than rediscovering them — and
they are a reminder worth keeping: all three produced a plausible reading, and
two of them would have compared two pages on which the migrated feature was not
even rendered.

**STOPPING HERE.** No second page was migrated. No further page will be
migrated without review.
