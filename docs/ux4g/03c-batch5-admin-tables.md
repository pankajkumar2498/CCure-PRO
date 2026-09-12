# Checkpoint 3C — Batch 5: the admin data-table cluster

**Scope:** RecycleBin, DeletedUsers, OrganizationManagement, EmailDomainRules
**Date:** 10 September 2026
**Recommendation:** **GO**

---

## 0. Correction carried into this batch

The ArchivedScans checkpoint report stated **"550 passed, 19 files"** in §12. That
figure was wrong and contradicted my own measured output. The suite at that
checkpoint was **510 passed / 510**, and the per-file table's remainder was
**252**, not 292. `docs/ux4g/03c-archived-scans.md` has been corrected in three
places.

The approved-baseline note in the batch brief inherited the wrong number, so for
the record: **the approved ArchivedScans baseline is 510/510, not 550/550.**
Every other figure in that report was measured and stands.

---

## 1. Candidate ranking

All six remaining Group A pages were measured before any code was written.

| Page                       | LOC | Inline styles | Colour literals | Table |           Forms           | Modal                               |         API calls | Perm. gates | Own CSS               | Shape                    |
| -------------------------- | --: | ------------: | --------------: | :---: | :-----------------------: | ----------------------------------- | ----------------: | ----------: | --------------------- | ------------------------ |
| **DeletedUsers**           | 394 |             1 |               0 |   1   |        search only        | shared `ConfirmDialog`              |                 5 |           1 | none                  | table + confirm + paging |
| **OrganizationManagement** | 425 |             3 |               0 |   1   | shared `OrganizationForm` | shared `Modal` ×2 + `ConfirmDialog` |                 5 |           4 | none                  | table + confirm          |
| **RecycleBin**             | 465 |            12 |              15 |   1   |           none            | **local** `ConfirmDialog`           |                 3 |           2 | none                  | table + confirm          |
| **Dashboard**              | 537 |             1 |              26 |   –   |        search only        | shared `Modal`                      |                 0 |           0 | none                  | card grid                |
| **SecurityReports**        | 622 |            17 |               4 |   –   |      search + filter      | **local** `ConfirmDialog`           | 4 + blob download |           2 | `SecurityReports.css` | card grid + tabs         |
| **EmailDomainRules**       | 627 |            45 |              16 |   1   |       2 real forms        | shared `ConfirmDialog`              |                 6 | route-level | none                  | table + forms + paging   |

Two facts from the design system decided the ranking as much as the numbers did:

- **`CcurePagination`'s own docstring names `DeletedUsers` and
  `EmailDomainRules` by name**, as pages doing this by hand — the same signal
  `CcureScanStatus` gave for ArchivedScans at the last checkpoint.
- **`RecycleBin` and `SecurityReports` contain byte-identical copies of the same
  local `ConfirmDialog`**, a third implementation of the shared one in
  `components/common/`. Three implementations of one dialog, all with the same
  three defects.

## 2. Selected batch and rationale

**RecycleBin, DeletedUsers, OrganizationManagement, EmailDomainRules — four pages.**

They are one shape: _data table + permission-gated row actions + destructive
confirmation_. That matters more than the LOC spread, because migrating them
together means one decision about tables, pagination, confirmations and row-action
naming applied four times, rather than four decisions that drift. Every primitive
they need — `CcureTable`, `CcurePagination`, `CcureInput`, `CcureSelect`,
`CcureBadge`, `CcureAlert`, `CcureButton`, `CcureLoader`, `CcureEmptyState` — is
already approved and exercised.

Specifically:

- **RecycleBin** is ArchivedScans' twin: same `getScans` source, same table, same
  `STATUS_STYLE[status] || STATUS_STYLE.running` defect. Leaving it behind would
  have left two twin pages rendering differently, which is itself a defect.
- **DeletedUsers** is the cleanest page in Group A (1 inline style, 0 colour
  literals) and is a straight substitution.
- **OrganizationManagement** is migrated _page-only_: the shared `Modal` and
  `OrganizationForm` are out of scope (§8), which keeps blast radius at zero.
- **EmailDomainRules** carries the highest inline-style density in Group A, but
  the complexity is _volume of one trivial transformation_, not architecture —
  and it holds a genuine dark-theme security defect (§9).

## 3. Pages NOT selected, and why

- **Dashboard** — thirteen scan templates each carry a hardcoded `bg`/`color`
  pastel pair driving an icon tint. Migrating it means designing a thirteen-entry
  accent token family: new design-system architecture, which this batch's rules
  exclude. It is also the post-login landing page, the widest blast radius in
  Group A.
- **SecurityReports** — its tab bar is `<div onClick>` with inline styles: not
  keyboard reachable, no `role="tab"`, no `aria-selected`. Fixing it properly
  means adopting `CcureTabs`, which nothing in the application uses yet. First
  use of a primitive belongs in a batch where it is the subject, not a fifth
  page. It also owns a stylesheet and a blob-download path with its own
  `Content-Disposition` parsing.

Both are a _different shape_ from this batch's four. Grouping them in would have
been throughput, not safety.

## 4. Baseline metrics

| Page                   | LOC | Inline styles | Colour literals in rendered markup |
| ---------------------- | --: | ------------: | ---------------------------------: |
| RecycleBin             | 465 |            12 |                                 15 |
| DeletedUsers           | 394 |             1 |                                  0 |
| OrganizationManagement | 425 |             3 |                                  0 |
| EmailDomainRules       | 627 |            45 |                                 16 |

Measured on the live rendered surface, both themes, across the four pages:
**170 inline-styled elements, 32 duplicate button accessible names, 0 table
captions, 0 scoped column headers, 0 row headers.**

Full suite before the batch: **510 tests, 510 passing** (the corrected
ArchivedScans baseline).

## 5. Baseline tests

Written against the **unmigrated** pages and run before any page was touched.

| File                                          |   Tests |    Pass |   Fail |
| --------------------------------------------- | ------: | ------: | -----: |
| `pages/RecycleBin.test.jsx`                   |      45 |      30 |     15 |
| `pages/admin/DeletedUsers.test.jsx`           |      49 |      37 |     12 |
| `pages/admin/OrganizationManagement.test.jsx` |      42 |      32 |     10 |
| `pages/admin/EmailDomainRules.test.jsx`       |      42 |      29 |     13 |
| **total**                                     | **178** | **128** | **50** |

Full suite at the baseline: **688 tests, 638 passed, 50 failed** — every failure
one of the 50 above, all accessibility or rendered-surface.

### Assertions of mine that were wrong, corrected before migration

Four, each documented at the site:

1. **`/3 deleted users/i` matched twice** — the pagination summary also reads
   "of 3 deleted users". Scoped to `.page-subtitle`, which is what the assertion
   was about.
2. **`"Acme Corp"` matched two rows** — two fixtures share org 7. Scoped to a
   row, and the second organisation asserted separately. Stricter, not looser.
3. **"does not report an unrecognised status as running" checked only the text.**
   The pre-migration page renders the raw word `queued` _in the running style_,
   so the assertion passed while leaving the defect untouched. Replaced with a
   comparison against a genuinely-running control row, which means the same thing
   on both sides of the migration and fails on the control.
4. Same again for the true-unknown case, plus a third assertion that an
   unrecognised status is named "Unknown" rather than invented.

Later, queries anchored on bare verbs (`/^restore$/i`, `/delete permanently/i`)
stopped matching once the migration gave each row's controls a distinct
accessible name — which is precisely what the "disambiguates" assertions demand.
They were re-anchored **per row**, and the page-wide uniqueness check kept as its
own assertion. That is a tightening: the row scope does the disambiguation the
bare verb used to rely on.

**No assertion was weakened to make the migration pass.**

## 6. Functional and security contracts

Preserved byte-for-byte on all four pages. The ones that carry real consequence:

**RecycleBin**

- `getScans(0, 200, "deleted")` — the scope argument is load-bearing; `getScans`
  defaults to `scope="active"`, so losing it lists **live** scans on a page whose
  second button purges them.
- `scans:restore` and `scans:purge` stay **separate** permissions, checked at
  render _and_ inside the handler. A user who may undo a deletion is not thereby
  a user who may make one permanent.
- Purge requires an explicit confirmation naming the scan; restore deliberately
  does not — it is the reversible direction.

**DeletedUsers**

- `listUsers({ skip: 0, limit: 100, scope: "deleted" })`.
- Organisations are requested **only** for a superadmin, decided from
  `currentUser.role.name` — an object, not a string — and that value stays in
  `loadData`'s dependency list, so a pre-hydration render retries.
- The restore confirmation still states that a restored account **stays
  inactive**. The backend enforces it; this wording is the only thing telling an
  administrator that restoring is not re-enabling.

**OrganizationManagement**

- Four distinct authorisations, and delete is a **conjunction**: superadmin
  **and** `organizations:delete`. A permission alone would let an org_admin who
  held it delete another tenant.
- `canManageOrg` still restricts an org_admin to their own organisation.
- `changeOrganizationStatus(id, { is_active: !org.is_active })` sends the
  inverted value, never a literal.

**EmailDomainRules**

- "ALLOW always wins" is still stated on the page.
- Both opposite removal warnings are preserved — removing an ALLOW can _start_
  blocking a domain; removing a DENY does not necessarily unblock one.
- The post-removal message still reports what the domain does _now_.
- `flag` mode is still distinguished from a refusal in the lookup result.
- `reason: undefined` rather than `""` on create; 400 ms search debounce;
  `skip: page * 25`.

No API call, payload, query parameter, navigation, error path or business rule
changed on any of the four. No backend change.

## 7. Defects discovered

**Reported by the page implementations (fixed):**

1. **`STATUS_STYLE[status] || STATUS_STYLE.running`** (RecycleBin) — any status
   the local map does not carry, `queued` and `pending` included, was painted as
   a scan _in progress_. A false statement about a scan on a page reporting what
   happened to it. Now `CcureScanStatus`, which names an unknown status
   "Unknown" and keeps the raw value in the title.
2. **`VERDICT_STYLE[verdict] || VERDICT_STYLE.deny`** (EmailDomainRules) — the
   same shape one page over: an unrecognised verdict was labelled **DENY**, which
   on that page is a claim that a domain is blocked. Now neutral "UNKNOWN".
3. **Three implementations of one confirmation dialog** — the shared one plus
   byte-identical local copies in RecycleBin and SecurityReports — all placing
   focus without trapping it, none restoring it, none describing the dialog
   beyond its title. On a dialog whose confirm button purges a scan, deletes a
   tenant or removes an account, the warning _is_ the content.
4. **Zero table captions, zero `scope` attributes, zero row headers** across all
   four pages.
5. **32 duplicate button accessible names** — "Restore", "Delete permanently",
   "Set deny", "Remove" repeated per row with nothing to tell the rows apart.
6. **No loading announcement, no assertive error announcement** on any of the
   four.
7. **The empty-corpus warning was colour-only and unannounced** — see §9.
8. **`.page-inner` was absent from EmailDomainRules entirely**; its root was an
   inline-styled `<div>`.

**Reported by the instrument (harness defects, §11):** four, each of which
produced a plausible wrong answer before it was caught.

## 8. Migration changes by page

Architecture used throughout: UX4G tokens → CCure semantic tokens → CCure
primitives → CCure security patterns → page. No `ux4g-*` class, no direct UX4G
import, no UX4G runtime, no new dependency.

| Page                   | LOC before → after | Inline styles | Colour literals |
| ---------------------- | ------------------ | ------------- | --------------- |
| RecycleBin             | 465 → 342          | 12 → 0        | 15 → 0          |
| DeletedUsers           | 394 → 423          | 1 → 0         | 0 → 0           |
| OrganizationManagement | 425 → 470          | 3 → 0         | 0 → 0           |
| EmailDomainRules       | 627 → 553          | 45 → 0        | 16 → 0          |

DeletedUsers and OrganizationManagement grew: declared table columns and
per-row accessible names cost lines that hand-written `<td>`s did not.

- **RecycleBin** — local `STATUS_STYLE`/`StatusBadge` and local `ConfirmDialog`
  deleted; `CcureTable`, `CcureScanStatus`, `CcureBadge`, `CcureButton`,
  `CcureAlert`, `CcureLoader`, `CcureEmptyState`, `CcureConfirmDialog`. New
  `recycle-bin.css` (62 lines, 7 rules), mirroring `archived-scans.css`
  deliberately — the divergence between the twins was the defect.
- **DeletedUsers** — `CcureTable` + `CcurePagination` + `CcureInput`;
  `.card--admin-table` replaced by a token-built `.du-panel`. New
  `deleted-users.css` (99 lines, 13 rules).
- **OrganizationManagement** — table, badges, buttons, alert and loader
  migrated; **`Modal` and `OrganizationForm` untouched**. New
  `organization-management.css` (53 lines, 6 rules).
- **EmailDomainRules** — 45 inline style objects to zero; both forms rebuilt on
  `CcureInput`/`CcureSelect` with real labels and `aria-labelledby` on each
  form; corpus banner to `CcureAlert`; verdict pill to `CcureBadge`; table to
  `CcureTable` + `CcurePagination`. New `email-domain-rules.css` (161 lines,
  24 rules).

### The one design-system addition, and why

**`CcureConfirmDialog`** (`design-system/patterns/`, 123 lines) — composition of
`CcureModal` + `CcureButton` + `CcureAlert`. No new hook, no new token, no new
CSS architecture; `CcureModal` already trapped and restored focus via
`useFocusTrap`.

It is here because **all four pages need one**, and the alternative was a fifth
and sixth copy of a dialog the codebase already had three of. Filed under
`patterns/` rather than `components/` for the reason `CcureScanStatus` is: the
primitive answers _how a dialog behaves_, the pattern answers _what this dialog
is for_.

**One deliberate behavioural change, flagged rather than slipped in:** all three
legacy implementations focused the **confirm** button on open. A dialog that
opens with the destructive action focused turns a stray Enter into a purge.
Initial focus is now **Cancel**, and the overlay no longer dismisses the dialog
by click. Both are asserted.

## 9. Accessibility and contrast results

Measured on the live rendered surface, in **both themes**, with every `rgba()`
composited through its real ancestor chain. Floors 4.5 (normal) / 3.0 (large:
≥24px, or ≥18.66px at weight ≥700).

|                                        |    Control |   Migrated |
| -------------------------------------- | ---------: | ---------: |
| Text elements measured                 |        114 |        166 |
| **Sub-AA on enabled elements**         |     **11** |      **0** |
| Exempt (disabled controls, WCAG 1.4.3) |          2 |          6 |
| Worst enabled value                    | **1.99:1** | **4.55:1** |

### The eleven, and the one that mattered

| Page / theme               | Element                                                     |      Ratio |
| -------------------------- | ----------------------------------------------------------- | ---------: |
| emailDomains / **dark**    | **"⚠ The blocklist is empty — nothing is being screened"** | **2.06:1** |
| recycle / light            | `running` badge                                             |     1.99:1 |
| recycle / light            | `complete` badge                                            |     2.09:1 |
| organizations / light      | `chip--active` "Active"                                     |     2.09:1 |
| organizations / light      | `chip--info` "enterprise"                                   |     2.34:1 |
| organizations / dark       | `chip--inactive` "Inactive"                                 |     2.59:1 |
| organizations / light+dark | `btn--primary` "+ New Organization"                         |     2.77:1 |
| organizations / light      | `chip--inactive` "Inactive"                                 |     4.39:1 |
| recycle / light            | `failed` badge                                              |     3.30:1 |
| recycle / dark             | `failed` badge                                              |     3.57:1 |

The first row is the finding worth the batch. CLAUDE.md records that the email
domain guard **fails open and silently** — an empty corpus screens nothing while
registration keeps working — and that this banner is the one place it becomes
visible. Its `#991b1b` on `rgba(220,38,38,0.08)` was picked for a light surface;
composited over the dark theme it measures **2.06:1**. The sentence telling an
administrator that nothing is being screened was, in dark theme, close to
unreadable. It is now a `CcureAlert` with `role="alert"`, so it is announced as
well as legible.

**The six exempt values are all disabled controls** — a pagination "Previous" on
page 1, an "Add rule" submit with an empty domain field. WCAG 1.4.3 exempts
inactive user-interface components. The probe was changed to _record_ the
disabled state rather than let me assume it: a disabled control's low contrast is
exempt, an enabled one's is a defect, and the colour pair alone cannot tell them
apart.

### Structural accessibility

|                                     | Control | Migrated |
| ----------------------------------- | ------: | -------: |
| Table captions (4 pages × 2 themes) |       0 |        8 |
| All column headers `scope="col"`    |       0 |        8 |
| Row headers (`th[scope="row"]`)     |       0 |       24 |
| Duplicate button accessible names   |      32 |        0 |
| Unnamed buttons                     |       0 |        0 |
| Unlabelled form controls            |       0 |        0 |
| Horizontal overflow                 |    none |     none |

Plus, asserted in the suites: focus trapped in every confirmation dialog, focus
restored to the invoking control on close, Escape closes, each dialog carries an
accessible description as well as a name, loading announced via `role="status"`,
errors announced via `role="alert"`, pagination is a labelled `<nav>` with a live
page-position status, and the lookup result on EmailDomainRules is a polite live
region.

### Carried forward, deliberately not fixed

**`.page-subtitle` measures 4.55:1 in light theme** — clearing AA by 1%. It is
pre-existing, identical before and after, shared by two dozen pages, and belongs
to the shell/AppLayout migration. Per the batch brief it stays documented and
untouched. It is the worst _enabled_ value on the migrated surface, which is why
it appears as "worst" in the table above.

Also out of scope and recorded rather than fixed:

- `components/layout/Modal` (9 consumers) has **no `role="dialog"` and no
  `aria-modal`** at all, and no focus trap. It backs the create/edit dialogs on
  OrganizationManagement. Shared shell.
- `components/common/ConfirmDialog` (now 3 consumers) keeps the same three gaps
  `CcureConfirmDialog` fixes. Shared shell.

## 10. CSS cleanup and consumer evidence

43 legacy classes the four pages stopped using were each searched
repository-wide, checked for substring false positives, and checked for dynamic
`className` construction.

**39 are kept**, because they still have other consumers — `.text-muted` (26),
`.btn` (30), `.muted` (30), `.alert` (23), `.card` (35), `.spinner` (16),
`.table-wrap` (14), `.data-table` (5), `.confirm-*` (3), `.pagination-*` (2–3),
and so on down to `.card--admin-table` (1). _The pages stop using them; they do
not get to remove them._

**4 are deleted from `src/styles/scan.css` (−23 lines)**, and only because the
search proved this batch was their last consumer:

| Selector                                           | Other consumers after this batch | Evidence                     |
| -------------------------------------------------- | -------------------------------: | ---------------------------- |
| `.table-controls`                                  |                                0 | Only definition + this batch |
| `.search-field` (and `.search-field .field-input`) |                                0 | Only definition + this batch |
| `.chip--info`                                      |                                0 | Only definition + this batch |
| `.table-empty-cell`                                |                                0 | Only definition + this batch |

Checked and **kept**: `.search-icon` sits between the two deleted search rules in
the same file and still has 3 consumers. `.chip`, `.chip--active`,
`.chip--inactive` are alive in `components/admin/UserTable.jsx`. The only dynamic
class construction anywhere in `src/` is `cred-section-chip--on` in
`CredentialedScan.jsx`, a different prefix.

`.chip--info` is worth naming: it measured **2.34:1**, so deleting it removes a
sub-AA rule from the codebase rather than merely stopping one page using it.

**Because `scan.css` is shared, everything was re-verified after the deletion** —
full suite, lint, a rebuilt container, the four-page structural diff, and the
five unrelated auth pages. All unchanged.

**A correction:** the header comments I first wrote in `deleted-users.css` and
`organization-management.css` listed these four among classes that "still have
other consumers". That was false. Both comments have been rewritten to state
what was actually deleted and why.

## 11. Regression methodology and results

The deterministic computed-style + geometry instrument from the auth and
ArchivedScans checkpoints, extended to four authenticated routes.
**Pixel hashing was not used as a gate.**

**Control image:** the identical tree with only the four page files reverted to
their pre-batch content. Its build output was **281.04 kB CSS / 1,699.64 kB JS —
byte-identical in size to the approved ArchivedScans checkpoint**, which is
independent confirmation that the control really is the previous baseline.

**Validation before any result was believed:** each container captured twice, in
two independent Chrome processes, requiring byte-identical output. Both sides
passed, for the structural instrument and for the contrast instrument
separately.

### Four harness defects found, each of which produced a plausible wrong answer

1. **The SPA route and its API endpoint share a path** on two of these four
   pages (`/admin/organizations`, `/admin/email-domains`). The _document_
   navigation matched the API stub and was served JSON, so React never mounted —
   and both pages captured as an empty document in **both** containers, which the
   comparison duly reported as **"identical"**. A clean result for two pages that
   had demonstrably changed. Fixed by requiring an `/api/` prefix on every stub.
2. **A fixed post-navigation sleep lost a race** on the first navigation of a
   fresh Chrome, and the losing run recorded a page with nothing on it.
3. **Readiness keyed on `document.body` never settles** — AppLayout's chrome
   updates on a timer, so "the DOM stopped changing" can never become true.
   Scoped to `.page-main`.
4. **`data-theme` is re-asserted by the application after hydration**, and
   whether that write lands before or after the harness's is a race. A losing run
   measures **light** token values while the attribute reads "dark" — caught by
   self-comparison, where the same `btn-label` resolved to 3.75:1 in one run and
   6.96:1 in the next. The theme is now re-asserted and verified against a token
   that actually differs between themes, and a run whose theme cannot be
   confirmed fails rather than reports.

Two further guards were added as a result: an empty page is now a hard error
rather than a silent result, and readiness keys on a marker string that **both**
implementations render — every class-based signal tried existed on only one side
(`.spinner` vs `.cc-loader`; `.page-inner`, which the pre-migration
EmailDomainRules does not have at all).

One further note: a run of 69 orphaned Chrome processes from repeated captures
starved the containers and produced a page that never mounted. Same shape as the
process contention seen in the auth batch — an environment artefact, not a code
defect, confirmed by a clean re-run.

### Results (both themes, all four pages)

|                                       | Control | Migrated |
| ------------------------------------- | ------: | -------: |
| Inline-styled elements                |     170 |    **0** |
| Duplicate button names                |      32 |    **0** |
| Table captions                        |       0 |    **8** |
| Fully scoped header rows              |       0 |    **8** |
| Row headers                           |       0 |   **24** |
| Unnamed buttons / unlabelled controls |   0 / 0 |    0 / 0 |
| Horizontal overflow                   |       0 |        0 |

All four pages CHANGED in the intended direction, **identically in light and
dark**. Row counts, header counts and body-row counts are unchanged where the
data is unchanged.

**No unrelated page changed:** the five auth pages captured **5/5 identical**
between control and migrated, with the container port excluded from the
comparison — the field whose inclusion made the auth batch's first such run
report all five as changed. Re-verified a second time _after_ the `scan.css`
deletion: still 5/5 identical.

## 12. Security, CSP and air-gap results

| Gate                                                     | Result                                                                                     |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| CSP                                                      | **byte-identical** — `Frontend/nginx.conf` not modified                                    |
| Security headers                                         | unchanged                                                                                  |
| External runtime origins                                 | **0** — 31 requests, all to the container origin                                           |
| UX4G runtime markers in `dist/`                          | **0**                                                                                      |
| `ux4g-*` classes in application code                     | **0** (one grep hit is a comment stating there are none)                                   |
| Direct UX4G imports from pages/components                | **0**                                                                                      |
| Analytics / telemetry added                              | none                                                                                       |
| Backend / API / routing / authorization changes          | none                                                                                       |
| Token or credential handling                             | not touched; `OrganizationForm`'s password provisioning deliberately out of scope          |
| New runtime dependency                                   | **none** — the `package.json` diff is Phase 2's approved `ux4g-web-components` + `wawoff2` |
| nginx / Docker / PreferencesContext / theme architecture | not modified                                                                               |
| `prefers-color-scheme` introduced                        | no — `data-theme` only                                                                     |

`scripts/host-nginx/nginx-host.conf` and `Backend/core/tasks.py` appear modified
in `git status`; both were already modified before this session began and neither
is mine.

## 13. Full test results

**688 tests, 688 passing, 23 files.** Lint clean at `--max-warnings=0`.
Production build green.

| File                                          |        Tests |
| --------------------------------------------- | -----------: |
| `pages/admin/DeletedUsers.test.jsx`           | **49** (new) |
| `pages/RecycleBin.test.jsx`                   | **45** (new) |
| `pages/admin/OrganizationManagement.test.jsx` | **42** (new) |
| `pages/admin/EmailDomainRules.test.jsx`       | **42** (new) |
| `pages/ArchivedScans.test.jsx`                |           40 |
| `design-system/contrast.test.js`              |           72 |
| `design-system/primitives.test.jsx`           |           53 |
| _(remaining 15 files)_                        |          345 |

All 50 baseline failures are green. Nothing regressed: the 638 assertions that
passed before the migration all still pass. Re-run in full **after** the
`scan.css` deletion — still 688/688.

## 14. Bundle impact

Against the previous approved checkpoint (ArchivedScans):

|          |      Before |       After |            Δ |
| -------- | ----------: | ----------: | -----------: |
| CSS raw  |   281.04 kB |   284.29 kB | **+3.25 kB** |
| CSS gzip |    47.90 kB |    48.43 kB | **+0.53 kB** |
| JS raw   | 1,699.64 kB | 1,695.02 kB | **−4.62 kB** |
| JS gzip  |   422.19 kB |   422.36 kB | **+0.17 kB** |

CSS grew by four page stylesheets (375 lines, 50 rules) less the 23 lines removed
from `scan.css`. JS shrank despite gaining `CcureConfirmDialog`, because two
local `ConfirmDialog` implementations, a `STATUS_STYLE` map, a `StatusBadge`, a
`VerdictPill` and 61 inline style objects went away. The gzip deltas are
fractions of a percent and are not treated as signal.

| Metric                                | Δ                                                                                                        |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Page LOC                              | 1,911 → 1,788 (**−123**)                                                                                 |
| Inline styles                         | 61 → **0**                                                                                               |
| Colour literals in rendered markup    | 31 → **0**                                                                                               |
| Legacy primitives used by these pages | `Button`, `ConfirmDialog`, `EmptyState`, `Loader` → none (`Modal`/`OrganizationForm` retained by design) |
| CSS deleted                           | 23 lines, 4 selectors                                                                                    |
| CSS added                             | 375 lines, 50 rules                                                                                      |
| Tests added                           | **178**                                                                                                  |

## 15. Files changed

**Modified (5)**

- `src/pages/RecycleBin.jsx` 465 → 342
- `src/pages/admin/DeletedUsers.jsx` 394 → 423
- `src/pages/admin/OrganizationManagement.jsx` 425 → 470
- `src/pages/admin/EmailDomainRules.jsx` 627 → 553
- `src/styles/scan.css` 3,634 → 3,611 (4 dead selectors removed)
- `src/design-system/index.js` (+1 export)

**Added (9)**

- `src/design-system/patterns/CcureConfirmDialog.jsx` (123)
- `src/styles/recycle-bin.css` (62) · `deleted-users.css` (99) ·
  `organization-management.css` (53) · `email-domain-rules.css` (161)
- `src/__tests__/pages/RecycleBin.test.jsx` (611) ·
  `admin/DeletedUsers.test.jsx` (622) ·
  `admin/OrganizationManagement.test.jsx` (589) ·
  `admin/EmailDomainRules.test.jsx` (619)

**Also corrected:** `docs/ux4g/03c-archived-scans.md` §12 (see §0).

Not touched: any backend file, `nginx.conf`, `Dockerfile`, `docker-compose.yml`,
`PreferencesContext`, the theme architecture, `components/layout/Modal`,
`components/admin/OrganizationForm`, `components/common/*`, `AppLayout`, and
every page outside the batch.

## 16. Engineering release gate

| Gate                                  | Result                                            |
| ------------------------------------- | ------------------------------------------------- |
| Full test suite                       | **688/688**                                       |
| Lint `--max-warnings=0`               | clean                                             |
| Production build                      | green                                             |
| Design-system tests                   | pass                                              |
| Contrast tests                        | pass                                              |
| Page-specific tests                   | 178/178                                           |
| Regression instrument self-comparison | identical, both containers, both instruments      |
| Both themes verified                  | yes                                               |
| No unrelated page changed             | 5/5 identical, re-verified after the CSS deletion |
| Sub-AA introduced by this batch       | **0**                                             |
| CSP byte-identical                    | yes                                               |
| Air-gap                               | clean                                             |
| New dependency                        | none                                              |

**PASS.**

## 17. Legal / licence gate

**OPEN.** Unchanged by this batch and not claimed closed. The UX4G licensing and
attribution question raised at Phase 2 remains outstanding; nothing here depends
on its resolution, and nothing here resolves it.

## 18. Recommendation

**GO.**

Four pages migrated, 178 assertions added, 50 baseline accessibility failures
closed, 11 measured sub-AA values eliminated with none introduced, 170 inline
styles and 32 duplicate control names removed, 4 provably dead selectors deleted
with consumer evidence, no unrelated page changed, no dependency added, CSP and
air-gap intact.

Two things a reviewer should weigh explicitly rather than take on trust:

1. **`CcureConfirmDialog` is a design-system addition**, which this batch's rules
   discouraged. The justification is in §8: four of four pages needed one, the
   alternative was a fifth copy of a dialog that already existed three times, and
   it composes two approved primitives without new tokens, hooks or CSS
   architecture. It also carries one deliberate behavioural change — initial
   focus moves from the destructive button to Cancel.
2. **Four selectors were deleted from a shared stylesheet.** Evidence is in §10
   and everything was re-verified afterwards, but it is the one change in this
   batch that reaches beyond the four pages.

Stopping here. No second batch started, and Group B/C/D, AppLayout, Dashboard and
SecurityReports are untouched.
