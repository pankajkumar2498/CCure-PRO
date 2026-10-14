# Checkpoint 3C — Batch 9: the credential pages

**Status: complete, awaiting review.**

|                 |                                                                             |
| --------------- | --------------------------------------------------------------------------- |
| Pages           | `src/pages/scan/ScanCredentials.jsx`, `src/pages/scan/CredentialedScan.jsx` |
| Routes          | `/scan-credentials`, `/scan/credentialed`                                   |
| New tests       | 79 (42 + 37), all passing                                                   |
| Full suite      | **1,002 passed / 1,002**, 31 files                                          |
| Lint            | `eslint src --max-warnings=0` — **clean**                                   |
| Build           | production build succeeds; Docker image builds and serves                   |
| Contrast        | 270 measurements, **0 sub-AA** (was 28 sub-AA over 184)                     |
| Unrelated pages | 37 states across 16 pages — **all identical**                               |
| Air-gap         | 13 requests, **0 external origins**                                         |
| CSP             | unchanged                                                                   |

Harness work is documented separately in
[`03c-batch9-harness.md`](03c-batch9-harness.md). **Two instrument defects were
found during this batch, both of which would have produced a clean result for a
build that had demonstrably changed.** That document should be read first,
because it is what licenses the numbers in this one.

---

## 1. Why these two, and why not a third

The accelerated batch-sizing rule targets 2–3 security-sensitive pages. The
proposed batch was `ConfigurationChecks + ScanCredentials + CredentialedScan`,
with the instruction to split if the contracts are materially different.

`ScanCredentials` and `CredentialedScan` belong together: both handle
credentials, and putting them in one batch is what surfaced the most useful
finding in it — that they need **opposite** answers to the same question
(§6). `ConfigurationChecks` was excluded: it has no credential contract, and
combining it would have been combining pages to hit a number, which the brief
forbids.

Two pages, one subject.

---

## 2. Baseline metrics

|                          | ScanCredentials | CredentialedScan |
| ------------------------ | --------------- | ---------------- |
| LOC before → after       | 550 → 534       | 604 → 598        |
| Inline `style={{…}}`     | 44 → **0**      | 19 → **0**       |
| Colour literals          | 24 → **0**      | 5 → **0**        |
| Baseline tests pass/fail | 32 / 10         | 28 / 9           |
| After migration          | **42 / 42**     | **37 / 37**      |

Both suites were written against the **unmigrated** page. The failing set is the
migration specification; the passing set is the regression gate.

Both mock `axiosInstance` rather than the API module, so the **real** `toPayload`
and the **real** `parseTargets` and payload builder run. Mocking the API module
would have made every payload assertion a test of the mock.

---

## 3. Dispatch and API contract — verified unchanged

Pinned by test, not by inspection.

### `CredentialedScan` → `POST /scan/credentialed`

- Endpoint and method unchanged; **exactly one** POST per dispatch, to that path
  and nowhere else.
- Payload keys asserted as an exact sorted set:
  `auth_method, credential_id, key_path, os_type, password, port, sections,
targets, username`.
- `parseTargets` splitting on `/[\s,;]+/` — `"10.0.0.5, 10.0.0.6 10.0.0.7;10.0.0.8"`
  → four expressions.
- `sections: null` when all are selected; explicit list when any is deselected.
- `port` coerced with `parseInt(port, 10) || 22`.
- JIT vs stored remain mutually exclusive: stored sends `credential_id` and no
  secret; JIT sends the secret and no id.
- `password` only for password auth, `key_path` only for key auth.
- Navigation target `/scan/credentialed/results?scan_id=…` unchanged; no
  navigation when the API reports failure.
- **No retry** — a rejected dispatch produces exactly one POST after 120 s of
  advanced timers.
- **No polling** — 120 s of advanced timers issues nothing.

### `ScanCredentials` → `/credentials*`

`toPayload` is untouched and still: omits `password`/`private_key` unless truthy
("leave unchanged"), deletes `credential_type` on update (create-only), maps
`domain` to `form.domain || null`, and coerces `port` to `Number(port)` or null.

### Authorization

`can(user, "scans", "execute")` still gates dispatch. Nothing is dispatched
without it. **The UI gate fires before the handler** — the form renders
non-editable — which is why the permission test asserts "dispatches nothing, by
whatever means" plus a separate non-editability assertion, rather than driving a
form it cannot type into. That is the gate working, not a defect; the original
assertion was written against a mechanism the page does not use.

**No backend, API, business-logic, scan-behaviour or credential-handling code
was modified in this batch.**

---

## 4. Credential handling — verified unchanged

The page header's claim — _"Credentials are NEVER stored — cleared from state
immediately after use"_ — is now asserted:

- the secret is cleared from React state after a successful dispatch;
- the secret never appears in DOM text, an `aria-label`, a `title` or a
  `placeholder`;
- the secret never appears in the request URL;
- the secret is not written to `console.error` when the dispatch fails.

`ScanCredentials`' own claim — _"A secret goes in and never comes back out"_ —
is why it gets the opposite reveal decision in §6.

---

## 5. Accessibility — what changed

Seven of the nine failing `CredentialedScan` assertions were accessibility
defects. All are fixed; two of the nine (inline styles, colour literals) were
satisfied by the styling work.

| Defect                                | Before                                        | After                                       |
| ------------------------------------- | --------------------------------------------- | ------------------------------------------- |
| Unnamed form controls                 | 5 (JIT), 4 (stored)                           | 0                                           |
| Unnamed control on the validate panel | 1                                             | 0                                           |
| Heading structure                     | `H3, H3, H3` — no `h1` at all                 | `H1 > H2, H2, H2`                           |
| Dispatch error announcement           | plain `<div>`                                 | `role="alert"` (CcureAlert `danger`)        |
| Running-scan announcement             | plain `<p>`                                   | `role="status"` (CcureAlert `info`)         |
| Dispatch control busy state           | none                                          | `aria-busy="true"` while loading            |
| Permission refusal                    | disabled control only                         | stated in text                              |
| Reveal toggle name / state            | none                                          | `aria-label` + `aria-pressed`               |
| Per-row action buttons                | 6 duplicate names                             | 0 — named per credential                    |
| Table semantics                       | no caption, no scoped headers, no row headers | caption, `scope="col"` ×6, `scope="row"` ×3 |

Measured across 8 states × 2 themes: **inline styles 390 → 0, duplicate button
names 36 → 0, unlabelled controls 40 → 0, table captions 0 → 6, scoped headers
0 → 6, row headers 0 → 18, horizontal overflows 0 → 0.**

`AppLayout` never rendered a page title: `<AppLayout pageTitle="Credentialed
Scan">` passed a prop the component does not read (`AppLayout({ children,
saveStatus, onNewScan })`). The page had no `h1`. It now renders its own, as
`ScanCredentials` and every other migrated page do, and the ignored prop is
gone.

### Three intentional behaviour changes

These are **behaviour changes, not preservation**, and are called out rather
than folded into "accessibility improvements":

1. **The collection checkboxes were `display: none`.** That removed them from
   the accessibility tree _and_ from the tab order — a keyboard user could not
   choose what the scan collects. They are now clipped
   (`.cs-visually-hidden`): still focusable, still announced, still operable.
   `.cs-chip:focus-within` gives the chip a visible focus ring, since the
   control that receives focus is invisible.
2. **The reveal toggle was `tabIndex={-1}`.** The only control that reveals a
   mistyped password was unreachable by keyboard. Removed.
3. **The two credential-source radios shared no `name`.** They are now a
   `<fieldset>` with a `<legend>` and a shared `name`, so they are announced as
   one choice and the arrow keys move between them. Previously each was an
   island held mutually exclusive only by React's `checked`.

---

## 6. The reveal-toggle finding

The two pages were migrated together, and the most useful thing that came out of
it is that they need **opposite** answers to the same question.

- **`ScanCredentials` deliberately does NOT use `CcurePasswordField`, and has no
  reveal control.** The server never returns the secret — the page's own API
  module says so in its header — so there is nothing to reveal. A field that
  _could_ display one is how a stored password reaches the DOM and the browser
  autofill store. It uses `CcureInput type="password"`.
- **`CredentialedScan` legitimately HAS one.** The operator is typing a secret
  _now_, not reading a stored one back, and a mistyped credential against a real
  host costs a failed logon that can trip an account lockout.

It is still not `CcurePasswordField` there either: that pattern also owns a
**strength meter**, which would grade a credential the operator does not own and
cannot change. It is an ordinary `CcureInput` with the toggle in the
`adornment` slot, which keeps the input's own `id`, label association and
`aria-describedby` wiring — an adorned field and a plain one are the same field
to assistive technology.

---

## 7. Contrast — before → after

Measured on the built containers, both themes, all 8 states, every `rgba()`
composited through its real ancestor chain. Floors 4.5 (normal) / 3.0 (large).

|              | Pre-migration                                           | Post-migration            |
| ------------ | ------------------------------------------------------- | ------------------------- |
| Measurements | 184                                                     | 270                       |
| Sub-AA       | **28**                                                  | **0**                     |
| Worst        | **1.44:1** — `pass-toggle` "👁", `#000000` on `#1e293b` | 4.55:1 — `.page-subtitle` |

More measurements after migration because more text renders (hints, labels,
alert bodies) — not because the probe changed floors.

The pre-migration failures were a light-theme palette on a page that renders in
whichever theme the account chose: the reveal glyph was effectively **invisible
in dark theme** (1.44:1), the page lede was 2.36:1, the "New credential" button
label 2.77:1, and the Windows beta warning 2.55:1.

The remaining worst case, 4.55:1, is `.page-subtitle` in light theme. It is
**above** the floor, and per the standing instruction it is a shell/AppLayout
issue and must not be fixed inside individual pages.

### One contrast defect this migration introduced, and fixed

The first contrast run flagged 4 sub-AA at 4:1 — the "Vulnerability Audit" link
inside the scope panel. `--ccure-text-link` is tuned for the page surface, not
for a tinted alert surface. Measured on the built container:

| Token                       | on info surface | on page surface |
| --------------------------- | --------------- | --------------- |
| `--ccure-text-link` (dark)  | **4:1**         | 7.59:1          |
| `--ccure-info-text` (dark)  | 7.36:1          | 13.97:1         |
| `--ccure-info-text` (light) | 5.82:1          | 6.1:1           |

Fixed with `.cs-scope .cs-linkbtn { color: var(--ccure-info-text) }` — scoped by
**this page's own class**, not by the alert's internal class name, so the page
does not depend on a design-system internal. Re-measured: 0 sub-AA. The
instrument confirmed the only property that changed between the two builds was
that one colour.

---

## 8. CSS changes and consumer evidence

### New, page-owned

| File                               | Lines |
| ---------------------------------- | ----- |
| `src/styles/scan-credentials.css`  | 146   |
| `src/styles/credentialed-scan.css` | 344   |

All 64 top-level selectors are prefixed `.sc-` or `.cs-` (21 + 43). **No element
selector, no `:root`, no global rule** — verified statically, so neither file
can reach another page.

### Deleted from shared stylesheets — 33 rules, 3,037 bytes

A census before the rewrite found `CredentialedScan.jsx` to be the **sole JSX
consumer of all 21** `cred-*` / `csc-*` / `pass-*` classes. After migration all
21 have zero consumers.

| File                   | Rules removed |
| ---------------------- | ------------- |
| `src/styles/scan.css`  | 25            |
| `src/styles/admin.css` | 8             |

These were not merely unused, they were **wrong**: `.cred-section` drew its
divider in `#f1f5f9` and `.cred-auth-btn--active` its shadow in
`rgba(0,0,0,.08)` — light-theme literals in a shared sheet.

Removal was done **by rule, never by line range**, and only where _every_
selector in the rule names a dead class, so a rule that also styles something
still in use is left alone. That is what makes it safe against two globally
imported stylesheets. An assertion confirms none of the dead classes survives
inside an `@media` block.

**The prune was proven inert by measurement, not by argument**: the full
unrelated-page regression was re-run afterwards (37 states, 16 pages — all
identical) and all 16 batch-9 states were identical to the pre-prune build.

### Kept

- `.field-input` (5 consumers), `.field-label` (3), `.alert` (42), `.btn` (28),
  `.muted` (29) — still shared.
- **`.cred-callout*` (9 rules in `scan.css`) is NOT deleted.** It had zero
  consumers _before_ this batch. That is unrelated cleanup and belongs to
  whoever owns that decision. Reported, not actioned.
- `.btn-link` — the page named it and **no stylesheet in the repository ever
  defined it.** Dropping it changes nothing visually. Replaced by `.cs-linkbtn`.

---

## 9. Unrelated-page regression

Pre-batch-9 and post-batch-9 containers, built from the same tree apart from
this batch's four files, captured with the already-validated batch 5–8 / auth /
gated harnesses **unchanged**.

| Harness   | Pages                                                              | States | Result            |
| --------- | ------------------------------------------------------------------ | ------ | ----------------- |
| auth      | Login, Register, ResetPassword, VerifyEmail, ForgotPassword        | 5      | identical         |
| batch 5   | RecycleBin, DeletedUsers, OrganizationManagement, EmailDomainRules | 8      | identical         |
| batch 6   | WebDashboard, ScanList, FindingsExplorer, AssetInventory           | 8      | identical         |
| batch 7   | NewWebScan                                                         | 4      | identical         |
| batch 8   | ScanDetail (5 lifecycle states)                                    | 10     | identical         |
| gated     | ArchivedScans                                                      | 2      | identical         |
| **Total** | **16 pages**                                                       | **37** | **0 differences** |

Run twice — before and after the CSS prune — with the same result.

**Coverage gap, stated plainly:** `RoleManagement` has no capture route in any
harness. That gap predates this batch. The auth harness measures its five pages
at one theme each, not two.

---

## 10. CSP, security and air-gap

- **CSP unchanged.** `Frontend/nginx.conf` is unmodified — `git diff HEAD`
  reports no change. (The on-disk SHA differs from the blob only by CRLF
  normalisation on checkout; content-identical, confirmed after `tr -d '\r'`.)
  The header served by both containers is byte-identical and present.
- **Air-gap intact.** 13 requests originated by the two pages, every one to the
  page's own origin, **zero external origins**.
- Neither page nor stylesheet introduces any URL.
- No CDN, no Google Fonts, no analytics, no external runtime asset.
- No `ux4g-*` class in application JSX; no `.ux4g-*` selector in application
  CSS; only `src/design-system/` imports `ux4g-web-components`; UX4G's
  `UX4G.js` runtime remains rejected.
- `PreferencesContext` / `preferences.theme` / `data-theme` remains the only
  theme mechanism. No `prefers-color-scheme` was introduced.

---

## 11. Bundle impact

|          | Batch 8     | Batch 9     | Δ            |
| -------- | ----------- | ----------- | ------------ |
| CSS raw  | 292.00 kB   | 295.78 kB   | +3.78 kB     |
| CSS gzip | 49.69 kB    | 50.29 kB    | +0.60 kB     |
| JS raw   | 1,676.79 kB | 1,674.34 kB | **−2.45 kB** |
| JS gzip  | 420.87 kB   | 421.17 kB   | +0.30 kB     |

Before the shared-stylesheet prune the CSS was 298.16 kB / 50.68 kB; the prune
reclaimed 2.38 kB raw, 0.39 kB gzip.

---

## 12. Files changed

**Migrated**

- `src/pages/scan/ScanCredentials.jsx` (550 → 534)
- `src/pages/scan/CredentialedScan.jsx` (604 → 598)

**Added**

- `src/styles/scan-credentials.css` (146)
- `src/styles/credentialed-scan.css` (344)
- `src/__tests__/pages/scan/ScanCredentials.test.jsx` (42 tests)
- `src/__tests__/pages/scan/CredentialedScan.test.jsx` (37 tests)

**Pruned**

- `src/styles/scan.css` (−25 rules)
- `src/styles/admin.css` (−8 rules)

**Lint fixes to test files written in earlier batches** — see §14.

**Not touched:** any backend file, any API module, any design-system component
or pattern, `nginx.conf`, `AppLayout`, `Toast`, `useScanPolling`.

---

## 13. Out-of-scope technical debt

Not fixed. Recorded per the standing rule that a functional defect found during
migration is classified, never silently repaired.

### 13.1 `ScanCredentials` toast calls have never worked — **user-visible, and worse than a missing toast**

`Toast.jsx` exports `useToasts()` returning `{ toasts, push, dismiss }` and
`ToastContainer({ toasts, dismiss })`. `ScanCredentials` destructures
`{ toasts, addToast, removeToast }` and passes `removeToast=`. **Both are
`undefined`.** Every toast call on the page throws `TypeError`.

**Pre-existing, and unchanged by this batch.** `Toast.jsx` is unmodified from
`HEAD`; `HEAD`'s `ScanCredentials.jsx` already carried the wrong names; and
`load`, `save` and `doDelete` are **byte-identical to `HEAD`** — verified by
diffing each function. Nine other pages use the correct
`{ toasts, push: pushToast, dismiss: dismissToast }` idiom.

The consequences are not cosmetic, because two of the five call sites are
_inside_ a `try`:

- **`save()`** — the success toast throws, the `catch` renders _"Could not save
  the credential."_ on a credential that **was created or updated
  successfully**, and `setEditing(null)` / `load()` never run. The modal stays
  open showing an error, so the operator retries — a second POST creating a
  **duplicate credential**.
- **`doDelete()`** — the success toast throws; the `catch` calls `addToast`
  again and throws again, producing an unhandled rejection. The confirm dialog
  stays open on a credential that **was deleted**.
- **`load()`** — a failed list fetch produces an unhandled rejection and no
  message, while `finally` clears the loading flag: the page renders "no
  credentials" for a _failure to fetch_ them.

This surfaces in the test run as `Errors 1` beside `1,002 passed` — an unhandled
rejection, not a failing assertion. **The suite reports 1,002/1,002 and an
error; both facts are true and neither should be quoted without the other.**

Recommended fix (one line, plus the container prop) — not applied here because
it is not migration-caused:
`const { toasts, push: addToast, dismiss: removeToast } = useToasts();`

### 13.2 `CredentialedScan` Windows beta copy contradicts the product

The warning says Windows scanning _"requires OpenSSH Server to be enabled on the
target"_. Per `CLAUDE.md`, WinRM has been the default Windows transport since
Phase 2 and **Windows targets no longer need OpenSSH**; SMB was added in Phase 12. `ScanCredentials`' own lede already says the opposite. Copy only — not
touched, because changing what a security page tells an operator is a product
decision.

### 13.3 `pageTitle` was an ignored prop

`AppLayout` never read it. Removed from `CredentialedScan` as part of giving the
page a real `h1`. Other pages may pass it too; not audited here.

### 13.4 `.cred-callout*` — 9 rules, zero consumers before this batch

Left in `scan.css`. Contains light-theme literals (`#f0fdf4`, `#eff6ff`,
`#bbf7d0`).

### 13.5 `.btn-link` was never defined

Named in the page's JSX, defined in no stylesheet. Now unreferenced.

### 13.6 `.page-subtitle` light-theme contrast 4.55:1

Above the floor, and a shell/AppLayout issue per standing instruction. Not
touched.

---

## 14. A reporting correction

**Lint was not clean at the start of this batch.** `npm run lint --max-warnings=0`
reported **12 errors, 4 of which predate batch 9** — unused `rowOf` helpers in
the RecycleBin, DeletedUsers and EmailDomainRules suites (batch 5) and an unused
`within` import in FindingsExplorer (batch 6). Those checkpoints reported a clean
lint gate; that was either scoped to changed files or simply missed.

All 12 are fixed (dead bindings removed, not renamed to `_`), and
`eslint src --ext .js,.jsx --max-warnings=0` now exits 0 across the whole tree.

**This is now the authoritative lint baseline: 0 errors, whole tree.** Earlier
checkpoints are not reopened and no retrospective fixes are made against them —
the discrepancy is recorded here once, and the current result stands.

---

## 18. Addendum — Stage 1: the §13.1 toast defect, fixed

Approved as a follow-up to this batch and applied as its own change, separate
from any migration work.

**Fix** — two lines in `src/pages/scan/ScanCredentials.jsx`:

```js
const { toasts, push: addToast, dismiss: removeToast } = useToasts();
...
<ToastContainer toasts={toasts} dismiss={removeToast} />
```

Renamed on the way _in_ rather than renamed throughout, so all five call sites
and the `load` / `save` / `doDelete` handlers around them stay byte-identical to
what batch 9 measured. `push` is `useCallback`-stable, so `load`'s `[addToast]`
dependency does not become a re-render loop. Nothing else was touched: no Toast
redesign, no API change, no business logic, no other page.

**8 focused tests added** (suite 42 → 50). They assert the _observable_
behaviour rather than the presence of a toast element, because the observable
behaviour is what a regression would break again: a successful save announces
success, does **not** enter the error path, closes the modal and refreshes the
list; a successful delete closes the confirmation and refreshes; a delete that
orphans a schedule surfaces the API's `note`; a failed list load surfaces the
error rather than rendering as an empty credential list; and clicking a toast
dismisses it.

Each test also watches for unhandled rejections around the action. That matters
because an unhandled rejection is reported by vitest at the **end** of a run and
attributed to a _file_, not a test — which is precisely how this defect survived
a green 1,002-test suite as "1,002 passed, 1 error".

**Sensitivity checked, not assumed.** With the fix reverted, **7 of the 8 new
tests fail** plus the unhandled error returns. The eighth ("reports a failed
save as a failure") passes either way by construction — on the failure path no
toast is reached — so it guards the error path against future regression rather
than detecting this defect.

|                       | Before                       | After                        |
| --------------------- | ---------------------------- | ---------------------------- |
| Full suite            | 1,002 passed, **1 error**    | **1,010 passed, 0 errors**   |
| ScanCredentials suite | 42                           | 50                           |
| Lint                  | 0                            | 0                            |
| CSS bundle            | 295.78 kB / 50.29 kB gzip    | unchanged (same hash)        |
| JS bundle             | 1,674.34 kB / 421.17 kB gzip | 1,674.33 kB / 421.18 kB gzip |

The two `Not implemented: window.alert` / `navigation` lines still present in
the run are jsdom stderr notices — the former is the known ScanDetail debt
(§13 item 6) — not unhandled errors. There is no `Errors` line in the summary
any more.

§13.2 (Windows/OpenSSH copy), §13.3–§13.6 remain open and untouched.

---

## 15. Legal / licence status

**Unchanged and still OPEN.** The README carries an MIT badge, `package.json`
declares no license, there is no LICENSE file, and Noto Sans redistribution is
unconfirmed. Nothing in this batch bears on it, and no legal clearance is
claimed.

---

## 16. Engineering gate

| Check                          | Result                                                      |
| ------------------------------ | ----------------------------------------------------------- |
| New tests pass                 | 79 / 79                                                     |
| Full suite                     | 1,002 / 1,002 (+ 1 pre-existing unhandled rejection, §13.1) |
| Lint `--max-warnings=0`        | clean (12 errors fixed, 4 pre-dating this batch)            |
| Production build               | succeeds                                                    |
| Docker build + serve           | succeeds, HTTP 200                                          |
| Harness determinism            | byte-identical, both containers                             |
| Harness sensitivity            | 3/3 injected changes detected **and named**                 |
| Harness control                | 8 unaffected states identical                               |
| Unrelated-page regression      | 37 states, 16 pages, 0 differences (run twice)              |
| Contrast                       | 270 measured, 0 sub-AA (was 28/184)                         |
| CSP                            | unchanged                                                   |
| Air-gap                        | 0 external origins                                          |
| API / dispatch / authorization | unchanged, pinned by test                                   |
| Credential handling            | unchanged, pinned by test                                   |

No STOP condition was triggered.

---

## 17. Recommendation

Batch 9 is complete and I recommend approval, with three things called out for
an explicit decision rather than assumed:

1. **§13.1 is a real user-visible defect on a credential-management page** —
   it reports failure on success and can drive duplicate credential creation.
   It is pre-existing and I have not touched it. It is a one-line fix and I
   suggest authorising it as its own small change.
2. **The shared-stylesheet prune (33 rules across `scan.css` and `admin.css`)
   is included in this batch.** It is evidence-backed and regression-verified
   twice, but it does modify two globally imported files. If you would rather
   batches never touch shared sheets, say so and I will revert it — the backups
   are kept.
3. **The three intentional behaviour changes in §5** are accessibility
   corrections, not preservation. "Byte-for-byte behaviour preserved" is **not**
   claimed for this batch.

**STOP** — awaiting review before batch 10.
