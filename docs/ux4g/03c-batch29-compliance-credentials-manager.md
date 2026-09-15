# Checkpoint 3C — Batch 29: ComplianceWorkspace's Credentials Manager on the design system

Batch 29 moves the **Credentials Manager** tab of ComplianceWorkspace onto the
design system:

- **the saved credentials list** — each stored credential's nickname, account,
  port and authentication method;
- **Register Credential** — the form that sends a new password or private key
  to be stored;
- **credential deletion** — which now asks in a design-system dialog.

## Why this is its own batch

The Credentials Manager is where secrets enter the product:

- **A password or private key is typed here and sent.** `POST
/compliance/credentials` takes it as a `SecretStr` under
  `compliance:manage_integrations`; the server encrypts it and never returns it.
- **The stored credentials authenticate to customer hosts.** The remediation
  dialog offers them when a fix is run against a machine.
- **Deletion is destructive and immediate.** `DELETE
/compliance/credentials/{id}` removes the record and its encrypted secret.

It shares no code path with remote execution: nothing on this tab runs a
command, reads a remediation request or approves one. The remediation dialog's
own use of the saved list is untouched.

## The batch boundary

| Surface                                                                                      | What it actually does                                                                                                                       | In 29               |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| Saved credentials list                                                                       | `GET /compliance/credentials` (`read`); the response carries id, name, username, method, port and creation time — no secret                 | Yes                 |
| Register Credential                                                                          | `POST /compliance/credentials` (`manage_integrations`) with name, username, method, the password or the key (the other `null`) and the port | Yes                 |
| Delete                                                                                       | `DELETE /compliance/credentials/{id}` (`manage_integrations`)                                                                               | Yes                 |
| `PaginationBar`                                                                              | The paging bar above the list; also used by the Approvals Queue                                                                             | No — kept as it was |
| The remediation dialog's stored-credential selector                                          | Reads the same list to run a fix on a host                                                                                                  | No                  |
| Approvals, the log viewer, gap analysis, the header and tab bar, the shared dialog container | Remote execution, page chrome                                                                                                               | No                  |
| `routers/credentials.py`, `GET /scan-schedules/credentials`                                  | The platform credential store's own endpoints; this tab does not use them                                                                   | Not reached         |

Everything that decides anything is pinned:

- **Everything outside the tab's render block and its three new pieces of
  state is the code that was here.** Removing exactly what Batch 29 added —
  `CcureConfirmDialog` and `CcurePasswordField` in the design-system import,
  the stylesheet import and the three state lines — and putting the legacy
  block back yields the page at `5539ddc` byte for byte (5,616 lines). The
  list read, the remediation dialog's read and selector, the pagination hook and
  `PaginationBar` are unchanged.
- **Everything inside the block that decides anything is unchanged.** 54 logic
  fragments — the paging bar's props, the column headings, the method labels,
  the admin gate, the create request and its payload, the success notice and the
  five resets, the failure notices, every field's value, change handler and
  placeholder, the method options, the delete request and its notices — occur in
  the new block; the call sites are the same multiset (19 / 19); `required` sits
  on the same five controls; and the password and key are referenced the same
  four times, as a field's value, its change handler and the request body.
- **No secret is logged, stored, put in a URL or rendered as text.** The logic
  check refuses a `console` call, browser storage, a template string or a text
  node carrying either secret in the new block, and requires
  `autocomplete="new-password"` on the password field.

**Baseline:** HEAD `5539ddc` (Batch 28).

**Not touched:** everything in the "No" rows above; `dashboard.css`,
`compliance.css` (whose `.compliance-form` the remediation dialog and the log
viewer still use, and whose `cw-pagination` rules `PaginationBar` still uses),
`scan.css`; the backend, the API client, `App.jsx`, AppLayout, the shared
`Modal`, every design-system primitive, `nginx.conf`, CSP and
`scripts/host-nginx/nginx-host.conf`.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `5539ddc`                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Tests first, on the page before migration   | 23 tests: the 17 contract tests pass, and the 6 batch 29 tests all fail, each for its intended reason                                                                                                                                                                                                                                                                                                                                                               |
| Trial replay, unchanged build               | The 8 Batch 29 captures and the two `cw-credentials` captures taken twice: **10 / 10** identical and every one clean; the keyboard probes reach the password and key fields with a visible ring. The unchanged image carries none of the Batch 29 code                                                                                                                                                                                                              |
| Baseline, unchanged build                   | 226 captures ready, twice. Determinism **226 / 226**, sensitivity **22 / 22**                                                                                                                                                                                                                                                                                                                                                                                       |
| Same tests, migrated                        | **17 / 17** contract tests and **6 / 6** batch 29 tests; Batch 28's **27 / 27**, Batch 27's **30 / 30**, Batch 26B's **52 / 52** and Batch 26A's **21 / 21** unchanged, with the UX4G integration tests **16 / 16** — 169 in all                                                                                                                                                                                                                                    |
| Logic unchanged                             | Outside the tab's render block and its three state lines the page is byte-identical to `5539ddc`; the list read, the remediation dialog's read and selector, the pagination hook and `PaginationBar` unchanged; 54 logic fragments unchanged; call sites 19 / 19; `required` on the same five controls; the secrets referenced the same four times; no `console` call, storage, template string or text node carries a secret; `new-password` on the password field |
| Full frontend suite                         | 63 files, **2366** tests, all passing (2343 + 23), on the second run — see §0.2                                                                                                                                                                                                                                                                                                                                                                                     |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                                                                                                                                                                                                                   |
| Pre-commit formatting                       | Every Batch 29 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                                                                                                                                                                          |
| UX4G guardrails                             | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/` — the broad grep's one mention is `DesignSystemShowcase.jsx`'s header comment, unchanged; 0 `ux4g-web-components` imports outside it; 0 UX4G runtime references in `src` or `index.html`; 0 external origins in `index.html`                                                                                                                                                               |
| Secret scan                                 | 0 private-key bodies in the changed files; 0 secret-shaped literals (24+ characters mixing upper case, lower case and digits) in the 1,261 lines this batch adds; the test's secrets are `synthetic-pass` and `synthetic key text`; 0 `console` calls in the tab                                                                                                                                                                                                    |
| Post determinism                            | post-a vs post-b **226 / 226** identical                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Unchanged states                            | Every previously migrated page and every other ComplianceWorkspace capture — Batch 28's eight, Batch 27's eleven, Batch 26B's seventeen and Batch 26A's eight included: **216 / 216** identical pre → post in every category, on both capture pairs                                                                                                                                                                                                                 |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Batch 29 requests                           | Identical before and after in every Batch 29 capture (0 deltas). The only compliance reads are the saved credentials, the marketplace and the summaries; no remediation, approval, evidence, report, scan, download or gap-analysis read                                                                                                                                                                                                                            |
| Credential safety                           | No credential created or deleted in any capture of the whole catalogue, in all four reports; 0 non-GET requests beyond the session refresh in any Batch 29 capture                                                                                                                                                                                                                                                                                                  |
| The deletion dialog                         | Open on the migrated build in both deletion captures — a dialog named "Delete credential" with Cancel and Delete credential — and absent on the legacy build in both                                                                                                                                                                                                                                                                                                |
| Placeholders                                | No harness token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any Batch 29 capture                                                                                                                                                                                                                                                                                                                                              |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines)                                                                                                                                                                                                                                                                                                                                                                    |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts, with 0 external `<link>`, `<script>`, `@import` or `url()` references. Both bundles carry the design system's 1,332 `--ux4g-*` token properties and 0 `.ux4g-` selectors or `ux4g-` class names                                                                                                                                                                                                         |
| Writes, navigations, off-origin, CSP issues | 452 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every Batch 29 capture ends on `/compliance` in all four reports                                                                                                                                                                                                      |
| Screenshots                                 | All 10 changed captures reviewed side by side, pre and post — on a trial build, again after the layout correction in §0.2, and on the final build. No regression                                                                                                                                                                                                                                                                                                    |
| Cleanup                                     | Harness containers and images: 0. Chrome, counted by the harness's profile-directory name: three headless browsers orphaned by earlier crashed runs (20 processes) found and stopped, none from this batch; 0 remain — see §0.2                                                                                                                                                                                                                                     |

### 0.1 The tab in tests and in the harness

`src/__tests__/pages/ComplianceWorkspace.credentials.test.jsx` mounts the real
page with only the axios instance, the shell and the signed-in user replaced,
`window.confirm` spied and every `console` method captured. The password and
key it types are synthetic, low-entropy placeholders (`synthetic-pass`,
`synthetic key text`). Its `afterEach` fails any test that put or patched
anything, posted anywhere but the credentials endpoint, sent a DELETE with
anything but its URL, reached a remediation, approval, evidence or report path,
or let either secret reach a URL, the console or browser storage.

**The contract (17 tests, passing on the page before migration and after):**

- **The list (6).** The tab reads the saved credentials once and lists each by
  nickname, username, port and method, with the paging summary and no creation
  time; anyone but an organisation admin or superadmin sees the list only — no
  Actions column, no Delete, no form; an organisation admin and a superadmin
  each see Delete on every row and the form; an empty list says "No saved
  credentials registered."; a list that cannot be read shows the page's error,
  lists nothing and logs the failure.
- **Registering (8).** A required nickname and username with their placeholders,
  port 22, the method on Password with its two options, a required masked
  password and no key field; choosing Private SSH Key swaps in a required key
  field and back; saving with a password posts the name, username, method, the
  password, a `null` key and the port as a number, reports "Credential saved
  successfully.", clears the fields and re-reads the list; saving with a key
  posts the key and a `null` password and keeps the method; a port of 0 is sent
  as 22; a refusal reports the API's detail, then its message, then the error's
  message, keeps what was typed and re-reads nothing; a validation refusal shaped
  as the API scrubs it never puts the password or key anywhere in the page but
  their own fields; after a successful save neither secret is left anywhere in
  the page.
- **Deleting (3).** Delete asks first, naming the credential ("Are you sure you
  want to delete Linux fleet?"), and declining sends nothing; confirming sends
  one DELETE for that credential carrying nothing but its URL, reports
  "Credential deleted successfully." and re-reads the list; a refusal reports the
  detail, then the message, then the error's message, and keeps the row.

**The specification (6 tests, each failing on the page before migration for its
intended reason):** the list as a captioned table under a heading, each
credential its row's header, its method a badge and its Delete named for it;
every field labelled, the password masked, described, `new-password` and with a
named visibility toggle, the key described, and no inline style or legacy class
in the form; Delete opening a dialog naming the credential with Cancel focused,
Cancel and Escape sending nothing and returning focus to Delete, and the
browser's confirm never used; a deletion in flight busy, not cancellable and not
sent twice, the dialog closing when it settles; Save busy and disabled while the
credential is sent, a second submit sending nothing; a token-only, prefix-scoped
stylesheet and no raw button, input, select, label, table or `window.confirm` in
the new source.

**Harness states (6 states, 8 captures),** all on `/compliance`. None types into
a field, saves a credential or deletes one:

| State                      | Persona, themes, viewport         | What it shows                                                                                                                    |
| -------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `cw29-credentials-admin`   | organisation admin; light, dark   | Three saved credentials — a password, a key and a long nickname — beside the empty register form; Tab reaches the password field |
| `cw29-credentials-analyst` | analyst; light                    | The list only                                                                                                                    |
| `cw29-credentials-empty`   | organisation admin; light         | No saved credentials, with the form                                                                                              |
| `cw29-credentials-key`     | organisation admin; light         | Private SSH Key chosen, so the key field replaces the password; Tab reaches it                                                   |
| `cw29-credentials-delete`  | organisation admin; light, dark   | The deletion dialog for "Linux fleet" open on the migrated build; on the legacy build the list's title is clicked instead        |
| `cw29-credentials-mobile`  | organisation admin; light, 390 px | The list and the form on a phone                                                                                                 |

`CW29_CREDENTIALS` gives each credential an id, a nickname, an account, a
method, a port and a creation time — what the API lists, and no secret. The
existing `cw-credentials` captures (an analyst, an empty list) change with the
tab, in both themes, and are counted with the batch rather than the regression
set.

### 0.2 Corrections

No contract assertion was changed after the page was migrated. These were, and
none of them is a gate:

- **The logic check first reported one fragment missing.** Prettier had joined
  the deletion notice's `pushToast(…)` onto one line, which drops the trailing
  comma the legacy multi-line call carried, and the check compared commas. It
  now ignores a trailing comma. In the same run its secret-handling line printed
  `false` only because it reused the check's overall failure flag; it has its own
  now, and no secret-handling check had failed.
- **The trial screenshots caught a layout defect.** The first stylesheet laid
  the tab out as a two-column grid, which kept an empty form column for anyone
  without the form: the analyst's list took about 60% of the row where the
  legacy list took all of it. The layout is now a wrapping row in which the list
  grows and the form keeps its width; the trial build was rebuilt and every
  Batch 29 capture reviewed again before the full run.
- **The first full post-migration run stopped at its unit gates** on
  AMTIntegration's "a rejected upload shows the API's detail or a default" — the
  known load flake, in a file this batch does not touch; 1 of 2366 tests. The run
  had captured nothing. The file passed alone (47 / 47) and the run was repeated
  from the start, every gate passing.
- **That first run's secret scan counted 13 "long literals".** Every one was an
  existing API path or a harness probe id, and none was on a line this batch
  adds. The scan now reads only the added lines and the two new files, and counts
  a literal only if it mixes upper case, lower case and digits: 0 in 1,261 lines.
- **The broad guardrail grep counted one `ux4g-` mention outside the design
  system**: the sentence in `DesignSystemShowcase.jsx`'s header comment stating
  that nothing uses a `ux4g-` class. A check for class names, selectors and
  imports finds none.
- **The flows' Chrome count never matched a harness browser.** It filtered
  command lines for `ccure-ux4g-harness`, but the harness names each browser's
  profile directory `ccure-harness-profile-…`, so the count's "0" — in this
  batch's flows and in Batches 27 and 28 — established nothing. Counted by the
  profile name after the final run, three headless harness browsers were still
  running: started on 13 September at 19:19 and on 15 September at 01:09 and
  10:22, the last at the moment Batch 27's post-a pass died at startup. None was
  from this batch's runs and no other Chrome was running. All 20 processes were
  stopped and 0 remain; 34 empty profile directories are left in the temp
  folder. The cause is recorded in §7.

---

## 1. Files changed

| File                                                           | Change                                                                                                                                    | LOC                       |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `src/pages/ComplianceWorkspace.jsx`                            | The Credentials Manager tab's render block; three pieces of state; `CcureConfirmDialog`, `CcurePasswordField` and the stylesheet imported | 5616 → 5646 (+175 / −145) |
| `src/styles/compliance-credentials.css`                        | New, page-owned: 7 `--ccure-*` references, 0 colour literals, 0 other custom properties, every selector under `cwc-`                      | new, 73                   |
| `src/__tests__/pages/ComplianceWorkspace.credentials.test.jsx` | New: 17 contract + 6 batch 29                                                                                                             | new, 869                  |
| `scripts/ux4g-harness/lib/fixtures.mjs`                        | Three saved-credential references                                                                                                         | +32                       |
| `scripts/ux4g-harness/lib/states.mjs`                          | 6 `cw29-` states; `cw28-` in the regression prefixes                                                                                      | +109 / −4                 |
| `docs/ux4g/03c-batch29-compliance-credentials-manager.md`      | This document                                                                                                                             | new                       |

In the tab (the legacy block against the new one):

| Measure                                                 | Before            | After                                     |
| ------------------------------------------------------- | ----------------- | ----------------------------------------- |
| Lines                                                   | 228               | 250                                       |
| Inline `style` attributes                               | 10                | **0**                                     |
| `var(--…)` references in markup                         | 2                 | **0**                                     |
| `dashboard.css` and `compliance.css` class references   | 11                | **0**                                     |
| Hand-built buttons / inputs / selects / labels / tables | 2 / 4 / 1 / 6 / 1 | **0 / 0 / 0 / 0 / 0**                     |
| `window.confirm`                                        | 1                 | **0**                                     |
| Native textarea                                         | 1                 | 1 — the key field, which has no primitive |
| `PaginationBar`                                         | 1                 | 1 — kept, as scoped                       |
| Design-system components                                | 0                 | 14                                        |
| Tests                                                   | 0                 | 23                                        |

Across the whole page, inline style attributes are 147 → 137, `db-` class
references 59 → 49, `.compliance-form` uses 3 → 2, hand-built buttons 20 → 18,
inputs 13 → 9, selects 21 → 20, bare labels 23 → 17, tables 3 → 2 and
`window.confirm` calls 3 → 2.

Bundle, measured from the two images' web roots:

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 407,193        | 407,745       | +552   |
| JS    | 1,577,217      | 1,576,973     | −244   |

---

## 2. Accessibility

1. **The list is a named table.** A `CcureTable` with the caption "Saved
   credentials" under the card's `h2`, `scope="col"` headers, each nickname as
   its row's header, and the method as a badge carrying its word. The legacy
   table had no caption and no scopes. Loading shows skeleton rows inside the
   table with a polite status, rather than "No saved credentials registered."
   while the list is still being read.
2. **Every field has an associated label.** The legacy `<label>` elements were
   siblings with no `for`: the nickname, username, port, method, password and key
   had no accessible name. Required fields are marked visibly and announced as
   required.
3. **The secret fields say what happens to what is typed.** The password and
   the key are described by "Stored encrypted. The saved list never shows it."
4. **The password is the design system's password field.** Masked by default;
   a visibility toggle named "Toggle Password visibility" with `aria-pressed`,
   kept out of the tab order as on every other password field in the product; a
   Caps Lock status while typing.
5. **Delete says which credential, and asks in a real dialog.** Each row's
   action is named "Delete {nickname}" and announced as opening a dialog. The
   dialog is named "Delete credential", described by what it removes, and
   carries the legacy question as its warning. Cancel takes focus, so a repeated
   Enter backs out; Escape cancels; focus returns to Delete. While the DELETE is
   out, the confirm button is busy and disabled and neither Cancel nor Escape can
   close the dialog over the request.
6. **Save shows it is working.** Busy and disabled while the credential is
   sent.
7. **Keyboard and focus.** Native controls in document order; the harness tabs
   to the password field and to the key field and records a visible focus ring
   before and after.
8. **Colour and layout** are `--ccure-*` tokens in both themes; the form sits
   beside the list and below it on a phone, and a long nickname wraps
   (no capture overflows horizontally).

Measured in the harness: on every capture with the register form, unlabelled
controls fall from 8 to 3 — `PaginationBar`'s page-size select and the header's
two selects; the analyst's captures stay at 3. `PaginationBar`'s « and » remain
its two glyph-only buttons. Failing text pairs fall from 15 to 1 in dark and 11
to 2 in light on the admin captures, 9 to 2 for the analyst, 8 to 2 on the empty
list and 5 and 6 to 1 and 2 on `cw-credentials`; every pair left is the shared
chrome's — the header's "Run Compliance Scan" button and, in light, the tab
bar's active label. While the deletion dialog is open the tab order is the
dialog's own three stops (36 → 3). On the legacy build in dark, the form's
labels were not legible at all.

---

## 3. Security and credential exposure

| Requirement             | Evidence                                                                                                                                                                                                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Where a secret goes     | The password or key reaches only the POST body. The tests fail if either reaches a URL, the console or browser storage, or appears in the page's text or any attribute outside its own field after a refusal; after a successful save neither is left anywhere in the page          |
| What the API returns    | The list's schema carries no secret, and nothing on the tab renders one; the harness fixtures carry references only — id, nickname, account, method, port, creation time                                                                                                            |
| Error handling          | Refusals are shown as the API's `detail` or `message`. The API's validation handler removes submitted values before it answers, and the contract replays that shape: the toast carries no secret                                                                                    |
| Logging                 | None added; the tab makes no `console` call; the page's five are the same                                                                                                                                                                                                           |
| Browser autofill        | The password field is `autocomplete="new-password"`, as on the product's other credential forms, so a browser does not offer the signed-in user's own password into it and a revealed field is not kept in form history                                                             |
| Masking                 | Unchanged by default: the password is masked; revealing it is an explicit, announced toggle                                                                                                                                                                                         |
| Deletion                | Confirmed in a dialog that cannot be answered by a stray Enter or sent twice; the DELETE carries only the credential's id in its path                                                                                                                                               |
| Permissions             | Unchanged: the form and Delete are offered to an organisation admin or superadmin; the server's `manage_integrations` refusal is shown                                                                                                                                              |
| No other writes         | No test puts or patches anything, or posts or deletes outside the credentials endpoint; 0 refused writes and 0 non-GET requests beyond the session refresh in any Batch 29 capture, and no credential created or deleted in any capture of the whole catalogue, in all four reports |
| Test values             | Synthetic, low-entropy placeholders; no real or realistic credential, key body or token in any test, fixture or state; gitleaks passes on the staged content with no allowlist                                                                                                      |
| UX4G guardrails         | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/`, 0 `ux4g-web-components` imports outside it, 0 UX4G runtime references in `src` or `index.html`, 0 external origins in `index.html`                                                                        |
| Backend and API         | No file under `Backend/`, `Frontend/src/api/`, `Frontend/src/design-system/`, `Frontend/src/components/`, `nginx.conf` or `scripts/host-nginx/` changed                                                                                                                             |
| CSP and external assets | CSP and the security headers identical on six routes; the post web root references the same 7 hosts as the pre, with 0 external `<link>`, `<script>`, `@import` or `url()`; 1,332 `--ux4g-*` token properties in both bundles and 0 `.ux4g-` selectors                              |

---

## 4. Intentional changes

1. **Deletion asks in a `CcureConfirmDialog`, not the browser's confirm.** The
   native confirm focuses OK, so a repeated Enter on Delete deleted the
   credential, and nothing stopped a second DELETE while the first was out. The
   question is the same sentence; Cancel is focused; Escape cancels; the dialog
   is busy while the request is out. The DELETE, its notices and the re-read are
   unchanged. The tab is not inside the shared dialog container, so this is a
   dialog of its own rather than one nested in another.
2. **Save is busy and disabled while the credential is sent**, so a second
   click no longer creates a second credential or a duplicate-name refusal.
3. **The password field is `CcurePasswordField`**, with a visibility toggle and
   a Caps Lock status, and `autocomplete="new-password"`, as on the product's
   other credential forms.
4. **Labels, descriptions, the table's caption and row headers, the method
   badge, the named Delete** and the loading state, as in §2.
5. **The tab no longer uses `.db-card`, `.db-table`, `.db-tag`, `.db-btn` or
   `.compliance-form`**; the layout is `compliance-credentials.css`.

---

## 5. What remains in ComplianceWorkspace, and why

| Part                                                      | Why it is not in 29                                                                                                                 |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Remediation and rollback dialog                           | One-time SSH credentials, the stored-credential selector and emergency bypass; it runs a fix on a host; still on `.compliance-form` |
| Approvals Queue, with its log viewer and rollback trigger | Approval dispatches remediation on the target host with stored credentials; the log viewer is still on `.compliance-form`           |
| Gap-analysis dialog                                       | Read-only, driven by the header's selectors                                                                                         |
| Header, tab bar, banner, loader                           | Shared by every tab; carries the page-wide scan trigger                                                                             |
| The shared dialog container                               | Hosts the remaining dialogs                                                                                                         |
| `PaginationBar`                                           | Still above the credentials list and the Approvals Queue                                                                            |
| `dashboard.css`, `compliance.css`, `scan.css`             | Still used by everything above                                                                                                      |

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-dashboard,cw-marketplace,cw-policies,cw-controls,cw-findings,cw-exceptions,cw-approvals,cw26a-,cw26b-,cw27-,cw28-,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-,ns-`
exits 0:

- All 216 unchanged captures are identical in every category — every
  ComplianceWorkspace capture outside this tab, the Approvals Queue and Batches
  26A to 28 included.
- pre-b vs post-b is also 216 / 216.
- Post determinism (post-a vs post-b) is 226 / 226.
- The 10 changed captures are the 8 `cw29-` captures and `cw-credentials` in
  both themes.

Every changed category on those 10 captures is accounted for:

| Category                                                                                          | Captures | Why it changed                                                                                                           |
| ------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| headings, roles, live, tables                                                                     | 10       | "Saved Credentials" and "Register Credential" as `h2`; the table's caption, column and row headers and its polite status |
| inline, classes, styles, rects, contrast, text, screenshot                                        | 10       | The restyle, the labels, the descriptions and the badges; the only failing pairs left are the shared chrome's            |
| names                                                                                             | 7        | The form's associated labels and the named Delete actions, on the captures with the form                                 |
| ariaStates                                                                                        | 6        | The password visibility toggle's `aria-pressed`, on the captures showing the password field                              |
| tabOrder                                                                                          | 6        | The named Delete actions; the dialog's three stops while it is open; on a phone the table's scroll region (37 → 38)      |
| dialogs                                                                                           | 2        | The deletion dialog                                                                                                      |
| clickable, probes, overflow, errorBoundary, url, theme, requests, writes, offOrigin, csp, runtime | —        | **Unchanged on all 10**: the same probe results, the same requests, no write, every capture on `/compliance`             |

Screenshots were reviewed side by side for all 10 captures: the admin tab in
both themes, the analyst's list, the empty list, the key field, the deletion
dialog in both themes, the phone layout and `cw-credentials` in both themes.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — kept exactly, pinned where marked:

- **The typed secret is in the DOM while it is being typed.** Both fields are
  React-controlled, and React mirrors a controlled input's value into its
  `value` attribute and a textarea's into its text: anything that serialises the
  DOM — a browser extension, a session-replay script, a DevTools snapshot — sees
  the password or key until the form is cleared. The legacy fields did the same;
  avoiding it needs uncontrolled fields. (pinned: cleared after a successful
  save)
- **The key field is spell-checked and the text fields accept autofill.** A
  browser's enhanced spell check may send what is typed into the key field to a
  remote service. The attributes that would stop it are not required by the
  migrated field's own safety and were left as found.
- **The private key is shown in clear while typed**, with no masking option.
- **A validation refusal reads "Failed to save credential: [object Object]".**
  The API's scrubbed `detail` is a list, and the page concatenates it. No secret
  is shown. (pinned: no secret)
- **The client's gate is a role name; the server's is a permission.** The form
  and Delete are offered to an organisation admin or superadmin, while the
  server requires `compliance:manage_integrations` — Batch 27's Marketplace
  finding, on a second surface. (pinned)
- **A port of 0, or one that does not parse, is sent as 22** without saying
  so; an out-of-range port is refused only by the server. (pinned)
- **Switching the method keeps the other secret in memory**: a password typed
  before choosing Private SSH Key is still held, is sent as `null`, and returns
  if Password is chosen again; both are cleared only by a successful save.
- **After a successful deletion focus returns to the removed row's Delete** and
  is lost when the list reloads.
- **A list that cannot be read** shows the page-level error banner and an empty
  table. (pinned)
- **`PaginationBar` is unchanged above the migrated table** — hand-built
  buttons and an unlabelled page-size select — until the Approvals Queue, its
  other user, is migrated.
- **The harness can orphan its browser.** `launchChrome` hands back its
  `close()` only once the DevTools connection has opened; when that connection
  fails at startup — the race recorded since Batch 27 — the run exits with the
  whole headless browser tree still running and its profile directory left in
  the temp folder. Three such browsers were found and stopped in this batch
  (§0.2). A harness change, outside this batch.
- **Harness:** no capture types, saves or deletes; the create and delete
  requests are proven by the unit contract. On the legacy build the two deletion
  states click the list's title, because there Delete opens the browser's
  confirm.

**Carried:** every item deferred by Batches 16 to 28 stands unchanged — among
them Batch 28's evidence findings, Batch 27's in-flight, role-gate and
native-confirm findings for the ordinary writes, the shared header and tab-bar
issues, the shared loader's raw error logging, the shared CcureModal
outside-click issue, the Batch 26B view issues, and the AMT, NetworkMap,
ScanHistory, CredentialedResults, Phase3Results and NewScan items — and none was
reopened here.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was reached:

- the list read, the create request and payload, the resets, the delete request
  and every notice are unchanged and pinned; the admin gate is unchanged;
- outside the tab's render block and its three state lines the page is
  byte-identical to `5539ddc`, and the remediation dialog, Approvals, the log
  viewer, gap analysis, the dialog container, the page chrome, `PaginationBar`, a
  design-system primitive, a shared component or a global stylesheet were not
  modified;
- the password and key reach only the request body — never a URL, the console,
  storage, or the page outside their own fields — and no secret-shaped value was
  added;
- deletion asks in a design-system dialog that a stray Enter cannot confirm and
  that cannot send twice, and Save cannot create a credential twice — the two
  behaviour changes, pinned;
- no backend or API file changed, and no logging was added;
- no write, credential creation or deletion, unexpected navigation, off-origin
  request, CSP issue, exception or console error in any capture, and no secret in
  any report;
- determinism, sensitivity and the regression gate over every previously
  migrated page and the rest of ComplianceWorkspace passed;
- security headers, the air-gap host set and the UX4G guardrails are unchanged.

Batch 30 is not started.
