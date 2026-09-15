# Checkpoint 3C — Batch 28: ComplianceWorkspace's attestation and evidence on the design system

Batches 26A to 27 moved ComplianceWorkspace's read-only views and its ordinary
writes. Batch 28 moves the **Control Manual Attestation dialog** — the one place
evidence files are uploaded, listed and removed — onto the design system:

- **the attestation form** — the control being attested, applicability and
  status, the justification, the evidence checklist, the next review date, the
  reviewer note and Save Attestation;
- **evidence upload** — the file picker, its local refusals and its in-flight
  state;
- **the evidence list** — each attached file's name and size;
- **evidence removal** — which now asks before it deletes.

The dialog is opened from the Controls register (Attest) and from a finding
awaiting review (Verify). Both entry points, the register's Evidence column and
the Findings actions were migrated in Batch 26B and are unchanged.

## Why this is its own batch

Attestation was kept apart from Batch 27's ordinary writes because it is a
different risk class, and the code says so:

- **It is the only upload path in the workspace.** `POST
/compliance/controls/{id}/evidence` takes a multipart file under
  `compliance:attest`. The server checks its type, its magic bytes, its size, a
  per-tenant quota and — where configured — malware, and it writes the file to
  disk.
- **It carries the only destructive evidence operation.** `DELETE
/compliance/evidence/{id}` removes the stored file and its record, with no
  recycle bin, and on the legacy page it did so on a single click.
- **Its contents are audit evidence.** An evidence file is handed back to
  everyone in the tenant, which makes this surface a file-sharing surface.

It shares nothing with credentials or remediation: no credential is read or
entered, nothing is executed on a host, and no remediation or approval path is
reached from the dialog.

## The batch boundary

| Surface                                                                                                       | What it actually does                                                                                                                   | In 28                   |
| ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| Attestation form                                                                                              | `POST /compliance/controls/{id}/attest` (`attest`) with status, note, justification, next review date and the listed files' ids         | Yes                     |
| Evidence upload                                                                                               | `POST /compliance/controls/{id}/evidence` (`attest`), multipart, field `file`; empty files and files above 25 MB refused before sending | Yes                     |
| Evidence list                                                                                                 | `GET /compliance/controls/{id}/evidence` (`read`); the dialog shows name and size only                                                  | Yes                     |
| Evidence removal                                                                                              | `DELETE /compliance/evidence/{id}` (`attest`)                                                                                           | Yes                     |
| Evidence download                                                                                             | `GET /compliance/evidence/{id}/download` exists in the API; **the page has never called it** and offers no download                     | Not present — not added |
| Attest and Verify buttons, register Evidence column                                                           | Open the dialog                                                                                                                         | No — Batch 26B          |
| Shared dialog container and its title logic                                                                   | Shared by every dialog                                                                                                                  | No                      |
| Credentials Manager, remediation and rollback dialog, Approvals, log viewer, gap analysis, header and tab bar | Credentials, remote execution, page chrome                                                                                              | No                      |

**Download was asked for and is not in this batch.** There is nothing to
migrate: no component, handler or request in the frontend reaches the download
endpoint. Adding one would be a new feature — a new authenticated request that
puts evidence contents on the reader's machine — and not a migration. The
contract fails if any test requests a download, and the harness never stubs
one.

The handlers are untouched, and that is pinned:

- **Everything outside the dialog body and the new `AttestationEvidence`
  component is the code that was here.** Removing exactly what Batch 28 added —
  `CcureLoader` in the design-system import, the stylesheet import and the
  component — and putting the legacy block back yields the page at `b2988b7`
  byte for byte (5,526 lines). `handleSubmitAttestation`, `loadControlEvidence`,
  `handleUploadEvidence`, `handleDeleteEvidence` and `openAttestModal` are
  byte-identical.
- **Everything inside that decides anything is unchanged.** 45 logic
  fragments — every field's value and change handler, the status options, the
  justification's label, placeholder and `required` switch, the clause text,
  the checklist, `accept`, the picker's disabled state and change handler, the
  file name and size, the removal call, the review date, the note and the submit
  — occur in the new block or its component; the handler call sites are the same
  multiset (7 / 7), and `required` sits on the same two controls.
- **The component makes no request of its own** and reads nothing about a file
  but its id, name and size. `onRemove` is the page's own removal handler.

**Baseline:** HEAD `b2988b7` (Batch 27).

**Not touched:** everything in the "No" rows above; `dashboard.css`,
`compliance.css` (whose `.compliance-form` the Credentials Manager, the
remediation dialog and the log viewer still use), `scan.css`; the backend, the
API client, `App.jsx`, AppLayout, the shared `Modal`, every design-system
primitive, `nginx.conf`, CSP and `scripts/host-nginx/nginx-host.conf`.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `b2988b7`                                                                                                                                                                                                                                                                                               |
| Tests first, on the page before migration   | 27 tests: the 19 contract tests pass, and the 8 batch 28 tests all fail, each for its intended reason                                                                                                                                                                                                                         |
| Trial replay, unchanged build               | The 8 Batch 28 captures taken twice: **8 / 8** identical and every one clean; in both dialogs the keyboard probe reaches its field with a visible ring. The unchanged image carries none of the Batch 28 code                                                                                                                 |
| Baseline, unchanged build                   | 218 captures ready, twice. Determinism **218 / 218**, sensitivity **22 / 22**                                                                                                                                                                                                                                                 |
| Same tests, migrated                        | **19 / 19** contract tests and **8 / 8** batch 28 tests; Batch 27's **30 / 30**, Batch 26B's **52 / 52** and Batch 26A's **21 / 21** unchanged, with the UX4G integration tests **16 / 16** — 146 in all                                                                                                                      |
| Logic unchanged                             | Outside the dialog body and the new component the page is byte-identical to `b2988b7`; the five handlers byte-identical; 45 logic fragments unchanged; call sites 7 / 7; `required` on the same two controls; the component makes no request and reads no evidence content                                                    |
| Full frontend suite                         | 62 files, **2343** tests, all passing (2316 + 27)                                                                                                                                                                                                                                                                             |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                           |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                                                                             |
| Pre-commit formatting                       | Every Batch 28 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                                    |
| UX4G guardrails                             | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/` — the broad grep's one mention is `DesignSystemShowcase.jsx`'s header comment, unchanged since before this batch; 0 `ux4g-web-components` imports outside it; 0 UX4G runtime references in `src` or `index.html`; 0 external origins in `index.html` |
| Post determinism                            | post-a vs post-b **218 / 218** identical                                                                                                                                                                                                                                                                                      |
| Unchanged states                            | Every previously migrated page and every other ComplianceWorkspace capture — Batch 27's eleven, Batch 26B's seventeen and Batch 26A's eight included: **210 / 210** identical pre → post in every category, on both capture pairs                                                                                             |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                   |
| Batch 28 requests                           | Identical before and after in every Batch 28 capture (0 deltas). The only compliance reads are the opened control's evidence list, the register or the findings, the marketplace and the summaries; no credential, remediation, report, scan, gap-analysis, evidence-file or download read                                    |
| Evidence safety                             | No evidence upload, removal, attestation or download in any capture of the whole catalogue, in all four reports                                                                                                                                                                                                               |
| The removal question                        | Open on the migrated build in all six question captures — a named group with Delete file and Keep file in the accessible names and the tab order — and absent on the legacy build in all six                                                                                                                                  |
| Placeholders                                | No harness token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any Batch 28 capture                                                                                                                                                                                                        |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines)                                                                                                                                                                                                                              |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts, with 0 external `<link>`, `<script>`, `@import` or `url()` references. Both bundles carry the design system's 1,332 `--ux4g-*` token properties and 0 `.ux4g-` selectors or `ux4g-` class names                                                                   |
| Writes, navigations, off-origin, CSP issues | 436 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every Batch 28 capture ends on `/compliance` in all four reports                                                                |
| Screenshots                                 | All 8 Batch 28 captures reviewed side by side, pre and post, on a trial build before the full run and again on the final one. No regression                                                                                                                                                                                   |
| Cleanup                                     | Harness containers, images and Chrome processes: 0                                                                                                                                                                                                                                                                            |

### 0.1 The dialog in tests and in the harness

`src/__tests__/pages/ComplianceWorkspace.attestation.test.jsx` mounts the real
page with only the axios instance, the shell and the signed-in user replaced,
and `window.confirm` spied. Its `afterEach` fails any test that put or patched
anything, posted anywhere but an attestation or an evidence upload, sent a
DELETE anywhere but an evidence file or with anything but its URL, requested a
download, a credential, a remediation or a report, or called the browser's
confirm.

**The contract (19 tests, passing on the page before migration and after):**

- **Opening (4).** Attest opens the dialog for its control with its number,
  title and description, the status on Applicable — implemented and its three
  options in order, an optional justification with the inclusion placeholder, a
  required note, an empty review date, the checklist and Save Attestation as the
  submit, and reads exactly that control's evidence list and nothing else; a
  control already excluded opens as not applicable, its justification required
  and prefilled with the exclusion placeholder and the clause 6.1.3(d) text, and
  both follow the status; Verify on a finding awaiting review opens the same
  dialog for the finding's control, reading its evidence and showing its
  checklist — and, as found, not its title; closing by button or Escape sends
  nothing.
- **The list (2).** Each file shows `📎 name (N KB)` rounded to the kilobyte and
  a Remove action, and nothing else about it — no hash, content type, uploader
  or date, and no link; a control with no evidence, or a list that cannot be
  read, lists nothing, and the read failure is logged.
- **Upload (6).** The picker accepts exactly the eleven evidence extensions and
  one file; choosing a file posts `FormData` whose only field is `file` with a
  `multipart/form-data` header, reports "Attached name.", re-reads the list and
  clears the picker; an empty file and one above 25 MB are refused locally with
  their messages and nothing sent, while 25 MB exactly is sent; while an upload
  is out the picker is disabled and "Uploading…" shows; a refusal reports the
  API's detail or the error's message and re-reads nothing; from Verify the file
  goes to the finding's control.
- **Removal (2).** Removing a file sends one DELETE with its id and nothing
  else, re-reads the list and reports "Evidence removed."; a refusal reports the
  detail or the message and keeps the file listed.
- **Saving (4).** The status, note, justification, review date as an ISO
  timestamp and the listed files' ids, then closing, "Attestation recorded." and
  a re-read; a blank justification and date as `null`; excluding a control with
  a blank justification refused before anything is sent; a refusal keeping the
  dialog open with the detail, Save enabled while the request is out.
- **Permissions (1).** A user without `compliance:attest` sees nothing hidden or
  disabled; the server's refusal is what they are shown.

**The specification (8 tests, each failing on the page before migration for its
intended reason):** the fields labelled and the exclusion's justification
required and described by the clause; the checklist and the attached evidence
as lists named by `h3` headings, with no inline style or legacy class; the
picker labelled, described by the accepted types and the 25 MB limit, and an
upload announced as a status; each Remove named for its file; Remove asking
first — nothing sent until Delete file, Keep file and Escape backing out with
focus returned; a double-click unable to delete, a removal in flight unable to
be sent twice and focus on the list's heading afterwards; a refused removal
returning focus to that file's Remove; a token-only, prefix-scoped stylesheet
and no raw button, select or label in the new source.

**Harness states (5 states, 8 captures),** all on `/compliance`. None chooses a
file, saves an attestation, downloads or removes evidence:

| State                  | Persona, themes, viewport | What it shows                                                                                                                                   |
| ---------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `cw28-attest`          | analyst; light, dark      | A.5.1 from the register, with its checklist and three files, one with a long name; Tab reaches the file picker                                  |
| `cw28-attest-excluded` | analyst; light, dark      | A.6.7, already excluded: not applicable, its justification required and prefilled, the clause shown; Tab reaches the justification              |
| `cw28-attest-verify`   | analyst; light            | Opened from a finding awaiting review                                                                                                           |
| `cw28-attest-question` | analyst; light, dark      | `cw28-attest` with the long-named file's removal question open on the migrated build; on the legacy build the dialog's title is clicked instead |
| `cw28-attest-mobile`   | analyst; light, 390 px    | The removal question on a phone                                                                                                                 |

`CW28_CONTROLS` is Batch 26B's register with a checklist on A.5.1 and a recorded
exclusion on A.6.7; `CW28_EVIDENCE` gives each file an id, a name and a size and
nothing else, because the dialog shows nothing else.

### 0.2 Corrections

No contract assertion was changed after the page was migrated. These were, and
none of them is a gate:

- **Two contract expectations were wrong about the legacy page, and were
  corrected on it before anything was migrated.** The first draft expected the
  dialog opened from a finding to show its control's title and description; the
  page shows neither, because a finding carries no control number. The test now
  pins what the page does, and the gap is recorded in §7. The second expected a
  space between a file's size and its Remove button in the item's text.
- **The logic check's `required` comparison was vacuous.** Its pattern ended an
  opening tag at the first `>`, which in these tags is an arrow function's
  `=>`, so it found no `required` on either side and compared two empty lists.
  It now reads each tag to its closing `>` at brace depth zero and finds the same
  two controls before and after.
- **The stylesheet's header comment first gave the legacy dialog's inline styles
  as fourteen**; the census measured twenty, and the comment says twenty.
- **The trial gate first stopped on the batch report, not on the page.** Its
  evidence-read match required a space straight after `/evidence`, where the API
  client appends `?org_id=…`, so every capture was marked unclean for reading no
  evidence while being clean on every other measure, and 8 / 8 identical. The
  match was corrected, the kept trial captures re-reported clean, and the rest of
  the baseline was captured against the same still-serving container.
- **The analysis first reported the removal question missing on the migrated
  build.** It searched the capture for the question's wording, but a report keeps
  text only as a length and a hash. It now reads what the question adds — the
  group role, and Delete file and Keep file in the accessible names and the tab
  order — and was run again over the same four reports; nothing was re-captured.
- **The broad guardrail grep counted one `ux4g-` mention outside the design
  system**: the sentence in `DesignSystemShowcase.jsx`'s header comment stating
  that nothing uses a `ux4g-` class. A check for class names, selectors and
  imports finds none.

---

## 1. Files changed

| File                                                           | Change                                                                                                                | LOC                       |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `src/pages/ComplianceWorkspace.jsx`                            | The attestation dialog body; the new `AttestationEvidence` component; `CcureLoader` and the stylesheet imported       | 5526 → 5616 (+231 / −141) |
| `src/styles/compliance-attestation.css`                        | New, page-owned: 55 `--ccure-*` references, 0 colour literals, 0 other custom properties, every selector under `cwa-` | new, 172                  |
| `src/__tests__/pages/ComplianceWorkspace.attestation.test.jsx` | New: 19 contract + 8 batch 28                                                                                         | new, 929                  |
| `scripts/ux4g-harness/lib/fixtures.mjs`                        | A register with a checklist and an exclusion, and an evidence list                                                    | +44                       |
| `scripts/ux4g-harness/lib/states.mjs`                          | 5 `cw28-` states; `cw27-` in the regression prefixes                                                                  | +123 / −6                 |
| `docs/ux4g/03c-batch28-compliance-attestation-evidence.md`     | This document                                                                                                         | new                       |

In the dialog (the legacy block against the new block and its component):

| Measure                                               | Before | After                                       |
| ----------------------------------------------------- | ------ | ------------------------------------------- |
| Lines                                                 | 195    | 143 + 140 (the component, with its comment) |
| Inline `style` attributes                             | 20     | **0**                                       |
| Colour literals                                       | 3      | **0**                                       |
| `var(--…)` references in markup                       | 3      | **0**                                       |
| `dashboard.css` and `compliance.css` class references | 5      | **0**                                       |
| Hand-built buttons / selects                          | 2 / 1  | **0 / 0**                                   |
| Native inputs                                         | 2      | 1 — the file picker, which has no primitive |
| Labels with no associated field                       | 6      | **0**                                       |
| Headings                                              | 0      | 2                                           |
| Tests                                                 | 0      | 27                                          |

Across the whole page, inline style attributes are 167 → 147, colour literals 6
→ 3, `db-` class references 63 → 59, `compliance.css` class references 4 → 3,
hand-built buttons 22 → 20, inputs 14 → 13, selects 22 → 21 and bare labels 29
→ 23.

Bundle, measured from the two images' web roots:

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 404,399        | 407,193       | +2,794 |
| JS    | 1,575,994      | 1,577,217     | +1,223 |

---

## 2. Accessibility

1. **Every field has an associated label.** The legacy `<label>` elements were
   siblings with no `for`: the status select, both textareas, the date and the
   file picker had no accessible name. Required fields are marked visibly and
   announced as required; the exclusion's justification keeps "(required)" in
   its accessible name.
2. **The clause describes the field it governs.** The ISO/IEC 27001:2022 clause
   6.1.3(d) sentence is the exclusion justification's description rather than a
   loose paragraph.
3. **The checklist and the attached files are named lists.** Each has an `h3`
   the list is labelled by; the legacy "headings" were `<label>` elements
   labelling nothing. The paperclip is decorative and hidden from assistive
   technology.
4. **The picker says what it accepts.** Its description lists the accepted
   types and the 25 MB limit, derived from the same constants the upload
   handler checks, so the text and the check cannot drift apart.
5. **An upload is announced.** "Uploading…" is a polite status region while the
   picker is disabled.
6. **Remove says which file.** Each is named "Remove {file}"; the legacy page
   had one unnamed "Remove" per row.
7. **Removal cannot happen by accident.** Remove asks in the row — "Delete
   {file}? This cannot be undone." — as a named group with Delete file and Keep
   file, and focus moves to Keep file, so a repeated Enter or Space backs out
   rather than deleting. Keep file or Escape returns focus to Remove without
   closing the dialog. The question's buttons ignore the second click of a
   double-click. While the DELETE is out, Delete file is busy and disabled, as are
   Keep file and every other Remove. Afterwards focus goes to the file's Remove if
   the API refused, otherwise to the list's heading.
8. **Keyboard and focus.** Native controls in document order inside the dialog's
   focus trap; the harness tabs to the file picker and to the justification and
   records a visible focus ring before and after.
9. **Colour and layout** are `--ccure-*` tokens in both themes; long file names
   wrap inside the dialog, and on a phone the question wraps below its file
   (no capture overflows horizontally).

Measured in the harness: every attestation capture's unlabelled controls fall
from 7 to the 2 header selects the page still carries. Failing text pairs fall
from 10 to 2 in light and from 8 to 1 in dark on the evidence captures, and from
3 to 2 and 7 to 1 on the others; every pair left is the shared chrome's — the
header's "Run Compliance Scan" button and, in light, the tab bar's active label.
Delete file, Keep file and the removal prompt pass in both themes. Disabled
controls, which WCAG 1.4.3 exempts, are counted separately, and their counts are
the same before and after. On the legacy build in dark, the dialog's labels were
not legible at all.

---

## 3. Security and API behaviour

| Requirement                 | Evidence                                                                                                                                                                                                                                                                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Upload                      | Endpoint, method, the single `file` field, the multipart header, the local empty and 25 MB refusals, the success and failure notices and the re-read pinned; `handleUploadEvidence` byte-identical                                                                                                                       |
| Removal                     | One DELETE per confirmed removal, carrying only its URL; the refusal notice pinned; `handleDeleteEvidence` byte-identical. The only behaviour added is the question before it and the guard against sending it twice                                                                                                     |
| Attestation                 | Endpoint and body pinned, including `evidence_file_ids`; the exclusion check pinned; `handleSubmitAttestation` byte-identical                                                                                                                                                                                            |
| Download                    | Not present before, not added; any download request fails the tests; not stubbed in the harness                                                                                                                                                                                                                          |
| Evidence content            | Only a file's name and size are shown, as before — never its hash, type, uploader, date or bytes; the component reads nothing else; no `dangerouslySetInnerHTML`                                                                                                                                                         |
| Permissions                 | Unchanged: no client gate; the server's `compliance:attest` refusal is shown                                                                                                                                                                                                                                             |
| No other writes             | No test puts or patches anything, or posts or deletes outside the three evidence and attestation writes; 0 refused writes and 0 non-GET requests beyond the session refresh in any Batch 28 capture, and no evidence upload, removal, attestation or download in any capture of the whole catalogue, in all four reports |
| Credentials and remediation | Never read or reached by any test or capture in this batch                                                                                                                                                                                                                                                               |
| Logging                     | None added; the page's five `console` calls are the same                                                                                                                                                                                                                                                                 |
| Secrets                     | No token, ticket or placeholder secret in any report; test fixtures use a zero-filled hash                                                                                                                                                                                                                               |
| UX4G guardrails             | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/`, 0 `ux4g-web-components` imports outside it, 0 UX4G runtime references in `src` or `index.html`, 0 external origins in `index.html`                                                                                                             |
| Backend and API             | No file under `Backend/`, `Frontend/src/api/`, `Frontend/src/design-system/`, `Frontend/src/components/`, `nginx.conf` or `scripts/host-nginx/` changed                                                                                                                                                                  |
| CSP and external assets     | CSP and the security headers identical on six routes; the post web root references the same 7 hosts as the pre, with 0 external `<link>`, `<script>`, `@import` or `url()`; 1,332 `--ux4g-*` token properties in both bundles and 0 `.ux4g-` selectors                                                                   |

---

## 4. Intentional changes

1. **Removal asks before it deletes** — the one behaviour change in this batch,
   asked for by its brief and pinned by three specification tests. On the legacy
   page a single click on Remove, or an Enter on it, deleted the stored file, and
   a double-click sent the DELETE twice. The question is asked in the row, not in
   a second dialog: the shared dialog container closes on any Escape that reaches
   the document, so a nested confirmation would close the attestation form with
   it. The DELETE itself, its handler and its notices are unchanged.
2. **Labels, descriptions and headings** as in §2; "Justification for exclusion
   (required)" is a label with a required marker, and "Attached evidence" is a
   heading above a labelled picker, "Add evidence file".
3. **The picker's description** names the accepted types and the limit.
4. **"Uploading…"** is the design system's inline loader.
5. **The form no longer uses `.compliance-form`**; its layout, textareas and
   submit share Batch 27's `.cww-form` rules, and the control, checklist, picker
   and files use the new `compliance-attestation.css`.

---

## 5. What remains in ComplianceWorkspace, and why

| Part                                                      | Why it is not in 28                                                                                                       |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Credentials Manager                                       | Password and key fields; stored credentials created and deleted; still on `.compliance-form`                              |
| Remediation and rollback dialog                           | Ad-hoc SSH credentials and emergency bypass; remote execution; still on `.compliance-form`                                |
| Approvals Queue, with its log viewer and rollback trigger | Approval dispatches remediation on the target host with stored credentials; the log viewer is still on `.compliance-form` |
| Gap-analysis dialog                                       | Read-only, driven by the header's selectors                                                                               |
| Header, tab bar, banner, loader                           | Shared by every tab; carries the page-wide scan trigger                                                                   |
| The shared dialog container                               | Hosts every dialog                                                                                                        |
| `PaginationBar`                                           | Still used by Credentials and Approvals                                                                                   |
| `dashboard.css`, `compliance.css`, `scan.css`             | Still used by everything above                                                                                            |

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,cw26a-,cw26b-,cw27-,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-,ns-`
exits 0:

- All 210 unchanged captures are identical in every category — every
  ComplianceWorkspace capture outside this dialog, Batch 27's dialogs included.
- pre-b vs post-b is also 210 / 210.
- Post determinism (post-a vs post-b) is 218 / 218.
- The 8 Batch 28 captures changed.

Every changed category on those 8 captures is accounted for:

| Category                                                                                                                             | Captures | Why it changed                                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| names                                                                                                                                | 8        | The fields' associated labels; each Remove named for its file                                                                                               |
| headings                                                                                                                             | 8        | "Audit evidence expected for this control" and "Attached evidence" as `h3`                                                                                  |
| inline, classes, styles, rects                                                                                                       | 8        | The restyle                                                                                                                                                 |
| contrast, text, screenshot                                                                                                           | 8        | The restyle, the labels and the picker's description; the only failing pairs left are the shared chrome's                                                   |
| tabOrder                                                                                                                             | 5        | The Remove buttons' new names on `cw28-attest`, and on the three question captures the question's two buttons in place of the file's Remove (13 → 14 stops) |
| roles                                                                                                                                | 3        | The question's named group                                                                                                                                  |
| ariaStates, dialogs, live, tables, clickable, probes, overflow, errorBoundary, url, theme, requests, writes, offOrigin, csp, runtime | —        | **Unchanged on all 8**: the same dialog container, the same probe results, the same requests, no write, every capture on `/compliance`                      |

Screenshots were reviewed side by side for all 8 captures: the dialog with its
checklist and files in both themes, the exclusion in both themes, the dialog
from a finding, the removal question in both themes and on a phone.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — kept exactly, pinned where marked:

- **The API serves evidence downloads and the dialog offers none.** Reviewers
  cannot open a file from the attestation dialog. Adding it is a feature, with
  its own review of what reaches the reader's machine. (pinned: no request)
- **Verify from a finding does not say which control it attests.** A finding
  carries no control number, and the context is shown only when there is one.
  (pinned)
- **An evidence list that cannot be read looks like no evidence.** The failure
  is logged to the console and the list is empty. (pinned)
- **The list has no loading state**: it is empty until its read returns, and a
  late response for a control closed in the meantime is not discarded.
- **Save Attestation has no in-flight state**, so a second click sends a second
  attestation; saving while an upload is still out sends the file ids without
  the one uploading. (pinned: Save enabled)
- **Uploads and removals take effect at once**, independent of the attestation:
  closing the dialog without saving keeps what was uploaded and does not bring
  back what was removed.
- **No client permission gate.** A user without `compliance:attest` is offered
  upload, removal and save and is refused by the server. (pinned)
- **Upload and removal failures read `detail` or the error's message**, never
  the response's `message` field, unlike the page's other writes. (pinned)
- **The next review date is converted at UTC midnight** and past dates are
  accepted.
- **Escape while a removal is in flight closes the dialog**, because the busy
  Delete file cannot hold focus and the shared container closes on Escape; the
  request completes and reports.
- **Harness:** no capture chooses a file, saves, or confirms a removal; the
  network behaviour of all three is proven by the unit contract. On the legacy
  build the two question states click the dialog's title, because there Remove
  is the delete.

**Carried:** every item deferred by Batches 16 to 27 stands unchanged — among
them Batch 27's in-flight, role-gate and native-confirm findings for the
ordinary writes, the shared header and tab-bar issues, the shared loader's raw
error logging, the shared CcureModal outside-click issue, the Batch 26B view
issues, and the AMT, NetworkMap, ScanHistory, CredentialedResults,
Phase3Results and NewScan items — and none was reopened here.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was reached:

- the upload, the removal and the attestation — endpoint, method, payload,
  local refusals, success and failure — are unchanged and pinned, and opening or
  closing the dialog sends nothing but the opened control's evidence read;
- outside the dialog body and its new component the page is byte-identical to
  `b2988b7`, the handlers included, and no other dialog, the dialog container,
  the page chrome, a design-system primitive, a shared component or a global
  stylesheet was modified;
- removal now asks before it deletes and cannot be sent by a double-click or
  twice while in flight — the one behaviour change, asked for and pinned;
- no download was added, no evidence content beyond a file's name and size is
  shown, and no credential, remediation or approval path was touched;
- no backend or API file changed, and no logging was added;
- no write, evidence operation, unexpected navigation, off-origin request, CSP
  issue, exception or console error in any capture, and no secret in any report;
- determinism, sensitivity and the regression gate over every previously
  migrated page and the rest of ComplianceWorkspace passed;
- security headers, the air-gap host set and the UX4G guardrails are unchanged.

Batch 29 is not started.
