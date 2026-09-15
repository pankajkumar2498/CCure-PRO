# Checkpoint 3C — Batch 30: ComplianceWorkspace's credential-bearing execution on the design system

Batch 30 moves ComplianceWorkspace's **credential-bearing remote-execution
workflow** onto the design system:

- **the Approvals Queue** — every remediation and rollback request, with
  Approve, Reject, Cancel, View Logs and Rollback;
- **the remediation and rollback dialog** — the guide, the repair script, the
  choice between a stored credential and one-time credentials, and the
  emergency bypass;
- **the execution log viewer** — a request's console output.

## Why this is its own batch

This is where the product runs commands on customer hosts:

- **A password or private key is typed here and sent.** `POST
/compliance/findings/{id}/remediate` and `POST
/compliance/remediations/requests/{id}/rollback` take one-time credentials as
  `SecretStr`; the server encrypts them on receipt and holds them on the request
  until it runs, is rejected or is cancelled.
- **A stored credential is chosen to authenticate to a host.** The dialog sends
  its id; its secret never reaches the page.
- **Approval turns a request into execution.** `POST
/compliance/remediations/requests/{id}/approve` with `{status: "approved"}`,
  under `compliance:approve_exception`, queues the worker that runs the script
  over SSH on the target. `{status: "rejected"}` and `POST …/{id}/cancel` (the
  creator only, under `compliance:remediate`) close the request and clear the
  username, encrypted secret, port and method held with it.
- **The emergency bypass skips the queue.** An administrator's dispatch with the
  bypass ticked runs the script directly.
- **The log is what ran on the host**, sanitised by the worker before it is
  stored.

## The batch boundary

| Surface                                                                                                   | What it actually does                                                                                                                                                 | In 30          |
| --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| Approvals Queue                                                                                           | `GET /compliance/remediations/requests`, re-read quietly every 5 seconds while the tab is open; id, control, host, command, requester, status and log — no credential | Yes            |
| Cancel                                                                                                    | `POST …/requests/{id}/cancel` with nothing but its URL; offered to the request's creator                                                                              | Yes            |
| Approve and Reject                                                                                        | `POST …/requests/{id}/approve` with `{status}`; offered to an organisation admin or superadmin who did not create the request                                         | Yes            |
| Execution log viewer                                                                                      | Shows the request's stored output; sends nothing                                                                                                                      | Yes            |
| Remediation dialog                                                                                        | `POST /compliance/findings/{id}/remediate` with a stored credential's id or one-time credentials, and the bypass flag                                                 | Yes            |
| Rollback dialog                                                                                           | `POST …/requests/{id}/rollback` with the same choice                                                                                                                  | Yes            |
| The queue's pager                                                                                         | `PaginationBar` above the queue becomes `PagingControls`, on the same pagination hook and page sizes                                                                  | Yes            |
| `PaginationBar` itself                                                                                    | Still the Credentials Manager's pager, so the queue was not its last user                                                                                             | No — kept      |
| The shared dialog container                                                                               | Hosts these dialogs; its title is the dialog's type upper-cased                                                                                                       | No — unchanged |
| The Credentials Manager, attestation and evidence, gap analysis, the header and tab bar, the Findings tab | Earlier batches and page chrome; the Findings tab's Remediate button opens the dialog and is unchanged                                                                | No             |
| `routers/compliance.py`, `core/compliance_tasks.py`                                                       | Read to confirm what the dialog now says about one-time credentials                                                                                                   | Not changed    |

Everything that decides anything is pinned:

- **Everything outside the two render blocks and the two new pieces of state is
  the code that was here.** Removing exactly what Batch 30 added —
  `CcureAlert` in the design-system import, the stylesheet import and the two
  decision state lines — and putting the legacy blocks back yields the page at
  `f3348f7` byte for byte (5,646 lines). `handleRemediate`, `handleRollback`,
  `handleCopyCommand`, the queue's 5-second poll, the pagination hook and the
  shared dialog container are unchanged.
- **Everything inside the blocks that decides anything is unchanged.** 123 logic
  fragments — the endpoints and bodies, every notice, the creator and
  administrator gates, the status tests, the active-rollback test, the request
  fields View Logs and Rollback hand the dialog, every field's value, change
  handler and placeholder, the method options, the dispatch branches and the
  no-script labels — occur in the new blocks; the call sites are the same
  multisets (18 / 18 in the queue, 15 / 15 in the dialogs).
- **No secret is logged, stored, put in a URL or rendered as text.** The
  one-time password and key are each referenced once in the dialog, as before,
  as their field's value; their setters and the request body are in the
  unchanged handlers. The logic check refuses, in the migrated blocks, a
  `console` call, browser storage, a template string or a text node carrying
  either, a credential payload field (`encrypted_…`, `key_content`,
  `.password`) and `dangerouslySetInnerHTML`, and requires
  `autocomplete="new-password"` on the password field.

**Baseline:** HEAD `f3348f7` (Batch 29).

**Not touched:** everything in the "No" rows above; `compliance.css` (whose
`.compliance-form` this page no longer uses, and whose `cw-pagination` rules
`PaginationBar` still uses), `dashboard.css`, `scan.css`; the backend, the API
client, `App.jsx`, AppLayout, the shared `Modal`, every design-system primitive,
`nginx.conf`, CSP and `scripts/host-nginx/nginx-host.conf`.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `f3348f7`                                                                                                                                                                                                                                                                                                                                                                                                       |
| Tests first, on the page before migration   | 31 tests: the 25 contract tests pass, and the 6 batch 30 tests all fail, each for its intended reason                                                                                                                                                                                                                                                                                                                                 |
| Trial replay, unchanged build               | The 17 Batch 30 captures and the two `cw-approvals` captures taken twice: **19 / 19** identical and every one clean. The keyboard probe reaches the one-time password field — with a visible ring and no accessible name — and cannot reach the console output. The unchanged image carries none of the Batch 30 code                                                                                                                 |
| Baseline, unchanged build                   | 243 captures ready, twice. Determinism **243 / 243**, sensitivity **22 / 22**; every Batch 30 capture clean in both passes                                                                                                                                                                                                                                                                                                            |
| Same tests, migrated                        | **25 / 25** contract tests and **6 / 6** batch 30 tests; Batch 29's **23 / 23**, Batch 28's **27 / 27**, Batch 27's **30 / 30**, Batch 26B's **52 / 52** and Batch 26A's **21 / 21** unchanged, with the UX4G integration tests **16 / 16** — 200 in all                                                                                                                                                                              |
| Logic unchanged                             | Outside the two blocks and their two state lines the page is byte-identical to `f3348f7`; the three handlers, the poll, the pagination hook and the dialog container unchanged; 123 logic fragments unchanged; call sites 18 / 18 and 15 / 15; each one-time secret referenced once, as its field's value, as before; no `console` call, storage, template string or text node carries a secret; `new-password` on the password field |
| Full frontend suite                         | 64 files, **2397** tests, all passing (2366 + 31), on the first run                                                                                                                                                                                                                                                                                                                                                                   |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                                                                                                                                   |
| Build                                       | `vite build` succeeds; its chunk-size warning, and its note that `axiosInstance.js` is imported both statically and dynamically, concern files this batch does not touch and predate it                                                                                                                                                                                                                                               |
| Pre-commit formatting                       | Every Batch 30 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                                                                                                                                            |
| UX4G guardrails                             | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/` — the strict and broad greps' one match each is `DesignSystemShowcase.jsx`'s header comment, unchanged since `f3348f7` and counted the same way in Batch 29; 0 `ux4g-web-components` imports outside it; 0 UX4G runtime references in `src` or `index.html`; 0 external origins in `index.html`                                                              |
| Secret scan                                 | 0 private-key bodies in the changed files; 0 secret-shaped literals (24+ characters mixing upper case, lower case and digits) in the 2,220 lines this batch adds; the test's secrets are `synthetic-pass` and `synthetic key text`; 0 `console` calls in the migrated blocks                                                                                                                                                          |
| Post determinism                            | post-a vs post-b **243 / 243** identical                                                                                                                                                                                                                                                                                                                                                                                              |
| Unchanged states                            | Every previously migrated page and every other ComplianceWorkspace capture — Batch 29's ten, Batch 28's eight, Batch 27's eleven, Batch 26B's seventeen and Batch 26A's eight included: **224 / 224** identical pre → post in every category, on both capture pairs                                                                                                                                                                   |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Batch 30 requests                           | Identical before and after in every Batch 30 capture (0 deltas). The only compliance reads are the remediation requests, the findings register, the saved credentials, the marketplace and the summaries; no evidence, report, scan, download or gap-analysis read                                                                                                                                                                    |
| Execution safety                            | No approval, rejection, cancellation, remediation or rollback request in any capture of the whole catalogue, in all four reports; 0 refused writes and 0 non-GET requests beyond the session refresh in any Batch 30 capture; no capture types a credential, dispatches or copies                                                                                                                                                     |
| The queue's questions                       | Open on the migrated build in all three question captures — a modal dialog named "Approve remediation request" (light and dark) or "Cancel rollback request", with Go back — and absent on the legacy build, in all four reports                                                                                                                                                                                                      |
| Placeholders                                | No harness token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any Batch 30 capture                                                                                                                                                                                                                                                                                                                |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines).                                                                                                                                                                                                                                                                                                                                     |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts, with 0 external `<link>`, `<script>`, `@import` or `url()` references. Both bundles carry the design system's 1,332 `--ux4g-*` token properties and 0 `.ux4g-` selectors or `ux4g-` class names.                                                                                                                                                                          |
| Writes, navigations, off-origin, CSP issues | 486 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every Batch 30 capture ends on `/compliance` in all four reports                                                                                                                                                                        |
| Screenshots                                 | All 19 changed captures reviewed side by side, pre and post — on a trial build, where they caught the lower-cased status words (§0.2), and on the final build. No regression. The phone capture of the queue shows the page scrolled past the card by the shared chrome, identically on both builds, and neither overflows                                                                                                            |
| Cleanup                                     | Harness containers and validation images: 0. Chrome, counted by the harness's profile-directory name: 0 before and after every run                                                                                                                                                                                                                                                                                                    |

### 0.1 The workflow in tests and in the harness

`src/__tests__/pages/ComplianceWorkspace.execution.test.jsx` mounts the real
page with only the axios instance, the shell and the signed-in user replaced,
`window.confirm` spied, the clipboard replaced and every `console` method
captured. Nothing is executed anywhere: every write is a mock. The one-time
password and key it types are synthetic, low-entropy placeholders
(`synthetic-pass`, `synthetic key text`). Its `afterEach` fails any test that
put, patched or deleted anything; posted anywhere but a finding's `remediate` or
a request's `approve`, `cancel` or `rollback`; sent a cancellation with anything
but its URL or an approval without its body; put either secret, or the words
`credential_id`, `jit`, `password` or `key_content`, into any URL; or let either
secret reach the console or browser storage.

**The contract (25 tests, passing on the page before migration and after):**

- **The queue (5).** It reads the requests once and lists each ticket's id,
  control, host, command, requester and status; an empty queue says so; an
  administrator decides others' requests, cancels their own, and sees logs and
  rollbacks where they apply; anyone else sees others' requests pending and may
  still cancel their own; the queue is re-read quietly every 5 seconds while the
  tab is open, and no longer once the tab is left.
- **Cancelling (3).** The creator is asked first, and declining sends nothing;
  confirming posts to `cancel` with nothing but the URL, says which kind of
  request was cancelled and re-reads the queue; a refusal reports the API's
  detail, then its message, then the error's message.
- **Approving and rejecting (3).** Approving posts the approval, says which kind
  was queued and re-reads the queue; rejecting posts the rejection and says which
  kind was rejected; a refusal of either reports the API's detail.
- **The log (1).** View Logs opens that request's log and sends nothing.
- **The remediation dialog (10).** Remediate opens the guide for the finding —
  its control, host, recommendation and script — with one-time credentials
  chosen; a finding with no script says so and cannot be dispatched; Copy puts
  the script on the clipboard and says so; dispatching with a one-time password
  posts it once, closes, reports the API's message, clears the secret and
  re-reads; with a one-time key it posts the key and a `null` password; with a
  stored credential it posts that credential's id only, chosen by its name and
  account; a missing username or stored credential is refused before anything is
  sent; only an administrator is offered the emergency bypass, which the request
  then carries; a refusal reports the API's detail and keeps the typed username;
  Close Guide closes and sends nothing.
- **The rollback dialog (3).** Rollback opens the warning for that request with
  its host and script and reads the stored credentials; dispatching posts the
  rollback with the credentials and no action, closes and reports the result; a
  refusal reports the API's detail.

**The specification (6 tests, each failing on the page before migration for its
intended reason):** the queue a captioned table under a heading, tickets its row
headers, status and rollback badges, and every action named for its ticket;
cancelling, approving and rejecting each asking in a dialog with Go back focused,
Go back and Escape sending nothing, and the browser's confirm never used; a
decision in flight busy, not dismissible and not sent twice, the dialog closing
when it settles; the dialog's fields labelled, the credential source a radio
group, the one-time password masked, never autofilled and described, and the
bypass described; the repair script and the console output named,
keyboard-reachable regions, Copy saying what it copies, the rollback warning a
design-system warning and a rollback's Dispatch a danger action; a token-only,
prefix-scoped stylesheet and no raw button, table, legacy class or
`window.confirm` in the new source.

**Harness states (12 states, 17 captures),** all on `/compliance`. None approves,
rejects, cancels, dispatches, copies or types:

| State                   | Persona, themes, viewport         | What it shows                                                                                                                                                                                                   |
| ----------------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cw30-queue-admin`      | organisation admin; light, dark   | Six requests in every status and both kinds: Approve and Reject on another's pending request, Cancel Rollback on the operator's own, View Logs on the executed and failed, Rollback on the executed remediation |
| `cw30-queue-analyst`    | analyst; light                    | The same queue without Approve or Reject                                                                                                                                                                        |
| `cw30-queue-empty`      | organisation admin; light         | No requests                                                                                                                                                                                                     |
| `cw30-queue-mobile`     | organisation admin; light, 390 px | The queue on a phone                                                                                                                                                                                            |
| `cw30-approve-ask`      | organisation admin; light, dark   | The approval question for a pending remediation, open on the migrated build; on the legacy build, where Approve posts at once, the queue's title is clicked instead                                             |
| `cw30-cancel-ask`       | organisation admin; light         | The cancellation question for the operator's own pending rollback, open on the migrated build; on the legacy build, where Cancel opens the browser's confirm, the title is clicked                              |
| `cw30-log-viewer`       | organisation admin; light, dark   | An executed request's console output; Tab is sent towards the output                                                                                                                                            |
| `cw30-rollback-dialog`  | organisation admin; light, dark   | The rollback dialog for the executed remediation                                                                                                                                                                |
| `cw30-remediate-dialog` | organisation admin; light, dark   | The remediation dialog from the Findings register with the emergency bypass ticked and nothing dispatched; Tab reaches the one-time password field                                                              |
| `cw30-remediate-key`    | organisation admin; light         | Private SSH Key chosen, so the key field replaces the password                                                                                                                                                  |
| `cw30-remediate-stored` | organisation admin; light         | Use Stored Credential chosen: the saved credentials listed by name and account                                                                                                                                  |
| `cw30-remediate-mobile` | organisation admin; light, 390 px | The remediation dialog on a phone                                                                                                                                                                               |

`CW30_REQUESTS` gives each request the fields the queue's API lists — id,
finding, control, command, host, status, bypass flag, times, requester, approver
and log — and no credential; its commands and logs are synthetic and nothing in
them was executed. `CW30_FINDINGS` is Batch 26B's findings register with a fix
registered on its failed A.8.8 finding. The stored credentials are Batch 29's
references. The router refuses every write regardless, and the batch report
counts them. The existing `cw-approvals` captures change with the tab, in both
themes, and are counted with the batch rather than the regression set.

### 0.2 Corrections

No contract assertion was changed after the page was migrated. These were, and
none of them is a gate:

- **One batch 30 test failed on the migrated page at first** — 183 of the 184
  tests in the six ComplianceWorkspace files passed. The source test looked for
  the legacy `mono` class with `\bmono\b`, which also matches the new
  `cwe-mono`, because a hyphen is a word boundary. It now requires `mono` to
  stand alone, and the migrated source has no `mono` class. No contract test
  was touched.
- **The trial screenshots caught the status words in lower case.** The first
  migrated queue showed "pending approval" where the legacy queue, through a
  `text-transform`, showed "Pending Approval". The badge now carries
  `cwe-status`, which capitalises it; the text itself was never changed. The
  focused tests (200 / 200) and the logic check were run again before the full
  run.

---

## 1. Files changed

| File                                                               | Change                                                                                                                                                                        | LOC                       |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `src/pages/ComplianceWorkspace.jsx`                                | The Approvals Queue's render block and the remediation, rollback and log dialog bodies; the decision question's two pieces of state; `CcureAlert` and the stylesheet imported | 5646 → 5444 (+508 / −710) |
| `src/styles/compliance-execution.css`                              | New, page-owned: 85 `--ccure-*` references, 0 colour literals, 0 other custom properties, every selector under `cwe-`                                                         | new, 299                  |
| `src/__tests__/pages/ComplianceWorkspace.execution.test.jsx`       | New: 25 contract + 6 batch 30                                                                                                                                                 | new, 1140                 |
| `scripts/ux4g-harness/lib/fixtures.mjs`                            | Six remediation requests and the findings register with a registered fix                                                                                                      | +70                       |
| `scripts/ux4g-harness/lib/states.mjs`                              | 12 `cw30-` states; `cw29-` in the regression prefixes                                                                                                                         | +203 / −5                 |
| `docs/ux4g/03c-batch30-compliance-credential-bearing-execution.md` | This document                                                                                                                                                                 | new                       |

In the two migrated blocks (legacy against new):

| Measure                                                 | Queue before      | Queue after              | Dialogs before     | Dialogs after                                                                                |
| ------------------------------------------------------- | ----------------- | ------------------------ | ------------------ | -------------------------------------------------------------------------------------------- |
| Lines                                                   | 327               | 358                      | 505                | 266                                                                                          |
| Inline `style` attributes                               | 18                | **0**                    | 42                 | **0**                                                                                        |
| Colour literals (hex / `rgba`)                          | 2 / 1             | **0 / 0**                | 8 / 2              | **0 / 0**                                                                                    |
| `var(--…)` references in markup                         | 5                 | **0**                    | 21                 | **0**                                                                                        |
| `db-`, `.compliance-form` and `mono` class references   | 20                | **0**                    | 16                 | **0**                                                                                        |
| Hand-built buttons / inputs / selects / labels / tables | 5 / 0 / 0 / 0 / 1 | **0 / 0 / 0 / 0 / 0**    | 5 / 6 / 2 / 13 / 0 | **0 / 3 / 0 / 3 / 0** — the two source radios and the bypass checkbox, each inside its label |
| Native textarea                                         | 0                 | 0                        | 1                  | 1 — the key field, which has no primitive                                                    |
| `window.confirm`                                        | 1                 | **0**                    | 0                  | 0                                                                                            |
| `PaginationBar`                                         | 1                 | **0** — `PagingControls` | 0                  | 0                                                                                            |
| Headings                                                | 0                 | 1                        | 2                  | 5                                                                                            |
| Design-system components                                | 0                 | 10                       | 0                  | 12                                                                                           |
| API calls                                               | 3                 | 3                        | 0                  | 0                                                                                            |
| Tests                                                   | 0                 | 31 across both           |                    |                                                                                              |

Across the whole page, inline style attributes are 137 → 77, hex colour literals
21 → 11, `rgba()` 3 → 0, `var(--…)` references in markup 80 → 54, `db-` class
references 49 → 22, `.compliance-form` uses 2 → 0, `mono` classes 8 → 1,
hand-built buttons 18 → 8, inputs 9 → 6, selects 20 → 18, bare labels 17 → 7,
tables 2 → 1, `window.confirm` calls 2 → 1 and `PaginationBar` uses 2 → 1; the
page is 5,646 → 5,444 lines.

Bundle, measured from the two images' web roots:

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 407,745        | 412,272       | +4,527 |
| JS    | 1,576,973      | 1,575,047     | −1,926 |

---

## 2. Accessibility

1. **The queue is a named table under a heading.** A section labelled by its
   `h2`, "Remediation Approvals Queue" (the legacy title was a styled `div`); a
   `CcureTable` with the caption "Remediation approval requests", `scope="col"`
   headers and each ticket id as its row's header. Loading shows skeleton rows
   with a polite status rather than "No approval tickets in this status." while
   the queue is still being read.
2. **Status is a word, and colour only repeats it.** Each status is a badge
   carrying its text; a rollback is marked by a "Rollback" badge. The legacy
   colours gave approved and executed one colour, and failed and rejected
   another.
3. **Every action says which ticket it acts on.** "Approve {ticket}", "Reject
   {ticket}", "Cancel Request {ticket}" or "Cancel Rollback {ticket}", "View Logs
   for {ticket}" and "Rollback {ticket}", each announced as opening a dialog. The
   visible labels are unchanged.
4. **Decisions ask in a real dialog.** Named "Approve remediation request",
   "Reject rollback request" and so on, described by the ticket, control and host,
   with the consequence as its warning. Go back takes focus, so a repeated Enter
   backs out; Escape goes back; focus returns to the action. While the request is
   out the confirm button is busy and disabled and neither Go back nor Escape can
   close the dialog over it.
5. **The queue's pager is the design-system pager** the other migrated tabs use,
   labelled "Approvals pagination", in place of `PaginationBar`'s unnamed « and »
   and unlabelled page-size select.
6. **The dialog has structure.** The guide, the log and each section carry
   headings; the target machine is labelled; a rollback's warning is a
   `CcureAlert` stating the risk in words rather than an orange rule beside a
   paragraph.
7. **The script and the console output can be reached and read.** Each is a
   region named by its heading and in the tab order, so a keyboard user can
   scroll it; the legacy blocks could not be focused. Copy is named "Copy repair
   script".
8. **The credential choice is a named group.** "Execution Credentials" is a
   fieldset and legend around the two source radios; the saved credential, SSH
   username, port, method, password and key each have an associated label. None
   of the legacy fields had one.
9. **The one-time secrets say what happens to them.** The password is the design
   system's password field — masked, with a named visibility toggle — and both it
   and the key are described by "Encrypted with this request; not added to saved
   credentials."
10. **The bypass is described and Dispatch shows its weight.** The emergency
    bypass checkbox is described by its audit note, and its ⚡ is hidden from
    assistive technology; Dispatch is a danger action for a rollback and
    whenever the bypass is ticked, and its 🚀 is hidden too.
11. **Colour and layout** are `--ccure-*` tokens in both themes — the console
    output no longer hard-codes a dark `#272822` panel — and the queue and the
    dialog reflow on a phone.

Measured in the harness: on every Batch 30 capture unlabelled controls fall to
2 — the header's two selects — from 3 on the queue (`PaginationBar`'s
page-size select was the third), 6 on the remediation dialog and 7 on the
rollback dialog, and `PaginationBar`'s « and », the queue's two glyph-only
buttons, are gone. Failing text pairs fall from 14 to 2 in light and 10 to 1 in
dark on the administrator's queue, the approval question and the log, 13 to 2
for the analyst, 8 to 2 on the empty queue, 16 and 15 to 2 and 1 on the
rollback dialog, and 4 and 6 to 2 and 1 on the remediation dialog; every pair
left is the shared chrome's — the header's "Run Compliance Scan" button and, in
light, the tab bar's active label. The four pager buttons disabled on a
one-page queue fall below text contrast, which WCAG exempts for disabled
controls. While a question is open the tab order is the dialog's own three
stops (34 → 3). The console output is reached by Tab with a visible ring on the
migrated build and not at all on the legacy one; the one-time password field is
reached with a visible ring on both, and its visibility toggle carries
`aria-pressed`.

---

## 3. Security and credential exposure

| Requirement                        | Evidence                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Where a one-time secret goes       | Only into `jit_credentials` in the body of the remediate or rollback POST, through the unchanged handlers. The tests fail if either secret reaches a URL, the console or browser storage, and a URL may carry no credential field at all                                                                                                                                 |
| What the server does with it       | Read, not changed: `SecretStr`, encrypted on receipt, held encrypted on the request, and passed encrypted to the worker on a bypass; rejection and cancellation clear the username, encrypted secret, port and method. The dialog's description of the one-time fields and the rejection question say exactly that                                                       |
| Stored credentials                 | Chosen by name and account and sent as `credential_id`; the saved list carries no secret (Batch 29), and neither does the queue's API — the request fixtures carry the fields it lists and no credential                                                                                                                                                                 |
| What the page renders              | Ticket, control, host, command, requester, status and the stored log. No credential is rendered; the log is shown as text as the worker stored it                                                                                                                                                                                                                        |
| Error handling                     | Refusals are shown as the API's `detail` or `message`, unchanged; no refusal path renders or logs a submitted value                                                                                                                                                                                                                                                      |
| Logging                            | None added; the migrated blocks make no `console` call; the page's five are the same                                                                                                                                                                                                                                                                                     |
| Browser autofill                   | The one-time password is `autocomplete="new-password"`, so a browser does not offer the signed-in user's own password into a field that sends someone else's, and a revealed value is not kept in form history                                                                                                                                                           |
| Masking                            | The password stays masked by default; revealing it is an explicit, announced toggle                                                                                                                                                                                                                                                                                      |
| Destructive actions                | Approve, Reject and Cancel ask first, in a dialog a stray Enter cannot confirm and that cannot send twice; Dispatch closes the dialog as it sends, as before, so it cannot be sent twice from it; the bypass needs its own checkbox and turns Dispatch into a danger action                                                                                              |
| Permissions                        | Unchanged: Cancel for the request's creator, Approve and Reject for an organisation admin or superadmin who did not create it, the bypass for an administrator. The server enforces `compliance:remediate`, `compliance:approve_exception`, creator-only cancellation, no self-approval and an administrator-only bypass                                                 |
| No execution from tests or harness | No approval, rejection, cancellation, remediation or rollback request in any capture of the whole catalogue, in all four reports; 0 refused writes and 0 non-GET requests beyond the session refresh in any Batch 30 capture; no capture types a credential, dispatches or copies                                                                                        |
| Test values                        | Synthetic, low-entropy placeholders; no real or realistic credential, key body or token in any test, fixture or state; gitleaks passes on the staged content with no allowlist                                                                                                                                                                                           |
| UX4G guardrails                    | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/` — the strict and broad greps' one match each is `DesignSystemShowcase.jsx`'s header comment, unchanged since `f3348f7` and counted the same way in Batch 29; 0 `ux4g-web-components` imports outside it; 0 UX4G runtime references in `src` or `index.html`; 0 external origins in `index.html` |
| Backend and API                    | No file under `Backend/`, `Frontend/src/api/`, `Frontend/src/design-system/`, `Frontend/src/components/`, `nginx.conf` or `scripts/host-nginx/` changed                                                                                                                                                                                                                  |
| CSP and external assets            | Identical on the pre and post images across six routes, `/compliance` included (42 header lines). Both images' web roots reference the same 7 absolute hosts, with 0 external `<link>`, `<script>`, `@import` or `url()` references. Both bundles carry the design system's 1,332 `--ux4g-*` token properties and 0 `.ux4g-` selectors or `ux4g-` class names.           |

---

## 4. Intentional changes

1. **Approve and Reject ask first.** On the legacy page one click on Approve
   queued a script to run on a customer host with the request's credentials, and
   one click on Reject closed the request and cleared its credentials. Each now
   asks in a `CcureConfirmDialog` that names the ticket, control and host and says
   what will happen; Go back is focused. The POSTs, bodies, notices and re-reads
   are unchanged.
2. **Cancel asks in the same dialog, not the browser's confirm**, with the legacy
   question as its warning. The native confirm focused OK, so a repeated Enter
   cancelled the request.
3. **A decision is busy while its request is out** and cannot be answered twice;
   the legacy buttons could post the same decision again while the first was in
   flight.
4. **Status and rollback are badges with their words**, and the colours now
   separate approved from executed and failed from rejected.
5. **The queue shows each fix command in full**, wrapped, where the legacy
   column cut it off with an ellipsis — an approver can read the whole script
   before approving it.
6. **The queue uses `PagingControls`**, with the same pagination hook, the same
   page sizes (10, 25, 50, 100) and the same noun.
7. **The dialog's fields are labelled and grouped; the one-time password is
   `CcurePasswordField` with `autocomplete="new-password"`; both one-time secrets
   are described; the script and console output are named, focusable regions;
   Copy is named; the rollback warning is a `CcureAlert`.**
8. **Dispatch is a danger action for a rollback or an emergency bypass**, and a
   primary action otherwise. What it sends and when it closes are unchanged.
9. **The blocks no longer use `.db-card`, `.db-table`, `.db-status`, `.db-btn`,
   `.compliance-form` or `mono`**, or hard-coded console colours; the layout is
   `compliance-execution.css`.

---

## 5. What remains in ComplianceWorkspace, and why

| Part                                                                                                                                   | Why it is not in 30                                                                                                                                         |
| -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Gap-analysis dialog                                                                                                                    | Read-only, driven by the header's framework selectors; it holds 23 of the page's 77 remaining inline style attributes and all 11 of its hex colour literals |
| Header — framework selectors, Gap Analysis, Run Compliance Scan, the policy action — the tab bar, the error banner and the loading bar | Shared by every tab and carrying the page-wide scan trigger; the other 54 inline style attributes                                                           |
| The shared dialog container                                                                                                            | Hosts every dialog, these three included, and titles each with its upper-cased type                                                                         |
| `PaginationBar`                                                                                                                        | Now only above the Credentials Manager's list; it can be retired once that pager is replaced                                                                |
| Marketplace's uninstall confirmation                                                                                                   | The page's last `window.confirm`, deferred by Batch 27                                                                                                      |
| `dashboard.css`, `compliance.css`, `scan.css`                                                                                          | Still used by everything above                                                                                                                              |

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-dashboard,cw-marketplace,cw-policies,cw-controls,cw-findings,cw-exceptions,cw-credentials,cw26a-,cw26b-,cw27-,cw28-,cw29-,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-,ns-`
exits 0:

- All 224 unchanged captures are identical in every category — every
  ComplianceWorkspace capture outside this workflow, the Credentials Manager
  and Batches 26A to 29 included.
- pre-b vs post-b is also 224 / 224.
- Post determinism (post-a vs post-b) is 243 / 243.
- The 19 changed captures are the 17 `cw30-` captures and `cw-approvals` in
  both themes.

Every changed category on those 19 captures is accounted for:

| Category                                                                                  | Captures | Why it changed                                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| headings, roles, names, inline, classes, styles, rects, contrast, text, screenshot        | 19       | The queue's `h2` and the dialogs' section headings; the credential group, the named regions and the pager's "Jump to page" group; the labelled fields and the removed glyph buttons; the restyle, badges and descriptions — the failing pairs left are the shared chrome's |
| live, tables                                                                              | 14       | The table's caption, column and row headers and polite status, and the pager's status, on the captures on the Approvals tab                                                                                                                                                |
| tabOrder                                                                                  | 16       | Actions named for their ticket; the question's three stops; the focusable repair script and console output; on a phone the table's scroll region (35 → 36)                                                                                                                 |
| ariaStates                                                                                | 8        | `aria-modal` on the open question (3) and the password visibility toggle's `aria-pressed` (5)                                                                                                                                                                              |
| dialogs                                                                                   | 3        | The approval and cancellation questions                                                                                                                                                                                                                                    |
| probes                                                                                    | 2        | The console output reached by Tab, with a visible ring                                                                                                                                                                                                                     |
| clickable, overflow, errorBoundary, url, theme, requests, writes, offOrigin, csp, runtime | —        | **Unchanged on all 19**: the same requests, no write, every capture on `/compliance`                                                                                                                                                                                       |

Screenshots were reviewed side by side for all 19 captures: the queue for an
administrator in both themes, for an analyst, empty and on a phone; both
questions; the log in both themes; the rollback dialog in both themes; the
remediation dialog in both themes, with a key, with a stored credential and on
a phone; and `cw-approvals` in both themes.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — kept exactly, pinned where marked:

- **Dispatch closes the dialog before the request settles.** There is no
  in-flight state: the result — a refusal, or the page's own "JIT Username is
  required." and "Please select a stored credential." — arrives as a notice after
  the dialog has gone, and the operator has to open it again. (pinned: closes,
  then reports)
- **One-time credentials outlive a refused dispatch.** The username, password
  and key are cleared only when a dispatch succeeds. After a refusal they stay in
  the page's state and are back in the fields — the password masked — the next
  time the dialog opens, for any finding or request. The port, method, credential
  source and chosen stored credential are never reset, and the bypass is reset
  only on success. (pinned: the username is kept)
- **The emergency bypass has no second question.** Ticking it and pressing
  Dispatch runs the script at once, skipping approval. Dispatch now turns into a
  danger action when it is ticked; a confirmation step would be a dialog inside
  the shared container, which this batch does not change.
- **The dialogs are titled "REMEDIATE", "ROLLBACK" and "LOG_VIEWER"** — the shared
  container upper-cases the dialog's type. Batch 26B's views test pins the
  container's titles. (pinned)
- **The typed secret is in the DOM while it is being typed.** Both one-time fields
  are React-controlled, as on the Credentials Manager: anything that serialises
  the DOM sees the value until it is cleared. The legacy fields did the same.
- **The key field is spell-checked and shows the key in clear while typed.**
- **The client's gates are a role name and a user id; the server's are
  permissions.** Approve, Reject and the bypass are offered by role name, while
  the server requires `compliance:approve_exception` and its own administrator
  test — Batch 27's Marketplace finding and Batch 29's, on a third surface.
  (pinned)
- **A cancelled request is stored as "rejected".** The server gives a
  cancellation the rejected status and records the canceller as its approver, so
  the queue cannot tell the two apart. Backend, not changed.
- **The log is shown as stored.** The page adds no redaction of its own and relies
  on the worker's pattern-based sanitiser, which masks `key: value` forms, URL
  user information, PEM private keys and `echo … | sudo -S`; a secret a script
  prints in another shape would be shown. Backend, not changed.
- **A validation refusal whose `detail` is a list** would read "Remediation
  error: [object Object]", as on the Credentials Manager. No submitted value is
  shown.
- **After a decision settles focus returns to the action that opened it**, which
  the queue's re-read may have removed.
- **In the dark theme the question's backdrop lightens the page behind it**
  rather than dimming it. It is `CcureConfirmDialog`'s own backdrop, the one
  Batch 29's deletion dialog uses; no design-system primitive changes here.
- **`PaginationBar` stays above the Credentials Manager's list** — unnamed « and
  », an unlabelled page-size select — as its only user, until that tab's pager is
  replaced.
- **Harness:** no capture approves, rejects, cancels, dispatches, copies or types;
  those requests are proven by the unit contract. On the legacy build the two
  question states click the queue's title. One state ticks the bypass checkbox,
  which changes only the dialog's own state. The runner's orphaned-browser issue
  recorded in Batch 29 stands.

**Carried:** every item deferred by Batches 16 to 29 stands unchanged — among
them Batch 29's credential-manager findings, Batch 28's evidence findings, Batch
27's in-flight, role-gate and native-confirm findings for the ordinary writes,
the shared header and tab-bar issues, the shared loader's raw error logging, the
shared CcureModal outside-click issue, the Batch 26B view issues, and the AMT,
NetworkMap, ScanHistory, CredentialedResults, Phase3Results and NewScan items —
and none was reopened here.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was reached:

- the queue read and its poll, the cancel, approve and reject requests and
  bodies, the remediate and rollback handlers, and every notice are unchanged and
  pinned; the creator, administrator and bypass gates are unchanged;
- outside the two blocks and their two state lines the page is byte-identical to
  `f3348f7`, and the Credentials Manager, attestation and evidence, gap analysis,
  the dialog container, the page chrome, `PaginationBar`, a design-system
  primitive, a shared component or a global stylesheet were not modified;
- the one-time password and key reach only the request body — never a URL, the
  console, storage or the page's text — and no secret-shaped value was added;
- approving, rejecting and cancelling ask in a design-system dialog that a stray
  Enter cannot confirm and that cannot send twice — the behaviour change, pinned;
- no backend or API file changed, and no logging was added;
- no approval, rejection, cancellation, remediation, rollback, credential
  submission, unexpected navigation, off-origin request, CSP issue, exception or
  console error in any capture, and no secret in any report;
- determinism, sensitivity and the regression gate over every previously
  migrated page and the rest of ComplianceWorkspace passed;
- security headers, the air-gap host set and the UX4G guardrails are unchanged.

Batch 31 is not started.
