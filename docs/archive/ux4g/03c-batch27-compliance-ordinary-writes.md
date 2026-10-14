# Checkpoint 3C — Batch 27: ComplianceWorkspace's ordinary writes on the design system

Batches 26A and 26B moved ComplianceWorkspace's read-only surface. Batch 27
moves its **ordinary authenticated writes** — the writes that change tenant
configuration or compliance records and carry no credential, no upload and no
remote execution:

- **Marketplace** — install and uninstall a framework;
- **Create Policy Baseline** — the dialog body;
- **Configure Rule Parameters** — the dialog body, opened from a policy's rules
  or from a finding;
- **Request Exception Waiver** — the dialog body, opened from a failed finding.

## The batch boundary

Inspection of the remaining workspace decided it, and the deciding facts were in
the code rather than in the tab names:

| Surface                                                | What it actually does                                                                                                                                                                                             | Class                        | In 27 |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- | ----- |
| Marketplace                                            | `POST /compliance/marketplace/{id}/install` and `/uninstall` (`manage_frameworks`); uninstall behind `window.confirm`; enabled only for an organisation admin or superadmin                                       | Ordinary write               | Yes   |
| Create Policy Baseline                                 | `POST /compliance/policies` (`manage_rules`)                                                                                                                                                                      | Ordinary write               | Yes   |
| Configure Rule Parameters                              | `PUT /compliance/rules/{id}` (`manage_rules`); shows the finding's collected evidence value                                                                                                                       | Ordinary write               | Yes   |
| Request Exception Waiver                               | `POST /compliance/findings/{id}/exception` (`attest`)                                                                                                                                                             | Ordinary write               | Yes   |
| Approvals Queue                                        | Approving commits the request and dispatches `run_reremediation_task` against the target host with the request's stored credential; the queue shows fix commands and opens execution logs and the rollback dialog | Credential-bearing execution | No    |
| Credentials Manager                                    | Password and key fields; create and delete                                                                                                                                                                        | Credentials                  | No    |
| Remediation and rollback dialog                        | Ad-hoc SSH credentials, emergency bypass                                                                                                                                                                          | Credentials                  | No    |
| Attestation dialog                                     | Evidence upload and delete                                                                                                                                                                                        | Uploads                      | No    |
| Gap-analysis dialog                                    | Read-only, launched from the header with its own framework selectors                                                                                                                                              | Page chrome                  | No    |
| Log viewer dialog                                      | Remediation console output                                                                                                                                                                                        | Remediation                  | No    |
| Shared dialog container, header, tab bar, scan trigger | Shared by every tab and dialog                                                                                                                                                                                    | Shared infrastructure        | No    |

Approvals looked like an ordinary approve/cancel queue and is not: approval is
the moment a remediation runs on a customer host. It belongs with the credential
and remediation work, not here.

The batch is presentation and accessibility only, and the rest is pinned:

- **Everything outside the three migrated blocks is the code that was here.**
  Removing exactly what Batch 27 added — one design-system import and the
  stylesheet import — and putting the three legacy blocks back yields the page at
  `61c0fd3` byte for byte (5,514 lines).
- **Everything inside them that decides anything is unchanged.** 42 logic
  fragments — every field's value and change handler, the platform and severity
  options, the rule-ID placeholder, the submit handlers, the evidence JSON, the
  install and uninstall handlers, the admin gating, the disabled state and the
  tooltip — occur in the new blocks; each block's handler call sites are the same
  multiset. The handlers themselves (`handleInstallFramework`,
  `handleUninstallFramework`, `handleCreatePolicy`, `handleSubmitEditRule`,
  `handleSubmitException`, `handleOpenEditRule`) are outside the blocks and
  byte-identical.
- **Writes, unchanged:** endpoints, methods, payloads, the confirmation text, the
  success notices and re-reads, and the failure notices with the API's detail.

**Baseline:** HEAD `61c0fd3` (Batch 26B).

**Not touched:** everything in the "No" rows above; `dashboard.css`,
`compliance.css` (whose `.compliance-form` the attestation, remediation and log
dialogs still use), `scan.css` and the rest of the legacy CSS chain; the
backend, the API client, `App.jsx`, AppLayout, every design-system primitive,
`nginx.conf`, CSP and `scripts/host-nginx/nginx-host.conf`.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `61c0fd3`                                                                                                                                                                                                                                     |
| Tests first, on the page before migration   | 30 tests: the 24 contract tests pass, and the 6 batch 27 tests all fail, each for its intended reason                                                                                                                                                               |
| Trial replay, unchanged build               | The 13 captures (`cw27-` and `cw-marketplace`) taken twice: **13 / 13** identical and every one clean; in each dialog the keyboard probe reaches a field. The unchanged image carries none of the Batch 27 code                                                     |
| Baseline, unchanged build                   | 210 captures ready, twice. Determinism **210 / 210**, sensitivity **22 / 22**                                                                                                                                                                                       |
| Same tests, migrated                        | **24 / 24** contract tests and **6 / 6** batch 27 tests; Batch 26B's **52 / 52** and Batch 26A's **21 / 21** unchanged                                                                                                                                              |
| Logic unchanged                             | Outside the three migrated blocks the page is byte-identical to `61c0fd3`; 42 logic fragments inside them unchanged; each block's handler call sites the same                                                                                                       |
| Full frontend suite                         | 61 files, **2316** tests, all passing (2286 + 30)                                                                                                                                                                                                                   |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                 |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                   |
| Pre-commit formatting                       | Every Batch 27 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                          |
| UX4G guardrails                             | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/`; 0 `ux4g-web-components` imports outside it; 0 UX4G runtime references in `src` or `index.html`                                                                                            |
| Post determinism                            | post-a vs post-b **210 / 210** identical                                                                                                                                                                                                                            |
| Unchanged states                            | Every previously migrated page, Batches 26A and 26B's captures, and ComplianceWorkspace's Dashboard, Controls, Policies, Findings, Exceptions, Credentials and Approvals tabs: **197 / 197** captures identical pre → post in every category, on both capture pairs |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                         |
| Batch 27 requests                           | Identical before and after in every Batch 27 capture (0 deltas). The only compliance reads are the marketplace, the summaries, the baselines, one baseline's rules and the findings; no credential, remediation, evidence, report, scan or gap-analysis read        |
| Placeholders                                | No harness token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any Batch 27 capture                                                                                                                                              |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines)                                                                                                                                                                    |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts, with 0 external `<link>`, `<script>`, `@import` or `url()` references. Both bundles carry the design system's 1,332 `--ux4g-*` token properties and 0 `.ux4g-` selectors or `ux4g-` class names         |
| Writes, navigations, off-origin, CSP issues | 420 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every Batch 27 capture ends on `/compliance` in all four reports      |
| Screenshots                                 | All 13 Batch 27 captures reviewed side by side, pre and post. No regression                                                                                                                                                                                         |

### 0.1 The writes in tests and in the harness

`src/__tests__/pages/ComplianceWorkspace.writes.test.jsx` mounts the real page
with only the axios instance, the shell and the signed-in user replaced, and
`window.confirm` spied. Its `afterEach` fails any test that deleted or patched
anything, posted or put anywhere but the four ordinary writes, or read
credentials, evidence, remediation requests or reports.

**The contract (24 tests, passing on the page before migration and after):**

- **Marketplace (8).** The tab's read and each framework's code, version,
  requirement count, installed state and action; for an analyst, both actions
  disabled with the permission reason as their tooltip and nothing sent or
  confirmed on a click; for an organisation admin and for a superadmin, one
  `POST …/install` with no body, the success notice and a quiet re-read; a
  refused install reporting the API's detail or the error's message; uninstall
  asking with the exact confirmation text, declining sending nothing, confirming
  posting once and re-reading, and a refusal reporting its message; an install in
  flight leaving the button enabled.
- **Create Policy Baseline (4).** Opening from the Policies header with two
  required text fields, the rule-ID placeholder, the platform choice defaulting
  to Any and a submit button, and closing by button or Escape sending nothing;
  publishing the name, platform and trimmed, non-empty rule IDs for ISO 27001
  when All Frameworks is selected, closing, notifying and re-reading; the chosen
  framework's ID when one is selected; a refusal keeping the dialog open with the
  API's detail, the button enabled while the request is out.
- **Configure Rule Parameters (9).** Prefilled heading, control, severity,
  expected value and evidence from Configure; for each of the five severities,
  the edited definition, lower-case severity and weight (10, 7, 5, 2, 0), then
  closing, notifying and re-reading; a numeric expected value sent as a number
  when it parses and as typed when it does not; from Findings, Medium when the
  finding has no severity, the finding's evidence JSON, and a re-read of the
  findings; a refusal keeping the dialog open with the detail.
- **Request Exception Waiver (3).** A required reason and expiry date, closing
  sending nothing; the reason and the expiry as an ISO timestamp, then closing,
  notifying and re-reading the findings; a refusal keeping the dialog open with
  the detail.

**The specification (6 tests, each failing on the page before migration for its
intended reason):** a section headed "Framework Marketplace" of cards named by
their `h3`, with an Installed badge; a disabled action described by the visible
permission reason; the Create Policy Baseline fields labelled, required and the
rule-ID format hinted; the Configure Rule Parameters fields labelled and the
evidence shown as code under an `h3`; the waiver's reason and expiry labelled; no
inline style or legacy class in the migrated markup, and a token-only,
prefix-scoped stylesheet.

**Harness states (7 states, 11 captures),** all on `/compliance`. None installs,
uninstalls, submits a dialog, approves or opens a credential, remediation,
attestation or evidence flow; opening these dialogs sends nothing:

| State                       | Persona, themes, viewport         | What it shows                                                                |
| --------------------------- | --------------------------------- | ---------------------------------------------------------------------------- |
| `cw27-marketplace-admin`    | organisation admin; light, dark   | Three frameworks, two installed, with enabled actions                        |
| `cw27-marketplace-analyst`  | analyst; light                    | The same, actions disabled with the permission reason                        |
| `cw27-marketplace-mobile`   | organisation admin; light, 390 px | The marketplace on a phone                                                   |
| `cw27-policy-dialog`        | analyst; light, dark              | Create Policy Baseline open; Tab reaches a field inside it                   |
| `cw27-rule-dialog`          | analyst; light, dark              | Configure Rule Parameters open from a baseline's rule; Tab reaches its field |
| `cw27-waiver-dialog`        | analyst; light, dark              | Request Exception Waiver open from a failed finding; Tab reaches the reason  |
| `cw27-waiver-dialog-mobile` | analyst; light, 390 px            | The waiver dialog on a phone                                                 |

The harness's `CW27_ORG_ADMIN` persona is `ANALYST` with the role named "Org
Admin"; nothing else about the operator changes.

### 0.2 Corrections

No contract assertion was changed. These were, and none of them is a gate:

- **The new stylesheet's header comment named `!important`**, which the
  specification's token check refuses anywhere in the file. The comment was
  reworded; the check was not.
- **Harness helper scripts derived from Batch 26B's needed correcting before
  use.** A text substitution left the capture report's state filter on Batch
  26B's states, and a one-line generator for the analysis and review scripts
  failed on shell escaping and wrote nothing, so those two were written
  directly. None of them lives in the repository, and none had produced a
  result.
- **The first post-migration run stopped at its unit gates** on AMTIntegration's
  "a rejected upload shows the API's detail or a default" — the load flake
  recorded since Batch 24, in a file this batch does not touch. The gate ran no
  captures. The file passed alone (47 / 47) and the flow was run again from the
  start, every unit gate passing.
- **In that second run the first capture pass died at startup**: the harness
  runner's DevTools WebSocket to Chrome errored before any page loaded, so the
  pass produced no report and the steps reading it could not run. The post
  container was still serving and the tree and image were unchanged, so that pass
  was captured again against the same container and every dependent step —
  determinism, both regression diffs, sensitivity, the analysis and the
  composites — was run again. The figures here are from that run.
- **The broad guardrail grep counted one `ux4g-` mention outside the design
  system**: a sentence in `DesignSystemShowcase.jsx`'s header comment stating
  that nothing uses a `ux4g-` class, unchanged since before this batch. A check
  for class names, selectors and imports finds none.

---

## 1. Files changed

| File                                                      | Change                                                                                                                | LOC                       |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `src/pages/ComplianceWorkspace.jsx`                       | The Marketplace block and the three dialog bodies; `CcureField` and the stylesheet imported                           | 5514 → 5526 (+133 / −121) |
| `src/styles/compliance-writes.css`                        | New, page-owned: 34 `--ccure-*` references, 0 colour literals, 0 other custom properties, every selector under `cww-` | new, 139                  |
| `src/__tests__/pages/ComplianceWorkspace.writes.test.jsx` | New: 24 contract + 6 batch 27                                                                                         | new, 888                  |
| `scripts/ux4g-harness/lib/fixtures.mjs`                   | An organisation-admin persona and a three-framework marketplace                                                       | +37                       |
| `scripts/ux4g-harness/lib/states.mjs`                     | 7 `cw27-` states; `cw26b-` in the regression prefixes                                                                 | +113 / −6                 |
| `docs/ux4g/03c-batch27-compliance-ordinary-writes.md`     | This document                                                                                                         | new                       |

In the three migrated blocks (Marketplace / Create Policy Baseline / Configure
Rule Parameters and Request Exception Waiver, where split):

| Measure                                               | Before        | After         |
| ----------------------------------------------------- | ------------- | ------------- |
| Inline `style` attributes                             | 9 (2 / 1 / 6) | **0**         |
| Colour literals                                       | 1             | **0**         |
| `dashboard.css` and `compliance.css` class references | 25            | **0**         |
| Hand-built buttons / inputs / selects                 | 5 / 4 / 2     | **0 / 0 / 0** |
| Labels with no associated field                       | 7             | **0**         |
| Tests                                                 | 0             | 30            |

In the harness, the dialogs' unlabelled controls fall from 5 (Create Policy
Baseline) and 4 (Configure Rule Parameters and Request Exception Waiver) to the 2
header selects the page still carries. Every failing text pair left on the Batch
27 captures belongs to the shared chrome — the header's "Run Compliance Scan"
button and, in light, the tab bar's active label. Disabled controls, which
WCAG 1.4.3 exempts, are counted separately, and their counts are the same
before and after.

Across the whole page, inline style attributes are 176 → 167, `db-` class
references 73 → 63, `compliance.css` class references 19 → 4, hand-built buttons
27 → 22, inputs 18 → 14, selects 24 → 22 and bare labels 36 → 29.

Bundle, measured from the two images' web roots:

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 402,468        | 404,399       | +1,931 |
| JS    | 1,576,094      | 1,575,994     | −100   |

---

## 2. Accessibility

1. **Marketplace is a named region of named cards.** A section headed
   "Framework Marketplace"; each framework a `CcureCard` section named by its
   `h3`. The padlock is decorative and hidden from assistive technology; the
   installed state is a badge with its word, not a colour.
2. **A disabled action says why, to everyone.** The legacy buttons carried the
   reason only in a `title`, which a keyboard or screen-reader user never reaches
   on a disabled control. The reason is now a visible sentence the button is
   described by; the tooltip is kept.
3. **Every dialog field has an associated label.** The legacy `<label>` elements
   were siblings with no `for`, so no field had an accessible name. Required
   fields are marked visibly and announced as required.
4. **The rule-ID format is a hint, and the current evidence describes the
   expected value** — both reach a screen reader with the field.
5. **The rule dialog's subject is a heading** (`h3` under the dialog's `h2`).
6. **Keyboard.** Native buttons, inputs, selects and a textarea, in document
   order inside the dialog's focus trap; the harness tabs to a field in each
   dialog and records a visible focus ring, before and after.
7. **Colour and layout** are `--ccure-*` tokens in both themes; below 640 px the
   marketplace is a single column; no capture overflows horizontally.

---

## 3. Security and API behaviour

| Requirement                        | Evidence                                                                                                                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Endpoints, methods, payloads       | All four writes pinned with their exact URL, method and body; handlers byte-identical                                                                                    |
| Success and failure                | Notices, dialog closing, re-reads and the API's detail on failure pinned for each write                                                                                  |
| Destructive action                 | Uninstall still asks with the same `window.confirm` text; declining sends nothing                                                                                        |
| Permissions                        | Unchanged: install and uninstall enabled only for an organisation admin or superadmin; the dialogs have no client gate, and the server's refusal is shown                |
| No other writes                    | No test deletes or patches anything; 0 refused writes and 0 non-GET requests beyond the session refresh in any Batch 27 capture, in all four reports                     |
| Credentials, evidence, remediation | Never read by any test or capture in this batch                                                                                                                          |
| Logging                            | None added; the page's five `console` calls are the same                                                                                                                 |
| Sensitive data                     | The rule dialog shows the finding's collected evidence value, as before; no credential, token, ticket or placeholder secret in any report; no `dangerouslySetInnerHTML`  |
| UX4G guardrails                    | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/`, 0 `ux4g-web-components` imports outside it, 0 UX4G runtime references in `src` or `index.html` |
| Backend and API                    | No file under `Backend/`, `Frontend/src/api/`, `nginx.conf` or `scripts/host-nginx/` changed                                                                             |
| External assets                    | The post web root references the same 7 hosts as the pre, with 0 external `<link>`, `<script>`, `@import` or `url()`                                                     |

---

## 4. Intentional changes

1. **Marketplace** is a headed section; each framework is a design-system card
   with its name as its heading. "✓ Installed" is an Installed badge; the empty
   placeholder beside Install is gone.
2. **Disabled actions show their reason as text** under the card, and the
   buttons are described by it; the inline opacity and cursor styles are replaced
   by the design system's disabled state.
3. **Create Policy Baseline:** "Rules IDs (comma separated)" reads "Rule IDs"
   with the hint "Comma separated."; fields are labelled and marked required.
4. **Configure Rule Parameters:** "Editing Rule:" is a heading; the current
   evidence value is the expected field's description rather than a separate
   paragraph.
5. **The dialog forms no longer use `.compliance-form`**, whose rules force every
   field's styling and the submit button's size; the submit buttons are
   full-width design-system buttons.

---

## 5. What remains in ComplianceWorkspace, and why

| Part                                                                                                                              | Why it is not in 27                                                        |
| --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Approvals Queue, with its log viewer and rollback trigger                                                                         | Approval dispatches remediation on the target host with stored credentials |
| Credentials Manager                                                                                                               | Password and key fields; create and delete                                 |
| Remediation and rollback dialog                                                                                                   | Ad-hoc credentials and emergency bypass                                    |
| Attestation dialog                                                                                                                | Evidence upload and delete                                                 |
| Gap-analysis dialog                                                                                                               | Read-only, driven by the header's selectors                                |
| Header (framework, scoping and gap selectors, Gap Analysis, Run Compliance Scan, Create Baseline Policy), tab bar, banner, loader | Shared by every tab; carries the page-wide scan trigger                    |
| The shared dialog container                                                                                                       | Hosts the credential, upload and remediation dialogs too                   |
| `PaginationBar`                                                                                                                   | Still used by Credentials and Approvals                                    |
| `dashboard.css`, `compliance.css`, `scan.css`                                                                                     | Still used by everything above                                             |

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-dashboard,cw-controls,cw-policies,cw-findings,cw-exceptions,cw-credentials,cw-approvals,cw26a-,cw26b-,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-,ns-`
exits 0:

- All 197 unchanged captures are identical in every category — Batch 26B's 17
  view captures and Batch 26A's eight Exceptions captures included.
- pre-b vs post-b is also 197 / 197.
- Post determinism (post-a vs post-b) is 210 / 210.
- The 13 Batch 27 captures changed: `cw-marketplace` in both themes and the 11
  `cw27-` captures.

Every changed category on those 13 captures is accounted for:

| Category                                                                                                                                                             | Captures | Why it changed                                                                                                                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| headings                                                                                                                                                             | 6        | "Framework Marketplace" and the framework cards' `h3` on the six Marketplace captures                                                                           |
| names                                                                                                                                                                | 7        | The dialog fields' associated labels on the seven dialog captures                                                                                               |
| inline, classes, styles, rects                                                                                                                                       | 11       | The restyle on the `cw27-` captures; `cw-marketplace`'s thin fixture has no frameworks to restyle                                                               |
| contrast, text, screenshot                                                                                                                                           | 13       | The restyle and the new heading; the only failing pairs left are the shared chrome's                                                                            |
| The other 17 — roles, ariaStates, dialogs, live, tables, clickable, tabOrder, probes, overflow, errorBoundary, url, theme, requests, writes, offOrigin, csp, runtime | —        | **Unchanged on all 13**: the same dialog container and roles, the same tab order and probe results, the same requests, no write, every capture on `/compliance` |

Screenshots were reviewed side by side for all 13 captures: the marketplace as an
organisation admin in both themes, as an analyst, and at 390 px; the empty
regression marketplace in both themes; each dialog open, in both themes where
captured, and the waiver dialog at 390 px.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — all kept exactly, and pinned where marked:

- **No write has an in-flight state.** Install, uninstall and all three dialog
  submits stay enabled while their request is out, so a second click sends a
  second request. (pinned)
- **The Marketplace gate is a role name, the server's is a permission.** The UI
  enables install and uninstall for a role named organisation admin or
  superadmin; the server requires `compliance:manage_frameworks`. A user holding
  the permission under another role sees the actions disabled, and a user with
  the role but not the permission is refused by the server. (pinned as found)
- **Uninstall is confirmed with the browser's native `window.confirm`**, not a
  design-system dialog; replacing it changes the flow and is left for the
  dialog-container work. (pinned)
- **An empty marketplace shows nothing** beneath its heading.
- **The Create Policy Baseline fields keep their values** after publishing or
  closing, as do the waiver's reason and expiry; the rule IDs start as an empty
  array rather than an empty string.
  Only the browser's `required` check stops a submit before anything is typed; if
  it were bypassed, the handler would fail on `.split` and report that as a
  failed create.
- **With All Frameworks selected, a baseline is created for ISO 27001** without
  saying so.
- **The rule dialog's severity weights are fixed in the client** (10, 7, 5, 2, 0),
  and when the rule's current expected value is a number the new one is parsed
  with `parseInt`, so "7.5" is sent as 7.
- **The waiver expiry is converted with `new Date("YYYY-MM-DD")`**, which is UTC
  midnight, and the client accepts a past date.
- **Every failure is a notice only**; none is shown on the field it concerns.
- **Harness:** dialogs are opened and never submitted, so the writes' network
  behaviour is proven by the unit contract, not by a capture; the runner can die
  at startup on its DevTools connection (§0.2).

**Carried:** every item deferred by Batches 16 to 26B stands unchanged — among
them the shared header and tab-bar issues, the shared loader's raw error logging,
the shared CcureModal outside-click issue, the Batch 26B view issues, and the
AMT, NetworkMap, ScanHistory, CredentialedResults, Phase3Results and NewScan
items — and none was reopened here.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was reached:

- all four ordinary writes — endpoint, method, payload, confirmation, success and
  failure handling — are unchanged and pinned, and opening or closing a dialog
  sends nothing;
- install and uninstall keep their admin gate, and the reason is now reachable
  without a mouse;
- outside the three migrated blocks the page is byte-identical to `61c0fd3`, and
  no other tab, dialog, the dialog container, the page chrome, a design-system
  primitive, a shared component or a global stylesheet was modified;
- no backend or API file changed, no credential, evidence or remediation path was
  touched, and no logging was added;
- no write, unexpected navigation, off-origin request, CSP issue, exception or
  console error in any capture, and no secret in any report;
- determinism, sensitivity and the regression gate over every previously migrated
  page and the rest of ComplianceWorkspace passed;
- security headers, the air-gap host set and the UX4G guardrails are unchanged.

Batch 28 is not started.
