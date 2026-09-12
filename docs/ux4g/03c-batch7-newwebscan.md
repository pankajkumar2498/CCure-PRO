# Checkpoint 3C — Batch 7: NewWebScan (scan dispatch)

**Scope:** `src/modules/web-scanning/pages/NewWebScan.jsx` — one page, alone
**Date:** 10 September 2026
**Recommendation:** **GO**

Harness changes are documented separately in
[`03c-batch7-harness.md`](03c-batch7-harness.md). No application file was
touched while that work was done.

---

## 1. Candidate and baseline summary

One page, selected by the brief rather than by ranking, because it is the
web-scanning **dispatch surface**: submitting this form makes this host send
ffuf and nuclei at a URL the operator typed.

| Metric                              |                                                             Baseline |
| ----------------------------------- | -------------------------------------------------------------------: |
| LOC                                 |                                                                  564 |
| Inline style objects                |                                                                   39 |
| Colour literals                     |                                                                    3 |
| `<input>` / `<select>`              |                                                                9 / 1 |
| `<label>` elements                  |                                                                   10 |
| …of which carry `htmlFor`           |                                                                **0** |
| `role="alert"`                      |                                                                **0** |
| `role="status"`                     |                                                                    1 |
| `aria-invalid` / `aria-describedby` |                                                                0 / 0 |
| Headings                            |                                        `h1` ×1, `h3` ×3 (skips `h2`) |
| Existing tests                      | **none** (the page was only mocked, in `WebScanningRoutes.test.jsx`) |

Measured on the live rendered surface: **32 unlabelled controls** across two
auth states × two themes, **130 inline-styled elements**.

Full suite before the batch: **804/804**. With the new assertions added:
**872 tests, 863 passing, 9 failing** — every failure one of the new
accessibility/surface assertions.

## 2. Exact security contracts verified

The strongest evidence first: **the dispatch code is character-identical to
`HEAD`.** `diff` over `createLaunchKey`, the whole of `handleSubmit`, and the
`formData` initialiser returns no differences. Since `handleSubmit` calls
`webScansApi.startScan({ ...formData, _idempotencyKey })` unchanged, and
`formData`'s shape is unchanged, the normaliser receives byte-identical input
and the wire payload cannot differ.

That is a structural argument. It is backed by assertions that mock
`axiosInstance` rather than `webScansApi`, so the **real**
`normalizeStartPayload`, `normalizeAuthConfig` and `btoa` run and the bytes
leaving the browser are pinned:

| Contract                                        | Verified                                                                                                              |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Endpoint and method                             | `POST "/web-scans"`, exactly once, no query string                                                                    |
| Payload keys                                    | `auth`, `authorization_confirmed`, `options`, `scan_name`, `scan_scope`, `target_url` — and nothing else              |
| `scan_scope` keys                               | `exclude_paths`, `include_subdomains`, `max_depth`                                                                    |
| `options` keys                                  | `enable_sqli`, `enable_xss`, `nuclei_severity`, `rate_limit`                                                          |
| Scan defaults                                   | `enable_sqli:true`, `enable_xss:true`, `nuclei_severity:["medium","high","critical"]`, `rate_limit:10`, `max_depth:3` |
| Target                                          | sent exactly as typed                                                                                                 |
| `authorization_confirmed`                       | `true` only when ticked; dispatch refused otherwise                                                                   |
| Idempotency                                     | `Idempotency-Key` header present; **one** POST per click, none after success; a **fresh** key after a failure         |
| Depth → `max_depth`, concurrency → `rate_limit` | carried through                                                                                                       |
| `auth` = none                                   | `{ type: "none" }`, no credential material                                                                            |
| `auth` = bearer                                 | `{ type: "bearer_token", token }`, token verbatim                                                                     |
| `auth` = cookie                                 | `{ type: "cookie", cookies: {…} }`, parsed to a map                                                                   |
| `auth` = basic                                  | `{ type: "custom_header", headers: { Authorization: "Basic " + btoa("user:pass") } }` — **encoding unchanged**        |
| Navigation                                      | `navigate("/web-scans/<id>", { replace: true })` on success; `navigate(-1)` on cancel                                 |
| Scan-id extraction                              | `id` → `web_scan_id` → `data.id`; absence is a failure, not a success                                                 |
| Error precedence                                | API `detail` → `err.message` → generic string                                                                         |
| No auto-retry                                   | none, over a simulated 120 s                                                                                          |
| No polling, no mount request                    | none                                                                                                                  |
| No other network call while launching           | `get`/`patch`/`delete` never invoked                                                                                  |

### Credential handling

| Check                                                       | Result                                                    |
| ----------------------------------------------------------- | --------------------------------------------------------- |
| Password rendered as a password control                     | yes, `type="password"`                                    |
| Password visibility behaviour                               | **unchanged** — no reveal control exists, before or after |
| Credential in the request URL                               | never                                                     |
| Credential in any accessible name, `title` or `placeholder` | never                                                     |
| Credential in rendered text                                 | never                                                     |
| Credential written to `console`                             | never — asserted on the failure path, where the page logs |
| Credential material after switching back to `none`          | dropped; payload contains no trace                        |
| New telemetry or network request                            | none                                                      |

**`CcurePasswordField` was deliberately NOT used.** It owns a visibility
toggle, a caps-lock warning and a strength meter. The toggle would change this
page's password-visibility behaviour, which this batch may not do; and a
strength meter is meaningless for a credential the operator is _supplying_ to
authenticate against somebody else's site rather than choosing.
`CcureInput type="password"` is the correct primitive, and an assertion pins the
absence of a reveal control so a later batch cannot add one by accident.

## 3. Tests before migration

**68 assertions written against the unmigrated page: 59 passing, 9 failing.**
The 9 are the migration's specification, all accessibility or rendered-surface.

### One assertion of mine was wrong, and correcting it found a real defect

"carries crawl depth into max_depth and concurrency into rate_limit" failed
against a page that maps them correctly. The cause was my typing technique —
and probing it empirically turned up something worth reporting:

```
initial value: 3
after clear:   3      ← onChange fires with "", parseInt("")||3 snaps it back
after type 7:  37     ← the keystroke appends to the restored "3"
checkValidity: false  (max="10")
```

So on the live page, **a user who clears the Crawl Depth field and types `7`
gets `37`**, which fails native validation and silently blocks submission with
only a browser tooltip. Same shape on Concurrency. That is caused by
`parseInt(e.target.value) || 3`, which is validation behaviour and therefore
out of scope for this batch — recorded in §16, preserved exactly.

The assertion was corrected to use a single `change` event, which is what
select-all-and-type actually produces, and it was testing my technique rather
than the payload mapping.

### One helper of mine was wrong

`launch()` queried the submit control by the name _"Launch Scan"_, but the
button's text becomes _"Starting Scan…"_ while a launch is in flight — so it
stopped finding the control exactly when the loading assertions needed it.
Re-anchored to match either.

**No assertion was weakened.** Nothing was deleted from functional coverage.

## 4. Tests after migration

**68/68 on the first run after migration**, with no re-anchoring required —
the field accessors were written to resolve by accessible name with a
structural fallback, so they addressed the same controls on both sides.

Full suite: **872 tests, 872 passing, 28 files.** Lint clean at
`--max-warnings=0`. Production build green.

## 5. Defects discovered

1. **Not one text, url, number or select control on this form had an accessible
   name.** Ten `<label>` elements, none with `htmlFor`, every input a _sibling_
   of its label rather than a child. That includes the **Target URL** — the
   field that decides what this host attacks — and both **basic-auth credential
   fields**. Measured: 5 unlabelled controls in the default state, 7 with basic
   auth selected, in both themes.
2. **A refused launch was never announced.** The error banner was a plain
   `<div>` with no `role`, on the one control in this product that fires an
   outbound scan.
3. **Heading levels skipped** `h1` → `h3`.
4. **The authorization declaration measured 4.41:1** — below AA. That is the
   sentence "I confirm that I am explicitly authorized to perform security
   scanning on this target", composited over its own amber panel.
5. **Clearing a numeric field snaps it back to the default and the next
   keystroke appends** (`3` → type `7` → `37`), silently blocking submission.
   Out of scope; see §16.

## 6. Accessibility and contrast, before → after

Live rendered surface, both themes, both auth states, every `rgba()`
composited through its real ancestor chain. Floors 4.5 / 3.0.

|                                       | Control | Migrated |
| ------------------------------------- | ------: | -------: |
| Text elements measured                |      36 |       48 |
| **Sub-AA on enabled elements**        |   **2** |    **0** |
| Worst enabled value                   |  4.41:1 |   4.55:1 |
| Exempt (disabled control, WCAG 1.4.3) |       2 |        4 |

The two sub-AA values were the authorization declaration in both auth states.
The migrated panel keeps the amber edge as a supporting cue and carries the
meaning in the sentence, which is what a reader who cannot distinguish the
colour actually gets.

| Structural                                        |          Control |         Migrated |
| ------------------------------------------------- | ---------------: | ---------------: |
| Unlabelled controls — default state               |                5 |            **0** |
| Unlabelled controls — basic auth                  |                7 |            **0** |
| Inline-styled elements (both states, both themes) |              130 |            **0** |
| Heading sequence                                  | `h1, h3, h3, h3` | `h1, h2, h2, h2` |
| Unnamed buttons                                   |                0 |                0 |
| Horizontal overflow                               |             none |             none |

Also asserted: required state exposed on both required fields; the auth-mode
select named; a launch failure announced through `role="alert"`; launch progress
announced politely through `role="status"` (preserved, not introduced); the
submit control reporting `aria-busy` while in flight; the whole form completable
with the keyboard alone, ending in a real dispatch.

**Carried forward, not fixed:** `.page-subtitle` at 4.55:1 in light — the
standing shared-shell issue. It is the worst enabled value on the migrated
surface.

## 7. Inline styles, 8. colour literals, 9. LOC

|                                                         | Before |          After |
| ------------------------------------------------------- | -----: | -------------: |
| Inline style objects (source)                           |     39 |          **0** |
| Inline-styled elements (rendered, both states × themes) |    130 |          **0** |
| Colour literals                                         |      3 |          **0** |
| LOC                                                     |    564 | **340 (−224)** |

## 10. CSS changes and consumer evidence

**Nothing was deleted.**

| Class           | JSX consumers after | CSS definitions | Verdict                           |
| --------------- | ------------------: | --------------: | --------------------------------- |
| `.form-group`   |                   0 |           **0** | nothing to delete — never defined |
| `.form-label`   |                   0 |           **0** | nothing to delete — never defined |
| `.form-input`   |                   0 |           **0** | nothing to delete — never defined |
| `.btn--outline` |                   3 |               — | KEEP                              |

The three `.form-*` names were **inert**: applied in the markup and defined in
no stylesheet anywhere in the repository. Every scrap of this form's appearance
came from the inline objects beside them. There is no dead rule to remove.

**Added:** 68 lines / 11 rules appended to
`src/modules/web-scanning/styles/web-scanning-pages.css` (now 353 lines total —
285 from batch 6, 68 from batch 7).

That file **is shared** with the four batch-6 pages, so the rule about
re-running unrelated-page regression after touching a shared stylesheet applies
and was followed — see §12. Nothing was added to `web-scanning.css`, which
ScanDetail and the routes file depend on.

`web-scanning.css` remains dead (79 lines, zero consumers, dead before batch 6)
and remains untouched, for the same reason as before: removing it is unrelated
cleanup.

## 11. Regression instrument results

Harness validation — including the new `prepare` capability and proof that it
is effective rather than a no-op — is in
[`03c-batch7-harness.md`](03c-batch7-harness.md).

Control image: the **unmigrated tree**, built and containerised before any page
was edited. Both containers self-compared **byte-identical** before any
comparison was believed, for the structural instrument and, separately, for the
contrast probe.

|                                            |       Control |      Migrated |
| ------------------------------------------ | ------------: | ------------: |
| Inline-styled elements                     |           130 |         **0** |
| Unlabelled controls (default / basic auth) |         5 / 7 |     **0 / 0** |
| Heading sequence                           | `h1,h3,h3,h3` | `h1,h2,h2,h2` |
| Duplicate button names                     |             0 |             0 |
| Horizontal overflow                        |             0 |             0 |

Every difference is intentional and accounted for. **No unexplained structural
difference.**

### A harness correction made mid-checkpoint, and reported rather than absorbed

The first post-migration run reported `unlabelledControls 7 → 2`. Investigating
before writing it down: the two residual "unlabelled" controls were the
**checkboxes**, which are labelled by _wrapping_ — the input sits inside its
`<label>`, which is a perfectly valid association and the one this codebase uses
for every checkbox. The probe checked only `aria-label` and `label[for]`.

Left alone, that would have put **two false "unlabelled control" findings** in
this report. The probe was corrected to consider all three naming routes
(`aria-label`, `aria-labelledby`, `label[for]`, wrapping `<label>`), both
containers were re-captured and re-validated by self-comparison, and the true
figures are the ones above: **5 → 0** and **7 → 0**.

## 12. Unrelated-page regression

| Set                                                                                | Result                        |
| ---------------------------------------------------------------------------------- | ----------------------------- |
| Auth group (Login, Register, ResetPassword, VerifyEmail, ForgotPassword)           | **5/5 identical**             |
| Batch-5 admin (RecycleBin, DeletedUsers, OrganizationManagement, EmailDomainRules) | **8/8 state×theme identical** |
| Batch-6 web-scanning (WebDashboard, ScanList, FindingsExplorer, AssetInventory)    | **8/8 state×theme identical** |

The last row is the one that matters most this batch: those four pages import
the stylesheet this batch appended to, and they are unchanged.

Container port excluded from every comparison.

## 13. CSP, security and air-gap results

| Gate                                          | Result                                                                                      |
| --------------------------------------------- | ------------------------------------------------------------------------------------------- |
| CSP                                           | **byte-identical** — `Frontend/nginx.conf` not modified                                     |
| nginx / Docker / security headers             | unmodified                                                                                  |
| External runtime origins                      | **0** — 31 requests, all to the container origin                                            |
| UX4G runtime markers                          | **0**                                                                                       |
| `ux4g-*` classes in the page                  | **0**                                                                                       |
| Direct UX4G imports outside the design system | **0**                                                                                       |
| `dangerouslySetInnerHTML`                     | **0**                                                                                       |
| Analytics / telemetry                         | none added                                                                                  |
| New runtime dependency                        | **none**                                                                                    |
| Docker production build                       | succeeds                                                                                    |
| Theme architecture                            | `data-theme` only                                                                           |
| `prefers-color-scheme`                        | **0**                                                                                       |
| Backend changes                               | **none** — `Backend/core/tasks.py` was already modified before this session and is not mine |
| `webScansApi.js`                              | **unmodified**                                                                              |

## 14. Bundle impact

Against Batch 6:

|          |      Before |       After |            Δ |
| -------- | ----------: | ----------: | -----------: |
| CSS raw  |   288.35 kB |   289.24 kB |     +0.89 kB |
| CSS gzip |    49.09 kB |    49.22 kB |     +0.13 kB |
| JS raw   | 1,685.57 kB | 1,681.56 kB | **−4.01 kB** |
| JS gzip  |   421.71 kB |   421.52 kB | **−0.19 kB** |

## 15. Files changed

**Modified (2)**

- `src/modules/web-scanning/pages/NewWebScan.jsx` 564 → 340
- `src/modules/web-scanning/styles/web-scanning-pages.css` +68 lines, +11 rules

**Added (1)**

- `src/__tests__/modules/web-scanning/NewWebScan.test.jsx` (931 lines, 68 tests)

**Docs:** `docs/ux4g/03c-batch7-harness.md`, this file.

Not touched: any backend file, `nginx.conf`, `Dockerfile`, `docker-compose.yml`,
`PreferencesContext`, the theme architecture, the design system,
`webScansApi.js`, `useScanPolling.js`, `WebScanningRoutes.jsx`,
`web-scanning.css`, `AppLayout`, ScanDetail, and every page outside this batch.

## 16. Out-of-scope security / behaviour findings

Recorded, not fixed. Each would change a contract this batch may not touch.

1. **A retry after a failure uses a NEW idempotency key.** `launchKeyRef` is
   cleared in the `catch`, so the second attempt is a new logical request rather
   than a replay of the first. That is right when the request never reached the
   API, and **wrong when it did and the response was lost** — the caller then
   creates a second scan against the same target, which is a second outbound
   ffuf/nuclei run. Behaviour is pinned by an assertion so it cannot drift
   silently, and the assertion's comment says it is recorded rather than
   endorsed. Deciding what the retry semantics should be is a dispatch-behaviour
   change and belongs to whoever owns that contract.
2. **Clearing a numeric field yields an out-of-range value.**
   `parseInt(e.target.value) || 3` restores the default on an empty field, so
   clearing Crawl Depth and typing `7` produces `37`, which fails
   `checkValidity()` against `max="10"` and blocks submission with only a native
   tooltip. Measured empirically (§3). Fixing it changes validation behaviour.
3. **No client-side permission gate on the web-scanning module.** Carried
   forward from batch 6 and restated because it lands squarely on _this_ page:
   the routes sit under `PrivateRoute` and the API enforces authorisation, but
   there is no `can()` affordance gate as there is on the scan and admin pages —
   on the form that dispatches ffuf and nuclei. Adding one would change
   authorisation semantics.
4. **`authorization_confirmed` is a client-asserted boolean.** The page refuses
   to dispatch without it and sends `true` when ticked; nothing here can
   establish that the claim is truthful. Recorded so it is not mistaken for an
   enforcement mechanism.

None of these blocked the migration, so none was fixed and no semantics changed.

## 17. Legal / licence status

**OPEN.** Unchanged by this batch and not claimed closed.

## 18. Engineering gate

| Gate                                    | Result                                            |
| --------------------------------------- | ------------------------------------------------- |
| Full test suite                         | **872/872**                                       |
| NewWebScan suite                        | **68/68**                                         |
| Lint `--max-warnings=0`                 | clean                                             |
| Production build                        | green                                             |
| Docker production build                 | succeeds                                          |
| Harness validated before use            | **PASS** — separate document                      |
| Harness correction found mid-checkpoint | reported, re-validated, figures corrected         |
| Regression self-comparison              | byte-identical, both containers, both instruments |
| Both themes and both auth states        | verified                                          |
| Unrelated pages                         | **13/13 identical**                               |
| Sub-AA introduced                       | **0** (2 eliminated)                              |
| Dispatch code vs HEAD                   | **character-identical**                           |
| CSP byte-identical                      | yes                                               |
| Air-gap                                 | clean                                             |
| New dependency                          | none                                              |
| New design-system component/pattern     | **none**                                          |

**PASS.**

## 19. Recommendation

**GO.**

One page, 68 assertions where there were none, 9 baseline accessibility failures
closed, 2 sub-AA values eliminated with none introduced, 39 inline style objects
and 224 lines removed, no design-system addition, no CSS deleted, no dependency,
13/13 unrelated pages unchanged, JS bundle smaller.

**On the phrase "byte-for-byte preserved":** the API, payload, credential
encoding, idempotency, authorization gate, validation rules, navigation and
error behaviour are preserved — and for the dispatch path that claim is
`diff`-backed, not asserted. The **presentation and accessibility deliberately
changed**: controls gained accessible names, errors gained `role="alert"`,
headings stopped skipping a level, and the authorization panel now carries its
meaning in words rather than in an amber border. Those are intentional UI
corrections, not preservation, and they are listed as such throughout.

Three things a reviewer should weigh rather than take on trust:

1. **The harness produced a false finding and I corrected it mid-checkpoint**
   (§11). "2 unlabelled controls" would have been wrong — they were labelled by
   wrapping. The correction is reported rather than absorbed, and the numbers in
   this report are the post-correction ones.
2. **`CcurePasswordField` was rejected on purpose** (§2). It would have added a
   visibility toggle, changing password-visibility behaviour that this batch is
   required to preserve. An assertion now pins the absence of a reveal control.
3. **Four out-of-scope findings are recorded, not fixed** (§16), the sharpest
   being the fresh-idempotency-key-on-retry behaviour. It is pinned by test so
   it cannot drift, but it is a real dispatch-semantics question for whoever
   owns that contract.

Stopping here. ScanDetail, Dashboard, SecurityReports, ConfigurationChecks,
ScanCredentials, CredentialedScan, ScanSchedules, Group C/D and the shell are
untouched.
