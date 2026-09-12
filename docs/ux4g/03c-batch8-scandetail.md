# Checkpoint 3C — Batch 8: ScanDetail (live scan view)

**Scope:** `src/modules/web-scanning/pages/ScanDetail.jsx` — one page, alone
**Date:** 10 September 2026
**Recommendation:** **GO**

Harness changes are in [`03c-batch8-harness.md`](03c-batch8-harness.md). No
application file was touched while that work was done. **The harness's
sensitivity check failed the first time and caught the instrument being blind to
the exact change this batch makes** — that story is in the harness document and
summarised in §16.

---

## 1. Why ScanDetail was selected alone

It is the only live surface in the web-scanning module, and its behaviour is
not what the name "polling" suggests.

Measured from `useScanPolling`, not assumed:

- one `getScan` on mount;
- a **WebSocket is the primary channel** — while it is healthy there is **no
  polling at all**;
- timed polling is a **fallback**, armed only after the socket errors, closes,
  or the ticket request fails;
- the fallback re-arms only while status is `running` / `pending` / `queued`;
- a terminal status over the socket triggers one final `getScan` and closes the
  socket;
- unmount clears both timers and closes the socket.

A presentation migration here can break things no static page can break: a timer
that multiplies, a second socket, a skeleton that flashes back over settled
results every five seconds, focus lost on every update. None of those is
visible in a diff.

## 2. Baseline metrics

| Metric                       |                      Baseline |
| ---------------------------- | ----------------------------: |
| LOC                          |                           720 |
| Inline style objects         |                            62 |
| Colour literals              |                             7 |
| Legacy `Skeleton` references |                             9 |
| `role="alert"`               |                         **0** |
| `role="progressbar"`         |                         **0** |
| `role="status"`              |                             1 |
| Headings                     | `h1` ×1, `h3` ×4 (skips `h2`) |

Measured on the live rendered surface across five states × two themes:
**229 inline-styled elements**, and — after the harness could see them at all —
**1 ARIA role in one state, 0 in the other four**.

## 3. Existing tests

**None.** ScanDetail was only ever mocked, in `WebScanningRoutes.test.jsx`.

Full suite before this batch: **922 tests, 910 passing, 12 failing** once the
new assertions were added — every failure one of the new
accessibility/rendered-surface assertions.

## 4. New tests

**51 assertions**, written against the unmigrated page: **38 passing, 12
failing** at baseline; **51/51** after migration.

The polling and socket group uses a **controllable fake `WebSocket`** that
records every instance, and asserts over simulated time by **request count** —
so "did a timer multiply?" and "was a second socket opened?" are answered rather
than assumed.

### Three assertions of mine were wrong and were corrected before migration

1. **`getByText("3")` was ambiguous** — the pipeline stepper numbers its phases
   1…4, so "3" matched a step marker as well as the high-findings count.
2. **A progress message legitimately appears twice** — once in the polite status
   line and once as a Live Activity entry — so `findByText` threw on multiple
   matches. Changed to assert presence; uniqueness is covered by the separate
   "no duplicate live region" assertion.
3. **`.closest("div")` returned the label's own div**, which holds the words and
   not the value, so the counter assertion compared against text that could
   never contain a number. Replaced with a climb that states what it is looking
   for.

### One assertion was narrowed, deliberately, with a guard added

"carries no inline styles" became **"carries no page-authored inline styles"**.
`CcureProgress` sets the fill's width inline (`width: 33.33%`) and it has to:
that is a measured per-instance value, not a design decision a token can carry —
exactly as `CcureSkeleton` documents for its dimensions. It comes from an
approved design-system component this batch may not modify, so an absolute
assertion would have been failing the design system rather than the page.

The allowance is deliberately narrow — a bare width percentage inside
`.cc-progress` — and a **second assertion was added** to guard it, so it cannot
become a place styling hides. Measured after migration, the only residual inline
styles anywhere on the page are that one width and `CcureSkeleton`'s dimensions.

**No functional coverage was deleted.**

## 5. Polling contract — verified, unchanged

`useScanPolling.js` is **UNMODIFIED** (verified by `git diff`). This page's use
of it is unchanged. Asserted by request count over simulated time:

| Property                                                     | Verified                                       |
| ------------------------------------------------------------ | ---------------------------------------------- |
| One `getScan` on mount, with the route id                    | yes                                            |
| One `getProgressTicket`                                      | yes                                            |
| **No polling while the socket is healthy**                   | 30 s simulated → still 1 request               |
| Fallback polling starts when the socket errors               | yes                                            |
| Interval is 5 s, not faster                                  | 4 s simulated → no additional request          |
| Polling stops at a terminal status                           | 60 s further simulated → no additional request |
| **No request after unmount**                                 | 60 s further simulated → no additional request |
| Ticket failure falls back to polling, opens no socket        | yes                                            |
| Terminal status over the socket triggers exactly one refetch | yes                                            |
| Repeated synchronous closures do not multiply the timer      | ≤ 1 poll per interval                          |

## 6. WebSocket contract — verified, unchanged

| Property                                          | Verified                 |
| ------------------------------------------------- | ------------------------ |
| Exactly one socket opened                         | yes                      |
| URL built from `getProgressSocketUrl(id, ticket)` | yes, ticket carried      |
| No second socket while one is live                | 30 s simulated → still 1 |
| Socket closed on unmount                          | yes                      |
| Live events rendered from socket messages         | yes                      |

## 7. API / network contract — verified, unchanged

`webScansApi.js` is **UNMODIFIED**. Endpoints, methods and parameters are
untouched: `getScan(id)`, `getProgressTicket()`, `getProgressSocketUrl(id,
ticket)`, `cancelScan(id)`, `downloadReport(id)`.

- **Cancel** still sits behind `window.confirm`; refusing sends nothing;
  accepting sends `cancelScan(id)` and then `refresh()`.
- **Download** still calls `downloadReport(id)`, builds a Blob, clicks a
  synthetic anchor, and still uses `alert()` on failure (preserved — changing it
  would change error behaviour).
- No new network call, no polling introduced where none existed, no retry added.

## 8. Scan-state contract

The status badge was a **two-way branch** — complete, else "info" — so _any_
unrecognised status was dressed as an active scan. Measured on the control, the
`failed` state rendered its badge in the info blue `#60a5fa`.

It is `CcureScanStatus` now, using the canonical vocabulary
(complete/completed, running, queued, pending, failed, unreachable,
cancelled/canceled, unknown). An unrecognised value renders as **Unknown**,
neutral, with the raw string kept in the title.

Backend status values are unchanged; nothing about the API's vocabulary was
touched. The `ACTIVE_STATUSES` / `COMPLETE_STATUSES` sets that decide which
actions are offered are byte-identical, and asserted: Cancel appears only while
active, Download only when complete, and an unknown status offers **neither**.

## 9. Accessibility findings

Found and fixed:

1. **The progress bar had no progressbar semantics** — a bare `<div>` with a
   width percentage: no role, no value, no name. It is `CcureScanProgress` now,
   reporting `valuenow` / `valuemin` / `valuemax` and a name.
2. **A scan that failed to load was never announced** — the error branch was a
   plain `<div>`.
3. **The pipeline stepper conveyed state through a tick glyph, a spinner and a
   number**, none of which carries text. Each step now states **Done / In
   progress / Pending** in words, with `aria-current="step"` on the active one.
4. **The incomplete-assessment caveat was not announced** — the most
   security-relevant text on the page, since it says the counts below it are not
   evidence of absence. It is `role="alert"` now.
5. **Heading levels skipped** `h1` → `h3`.
6. **The four headline counters had no programmatic name** — a styled label div
   beside a styled value div, tied together by nothing.
7. **Loading placeholders were exposed to assistive technology** and there was
   no loading announcement.

## 10. Contrast, before → after

Live rendered surface, five states × two themes, `rgba()` composited through the
real ancestor chain. Floors 4.5 / 3.0.

|                                |    Control | Migrated |
| ------------------------------ | ---------: | -------: |
| Text elements measured         |        110 |      152 |
| **Sub-AA on enabled elements** |     **18** |    **0** |
| Worst enabled value            | **1.93:1** |   4.55:1 |

Representative failures on the control:

| State / theme            | Element                                 |      Ratio |
| ------------------------ | --------------------------------------- | ---------: |
| detailComplete / light   | `complete` status badge                 | **1.93:1** |
| detailRunning / light    | `running` status badge                  |     2.05:1 |
| **detailFailed / light** | **status badge, rendered in info blue** | **2.05:1** |
| all states / light       | target URL link                         |     2.65:1 |
| complete, caveat / both  | `btn--primary` Download Report          |     2.77:1 |
| all states / light       | `Explore Findings →` heading            |     2.77:1 |
| running / both           | `btn--outline` Cancel Scan              |     3.30:1 |

**Carried forward, not fixed:** `.page-subtitle` at 4.55:1 in light — the
standing shared-shell issue, and now the worst enabled value on the migrated
surface. Not touched inside this page, per the standing instruction.

## 11–13. Inline styles, colour literals, LOC

|                                                        | Before |                                              After |
| ------------------------------------------------------ | -----: | -------------------------------------------------: |
| Inline style objects (source)                          |     62 |                                              **0** |
| Inline-styled elements (5 states × 2 themes, rendered) |    229 | **9** — all design-system per-instance values (§4) |
| Colour literals                                        |      7 |                                              **0** |
| LOC                                                    |    720 |                                     **409 (−311)** |

## 14. Skeleton migration

ScanDetail used the legacy `Skeleton` in one state (the initial load), nine
times. It now uses `CcureSkeleton`, which is `aria-hidden` by construction —
paired with a `role="status"` announcement, because hiding the placeholders
without announcing anything would leave a screen-reader user told nothing at all.

**`components/common/Skeleton.jsx` is UNMODIFIED and was NOT deleted.**

**It now has zero consumers.** ScanDetail was the last one. Per the batch brief
that fact is documented and no deletion performed — removing it is not clearly
within this batch's approved scope. For a future batch: the component injects a
`<style>` element **per instance** and has **no reduced-motion guard** on an
infinite shimmer, so it is worth removing rather than merely leaving.

`.skeleton-loader` is likewise untouched; its only remaining reference anywhere
is inside `Skeleton.jsx` itself.

## 15. CSS changes and consumer evidence

**Nothing was deleted.**

| Class              |       JSX consumers after | Verdict                                                 |
| ------------------ | ------------------------: | ------------------------------------------------------- |
| `.skeleton-loader` | 1 — `Skeleton.jsx` itself | KEEP                                                    |
| `.btn--outline`    |                         2 | KEEP                                                    |
| `.btn--primary`    |                        16 | KEEP                                                    |
| `.spinner-icon`    |                         0 | **nothing to delete — never defined in any stylesheet** |

`.spinner-icon` was inert: applied to the inline SVG and defined nowhere; the
rotation came from an inline `animation` property, not from that class.

**Added:** 183 lines / 25 rules appended to
`src/modules/web-scanning/styles/web-scanning-pages.css` (now 537 lines: 285
from batch 6, 68 from batch 7, 183 from batch 8).

That file is **shared** with the batch-6 and batch-7 pages, so the mandatory
unrelated-page regression applies and was run — §17.

`web-scanning.css` is **UNMODIFIED** and still dead (79 lines, zero consumers,
dead before batch 6). Removing it remains unrelated cleanup.

## 16. Regression harness validation

Full detail in [`03c-batch8-harness.md`](03c-batch8-harness.md). Three things
belong here:

**The harness gained per-route state overrides.** ScanDetail is the first
dynamic page in this migration — five different pages behind one URL — and a
single capture would have measured one and reported clean about the other four,
including the failure state and the coverage caveat.

**The progress ticket is refused on purpose.** Against a container with no live
scanner the socket's open → error → reconnect cycle made the live-status badge
flip between samples. Failing `/auth/ticket` takes the hook's documented
ticket-failure path: `liveStatus` settles once, no socket, no reconnect timer —
deterministic, and still a real code path.

**The sensitivity step failed, and it was right to.** `role="progressbar"` plus
an `aria-label` was injected as a probe; the instrument reported **ten
"identical" results against a build that had demonstrably changed**. It recorded
accessible names for `input`, `select` and `button` only, so a role on any other
element was invisible — and _adding progressbar and alert semantics is exactly
what this batch does_. An ARIA role census was added; the re-run detected the
change in **8 of 8 applicable states** and correctly reported **identical for
the 2 loading states, which render no progress bar**.

Had step 5 been skipped, this report would have claimed a verified clean
regression on the one class of change it was least able to see.

### Results, control vs migrated

Both containers self-compared **byte-identical** before any comparison was
believed, for the structural instrument and separately for the contrast probe.
The five states were verified to be **genuinely distinct** (5 of 5) so the
overrides could not be a no-op.

| State    | Inline styled | ARIA roles                            | Headings        |
| -------- | ------------- | ------------------------------------- | --------------- |
| Running  | 58 → 1        | 1 → 2 (+progressbar `valuenow=33.33`) | `h3`×2 → `h2`×6 |
| Complete | 52 → 1        | 0 → 1 (+progressbar `valuenow=100`)   | `h3`×1 → `h2`×5 |
| Failed   | 52 → 1        | 0 → 1 (+progressbar)                  | `h3`×1 → `h2`×5 |
| Caveat   | 56 → 1        | 0 → 2 (**+alert**, +progressbar)      | `h3`×1 → `h2`×5 |
| Loading  | 11 → 8        | 0 → 1 (+status, `aria-live=polite`)   | —               |

Identical in light and dark for every state. No horizontal overflow, before or
after. **No unexplained structural difference.**

### Polling-visual checks (§10 of the brief)

Asserted in the suite rather than inferred:

- **Settled results are never replaced by placeholders** — `loading && !scan` is
  unchanged and directly asserted, including after a socket failure triggers a
  refetch.
- **The DOM does not grow** across twelve consecutive socket updates.
- **No duplicate live region** for the same text.

## 17. Unrelated-page regression

The shared stylesheet was modified, so this was mandatory.

| Set                                       | Result              |
| ----------------------------------------- | ------------------- |
| Auth group (5 pages)                      | **5/5 identical**   |
| Batch 5 admin (4 pages × 2 themes)        | **8/8 identical**   |
| Batch 6 web-scanning (4 pages × 2 themes) | **8/8 identical**   |
| Batch 7 NewWebScan (2 states × 2 themes)  | **4/4 identical**   |
| **Total**                                 | **25/25 identical** |

Container port excluded from every comparison.

## 18. CSP, security and air-gap

| Gate                                                                         | Result                                                  |
| ---------------------------------------------------------------------------- | ------------------------------------------------------- |
| CSP                                                                          | **byte-identical** — `Frontend/nginx.conf` not modified |
| nginx / Docker / security headers                                            | unmodified                                              |
| External runtime origins                                                     | **0** — 31 requests, all to the container origin        |
| UX4G runtime markers / `ux4g-*` classes / direct imports                     | **0 / 0 / 0**                                           |
| `dangerouslySetInnerHTML`                                                    | **0**                                                   |
| Analytics / telemetry                                                        | none added                                              |
| New runtime dependency                                                       | **none**                                                |
| Docker production build                                                      | succeeds                                                |
| Theme architecture                                                           | `data-theme` only; no `prefers-color-scheme`            |
| Backend changes                                                              | **none**                                                |
| `useScanPolling.js` / `webScansApi.js` / `Skeleton.jsx` / `web-scanning.css` | **all UNMODIFIED**                                      |

## 19. Bundle impact

Against Batch 7:

|          |      Before |       After |            Δ |
| -------- | ----------: | ----------: | -----------: |
| CSS raw  |   289.24 kB |   292.00 kB |     +2.76 kB |
| CSS gzip |    49.22 kB |    49.69 kB |     +0.47 kB |
| JS raw   | 1,681.56 kB | 1,676.79 kB | **−4.77 kB** |
| JS gzip  |   421.52 kB |   420.87 kB | **−0.65 kB** |

## 20. Files changed

**Modified (2)**

- `src/modules/web-scanning/pages/ScanDetail.jsx` 720 → 409
- `src/modules/web-scanning/styles/web-scanning-pages.css` +183 lines, +25 rules

**Added (1)**

- `src/__tests__/modules/web-scanning/ScanDetail.test.jsx` (824 lines, 51 tests)

**Docs:** `docs/ux4g/03c-batch8-harness.md`, this file.

Not touched: any backend file, `nginx.conf`, `Dockerfile`, `docker-compose.yml`,
`PreferencesContext`, the theme architecture, the design system,
`useScanPolling.js`, `webScansApi.js`, `WebScanningRoutes.jsx`,
`web-scanning.css`, `components/common/Skeleton.jsx`, `AppLayout`, and every
page outside this batch.

## 21. Out-of-scope security / behaviour findings

Recorded with evidence, not fixed. Each would change a contract this batch may
not touch.

1. **`useScanPolling` can multiply its fallback timer — reproduced.**
   `poll()` sets `timerRef.current = null` _before_ awaiting `fetchScan()`. A
   socket closure landing inside that await passes the
   `if (timerRef.current) return` guard and arms a **second** timer; the
   original poll then overwrites the ref, orphaning the second one, which still
   fires.

   Measured with a fake socket and a deliberately hung fetch:
   **2 polls in a single 5-second interval.** On a page whose fallback exists
   precisely because the socket is unstable — i.e. exactly when repeated
   closures happen — this doubles request rate against the API each time it
   recurs. The fix belongs in the hook, which this batch does not modify.

   The synchronous multi-closure case does **not** multiply and is covered by a
   passing assertion; it is the re-entrant window that does.

2. **A failed download reports through `window.alert`.** Blocking, unstyled,
   and invisible to a screen-reader user who has moved focus. Preserved because
   removing it changes error behaviour. Same finding as batch 7's triage alert.

3. **The scanned target is a live link** (`target="_blank" rel="noreferrer"`),
   where the sibling pages ScanList and AssetInventory deliberately render
   targets as text so nobody clicks through to a scanned host from inside the
   console. Preserved because changing it changes navigation behaviour. The
   inconsistency is worth a deliberate decision.

4. **No client-side permission gate on the web-scanning module.** Carried
   forward from batches 6 and 7 and restated: the routes sit under
   `PrivateRoute` and the API enforces authorisation, but there is no `can()`
   affordance gate — including on **Cancel Scan**, which is a state-changing
   action. Adding one would change authorisation semantics.

5. **`components/common/Skeleton.jsx` now has zero consumers** (§14). Not a
   defect, but it injects a `<style>` per instance and has no reduced-motion
   guard, so it is worth removing rather than leaving.

## 22. Legal / licence status

**OPEN.** Unchanged by this batch and not claimed closed.

## 23. Engineering gate

| Gate                                      | Result                                                                 |
| ----------------------------------------- | ---------------------------------------------------------------------- |
| Full test suite                           | **923/923**                                                            |
| ScanDetail suite                          | **51/51**                                                              |
| Lint `--max-warnings=0`                   | clean                                                                  |
| Production build / Docker build           | green / succeeds                                                       |
| Harness validated before use              | **PASS** — including a failed sensitivity step, fixed and re-validated |
| Regression self-comparison                | byte-identical, both containers, both instruments                      |
| Five lifecycle states, both themes        | verified                                                               |
| Unrelated pages                           | **25/25 identical**                                                    |
| Sub-AA introduced                         | **0** (18 eliminated)                                                  |
| Polling / socket / API contract           | unchanged, asserted by request count over simulated time               |
| Shared hook, API, Skeleton, stylesheet    | all unmodified                                                         |
| CSP / air-gap                             | byte-identical / clean                                                 |
| New dependency or design-system component | **none**                                                               |

**PASS.**

## 24. Recommendation

**GO.**

One page, 51 assertions where there were none, 12 baseline accessibility
failures closed, **18 measured sub-AA values eliminated with none introduced**,
62 inline style objects and 311 lines removed, no design-system addition, no CSS
deleted, no dependency, 25/25 unrelated comparisons unchanged, JS bundle
smaller.

**Distinguishing what was preserved from what was intentionally changed:**

- **Preserved, and verified rather than asserted:** the polling and WebSocket
  lifecycle (by request count over simulated time), every API endpoint and
  parameter, cancel and download behaviour including the `alert`, the
  active/complete status sets, the pipeline phase order, the progress
  derivation, and the coverage-caveat logic in full. `useScanPolling.js` and
  `webScansApi.js` are byte-identical.
- **Intentionally changed — presentation:** 62 inline style objects and 7 colour
  literals replaced by semantic tokens.
- **Intentionally changed — accessibility corrections:** progressbar semantics,
  an announced error, an announced coverage caveat, pipeline states in words,
  named counters, corrected heading levels, hidden-but-announced loading.
- **Intentionally changed — status semantics:** an unrecognised status now
  renders as **Unknown** instead of inheriting the active-scan treatment. This
  is a correction, not preservation, and it is the one behavioural change worth
  a reviewer's explicit attention.

Three things to weigh rather than take on trust:

1. **The harness was blind to this batch's headline change** until the
   sensitivity step exposed it (§16). Ten "identical" results against a changed
   build. The fix and re-validation are documented; the numbers in this report
   are post-fix.
2. **A reproduced polling defect is being left in place** (§21.1) — the
   re-entrant fallback timer, measured at 2 polls per interval. It is in the
   hook, out of scope, and pinned by evidence rather than left as a suspicion.
3. **The legacy `Skeleton` is now zero-consumer** (§14) and was deliberately not
   deleted.

Stopping here. Dashboard, SecurityReports, ConfigurationChecks, ScanCredentials,
CredentialedScan, ScanSchedules, Group C/D and the shell are untouched.
