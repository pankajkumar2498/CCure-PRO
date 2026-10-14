# Checkpoint 3C — Batch 16: the validation harness, restored in the repository

Batch 15 recorded (§0) that the capture harness batches 6–14 relied on existed
in no commit. It had lived in a previous session's scratch directory. So
Batch 15 shipped with no determinism, sensitivity or diff gate. Batch 16's first
step was to rebuild one, in the repository, and prove it on the build before
any Batch 16 change.

This is a new harness written for the same purpose. It is **not** the
batch 6–14 instrument, and none of that instrument's figures should be read as
comparable. Its usage is in
[`Frontend/scripts/ux4g-harness/README.md`](../../../Frontend/scripts/ux4g-harness/README.md).

---

## 1. What is in the repository

All of it is under `Frontend/scripts/ux4g-harness/`: outside `src/`, so ESLint
and Vitest never see it, and with no npm dependencies.

| File                 | Role                                                                                                                                            |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `serve.mjs`          | Builds the production image and serves it on loopback. `api` resolves to the container itself, so nothing reaches a live API.                   |
| `run.mjs`            | Captures every state in headless Chrome over DevTools. Answers `/api` from fixtures, refuses writes, blocks off-origin requests and WebSockets. |
| `compare.mjs`        | Compares two reports. `--mode determinism` requires identical reports; `--mode diff` names every delta and gates the `--identical` prefixes.    |
| `sensitivity.mjs`    | Injects each deliberate regression into the unchanged build and requires it to be detected.                                                     |
| `lib/chrome.mjs`     | Chrome discovery and launch, the DevTools client, and shutdown: graceful `Browser.close`, then process-tree kill and a profile-scoped sweep.    |
| `lib/freeze.mjs`     | Frozen `Date`, seeded `Math.random`, animations and transitions off.                                                                            |
| `lib/router.mjs`     | The fixture router: session refresh answered, other writes 403, unstubbed reads 404.                                                            |
| `lib/fixtures.mjs`   | Personas and API fixtures. Field names are taken from the pages' reads and checked against `Backend/routers`.                                   |
| `lib/states.mjs`     | The state catalogue: 43 captures across 29 state definitions.                                                                                   |
| `lib/measure.mjs`    | The in-page census: names, headings, roles, ARIA state, tables, classes, contrast, geometry and more. Also the focus snapshot.                  |
| `lib/injections.mjs` | Ten deliberate regressions and the categories each must change.                                                                                 |
| `lib/png.mjs`        | A dependency-free PNG decoder, for comparing screenshots pixel by pixel.                                                                        |

**The catalogue.**

| Area                         | Captures | Covers                                                                                             |
| ---------------------------- | -------- | -------------------------------------------------------------------------------------------------- |
| AssetRegistry (`ar-`)        | 13       | Assets, read-only persona, empty, error, services, services dialog, TLS, mobile width              |
| VulnerabilityBrowser (`vb-`) | 12       | Grouped, CVE, read-only persona, null CVSS, drawer, drawer triage form, empty, error, mobile width |
| SecurityDashboard (`sd-`)    | 2        | Regression only: must not change                                                                   |
| ComplianceWorkspace (`cw-`)  | 16       | Regression only: all eight tabs, both themes                                                       |

Keyboard probes run in the AssetRegistry and VulnerabilityBrowser states. Each
presses real keys and checks the result:

- sort by keyboard;
- drill-down by keyboard;
- managed toggle reachable;
- certificate asset link reachable;
- the services dialog opens and Escape closes it;
- the finding drawer opens and Escape closes it;
- the view toggle's focus ring.

---

## 2. Proof on the pre-Batch-16 build

**The image.** `ccure-ux4g-validation:b16-pre` was built from the tree as
Batch 15 left it, before any Batch 16 page change. The capture proves this
independently of timestamps:

- Every AssetRegistry and VulnerabilityBrowser state carries `db-*` classes, for
  example 33 elements on `ar-assets`, 26 on `vb-cve` and 32 on `vb-drawer`.
- `vb-cve-nullcvss` never becomes ready. It logs
  `TypeError: Cannot read properties of null (reading 'toFixed')`, which is the
  crash Batch 16 fixes.

| Gate                        | Result                                                                                                                                                |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Determinism, pre-a vs pre-b | **43 / 43 identical.** One note: `cw-findings.light` differs on 44 pixels, max channel delta 1/255, inside the tolerance (§3, defect 5).              |
| Sensitivity                 | **20 / 20.** Ten injections × two states (`ar-assets`, `vb-cve`), each detected in every expected category.                                           |
| Isolation, every capture    | 0 refused writes, 0 off-origin requests, 0 CSP issues, 0 page exceptions. The one unstubbed request is `GET /api/notifications/stream`, the SSE feed. |

---

## 3. Harness defects found while proving it, and fixed

Defects 1–5 were found before any post-change capture, and every pre capture
was taken again after they were fixed. Defects 6–8 are in tooling around the
captures and changed no measurement. None of the eight touched application
code.

1. **Sensitivity picked states by prefix.** `ar-assets` also matched every
   `ar-assets-*` variant. It now uses exact ids.
2. **The managed-toggle probe matched the filter.** Its pattern also hit the
   "Managed state" `<select>` above the table. The probe is now scoped to
   `tbody`.
3. **ComplianceWorkspace states never became ready.** The page's title is not a
   heading and its tabs are not buttons. `ready` now waits on the title text,
   and the tab click finds the label inside the tab bar.
4. **The class census could not see a legacy class added to a legacy
   element.** The `legacy-class` injection adds `db-btn` to the `h1`. On a page
   that already uses `db-btn`, and whose `h1` already carries `db-page-title`,
   that changed neither the element count nor the set of names. Sensitivity was
   **18 / 20**. The census now also records a token count and per-element class
   signatures, and sensitivity is 20 / 20.
5. **Screenshot equality was a SHA-256 of the PNG.** Two captures of the same
   build differed on 44 pixels. All 44 were at the four rounded corners of one
   card, each by 1/255 in one channel: anti-aliasing noise. Screenshots are now
   compared pixel by pixel, with `SCREENSHOT_TOLERANCE = 2`. Checked against
   known pairs:

   | Pair                      | Result                     |
   | ------------------------- | -------------------------- |
   | The noise pair            | 0 pixels beyond, 44 within |
   | Light theme vs dark theme | 2,569,535 pixels beyond    |
   | Two identical captures    | 0 / 0                      |

   Pixels inside the tolerance are printed as notes, never dropped.

6. **`serve.mjs build` reported success as failure.** With `stdio: "inherit"`
   there is no captured stdout, so `.trim()` threw after Docker had finished,
   and the command exited 1. The image had been built and tagged. Its ID
   matched the one served, which was checked before its captures were trusted.
7. **The entry points could not be imported.** Each guards its command-line code
   with `pathToFileURL(process.argv[1])`. Under `node -e`, `argv[1]` is
   undefined, so importing `compareReports` from a one-off analysis threw. The
   guard now checks that `argv[1]` exists first.
8. **Every run leaked a headless Chrome.** After this session's runs, 36
   harness Chrome processes were still alive: 12 whole browser trees, some
   from runs that had finished normally. `close()` called `taskkill /T` on the
   parent without first asking the browser to exit. `/T` walks the process tree
   from the parent, so a helper whose parent has already gone is not in it.
   Leftovers like these caused the profile-lock `EPERM` failures seen during
   Batch 15 validation.

   `close()` now:

   - sends CDP `Browser.close` and waits up to 5 seconds for the process to
     exit;
   - kills the process tree;
   - on Windows, stops any process still carrying that launch's unique profile
     directory name in its command line. That name cannot match any other
     Chrome.

   _Verified:_ after a diagnostic run with the fix, the count was unchanged.
   Over the full final post run (image rebuild, mobile check, 86 captures), the count was 0 before and 0 after.

---

## 4. Ordering, stated plainly

Batch 16 required the harness first, then pre-build proof, then the change.

- **Before the first pre run.** The harness and the Batch 16 tests were written
  first, and the pre image was built before any page change.
- **During the first pre run.** Drafting the page changes began while that run
  was in progress. Its gates failed: determinism 42 / 43, sensitivity 18 / 20.
- **Before any post image existed.** The harness was fixed (§3), the pre
  captures were taken again, and both gates passed.
- **No post measurement came before the pre gates passed.** The pre image is a
  build artefact, so page edits in the working tree cannot reach it; §2 shows
  that from its own capture.

---

## 5. Limits

- Only catalogued states are measured. A route or state missing from
  `lib/states.mjs` is unmeasured, not passed.
- The API is fixtures, so server behaviour, permissions enforced server-side
  and real data volumes are not exercised. RBAC is exercised only on the client,
  through personas.
- Contrast is computed from computed colours on text. Text over gradients or
  images is counted as unknown.
- Captures are comparable only on the same machine with the same Chrome build.
  Font rasterisation differs between them.
