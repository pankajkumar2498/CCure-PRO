# Batch 8 — regression harness change

**This document covers the harness only.** No application file was modified
while this work was done, and no application migration had begun. Third
application of the process rule introduced at the Batch 5 review.

**The headline: the sensitivity step failed the first time, and it was right
to.** Details in §4.

---

## 1. Why a change was needed

ScanDetail is the first genuinely **dynamic** page in this migration. What it
renders is decided by the scan's _status_, not by the route: a running scan, a
completed one, a failed one, one carrying an incomplete-assessment caveat and
the initial loading state are five different pages behind one URL.

A single capture would measure one of them and report clean about the other
four — including the failure state and the coverage caveat, which is the most
security-relevant text on the page.

It also opens a WebSocket, which introduces a second problem: reproducibility.

## 2. What changed

`capture-batch8.mjs` is `capture-batch7.mjs` with three changes.

| Change                                                       | Why                                                                                                                                                       |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Per-route `overrides`** — `scan`, `scanFails`, `scanHangs` | one path, five states; the stub for `GET /web-scans/:id` is chosen per route                                                                              |
| **`marker: null` support**                                   | the loading state has no settled text of its own, so readiness there is size-stability alone, guarded by a check that placeholders are actually on screen |
| **An ARIA role census** (`roles`, `ariaLive`)                | added _because the sensitivity step failed_ — see §4                                                                                                      |

### The progress ticket is refused deliberately

`useScanPolling` opens a WebSocket. Against a container with no live scanner
that socket's open → error → reconnect cycle makes the live-status badge flip
between "Connecting" and "Polling" between samples, and the capture stops being
reproducible.

Failing `/auth/ticket` with a 503 takes the hook's **documented
ticket-failure path**: `liveStatus` settles on `degraded` once, no socket is
created, and no reconnect timer is armed. The page becomes deterministic _and_
is still exercising a real code path rather than a contrived one.

**Unchanged, deliberately:** one container per process; stubs matched on
pathname and only under `/api/`; `user.role` as an object; readiness scoped to
`.page-main`; `data-theme` re-asserted and verified; an empty capture is a hard
error; recorded `url` asserted and excluded from comparison; the corrected
three-route accessible-name logic from batch 7.

## 3. The five states are genuinely distinct

Captured from one container in one run:

```
detailRunning    skeletons: 0  headings: 5  buttons: Cancel Scan
detailComplete   skeletons: 0  headings: 4  buttons: Download Report
detailFailed     skeletons: 0  headings: 4  buttons: (none)
detailCaveat     skeletons: 0  headings: 4  buttons: Download Report
detailLoading    skeletons: 8  headings: 0  buttons: (none)
distinct states: 5 of 5
```

Had the overrides been a no-op, these would have been five copies of one state.
This check is why that is knowable.

## 4. The sensitivity step failed, and what that exposed

**Step 5, first attempt.** `role="progressbar"` plus an `aria-label` was added
to the progress bar and built as a probe image. The instrument reported:

```
detailRunning/light     identical
detailRunning/dark      identical
detailComplete/light    identical
… all ten states …      identical
```

**Ten "identical" results against a build that had demonstrably changed.**

The cause: the probe recorded accessible names for `input`, `select` and
`button` only. A `role` on any other element — a `div`, a `section`, a status
banner — was invisible to it.

That mattered far more than a missed attribute, because **adding progressbar and
alert semantics is exactly what this batch's migration does**. The instrument
was blind to the single class of change it was about to be used to verify, and
would have reported a clean regression while proving nothing about it.

### The fix

An ARIA role census: every `[role]` inside `.page-main`, recorded as
`role | accessible-name | aria-value/live/busy/current/pressed`, sorted; plus
an `[aria-live]` census. Sorted so that equivalent elements in a different order
do not read as a difference.

### Re-run

```
detailRunning/light     DETECTED | new role: ["progressbar|HARNESS PROBE PROGRESS|"]
detailRunning/dark      DETECTED | …
detailComplete/light    DETECTED | …
detailComplete/dark     DETECTED | …
detailFailed/light      DETECTED | …
detailFailed/dark       DETECTED | …
detailCaveat/light      DETECTED | …
detailCaveat/dark       DETECTED | …
detailLoading/light     identical
detailLoading/dark      identical

detected 8, identical 2
```

Detected in all eight states that render a progress bar, and **correctly
identical in the two loading states, which render none**. Sensitivity where the
change exists; no noise where it does not.

## 5. Validation summary

Control image: the **unmigrated tree**, built and containerised before any page
was edited (`ccure-b8-pre`, `:3289`).

| Step | Check                                                   | Result                                           |
| ---- | ------------------------------------------------------- | ------------------------------------------------ |
| 3    | Capture the same container twice, independent processes | done                                             |
| 4    | Byte-identical output                                   | **BYTE-IDENTICAL** (before and after the §4 fix) |
| 5    | Detect a known intentional difference                   | **FAILED first, then DETECTED 8/8 applicable**   |
| 6    | Identical for unchanged states                          | **2/2 loading states identical**                 |
| —    | Overrides actually produce different states             | **5 distinct of 5**                              |

The probe source was reverted immediately after the probe image was built;
`grep -c "HARNESS PROBE"` on the working tree returns `0`.

## 6. What this does not establish

The role census proves sensitivity to ARIA roles, names and the value/live
attributes listed. It does not prove sensitivity to every possible change, and
it says nothing about network behaviour — no browser-level structural capture
can. The polling and WebSocket contract is pinned by unit assertions over
simulated time with a controllable fake socket; those are in the checkpoint
report, not here.

## 7. Files

Scratchpad only — none of this ships:

- `capture-batch8.mjs` — derived from the approved `capture-batch7.mjs`
- `diff-batch8.mjs` — the same differ with its state list swapped
- `run-capture8.sh` — one Chrome per capture, torn down after

No application file, test, stylesheet or dependency was touched by this change.
