# Batch 6 — regression harness change

**This document covers the harness only.** No application code was modified
while any of the work below was done, and no application migration had begun.
Written to satisfy the process rule introduced at the Batch 5 review: the
regression instrument is now shared infrastructure, a change to it is its own
piece of work, and _a false regression result is worse than no regression
result_.

---

## 1. Why a change was needed

The instrument approved at Batch 5 (`capture-batch5.mjs`) is hard-wired to four
routes and their API surfaces. Batch 6 targets a different four routes in
`modules/web-scanning/`. Nothing about the capture, readiness, theme-settling or
assertion logic needed to change — only _what it points at_.

## 2. What changed, exactly

`capture-batch6.mjs` is `capture-batch5.mjs` with three substitutions and
nothing else:

| Region                | Change                                                                                                                                                                                    |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ROUTES`              | four web-scanning routes, each with a readiness marker string                                                                                                                             |
| Fixtures              | `WEB_SCANS`, `FINDINGS`, `ASSETS`, `WEB_SUMMARY`, `WEB_SCORECARD`, `WEB_TRENDS` replace the batch-5 payloads                                                                              |
| Stub table            | `/dashboard/web-*`, `/web-scans`, `/web-scans/:id/findings`, `/web-scans/:id/assets` replace the admin endpoints                                                                          |
| `PROBE` selector list | **appended** eight module selectors (`.ws-badge`, `.ws-stat-card`, `.ws-grid-table`, `.skeleton-loader`, `.stat-card`, `.btn--outline`, `.cc-skeleton`, `.cc-severity`). Nothing removed. |

**Unchanged, deliberately** — every property that makes the instrument
trustworthy, each of which exists because getting it wrong once produced a
plausible wrong answer:

- one container per process;
- stubs matched on **pathname**, and only when the path starts with `/api/`, so
  an SPA route that shares a path with its API endpoint cannot have its document
  navigation answered with JSON;
- `user.role` supplied as an **object** with `.name`;
- readiness = marker present in `.page-main` **and** that subtree's size stable
  across three consecutive samples — not `document.body`, which never settles
  because AppLayout's chrome updates on a timer;
- `data-theme` re-asserted and then **verified** against a token that differs
  between themes, failing rather than reporting if it cannot be confirmed;
- an empty capture is a hard error, never a result;
- the recorded `url` is asserted against the requested one and then **excluded**
  from the comparison, because it carries the container port.

## 3. Validation performed, in order

The control image is the **current unmigrated tree**, built and containerised
before any page was edited (`ccure-b6-pre`, `:3295`).

| Step | Check                                                              | Result                                |
| ---- | ------------------------------------------------------------------ | ------------------------------------- |
| 3    | Capture the same container twice, two independent Chrome processes | done                                  |
| 4    | Require byte-identical output                                      | **BYTE-IDENTICAL**                    |
| 5    | Detect a known intentional difference                              | **DETECTED**                          |
| 6    | Report identical for unchanged pages                               | **IDENTICAL, 3/3 pages, both themes** |

### The known intentional difference

A single `<caption>HARNESS PROBE CAPTION</caption>` was added to ScanList's
table, built as `ccure-frontend:b6-probe` (`:3294`), and **the source was
reverted immediately afterwards** — `grep -c "HARNESS PROBE CAPTION"` on the
working tree returns `0`. The image exists only as a probe target and is torn
down with the rest.

Comparing control against probe build:

```
webDashboard   [light] identical   [dark] identical
scanList       [light] CHANGED  caption false -> true
               [dark]  CHANGED  caption false -> true
findings       [light] identical   [dark] identical
assets         [light] identical   [dark] identical
```

That is both halves of the requirement in one run: the instrument saw the one
thing that changed, on the one page that changed, in both themes — and reported
the three untouched pages as identical rather than as noise.

## 4. What this does not establish

Detecting an added `<caption>` proves the instrument is _sensitive to structural
change_ and _not noisy_. It does not prove sensitivity to every class of change
the migration will make; the per-page structural diff and the contrast probe in
the Batch 6 checkpoint report are what cover those, and both carry their own
self-comparison gate.

The contrast instrument (`contrast-batch6.mjs`) is validated the same way at the
point of use, and its numbers are reported only after a self-comparison run.

## 5. Files

Scratchpad only — none of this ships:

- `capture-batch6.mjs` — derived from the approved `capture-batch5.mjs`
- `diff-batch6.mjs` — the batch-5 differ with its page list swapped
- `run-capture6.sh` — one Chrome per capture, torn down after

No application file, test, stylesheet or dependency was touched by this change.
