# Batch 7 — regression harness change

**This document covers the harness only.** No application file was modified
while any of the work below was done, and no application migration had begun.
Written to satisfy the process rule introduced at the Batch 5 review, and
followed for the second time here.

---

## 1. Why a change was needed

Two reasons, one routine and one that is the point of this document.

**Routine:** the instrument is hard-wired to a route table. Batch 7 targets
`/web-scans/new`.

**Not routine:** NewWebScan's credential fields are **conditional** — the
username, password, token and cookie inputs do not exist in the DOM until the
authentication mode is switched. A single-state capture would therefore measure
nothing at all about the part of this page that handles credentials, which is
the part that matters most on a page that dispatches ffuf and nuclei at a
caller-named target. It would also compare clean before and after while covering
none of it, which is the failure mode this instrument exists to prevent.

## 2. What changed, exactly

`capture-batch7.mjs` is `capture-batch6.mjs` — itself the instrument approved at
Batch 5 — with two changes:

| Region            | Change                                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| `ROUTES`          | one path, captured in **two states**: `newScanDefault` and `newScanBasicAuth`                           |
| **new** `prepare` | an optional per-route expression, evaluated after the page has settled and before the theme is asserted |

`prepare` drives the page **through its own `<select>`**, dispatching a real
`change` event via the native value setter. It does not reach into React state,
and it does not construct DOM. What it produces is what a user switching the
auth mode produces.

Two guards were added with it, because a prepare step that silently did nothing
would produce a capture of the _default_ state filed under the _variant's_ name
— and the comparison would then be measuring the wrong thing while looking
perfectly healthy:

- a thrown exception inside `prepare` fails the capture;
- a `prepare` that cannot find the control it is meant to drive returns
  `"no-select"`, which fails the capture.

**Unchanged, deliberately:** one container per process; stubs matched on
pathname and only under `/api/`; `user.role` as an object; readiness scoped to
`.page-main` with marker plus size-stability; `data-theme` re-asserted and
verified against a token that differs between themes; an empty capture is a hard
error; the recorded `url` asserted and then excluded from comparison.

## 3. Validation performed, in order

Control image: the **unmigrated tree**, built and containerised before any page
was edited (`ccure-b7-pre`, `:3292`).

| Step | Check                                                              | Result                        |
| ---- | ------------------------------------------------------------------ | ----------------------------- |
| 3    | Capture the same container twice, two independent Chrome processes | done                          |
| 4    | Require byte-identical output                                      | **BYTE-IDENTICAL**            |
| 5    | Detect a known intentional difference                              | **DETECTED, 4/4 state×theme** |
| 6    | Report identical for an unchanged control                          | **IDENTICAL** (step 4)        |
| —    | Prove `prepare` actually does something                            | **7 → 9 controls**            |

### The `prepare` step is effective, not merely present

Captured from the same container in the same run:

```
newScanDefault    labelled controls: 7
newScanBasicAuth  labelled controls: 9   (username + password appear)
variant differs from default: true
```

Had `prepare` been a no-op, these two would have been identical and the variant
would have been a duplicate wearing a different name. This check is why that is
knowable.

### The known intentional difference

`aria-label="HARNESS PROBE AUTH TYPE"` was added to the auth-mode `<select>`,
built as `ccure-frontend:b7-probe` (`:3291`), and **the source was reverted
immediately afterwards** — `grep -c "HARNESS PROBE"` on the working tree returns
`0`.

```
newScanDefault/light    DETECTED   select name: ["SELECT:UNLABELLED"] -> ["SELECT:HARNESS PROBE AUTH TYPE"]
newScanDefault/dark     DETECTED   select name: ["SELECT:UNLABELLED"] -> ["SELECT:HARNESS PROBE AUTH TYPE"]
newScanBasicAuth/light  DETECTED   select name: ["SELECT:UNLABELLED"] -> ["SELECT:HARNESS PROBE AUTH TYPE"]
newScanBasicAuth/dark   DETECTED   select name: ["SELECT:UNLABELLED"] -> ["SELECT:HARNESS PROBE AUTH TYPE"]
```

The probe was chosen to be the _same shape_ as a change the migration actually
makes — giving a control an accessible name — rather than something arbitrary,
so the sensitivity demonstrated is the sensitivity that will be relied on.

All four states report it because the select exists in all four. That is
correct, not noise: the pages that should be unaffected by this batch are
covered by the unrelated-page regression in the checkpoint report.

## 4. What this does not establish

Detecting an added `aria-label` proves the instrument is sensitive to accessible
naming and is not noisy. It does not prove sensitivity to every class of change,
and it says nothing about the wire payload — no browser-level instrument can.
The dispatch contract is pinned by unit assertions that mock `axiosInstance`
rather than `webScansApi`, so the real payload normaliser and the real `btoa`
encoding run; those are in the checkpoint report, not here.

## 5. Files

Scratchpad only — none of this ships:

- `capture-batch7.mjs` — derived from the approved `capture-batch6.mjs`
- `diff-batch7.mjs` — the same differ with its page list swapped
- `run-capture7.sh` — one Chrome per capture, torn down after

No application file, test, stylesheet or dependency was touched by this change.
