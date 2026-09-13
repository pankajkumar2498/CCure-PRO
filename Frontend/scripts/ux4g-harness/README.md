# UX4G validation harness

Measures what a page does in a real browser against a production build, and
compares two measurements. A migration batch is judged by a capture before the
change and a capture after it, not by reading the diff.

It lives outside `src/`, so neither ESLint nor Vitest picks it up, and it has
no npm dependencies.

## Requirements

- Docker, to build and serve the production image.
- Chrome or Chromium. Common install paths are searched; set `CHROME_PATH` to
  override.
- Node 20 or later.

## Isolation

Nothing a capture does can reach a real system:

- `serve.mjs up` binds the container to `127.0.0.1` and resolves `api` to the
  container's own loopback. nginx starts, but its `/api` proxy has nowhere to
  go.
- The browser intercepts every `/api` request and answers it from
  `lib/fixtures.mjs`. `POST /auth/refresh` is the only write answered; any other
  write gets 403 and is recorded as a refused write. A read with no fixture gets
  404 and is recorded as unstubbed.
- Off-origin requests and WebSockets are blocked and recorded.
- `Date` is frozen at `2026-09-12T10:00:00Z`, `Math.random` is seeded, and
  animations and transitions are switched off.
- Background polls never fire. An interval of 10 seconds or more
  (`LONG_INTERVAL_MS`) is registered but does not run, so a capture's request
  log does not depend on how many seconds the capture took. Initial loads do
  not wait on an interval, so nothing a page shows is lost.
- The shell's notification stream is SSE. The harness answers it 404 and the
  shell retries on a backoff timer, so a capture logs one, two or three
  attempts depending on its length. `compare.mjs` compares repeated attempts
  as one; `report.json` keeps them all.
- No capture can mount a Phase 3 route (`lib/guard.mjs`). Phase 3 starts scans
  from an effect on mount, and Phase 2 hands off to it in automatic mode.
  `history.pushState` and `replaceState` refuse `/scan/vulnerability-audit`,
  `/scan/advanced-scan` and `/scan/{id}/phase3` with a `DataCloneError`, which
  React Router rethrows before its listener runs, so the route never renders;
  a document loaded at such a URL stops before the application boots. A refusal
  is recorded under `blockedNavigations` and makes `run.mjs` exit 1.

## Workflow

```sh
# from the repository root
node Frontend/scripts/ux4g-harness/serve.mjs build ccure-ux4g-validation:pre
node Frontend/scripts/ux4g-harness/serve.mjs up ccure-ux4g-validation:pre 3216 ccure-harness-pre

cd Frontend
node scripts/ux4g-harness/run.mjs --base http://127.0.0.1:3216 --label pre-a --out OUT/pre-a
node scripts/ux4g-harness/run.mjs --base http://127.0.0.1:3216 --label pre-b --out OUT/pre-b
node scripts/ux4g-harness/compare.mjs OUT/pre-a/report.json OUT/pre-b/report.json --mode determinism
node scripts/ux4g-harness/sensitivity.mjs --base http://127.0.0.1:3216 --baseline OUT/pre-a/report.json --out OUT/sensitivity

# make the change, then build and serve it on another port and capture post-a and post-b the same way
node scripts/ux4g-harness/compare.mjs OUT/post-a/report.json OUT/post-b/report.json --mode determinism
node scripts/ux4g-harness/compare.mjs OUT/pre-a/report.json OUT/post-a/report.json --mode diff --identical sd-,cw-

node scripts/ux4g-harness/serve.mjs down ccure-harness-pre
```

`run.mjs` also takes `--states` (comma-separated id prefixes), `--themes`
(`light,dark`) and `--inject NAME`. With no `--out`, output goes to
`<tmp>/ccure-ux4g-harness/<label>`. Each run writes `report.json` and a
`shots/` directory.

## The three gates

Pass them in order. A later gate means nothing if an earlier one failed.

1. **Determinism.** Two captures of the same build must be identical in every
   category. Otherwise a delta after a change could be noise.
2. **Sensitivity.** Each entry in `lib/injections.mjs` is a deliberate
   regression injected into the unchanged build. Every one must show up in each
   category it is expected to change. Otherwise "no delta" could just mean the
   harness cannot see that kind of change.
3. **Diff.** Compare the pre capture with the post capture. States named with
   `--identical` must show no delta at all. Every other delta is printed by
   category, and each one has to be accounted for.

| Injection                | Must be detected in |
| ------------------------ | ------------------- |
| `header-colour`          | styles, screenshot  |
| `strip-aria-states`      | ariaStates          |
| `strip-accessible-names` | names               |
| `remove-focus-ring`      | probes              |
| `untabbable-controls`    | tabOrder, probes    |
| `legacy-class`           | classes             |
| `write-attempt`          | writes              |
| `inline-script`          | csp                 |
| `off-origin-image`       | csp                 |
| `layout-shift`           | rects, screenshot   |
| `pointer-only-target`    | clickable           |

## What a capture records

These are the categories in `compare.mjs`:

- **names, headings, roles, ariaStates, dialogs, live.** Accessible names,
  unnamed controls, headings, landmarks, ARIA state, dialogs and live regions.
- **tables.** Captions (including misplaced ones), `scope`, sort buttons,
  `aria-sort` and row counts.
- **tabOrder, probes.** The full Tab sequence, plus scripted keyboard checks:
  Tab to a target, press a key, then expect a DOM condition or a request.
- **contrast.** Text contrast from computed colours. Pairs it cannot resolve
  (gradients, images) are counted as unknown, not passed.
- **classes.** Legacy `db-*` usage: element count, token count, class names and
  per-element signatures. Also design-system element counts.
- **clickable.** Elements with a pointer cursor that are not controls, sit
  inside no control and are not themselves reachable by Tab. A focusable
  container is not a control: until batch 18 `[tabindex]` counted as one, and
  the shell's `<main tabIndex={-1}>` hid every page from this list.
- **inline, styles, rects, overflow.** Inline styles, plus computed style and
  geometry of each state's tracked selectors, and horizontal overflow.
- **text, url, theme, errorBoundary.** A hash of the visible text, the final
  URL, the resolved theme, and whether an error boundary rendered.
- **requests, writes, offOrigin, csp, runtime.** The network log, refused
  writes, blocked off-origin requests, CSP issues, readiness, exceptions and
  console errors.
- **screenshot.** Described in the next section.

## Screenshots

Screenshots are compared pixel by pixel. A pixel counts as changed only when
one of its channels moves by more than `SCREENSHOT_TOLERANCE` (2/255).

The threshold is measured, not guessed. Two captures of the same build once
differed on 44 anti-aliased pixels at a card's rounded corners, by 1/255 in one
channel. That is rasteriser noise. Every injection that expects a screenshot
delta changes pixels by far more.

Differences inside the tolerance are not hidden. The comparison prints them as
notes beside the state.

## States

`lib/states.mjs` holds the catalogue. Each state has:

- a route and a persona;
- fixtures and themes;
- a `ready` expression;
- optional actions and keyboard probes;
- the selectors whose style and geometry are tracked.

A state can also carry `viewport`, `readyTimeout`, `session` (sessionStorage
entries) and `init`, a script evaluated before the application boots, which
is how router state a real navigation would have carried gets seeded. Probes
can press `Tab`, `Enter`, `Space`, `Escape` and `ArrowRight`.

`repeatable` lists regular-expression sources for requests a state makes on a
timer with no upper bound, such as the Phase 2 poll of a running scan. Those
lines compare as one in that state only; `report.json` keeps every one.

States record what the page does, never what a build is expected to do. The
same catalogue runs before and after a change.

When adding a page:

- **Take fixture field names from the page's own reads.** Check them against
  the backend response too. A fixture with invented field names renders a row
  of dashes, and that still satisfies a loose check.
- **Make `ready` wait on content, not markup.** Markup is what a migration
  changes.
- **Add pages that must not change to `REGRESSION_PREFIXES`.** Then gate them
  with `--identical`.

## Limits

- Only the states in the catalogue are measured.
- Fixtures stand in for the API, so server behaviour is not exercised.
- Font rasterisation differs between machines and Chrome builds. Compare only
  captures taken on the same machine with the same browser.
