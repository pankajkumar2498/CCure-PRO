# Checkpoint 3C — Batch 21: NetworkMap on the design system

NetworkMap is the network topology map (`/topology`, `/scan/topology-map` and
`/scan/:scanId/topology-map`). It reads one topology graph and draws it with
vis-network: infrastructure, subnets that expand into their hosts, typed
links, a data-quality summary, subnet filters and search, a panel for the
selected node, and two dialogs that explain a subnet's endpoint evidence and
its recommended next actions.

**The page only reads.** It makes one kind of request — `GET /topology/map`
or `GET /topology/map/{scanId}` — and writes nothing. The risk in this batch is
the graph, not the data:

- **The page around the graph** is design-system primitives (CcureButton,
  CcureSelect, CcureInput, CcureCard, CcureBadge, CcureAlert, CcureLoader,
  CcureEmptyState, CcureTable, CcureModal) and a token-only `NetworkMap.css`.
- **The canvas takes its colours from tokens.** A canvas cannot read CSS, so
  every colour vis-network draws is named by a `--nmap-*` property that
  `NetworkMap.css` defines from a `--ccure-*` token. The page reads the
  computed values, and reads them again when the theme changes (§1.1).
- **The graph's behaviour is the code that was here.** Requests, layout,
  physics, expand and collapse, filters, search, the 15-subnet confirmation,
  node clicks and both dialogs' content are unchanged, and pinned by contract
  tests written against the legacy page first (§3).

**Baseline:** HEAD `61c31cc` (Batch 20). Batch 21 is uncommitted.

**Not touched:**

- ScanHistory, CredentialedResults, Phase3Results, NewScan,
  ComplianceWorkspace, OrganizationManagement and every other page.
- `components/layout/Modal.jsx`, CcureModal and every other design-system
  primitive, CVELink, RiskBadge and the Toast shim.
- `global.css`, `scan.css`, `dashboard.css` and the rest of the legacy CSS
  chain.
- `App.jsx`, PrivateRoute, `auth/permissions`, `api/*`, the backend, the
  vis-network version, `package.json`, the lockfile, `nginx.conf`, CSP and
  `scripts/host-nginx/nginx-host.conf`.
- The harness's capabilities, apart from one key (§0.3). No WebSocket or SSE
  support, no canvas clicking, no file or download driving; `BLOCKED_ROUTES` is
  unchanged.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `61c31cc`                                                                                                                                                                                                                                                                                 |
| Tests first, on the legacy page             | 75 tests: the 56 contract tests pass, the 19 batch 21 tests all fail, each for its intended reason. Two corrections to the tests themselves before the baseline (§0.2)                                                                                                                                          |
| Canvas determinism, unchanged build         | The 7 `nm-` captures taken twice: **7 / 7** identical, all ready; 0 writes, 0 off-origin, 0 CSP issues, 0 exceptions, 0 console errors; all 7 keyboard probes reached and passed in both runs                                                                                                                   |
| Baseline, unchanged build                   | 111 captures ready, twice. Determinism **111 / 111**, sensitivity **22 / 22**                                                                                                                                                                                                                                   |
| Same tests, migrated                        | **75 / 75**, first run                                                                                                                                                                                                                                                                                          |
| Logic unchanged                             | Diffing the component body legacy → migrated, every changed hunk is a colour source, the theme observer, the guidance titles' glyph split, or inline styles removed from the guidance text. Requests, filters, expand and collapse, search, the confirmation, click handling, destroy and rebuild are unchanged |
| Full frontend suite                         | 54 files, **1850** tests, all passing (1783 − 8 replaced smoke tests + 75)                                                                                                                                                                                                                                      |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                             |
| Build                                       | `vite build` succeeds. Its two warnings (chunk size, an ineffective dynamic import) are on the unchanged image too                                                                                                                                                                                              |
| Pre-commit formatting                       | Every Batch 21 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                      |
| Post determinism                            | post-a vs post-b **111 / 111** identical                                                                                                                                                                                                                                                                        |
| Unchanged pages                             | AssetRegistry, VulnerabilityBrowser, SecurityDashboard, ComplianceWorkspace, Phase2Results, Phase1Results and AMTIntegration: **104 / 104** captures identical pre → post in every category, on both capture pairs                                                                                              |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                     |
| NetworkMap requests                         | Identical before and after in every `nm-` capture, probes included (0 deltas). Only GETs; the topology requests carry `subnet_mask` and, on the org-wide map, `active_within_days` (plus the `org_id` the axios instance adds)                                                                                  |
| CSP and security headers                    | Identical on the pre and post images across seven routes, the three NetworkMap routes included (49 header lines)                                                                                                                                                                                                |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                                                                    |
| Writes, navigations, off-origin, CSP issues | 222 post captures: 0 refused writes, 0 blocked Phase 3 navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every `nm-` capture ends on its own route in all four reports                                             |
| Screenshots                                 | All 7 NetworkMap captures reviewed side by side, pre and post. No regression; one layout difference at 390 px is recorded (§4, item 15)                                                                                                                                                                         |

### 0.1 Deterministic canvas captures

A canvas state could not simply use the runner's settle. Drawing on a canvas is
not a DOM mutation, and the page fits the view 300 ms after building the graph
and animates the fit for 400 ms — ending about when a capture would otherwise
be taken. (The clock is not involved: vis-network's animation does not read
`Date.now`, and `Math.random` is already seeded.)

The `nm-` canvas states are therefore ready only once the canvas has existed
for 1.5 s and three consecutive readings of its pixels, 200 ms apart, are
identical. The readings are taken by the state's `ready` expression from
outside the page; NetworkMap carries no hook. The trial on the unchanged build
proved it before anything was migrated: 7 / 7 identical across two runs, and
111 / 111 across the full baseline.

### 0.2 Corrections

No correction was needed to the page after migration: the tests, lint, build
and every harness gate passed on the first migrated build.

Two corrections were made to the tests before the baseline was taken:

1. **A contract test was wrong about the legacy page.** "Gives nodes and edges
   plain-text tooltips" required every edge to carry a title, but the links
   from an expanded subnet to its hosts never had one. The test now pins that
   those links carry none and every other edge carries a string.
2. **One specification test passed on the legacy page.** The map region and
   the data-quality summary were already named, so that test was moved into
   the contract block, leaving 19 specification tests that all fail on the
   legacy page.

Two small overlaps with the capture runs, both before any measurement they
could affect: ESLint and Prettier on two files ran for a few seconds as the
first baseline capture began (determinism 111 / 111 and sensitivity 22 / 22
held), and a sub-second text diff ran just before the post image build.

### 0.3 Harness changes

- **7 NetworkMap captures** in 6 states:
  - `nm-org` (both themes), `/topology`, with seven keyboard probes;
  - `nm-scan`, `/scan/nm-scan-7/topology-map`;
  - `nm-mobile` (390 px), `nm-empty`, `nm-error` (500);
  - `nm-denied`: a persona without `scans:read`, which the routes still admit
    and which the backend refuses with its 403 detail.
- **Probes**, all on `nm-org`: Refresh (Enter → the same topology GET), Fit
  Screen (Enter, requests nothing), Expand All and Collapse All (Enter → 14 and
  7 visible nodes), a subnet checkbox (Space → unchecked), the freshness window
  (ArrowRight → `active_within_days=90`) and the mask (ArrowLeft →
  `subnet_mask=23`).
- **Safety rules.** No state or probe touches the canvas: node selection, the
  evidence and guidance dialogs and asset navigation start from a click on a
  node and are covered by the unit tests. The fixture has three subnets, so
  Expand All stays below the 15-subnet confirmation, which would open a native
  dialog.
- **Fixtures** follow `get_topology_graph`'s field names (graph_version 3).
- **`run.mjs` gains `ArrowLeft`** beside the existing `ArrowRight`. It is the
  only capability change: the mask select's default, /24, is its last option,
  so no existing key could change it.
- **`REGRESSION_PREFIXES`** now includes `amt-`, so Batch 20's captures are in
  the regression gate.
- The catalogue is now 77 states, 111 captures.

---

## 1. Files changed

| File                                             | Change                                                                                                                       | LOC         |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `src/pages/scan/NetworkMap.jsx`                  | Design-system page around the graph; canvas colours and node icons from tokens; CcureModal dialogs; captioned evidence table | 1905 → 1936 |
| `src/styles/NetworkMap.css`                      | Rewritten on tokens: 164 `--ccure-*` references, 23 `--nmap-*` canvas properties, 0 colour literals                          | 827 → 676   |
| `src/__tests__/pages/scan/NetworkMap.test.jsx`   | Replaces the 8 smoke tests: 56 contract + 19 batch 21                                                                        | 252 → 2017  |
| `scripts/ux4g-harness/lib/{fixtures,states}.mjs` | NetworkMap fixtures, a persona without `scans:read`, 6 `nm-` states; `amt-` in the regression prefixes (§0.3)                | —           |
| `scripts/ux4g-harness/run.mjs`                   | `ArrowLeft` in the key table (§0.3)                                                                                          | +5          |

| Measure                                                             | Before                                                          | After              |
| ------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------ |
| Inline `style` attributes                                           | 17                                                              | **0**              |
| Colour literals in the page                                         | 218 (214 hex, 1 `rgba`, 3 `var()` strings handed to the canvas) | **0**              |
| Colour literals in the stylesheet                                   | 32 (7 hex, 25 `rgba`)                                           | **0**              |
| Legacy variable references in the stylesheet                        | 89                                                              | **0**              |
| `!important` / `@keyframes` in the stylesheet                       | 1 / 1                                                           | 0 / 0              |
| Elements using `scan.css`'s `btn`, `btn--primary`, `btn--secondary` | 4                                                               | **0**              |
| `nmap-stat` (a class no stylesheet defines)                         | 2                                                               | **0**              |
| Legacy `Modal` dialogs                                              | 2                                                               | **0** (CcureModal) |
| `role="table"` on `<div>`s with no cells or header roles            | 1                                                               | **0** (CcureTable) |
| Unlabelled controls (org-wide map)                                  | 4                                                               | **0**              |
| Failing text contrast pairs (`nm-org`, light / dark)                | 13 / 3                                                          | **0 / 0**          |
| Tests                                                               | 8                                                               | 75                 |

The page is 31 lines longer. The 22 SVG icons lost their gradient definitions
(132 lines) and the two colour tables went (31 lines), but the token map with
its fallbacks, the six colour families, the icon painter, the evidence table's
column definitions and the theme observer are new.

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 377,842        | 377,403       | −439   |
| JS    | 1,618,514      | 1,613,404     | −5,110 |

### 1.1 How the canvas gets its colours

The chain the batch was asked for:

    --nmap-* property (NetworkMap.css, on .nmap-page)
      → --ccure-* token (light or dark)
        → computed value (getComputedStyle on the page element)
          → vis-network node and edge options, and the SVG icon strings

- **23 roles**, each a `--nmap-*` property: the canvas background and label
  halo; the muted label colour; the default and highlighted edge; one colour
  per link type (LLDP, CDP, EDP, ARP); three status lights; and an ink and a
  fill for each of six device families.
- **JavaScript holds the property names, never a colour.** `CANVAS_TOKENS`
  maps each role to its property and to a CSS system colour (`Canvas`,
  `CanvasText`, `GrayText`, `Highlight`), used only when the property cannot be
  read: under jsdom, where custom properties come back empty or as an
  unresolved `var(…)`, or before the stylesheet applies. A system colour keeps
  the map legible in the viewer's own scheme, where an empty string would
  leave vis-network drawing its defaults.
- **Scoped to the page.** The properties are declared on `.nmap-page`, not on
  `:root`, so defining them changes nothing on any other page.
- **The icons are templates.** The 22 SVGs keep their shapes; each colour is a
  slot (`{ink}`, `{fill}`, `{canvas}`, `{ok}`, `{alert}`, `{info}`) filled from
  the palette. The data URLs are painted once per palette rather than once per
  node.
- **The theme can change after the graph is drawn**, and does: PreferencesContext
  sets `data-theme` when the preferences request returns, which can be after
  the topology request. A MutationObserver on `<html>`'s `data-theme` re-reads
  the palette and, if it changed, re-syncs the existing DataSets the way a
  filter change does. The network is not rebuilt, so zoom and pan survive; a
  unit test pins that the same Network instance is kept in both directions.
- **The -text tokens, not the -solid ones.** In the light theme
  `--ccure-warning-solid` measures 2.38:1 and `--ccure-info-solid` 2.21:1
  against the surface, below the 3:1 a graphic needs. Labels and icon outlines
  use the -text tokens, and icon bodies the tinted -bg tokens.
- **No new design-system primitive.** The resolver is two functions and a hook
  inside the page.

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures; the
unit tests cover the same points and the parts the harness cannot reach.

- **Controls had no names.** The mask, window and layout selects and the
  search box were unlabelled on every capture (4, or 3 on a scan's map, where
  there is no window). After: 0, each with a visible label.
- **Headings.** The sidebar sections were `h3` beneath the page's `h1`; they
  are `h2`, as is the selected node, and "Recommended Next Actions" is an `h3`.
  The `h1`'s accessible name no longer includes the 🗺️ glyph.
- **The selects had no focus ring.** The legacy stylesheet set `outline: none`
  on them: the window and mask probes reached them with no visible focus
  (`ring=0`). After: `ring=1` on both, in both themes.
- **Failures were plain text.** A failed load is an alert beside its Retry
  button (0 → 1 alert on the error and denied captures), loading is a status,
  and selecting a node on the canvas is announced in a polite status region.
- **Contrast.** Failing text pairs, before → after:

  | Capture              | Light  | Dark  |
  | -------------------- | ------ | ----- |
  | Org-wide map         | 13 → 0 | 3 → 0 |
  | Scan's map           | 13 → 0 | —     |
  | At 390 px            | 13 → 0 | —     |
  | Empty map            | 13 → 0 | —     |
  | Failed load          | 16 → 0 | —     |
  | Without `scans:read` | 16 → 0 | —     |

  Legacy defects now gone: the ARP and neighbour-discovery pills at 1.77
  (present) and 1.57 (missing); the dividers at 1.18 and 1.23 (1.72 and 1.41
  in dark); the header counts at 2.32; Refresh and the subtitle at 2.45 (the
  subtitle 3.75 in dark); Select All, Clear, the summary counts and the error
  text at 2.77; Retry at 3.39.

- **Canvas contrast**, which the harness cannot see, is measured from the token
  files by the unit tests, in both themes. Lowest ratios:

  | Pair                               | Floor | Light | Dark |
  | ---------------------------------- | ----- | ----- | ---- |
  | Labels on the canvas halo          | 4.5   | 5.43  | 7.59 |
  | Edges and link types on the canvas | 3     | 4.74  | 7.59 |
  | Icon outlines on the canvas        | 3     | 5.43  | 7.59 |
  | Icon detail on the icon's own fill | 3     | 5.09  | 5.07 |
  | Status lights on their icon's fill | 3     | 4.33  | 7.75 |

  The legacy canvas drew pale labels with a navy halo in both themes, on a
  white background in the light theme; it was never measured.

- **Keyboard.** Tab stops are unchanged in number on every capture (36 on the
  org-wide map, 35 on a scan's, 37 at 390 px, 32 empty, 33 failed, 29 denied).
  All seven probes reach the same controls before and after, with a visible
  ring. Names in the tab order lose their glyphs.
- **Dialogs and the evidence table** open only from a click on a node, so the
  harness cannot reach them. The unit tests pin CcureModal's dialog role and
  name, the table's caption and scoped headers, the navigation region for the
  pager, and that "Matched" links announce their new tab.
- **Two measurement notes.**
  - The harness's roles census counts elements carrying an explicit `role`
    attribute. The legacy page wrote `role="region"`, `"complementary"` and
    `"group"` on `<div>`s; the migrated page uses `<section aria-label>`,
    `<aside aria-label>` and a `<fieldset>` with a legend, which carry those
    roles natively, so the census shows them as gone. The unit tests find all
    three by role and name.
  - The probe's focus snapshot names an element from `aria-label` or its text,
    so the subnet checkbox — now named by its wrapping `<label>` — reads as an
    empty name there. The names census, which follows labels, reports 0
    unlabelled controls.
- **Not changed:** vis-network's seven navigation buttons are pointer-only
  `<div>`s on every capture with a graph, before and after (§7).

---

## 3. Security validation

- **Requests are unchanged, and pinned on the legacy page first.** The
  contract tests assert what leaves the page:
  - `GET /topology/map?subnet_mask=24&active_within_days=30` on `/topology`
    and `/scan/topology-map`; `GET /topology/map/{id}?subnet_mask=24`, with no
    window and no window control, from the route parameter or `?scan_id=`;
  - one request per load; a refetch when the mask or window changes, the
    window keeping its value, and no `active_within_days` for "All recorded
    history"; Refresh and Retry refetch, and Refresh cannot fire while a load
    is in flight;
  - an `afterEach` in every test that nothing was sent with POST, PUT, PATCH
    or DELETE and that every GET went to `/topology/map`.
- **Failure handling is unchanged:** `success: false` reads "Failed to load
  topology data"; a rejected request shows the API's `detail`, else the
  error's message; a Network that cannot start reads "Failed to load network
  engine."; a load clears hidden subnets and the selection.
- **The 15-subnet confirmation is unchanged:** the same `window.confirm` text,
  asked only above 15 visible non-MAC-only subnets; declining expands nothing,
  and hiding a subnet can bring the count back under the threshold.
- **The graph is unchanged:** node ids, labels, sizes, levels, fonts,
  images, tooltips, edge widths and dashes, the 50-host cap, duplicate-id
  dropping, the layout, physics and interaction options, the initial and
  on-request fit, rebuild on a layout change, no rebuild while searching, and
  destroy on unmount — all pinned.
- **Tooltips are still plain text.** Node and edge titles are strings (pinned
  exactly), and vis-network 9.1.13 writes a string title with `innerText`, so
  hostnames, vendors and port descriptions from scanned devices cannot inject
  markup. The SVG icons are constant templates: no scanned value reaches them,
  only token values.
- **Routes and permission are unchanged.** `App.jsx` still mounts the page on
  the same three routes behind the base sign-in check and no permission gate
  (asserted from the source); a visitor who is not signed in is sent to
  `/login` with nothing requested; a signed-in user without `scans:read`
  mounts the page and sees the backend's 403 detail.
- **Navigation is unchanged:** "View Asset Details" goes to `/assets/{id}`;
  the guidance dialogs go to `/scan/new` or `/assets`, or close; matched
  endpoints still open `/assets/{id}` in a new tab with
  `rel="noopener noreferrer"`.
- **The harness never wrote or navigated away.** No refused write in any
  report, every `nm-` capture ended on its own route, and the only non-GET is
  the session refresh every page makes.
- **Nothing new executes or leaves the site.** No new dependency, no
  `dangerouslySetInnerHTML`, no new kind of resource (the icons were already
  `data:image/svg+xml` URLs). Security headers and the air-gap host set are
  identical.

---

## 4. Intentional changes

1. **Headings.** The title keeps its `h1`, without the 🗺️ glyph in its name.
   The sidebar sections (Subnets, Device Types) and the selected node are `h2`,
   which were `h3`; "Recommended Next Actions" is an `h3`, which was bold text.
   The empty state's title is CcureEmptyState's paragraph, where it was an
   `h3`.
2. **Controls are labelled.** The mask, window and layout selects have visible
   labels ("Subnet mask", "Seen within", "Layout"), which were unassociated
   text, and the search box is labelled "Search hosts"; placeholders are
   unchanged, and the select titles are kept as tooltips.
3. **Buttons are CcureButton, named by their words.** Select All, Clear, Retry
   and the recommended actions carried `aria-label`s in place of their visible
   text — "Clear" was announced as "Deselect and hide all subnets on graph",
   which does not contain the word a speech-input user would say. Glyphs no
   longer lead the names ("↻ Refresh" is "Refresh"). Refresh uses CcureButton's
   loading state while a load is in flight, with the same "Syncing..." text.
4. **Subnet checkboxes** are named by the subnet and grouped as "Visible
   subnets" (a fieldset with a visually hidden legend). They were each named
   "Toggle visibility of subnet …".
5. **Selecting a node on the canvas is announced** ("Selected subnet
   10.40.1.0/24") in a polite status region. The canvas itself is unchanged.
6. **Both dialogs are CcureModal**: a portal, focus trap and restoration,
   Escape, and the rest of the page hidden from assistive technology while
   open. Titles are the same words without their glyphs; the close button is
   "Close dialog"; the pager and the guidance buttons sit in the dialog footer.
7. **The endpoint evidence is a table.** It was a `role="table"` `<div>` whose
   rows held plain `<span>`s, with no cells or column headers. It is
   CcureTable, captioned "Endpoints in {subnet}", with `scope="col"` headers,
   the MAC as each row's header and "No endpoints match this filter." inside
   the table. The pager is a navigation region, "Endpoint pages".
8. **"Matched" links say they open a new tab** (visually hidden text); the
   link, its target and `rel` are unchanged. "View Asset Details" names its
   node.
9. **Messages are design-system components:** the failed load is a CcureAlert
   beside Retry, loading is CcureLoader, the 50-host cap is a CcureAlert
   warning that does not interrupt, and the ARP and neighbour-discovery
   results are badges.
10. **The canvas follows the theme.** The legacy canvas drew the same dark
    palette in both themes. Labels, halos, icons, edges and the legend
    swatches now come from tokens (§1.1).
11. **Device colours are grouped into six families.** The legacy palette gave
    most of the 21 categories their own hue, unmeasured. Hues now follow the
    design system's six: routing and load balancing; perimeter and printing;
    switches and endpoints; wireless, modems and subnets; operational
    technology and mobile; compute, storage and unknown. Icon shapes and labels
    still distinguish every category. Gradients inside the icons are flat
    colours.
12. **The node shadow uses vis-network's default colour** (`rgba(0,0,0,0.5)`);
    the page passed `rgba(0,0,0,0.4)`.
13. **vis-network's tooltip is styled from tokens** inside the map; its own
    stylesheet painted it the same pale yellow in both themes.
14. **Decorative glyphs are hidden** from assistive technology: 🗺️, ↻, 🔍, 📂,
    📁, 📊, 🔗, → and the guidance dialogs' 🚀, 🔌, 🌐 and 📋.
15. **At 900 px and below the map is 450 px tall** and the controls stack, with
    the subnet and legend cards beneath it. The legacy layout stretched the map
    to fill the viewport's height on a narrow screen (about 1,200 px at 390 px),
    pushing the sidebar far below. Wider screens keep the legacy height.

---

## 5. Retirement

- **The page no longer uses anything from `scan.css`** (`btn`,
  `btn--primary`, `btn--secondary`). `scan.css` is untouched and still used
  elsewhere.
- **Legacy `Modal` consumers:** three remain (OrganizationManagement,
  Phase3Results, ComplianceWorkspace). Its header comment still lists
  NetworkMap; the file was out of scope.
- `NetworkMap.css` is still page-owned and imported only by NetworkMap.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,sd-,p2-,p1-,amt-`
exits 0:

- All 104 unchanged-page captures are identical in every category, Batch 20's
  11 AMT captures included.
- pre-b vs post-b is also 104 / 104.
- Post determinism (post-a vs post-b) is 111 / 111.
- 104 of 111 captures are identical overall; the 7 NetworkMap captures changed.

Every changed category on those 7 captures is accounted for:

| Category                                         | Captures | Why it changed                                                                                                                                                           |
| ------------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| names, headings, roles, live                     | 7 each   | §2: labelled controls; `h3` → `h2`; explicit roles replaced by native elements (a census artefact, §2); the selection status region, and the failed load's alert         |
| contrast                                         | 7        | 0 failing pairs on every NetworkMap capture                                                                                                                              |
| tabOrder                                         | 7        | Names without glyphs; the same number of stops                                                                                                                           |
| probes                                           | 2        | `nm-org` (both themes): the selects now show a focus ring; the checkbox's focus-snapshot name (§2)                                                                       |
| inline, classes, styles, rects, text, screenshot | 7        | The restyle. The legend's 12 inline dots and the canvas container's inline `display` are gone; what remains is vis-network's own elements and the shell's two quota bars |
| requests, writes, url, runtime                   | —        | **Unchanged**                                                                                                                                                            |
| tables, dialogs, ariaStates, clickable, overflow | —        | Unchanged: no capture opens a dialog or the evidence table, and the 7 pointer-only targets are vis-network's navigation buttons in both builds                           |

Screenshots were reviewed side by side for all 7 captures: the page, the
empty, failed and denied states, the canvas in both themes, and the 390 px
layout (§4, item 15).

---

## 7. Deferred, and found but not fixed

- **The graph is pointer-only.** Selecting a node — and everything that
  follows from it: the detail panel, endpoint evidence, recommended actions and
  the asset link — starts with a click on the canvas. vis-network's keyboard
  navigation is off, and turning it on would change the graph's interaction,
  which this batch was told not to do. The new announcement says what was
  selected; it does not make selection keyboard-reachable.
- **vis-network's own controls:** its seven navigation buttons are `<div>`s
  reachable only by pointer, and its canvas frame is an unnamed tab stop
  (`tabIndex = 0`).
- **The routes are not gated on `scans:read`.** A signed-in user without it
  loads the page and meets the backend's raw 403 text as a failed load.
- **The 15-subnet confirmation is the browser's native `window.confirm`**, kept
  exactly as the contract requires.
- **Hosts are capped at 50 per expanded subnet** on the graph, and evidence
  pages are fixed at 50 rows.
- **Graph search matches only label, IP and MAC**, while the evidence search
  matches nine fields; MAC-only endpoints are never expanded by search.
- **`hasFdb` is computed and never shown.**
- **The MAC-only cluster is recognised by its literal name**, "MAC-Only / FDB".
- **Canvas contrast is measured from the token files**, not from pixels: the
  harness cannot see text drawn on a canvas.
- **Force-directed layout is not captured.** Its physics runs on after
  stabilising for an unbounded time; the layout change is covered by the unit
  tests.
- **Harness:**
  - the router ignores query strings, so one payload answers every mask and
    window;
  - node clicks, both dialogs and asset navigation are covered by the unit
    tests only;
  - the roles census counts explicit `role` attributes, and the focus snapshot
    does not follow `<label>` associations (§2).
- **Carried:**
  - the Toast and Modal shims, and the legacy Modal's three remaining
    consumers;
  - CVELink (`cve-id`) and CcureTabs (`active`) still match `dashboard.css`
    selectors;
  - from batch 20: the AMT import has no confirmation and `assets:update` is
    its only check; a failed export is silent and its object URL never
    revoked; the fixed 1.5-second post-import reload; per-keystroke untrimmed
    filters; a failed statistics load reads as "never imported"; Department
    shows the company name; asset links are full page loads; the fixed page
    size; the harness's file-input, download and text-entry limits;
  - from batches 15 to 19: ScanContext's duplicate GET, the `cc_executionMode`
    reset, polling that never times out, Phase 3's automatic start,
    ExportPanel's CSV formula injection and the truncated custom port list.

---

## 8. Result

**GO for review.** Every gate passed on the final build, and no STOP condition
was reached:

- the topology requests — method, both paths, `subnet_mask`,
  `active_within_days` and its 30-day default — are unchanged and pinned, and
  nothing is written;
- the graph's layout, physics, hierarchy, node formatting, expand and
  collapse, filters, search, the 15-subnet confirmation, node clicks, both
  dialogs and all navigation are unchanged and pinned;
- the routes and their sign-in-only protection are unchanged;
- no write, no unexpected navigation, no off-origin request, no CSP issue, no
  exception and no console error in any capture;
- determinism, sensitivity and the regression gate over every previously
  migrated page passed;
- security headers and the air-gap host set are identical;
- no shared component, design-system primitive or global stylesheet was
  modified.

Nothing from Batch 21 is committed.
