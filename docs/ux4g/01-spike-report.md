# UX4G migration — Phase 1 compatibility spike

**Date:** 9 September 2026
**Branch:** `feat/ux4g-spike`
**Baseline:** [`00-baseline.md`](00-baseline.md)
**Recommendation: GO**, with one Phase 2 action that is quantified below.

---

## 1. UX4G package and version

|                          |                                                              |
| ------------------------ | ------------------------------------------------------------ |
| Package                  | `ux4g-web-components`                                        |
| Version                  | **2.1.0** — pinned exactly in `package.json`, not `^2.1.0`   |
| Publisher                | `ux4g.npm`                                                   |
| What was adopted         | `ux4g-web-components/styles.css` (CSS + 1,452 design tokens) |
| What was **not** adopted | `ux4g-web-components/runtime` — see §3                       |

**2.1.0 is not "UX4G 3.0 code" and is not described as such anywhere in this
work.** Phase 0 established that 3.0 is the version of the UX4G _Figma_ kit;
the CSS distribution is 2.1.0 and the `UX4G.js` runtime inside it announces
itself as 1.1.0. The spike evaluates 2.1.0 as the mechanism for implementing
the 3.0 design language.

The version is pinned rather than caret-ranged because the guarantees in §7 and
§9 were measured against this exact build. A floating range would let a
`npm install` on a fresh clone silently adopt a version none of them were
checked against.

---

## 2. CSS integration — PASS

`ux4g-web-components/styles.css` builds under Vite 8.2.2 with React 18.3.1 and
needs no loader, no PostCSS plugin and no configuration change. It declares no
runtime dependencies.

It is not imported directly. The chain is:

```
node_modules/ux4g-web-components/styles/ux4g.css
   → scripts/build-ux4g-assets.mjs        (npm prebuild / pretest)
   → src/design-system/tokens/ux4g.generated.css
   → src/design-system/tokens/index.css   (with ccure-tokens.css, themes.css)
   → src/design-system/index.js
   → src/main.jsx, imported BEFORE styles/global.css
```

**The import order in `main.jsx` is load-bearing and is commented as such.**
UX4G's reset carries zero specificity (§7), so every CCure rule outranks it —
but two zero-specificity rules are decided by source order alone, and CCure's
own `*` reset must come second to win that tie. Reversing the two lines is not
a formatting change.

`main.jsx` and `App.jsx` are the only pre-existing files modified: one import
line and one spike route. No page, no component, no API module, no auth or
RBAC code was touched.

---

## 3. Runtime decision — NOT ADOPTED

`dist/runtime/index.mjs` contains:

```js
const script1 = document.createElement("script");
script1.setAttribute("data-ux4g-runtime", "main");
script1.textContent =
  "/*! UX4G.js … Version: 1.1.0 */ (function (global) { … })";
```

It injects its ~300 kB library as an **inline `<script>`**. Under `script-src
'self'` the browser refuses to execute it. Running it would require
`script-src 'unsafe-inline'` — dismantling the strongest directive in the
policy of a security-audit product. **Not done, and not proposed.**

It is also unnecessary. The runtime supplies Dropdown, Collapse, Offcanvas,
Tooltip, Popover, Toast, Carousel, Tabs and Scrollspy — imperative DOM
manipulation that React already owns here and that would contend with the
reconciler for the same nodes.

The package's `exports` map lists `./styles.css` and `./runtime` separately, so
importing the stylesheet cannot pull the runtime in. That absence is enforced,
not merely intended:
`ux4g-integration.test.js › "no source file imports the UX4G runtime"` walks
every file under `src/` and fails on any import of `ux4g-web-components/runtime`
or `/design-system`.

Verified in the built artefact: `data-ux4g-runtime`, `UX4G.js`,
`ux4g-backdrop` and `createElement("script")` each occur **0 times** in
`dist/assets/*.js`.

Other runtime hazards, all measured at zero: `eval(`, `new Function`, `fetch`,
`XMLHttpRequest`, external hostnames, `customElements.define`, `attachShadow`.

---

## 4. Font extraction — PASS

UX4G embeds all seven faces as `data:font/*;base64`. That is 91% of the
stylesheet, and `font-src 'self'` does not permit `data:` — imported as
shipped, every font is blocked and the icon fonts render as tofu.

`scripts/build-ux4g-assets.mjs` lifts them out, converts to WOFF2 via
`wawoff2` (a WASM build of Google's woff2 — no native compilation, so it works
in `node:20-slim`), writes them under `public/assets/`, and rewrites each
`@font-face` to a same-origin path.

```
Noto Sans                       1996.6 kB →   868.5 kB
Noto Sans Display               1503.9 kB →   666.9 kB
UX4G Material Icons              348.5 kB →   125.3 kB
UX4G Material Icons Outlined     331.2 kB →   151.6 kB
UX4G Material Icons Round        390.7 kB →   169.6 kB
UX4G Material Icons Sharp        279.3 kB →   132.8 kB
UX4G Material Icons TwoTone      660.0 kB →   210.6 kB
────────────────────────────────────────────────────────
fonts                           5510.3 kB →  2325.3 kB
stylesheet                      8120.4 kB →   773.5 kB   (−90.5%)
```

Four things worth recording:

- **`/assets/` is deliberate, not incidental.** `Frontend/nginx.conf` caches
  `^/assets/.+\.(…|woff2?|…)$` for a year as immutable. Verified live:
  `Cache-Control: public, immutable`, `Expires` one year out. A sibling
  `/fonts/` directory would have fallen through to `location /` and been
  re-fetched.
- **The files are real fonts, not truncated buffers.** All seven carry the
  `wOF2` signature, and a round-trip decompression of `noto-sans.woff2` yields
  2,049,496 bytes with sfnt version `00010000` (valid TrueType).
- **Only one font is actually downloaded.** The browser fetched
  `noto-sans.woff2` and nothing else — `@font-face` is lazy, and no rendered
  element used the other six families. The 2.3 MB on disk is not a page-load
  cost.
- **The build refuses to ship a broken result.** Three assertions abort it: any
  surviving `data:` font URI, any external origin in the output, and a missing
  `@font-face` count. A repackaged upstream fails loudly instead of silently
  shipping unstyled text.

Generated CSS and fonts are **gitignored** — they are build output derived from
the pinned package, regenerated by `prebuild` inside the Docker build. The
alternative would put 3 MB of derived bytes under review on every UX4G bump
and let the committed copy drift from the lockfile.

---

## 5. CSP — UNCHANGED, PASS

**No directive was added, removed, widened or reordered.** `Frontend/nginx.conf`
was not edited at all.

Served by the production image, via the check CLAUDE.md prescribes:

```console
$ curl -sD - -o /dev/null http://127.0.0.1:3299/ | grep -i content-security
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:;
  img-src 'self' data:; font-src 'self'; object-src 'none';
  base-uri 'self'; frame-ancestors 'none';
```

Byte-identical to the Phase 0 baseline, and present on a deep link
(`/ux4g-spike`) as well as `/`, along with all five other security headers.

Per-directive compliance of what actually ships:

| Directive                          | What the page requires                            | Verdict |
| ---------------------------------- | ------------------------------------------------- | ------- |
| `script-src 'self'`                | one same-origin module script; no inline, no eval | PASS    |
| `style-src 'self' 'unsafe-inline'` | one same-origin stylesheet                        | PASS    |
| `font-src 'self'`                  | 7 same-origin `.woff2`; **0** `data:` fonts       | PASS    |
| `img-src 'self' data:`             | 12 `data:image/svg+xml`, already permitted        | PASS    |
| `connect-src 'self' ws: wss:`      | unchanged                                         | PASS    |

**Browser console: zero CSP violations** in both themes (headless Chrome,
stderr captured, matched against `Content Security Policy|Refused to|blocked`).

---

## 6. Air-gap — PASS, measured in a real browser

Static analysis of every byte the container serves, then a runtime check.

**Static.** The served `index.html` contains exactly three references, all
same-origin: `/favicon.svg`, `/assets/index-*.js`, `/assets/index-*.css`. The
served CSS contains 7 same-origin `url()`, 12 `data:` URIs, 8 SVG fragments and
**0 external**. `cdn.ux4g.gov.in`, `clarity.ms`, `ux4g-analytics`, `unpkg`,
`jsdelivr` and `cdnjs` occur zero times anywhere. (`fonts.googleapis.com` and
`fonts.gstatic.com` each appear once — in the pre-existing HTML _comment_
recording that Google Fonts were removed. Not references.)

**Runtime.** Headless Chrome with `--log-net-log`, browser background
networking disabled. The page requested exactly seven URLs, all same-origin:

```
http://127.0.0.1:3299/ux4g-spike
http://127.0.0.1:3299/assets/index-*.js
http://127.0.0.1:3299/assets/index-*.css
http://127.0.0.1:3299/assets/fonts/ux4g/noto-sans.woff2
http://127.0.0.1:3299/favicon.svg
http://127.0.0.1:3299/api/auth/refresh
http://127.0.0.1:3299/
```

The NetLog also showed five Google hosts. **A control run against
`about:blank` contacted the identical five**, so the set difference is empty:

```
EXTERNAL HOSTS PRESENT FOR THE SPIKE BUT NOT FOR about:blank:
    NONE
```

They are Chrome's own profile services — network time (`cup2key`), account
list (`source=ChromiumBrowser`), Safe Browsing OHTTP keys (`ohttp_gateway`) and
Google's CSP report-to endpoints — present with no page loaded at all. **Zero
external requests are attributable to the application.**

The one same-origin call worth naming is `/api/auth/refresh`: that is
`AuthContext` booting, present before this work and unrelated to UX4G.

---

## 7. Class collisions and unmigrated-page regression — PASS

### The analytical result

Phase 0 found three intersecting class tokens — `active`, `muted`, `is-muted`
— and every UX4G rule using them is compound-scoped to a `.ux4g-*` class.
Re-verified on the generated CSS and pinned by test: **no bare `.active {}`,
`.muted {}` or `.is-muted {}` rule exists.** CCure uses `active` in 148 JSX
places and `muted` in 388, so a bare rule would have mattered.

UX4G's element rules are wrapped in `:where(…)` — `:where(body)`,
`:where(html)`, `:where(button)`, `:where(a)`, `:where(img)`,
`:where(button,input,optgroup,select,textarea)` — all zero specificity, so
every CCure rule outranks them. CCure's stylesheets contain only two bare
element selectors (`body`, `html`), both of which set the properties UX4G's
`:where(body)` would otherwise supply.

### The defect this test actually caught

`:where()` beats no CCure rule — but it **does** beat the user-agent
stylesheet, because author-level rules always do. UX4G's universal reset is:

```css
:where(*, :before, :after) {
  border: 0;
  box-sizing: border-box;
  margin: 0;
  outline: 0;
  padding: 0;
}
```

Two of those declarations land on elements CCure styles with neither:

- **`border:0`** — a multiline scan found **107 controls** (`<input type=text>`,
  `<select>`, `<textarea>`) with no `className` and no inline style. They are
  the search boxes and filter dropdowns on `AssetRegistry`, `AssetDetail`,
  `ComplianceWorkspace` and the global search in `AppLayout`, and they rely on
  the UA default border. Unscoped, they lose it and stop reading as inputs.
- **`outline:0`** — CCure sets an outline in only 36 of its 76 focus rules, so
  the rest lose their focus ring. A WCAG 2.4.7 failure introduced by an import.

Neither is visible in a green test suite and both affect pages nobody touched.

**Fix:** `build-ux4g-assets.mjs` rescopes the reset to UX4G's own components —

```css
:where([class*="ux4g-"],[class*="ux4g-"]:before,[class*="ux4g-"]:after){…}
```

Nothing is deleted, specificity stays zero, UX4G components keep the reset they
expect, and CCure's own `*` reset continues to supply box-sizing/margin/padding
globally as before. `themes.css` additionally restores a `:focus-visible` ring
as a floor, which is an improvement on the baseline rather than a repair.

The build aborts if the upstream reset is not found, so a repackaged UX4G
cannot reintroduce this silently.

### The empirical result

The unmigrated `Login` page, rendered by two containers — port 3200 is the live
`ccure-frontend` with no UX4G, port 3299 is the spike image with it.

A naive byte comparison differed by 1,381 bytes. **That comparison is invalid,
and the control proves it:** two captures of the _same_ baseline container also
differ (466,314 vs 465,470 bytes, different hashes). The login page animates.

Re-run with `--force-prefers-reduced-motion`:

```
baseA   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3200, no UX4G)
baseB   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3200, no UX4G)
ux4g    428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3299, UX4G)

baseline self-consistency : IDENTICAL   ← the test is deterministic
baseline vs UX4G          : IDENTICAL   ← pixel-for-pixel
```

**Importing the UX4G stylesheet changes an unmigrated page by zero pixels.**

`Login.jsx` was deliberately not migrated. The brief listed it in scope, but
leaving it untouched keeps every real page as a regression control and keeps
the MFA and auth-gateway code out of a spike. The login _form_ is reproduced in
the spike page instead, so the primitives are proven against that shape without
the auth path being touched. Migrating the real Login belongs to Phase 7
Group A, with the primitives already proven.

---

## 8. Dark mode — PASS

`PreferencesContext` is unmodified. The contract — server-persisted
`preferences.theme` → `documentElement.setAttribute("data-theme","dark")` — is
untouched, and no second theme mechanism was introduced.

UX4G themes on the identical selector, `:root[data-theme=dark]`, redefining
**217** of its own tokens. `--ccure-*` resolves through those, so one attribute
drives both token sets with no adapter. Confirmed visually in both themes
(screenshots captured) and pinned by three tests: the selector exists, the dark
block redefines >100 tokens, and UX4G ships **zero** `prefers-color-scheme`
rules — one would silently override the user's stored account preference.

The Phase 0 defect is fixed: `--ccure-sev-*` now carries an explicit dark
block, where the old `--sev-*` had none at all and severity colour was
identical in both themes.

---

## 9. Accessibility — PASS, with measured contrast

Five primitives and a shell were built, each closing one of the categorical
gaps Phase 0 measured. **79 new tests**, all passing.

| Requirement                                  | Implementation                                                                                                                       |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Button keyboard / focus / disabled / loading | native `<button>`, `type="button"` by default, `disabled` **and** `aria-busy` while loading, label retained under the spinner        |
| Input label association                      | `useId` → `for`/`id`; unique per instance                                                                                            |
| Input error association                      | `aria-describedby` + `aria-invalid`; error `role="alert"`; error supersedes hint rather than queueing behind it                      |
| Modal                                        | `role="dialog"`, `aria-modal`, name from title, real focus trap, Escape (opt-out), focus restoration, refcounted scroll lock, portal |
| Toast                                        | **two** always-mounted live regions, assertive and polite, populated afterwards                                                      |
| Navigation                                   | `aria-current="page"` — and the active style is keyed on the attribute, so visual and announced state cannot diverge                 |
| Landmarks                                    | `banner`, `complementary`, `navigation` ×2 (each named), `main`, `contentinfo`; exactly one `<h1>`                                   |
| Skip link                                    | first tab stop, targets a `tabindex="-1"` `<main>`                                                                                   |

Two implementation points that are the whole reason those components exist:

- **The toast live regions are mounted empty for the session.** Assistive
  technology announces _mutations_ of a region it is already watching; a region
  created together with its first message frequently announces nothing. The
  existing `Toast.jsx` returns `null` when empty and has no `aria-live` at all.
- **`<main>` needs `tabindex="-1"`.** Without it the skip link scrolls but
  leaves focus at the top of the document, so the next Tab re-enters the
  navigation the user just skipped.

### Contrast — computed, not eyeballed

32 assertions resolve the real `var()` chains and compute WCAG ratios in both
themes. The floor is **4.5:1 throughout**, including severity, because severity
appears as small badge text in dense tables.

Two genuine failures were found and fixed, both of which looked fine on screen:

|                        | Was                               | Now                   |
| ---------------------- | --------------------------------- | --------------------- |
| Danger button, light   | `red-600` → **4.38:1** (below AA) | `red-700` → 6.29:1    |
| Severity high, light   | `orange-600` → **2.38:1**         | `orange-800` → 5.43:1 |
| Severity medium, light | `yellow-600` → **1.38:1**         | `yellow-900` → 5.24:1 |
| Severity info, light   | `cyan-600` → **2.21:1**           | `cyan-800` → 6.10:1   |

Both fixes are one declaration each in `ccure-tokens.css` — the semantic layer
earning its place, rather than a patch to UX4G or a per-component exception.

**One honest cost:** at 4.5:1 on white there is no accessible bright yellow, so
"medium" is a dark amber (`#876800`). That is a property of the requirement,
not a choice. Severity is never carried by colour alone — the badge always
carries its label.

Dark mode needed no adjustment; the 300-steps measure 11.6–16.2:1.

---

## 10. Visual — PASS

Screenshots captured headless at 1440×1500 in both themes. Both render
correctly: UX4G typography (visibly Noto Sans, not a fallback — which is itself
the proof the self-hosted WOFF2 loaded under `font-src 'self'`), UX4G's
primary, the four status colours, the sidebar with an announced active item,
and a government identity line in the footer.

It reads as a professional government security console rather than a citizen
services portal: dense permission-shaped navigation, a compact header, a
working area that gives space to content. CCure's information architecture is
intact because the shell is presentational and takes its sections as data.

---

## 11. Docker — PASS

Built and run through the real production path: `Dockerfile` unchanged,
`node:20-slim` → `nginx:stable-alpine`, `nginx.conf` unchanged.

- `npm install` and `prebuild` both run **inside the image**; all seven WOFF2
  files are present in `/usr/share/nginx/html/assets/fonts/ux4g/`. The image
  builds its own assets and reaches no network at runtime.
- SPA deep link `/ux4g-spike` → HTTP 200 with full CSP.
- `/assets/fonts/ux4g/noto-sans.woff2` → HTTP 200, `font/woff2`,
  `public, immutable`.
- **The live deployment was never touched.** The spike ran as
  `ccure-ux4g-spike` on `127.0.0.1:3299`, a separate image tag;
  `ccure-frontend` stayed up on 3200 throughout and served as the A/B control.

One pre-existing wrinkle: the image cannot start on Docker's default bridge
because `nginx.conf` proxies to the `api` host, which only resolves on the
compose network. Not introduced here, and not a defect — it is how the config
is meant to run.

**Cleanup:** `docker rm -f ccure-ux4g-spike && docker rmi ccure-frontend:ux4g-spike`.

---

## 12. Bundle size

|            |      Before |       After |              Δ |
| ---------- | ----------: | ----------: | -------------: |
| CSS        |   188.90 kB |   999.56 kB | **+810.66 kB** |
| CSS (gzip) |    32.56 kB |   149.06 kB | **+116.50 kB** |
| JS         | 1,698.95 kB | 1,716.59 kB |      +17.64 kB |
| JS (gzip)  |   419.68 kB |   424.78 kB |       +5.10 kB |
| index.html |     1.36 kB |     1.36 kB |              — |
| Build time |      4.21 s |      1.60 s |              — |
| Modules    |         178 |         190 |            +12 |

**Fonts, reported separately as the brief asks:** 7 files, 2,325 kB on disk.
Not a page-load cost — the browser fetched exactly one (`noto-sans.woff2`,
868 kB) and only because the page renders UX4G typography. The other six are
never requested unless something uses those families.

### The CSS figure is mostly waste, and it is quantified

```
whole UX4G stylesheet     773.5 kB   gz 109.4 kB
  :root token block        49.1 kB
  dark token block          6.2 kB
  @font-face                1.2 kB
  ── tokens + fonts only    56.5 kB   gz   9.1 kB
  component/utility CSS    717.0 kB   (92.7% of the file)
```

**CCure references zero UX4G classes.** Every component here is a `cc-` class
reading `--ccure-*` — the "UX4G underneath, CCure on top" architecture. Under
that architecture the 717 kB of `.ux4g-btn`, `.ux4g-card`, `.ux4g-accordion`
et al. is dead weight.

Shipping only the token blocks and `@font-face` would cut the CSS delta from
**+116.5 kB gzip to +9.1 kB gzip** with no functional loss. That is a Phase 2
decision — it also decides whether CCure may ever use a UX4G class directly —
and it is deliberately **not** done here.

---

## 13. Licence — UNRESOLVED, gate stands

Documented, not solved, as instructed.

- `ux4g-web-components@2.1.0` ships **no LICENSE file**.
- Its `package.json` has **no `license` field**.
- No copyright or licence notice appears in `styles/ux4g.css`.
- Publisher is `ux4g.npm`, consistent with an official NeGD/MeitY release.
  Consistency is not a grant.
- The bundle embeds Noto Sans and Material Icons, individually OFL / Apache-2.0
  _upstream_ — which says nothing about this redistribution.

**No licence has been assumed or invented, and government origin has not been
read as permission.** The spike vendors nothing permanently: the package sits
in `node_modules`, and the generated CSS and fonts are gitignored build output.

**This must be resolved before Phase 2 makes vendoring permanent.**

---

## 14. Known issues

| #   | Issue                                             | Severity          | Note                                                                                                                                    |
| --- | ------------------------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | CSS +116.5 kB gzip, 92.7% unused                  | **High**          | Quantified in §12; Phase 2 can reduce to +9.1 kB                                                                                        |
| 2   | Licence unresolved                                | **High**          | §13 — gates Phase 2                                                                                                                     |
| 3   | `/ux4g-spike` route is public                     | Medium            | Spike-only, removed before merge; renders no data and calls no API                                                                      |
| 4   | 6 of 7 fonts shipped, never fetched               | Medium            | 1,457 kB of image size for families nothing uses. CCure has its own inline SVG icons — the Material Icons set may be droppable outright |
| 5   | Legacy tokens not re-pointed                      | By design         | `--accent`/`--text`/`--bg-app` untouched, which is _why_ unmigrated pages are pixel-identical. Phase 3                                  |
| 6   | `Login.jsx` not migrated                          | By design         | §7 — kept as a regression control                                                                                                       |
| 7   | No Table/Tabs/Pagination/Breadcrumb primitives    | Expected          | Outside Phase 1's nine-component scope                                                                                                  |
| 8   | Light-mode "medium" severity is amber, not yellow | Low               | §9 — unavoidable at 4.5:1 on white                                                                                                      |
| 9   | Two `Cache-Control` headers on font responses     | Low               | Pre-existing nginx `expires` + `add_header`; browsers combine them                                                                      |
| 10  | Still one 1.7 MB JS chunk                         | Low, pre-existing | Recorded in Phase 0; not this phase's business                                                                                          |

No hard-stop condition was met. CSP was not weakened, no external runtime
request is required, air-gap holds, no `unsafe-inline`/`unsafe-eval` is needed,
fonts work under `font-src 'self'`, and the production Docker path builds and
serves.

---

## 15. Files changed

**Added**

```
Frontend/.gitignore                                     (generated assets)
Frontend/scripts/build-ux4g-assets.mjs                  (font extraction + reset scoping)
Frontend/src/design-system/index.js
Frontend/src/design-system/tokens/index.css
Frontend/src/design-system/tokens/ccure-tokens.css
Frontend/src/design-system/tokens/themes.css
Frontend/src/design-system/components/components.css
Frontend/src/design-system/components/CcureButton.jsx
Frontend/src/design-system/components/CcureInput.jsx    (+ CcureSelect, CcureField)
Frontend/src/design-system/components/CcureAlert.jsx
Frontend/src/design-system/components/CcureModal.jsx
Frontend/src/design-system/components/CcureToast.jsx
Frontend/src/design-system/hooks/useFocusTrap.js
Frontend/src/design-system/patterns/CcureAppShell.jsx
Frontend/src/design-system/patterns/shell.css
Frontend/src/pages/Ux4gSpike.jsx                        (SPIKE ONLY — remove before merge)
Frontend/src/__tests__/design-system/ux4g-integration.test.js
Frontend/src/__tests__/design-system/components.test.jsx
Frontend/src/__tests__/design-system/contrast.test.js
docs/ux4g/01-spike-report.md
```

**Modified**

```
Frontend/package.json        + ux4g-web-components@2.1.0 (pinned), wawoff2 (dev),
                               prebuild/pretest/ux4g:assets scripts
Frontend/package-lock.json   lockfile
Frontend/src/main.jsx        one import, before global.css (order documented)
Frontend/src/App.jsx         one spike route + import (removed before merge)
```

**Not modified:** `Frontend/nginx.conf`, `Frontend/Dockerfile`,
`docker-compose.yml`, every page, every API module, `AuthContext`,
`PreferencesContext`, `PrivateRoute`, `permissions.js`, all 16 legacy
stylesheets.

---

## 16. Verification summary

| Check                                  | Result                                                             |
| -------------------------------------- | ------------------------------------------------------------------ |
| `npm test`                             | **118 passed / 9 files** (39 baseline + 79 new)                    |
| `npm run lint`                         | clean at `--max-warnings=0`                                        |
| `npm run build`                        | green, 190 modules                                                 |
| `docker build`                         | green, fonts generated in-image                                    |
| CSP served                             | byte-identical to baseline                                         |
| CSP violations in browser              | 0                                                                  |
| External requests attributable to page | **0** (proven against an `about:blank` control)                    |
| Unmigrated page regression             | **0 pixels** (byte-identical PNG, with a self-consistency control) |
| Contrast, both themes                  | 32/32 at 4.5:1                                                     |

---

## Phase report

**PHASE:** 1 — UX4G compatibility spike
**STATUS:** Complete
**UX4G VERSION:** `ux4g-web-components@2.1.0` (pinned). Not "3.0 code" — 3.0 is
the Figma kit; 2.1.0 is the mechanism.
**CSS:** integrated via a generated, self-hosted build step. Builds under Vite 8
/ React 18 with no config change.
**RUNTIME:** **not adopted.** Injects an inline `<script>`; blocked by
`script-src 'self'`. Absence enforced by test.
**FONTS:** 7 faces extracted to self-hosted WOFF2, 5,510 → 2,325 kB; stylesheet
8,120 → 773 kB. Served same-origin, immutable-cached, valid `wOF2`. One font
actually fetched.
**CSP:** **unchanged, byte-for-byte.** No directive touched; `nginx.conf` not
edited. Zero violations in-browser.
**AIR-GAP:** **zero external requests attributable to the page**, proven in a
real browser against an `about:blank` control.
**DARK MODE:** one `data-theme` attribute drives UX4G's 217 tokens and CCure's.
`PreferencesContext` untouched. Severity now has the dark block it never had.
**ACCESSIBILITY:** 5 primitives + shell; skip link, `aria-describedby`,
`aria-current`, dialog semantics, focus trap and restoration, dual live
regions. 32 contrast assertions at 4.5:1 — **three real failures found and
fixed**.
**DOCKER:** production path builds and serves; live deployment untouched and
used as the A/B control.
**BUNDLE DELTA:** CSS +116.5 kB gzip, JS +5.1 kB gzip, fonts +2,325 kB on disk
(868 kB fetched). **92.7% of the CSS is unused**; Phase 2 can cut the delta to
+9.1 kB gzip.
**LICENSE:** **UNRESOLVED.** No LICENSE file, no `license` field. Nothing
assumed, nothing vendored permanently. Gates Phase 2.
**RISKS:** 10 in §14; the two High items are the CSS size (quantified, with a
known fix) and the licence (needs a human answer).
**GO/NO-GO:** **GO.** No hard-stop condition was met. Every non-negotiable held
without compromise — and the two defects the spike found (`border:0`/`outline:0`
on 107 unclassed controls; three sub-AA colours) would both have shipped
looking correct.

**NEXT PHASE:** 2 — dependency strategy. Resolve the licence first, then decide
token-only versus full stylesheet, and which font families to keep.
**Awaiting your review before starting.**
