# Phase B.11 — UX4G 3.0.0 → 3.0.2 upgrade review

Reviewed on 2026-10-07, on `modular_architecture`, starting from `76238d5`. This
is the compatibility, accessibility, security and CSP review that
[`UX4G_STANDARD.md`](UX4G_STANDARD.md) requires before the pin changes. The
executable release definition remains
[`Frontend/ux4g-baseline.json`](../../Frontend/ux4g-baseline.json); versions in
this record are dated evidence.

## 1. Decision

**UPGRADED TO 3.0.2**, with one change to the central pipeline (§4). Upstream
describes 3.0.1 and 3.0.2 as patch releases with "no public class, token-name, or
runtime API removals". That is not accurate for this project. 3.0.1 renamed the
dark-theme selector, removed three tokens and removed the alert variant layout
rules. None of the three is in either changelog. All three are in 3.0.1 and 3.0.2
alike, so they are deliberate rather than a bad build. Each one was measured and
absorbed as described below.

## 2. Official verification and provenance

| Item                   | Verified value / evidence                                                                                         |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| npm package            | `ux4g-web-components@3.0.2`, registry `dist-tags.latest` = `3.0.2`, not deprecated                                |
| Release history        | 3.0.0 2026-09-27, 3.0.1 2026-10-05, 3.0.2 2026-10-06 (registry `time`)                                            |
| Publisher / maintainer | `ux4g.npm` / `support.ux4g@digitalindia.gov.in`, same account and sole maintainer as 3.0.0                        |
| Registry signatures    | 2, as for 3.0.0; no provenance attestation on either                                                              |
| Integrity              | `sha512-7FuSYAiS…3HbXgA==`; the downloaded tarball was hashed independently and matches the registry and lockfile |
| Dependencies           | No runtime, peer or optional dependencies; no `preinstall`/`install`/`postinstall`/`prepare` script               |
| Corresponding CDN      | `UX4G@3.3.2`, mapped by the packaged changelog (evidence only, never a dependency)                                |
| Lockfile change        | UX4G's root declaration, version, tarball URL and integrity only; no other package moved                          |

## 3. What changed upstream, and what it does here

Twelve files differ between the 3.0.0 and 3.0.2 tarballs. Only
`styles/ux4g.css` reaches this application. `package.json` changes only its
version (exports, files and scripts are identical). The runtime files changed,
but the runtime stays disabled. The changelog and README are documentation.

The stylesheet was compared with PostCSS. Token chains were resolved, and the
component subset was regenerated through `componentCss()` from both releases,
so the comparison covers the bytes this application actually ships.

| Surface                     | Upstream change                                                                                                                                        | Effect here and action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Dark-theme selector**     | `:root[data-theme=dark]` (115 tokens) became `.dark,:root[data-mode=dark],[data-mode=dark]` (112 tokens)                                               | **Breaking.** The generator stopped with "Upstream restructured its tokens", as designed. Unmapped, 33 of the 87 tokens our source uses would have taken their light values in dark mode. The pipeline now re-emits the block under the app's own `:root[data-theme=dark]` (§4).                                                                                                                                                                                                                                                  |
| Tokens                      | +12 (`--ux4g-size-/sz-500…700`, `--ux4g-btn-radius`, `--ux4g-navbar-radius`); −3 (`--ux4g-rgb-white`, `--ux4g-rgb-black`, `--ux4g-text-default-color`) | None of the three removed tokens is referenced by authored source. With the selector mapped, 80 of the 87 tokens our source uses resolve identically in light and dark. The other 7 (`--ux4g-bg-overlay`, `--ux4g-text-neutral-disabled`, `--ux4g-bg-neutral-disabled`, `--ux4g-shadow-l1`…`l4`) are the same colours rewritten from `hsla()`/`rgba()` to `color-mix(in srgb, X calc(n*100%), transparent)`. Chromium 153, Firefox 155 and WebKit 26.6 each compute the old value (probed directly, e.g. `#171717` at 0.7 alpha). |
| Dangling reference          | 3.0.2 still uses `var(--ux4g-text-default-color)` once, though it no longer declares it                                                                | Not in the delivered subset (0 occurrences in generated CSS or `dist`).                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Alert variants**          | The 13 `.ux4g-alert.ux4g-alert-{info,success,warning}` rules were removed; variants now set `--ux4g-alert-bg/-text` and share one rule                 | `CcureAlert` composes `ux4g-alert ux4g-alert-<variant>`, so it is affected. Measured below. Accepted as the official design; not re-created locally, per the standard's rule against custom equivalents.                                                                                                                                                                                                                                                                                                                          |
| Navbar                      | Mobile breakpoint 768px → 991.98px                                                                                                                     | The shell header uses only `ux4g-navbar`; the one rule reaching it is `position:relative`, which `shell.css` (loaded later, same specificity) overrides. Measured `sticky` at 900px in both releases.                                                                                                                                                                                                                                                                                                                             |
| Buttons                     | Radius reads `var(--ux4g-btn-radius, …)`; `--ux4g-btn-radius` = `var(--ux4g-radius-md)`                                                                | `s`/`m`/`l` buttons unchanged. `xs` would move from `radius-sm` to `radius-md`, but `CcureButton` never emits `xs`.                                                                                                                                                                                                                                                                                                                                                                                                               |
| Smaller component changes   | Spinner mask uses a colour token instead of `#fff`; dropdown item gains text colour; textarea counter loses its background                             | Masks use alpha only, so the spinner renders the same. The other two are minor.                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Dark variants of components | Four rules (`.ux4g-table-select`, logos) moved from `[data-theme=dark]` to `.dark`/`[data-mode=dark]`                                                  | Never delivered: the extractor admits only selectors that lead with a component class.                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Fonts                       | All seven `@font-face` descriptors and payloads identical                                                                                              | None.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Class inventory             | 0 removed, 31 added (height/width utilities)                                                                                                           | Utilities are not delivered.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

### Alert rendering, measured

`CcureAlert` markup was rendered against the 3.0.0 and 3.0.2 design-system CSS
in Chromium at 900px, in light and dark mode. Computed styles:

| Variant | 3.0.0                                                       | 3.0.2                                                                                 |
| ------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| info    | padding 16/16, top-aligned, title 15px above a 13px message | padding 12/32, centred, 16px title inline with a 14px message                         |
| warning | padding 16/16, top-aligned, title 15px above a 14px message | as info                                                                               |
| success | padding 12/16, bg `rgb(221,248,216)` / dark `rgb(0,82,44)`  | as info; bg `rgb(242,252,239)` / dark `rgb(0,56,31)`, the project's own success token |
| danger  | padding 12/32, centred, 16px title inline                   | unchanged                                                                             |

All four variants now share the layout the danger alert already had. Borders
and colours are otherwise unchanged; the borders come from the project's adapter
CSS. The lowest text contrast is 5.09:1 in both releases. Success contrast rises
from 8.24 to 8.89:1 in light and from 5.48 to 7.76:1 in dark.

## 4. Pipeline change

- `scripts/ux4g-baseline.mjs` names `UPSTREAM_DARK_SELECTOR` (the approved
  release's dark selector, matched exactly) and `APP_DARK_SELECTOR`
  (`:root[data-theme=dark]`, the attribute `PreferencesContext` writes).
- `scripts/build-ux4g-assets.mjs` reads the upstream block and emits it under the
  app's selector. The bare `.dark` class and `[data-mode]` are never emitted:
  `.dark` would restyle any element carrying that class, and nothing sets
  `data-mode`. A further upstream rename still stops the build.
- `scripts/ux4g-component-assets.mjs` mirrors the same block onto the scoped dark
  surfaces (`.cc-theme-dark`, the sign-in hero panel). It used to skip silently
  when the block was missing. That would have left those surfaces on light
  tokens with no error. It now refuses.
- Tests: the generated tokens never contain `.dark` or `data-mode`; the component
  subset carries the scoped dark mirror and no upstream dark selector; a source
  without the dark block is refused.

## 5. Security and CSP

- **3.0.1 added `@import url("https://fonts.googleapis.com/css2?…")`**, which
  loads 21 Google font families, at the top of `ux4g.css`. It is not delivered.
  The generator assembles only `:root` blocks, the dark block and the retained
  font faces. Its existing assertion and two tests reject any external origin
  and name `fonts.googleapis.com` explicitly. Zero occurrences in the generated
  CSS and in `dist`. Delivering it would breach `font-src 'self'`, the
  air-gapped deployment and visitor privacy.
- The deployment CSP is unchanged; `ux4g:check --dist` verifies its hash.
- The vendor runtime changed upstream and remains disabled.

## 6. Validation

From `Frontend/`, after `npm ci`, every required check in the standard:

| Check                                              | Result                                                                                                                     |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `ux4g:check -- --dependencies-only`                | PASS, 3.0.2                                                                                                                |
| `VITE_API_BASE_URL=/api npm run build`             | PASS                                                                                                                       |
| `ux4g:verify`                                      | two independent runs produced byte-identical output                                                                        |
| `ux4g:check -- --dist`                             | PASS                                                                                                                       |
| `ux4g:architecture`                                | PASS                                                                                                                       |
| `build-authorization-inventory.mjs --check`        | inventory is current                                                                                                       |
| `npm run lint`                                     | PASS                                                                                                                       |
| `npm test`                                         | 114 files, 3117 tests passed (3114 before + 3 new)                                                                         |
| `npm run test:browser` (Chromium, Firefox, WebKit) | 420 passed (140 per engine), none failed or flaky, 14.9 min; WebKit through the userland launcher, host pre-flight skipped |

## 7. Limits

- Automated checks complement, not replace, manual assistive-technology review.
- The Storybook documentation and the CDN 3.3.2 stylesheet were not audited.
- Worth reporting upstream: the changelog omits the selector rename, the
  `--ux4g-text-default-color` removal (still referenced once), the alert rule
  removal and the external font `@import`.
