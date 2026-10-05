# UX4G migration — Phase 2 dependency strategy

> Historical decision record for the earlier tokens-only foundation. The active
> approved version/provenance now comes from `Frontend/ux4g-baseline.json` and
> [Phase B.1](B1_VERSION_FOUNDATION.md). Version numbers and measurements below
> describe that earlier assessment, not an independent current pin. Tokens-only
> global delivery remains excluded. [Group 1](B3_B4_SHARED_PRIMITIVES_SHELL.md)
> now provides scoped official component CSS through shared React adapters;
> the vendor runtime remains disabled under the existing CSP.

**Date:** 9 September 2026
**Branch:** `feat/ux4g-spike`
**Prior phases:** [`00-baseline.md`](00-baseline.md) · [`01-spike-report.md`](01-spike-report.md)
**Recommendation: GO for Phase 3**, with one open item that is a decision for a
person, not a build (§1).

---

## 1. Licence status

**Phase 1 reported "no licensing information". That was wrong, and this
corrects it.** The package does declare a licence — in a place the earlier
check did not read.

### What the publisher states

| Location                                 | Content                                                                               |
| ---------------------------------------- | ------------------------------------------------------------------------------------- |
| `README.md` line 4                       | `[![License: MIT](…badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)` |
| `README.md` §License (line 2609)         | `## License` / `MIT`                                                                  |
| `package.json` `license` field           | **absent**                                                                            |
| npm registry `license` metadata          | **absent** (`npm view … license` returns nothing)                                     |
| `LICENSE` / `LICENCE` file               | **absent**                                                                            |
| Copyright notice anywhere in the package | **absent**                                                                            |
| Notice inside `styles/ux4g.css`          | **absent**                                                                            |

### Provenance

|                       |                                        |
| --------------------- | -------------------------------------- |
| Package               | `ux4g-web-components`                  |
| Version               | `2.1.0`, published 5 September 2026    |
| Publisher             | `ux4g.npm`                             |
| Maintainer contact    | **`support.ux4g@digitalindia.gov.in`** |
| Repository / homepage | not declared                           |

The maintainer address is on `digitalindia.gov.in` — the Government of India
programme under MeitY that operates UX4G. That is meaningful provenance
evidence and it is consistent with an official NeGD release. **It is still not
a licence grant**, and per the standing instruction none has been inferred from
it.

### The two questions that remain open

1. **Whose copyright, and where is the notice?** MIT's own terms require that
   "the above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software." The package contains no
   copyright line, so a redistributor cannot comply with the condition the
   licence itself imposes. A README declaration without a notice to carry is an
   incomplete grant, not a defective one — but it needs the notice supplied.

2. **What covers the embedded third-party fonts?** The stylesheet embeds Noto
   Sans and five Material Icons faces. Upstream those are SIL OFL 1.1 and
   Apache-2.0 respectively; an MIT statement on the bundle does not
   automatically re-license them, and OFL in particular carries its own
   redistribution conditions. **This pipeline extracts and self-hosts Noto Sans**
   (§5), which is a redistribution of an OFL work in its own right and normally
   requires the OFL text to travel with it.

### Required confirmation

A written statement from the UX4G team (`support.ux4g@digitalindia.gov.in`)
covering:

- the copyright holder and notice text to reproduce;
- confirmation that MIT covers `styles/ux4g.css` including its derived forms;
- the licence and attribution requirements for the embedded Noto Sans, given
  that CCure self-hosts an extracted copy;
- ideally, a `LICENSE` file and a `license` field in a future release, which
  would close this permanently.

### Impact if it cannot be confirmed

Ranked by cost, because the exposure is smaller than it first appears:

- **Tokens are the smallest possible surface.** Production now ships
  `:root` custom properties and one `@font-face` — colour values, spacing
  numbers and radii. Whether a palette of hex values attracts copyright at all
  is a much weaker claim than for 717 kB of authored component CSS, which this
  build no longer ships.
- **The font is separable.** If OFL attribution cannot be satisfied,
  `KEEP_FONTS` becomes empty and `--ccure-font` falls back to the existing
  `system-ui, sans-serif` stack. One constant, no architectural change.
- **Nothing is vendored.** The package sits in `node_modules`; the generated
  CSS, the manifest and the WOFF2 are all gitignored build output. No UX4G
  bytes are committed to this repository.

**The gate therefore stands but does not block Phase 3.** Phase 3 migrates
CCure pages onto `--ccure-*` and `cc-*`, which is CCure's own code. The licence
answer determines what `--ccure-*` resolves _to_, not whether the layer exists.
It must be settled before a production release, and it is the one item in this
report that no amount of engineering can close.

---

## 2. Final UX4G package and version

```
ux4g-web-components@2.1.0     (exact pin, no caret — enforced by test)
  ├─ styles/ux4g.css          → design tokens + @font-face  [ADOPTED, subset]
  └─ dist/runtime/*           → UX4G.js 1.1.0               [NOT ADOPTED]
```

**2.1.0 is not "UX4G 3.0 code" and is not described as such.** One new fact
since Phase 1 clarifies the versioning, from the package's own CHANGELOG:

> **[2.1.0] — 2026-09-05** … Corresponds to CDN `UX4G@3.2.0`.

So npm `2.1.0` and CDN `UX4G@3.2.0` are the same content under two version
lines, and the Figma kit is 3.0. The design language CCure implements is UX4G
3.x; the npm package is the mechanism. That is the correspondence the Phase 0
question was really asking about, and it now has a source.

The pin is exact because every guarantee in these documents — the
class-collision set, the reset shape, the token closure, the contrast figures —
is a property of this build. `guardrails.test.js` fails on a caret or a
mismatch between `package.json` and what is installed.

---

## 3. Full stylesheet vs token subset — **token subset**

Chosen on completeness first, size second, exactly as instructed.

### Completeness was verified before size was considered

The concern with a subset is a token that resolves in the full stylesheet and
silently yields nothing in the subset — an unresolved custom property produces
no colour rather than an error, so it fails invisibly.

Computed over the **transitive closure**, not just direct references:

```
--ccure-* directly references          77 --ux4g-* tokens
transitive closure                    117 --ux4g-* tokens
unresolvable inside the subset          0    ← COMPLETE
```

**A defect found while doing this, which would have broken a naive subset:**
upstream ships **six `:root{}` blocks**, not one. Taking "the `:root` block"
captures 1,277 of 1,332 tokens and drops 55 — silently. The build now collects
every block and asserts it found them; `contrast.test.js` had the same
first-match bug and now merges all blocks with a parse-sanity guard that fails
if fewer than 900 tokens are read.

|                                               |    tokens |
| --------------------------------------------- | --------: |
| `:root` blocks (×6)                           |     1,277 |
| `:root[data-theme=dark]`                      |       114 |
| **subset total**                              | **1,332** |
| defined only inside `.ux4g-*` component rules |       120 |
| total in the file                             |     1,452 |

The 120 excluded ones are component-internal — `--ux4g-accordion-arrow-size`
declared inside `.ux4g-accordion-arrow-left` and similar. They are meaningful
only if the component is used, which the class policy forbids.

### Then the size

|                            |         raw |       gzip |
| -------------------------- | ----------: | ---------: |
| Full stylesheet (Phase 1)  |    773.5 kB |   109.4 kB |
| **Token subset (Phase 2)** | **58.5 kB** | **9.6 kB** |

### What the subset buys beyond size

Not shipping component CSS **removes a class of risk rather than containing
it**:

- **No universal reset ships at all.** Phase 1 had to rescope
  `:where(*,:before,:after){border:0;outline:0}` because it stripped the UA
  border from 107 unclassed controls and the focus ring from anything CCure
  did not explicitly focus-style. That rule is now simply absent.
- **Class collision becomes structurally impossible.** The emitted file
  contains comments, one `@font-face` and seven `:root` blocks — no class
  selector, no element selector. There is no rule that can match anything CCure
  renders. A test strips those three constructs and asserts nothing remains.

### Reversibility

The decision is one environment variable, not a rewrite. `UX4G_CSS_MODE=full`
restores the whole stylesheet with the Phase 1 reset rescoping and font
externalisation intact. If CCure ever adopts `.ux4g-*` classes directly, that
is the switch — and the class policy (§4) is what would have to change first.

---

## 4. UX4G class policy — **adopted and enforced**

> **Application code must not use `ux4g-*` classes directly.** > `<CcureButton />`, never `<button class="ux4g-btn-primary">`.

Two reasons, and the second is the one that makes it non-negotiable here:

1. It is what allows the UX4G version underneath to change, or be replaced,
   without editing pages — the premise of the whole layered architecture.
2. **Production ships tokens only.** There is no `.ux4g-btn` rule in the
   bundle, so a `ux4g-` class matches nothing and styles nothing. It would
   present as a CSS bug and be debugged as one, wasting time on a policy
   breach that looks like a defect.

Three tests enforce it (`guardrails.test.js › UX4G class policy`):

| Guard                                                      | What it catches                                                                         |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| no `ux4g-` token inside any `className`                    | the direct case, in `"…"` and ``{`…`}`` forms                                           |
| no `.ux4g-` selector in CCure's own CSS                    | a `cc-*` rule built on a UX4G class, which would reintroduce the need for component CSS |
| only `src/design-system/` may import `ux4g-web-components` | keeps the seam real rather than conventional                                            |

The rule caught its own anti-example on first run — the `className="ux4g-btn-primary"`
written in the test's documentation. The example is now spelled with `class`
so an illustration does not trip the rule it illustrates.

**CCure references zero UX4G classes today**, so the policy is adopted from a
clean state rather than retrofitted.

---

## 5. Font inventory and decision

Four independent lines of evidence per face, as required — nothing removed on
assumption.

| Face                | Consumer in UX4G's own CSS        | CCure consumer                                | Token path                   | Browser fetched | Decision |
| ------------------- | --------------------------------- | --------------------------------------------- | ---------------------------- | --------------- | -------- |
| **Noto Sans**       | `:where(body)`, `body,html`       | `--ccure-font` → every `cc-*`                 | `--ux4g-font-family-base`    | **yes**         | **KEEP** |
| Noto Sans Display   | **none**                          | `--ccure-font-display` — declared, **unused** | `--ux4g-font-family-display` | no              | remove   |
| UX4G Material Icons | `.ux4g-icon`, `.ux4g-icon-filled` | none                                          | none                         | no              | remove   |
| …Outlined           | `.ux4g-icon-outlined`             | none                                          | none                         | no              | remove   |
| …Round              | `.ux4g-icon-round`                | none                                          | none                         | no              | remove   |
| …Sharp              | `.ux4g-icon-sharp`                | none                                          | none                         | no              | remove   |
| …TwoTone            | `.ux4g-icon-twotone`              | none                                          | none                         | no              | remove   |

**The Material Icons question is settled, not assumed.** All five are reachable
only through `.ux4g-icon*` — component classes this build does not ship and the
§4 policy forbids. Against that, CCure's own icon usage measured on this tree:

```
inline <svg> in JSX      63
icon-font classes        0
<i> elements             0
```

CCure draws every icon as inline SVG. There is no code path, present or
permitted, that could request a Material Icons face.

**Noto Sans Display** has no consumer in UX4G's CSS at all and reaches nothing
in CCure. The `--ccure-font-display` token is kept — it falls back to
`--ux4g-font-family-base` — so a future display-typography decision costs one
line in `KEEP_FONTS`, not a re-architecture.

Removing a face drops its `@font-face` **and** does not write its WOFF2, so
nothing can reference a file that is absent. A build-time assertion requires
the emitted `@font-face` count to equal the number of font files written.

|               |  Phase 1 |             Phase 2 |
| ------------- | -------: | ------------------: |
| Faces shipped |        7 |               **1** |
| Bytes on disk | 2,325 kB | **868 kB** (−62.7%) |

Result: minimum self-hosted set, WOFF2, `font-src 'self'`, no `data:` font
URIs — the stated preferred outcome, with **no CSP change**.

---

## 6. Generated asset pipeline

`scripts/build-ux4g-assets.mjs`, run by `prebuild` and `pretest` and therefore
inside the Docker build. Against the required properties:

| Requirement                      | How                                                                                                                                          |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Derives from the pinned package  | reads `node_modules/ux4g-web-components`, and **aborts** if the installed version ≠ `2.1.0`                                                  |
| Deterministic output             | proven, not asserted — see below                                                                                                             |
| Fails on unexpected reset change | `RESET_RE` must match; missing → build fails with the reason                                                                                 |
| Fails on `data:` font URIs       | scans the emitted CSS; any survivor aborts                                                                                                   |
| Fails on external origins        | scans for `url(http…)`; any match aborts                                                                                                     |
| Validates `@font-face` output    | emitted face count must equal files written                                                                                                  |
| Produces valid WOFF2             | `wawoff2` (WASM build of Google's woff2 — no native toolchain); Phase 1 verified the `wOF2` signature and a round-trip to a well-formed sfnt |
| No runtime Internet access       | inputs are local; the emitted CSS is asserted to contain no external origin                                                                  |
| Works in the Docker build        | verified — the image contains `noto-sans.woff2` generated in-image                                                                           |

Two additions this phase:

- **A manifest.** `ux4g.generated.manifest.json` records the source package and
  version, the mode, and a SHA-256 prefix and byte count for the CSS and each
  font. It is what makes gitignored output auditable, and five guardrail tests
  read it — including one asserting no font file exists that the manifest does
  not name, so a leftover from a previous run cannot be served silently.

- **A reproducibility check**, `npm run ux4g:verify`. It snapshots the output,
  **deletes it**, rebuilds, and compares hashes. Deleting matters: without it a
  second run could pass by leaving the first run's files in place.

```
[ux4g:verify] reproducibility
  source        ux4g-web-components@2.1.0  mode=tokens
  css sha256    15658a1eb682ac57dafc1502e8d2f7eee5b16f1e4702bc86f75d3a8fc7b8ddd8
  noto-sans     e30fe55bc615a405377c86ef627742bcba7dddbb0053a1dbe34860cae1ecc92c
  two independent runs produced byte-identical output
```

### Why the generated assets stay gitignored

"Derived output need not be committed" is only sound if the derivation is
deterministic — otherwise the artefact in a Docker image and the one a
developer holds can differ with nothing to show it. So the premise is
**tested** rather than asserted: `ux4g:verify` fails the build if it stops
holding, and its failure message says explicitly that the gitignore decision
would then have to be revisited.

Given that, committing ~930 kB of derived bytes would put them under review on
every UX4G bump and let the checked-in copy drift from what the lockfile
installs. The manifest plus the version assertion give the audit trail without
the artefacts.

---

## 7. CSS reset strategy

**Production emits no reset at all**, which is stronger than the Phase 1
scoping and is the direct consequence of §3.

The protection is nonetheless kept in full, because the risk returns the moment
anyone sets `UX4G_CSS_MODE=full`:

- `RESET_RE` still asserts upstream's reset **shape** in both modes. A
  repackaged upstream fails the build with an explanation, rather than quietly
  reintroducing `border:0` on 107 unclassed controls.
- `full` mode still rescopes it to `:where([class*="ux4g-"],…)` and still
  aborts if a universal `:where(*)` survives.
- `themes.css` keeps the `:focus-visible` floor. It was introduced to repair
  `outline:0`, but it is worth having on its own: CCure sets an outline in only
  36 of its 76 focus rules, so the floor is an improvement over the pre-UX4G
  baseline regardless of what UX4G ships.
- A test asserts the emitted CSS contains **no `:where(` at all** and no bare
  `body`/`html` rule.

Nothing here was weakened; one layer became unnecessary and was kept anyway.

---

## 8. Token architecture

```
src/design-system/tokens/
  ux4g.generated.css   generated · 6 :root blocks + dark block + 1 @font-face
  ccure-tokens.css     --ccure-* semantic layer (authored)
  themes.css           theme contract, focus floor, reduced motion, forced-colors
  index.css            import order (load-bearing, documented in the file)
```

```
UX4G primitives  →  CCure semantics  →  CCure components  →  pages
   --ux4g-*          --ccure-*            cc-*                (Phase 3+)
```

**Legacy tokens are deliberately untouched.** The 44 existing names
(`--accent`, `--text`, `--bg-app`, …) still resolve exactly as `theme.css`
defines them, and `ccure-tokens.css` redefines none — asserted by a test that
fails if any legacy name appears as a declaration in the semantic layer.

That is precisely why an unmigrated page renders pixel-identically (§13).
Re-pointing them would restyle 79 pages through 2,155 `var()` call sites in one
change, which is the big-bang this plan exists to avoid. It belongs to the
migration phase, as its own reviewable step.

Two corrections carried in the semantic layer, both from Phase 1 measurement
and both still enforced: the danger-button step (light mode) and the five
severity steps, which UX4G's obvious 600-step choice fails on white.

---

## 9. Dark mode

Unchanged and unchallenged. `PreferencesContext` was not modified in Phase 1 or
Phase 2; `preferences.theme` remains the backend contract; `data-theme` on
`documentElement` remains the only switch.

Both token sets respond to that one attribute — verified again on the
token-only build by rendering the showcase in both themes, and pinned by three
tests: the dark selector exists, it redefines >100 tokens, and UX4G ships zero
`prefers-color-scheme` rules (one would silently override the user's stored
account preference).

No second mechanism was introduced. The showcase's `?theme=` parameter is a
development affordance for headless capture; it writes the same attribute and
restores the previous value on unmount.

---

## 10. Guardrail tests

All 13 required protections, plus contrast. **137 tests pass** (39 pre-existing

- 98 design-system).

| #   | Protection                                                                                                        | Where                          |
| --- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| 1   | UX4G version pinned exactly, and installed version matches                                                        | `guardrails`                   |
| 2   | UX4G runtime never imported (walks all of `src/`)                                                                 | `ux4g-integration`             |
| 3   | No runtime markers in built JS                                                                                    | `guardrails` (against `dist/`) |
| 4   | No `eval` / `Function` constructor in source                                                                      | `guardrails`                   |
| 5   | No external origin or CDN/analytics host in generated or built assets                                             | both                           |
| 6   | No `data:` font URI survives                                                                                      | both                           |
| 7   | Reset shape asserted; `full` mode rescopes; tokens mode emits none                                                | build + `ux4g-integration`     |
| 8   | No selector can match a CCure element; no bare colliding rule                                                     | `ux4g-integration`             |
| 9   | `data-theme` drives dark mode; no `prefers-color-scheme`                                                          | `ux4g-integration`             |
| 10  | Contrast ≥ 4.5:1, both themes, 32 assertions                                                                      | `contrast`                     |
| 11  | Manifest matches installed package; every font present at recorded size; no unnamed font on disk; exact drop list | `guardrails`                   |
| 12  | Runtime dependency allowlist; `wawoff2` stays a dev dependency                                                    | `guardrails`                   |
| 13  | No `ux4g-` class in `className`; none in CCure CSS; only the design system may import the package                 | `guardrails`                   |
| +   | Dev-only showcase absent from production bundle                                                                   | `guardrails`                   |

Two are worth calling out as more than box-ticking:

- **#12** turns adding a runtime dependency into a deliberate, reviewed act.
  For an air-gapped product a new dependency is a new thing that might reach
  the network.
- **#11's** "no font file the manifest does not name" catches the case where a
  removed face leaves a stale WOFF2 that nginx keeps serving and the image
  keeps carrying while nothing references it.

---

## 11. CSP result — unchanged, byte-for-byte

`Frontend/nginx.conf` has not been edited in any phase. Served by the Phase 2
production image, via the check CLAUDE.md prescribes:

```console
$ curl -sD - -o /dev/null http://127.0.0.1:3299/ | grep -i content-security
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:;
  img-src 'self' data:; font-src 'self'; object-src 'none';
  base-uri 'self'; frame-ancestors 'none';
```

Identical to the Phase 0 baseline. Nothing was added: no `unsafe-inline`, no
`unsafe-eval`, no `data:` in `font-src`, no external script or style source.

Browser console clean — no CSP or blocked-resource messages in either theme.

---

## 12. Air-gap result — zero external requests attributable to CCure

Re-verified on the Phase 2 production image, and this time one finding needed
chasing rather than dismissing.

**The page's complete request set** (`/login`, production image):

```
/login   /   /favicon.svg
/assets/index-DVJO2PAE.js
/assets/index-DfcnUN7Z.css
/api/auth/refresh          ← AuthContext booting, pre-existing
/api/auth/check-email      ← Login's own probe, pre-existing
```

All same-origin. No font is requested, because no production page consumes
`--ccure-font` yet — the foundation is in place and inert until Phase 3.

**The finding.** Comparing against `about:blank` showed two extra hosts, and
comparing against the _baseline container's own_ `/login` narrowed it to one:
`android.clients.google.com`, present for the UX4G build and not for the
baseline. Chrome's host set had been stable across four identical baseline
runs, so noise was not a safe assumption.

Resolved on two independent lines:

- **What was requested**: `/c2dm/register3` and `/checkin` — Chrome's push
  registration and device check-in, browser-level services on a periodic
  schedule.
- **Whether our code could cause it**: the served HTML, CSS and JS contain
  **zero** occurrences of `android.clients`, `c2dm`, `firebase`, `PushManager`
  or `serviceWorker`. (`checkin` and `gcm` matched only `"Checking…"` UI text
  and base64 metadata.) There is no mechanism in the bundle to trigger a push
  registration.
- **Empirically**: four _further_ baseline runs — no UX4G at all — all
  contacted `android.clients.google.com`. It is periodic, not page-driven.

```
hosts contacted by Phase 2 but not by the identical baseline page: NONE
```

Also confirmed: the font loads correctly under the token-only build
(`/assets/fonts/ux4g/noto-sans.woff2` requested and applied, typography renders
as Noto Sans), with no blocked-resource message.

---

## 13. Unmigrated-page regression — zero pixels, re-verified

Same methodology as Phase 1: the unmigrated `Login` page rendered by the
baseline container (3200, no UX4G) and the Phase 2 image (3299), with
`--force-prefers-reduced-motion` to make the comparison deterministic.

```
p2-baseA   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (no UX4G)
p2-baseB   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (no UX4G)
p2-ux4g    428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (Phase 2)

self-consistency : IDENTICAL     ← the comparison is valid
baseline vs P2   : IDENTICAL     ← zero pixels changed
```

Byte-identical, and the same hash as the Phase 1 run — so the token-only change
altered nothing about how unmigrated pages render.

---

## 14. Bundle size

|                 |     Baseline |         Phase 1 |               **Phase 2** | Δ vs baseline |
| --------------- | -----------: | --------------: | ------------------------: | ------------: |
| CSS raw         |    188.90 kB |       999.56 kB |             **266.75 kB** |     +77.85 kB |
| **CSS gzip**    | **32.56 kB** |   **149.06 kB** |              **46.27 kB** | **+13.71 kB** |
| JS raw          |  1,698.95 kB |     1,716.59 kB |           **1,701.30 kB** |      +2.35 kB |
| JS gzip         |    419.68 kB |       424.78 kB |             **420.38 kB** |      +0.70 kB |
| Fonts on disk   |            0 |        2,325 kB |                **868 kB** |       +868 kB |
| Fonts requested |            0 | 868 kB (1 of 7) | **0** (none yet consumed) |             — |
| Build time      |       4.21 s |          1.60 s |                **0.51 s** |             — |

**Phase 1 → Phase 2: CSS gzip 149.06 → 46.27 kB (−69%), fonts 2,325 → 868 kB
(−63%), JS back to +0.7 kB** as the showcase left the production bundle.

### Against the ~9.1 kB target

The target was for UX4G's contribution, and that is met:

| Component of the delta                            |     raw |       gzip |
| ------------------------------------------------- | ------: | ---------: |
| `ux4g.generated.css` — UX4G tokens + `@font-face` | 58.5 kB | **9.6 kB** |
| `ccure-tokens.css` — CCure semantic layer         | 15.8 kB |     4.7 kB |
| `components.css` — CCure primitives               | 14.0 kB |     3.4 kB |
| `shell.css` — CCure app shell                     |  9.2 kB |     2.6 kB |
| `themes.css` — theme contract, focus floor        |  4.9 kB |     2.0 kB |

**UX4G's own overhead is 9.6 kB gzip standalone**, essentially the predicted
9.1 kB. The remaining ~4 kB of the measured +13.71 kB is CCure-authored code
that did not exist before — the primitives, the shell and the semantic layer —
and it is not UX4G overhead. It will pay for itself as pages migrate onto
shared components and their bespoke CSS is retired.

The JS figure is worth noting: **+0.70 kB gzip** for the entire design system.
The primitives are small because React already provides the behaviour, which is
what rejecting the UX4G runtime bought.

---

## 15. Docker result

Built and run through the real production path — `Dockerfile`, `nginx.conf`
and `docker-compose.yml` all unmodified across both phases.

- `npm install` → `prebuild` runs **inside the image**; the token-only CSS and
  the single font are generated there.
- Image now contains exactly one font file: `noto-sans.woff2`, 889,348 bytes.
- CSP served in full on `/` and on deep links.
- **The dev-only showcase is absent**: `/design-system` returns the SPA shell
  with no showcase markup, and the production bundle contains zero occurrences
  of `DesignSystemShowcase` or its title string.
- **The live deployment was never touched.** The Phase 2 image ran as
  `ccure-ux4g-p2` on `127.0.0.1:3299`; `ccure-frontend` stayed up on 3200
  throughout and served as the A/B control.

Cleanup: `docker rm -f ccure-ux4g-p2 && docker rmi ccure-frontend:ux4g-p2 ccure-frontend:ux4g-spike`.

---

## 16. Showcase route

`/ux4g-spike` is gone. It is now `/design-system`, rendering
`src/pages/DesignSystemShowcase.jsx`, behind `import.meta.env.DEV` with a lazy
import — so Rollup folds the condition to `false` in production and drops both
the route and the module.

Against the stated conditions:

| Condition                           | Status                                                                                                |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------- |
| exposes no production data          | renders literals only; calls no API                                                                   |
| requires no backend functionality   | none                                                                                                  |
| clearly development-only            | absent from production builds, **verified by test** against `dist/`                                   |
| removed or converted before release | converted — it is now an intentional component showcase, and the guardrail keeps it out of production |

It earns its keep as the only place the primitives are exercised in both themes
before any page uses them.

---

## 17. Remaining risks

| #   | Risk                                                                                                              | Severity          | Position                                                                                                                                                                                                                      |
| --- | ----------------------------------------------------------------------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Licence: no LICENSE file, no `license` field, no copyright notice; OFL terms for the extracted Noto Sans unstated | **High**          | §1. Needs a written answer from `support.ux4g@digitalindia.gov.in`. Does not block Phase 3; must be settled before production release. Exposure is minimised — tokens only, nothing vendored, font removable via one constant |
| 2   | A UX4G bump invalidates the measured guarantees                                                                   | Medium            | Build **aborts** on a version mismatch; bumping means deliberately re-running the Phase 1 checks                                                                                                                              |
| 3   | Token-only means a future `.ux4g-*` class silently styles nothing                                                 | Medium            | Three guardrails make it a test failure rather than a debugging session; `UX4G_CSS_MODE=full` is the escape hatch                                                                                                             |
| 4   | `--ccure-font-display` is declared but unused, and its font is not shipped                                        | Low               | Falls back to the base family. One `KEEP_FONTS` entry if display typography is ever wanted                                                                                                                                    |
| 5   | Legacy tokens not yet re-pointed                                                                                  | By design         | Why unmigrated pages are pixel-identical. Phase 3, as its own change                                                                                                                                                          |
| 6   | No Table / Tabs / Pagination / Breadcrumb primitives                                                              | Expected          | Phase 3 scope; the tables are the biggest accessibility gap in the product (46 tables, 330 `<th>`, zero `scope`)                                                                                                              |
| 7   | Still one 1.70 MB JS chunk; `vis-network` on every route                                                          | Low, pre-existing | Recorded in Phase 0. Not caused by, and not addressed by, this work                                                                                                                                                           |
| 8   | Contrast is asserted on tokens, not on rendered pixels                                                            | Low               | Token-level is the right layer for a design system, but a page can still place text on an unexpected background. Page-level checking belongs with page migration                                                              |

---

## Phase report

**PHASE:** 2 — UX4G foundation and dependency strategy
**STATUS:** Complete
**LICENSE:** **Open, and Phase 1's finding is corrected** — the README does
declare MIT (badge + `## License` section), but there is no LICENSE file, no
`license` field, and no copyright notice to reproduce, and the embedded Noto
Sans carries its own OFL terms. Maintainer is
`support.ux4g@digitalindia.gov.in`. Nothing assumed, nothing vendored.
**UX4G PACKAGE:** `ux4g-web-components@2.1.0`, exact pin enforced by test.
CHANGELOG confirms it corresponds to CDN `UX4G@3.2.0`.
**CSS STRATEGY:** **Token subset.** Completeness verified first — the full
117-token transitive closure resolves, zero missing. 773.5 → 58.5 kB raw,
109.4 → 9.6 kB gzip. Reversible via `UX4G_CSS_MODE=full`.
**UX4G CLASS POLICY:** **Adopted**, enforced by three tests. Application code
uses `Ccure*` primitives; only the design system may import the package.
**FONTS:** 7 → **1** (Noto Sans, 868 kB, −62.7%). Every removal proven against
four independent sources. Minimum set, WOFF2, `font-src 'self'`, no `data:`
URIs, no CSP change.
**ASSET PIPELINE:** Version-pinned, **reproducibility proven** by
`npm run ux4g:verify` (delete-and-rebuild, byte-identical). Manifest records
source, mode and hashes. Six build-time assertions.
**TOKENS:** Four-file layer finalised. Legacy tokens untouched — asserted by
test — which is why unmigrated pages are unchanged.
**DARK MODE:** Unchanged. `PreferencesContext` and `preferences.theme`
untouched; one `data-theme` attribute drives both token sets. No second
mechanism.
**GUARDRAILS:** All 13 required protections plus contrast. **137 tests pass**,
lint clean.
**CSP:** **Byte-for-byte unchanged.** `nginx.conf` not edited in any phase.
Zero violations in-browser.
**AIR-GAP:** **Zero external requests attributable to CCure.** The one
unexplained host was run down to Chrome's periodic GCM check-in and disproved
on three independent lines.
**DOCKER:** Production path builds and serves; one font in the image; showcase
absent; live deployment untouched and used as the A/B control.
**BUNDLE:** CSS gzip **+13.71 kB** vs baseline, of which UX4G is **9.6 kB** and
the rest is new CCure code. JS gzip **+0.70 kB**. Fonts 868 kB on disk.
**Unmigrated-page regression: zero pixels**, byte-identical PNG.
**RISKS:** 8 in §17; one High (licence), and it is a decision for a person
rather than a build.
**GO/NO-GO:** **GO for Phase 3.** The foundation is small, self-hosted,
reproducible, guarded, and provably invisible to every page that has not opted
into it. The licence gate is carried forward explicitly and must be closed
before production release.

**NEXT PHASE:** 3 — component and page migration, starting with the shared
primitives the application lacks (Table, Tabs, Pagination, Breadcrumb) and then
Group A pages. **Awaiting your review before starting.**
