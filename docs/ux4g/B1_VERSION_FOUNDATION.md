# Phase B.1 — approved UX4G version and dependency foundation

This is the historical B.1 record. The current centralized delivery pipeline,
including removal of the experimental full-CSS override, is documented in
[`B2_ASSET_PIPELINE.md`](B2_ASSET_PIPELINE.md). B.2 preserves the B.1 delivered
CSS/font bytes and does not migrate components or typography.

Verified on 2026-10-04, on `modular_architecture`, starting from
`bad5b3f0e1d24f8485d8cae9b1ee7b0f156e5860`. This is a scoped foundation
upgrade. Pages, primitives, authentication, RBAC, API contracts, backend code,
routing and module boundaries were not changed. No commit or deployment was
performed. The running frontend was not restarted.

The authoritative, executable release definition is
[`Frontend/ux4g-baseline.json`](../../Frontend/ux4g-baseline.json).
Version references in this report are dated evidence, not independent pins.

## 1. Official verification and decision

**UPGRADED TO 3.0.0**, approved for the existing token/font delivery pipeline
only. Full component CSS and vendor runtime are not approved by this decision.

| Item                              | Verified value / evidence                                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Design-system family              | UX4G 3.0, as described by the official installation site                                                                       |
| Design/Figma version              | 3.0, according to the official site's design-kit FAQ; the design file itself was not audited                                   |
| npm package and latest stable tag | `ux4g-web-components@3.0.0`; registry `dist-tags.latest` is `3.0.0`, without prerelease/deprecation metadata                   |
| Publisher / maintainer            | `ux4g.npm`, `support.ux4g@digitalindia.gov.in`, in official package registry metadata                                          |
| Published                         | 2026-09-27T17:17:41.743Z; packaged changelog entry dated 2026-09-26                                                            |
| Corresponding CDN release         | `UX4G@3.3.0`, explicitly mapped by the packaged changelog; previous npm 2.1.0 mapped to CDN 3.2.0                              |
| Provenance                        | Exact registry tarball and SHA-512 integrity in the baseline and lockfile; downloaded tarball integrity independently verified |
| Approval boundary                 | Current tokens/font/reset compatible; component/runtime migration requires later review                                        |

Authoritative sources:

- [Official UX4G installation and integration guidance](https://www.ux4g.gov.in/get-started/installation).
- [Official component documentation](https://doc.ux4g.gov.in/web/?path=/story/getting-started-quick-start-guide--quick-start).
- [Publisher registry release history and dist-tags](https://registry.npmjs.org/ux4g-web-components).
- [Exact publisher release metadata](https://registry.npmjs.org/ux4g-web-components/3.0.0).
- [Verified npm distribution containing README, CHANGELOG, CSS, runtime and types](https://registry.npmjs.org/ux4g-web-components/-/ux4g-web-components-3.0.0.tgz).
- [Corresponding official CDN CSS entrypoint](https://cdn.ux4g.gov.in/UX4G@3.3.0/index.css), used as evidence, not a production dependency.

These version namespaces are distinct. A CDN suffix is not an npm pin. The
current npm latest tag is a verified publisher fact; approval for CCure is the
bounded compatibility decision above, not a claim of government certification.

The 3.0.0 changelog maps the CDN release but leaves its detailed major-change
description unfinished. Package contents were therefore compared directly.
The Storybook site is client rendered; its complete interactive component
documentation was not independently verified in this review.

No official React-specific package was established. Registry lookups for
`ux4g-react-components` and `@ux4g/react` returned 404. The unrelated
`ux4g-react@0.0.1` has publisher `kousict` and a Gmail maintainer address; it is
unverified and unapproved. Official integration guidance supports applying the
published CSS to React markup. This project retains React ownership of behavior.

## 2. Compatibility investigation

Comparison used the installed 2.1.0 distribution and the independently verified
3.0.0 tarball, with PostCSS parsing, token-reference resolution, font hashes,
selector/class inventories, export metadata and runtime-source inspection.

| Surface                                    | Result and migration implication                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tokens                                     | 20 base grid/gutter tokens added; no base/dark token removals or changed values. All 87 distinct UX4G tokens referenced by authored application source resolve identically in light and dark themes, including variable chains. No missing reference/cycle found.                                                                                                             |
| Reset / box sizing                         | Universal reset unchanged: `border:0; box-sizing:border-box; margin:0; outline:0; padding:0`. Existing generator rescoping preserved. This does not approve the global reset for later full-CSS adoption.                                                                                                                                                                     |
| Fonts / typography                         | All seven upstream font-face descriptors and embedded payloads unchanged. The same Noto Sans 400 normal face is converted to WOFF2 and served from the same origin; no font duplication or removal introduced.                                                                                                                                                                |
| Component classes / APIs                   | Export map unchanged, but runtime and type files changed. Exact selector strings: 350 removed, 612 added; these counts include grouping changes. Actual official class names: 106 removed, 267 added. Examples include `ux4g-btn-lg/md/sm` and corresponding input/checkbox/table sizes replaced by newer size naming. Full component compatibility is not established.       |
| Forms, buttons, tables, dialogs, dropdowns | Component rules and size selectors changed. New declaration/consent/signature pattern attributes were observed. No current components consume this CSS; later adapters need component-level behavior, sizing, semantics and keyboard review.                                                                                                                                  |
| Layout / spacing / responsiveness          | New grid/gutter tokens and responsive gutter utilities appear. Existing consumed spacing/breakpoint/z-index tokens remain identical. Activating layout/utilities could change container widths, gutters and cascade; B.1 keeps them excluded.                                                                                                                                 |
| Global CSS / collisions                    | Authored CSS-class intersection with upstream stylesheet includes `is-active` and `muted`. This is a static inventory, not proof of collision-free full CSS. Unprefixed selectors, html/body/heading/form rules, specificity, focus rules, z-index and responsive utilities require cascade measurements in B.2/B.3. The current extracted delivery does not add those rules. |
| CSS attributes                             | New `src`, `data-variant` and `data-state` selector attributes observed; no removed selector attribute found.                                                                                                                                                                                                                                                                 |
| Runtime attributes                         | Ten new data attributes observed, including declaration scrollbox, consent checkbox, signature box, input wrapper and submit-button hooks; no removed runtime data attribute found.                                                                                                                                                                                           |
| Runtime                                    | Bootstrap ESM grows from 309,578 to 324,798 bytes; both embedded behavior payloads changed. It creates two inline script elements and provides no observed nonce integration. No `eval`/`new Function` calls found. Runtime remains excluded.                                                                                                                                 |
| Dependencies                               | Both releases declare no runtime, peer or optional dependencies. Upstream development dependencies are publisher build tooling, not installed as application transitives.                                                                                                                                                                                                     |
| Browser requirements                       | Neither package declares an engines/browser matrix. No complete official support matrix verified. Chromium regression measurements establish only the tested browser behavior; cross-browser support remains B.8 work.                                                                                                                                                        |

Noto Sans Display 400 normal and five Material Icons families remain omitted
by the pre-existing delivery policy. Upstream formats are embedded TTF for
Noto Sans/Display and mixed TTF/OTF for icons, all with `font-display:swap`.
Common headings reference the display-family token, but already use its
fallback because that face was not delivered. B.1 preserves this behavior;
typography delivery/unification belongs to B.2 and later UI phases.

## 3. Dependency, provenance and asset guardrails

`package.json`, lockfile root and the sole installed UX4G package all specify
exact `3.0.0`. The lockfile diff changes only UX4G's root declaration and its
version, tarball URL and integrity. No other dependency was upgraded.

`ux4g-baseline.json` supplies the generator's expected version, input CSS hash,
delivery mode and retained font policy. `ux4g-baseline.mjs` rejects incorrect
installed version or upstream CSS hash before any asset writes. Missing input
fails clearly; there is no fallback release.

`npm run ux4g:check` is offline and read-only. It checks:

- Exact package/lock/root/installed agreement and registry URL/integrity.
- Actual nested installed packages separately from the lockfile, including
  same-version duplicates, aliases and unexpected UX4G packages/dependencies.
- Unapproved competing framework declarations, lockfile/installed entries and
  source imports/assets, including Bootstrap, MUI, Ant Design, Chakra,
  PrimeReact, Semantic UI, Bulma, Tailwind and other known framework families.
- UX4G source imports confined to the design-system layer; runtime/full CSS
  activation rejected under this B.1 baseline. Existing component migration is
  not required. The existing official-class prohibition is retained for the
  current token-only delivery and must be deliberately revised in B.2/B.3.
- Generated baseline/provenance/version/mode, CSS/font byte counts and full
  SHA-256 hashes, expected font files and same-origin asset delivery.
- Unchanged deployment CSP policy hashes and forbidden runtime bundle markers.

Known framework names are a maintainable denylist, not a guarantee of detecting
every future framework or hand-vendored copy. Explicit approval of a framework
requires a reviewed change to the policy; there is no silent exception switch.

The generated CSS, font and manifest remain ignored derived build outputs.
No timestamps, absolute machine paths or random values enter the manifest.
`npm run ux4g:verify` deletes generated output before each of two independent
runs, checks provenance and compares raw CSS/font/manifest bytes, filenames
and ordering. Both runs were byte-identical.

| Evidence                                            | SHA-256                                                            |
| --------------------------------------------------- | ------------------------------------------------------------------ |
| Upstream 3.0.0 CSS                                  | `8963db356123377037fddd8ce9fc4fdc1a9259dee79ffc962a6b90e63f8be2aa` |
| Generated token CSS                                 | `be437be1fb4c6524a68f1267aa0faecab45a623b4caa51319198f03f5c23a551` |
| Generated manifest                                  | `00557d2ff497ed508db1f399b0fdc62cd8f30f2f8e6565d38366b10ea8e1591c` |
| Noto Sans WOFF2, before and after                   | `e30fe55bc615a405377c86ef627742bcba7dddbb0053a1dbe34860cae1ecc92c` |
| Application JS payload, before and after host build | `d81b23f09bd896160a1a6cb534d68e044db7ea028ea5edd80f191408c88eb3ce` |

Generated version is `3.0.0`, delivery mode `tokens`, with one retained font.
The existing experimental full-CSS mode is not approved for application use;
foundation validation rejects delivery-mode drift.

## 4. CSP and runtime decision

`Frontend/nginx.conf` is unchanged, with full file SHA-256
`122bbc6209f9fb3cb9197538f734ff0a32238e42d352f1303d35ea2c238ed39b`.
Before/after Docker HTTP headers were identical:

```text
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self';
object-src 'none'; base-uri 'self'; frame-ancestors 'none';
```

The existing style allowance is unchanged. No script `unsafe-inline`,
`unsafe-eval`, CDN origin or additional script exception was introduced.

**Runtime not enabled because CSP incompatibility exists.** The official
bootstrap injects inline script text without observed nonce support, which
`script-src 'self'` blocks. CSS/assets remain usable through the approved
same-origin pipeline and React adapters. Static inspection is not a complete
runtime security audit; it does not establish safe runtime integration.
The browser harness's deliberate inline-script injection was detected by CSP.
Actual same-origin font requests returned 200, `font/woff2`, 889,348 bytes,
with the unchanged hash above. Main captures recorded no CSP violations.

## 5. Measured build impact

Host: Node 20.20.2, npm 10.8.2. Existing CI uses Node 22; existing Docker build
uses its pinned Node 25 image and Nginx. No build environment was changed.
Sizes are exact bytes; timings are single observed runs, not benchmarks.

| Measurement                           |           Before, npm 2.1.0 |            After, npm 3.0.0 |             Delta |
| ------------------------------------- | --------------------------: | --------------------------: | ----------------: |
| Unpacked UX4G distribution file bytes |                  10,954,386 |                  11,132,718 |          +178,332 |
| Installed `node_modules` file bytes   |                 198,051,364 |                 198,208,430 |          +157,066 |
| Upstream CSS                          |                   8,315,261 |                   8,369,064 |           +53,803 |
| Generated token CSS                   |                      59,937 |                      60,619 |              +682 |
| Generated WOFF2                       |                     889,348 |                     889,348 |                 0 |
| Production CSS                        |                     434,339 |                     435,019 |              +680 |
| Production JS                         |                   1,737,721 |                   1,737,721 | 0, byte-identical |
| Generated delivery assets             | 1 CSS + 1 font + 1 manifest | 1 CSS + 1 font + 1 manifest |                 0 |
| Build including generation            |              18.340 seconds |              18.144 seconds |    -0.196 seconds |
| Vite-only reported build time         |                1.33 seconds |                1.23 seconds |     -0.10 seconds |
| Final Docker validation build         |              22.158 seconds |              22.228 seconds |    +0.070 seconds |
| Docker image size                     |                  97,301,783 |                  97,302,269 |              +486 |

The first upgrade Docker run took 33.517 seconds; the final run above followed
the verifier path-resolution correction. Both succeeded. Cache and concurrent
validation affect timings. Existing large-chunk and ineffective dynamic-import
warnings remain; B.1 does not optimize them. JS asset filenames can change
through build metadata despite byte-identical JS payloads.

## 6. Validation results and limits

| Check actually executed                                  | Result                                                                                                       |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `npm install --save-exact ux4g-web-components@3.0.0`     | PASS; changed one package                                                                                    |
| `npm ci`                                                 | PASS; 359 packages added, no lockfile drift                                                                  |
| `npm ls ux4g-web-components`                             | PASS; exactly one root `ux4g-web-components@3.0.0`                                                           |
| `npm ls --all`                                           | PASS, exit 0; absent optional platform/test packages are reported as optional                                |
| `npm run ux4g:check -- --dependencies-only`              | PASS                                                                                                         |
| `npm run build`                                          | PASS; 304 transformed modules                                                                                |
| `npm run ux4g:verify`                                    | PASS; two clean, byte-identical generation runs                                                              |
| `npm run ux4g:check`                                     | PASS; dependency/provenance/duplicate/framework/assets/CSP checks                                            |
| `npm test`, final full run                               | PASS; 105 files, 3,051 tests, including existing accessibility tests and 24 new negative foundation fixtures |
| `npm run lint` and explicit ESLint on foundation scripts | PASS, zero warnings                                                                                          |
| Docker builds and repository frontend smoke script       | PASS; SPA, deep routes, immutable JS, gateway prefix, CSP/nosniff and Nginx startup                          |
| Browser before/after comparison                          | PASS for regression comparison; 136/136 states identical                                                     |
| Browser harness determinism                              | PASS; two repeated captures of four representative states on each build                                      |
| Browser harness sensitivity                              | PASS; all 11 deliberate injections detected in every expected category                                       |

The first full unit run had a new suite-import failure because Vite transformed
a relative `new URL` into an HTTP URL. Resolving the script directory from
`fileURLToPath(import.meta.url)` corrected it; the full suite was rerun, without
removing or suppressing tests. Existing jsdom navigation/window-alert
diagnostics remain in passing application tests.

Chromium captures used isolated production Docker builds and intercepted API
fixtures: eight Common/module-entry pages, Asset Registry, Security Dashboard,
login, organization creation/user-role dialogs and settings drawer, at widths
320, 375, 390, 414, 768, 1024, 1280, 1440 and 1920, plus eight selected dark
captures. Compared accessible names, ARIA, tables, Tab order, live regions,
styles, geometry, overflow, contrast, requests, runtime errors and screenshots.
All 136 main states were ready, with no failed action, unstubbed API request,
write attempt, off-origin request, CSP violation, exception or blocked route.
Sensitivity deliberately creates regressions; its requests are never sent to
the real backend. The additional Asset Registry keyboard probe opens a detail
route whose four detail reads are not covered by the old fixture catalogue; they
return intercepted 404s equally before/after, while sort, focus, toggle
reachability and row navigation probes pass. These are fixture gaps, not
production validation of that detail API.

Known browser defects are preserved: 14 Audit overflow states, five login
contrast-failure states (10 measured failing label instances), hidden mobile
navigation focusability and other Phase A focus/menu/dialog findings. Identical
captures prove no measured regression, not accessibility conformance. Functional
test coverage includes auth/MFA/RBAC/route/API and Audit/scan workflows; this
does not replace live-backend or complete cross-browser end-to-end testing.

`npm audit --json` returned exit 1 both before and after: the vulnerability
records are identical, with five affected package entries (three high, two
moderate): Axios, brace-expansion, js-yaml, react-router and react-router-dom.
No UX4G advisory or new dependency finding was reported. The production audit
(`--package-lock-only --omit=dev --audit-level=high`) also returned exit 1:
Axios high and the two router entries moderate. The existing security workflow
therefore remains failing on this pre-existing high-severity finding. No audit
failure was downgraded to a warning and no unrelated package was upgraded.
Security remediation requires a separate dependency/API compatibility task.

Raw local evidence is in `/tmp/ccure-b1`: publisher metadata, comparison JSON,
before/after measurements, command logs, browser reports/screenshots,
determinism/sensitivity reports and HTTP/font hashes. This directory is
temporary; the dated results and hashes above are the persistent review record.

## 7. Permanent development rule and CI scope

Use the latest officially published/recommended stable UX4G release applicable
after compatibility/security/CSP validation, then pin the approved release
exactly. Never use a floating latest tag or introduce an older release as
incidental development. Refresh official evidence deliberately at upgrades;
offline CI checks the approved baseline, not the changing registry latest tag.

All modules share Official UX4G → CCure Design System → Platform Shell/product
modules. Use official equivalents through approved thin React adapters. Custom
equivalents need a documented technical reason; another framework needs explicit
approval. Preserve accessibility, responsive behavior, spacing, typography and
visual language. Existing application-specific CSS is tracked migration work.

The rule is recorded in frontend architecture/README, `Frontend/AGENTS.md` and
`CLAUDE.md` for developers and coding assistants. CI now checks the dependency
foundation after installation and reproducibility/provenance after build,
alongside existing tests/lint. It does not demand component adoption before
those migration phases are implemented. Full browser/accessibility architecture
enforcement and framework-denylist evolution remain B.9 work.

## 8. Changed files

| File                                                      | B.1 purpose                                                             |
| --------------------------------------------------------- | ----------------------------------------------------------------------- |
| `Frontend/ux4g-baseline.json`                             | Sole approved release/provenance and delivery/CSP definition            |
| `Frontend/package.json`                                   | Exact dependency upgrade and foundation-check command                   |
| `Frontend/package-lock.json`                              | Matching exact registry release/integrity                               |
| `Frontend/scripts/ux4g-baseline.mjs`                      | Shared baseline loader and installed input verification                 |
| `Frontend/scripts/check-ux4g-foundation.mjs`              | Offline dependency/duplicate/framework/asset/CSP checks                 |
| `Frontend/scripts/build-ux4g-assets.mjs`                  | Baseline-driven generation and full provenance/hashes                   |
| `Frontend/scripts/verify-ux4g-assets.mjs`                 | Two clean runs and raw manifest/CSS/font comparison                     |
| `Frontend/src/__tests__/design-system/foundation.test.js` | Negative drift/duplicate/tamper/framework/CSP fixtures                  |
| `Frontend/src/__tests__/design-system/guardrails.test.js` | Existing checks read the authority and current font policy              |
| `.github/workflows/ci.yml`                                | Dependency and reproducible-asset CI gates                              |
| `Frontend/AGENTS.md`                                      | Permanent instructions for frontend coding agents                       |
| `Frontend/README.md`                                      | Developer standard and executable check guidance                        |
| `docs/FRONTEND_ARCHITECTURE.md`                           | Project-wide architecture/design-system rule and accurate current stack |
| `CLAUDE.md`                                               | Matching frontend instructions for coding assistants                    |
| `docs/ux4g/02-dependency-strategy.md`                     | Historical 2.1.0 evidence banner pointing to current authority          |
| `docs/ux4g/B1_VERSION_FOUNDATION.md`                      | Verification, compatibility, measurements, limits and coherent rollback |

Unrelated pre-existing untracked Policy documents and architecture documents
were left untouched. No application component or stylesheet was edited.

## 9. Coherent rollback to the previous 2.1.0 state

Rollback is one complete set. Do not change only the package version or leave
3.0.0 baseline/tests/generator metadata with a 2.1.0 installation. Before using
this procedure, preserve the current B.1 patch and any later edits. It restores
only the listed B.1 paths, not the whole repository or unrelated untracked work.

From the repository root, restore every previously tracked B.1 file to the
starting revision:

```bash
git restore --source=bad5b3f0e1d24f8485d8cae9b1ee7b0f156e5860 --staged --worktree -- \
  Frontend/package.json Frontend/package-lock.json \
  Frontend/scripts/build-ux4g-assets.mjs \
  Frontend/scripts/verify-ux4g-assets.mjs \
  Frontend/src/__tests__/design-system/guardrails.test.js \
  .github/workflows/ci.yml CLAUDE.md Frontend/README.md \
  docs/FRONTEND_ARCHITECTURE.md docs/ux4g/02-dependency-strategy.md
```

Unstage and remove only the newly added B.1 paths:

```bash
git rm --cached --ignore-unmatch -- \
  Frontend/ux4g-baseline.json Frontend/scripts/ux4g-baseline.mjs \
  Frontend/scripts/check-ux4g-foundation.mjs \
  Frontend/src/__tests__/design-system/foundation.test.js \
  Frontend/AGENTS.md docs/ux4g/B1_VERSION_FOUNDATION.md
rm -f -- Frontend/ux4g-baseline.json Frontend/scripts/ux4g-baseline.mjs \
  Frontend/scripts/check-ux4g-foundation.mjs \
  Frontend/src/__tests__/design-system/foundation.test.js \
  Frontend/AGENTS.md docs/ux4g/B1_VERSION_FOUNDATION.md
```

Then regenerate the ignored assets from a fresh installation with the restored
generator and verifier:

```bash
cd Frontend
npm ci
npm ls ux4g-web-components
npm ls --all
npm run ux4g:assets
npm run ux4g:verify
npm run build
npm test
npm run lint
```

Verify installed/generated version 2.1.0, token CSS 59,937 bytes/hash prefix
`15658a1eb682ac57`, one unchanged Noto Sans WOFF2, and unchanged CSP. Build a
fresh frontend image and run `bash scripts/ci/smoke_frontend.sh IMAGE`; deployment
or restart is a separate action. Never reuse a 3.0.0 `dist` or image after
rollback. If B.1 has subsequently been committed as one isolated commit, revert
that entire commit instead of selectively restoring paths, then run the same
install/regeneration/validation sequence. Do not run a blanket reset/clean.

## 10. Deferred phases and verdict

- B.2: approved component/layout/utility CSS pipeline and typography delivery.
- B.3: central UX4G React primitives and migration-aware class-policy revision.
- B.4: shared shell/navigation visual and interaction migration.
- B.5: authentication UI migration, without auth-contract changes.
- B.6: Audit components/workflows adopting the central primitives.
- B.7: Phase A accessibility remediation and broader conformance evaluation.
- B.8: responsive defects and supported-browser matrix/verification.
- B.9: broader architecture, visual, keyboard and accessibility CI enforcement.
- B.10: final documentation freeze after verified component adoption.

**GO — B.1 COMPLETE** for the bounded dependency/token/font foundation.
Pre-existing security/a11y findings remain explicit; this is not a complete
UX4G component migration or GIGW/WCAG conformance declaration.

**Commit-ready changes: YES.** No commit made in this phase.
