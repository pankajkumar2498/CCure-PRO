# Phase B.2 — centralized UX4G asset pipeline

> Group 1 extends this completed B.2 pipeline with scoped official component CSS. See [B.3/B.4 implementation and validation](B3_B4_SHARED_PRIMITIVES_SHELL.md); the B.2 results below remain historical evidence.

This phase strengthens the approved B.1 asset foundation without migrating
components or changing application styling, typography, functionality, APIs,
auth/RBAC, routing or backend code. The exact approved release remains
`ux4g-web-components@3.0.0` from the publisher registry, defined in
[`Frontend/ux4g-baseline.json`](../../Frontend/ux4g-baseline.json).
Release identity, publisher verification and CSP investigation are recorded in
the historical [B.1 report](B1_VERSION_FOUNDATION.md).

## Delivery contract

```text
Exact approved npm package + locked WOFF2 converter
                        ↓
             build-ux4g-assets.mjs
                        ↓
           tokens + existing self-hosted font
                        ↓
          CCure Design System token entry point
                        ↓
          Common / Auth / Audit / Policy / Rank / IR
```

All modules continue to consume the existing design system. No module owns a
UX4G package version, asset generator, vendor stylesheet, font declaration or
CDN import. The sole CSS import remains in
`src/design-system/tokens/index.css`; its content and import order were not
changed in B.2.

The approved delivery mode is `tokens`. Only the existing Noto Sans face is
delivered. No component/layout/utility CSS, universal reset, additional font or
vendor runtime is activated. Noto Sans Display and icon-font omissions retain
the existing fallback behavior. Typography changes need a later explicit
migration review.

## Central implementation and outputs

`scripts/ux4g-pipeline.mjs` defines the shared asset layout, approved-mode
validation, implementation/converter identity and token/font URL checks. The
generator, verifier and foundation checker all use this definition.

| Generated output                                        | Role                                                                                             |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `src/design-system/tokens/ux4g.generated.css`           | UX4G root/dark tokens and the retained font-face; imported only by the central token entry point |
| `public/assets/fonts/ux4g/noto-sans.woff2`              | The existing font, derived from the verified package's embedded font data                        |
| `src/design-system/tokens/ux4g.generated.manifest.json` | Build provenance and complete output/input identity                                              |
| `public/assets/ux4g/manifest.json`                      | Byte-identical provenance copy, published at the same origin and copied into `dist` by Vite      |

Generated outputs remain ignored. Docker's build context also excludes them,
along with staging/lock directories, so a developer's cached assets cannot
supply the image's inputs. Docker installs with `npm ci`, checks the approved
dependency foundation, regenerates assets and validates the production copies.
No application code fetches the provenance JSON; it adds no UI behavior.

## Input verification and safe publication

Before generation, the pipeline verifies the exact dependency/lock/installed
package, upstream stylesheet SHA-256, approved token-only mode, unchanged CSP
and asset-source boundaries. There is no release fallback. `UX4G_CSS_MODE=full`
fails before publishing anything; environment settings cannot activate
unapproved CSS. The old experimental full-CSS branch was removed.

Manifest schema 2 records:

- Exact npm version, tarball URL, registry integrity and publisher identity.
- Verified upstream CSS hash and approved-baseline file hash.
- Generator, baseline-loader and shared-pipeline implementation hashes.
- Locked `wawoff2` version/integrity and hashes of its entry point, compressor
  and compiled compression binding, which contains the conversion implementation.
- Generated CSS/font byte counts and full SHA-256 hashes; embedded font-source
  hash; retained/omitted families; relative output layout and delivery mode.

The manifest contains no timestamps, random identifiers or machine-specific
absolute paths. Temporary staging paths never enter generated output.

All conversion, parsing and content checks complete before existing assets
are replaced. The generator writes a complete set into a temporary staging
directory, serializes publication with `.ux4g-assets.lock`, and publishes the
source manifest last. Ordinary publication failures restore the prior output
set. If restoration itself fails, backups are retained and the error identifies
their location. Do not delete those backups until recovery is complete.

This is staged publication with recovery, not a claim that multiple directory
renames are one filesystem transaction. An interrupted process can leave a
lock/staging directory or incomplete set; validation rejects mismatched output.
Confirm no publisher is active, preserve backups and regenerate/recover before
removing a leftover lock. Do not delete a lock belonging to an active build.

## Detecting stale assets and bypasses

`npm run ux4g:check` checks generated source assets without changing them. It
rejects stale baseline/generator/converter identity, incorrect package
provenance/version, changed CSS/font bytes, unexpected font files, disagreement
between build and public manifests, and font URLs outside the central output.
It also checks that token-only CSS contains no component/reset rules.

Source checks reject direct module imports of generated CSS, known vendor-path
bypasses, UX4G CDN assets, copied generated CSS headers, additional retained-font
declarations, and named UX4G asset files outside the pipeline. Existing
dependency/duplicate/framework/runtime/CSP guards remain in place.

These checks detect known imports, naming and provenance signals; they are not
a guarantee of recognizing arbitrary hand-vendored assets with all identifying
metadata removed. The architectural rule applies even where automation cannot
identify such a copy.

`npm run ux4g:check -- --dist` additionally requires the deployed provenance
bytes to equal the generated manifest and every deployed font/inventory to
match its output hash. Both `postbuild` and `prepreview` run this validation,
so building or previewing an incomplete/stale production set fails clearly.
Bare `vite build` bypasses npm lifecycle hooks; use `npm run build`.

## Commands and CI flow

From `Frontend`:

```bash
npm ci
npm ls ux4g-web-components
npm ls --all
npm run ux4g:check -- --dependencies-only
npm run ux4g:assets
npm run ux4g:verify
npm run build
npm run ux4g:check -- --dist
npm test
npm run lint
```

`dev` and `pretest` generate through the same pipeline. `prebuild` generates,
Vite bundles the existing central CSS and copies public assets, and `postbuild`
checks the deployed manifest/fonts. The reproducibility verifier starts each
of two runs without CSS, font, build manifest or public manifest, then compares
all four outputs and checks their provenance.

CI retains the B.1 dependency and reproducibility checks and now verifies
production copies with `--dist`. It does not require UI component migration.
No dependency, lockfile version, Node image, CSP policy or UI framework was
changed by B.2.

## Validation evidence

Validation date: 2026-10-04. Branch: `modular_architecture`; HEAD remains
`bad5b3f0e1d24f8485d8cae9b1ee7b0f156e5860`. B.1 changes were already uncommitted
at the start of B.2 and were preserved. No commit, deployment or restart of
the running frontend was performed.

The delivered source token CSS, bundled CSS, JS and WOFF2 are byte-identical
to B.1. B.2 adds only provenance JSON to public delivery:

| Artifact              | Bytes / SHA-256                                                                |
| --------------------- | ------------------------------------------------------------------------------ |
| Token CSS             | 60,619 / `be437be1fb4c6524a68f1267aa0faecab45a623b4caa51319198f03f5c23a551`    |
| Noto Sans WOFF2       | 889,348 / `e30fe55bc615a405377c86ef627742bcba7dddbb0053a1dbe34860cae1ecc92c`   |
| Build/public manifest | 2,588 / `07cf169be49da492e9d33056ecfe7df18e0d5f4962adf29d3b5e47ddf2dd3204`     |
| Host production CSS   | 435,019 / `bb7923e4b6a8af05ee2705ac79be0843e777152ee5a2cf412a79b713d49fcf01`   |
| Host production JS    | 1,737,721 / `d81b23f09bd896160a1a6cb534d68e044db7ea028ea5edd80f191408c88eb3ce` |

Both clean generation runs produced identical bytes for CSS, font and both
manifest copies. The public JSON returned 200 with `application/json` from the
Docker image and equaled the local generated metadata. The font returned 200,
`font/woff2`, with its unchanged hash.

The Nginx configuration and before/after HTTP CSP headers are unchanged.
`script-src 'self'` and `font-src 'self'` remain in force. The pre-existing
style allowance remains unchanged; no `unsafe-inline`/`unsafe-eval` or new
origin was added. Runtime remains disabled because the publisher's bootstrap
injects inline scripts incompatible with the current script policy.

The initial build caught an overbroad new font-source check that classified
the legitimate compiled CSS bundle as an authored font declaration. The check
was scoped to authored source/public CSS, and the build passed without changing
UI code or weakening any runtime/CSP check.

The local clean-install flow passed dependency checks, asset generation,
two-run reproducibility and production build/validation. Lint passed with zero
warnings, including explicit ESLint checks on build-time scripts. Focused
foundation/pipeline tests passed: 33 tests across two files, including nine new
B.2 tests. The corrected pipeline/import-architecture checks passed 60 tests.

| Validation actually executed                                                                                  | Result                                                                                  |
| ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Clean local `npm ci`, `npm ls` and foundation checks                                                          | PASS; no lockfile drift, one exact approved UX4G installation                           |
| Local asset generation and two-clean-run reproducibility                                                      | PASS; all four output copies match                                                      |
| Local production build / `postbuild --dist`                                                                   | PASS; current CSS/JS/font bytes unchanged                                               |
| Clean Node 22.23.3 / npm 10.9.9 CI-equivalent install, build, generation, reproducibility and deployed parity | PASS; Node 20/22 generated manifest bytes identical                                     |
| Local frontend/script lint and Node 22 frontend lint                                                          | PASS, zero warnings                                                                     |
| New pipeline/foundation negative tests                                                                        | PASS, 33 tests                                                                          |
| Corrected pipeline plus existing import-architecture tests                                                    | PASS, 60 tests                                                                          |
| Final full unit suite on Node 22, `npm test -- --maxWorkers=4`                                                | PASS; 106 files / 3,060 tests, zero unhandled errors, 100.36 seconds                    |
| Isolated B.1 full-suite comparison on Node 22                                                                 | PASS; 105 files / 3,051 tests                                                           |
| No-cache Docker build, using the existing Node 25 image                                                       | PASS; 31.107 seconds, image 97,311,828 bytes                                            |
| Repository Docker/frontend smoke script                                                                       | PASS; SPA, deep routes, immutable bundle, gateway prefix, CSP/nosniff and Nginx startup |
| Before/after browser regression                                                                               | PASS; 136/136 states identical                                                          |
| Final Docker artifact parity                                                                                  | PASS; every served file equals the browser-tested B.2 image                             |

GitHub Actions was not remotely triggered because no commit/push was performed.
The workflow's asset commands were exercised in a clean Node 22 copy, including
fresh installation and generation; actual Docker delivery was validated under
the repository's existing Node 25 image.

Full-suite execution exposed a new test-data/import-audit collision, corrected
by constructing fixture CSS directives without masquerading as actual module
imports. The existing import audit and all pipeline assertions remain intact.

The nine new pipeline tests exercise build-time Node filesystem and publication
code. They explicitly use Vitest's Node environment rather than jsdom. Existing
application and accessibility test environments were not changed. The final
complete B.2 run passed all 3,060 tests with zero unhandled errors, followed by
successful lint and production-asset validation.

Earlier full-suite attempts hit unchanged application/test timing defects:
Audit Logs pagination assertions inspect the last API call, which can instead
be the live `limit:10` polling request; and Compliance Workspace toast callbacks
can run after jsdom teardown, producing `window is not defined`. The default
Node 22 run passed all 3,060 assertions but exited 1 on those two unhandled
Toast errors. Local/default and Node 22 four-worker runs passed 3,059 assertions
and failed the Audit Logs timing assertion. No error was suppressed, test
removed or timeout increased. The relevant application/test files are unchanged
from HEAD/B.1. Their isolated B.1 comparison passed 59 tests, and the complete
B.1 comparison passed all 3,051 tests. The final B.2 pass does not establish that
these timing-sensitive tests are stable under every scheduling condition.
Their poll/timer stabilization remains separate work; no application behavior
or existing test assertion was changed in this phase.

Browser comparison uses isolated production images and intercepted API
fixtures, with no real-backend writes. It covers Common/module entry pages,
login, representative Audit pages, organization/user-role dialogs and settings
at widths 320, 375, 390, 414, 768, 1024, 1280, 1440 and 1920, plus selected dark
states. All 136 before/after captures are identical across screenshots, styles,
geometry, accessible names, ARIA, tab order, tables, requests and runtime
measurements. All states were ready, without failed actions, writes, unstubbed
requests, off-origin requests, CSP violations, exceptions or blocked routes.

Known issues remain unchanged: 14 Audit overflow states and five login
contrast-failure states, plus the other Phase A focus/menu/dialog findings.
Passing regression comparison is not complete accessibility conformance.
Existing chunk-size/dynamic-import build warnings remain.

`npm audit --json` still exits 1 with the same five package findings as B.1
(three high, two moderate; Axios, brace-expansion, js-yaml and the two router
entries). No new finding or dependency/lockfile change was introduced. The
existing production security gate remains affected by Axios. No audit failure
was suppressed and no unrelated dependency was upgraded.

## Files changed relative to B.1

| File                                                          | Purpose                                                                      |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `Frontend/scripts/ux4g-pipeline.mjs`                          | Shared layout, approved mode, input identity and token/font validation       |
| `Frontend/scripts/build-ux4g-assets.mjs`                      | Central validation, staged publication/recovery and provenance generation    |
| `Frontend/scripts/check-ux4g-foundation.mjs`                  | Stale implementation/tool checks, source boundaries and production parity    |
| `Frontend/scripts/verify-ux4g-assets.mjs`                     | Shared paths and reproducibility of all output copies                        |
| `Frontend/package.json`                                       | Production validation in postbuild/prepreview                                |
| `Frontend/ux4g-baseline.json`                                 | B.2 migration status/report pointer; exact release and font policy preserved |
| `Frontend/Dockerfile`                                         | Dependency/source validation before image generation/build                   |
| `Frontend/.dockerignore`                                      | Exclude cached generated output and publication staging                      |
| `Frontend/.gitignore`                                         | Ignore generated public provenance and staging/lock output                   |
| `.github/workflows/ci.yml`                                    | Verify production parity in the existing asset gate                          |
| `Frontend/src/__tests__/design-system/asset-pipeline.test.js` | Negative pipeline, publication/recovery and deployed-copy fixtures           |
| `Frontend/src/__tests__/design-system/foundation.test.js`     | Existing asset fixtures include current pipeline provenance                  |
| `Frontend/AGENTS.md`                                          | Central-pipeline instructions for coding assistants                          |
| `Frontend/README.md`                                          | Developer pipeline usage and validation commands                             |
| `docs/FRONTEND_ARCHITECTURE.md`                               | Current shared delivery architecture                                         |
| `CLAUDE.md`                                                   | Matching assistant pipeline instructions                                     |
| `docs/ux4g/B1_VERSION_FOUNDATION.md`                          | Preserve historical evidence with current-pipeline pointer                   |
| `docs/ux4g/B2_ASSET_PIPELINE.md`                              | Pipeline contract, verification and transition record                        |

No application component, authored UI stylesheet, routing/API module, backend
file, dependency declaration version or lockfile was changed in B.2.

## Recovery and rollback

For ordinary stale generated assets, run `npm ci`, `npm run ux4g:assets`,
`npm run ux4g:verify` and `npm run build`; validate `--dist`. Do not hand-edit
manifest hashes or add an alternate font/CDN to make checks pass.

Rollback of B.2 must retain the approved B.1 **3.0.0** foundation. Restore the
B.1 versions of the changed scripts, package scripts, baseline, Docker/ignore
files, CI and documentation; remove the new pipeline helper/test/report and
generated `public/assets/ux4g` directory. Reinstall and regenerate with B.1's
generator/verifier, then build, test, lint and run Docker/browser validation.
Never reuse a B.2 `dist` or image with restored B.1 generation code.

A local pre-B.2 source snapshot is retained at `/tmp/ccure-b2/b1-snapshot`,
with its file inventory and B.2 changes list in the same evidence directory.
This is temporary evidence, not a permanent backup. When committing, keep B.1
and B.2 as reviewable units so a future B.2 revert preserves B.1. In the current
uncommitted workspace, do not restore B.2 paths blindly from HEAD: HEAD still
predates B.1, so that would undo the approved dependency foundation. Preserve
later/user edits before any rollback.

## B.3 boundary

B.3 can start from this centralized, verified asset delivery contract. It must
review official component CSS and adapter semantics before enabling those
assets or relaxing the current official-class guard. It must keep one approved
package/source and pipeline, React-owned behavior and the restrictive CSP.
Runtime activation, typography changes, component migration, Phase A
accessibility/responsive repairs and cross-browser conformance remain deferred.

Local command logs, before/after browser reports/screenshots, Node 22 validation,
Docker/HTTP evidence and snapshots are under `/tmp/ccure-b2`.

**GO — B.2 COMPLETE**
