# B.7–B.10 — Final frontend closure

Date: 5 October 2026. Scope: final accessibility/responsive closure, CI enforcement
and documentation freeze. All in-scope checks pass; release acceptance limits
and pre-existing dependency findings are recorded separately below.

## B.7 — Accessibility

The B.6 foundation had already repaired the original Phase A focus indicators,
mobile navigation, native settings radios, most contrast and Audit overflow.
This phase closes the remaining shared behavior and newly exposed browser cases:

- Modal focus enters synchronously before background isolation. Cleanup restores
  focus after isolation is removed. Only the top trap handles keys; native radio
  groups contribute one Tab stop. A missing/hidden opener falls back to the
  current main landmark. Background attributes are restored exactly.
- Modal isolation follows every ancestor to body and handles nested/shared and
  late portals. Only the top dialog remains available in the accessibility tree.
- Dropdown items act before menu closure and focus restoration, preserving native
  Enter activation. Organization choices expose `menuitemradio`/`aria-checked`
  while retaining their existing switch callbacks.
- Scan progress and scrollable Terms/Privacy text are named keyboard-reachable
  regions. The credential password visibility target now meets the 24 CSS-pixel
  floor. Configuration and organization-wide web finding links use the existing
  accessible semantic link token in both themes.
- No native `alert()` calls remained in application source. A permanent AST gate
  now prevents their reintroduction.
- The initial authentication pending view now uses the named shared loader and
  semantic theme colors. Auth/session/permission/redirect decisions are unchanged.
  Chrome's actual accessibility tree confirms foreground-only dialogs, restoration
  of the outer dialog/page and native radio names/checked values.

## B.8 — Responsive/browser closure

The durable Playwright catalogue extends the B.5/B.6 synthetic states with all
Common administration and product entry pages, remaining Audit configuration,
credentials, schedules, policies, asset detail, web results and report routes.
The current Policy/Rank/IR pages are module entry placeholders.

Every catalogue page runs in both themes at 320, 375, 390, 414, 768, 1024, 1280,
1440 and 1920 CSS pixels in Chromium, Firefox and WebKit. Axe WCAG A/AA checks run
at 320 and 1440; page overflow, CSP, browser exceptions and undeclared requests
are checked at every width. Separate cases cover loading, empty, error, denied,
MFA/security, destructive dialogs, shared primitives and long text. Reflow cases
use 640×500 and 320×250 viewports for 200%/400% W3C equivalence; another case
enlarges text to 200%. These are automated equivalents, not browser-UI zoom tests.

Long organization text elides within the available header width; its full name
remains in the accessible trigger label and the organization menu. Header
icons/actions retain their intrinsic sizes. Firefox exposed controls shrinking
and overflowing despite the table correctly scrolling locally; a final geometry
probe also caught multiline header text being clipped vertically. The permanent
long-text case checks both header containment and page overflow at all nine widths.
Common pages additionally assert full available shell width at 1280 and 1920.
No global overflow suppression or new `!important` override was added. No routing
contract changed.

## B.9 — Enforcement

- Existing foundation gates retain the exact reviewed version, single package,
  registry integrity, self-hosted fonts, CSP hash and disabled runtime checks.
  Existing asset verification checks provenance, stale output and deterministic
  regeneration. No generator or vendor source was changed.
- `ux4g:architecture` parses JSX/CSS, enforces shared primitives/entrypoint/vendor
  class boundaries, forbids native alerts and global overflow workarounds, and
  ratchets existing `!important` declarations against a documented manifest.
  Positive/negative tests exercise these gates.
- Three existing native file inputs are narrow documented upload exceptions,
  each limited to one input in its existing workflow. Domain risk/CVE/topology/
  evidence views retain their specialized content and shared surrounding controls.
- Existing module boundary, Auth/MFA/session, RBAC and route/API contract unit
  suites remain mandatory, alongside authorization inventory consistency.
  Organization test expectations now use the corrected menu radio role. A
  pre-existing AMT delayed-refresh leak is cleaned up in test teardown; its
  production scheduling and API contract are unchanged. Negative source fixtures
  use resolvable imports and JSX expressions so older scanners do not mistake
  them for application implementation.
- CI installs exact development-only Playwright/axe dependencies from the lock,
  builds with the same `/api` base used by Docker, installs the pinned browser
  engines, runs all gates without retries/exclusions, and retains failure traces
  and the JSON report. Browser files are explicitly excluded from Vitest and
  included in lint. Outputs stay outside source.
- The isolated test server serves production dist and an additional shared
  primitive fixture under the production CSP verbatim. No request is forwarded
  to a live backend; undeclared/off-origin requests fail. Test scripts require
  no application service restart and make no live API writes.

## B.10 — Permanent standard

[UX4G_STANDARD.md](UX4G_STANDARD.md) defines the permanent project rule, reviewed
upgrade process, shared adapter boundaries, documented exceptions, validation
commands and release acceptance limits. Root/frontend AGENTS, CLAUDE, both READMEs
and frontend architecture link it. The executable baseline records the final
phase and report while retaining the exact approved package and all security
identities. Stale comments referring to UX4G 2.1/global resets were corrected;
the CSS rules are unchanged.

## Final validation

| Check                                                      | Result                                                                                                      |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Clean `npm ci`, Node 22.23.3 CI toolchain                  | Pass; exact lockfile, 364 installed packages                                                                |
| Production build, local and clean Node 22                  | Pass, including the shipped-asset/runtime guard                                                             |
| UX4G foundation, dependency and dist checks                | Pass; exactly `ux4g-web-components@3.0.0`                                                                   |
| Asset generation, provenance and two-run reproducibility   | Pass; five CSS/font/manifests also byte-identical across local Node 20 and clean Node 22                    |
| UI architecture/exception/documentation gate               | Pass                                                                                                        |
| Authorization inventory consistency                        | Pass; only source line metadata changed                                                                     |
| Lint, source and new browser/architecture tooling          | Pass, zero warnings                                                                                         |
| Full unit suite                                            | 111 files, 3,104 tests pass on clean Node 22                                                                |
| Full browser matrix                                        | 351 cases pass; no skipped/flaky/failed cases                                                               |
| Final checks after the loader/header edits and added gates | 36 targeted cases pass across all three engines                                                             |
| Browser accessibility                                      | No axe WCAG A/AA violations in tested states; explicit keyboard/focus/menu/radio/isolation checks pass      |
| Native Chrome accessibility-tree probe                     | Six stages pass: navigation, account, nested password, outer restoration, page restoration, settings radios |
| CI workflow syntax                                         | Actionlint passes                                                                                           |
| Production Docker build / isolated nginx smoke             | Pass; SPA fallback, font, provenance and unchanged CSP                                                      |

The final default browser suite contains 357 cases: 119 per engine, including the
new authentication pending state and Common full-width case. The full matrix ran
before those final additions; the final 36-case targeted run covers the changed
areas and added checks. This is not a claim of a second complete 357-case run.
The available branded Chrome was 153.0.8010.36; Firefox was 155.0; Linux WebKit
was 26.6. Local WebKit's missing host libraries were supplied from an isolated
temporary library directory. No system package or production service changed.
CI uses Playwright's normal pinned-engine/dependency installation.

Detailed local logs/reports are under `/tmp/ccure-b7-b10/`, especially
`browser-final.json`, `browser-closure-final.json`, `unit-and-lint-final.log`,
`asset-equivalence.json`, `private-route-contract.json`, `inventory-contract.json`
and `preservation.json`. CI retains browser evidence as `ux4g-browser-evidence`.
Remote GitHub jobs were not triggered; workflow commands were checked locally
using the clean CI toolchain and available browser engines.

## Limits and unrelated work

Automation checks accessible names/roles, keyboard behavior and background
isolation, but does not certify GIGW/WCAG or replace assistive-technology users.
Branded macOS/iOS Safari, NVDA/JAWS/VoiceOver and browser-UI zoom review remain
release acceptance checks requiring appropriate workstations. Orca is installed
on this machine, but the executor has no interactive display. Linux WebKit is
the available Safari engine test, not a branded Safari certification.

`npm audit` reports five pre-existing advisories (two moderate, three high) in
axios, brace-expansion, js-yaml, react-router and react-router-dom. The complete
advisory records match the B.6 lockfile exactly; none came from the added test
dependencies. Dependency remediation belongs to the existing security process;
no audit finding was suppressed. Existing dependency deprecation notices, build
chunk-size warnings and unit-test React/jsdom diagnostic output remain. The local
Node 20 Vite engine warning is avoided by the validated Node 22 CI toolchain.
There are no remaining new in-scope failures.

Backend, API clients, Auth/MFA/session/RBAC decisions, routing, CSP and UX4G runtime
behavior are preserved. An AST comparison confirms `PrivateRoute` is identical
outside its pending-state presentation/import. The authorization inventory is
identical after excluding line numbers. Existing B.1–B.6 commits and all seven
unrelated working-tree files are untouched, verified by content hashes and modes.
The Git index stays empty. This phase does not deploy, push, restart application
services or commit.

## Changed file groups

- Shared UI: Dropdown/menu item roles, modal focus/isolation hooks and hook order,
  pending-page layout, corrected token comments, organization header semantics
  and text containment, Common standalone header action sizing.
- Touched presentation: PrivateRoute's pending view, registration policy regions,
  Audit ScanStepper region, credential password target and configuration/web
  finding link colors. Authorization inventory changes only line metadata.
- Enforcement: exact development test dependencies/lock, package scripts,
  Vitest discovery, architecture checker/exception manifest, browser config,
  fixtures/helpers/page/keyboard/primitive/reflow suites and isolated test server.
- Unit tests: new isolation/boundary tests, organization role expectations,
  accessible pending-state assertion and AMT delayed timer teardown.
- CI/docs: frontend workflow additions, root/frontend AGENTS, CLAUDE, root/frontend
  READMEs, frontend architecture, executable UX4G phase metadata, permanent
  standard and this closure record. Historical B.1–B.6 reports are unchanged.
