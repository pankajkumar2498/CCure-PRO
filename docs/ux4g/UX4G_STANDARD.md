# Permanent frontend standard

CCure Audit PRO uses one consistent UX4G design language based on the officially
recommended/stable UX4G release applicable to the project. The exact approved
version is pinned after compatibility/security review. Official UX4G components
are preferred; thin CCure adapters are allowed where application contracts
require them. Custom UI is allowed only for genuine domain-specific functionality.
No competing UI framework is permitted. The rule applies to all modules and
future contributors/AI agents and is enforced through CI.

## Approved release and upgrade process

`Frontend/ux4g-baseline.json` is the executable release/provenance authority.
The approved package remains **`ux4g-web-components@3.0.0`**. The package's
version, the UX4G design-family version and the separately published CDN version
are different identifiers; do not substitute one for another. B.1–B.6 records
retain their historical evidence. No existing commit is rewritten.

Before proposing a release change, check the [official installation guide](https://www.ux4g.gov.in/get-started/installation),
[official web documentation](https://doc.ux4g.gov.in/web/?path=/story/getting-started-quick-start-guide--quick-start)
and verified npm publisher/release metadata. Record compatibility, accessibility,
security and CSP review, update the exact pin/lockfile/baseline together and
regenerate through the central pipeline. CI is offline after dependency/browser
installation and enforces the approved release. It does not silently track a
mutable `latest` tag, download a CDN or upgrade a production dependency.

## Component, layout and behavior boundary

- All modules import `src/design-system/index.js` (or its directory entrypoint).
  Vendor classes, CSS and JavaScript belong only in that shared foundation.
- Prefer the shared official CSS adapters for buttons, forms, radio/checkbox/
  switch controls, feedback, cards, tables, tabs, menus, modals and drawers.
  Preserve native props/events, form values and accessible names.
- Use the fluid Platform Shell and shared tokens for spacing, typography,
  colors, focus and responsive behavior. Keep scrolling tables/graphs inside
  their own named, keyboard-reachable regions. Never suppress page overflow
  with global `overflow-x: hidden`/`clip` or add mass `!important` overrides.
- Domain content such as CVEs, scan evidence, topology and risk charts stays
  within Audit. The shared surrounding controls remain mandatory.
- Three native file inputs are documented compatibility exceptions:
  AMT JSON inventory, NewScan target-list file and Compliance evidence upload.
  No shared upload adapter yet preserves all three contracts. Each is named,
  and only one file input is permitted in each existing workflow. Other native
  button/input/select/textarea/table/dialog equivalents fail the boundary gate.
- Existing domain `!important` declarations and reduced-motion overrides are
  recorded in `Frontend/ux4g-ui-exceptions.json`. Removal is allowed; adding new
  declarations fails. Do not expand the manifest merely to make CI pass.

## Accessibility, responsive and security requirements

New/touched UI must have visible keyboard focus, labels and error associations,
correct menu/radio semantics and keyboard behavior, named dialogs, top-dialog
focus confinement, inert/hidden background isolation, Escape behavior and
focus restoration. Use shared feedback instead of native `alert()`.

The browser gate checks WCAG A/AA rules including contrast, semantic names,
scroll-region reachability and target sizes, plus explicit keyboard interactions.
It exercises 320, 375, 390, 414, 768, 1024, 1280, 1440 and 1920 CSS-pixel widths,
light/dark states and 200%/400% equivalent reflow. Data tables/maps may scroll
locally; ordinary page content must reflow. Long text and loading/empty/error/
destructive states belong in the synthetic catalogue whenever functionality is
added. The current Policy/Rank/IR entries are placeholders, not implemented
product screens; future implementations must extend this catalogue.

Keep Auth/MFA/session/RBAC decisions, API payloads, routing and module boundaries
unchanged during presentation work. The unit suite tests those contracts; the
authorization inventory must match source. Browser API reads/writes are explicit
synthetic fixtures and never contact a live backend.

UX4G assets are self-hosted and generated once from the approved package.
The full global reset and UX4G runtime remain disabled. The runtime's bootstrap
conflicts with `script-src 'self'`; do not relax CSP to enable it. The browser
server applies the existing production CSP verbatim. The pre-existing
`style-src` policy is preserved; no new policy exception is introduced.

## Required checks

From `Frontend/`, after a clean checkout:

```sh
npm ci
npm run ux4g:check -- --dependencies-only
VITE_API_BASE_URL=/api npm run build
npm run ux4g:verify
npm run ux4g:check -- --dist
npm run ux4g:architecture
node scripts/build-authorization-inventory.mjs --check
npm run lint
npm test
npx playwright install --with-deps chromium firefox webkit
npm run test:browser
```

Browser artifacts go outside source (`/tmp` by default, a CI runner directory
in CI). Browser checks use production dist plus a separately built primitive
fixture, and a loopback test server that refuses all unmocked API calls.
Tests assert behavior and geometry, not platform-dependent screenshot pixels.
Record failed gate findings; fix new regressions and close known in-scope issues.
Do not add broad axe exclusions, retries or ignored errors to obtain a green run.

## Evidence limits and manual review

Automated tests complement manual accessibility and assistive-technology review;
they do not certify UX4G/GIGW/WCAG conformance. See [GIGW 3.0](https://guidelines.india.gov.in/)
for the government project assessment framework and [Playwright accessibility testing](https://playwright.dev/docs/accessibility-testing)
for automation limits. Linux WebKit exercises the Safari engine; it is not a
branded macOS/iOS Safari or VoiceOver run. Actual NVDA/JAWS/VoiceOver user testing
requires an appropriate workstation and remains part of release acceptance.

The zoom gate verifies [W3C reflow equivalence](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html):
1280 CSS pixels at 200%/400% gives 640/320 CSS pixels, with viewport height scaled
too. A separate 200% text-size check detects fixed-height clipping. These are
explicitly automated equivalents, not claims of clicking every browser's zoom UI.
Manual branded-browser zoom and screen-reader review should accompany a release.

Phase closure and validation evidence: [B.7–B.10 report](B7_B10_FINAL_CLOSURE.md).
