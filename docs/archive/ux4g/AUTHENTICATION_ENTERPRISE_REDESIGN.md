# Authentication enterprise presentation

7 October 2026. Scope: Authentication UI and Authentication-specific branding.

## Presentation

Sign-in, registration, forgot/reset password, the MFA challenge, email
verification, and the incompatible-backend Authentication error share
`Frontend/src/shell/auth/components/AuthLayout.jsx`. Session expiry continues
to return to the same sign-in page with the existing message and redirect.
Authentication rendering failures also have a scoped fallback, with a fresh
sign-in link and no scan-success claim or private error stack. Previously those
failures could reach Audit's global render fallback, which describes a saved
scan result. That global fallback and all Audit presentation remain unchanged.

The layout has a bounded desktop workspace, a restrained dark identity panel,
left-aligned form headings, and a persistent CCure header. Phone and tablet
layouts omit the identity panel and bring the form directly below the header.
The identity reads “CCure — Enterprise Security / Vulnerability Management
Platform”. CCure's shield, central Noto Sans font, and approved semantic colors
remain in use; the logo's glow is removed. No marketing illustration, animation,
certification, usage figure, or connection-security claim is introduced.

Registration now describes creating a personal account, email verification,
and administrator approval rather than registering an organization. Password
guidance reflects the existing rules. Recovery no longer calls the reset link
“encrypted”. Each Authentication page sets a contextual document title ending
in `| CCure`, restoring the prior title when it unmounts.

## Existing primitives and behavior

| Presentation                                       | Reused approved adapter                          |
| -------------------------------------------------- | ------------------------------------------------ |
| Form surface                                       | `CcureCard`                                      |
| Primary actions and navigation                     | `CcureButton`, including its router-Link support |
| Account and OTP fields, labels, hints, errors      | `CcureInput`                                     |
| Passwords, visibility, strength, mismatch guidance | `CcurePasswordField`                             |
| Remember identity and legal consent                | `CcureCheckbox`                                  |
| Error, success, session, and approval messages     | `CcureAlert`                                     |
| Task context label                                 | `CcureBadge`                                     |
| Pending email verification                         | `CcureLoader`                                    |
| Terms and Privacy dialogs                          | `CcureModal`                                     |

The dependency remains exactly `ux4g-web-components@3.0.0`. There are no vendor
imports, local font declarations, new primitive implementations, or changes to
the central asset pipeline, design tokens, runtime policy, or CSP. Auth layout
rules live under `.auth-layout` in Authentication's stylesheet; the global form
stylesheet and all application product layouts are unchanged.

One additive shared-adapter option is necessary for the requested keyboard
accessibility: `visibilityToggleTabIndex` on `CcurePasswordField`. Authentication
opts into `0`; the previous `-1` default remains for every other consumer.
The existing toggle retains its field-specific name, pressed state, controlled
input reference, and button type. MFA's code field has a distinct React key so
its existing autofocus works when moving from the credential form to the
challenge, instead of reusing the credential input DOM node.

Authentication handlers, validation functions, and existing state/effect hooks
were compared with HEAD and remain unchanged. API clients, authentication
context, session handling, PrivateRoute, RBAC, backend, Audit, Dashboard,
Platform Shell, Policy, Rank, and IR were not modified.
Public Authentication URLs and routing contracts remain unchanged. The only
composition-root change groups the five public Authentication routes under the
scoped render boundary; the incompatible-backend refusal also uses that boundary.
Protected application routes and authorization decisions remain unchanged.
Only the inventory's source-line metadata was refreshed.

## Legally controlled branding exception

The documents supplied to registration from
`Frontend/src/modules/audit/legal/legalDocuments.jsx` remain byte-for-byte
unchanged. Their titles are “Terms of Service — CCure Audit PRO” and
“Privacy Policy — CCure Audit PRO”; the Terms body also uses that identity and
contains Audit-specific descriptions. The existing owner decision D12-9
requires legal review for rewording. This redesign preserves both bodies and
their titles, consent behavior, and navigation labels. No replacement legal
wording has been invented.

The new source-copy regression scans Authentication pages, components, helpers,
and its API client, rejecting inappropriate Audit branding and unsupported
claims while preserving permission keys such as `audit.scan.read`. Browser
checks inspect the rendered Authentication identity and document titles,
excluding the approved legal dialog text, and separately exercise both legal
dialogs and their focus restoration.

## Validation

- Clean cached `npm ci --offline --no-audit`; installed dependency tree and
  exact UX4G version verified.
- Dependency foundation, production build with `VITE_API_BASE_URL=/api`,
  deterministic asset regeneration, and production asset checks pass.
- UX4G architecture, authorization inventory consistency, lint, and whitespace
  checks pass.
- Full frontend unit suite: **114 files, 3,114 tests pass**. This includes all
  **187 existing Authentication page tests**, two new identity regressions, and
  two new rendering-failure regressions. Route contract checks also pass.
- Browser checks use production dist, the existing separately built primitive
  catalogue, explicit synthetic reads/writes, and the unchanged production CSP.
  They cover 320, 375, 390, 414, 768, 1024, 1280, 1440, and 1920 CSS-pixel widths,
  light/dark themes, keyboard interactions, and 200%/400% equivalent reflow.
  Additional Authentication checks cover required/mismatch validation, pending
  submissions, OTP failure and email codes, expired sessions, missing reset
  links, pending email verification, registration disabled, compatibility
  errors, visible password-toggle focus, and both legal dialogs.
  An injected Authentication rendering fault additionally checks safe recovery,
  absence of scan claims/private diagnostics, and containment within Auth.
  The exact synthetic React-child fault is checked through console argument
  messages because Firefox serializes `console.error(Error)` as the opaque
  text “Error”. Each matching event is accounted for once; unrelated exceptions,
  API calls, CSP issues, and accessibility findings still fail the gate.
- Final dedicated Authentication browser suite: **63/63 pass** (21 checks in
  each of Chromium, Firefox, and WebKit). All existing Authentication page,
  flow, legal-dialog, and reflow catalogue checks also pass in all three engines.
- Final complete frontend browser matrix: **419/420 pass**. Chromium and
  Firefox each pass 140/140; WebKit passes 139/140. The unchanged Audit
  credentialed-report page (`page cr-report`, dark theme, 320px) reports a
  color-contrast failure in that run. Its failure screenshot shows the dark
  report surfaces, while axe reports white backgrounds for several report
  descendants. Three independent isolated runs of this exact check on the
  same final build pass **3/3** with all widths, both themes, and the original
  accessibility assertions. This is a non-reproduced wider-suite finding,
  not a clean full-matrix result. No Audit code, retry configuration, or
  contrast assertion was changed; the original failure artifacts are retained.

Browser artifacts and review screenshots are outside source under `/tmp`.
The final matrix report is `/tmp/ccure-auth-browser-final-report.json`; the
isolated diagnostic is `/tmp/ccure-auth-cr-report-diagnostic.json`. Desktop,
phone, registration, reset, dark-theme, and focused MFA screenshots were also
visually reviewed (`/tmp/ccure-auth-*.png`).
Automated checks do not assert GIGW/WCAG certification or replace manual
screen-reader review on the appropriate assistive-technology workstation.

During validation, asset reproducibility verification temporarily removed
generated files while an initial browser/unit run was reading them. That caused
an initial fixture-build error and two missing-file test failures. Asset
verification finished successfully; the full unit suite was rerun successfully
with no overlapping deletion. Browser fixture corrections handle existing
organization query parameters and use the native keyboard path for the shared
consent checkbox. No production behavior or test exclusions were changed to
resolve these validation findings.

The first complete matrix passed all **278 Chromium/Firefox checks**. WebKit
could not launch because the host lacked `libva`, `libva-drm`, `libnice`, and
`libx264`. Using the repository's user-local dependency recovery approach,
Ubuntu packages were unpacked into `/tmp/ccure-auth-webkit-libs`; an already
cached libx264 was reused. All four libraries were checked with `ctypes.CDLL`,
the WebKit executable's `ldd` dependencies resolved, and the installed engine
launched and rendered. A temporary launcher supplies those library paths through
the existing `UX4G_WEBKIT_EXECUTABLE` configuration. No system package, application
code, CSP, test assertion, retry, or accessibility exclusion was changed for
this environment recovery. The recovered WebKit matrix passed **139/139 checks**.
The final 420-check matrix above includes the additional Authentication render
fallback and its regression.

## Rollback

Revert this change's Authentication presentation files and tests, remove the
public-route render-boundary wrapper/import in `App.jsx`, and revert the
additive password-adapter option and its Authentication test update. Refresh
authorization-inventory source-line metadata through its existing generator.
No backend, database, dependency, token, CSP, or deployment migration is needed.
Leave unrelated workspace files and legally controlled documents unchanged.
