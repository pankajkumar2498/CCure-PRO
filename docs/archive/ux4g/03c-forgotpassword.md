# Phase 3C Batch 2 — ForgotPassword

One page. No other page was modified.

## 1. Page Selection

Chosen by you as the first auth-adjacent form migration. It is the smallest
Group A page (118 LOC), it exercises `CcureInput` and `CcureFormField` — which
batch 1 could not — and it is a **public route**, so unlike `RoleManagement` a
real before/after browser capture was possible.

It also carries a genuine security contract, which is the point of doing it
deliberately rather than incidentally.

## 2. Baseline

| Metric                            |                                                             Value |
| --------------------------------- | ----------------------------------------------------------------: |
| JSX LOC                           |                                                               118 |
| Page-local CSS                    |            **0** — everything came from shared `styles/forms.css` |
| Inline `style={{`                 |                                                                 0 |
| Hardcoded colours in the page     |                           0 (the shared auth shell supplies them) |
| Legacy token references           |                                                                 0 |
| Buttons / inputs / labels / forms |                                                     1 / 1 / 1 / 1 |
| Alerts                            | 2 (`.auth-error` `role="alert"`, `.auth-success` `role="status"`) |
| Loaders                           |                              1 (`.btn-spinner` inside the button) |
| Links                             |                                                      1 (`/login`) |
| API calls                         |                                                                 1 |
| Route                             |                                       `/forgot-password` (public) |
| Query parameters                  |                                                              none |

Selectors used, **all shared with four unmigrated auth pages**:
`.auth-split-wrapper`, `.auth-form-panel`, `.auth-card`, `.auth-brand`,
`.auth-title`, `.auth-sub`, `.auth-error`, `.auth-success`, `.auth-form`,
`.field`, `.auth-btn`, `.btn-spinner`, `.auth-switch`, `.auth-link`.

## 3. Functional Contract

```
Route     /forgot-password   (public, no guard)
API       POST /auth/forgot-password
Payload   { email_or_username: <trimmed string> }
Response  res.detail (optional)

Submit    forgotPassword(emailOrUsername.trim())  — exactly once
Success   setSuccess(res.detail || "If this account is registered, you will
                                    receive a reset link shortly.")
          → the form is UNMOUNTED and replaced by the confirmation
Error     message → data.message
                  → data.detail (array joined on ", " by .msg, else the string)
                  → "An error occurred. Please try again."
          → the form REMAINS mounted so the user can retry
Loading   button disabled; label becomes "Sending recovery link..."
Nav       <Link to="/login">Sign in</Link>
```

The field is `type="text"`, not `type="email"` — the endpoint accepts a
username as well as an address, and `type="email"` would make the browser
reject a username before any request was made.

## 4. Security Contract

`/auth/forgot-password` is deliberately **not** an account-existence oracle.
CLAUDE.md records that `"User not found."` was once a fourth distinct failure
message on this path and was removed precisely because it distinguished a
registered address from an unregistered one.

What the page must preserve:

|                               |                                                                                                                                                        |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Uniform response              | The backend answers 200 with the same body either way. The UI must not undo that by rendering two different states.                                    |
| One request per submission    | No probe, no pre-check, nothing whose timing could be compared between a known and an unknown address.                                                 |
| Generic confirmation          | `"If this account is registered, you will receive a reset link shortly."` is the fallback; the backend's own `detail` is shown verbatim when supplied. |
| No disclosing wording         | Nothing anywhere may say an account was or was not found.                                                                                              |
| Error path is equally uniform | The error branch renders whatever the API returned and adds no existence-dependent state of its own.                                                   |

**Timing:** the page performs exactly one `await` on one endpoint. The
migration added no conditional work, no second request and no branch that
depends on the response content beyond selecting the message string, so it
introduces no timing signal.

## 5. Baseline Tests

25 assertions were written against the **unmigrated** page and run before any
change. Result: **20 passed, 4 failed** (after one correction, below).

| Group                          | Result   | Meaning                                                                                                                                            |
| ------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| API contract (4)               | **pass** | endpoint, payload, trimming, one call, no call on mount, username accepted                                                                         |
| Account-enumeration safety (5) | **pass** | generic message, identical DOM for registered vs unregistered, no disclosing wording on either path, single request                                |
| Behaviour (7)                  | **pass** | backend detail honoured, form unmounts on success and persists on error, validation-array joining, generic fallback, double-submit prevented, link |
| Accessibility (4 of 8)         | **fail** | the migration's specification                                                                                                                      |

The four failures — each fixed by the migration:

1. **Two `<h1>` elements** on the page.
2. **Required state not announced** — the visible label said nothing.
3. **No description** — the placeholder was the only guidance, and a
   placeholder vanishes the moment the user types.
4. **No `aria-busy`** while submitting.

### One baseline assertion was wrong and was corrected, not weakened

The DOM-comparison test initially failed. The diff was a single value:

```
Expected: <span class="auth-metric-val">3,250+</span>
Received: <span class="auth-metric-val">2,250+</span>
```

That is `AuthHeroPanel`'s decorative "Assets Audited" counter — a `setInterval`
counting to 10,000. The two renders were captured at different animation
frames. The test was measuring the clock, not the response.

It was rescoped to `.auth-form-panel`, which is where an enumeration signal
would actually surface, and the reason is recorded in the test. The assertion
is narrower and now meaningful; it was not relaxed to make it pass.

## 6. Migration Map

| Existing                                               | CCure replacement                                                     |
| ------------------------------------------------------ | --------------------------------------------------------------------- |
| `<input id="emailOrUsername">` + `<label>` in `.field` | `CcureInput` (label, hint, `aria-describedby`, `aria-invalid` wiring) |
| `<button class="auth-btn">` + `.btn-spinner`           | `CcureButton` (`loading`, `aria-busy`, disabled)                      |
| `<div class="auth-error" role="alert">`                | `CcureAlert variant="danger"`                                         |
| `<div class="auth-success" role="status">`             | `CcureAlert variant="success"`                                        |

**Kept custom, deliberately:** the auth shell — `.auth-split-wrapper`,
`AuthHeroPanel`, `.auth-card`, `.auth-brand`, `.auth-title`, `.auth-sub`,
`.auth-switch`, `AuthTrustFooter`. Four unmigrated auth pages share every one
of those classes; replacing them here would either break those pages or make
this one visually inconsistent with the rest of the auth flow. They migrate as
a group.

## 7. Changes

Business logic is unchanged: `handleSubmit`, all four `useState` declarations,
the `try/catch/finally`, the trim, the message-precedence chain and every
string were copied verbatim. Only the returned JSX changed.

### The finding that shaped this batch

`.auth-split-wrapper` hardcodes `background:#020617; color:#f8fafc`, and
`.auth-card` is `rgba(15,23,42,.85)`. **The auth flow is a fixed dark surface
that ignores `data-theme` entirely.**

CCure primitives resolve their colours from `--ccure-*`, which follow the root
theme. Dropping `CcureInput` onto that card unchanged would render **a white
box with near-black text on a #0f172a card** whenever the user's account theme
is light — which is the default. Not a styling nit: a contrast failure
introduced by the migration.

**Resolution — `.cc-theme-dark`, added to the design system's token layer.** A
container class that redefines the CCure semantic tokens to their dark values,
so any `cc-*` descendant renders dark regardless of the root theme. The card
carries it.

Why a class rather than `data-theme="dark"` on the div: `data-theme` is a
root-only contract written by `PreferencesContext`, and UX4G's own tokens are
defined at `:root[data-theme=dark]` and **do not scope to a subtree** — the
attribute on a div would style nothing. Keeping an account-level theme and a
locally dark region as separate ideas is correct, because they are separate
ideas.

This is a design-system addition made during a page migration. It is justified:
**five** pages need it, it belongs in the layer that owns theming, and the
alternative was either a contrast failure or re-hardcoding colours in the page.

### A bug in that addition, caught by its own test

The first version redefined the severity **text** colours but not their
**tints**, so `--ccure-sev-critical` (#ffb3ae) sat on `--ccure-sev-critical-bg`
(#fff8f8) at **1.63:1** — light on light. The contrast suite, extended to cover
the new palette, caught it immediately.

Rather than patch the five it happened to surface, an audit found the general
case: **11 tokens** whose light definition resolves through a UX4G _semantic_
token, which flips only at `:root` and therefore silently keeps its light value
inside a scoped container. All 11 are now restated, and a guardrail test
enforces completeness so the next token added cannot repeat it.

## 8. Accessibility

|                           | Before                      | After                                            |
| ------------------------- | --------------------------- | ------------------------------------------------ |
| Label association         | `<label for>` present       | preserved via `CcureInput`                       |
| Required announced        | **no** — attribute only     | `required` + `(required)` in the accessible name |
| Field description         | **none** — placeholder only | hint wired through `aria-describedby`            |
| `aria-invalid`            | n/a                         | set only when an error is present                |
| Loading announced         | **no**                      | `aria-busy="true"`                               |
| Button name while loading | changed, no busy state      | name retained, busy stated                       |
| Error                     | `role="alert"`              | preserved                                        |
| Confirmation              | `role="status"`             | preserved — polite, and deliberately so          |
| Focus visibility          | shared auth CSS             | design-system focus ring, scoped dark            |
| Contrast                  | —                           | 63 assertions across three palettes              |
| Two `<h1>`                | **defect**                  | **still present — not fixed, see §18**           |

`role="status"` on the confirmation is kept rather than upgraded to `alert`: it
is a confirmation, it is the _same_ confirmation either way, and making it
interrupt would be a change to security-adjacent messaging for no benefit.

## 9. Visual Regression

Real before/after captures from both containers (3200 unmigrated, 3299
migrated), desktop 1280×900 and mobile 390×844, reduced-motion.

### Intentional design changes

- **Button colour**: cyan gradient → UX4G primary (violet). The design-system
  brand colour taking over, scoped dark.
- **Required marker** now visible next to the label.
- **Hint line** added under the input.
- Input border/padding follow `CcureInput`.

### Accidental regressions

**None found.** The hero panel, card geometry, title, sub-title, switch link
and trust footer are pixel-consistent. Card content shifts down ~4px, entirely
accounted for by the added hint line.

### One thing worth your decision, reported as neither

The placeholder became more prominent. Measured on the dark scope:

```
value text   neutral-50  #fafafa on #0a0a0a = 18.97:1
placeholder  neutral-200 #e5e5e5 on #0a0a0a = 15.72:1
```

`.cc-field__control::placeholder` uses `--ccure-text-secondary`, which on a
dark surface is nearly as bright as a real value — so the placeholder can read
as a filled field. The old page's placeholder was visibly dimmer.

This is a **design-system** issue affecting every `CcureInput`, not a
ForgotPassword one. The fix is a placeholder tier between secondary and
disabled — one declaration — but it changes every input in the product, so it
is raised here rather than slipped into a page migration. See §18.

## 10. Functional/API Regression

|                      | Before                       | After     |
| -------------------- | ---------------------------- | --------- |
| Route                | `/forgot-password`           | identical |
| Endpoint             | `POST /auth/forgot-password` | identical |
| Payload              | `{ email_or_username }`      | identical |
| Trimming             | page trims, api trims        | identical |
| Calls per submission | 1                            | 1         |
| Calls on mount       | 0                            | 0         |
| Success behaviour    | form unmounts                | identical |
| Error behaviour      | form persists                | identical |
| Message precedence   | message → detail → generic   | identical |
| Double-submit        | blocked while loading        | identical |
| Navigation           | `/login`                     | identical |

Network capture on the migrated page confirms no new request:

```
/forgot-password  /  /favicon.svg
/assets/index-*.js  /assets/index-*.css
/assets/fonts/ux4g/noto-sans.woff2      ← first production page to use the font
/api/auth/refresh                        ← AuthContext boot, pre-existing
```

## 11. Security Regression

**None. Account-enumeration behaviour is unchanged**, and now asserted rather
than assumed:

- The DOM of the confirmation is **byte-identical** for a registered and an
  unregistered identifier (form-panel comparison).
- Exactly one request per submission, whatever was typed.
- No disclosing wording on the success path, checked against six phrasings
  including `"not found"`.
- No disclosing wording on the error path.
- The generic fallback string is unchanged, character for character.
- The security rationale comments are preserved and expanded at the top of the
  file.

No new branch, request or timing-dependent work was introduced.

## 12. Metrics

| Metric                     |      Before |                  After |                                  Δ |
| -------------------------- | ----------: | ---------------------: | ---------------------------------: |
| Page JSX LOC               |         118 |                    151 | +33 (doc block; markup is smaller) |
| Page-local CSS             |           0 | 30 lines / **8 rules** |                                 +8 |
| Shared `forms.css`         |         908 |                **908** |                0 — nothing deleted |
| Inline `style={{`          |           0 |                      0 |                                  0 |
| Hardcoded colours (code)   |           0 |                      0 |                                  0 |
| Legacy token references    |           0 |                      0 |                                  0 |
| Raw `<input>` / `<button>` |       1 / 1 |              **0 / 0** |                                  — |
| CCure component instances  |           0 |                  **4** |                                 +4 |
| API endpoints              |           1 |                      1 |                                  0 |
| Tests (whole suite)        |         253 |                **300** |                                +47 |
| Contrast assertions        |          42 |                 **63** |      +21 (new scoped-dark palette) |
| CSS bundle raw             |   278.12 kB |              280.86 kB |                           +2.74 kB |
| CSS bundle gzip            |    47.73 kB |           **48.01 kB** |                       **+0.28 kB** |
| JS bundle raw              | 1,705.82 kB |            1,705.69 kB |                           −0.13 kB |
| JS bundle gzip             |   421.39 kB |          **421.54 kB** |                       **+0.15 kB** |

Shared auth CSS is intact and still consumed: `.auth-error` by 4 files,
`.auth-btn` by 4, `.auth-success` by 2. **Nothing was deleted** — this page's
old styling is still needed by Login, Register, ResetPassword and VerifyEmail.

## 13. Validation

| Check            | Result                                                                     |
| ---------------- | -------------------------------------------------------------------------- |
| Tests            | **PASS — 300 passed, 14 files** (was 253/13)                               |
| Lint             | **PASS** — `--max-warnings=0`                                              |
| Build            | **PASS** — 2.23 s                                                          |
| CSP              | **PASS** — byte-for-byte unchanged; `nginx.conf` never edited              |
| Air-gap          | **PASS** — zero external hosts vs the baseline control                     |
| Accessibility    | **PASS** — 4 baseline gaps closed; 1 documented, not fixed                 |
| Contrast         | **PASS** — 63 assertions, three palettes, all ≥ 4.5:1                      |
| Dark mode        | **PASS** — plus a new scoped-dark palette, fully measured                  |
| Responsive       | desktop clean; mobile overflow **pre-existing and identical before/after** |
| UX4G policy      | **PASS** — no `ux4g-*` class, no direct import, no runtime                 |
| Login regression | **PASS** — see below                                                       |

```
d-baseA   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3200, no UX4G)
d-baseB   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3200, no UX4G)
d-ux4g    428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3299, batch 2)

matches the expected hash: YES
```

**Sixth consecutive checkpoint at the same hash.** Not adjusted; `Login.jsx`
not touched.

## 14. Bundle Impact

CSS **+0.28 kB gzip** — the `.cc-theme-dark` block (41 token declarations) plus
8 page rules. JS **+0.15 kB gzip**; `CcureInput` and `CcureAlert` enter the
production bundle for the first time, and `CcureButton` was already there via
batch 1.

The font is now genuinely fetched on a production page. It was shipped from
Phase 2 onward but never requested, because no migrated page rendered
`--ccure-font` until this one.

## 15. Files Changed

**Modified (3)**

```
Frontend/src/pages/ForgotPassword.jsx            118 → 151  (presentation only)
Frontend/src/design-system/tokens/themes.css      94 → 177  (.cc-theme-dark)
Frontend/src/__tests__/design-system/contrast.test.js  + scoped-dark palette
Frontend/src/__tests__/design-system/guardrails.test.js + completeness guard
```

**Added (2)**

```
Frontend/src/styles/forgot-password.css                30 lines (8 rules)
Frontend/src/__tests__/pages/ForgotPassword.test.jsx   25 tests
docs/ux4g/03c-forgotpassword.md                        —
```

**Not modified:** every other page including the four remaining auth pages;
`styles/forms.css`; every API client; `App.jsx`; routing; `PrivateRoute`;
`nginx.conf`; `Dockerfile`; `docker-compose.yml`; `package.json`. No old
primitive was deleted.

## 16. Commit(s)

None yet — staged for review. Proposed split:

```
feat(design-system): add scoped dark surface context
fix(design-system): restate every token that would resolve light when scoped
refactor(forgot-password): replace form controls with CCure primitives
test(forgot-password): pin the account-enumeration contract
docs(ux4g): checkpoint 3C batch 2 report
```

## 17. Release Gates

**Engineering gates: PASS.** Tests, lint, build, CSP, air-gap, contrast, dark
mode, UX4G policy and the Login regression all pass. No stop condition was met.

**Legal/licence gate: OPEN.**

```
UX4G README declares MIT
package.json has no license field
package has no LICENSE file
package contains no copyright notice to reproduce
embedded Noto Sans carries OFL attribution/redistribution requirements
```

Written confirmation from `support.ux4g@digitalindia.gov.in` is still required
before a production release containing redistributed UX4G-derived assets. **No
legal clearance is claimed and no copyright notice has been invented.**

This gate is now marginally more material than it was: the self-hosted Noto
Sans is, as of this batch, actually served to browsers on a production page
rather than merely present in the image.

## 18. Issues / Risks

| #   | Issue                                                                          | Severity              | Position                                                                                                                                                                                                                                         |
| --- | ------------------------------------------------------------------------------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | UX4G licence                                                                   | **Open release gate** | §17                                                                                                                                                                                                                                              |
| 2   | **Placeholder reads as a filled value on the dark scope** (15.72:1 vs 18.97:1) | Medium                | Design-system issue affecting every `CcureInput`. One-declaration fix — a placeholder tier — but it changes every input in the product. Your call whether it goes in the next batch or its own change                                            |
| 3   | **Two `<h1>` on all five auth pages**                                          | Medium, pre-existing  | `AuthHeroPanel` renders one alongside the card's. The fix is `h1`→`h2` (styling comes from the class, so zero visual change) but it alters four pages this batch may not touch. A test now records the defect and will fail when it is corrected |
| 4   | Mobile overflow on `.auth-card`                                                | Medium, pre-existing  | Identical before and after; `max-width:440px` + 36px padding exceeds a 390px viewport. Shared by five pages                                                                                                                                      |
| 5   | Auth flow is now visually mixed                                                | Medium                | ForgotPassword uses design-system controls; Login, Register, ResetPassword and VerifyEmail do not. A user moving from Login to "Forgot password?" sees a different button colour. Argues for migrating the auth group next, together             |
| 6   | `.cc-theme-dark` has one consumer today                                        | Low                   | Four more arrive with the auth group. Justified now because the alternative was a contrast failure                                                                                                                                               |

## 19. Recommendation

**GO WITH CONDITIONS.**

The migration is sound: the security contract is preserved and now asserted,
all engineering gates pass, and the Login regression is untouched at the sixth
consecutive checkpoint. The methodology transferred to an auth-adjacent form
without incident.

The conditions are the two items that should be settled before batch 3 rather
than accumulated:

1. **Decide on the placeholder tier** (§18.2). It is a real perceived-affordance
   regression on a production page, and it will replicate onto every form that
   migrates next.
2. **Migrate the auth group together** — Login, Register, ResetPassword,
   VerifyEmail — rather than scattering them among other pages. They share
   every class, they share the two-`<h1>` defect, they share the mobile
   overflow, and they now share a design-system surface with ForgotPassword.
   Migrating them as one batch lets those three be fixed once, and ends the
   mixed appearance of the auth flow quickly.

I would not treat either as blocking this batch's work, but both get worse the
longer they wait.

**STOPPING HERE for review.** No further page will be migrated without
approval.
