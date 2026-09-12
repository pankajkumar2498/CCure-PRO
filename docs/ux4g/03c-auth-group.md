# Phase 3C — Auth Group Migration

Login, Register, ResetPassword and VerifyEmail, migrated as one batch.
ForgotPassword was the reference implementation and is **not** re-migrated.

---

## 1. Scope

**Migrated (4):** `Login.jsx`, `Register.jsx`, `ResetPassword.jsx`,
`VerifyEmail.jsx`.

**Touched because they are shared by those four:** `AuthHeroPanel.jsx` (the
duplicate-`<h1>` fix), `styles/forms.css` (dead-rule removal + a
reduced-motion guard), `CcureInput`, `CcureButton` (both additive).

**Not touched:** every other page, all backend/API code, the authentication
protocol, authorization, routing, CSP, nginx, Docker, `PreferencesContext`, the
UX4G package or its version, and `package.json`.

---

## 2. Baseline

Recorded before any modification.

|                      |    Login |    Register |     ResetPassword |     VerifyEmail |
| -------------------- | -------: | ----------: | ----------------: | --------------: |
| Route                | `/login` | `/register` | `/reset-password` | `/verify-email` |
| LOC                  |      436 |         885 |               309 |             196 |
| Inline `style={{…}}` |        5 |          35 |                 8 |               5 |
| Hardcoded hex        |        0 |          28 |                 8 |               2 |
| `<input>`            |        4 |           6 |                 2 |               1 |
| `<button>`           |        5 |          10 |                 3 |               1 |
| `useState`           |       14 |          21 |                10 |               5 |

**CSS classification.** `forms.css` (908 lines) was the only stylesheet
involved, and it is imported globally via `global.css`, not per page.

| Tier                                        | Selectors                                                                                                                                                              | Disposition                                                                        |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Shared by all five auth pages (the _shell_) | `.auth-split-wrapper`, `.auth-form-panel`, `.auth-card`, `.auth-title`, `.auth-sub`, `.auth-switch`, `.auth-link`, `.auth-brand*`, `.auth-hero*`, `.auth-trust-footer` | **Kept.** ForgotPassword depends on it; rehousing it was not this batch's business |
| Shared by only the four migrated pages      | `.auth-error`, `.auth-success`, `.auth-info`, `.auth-btn`, `.password-input-wrapper`, `.password-toggle-btn`, `.caps-lock-warning`, `.strength-*`                      | **Deleted** — see §9                                                               |
| Shared with pages outside the batch         | `.field`, `.field-label`, `.field-hint`, `.field-input`, `.btn-spinner`, `.auth-checkbox-*`                                                                            | **Kept** — consumers listed in §9                                                  |

**Shared auth-shell consumer audit.** A substring search for `auth-` initially
implicated `pages/scan/CredentialedScan.jsx`. It does not use the shell: its
class is `cred-auth-btn`. Likewise `ChangePasswordModal.jsx` uses
`cpw-strength-bar`, not `.strength-bar`. Both were verified by reading the
call sites, not by trusting the grep — the prefixes are what make the deletions
in §9 safe.

---

## 3. Functional contracts pinned

**Login** — `POST /auth/login` via `AuthContext.login({email_or_username,
password})`. Identifier trimmed, password never trimmed. `status ==
"mfa_required"` shows the challenge and does **not** navigate;
`verifyMfa(mfaToken, code.trim())` → `refreshUser()` → navigate. Email OTP via
`sendEmailOtp(mfaToken)` with a 60 s cooldown that clears on failure.
Remember-me writes `ccure_remember_me` + `ccure_remembered_identity` and clears
the legacy `ccure_remembered_email`. Redirect: router `state.from`
(path+search+hash) → else `postLoginRedirect` **only** when
`state.reason === "expired"` → else `/dashboard`; the session key is removed on
success. Self-registration probe: `null` renders neither branch.

**Register** — `POST /auth/register` → 202, **no tokens**, no session. Email
lower-cased and trimmed, password never trimmed. 404 ⇒ the deployment has
self-registration off. Username availability debounced at 500 ms, ≥3 chars, no
`@`. Domain advisory debounced at 600 ms; a failed probe is silent.

**ResetPassword** — `POST /auth/reset-password` with the query-string token in
the body. Four complexity rules plus confirmation. Success → 2.5 s → `/login`.

**VerifyEmail** — `POST /auth/verify-email {token}` once on mount, guarded
against StrictMode's double mount. `resendVerification(email)`; its failure is
swallowed.

---

## 4. Tests written against the unmigrated pages

**159 new assertions across four files, run against the pre-migration code.**

|                 |   total |  passed | failed |
| --------------- | ------: | ------: | -----: |
| Login           |      46 |      44 |      2 |
| Register        |      47 |      40 |      7 |
| ResetPassword   |      38 |      33 |      5 |
| VerifyEmail     |      28 |      23 |      5 |
| **Suite total** | **469** | **450** | **19** |

**Every functional and security assertion passed against the unmigrated code.
All 19 failures were in an `accessibility` group.** That is the shape the
method is for: the failing set became the specification, and the passing set
became the regression gate.

Three of my own assertions were wrong and were corrected _before_ migration,
each because the page was right and the test was not:

- **"never echoes the password into the DOM."** React mirrors a controlled
  input's value into the DOM `value` attribute — verified with a minimal
  reproduction. That is true of every controlled field in the application,
  `CcureInput` included, and making the field uncontrolled to avoid it would
  change authentication behaviour for no security gain. Narrowed to: the secret
  must not reach rendered text, any other element, or storage.
- **"missing token and invalid token render identically" (VerifyEmail).** I had
  over-read the page's own comment. "Missing" is decidable from the URL the
  visitor already holds and involves no server, so it is not an oracle. The
  assertion that carries the weight — two _different refused tokens_ render
  identically — is now the one being made, alongside a check that both dead
  ends share a heading and a recovery path.
- **"refuses an unticked terms box with a message."** The checkbox carries
  `required`, so constraint validation stops the submit before `validate()`
  runs. The contract that matters is that consent was not given and nothing was
  sent; that is what is asserted.

---

## 5. Defects reproduced, and one that did not reproduce

### Duplicate `<h1>` — REPRODUCED, FIXED

`AuthHeroPanel` rendered `<h1 class="auth-hero-headline">` beside each card's
own `<h1>`, giving all **five** auth pages two competing document titles.
Measured in a real browser: 2 per page, at every viewport tested.

Fixed by `h1` → `h2`. The change is **visually inert**, and that is measured
rather than asserted: `theme.css` zeroes UA margins universally and
`.auth-hero-headline` sets font-size, weight, line-height and margin-bottom
explicitly, and a computed-style comparison of `.auth-hero-headline` across the
two builds shows no difference in any property — only `_tag: H1 -> H2`.

`ForgotPassword.test.jsx` carried an assertion that **pinned the defect**
(`expect(container.querySelectorAll("h1")).toHaveLength(2)`) with a comment
saying it would fail usefully once corrected. The expectation is inverted, not
deleted: the same line now proves the fix.

### Mobile overflow at 390×844 — **DID NOT REPRODUCE**

The brief asked me to fix this "only after reproducing it in the baseline". It
does not reproduce, and I have not applied a fix.

Measured over CDP by walking every element's border box and comparing
`documentElement.scrollWidth` against `clientWidth`:

| Viewport                                        | Container                   | Pages | Overflowing elements |
| ----------------------------------------------- | --------------------------- | ----: | -------------------: |
| 390×844, 360×800, 320×568                       | pre-UX4G baseline (`:3200`) |     5 |                **0** |
| 320×568                                         | pre-batch (`:3299`)         |     5 |                **0** |
| 768×1024, 961×900, 1024×768, 1280×900, 1440×900 | pre-UX4G baseline           |     5 |                **0** |

**45 page/viewport measurements, zero horizontal overflow.**

The cause of the original diagnosis was an arithmetic assumption:
`.auth-card` is `width:100%; max-width:440px; padding:40px 36px`, which looks
like 440+72 — but `theme.css` sets `box-sizing: border-box` universally, so the
padding is inside the width and the card never exceeds its panel's content box.

Re-measured after migration at all seven viewports: still zero.

**No `overflow-x: hidden` was added anywhere and no content is hidden.**

### Three sub-AA contrast values — FOUND during baselining, FIXED

Not in the brief; found by measuring the auth surface while pinning the
baseline. Each value is composited through its actual ancestor chain.

|                                                           |     Before |       After | Where                          |
| --------------------------------------------------------- | ---------: | ----------: | ------------------------------ |
| Pending-approval notice text (`#b45309` on an amber tint) | **3.02:1** |  **5.34:1** | Register, VerifyEmail          |
| **Unmet** password rule (`#64748b`)                       | **3.85:1** | **14.50:1** | Register, ResetPassword        |
| Input placeholder (`#64748b`)                             | **3.31:1** |  **7.66:1** | Login, Register, ResetPassword |

The first is the sharpest: the pending-approval notice carries the single most
important sentence on the page — _confirming your email does not grant access_ —
and it was the least readable thing on it, dark amber on a dark card. The
second is nearly as pointed: the _met_ rules were legible at 9.53:1 and the
_unmet_ ones — the only actionable ones — were not.

### Four more accessibility defects, found by the baseline tests

| Defect                                                                                          | Pages                                |
| ----------------------------------------------------------------------------------------------- | ------------------------------------ |
| Caps-lock warning was a bare `<div>` — never announced                                          | Login, Register, ResetPassword       |
| Field hints/errors not wired to their input (`aria-describedby`, `aria-invalid`)                | Register, ResetPassword, VerifyEmail |
| Password strength conveyed by four unlabelled `<span>`s                                         | Register, ResetPassword              |
| Policy modals: no `role="dialog"`, no name, no focus trap, no Escape; dismiss control named `×` | Register                             |

### A fifth, found while making the visual regression deterministic

`forms.css` declares **seven** animations — a moving grid, a scanning line, two
drifting blobs, a pulsing status dot, a card entrance and a spinner — and had
**no `prefers-reduced-motion` guard of any kind**. The design system's guard
zeroes `--ccure-duration-*`, which these literals do not use, so it could never
reach them. A user who has asked the platform to stop moving things got five
continuous animations on every auth page.

Guarded, with two deliberate exclusions:

- `.auth-feature-card` is declared `opacity: 0` and relies on
  `fadeUp … forwards` to become visible. `animation: none` alone would leave
  the three feature cards **permanently invisible** — a guard that deletes
  content in the name of accessibility. The end state is restored explicitly.
- `.btn-spinner` is left running. Its rotation is not decoration; it is the
  only indication that a submitted form is still working, and freezing it
  reports a stalled request.

Verified by emulating both media states: under `reduce`, all four decorative
animations report `animation-name: none` **and** `.auth-feature-card` reports
`opacity: 1`.

---

## 6. Design-system changes

Three, all additive and all driven by a need the four pages share. The
placeholder tier and scoped-dark guards approved at the previous checkpoint
were **not** revisited.

**`CcureInput` — `adornment` prop.** The password visibility toggle has to sit
inside the field box. The adornment is a _sibling_ of the input, not a wrapper
around it, so the input keeps its own id, label association and describedby
wiring: an adorned field and a plain one are the same field to assistive
technology. Space is reserved with `padding-inline-end` rather than a flex row,
because a flex row makes the input a flex item and the focus ring is then drawn
around the row instead of the field being typed in.

**`CcureButton` — `as` prop.** Three of these pages render an action that
navigates. Those must stay links — only a link can be opened in a new tab,
copied, or announced as "link". Before this the pages reached for
`<Link className="auth-btn">` and hand-copied the button's class names.
`type` and `disabled` are button-only and are not passed to a non-button:
`disabled` on an `<a>` is invalid, and an anchor that _looks_ disabled while
still following its href is worse than one that never looked disabled.

**`CcurePasswordField` — new security pattern.** Six password fields across
three pages duplicated the same markup and the same four defects. It owns the
toggle, the announced caps-lock warning and the strength meter, and is
deliberately _not_ a password policy: the grading predicates are shared through
`gradePassword`, and each page keeps its own `validate()` so a rule cannot be
enforced in one place and not the other.

One defect the shared component introduced and my own test caught: both toggles
on the reset form initially received the identical accessible name "Toggle
password visibility". Two controls sharing one name is exactly what the
per-page implementations had avoided by hand. The field's label is now folded
in — "Toggle New Password visibility", "Toggle Confirm Password visibility".

---

## 7. What the pages became

|                     | LOC before | after |        Δ |
| ------------------- | ---------: | ----: | -------: |
| `Login.jsx`         |        436 |   409 |      −27 |
| `Register.jsx`      |        885 |   577 | **−308** |
| `ResetPassword.jsx` |        309 |   213 |      −96 |
| `VerifyEmail.jsx`   |        196 |   227 |      +31 |
| `forms.css`         |        908 |   735 | **−173** |

VerifyEmail grows because it gained explanatory comments and a `role="status"`
on the in-flight panel; its markup shrank.

Measured in a live browser, pre-batch → post-batch:

|                        | Login     | Register  | ResetPassword | VerifyEmail | ForgotPassword |
| ---------------------- | --------- | --------- | ------------- | ----------- | -------------- |
| `<h1>` count           | 2 → **1** | 2 → **1** | 2 → **1**     | 2 → **1**   | 2 → **1**      |
| Inline-styled elements | 4 → **2** | 7 → **2** | 2 → **2**     | 3 → **2**   | 2 → 2          |
| `.field` (legacy)      | 2 → **0** | 5 → **0** | 2 → **0**     | 1 → **0**   | 0              |
| `.auth-btn` (legacy)   | 1 → **0** | 1 → **0** | 1 → **0**     | 1 → **0**   | 0              |
| `.cc-field__control`   | 0 → 2     | 0 → 5     | 0 → 2         | 0 → 1       | 1              |

Every page-level inline style is gone. The two that remain on each page are a
`drop-shadow` filter inside `AuthIcons`' SVG — a shared component outside this
batch, and the same two the approved ForgotPassword already carries.

---

## 8. Contrast, measured on the live surface

Computed styles read from the running container, every `rgba()` composited
through its real ancestor chain.

**Default states, all five pages:**

| Element        | Colour on surface      |   Ratio |
| -------------- | ---------------------- | ------: |
| Field label    | `#fafafa` on `#0f172a` | 17.16:1 |
| Input value    | `#fafafa` on `#0a0a0a` | 18.97:1 |
| Field hint     | `#e5e5e5` on `#0f172a` | 14.22:1 |
| `.auth-sub`    | `#94a3b8` on `#0f172a` |  6.99:1 |
| Checkbox label | `#94a3b8` on `#0f172a` |  6.99:1 |
| Primary button | `#171717` on `#a391ff` |  6.87:1 |

**Conditional states**, measured by mounting the real class names inside the
real `.auth-card cc-theme-dark` surface:

| State           |  Ratio |     | State                 |   Ratio |
| --------------- | -----: | --- | --------------------- | ------: |
| Alert · warning | 5.34:1 |     | Field error           | 10.71:1 |
| Alert · danger  | 7.64:1 |     | Caps-lock warning     | 12.05:1 |
| Alert · success | 7.76:1 |     | Password rule · unmet | 14.50:1 |
| Alert · info    | 7.36:1 |     | Password rule · met   | 10.70:1 |
| Placeholder     | 7.66:1 |     | Strength grade        | 14.50:1 |

**No sub-AA value on any of the five pages, in any state measured.**

The label figure is the evidence for a specificity fix. `.auth-card label`
(0,1,1) was silently beating `CcureField`'s own `.cc-field__label` (0,1,0), so
the design system's token was being overridden by a literal on every migrated
field. Removing it moved labels from `#e2e8f0` (14.86:1) to `#fafafa`
(17.16:1) — a small gain, but the point is that the token layer is now actually
in charge.

---

## 9. CSS deleted, with evidence

`forms.css` 908 → 735 lines. Every deletion was preceded by a consumer search
across all `.jsx` outside tests, and the two apparent survivors were read at the
call site and shown to be different classes (`cred-auth-btn`, `cpw-strength-*`).

| Deleted                                                                                    | Last consumers                                                                             |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| `.auth-error`, `.auth-success`, `.auth-info`                                               | the four migrated pages → `CcureAlert`                                                     |
| `.auth-btn` (+3 states)                                                                    | the four migrated pages → `CcureButton`                                                    |
| `.password-input-wrapper`, `.password-toggle-btn` (+hover)                                 | Login, Register, ResetPassword → `CcurePasswordField`                                      |
| `.caps-lock-warning`                                                                       | same three → `CcurePasswordField`                                                          |
| `.strength-bar/-seg/-label`, `.strength-1..4`                                              | Register, ResetPassword → `CcurePasswordField`                                             |
| `.auth-card label`, `.auth-card .field {input,select,.field-input}` (+focus, +placeholder) | no auth page renders `.field` any more; the bare-label rule was overriding the token layer |
| `.auth-brand-gem`, `.auth-trust-dot`, `.animated-gem`, `@keyframes gem-spin`               | **already dead before this batch** — zero consumers                                        |

**Kept, because pages outside the batch still use them:** `.field`,
`.field-label`, `.field-hint`, `.field-input` (7 admin/scan files),
`.btn-spinner` (7 files), `.auth-checkbox-row/-label` (Login, Register).

Autofill handling **moved rather than deleted**. `.auth-card
input:-webkit-autofill` was the only thing stopping Chrome painting its pale
yellow behind a dark field, and the design system had none. It now lives on
`.cc-field__control` in tokens — it belongs to the control, not to one page's
card, because every `CcureInput` on any dark surface has the problem.

---

## 10. Visual regression — and a method that had to be replaced

**Pixel hashing is not a sound instrument on this surface, and I am reporting
that rather than reporting its output.**

Two consecutive full-page captures of the _same_ container, same viewport, same
flags, produced **different hashes on 3 of 5 pages**. The instability is
intermittent and moves between pages, which is consistent with `backdrop-filter:
blur(24px)` compositing jitter rather than any page behaviour. Adding the
reduced-motion guard (§5) improved it — Login and Register are now stable across
four consecutive runs — but ResetPassword, VerifyEmail and ForgotPassword remain
unstable.

A worse problem surfaced in the replacement. My first computed-style differ
navigated both containers from one shared CDP page target and returned **"no
computed differences" for `/login` and `/register`** — pages a direct probe
proved had changed from 2 `<h1>` / 0 `cc-field__control` to 1 / 2. A comparison
instrument that can report clean when the subject changed is worse than no
instrument. It was rewritten to capture each container in an independent
process and diff the files offline, with an assertion that the probe measured
the URL it was asked for.

The replacement was then **validated before being trusted**: capturing the same
container twice produces byte-identical output. That is what §7's table is
measured with.

| Instrument                         | Deterministic                         | Used as                        |
| ---------------------------------- | ------------------------------------- | ------------------------------ |
| Full-page pixel hash               | **No** (3/5 pages unstable)           | Human-reviewable evidence only |
| Computed style + geometry + counts | **Yes** (verified by self-comparison) | The regression gate            |

**The `ForgotPassword` control.** ForgotPassword is not in this batch, so it is
the test of whether the batch leaked. Pre-batch → post-batch it shows **no
computed differences** in any of 27 selectors × 13 properties, and no element
count changed. Its only change is the shared `<h1>` → `<h2>`, which is the
intended fix and is visually inert by the same measurement.

**On the historical Login hash.** `81BDD19B5730080794B1FBEA579C9E47` was
produced by an earlier checkpoint's capture path. It is preserved here as the
documented historical baseline, and it is **not comparable** to any figure in
this report: capturing the _unmigrated_ baseline container with this batch's CDP
method yields `8ADFFB32EBD5D41D85B1E6D2D3FBB1B4`, which differs from the
historical value on a build the migration never touched. The difference is the
capture method, not the page. I have not re-stated it as "changed as expected",
because that would imply a comparison I cannot honestly make. Login's stable
hash under the current method, post-migration, is
`7BFB6EAEF966B4B94485A699EE06FD69`.

---

## 11. Security and regression checks

| Check                                      | Result                                                                                                                                             |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Content-Security-Policy                    | **byte-identical** to the pre-UX4G baseline (md5 `6d0616e9…` both)                                                                                 |
| Other security headers                     | X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy all identical                                                         |
| Air-gap — page-originated requests         | **0 external origins** across all five pages (28 requests, all same-origin); baseline control also 0                                               |
| External origins in `dist`                 | 8, all pre-existing link hrefs/doc URLs; `fonts.googleapis` matches an HTML **comment** recording its removal, present identically in the baseline |
| UX4G runtime markers in `dist`             | 0 (`UX4G.js`, `script1.textContent`, `ux4g.min.js`)                                                                                                |
| Analytics / telemetry markers              | 0 (`clarity`, `googletagmanager`)                                                                                                                  |
| `ux4g-*` classes in application JSX        | 0                                                                                                                                                  |
| Direct UX4G imports from pages/components  | 0 (one match is a doc comment stating there are none)                                                                                              |
| Dev-only showcase in production bundle     | 0                                                                                                                                                  |
| UX4G asset reproducibility (`ux4g:verify`) | two independent runs byte-identical                                                                                                                |
| New runtime dependency                     | none                                                                                                                                               |
| Backend / API / routing / auth protocol    | not modified                                                                                                                                       |

**Account-enumeration contracts, asserted in code:** Register never claims an
address is registered and shows only the domain verdict; its confirmation is
conditional ("_if_ that address can be registered"); the resend path reports
success even when the request fails, on both Register and VerifyEmail;
ResetPassword's three failure branches render one message and the page adds no
wording separating them; two different refused verification tokens render
identically.

**Token handling, asserted in code:** the reset and verification tokens never
appear in rendered text, in `innerHTML`, in `localStorage`/`sessionStorage`, or
in any outgoing `href`. The `mfa_token` is likewise never rendered or persisted.
No password reaches storage or any element other than its own field.

---

## 12. Tests

**470 passed, 18 files** (was 310 before this batch; 469 at the pre-migration
baseline).

| File                             | Tests |
| -------------------------------- | ----: |
| `pages/Register.test.jsx`        |    47 |
| `pages/Login.test.jsx`           |    46 |
| `pages/ResetPassword.test.jsx`   |    39 |
| `pages/VerifyEmail.test.jsx`     |    28 |
| `pages/ForgotPassword.test.jsx`  |    25 |
| _(design-system + pre-existing)_ |   285 |

All 19 baseline failures are green. Nothing regressed. Lint clean at
`--max-warnings=0`; build passes.

Three assertions changed during migration, each for a reason recorded at the
call site:

- Label selectors gained a word boundary. `CcureField` appends "(required)" to
  a required field's accessible name — approved Phase 3A behaviour that
  ForgotPassword already ships — so `/^password$/` no longer matches. The
  anchors were tightened, not loosened; each still matches exactly one field.
- The strength-meter assertion was **strengthened** from "has a `role`
  attribute" to a named `role="meter"` with `aria-valuenow`, `aria-valuemax`
  and `aria-valuetext`, because "3" without "of 4" is not an announcement
  anyone can act on.
- The modal dismiss selector moved from `name: "×"` to `name: /close dialog/i`
  — that _is_ the fix, and a sibling assertion pins that no button is named by
  the bare glyph.

---

## 13. Bundle

|          |   Pre-batch |      Post-batch |            Δ |
| -------- | ----------: | --------------: | -----------: |
| CSS raw  |   281.03 kB |   **280.63 kB** | **−0.40 kB** |
| CSS gzip |    48.03 kB |    **47.83 kB** | **−0.20 kB** |
| JS raw   | 1,705.69 kB | **1,700.36 kB** | **−5.33 kB** |
| JS gzip  |   421.54 kB |       421.76 kB |     +0.22 kB |

CSS is smaller despite gaining a new pattern, its stylesheet, an adornment
block, an autofill block and a reduced-motion guard — the 173 deleted lines of
`forms.css` more than cover it. JS is smaller because the pages shed markup and
inline style objects; the small gzip increase is compression noise on a larger
dictionary.

---

## 14. Files changed

**Modified (7)**

```
Frontend/src/pages/Login.jsx                        436 → 409
Frontend/src/pages/Register.jsx                     885 → 577
Frontend/src/pages/ResetPassword.jsx                309 → 213
Frontend/src/pages/VerifyEmail.jsx                  196 → 227
Frontend/src/components/auth/AuthHeroPanel.jsx      h1 → h2 (shared)
Frontend/src/styles/forms.css                       908 → 735
Frontend/src/__tests__/pages/ForgotPassword.test.jsx  defect assertion inverted
```

**Design system (5)**

```
components/CcureInput.jsx        + adornment slot
components/CcureButton.jsx       + polymorphic `as`
components/components.css        + adornment, + autofill
patterns/CcurePasswordField.jsx  NEW
patterns/security-patterns.css   + password-field styles
index.js                         + CcurePasswordField, PASSWORD_RULES, gradePassword
```

**Added (6)**

```
Frontend/src/styles/auth.css
Frontend/src/__tests__/pages/Login.test.jsx
Frontend/src/__tests__/pages/Register.test.jsx
Frontend/src/__tests__/pages/ResetPassword.test.jsx
Frontend/src/__tests__/pages/VerifyEmail.test.jsx
docs/ux4g/03c-auth-group.md
```

---

## 15. Release gates

**Engineering: PASS.** 470/470 tests, lint clean, build green, CSP identical,
air-gap clean, zero sub-AA values, zero overflow, one `<h1>` per page, no
unrelated page changed. No stop condition was met.

**Legal / licence: OPEN — unchanged.**

```
UX4G README declares MIT
package.json has no license field
package has no LICENSE file
package contains no copyright notice to reproduce
embedded Noto Sans carries OFL attribution/redistribution requirements
```

Written confirmation from `support.ux4g@digitalindia.gov.in` remains required
before a production release containing redistributed UX4G-derived assets. **No
legal clearance is claimed and no copyright notice has been invented.**

---

## 16. Recommendation

**GO WITH CONDITIONS.**

The four pages are migrated, the whole auth group now shares one token layer,
and the batch removed more code than it added. Eight accessibility defects were
found and fixed, three of them sub-AA contrast values that no test in the
project could previously have caught — including a notice about account
approval that was, at 3.02:1, the least readable sentence on the page it most
needed to be read on.

Two conditions, neither blocking:

1. **The mobile overflow does not exist.** I could not reproduce it in 45
   measurements across nine viewports and three builds, and the original
   diagnosis was arithmetic that `box-sizing: border-box` invalidates. Nothing
   was changed to "fix" it. If it was observed on a real device rather than
   inferred, that device's viewport and browser would be worth naming, because
   headless Chrome at 320–1440 px does not show it.

2. **Pixel-hash visual regression should be retired for this surface.** It is
   non-deterministic on 3 of 5 auth pages because of `backdrop-filter`, and the
   historical Login hash is not comparable across capture methods. The
   computed-style and geometry instrument used here is deterministic, was
   validated by self-comparison before being trusted, and caught what the pixel
   hash could not — including that my own first version of it returned a false
   clean on two pages that had demonstrably changed. Whoever runs the next
   batch should inherit that instrument, not the hash.

One item carried forward from the previous checkpoint is now closed as a side
effect: light and dark **root** placeholders were previously validated by
measurement only, because no capturable surface rendered a placeholder. Three
migrated pages now do — though still on the scoped-dark surface, so the root
palettes remain measurement-only.

**STOPPING HERE.** No further Group A page will be migrated without review.
