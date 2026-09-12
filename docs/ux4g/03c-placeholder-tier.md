# Phase 3C — Design-System Placeholder Tier

A design-system correction. **No application page was modified.**

## 1. Problem

The ForgotPassword checkpoint measured, on the scoped-dark auth surface:

```
value text   --ccure-text            #fafafa on #0a0a0a = 18.97:1
placeholder  --ccure-text-secondary  #e5e5e5 on #0a0a0a = 15.72:1
```

Both clear WCAG AA comfortably. The defect is not contrast — it is **perceived
hierarchy**. At 83% of the value tier's contrast, a placeholder reads at
essentially the same weight as entered text, so an empty field looks filled.

On a password-recovery form that matters more than it sounds: a user who
believes a field is already populated does not type in it.

## 2. Root Cause

```css
.cc-field__control::placeholder {
  color: var(--ccure-text-secondary);
  opacity: 1;
}
```

The design system exposed three text tiers — `--ccure-text`,
`--ccure-text-secondary`, `--ccure-text-disabled` — and the placeholder was
routed onto the middle one.

That token is not the problem and could not be changed: **24 consumers** across
`components.css`, `shell.css`, `security-patterns.css` and
`role-management.css` use it for hints, subtitles, captions, table headers and
footer text. Dimming it to suit placeholders would have dimmed all of those.

The tier was missing, not miscoloured.

## 3. Solution

A fourth semantic tier, `--ccure-text-placeholder`, sitting between secondary
and disabled:

```
--ccure-text              value, heading, label
--ccure-text-secondary    hint, subtitle, caption
--ccure-text-placeholder  an empty field's prompt      ← new
--ccure-text-disabled     inoperable control
```

### Why not UX4G's own tertiary tier

`--ux4g-text-neutral-tertiary` exists and looked like the obvious home. It was
measured and rejected:

|       | resolves to           | on the input surface | vs secondary                                   |
| ----- | --------------------- | -------------------: | ---------------------------------------------- |
| light | neutral-500 `#737373` |               4.74:1 | good subordination                             |
| dark  | neutral-300 `#d9d9d9` |          **14.03:1** | secondary is 15.72 — **reproduces the defect** |

Adopting it would have fixed light mode and left the dark case essentially
unchanged, which is where the problem was found in the first place. CCure picks
its own steps.

### Why not `opacity`

The brief rules it out and the measurement agrees: an opacity value makes
correctness depend on a browser's placeholder default, which differs (Firefox
dims placeholders on its own). The tier is expressed as a colour, and
`opacity: 1` is kept explicitly so no browser can reintroduce a second,
unmeasured dimming on top of it.

## 4. Token Matrix

Measured against `--ccure-surface`, which is what `.cc-field__control` uses as
its background.

| Context                        | Placeholder             | Background |   Contrast |
| ------------------------------ | ----------------------- | ---------- | ---------: |
| Light                          | `neutral-600` `#525252` | `#ffffff`  | **7.81:1** |
| Dark (root)                    | `neutral-400` `#a1a1a1` | `#0a0a0a`  | **7.66:1** |
| Scoped dark (`.cc-theme-dark`) | `neutral-400` `#a1a1a1` | `#0a0a0a`  | **7.66:1** |

Value text, for comparison, and the resulting subordination:

| Context     | Value text | Contrast | Placeholder share |
| ----------- | ---------- | -------: | ----------------: |
| Light       | `#171717`  |  17.93:1 |         **0.44×** |
| Dark (root) | `#fafafa`  |  18.97:1 |         **0.40×** |
| Scoped dark | `#fafafa`  |  18.97:1 |         **0.40×** |

Was 0.83× before. Roughly equal subordination in both themes, so a form does
not feel different depending on the account theme.

The full ordering holds in every palette — `disabled` is translucent
(`hsla(…, .25)`) and composites to ~1.7–2.0:1, well below the placeholder:

```
value 17.93  >  secondary 10.37  >  placeholder 7.81  >  disabled ~1.73   (light)
value 18.97  >  secondary 15.72  >  placeholder 7.66  >  disabled ~2.03   (dark)
```

Light `neutral-600` was chosen over `neutral-500` (4.74:1) deliberately: 4.74
clears the 4.5 floor by 5%, which is not the "comfortably above" the brief
asks for, and would be at risk from any palette renumber. 7.81 keeps the same
subordination ratio as the dark palette while leaving real margin.

## 5. Component Change

One declaration:

```css
.cc-field__control::placeholder {
  color: var(--ccure-text-placeholder); /* was --ccure-text-secondary */
  opacity: 1;
}
```

Entered text continues to use `color: var(--ccure-text)` on
`.cc-field__control`, unchanged.

Nothing else about the input was touched: dimensions, padding, borders, focus
ring, `aria-invalid`, `aria-describedby`, label association, validation,
disabled and error states are all as they were.

## 6. Token Dependency Audit

The ForgotPassword batch established that scoped-dark tokens can silently
inherit light values. That reasoning was repeated here, and it found a **gap in
the existing guard**.

The Phase 3C batch-2 guard flags a `--ccure-*` token whose light definition
routes through a UX4G _semantic_ token but which is absent from
`.cc-theme-dark`. `--ccure-text-placeholder` is defined against a **fixed
palette step** (`--ux4g-color-neutral-600`), which is not theme-dependent, so
the existing guard would **not** have caught an omission. Demonstrated, not
assumed.

A second guard was added — narrowly:

> **every token overridden in `ccure-tokens.css`'s `:root[data-theme="dark"]`
> block must also appear in `.cc-theme-dark`**

That covers this token and severity, which had been handled by hand. It was
**mutation-tested**: removing the entry from `.cc-theme-dark` makes it fail and
name the offender —

```
AssertionError: overridden for the root dark theme but not for .cc-theme-dark:
  expected [ '--ccure-text-placeholder' ] to deeply equal []
```

The token is now declared in all three places: `:root` (light),
`:root[data-theme="dark"]`, `.cc-theme-dark`.

No other `--ccure-*` token was touched, and no UX4G semantic token remains
unintentionally light inside `.cc-theme-dark` — both guards pass.

## 7. Tests

**310 passed, 14 files** (was 300).

| Added                      | What                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Contrast × 3 palettes      | placeholder ≥ 4.5:1 against the input surface                                                                             |
| Hierarchy × 3 palettes     | placeholder contrast **< value** and **< secondary**, still ≥ 4.5                                                         |
| Subordination × 3 palettes | placeholder ≤ 0.6× the value tier's contrast — catches a collapse back onto secondary, which a bare "less than" would not |
| Guardrail                  | root-dark overrides mirrored in `.cc-theme-dark` (mutation-verified)                                                      |

Contrast suite: **63 → 72 assertions**. Guardrails: **20 → 21**.

Existing `CcureInput` behaviour is unchanged and still covered by the Phase 3A
primitive suite: label association, `aria-describedby` for hint and error,
`aria-invalid` only when invalid, required announcement, unique ids, error
supersedes hint. All pass.

## 8. Visual Validation

| Context     | Evidence                                                                                                                                                                                                          |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scoped dark | `/forgot-password` on the production image — captured before and after. The placeholder is now a clearly subordinate grey where it previously read at near-value weight. Label, hint, button and layout unchanged |
| Light root  | **measured only** — see below                                                                                                                                                                                     |
| Dark root   | **measured only** — see below                                                                                                                                                                                     |

Honest limitation: the design-system showcase's form section has **no
placeholder attribute** on its inputs, and the one input that does carry a
placeholder is inside a modal that a headless screenshot cannot open. Rather
than modify the showcase — a page, and outside this task's scope — light and
dark root are validated by the measured token matrix in §4 and by the nine new
contrast/hierarchy assertions, which run against all three palettes.

The scoped-dark context is the one where the defect was found and is validated
visually.

## 9. Regression

| Check                               | Result                                                                                            |
| ----------------------------------- | ------------------------------------------------------------------------------------------------- |
| Login hash                          | `81BDD19B5730080794B1FBEA579C9E47` — **matches expected**, unchanged                              |
| Application pages                   | **none modified** — verified by file mtime; the three previously migrated files predate this task |
| CSP                                 | byte-for-byte unchanged                                                                           |
| Air-gap                             | zero external hosts attributable to CCure                                                         |
| `ux4g-*` classes in application JSX | 0                                                                                                 |
| Direct UX4G imports from pages      | 0 (one match is a doc comment stating there are none)                                             |
| UX4G runtime markers in `dist`      | 0                                                                                                 |
| New dependency                      | none                                                                                              |
| Lint                                | clean at `--max-warnings=0`                                                                       |
| Build                               | pass                                                                                              |

## 10. Bundle Impact

|          |      Before |         After |            Δ |
| -------- | ----------: | ------------: | -----------: |
| CSS raw  |   280.86 kB |     281.03 kB | **+0.17 kB** |
| CSS gzip |    48.01 kB |  **48.03 kB** | **+0.02 kB** |
| JS raw   | 1,705.69 kB |   1,705.69 kB |        **0** |
| JS gzip  |   421.54 kB | **421.54 kB** |        **0** |

Three token declarations and one changed property value. JS is untouched
because nothing about the component's JavaScript changed.

## 11. Files Changed

**Modified (5)**

```
Frontend/src/design-system/tokens/ccure-tokens.css     + placeholder tier (light + root dark)
Frontend/src/design-system/tokens/themes.css           + placeholder tier in .cc-theme-dark
Frontend/src/design-system/components/components.css   ::placeholder now uses the tier
Frontend/src/__tests__/design-system/contrast.test.js  + 9 assertions
Frontend/src/__tests__/design-system/guardrails.test.js + root-dark mirror guard
```

**Added (1)**

```
docs/ux4g/03c-placeholder-tier.md
```

**Not modified:** `Login.jsx`, `Register.jsx`, `ResetPassword.jsx`,
`VerifyEmail.jsx`, `ForgotPassword.jsx`, `RoleManagement.jsx`, every other
page, `DesignSystemShowcase.jsx`, all backend/API code, routing, auth,
`PreferencesContext`, `nginx.conf`, Docker, CSP, the UX4G package and version,
and `package.json`.

## 12. Release Gates

**Engineering: PASS.** Tests, lint, build, contrast, guardrails, CSP, air-gap
and the Login regression all pass. No stop condition was met.

**Legal/licence: OPEN.**

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

## 13. Recommendation

**GO.**

The correction is three token declarations and one property. The placeholder is
now measurably subordinate in every palette — 0.83× of the value tier before,
0.40–0.44× after — while staying comfortably above the AA floor, and the
ordering value > secondary > placeholder > disabled holds throughout.

The more durable outcome is the guard. This task found that the batch-2
completeness check could not see a token defined against a fixed palette step,
so a scoped-dark omission would have been silent. That hole is closed and
mutation-tested, which matters more than the colour: every future `CcureInput`
migration now inherits a correct placeholder hierarchy, and the next token
added against a palette primitive cannot quietly skip the scoped-dark palette.

One item is worth carrying forward, not blocking: **light and dark root were
validated by measurement rather than by picture**, because no capturable
surface currently renders a placeholder outside the auth page. Adding a
placeholder to the showcase's form section would close that gap in one line —
it belongs to whoever next touches the showcase, not here.

**STOPPING HERE.** No application page will be migrated without approval.
