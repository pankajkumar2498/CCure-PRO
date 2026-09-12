# Checkpoint 3C — Batch 14: the account dialogs

`ProfileModal` and `ChangePasswordModal` onto CcureModal, CcureTabs,
CcureInput, CcurePasswordField, CcureButton, CcureAlert, CcureBadge and
CcureConfirmDialog. AppLayout's mount point
(`showProfile && <ProfileModal onClose>`) is untouched. Harness detail in
`03c-batch14-harness.md`.

## 1. Files changed

| File                                                    | Change                                                                         | LOC        | inline / colour literals |
| ------------------------------------------------------- | ------------------------------------------------------------------------------ | ---------- | ------------------------ |
| `src/components/layout/ProfileModal.jsx`                | rewritten on primitives; every API call and argument preserved (see §3)        | 968 → 860  | 37 → 0 / 14 → 0          |
| `src/components/layout/ChangePasswordModal.jsx`         | rewritten on CcureModal + CcurePasswordField; strength meter as `role="meter"` | 228 → 207  | 2 → 0 / 5 → 0            |
| `src/styles/account-dialog.css`                         | **new**, layout only, tokens only                                              | 519        | 0                        |
| `src/design-system/hooks/useFocusTrap.js`               | nesting stack: only the innermost active trap acts on Tab/focusin (§4)         | 138 → 157  |                          |
| `src/styles/animations.css`                             | census-backed prune of 125 `pm-*` / `cpw-*` rules                              | 1684 → 870 |                          |
| `src/__tests__/components/layout/ProfileModal.test.jsx` | **new**, 26 tests (20 regression + 6 spec)                                     |            |                          |
| `src/__tests__/design-system/components.test.jsx`       | +1 nested-trap guardrail                                                       |            |                          |

Not touched: AppLayout, AuthContext (`refreshUser`), `api/user.js`,
`api/auth.js`, every page, the Toast/Modal shims, CSP, nginx.

## 2. Accessibility (10 states × 2 themes)

| Measure                               | Pre                                                                         | Post                                                                                                                 |
| ------------------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Dialog `aria-modal`                   | none (both dialogs)                                                         | both, plus the revoke confirmation (`describedby`)                                                                   |
| Focus trap (12 real Tab presses, CDP) | 0 inside / 12 escaped — first Tab landed on the skip link behind the dialog | 12 / 0 on the profile dialog, the security tab and the **nested** change-password dialog                             |
| Unnamed buttons                       | 1–7 per state (close ×2, revoke ×2, eye toggles ×3)                         | 0                                                                                                                    |
| Unlabelled controls                   | 1–4 (three password fields unlabelled)                                      | 0                                                                                                                    |
| Tabs                                  | 2 bare buttons                                                              | `tablist` "Account sections", 2 `tab` with `aria-selected`, roving tabindex, arrow keys, `tabpanel` named by its tab |
| Inline styles (dialog)                | up to 7                                                                     | 0 (2 remaining are the shell's progress widths)                                                                      |
| Contrast failures (892 → 902 pairs)   | 50 sub-AA (worst 1:1, avatar)                                               | **0**                                                                                                                |
| Live regions                          | none                                                                        | loading states `role="status"`, alerts `role="alert"`/`status`, copied-codes announcement                            |

## 3. Security validation

- **API contract**: `getProfile`, `updateProfile({full_name, email})`,
  `getSessions`, `revokeSession(id)`, `revokeOtherSessions()`,
  `changePassword(current, next)`, `enableMfa()` → `confirmMfa(code)` →
  backup codes, `disableMfa(password)`, `refreshUser(true)` after a
  successful confirm or disable, session list pruned to the current session
  afterwards — each asserted by a test with the exact arguments.
- **Password leak**: the test walks every attribute of every element (password
  inputs' own `value` excepted) and the visible text for the typed
  current/new/disable-MFA passwords; harness `passwordFields` census shows
  three named `type=password` controls with `autocomplete=new-password` and
  empty values; `textInputsNamedPassword = 0`; zero `console.*` calls in
  either component.
- **MFA secret / backup codes**: rendered only inside the enrolment step
  (`<code>` elements), never in an attribute, name or title (attribute walk
  after each step); leaving the wizard clears them from state, and the test
  proves they are gone from `document.body.textContent`. The harness never
  drives enrolment, and no capture's `bodyText` contains a secret.
- **Mutation safety**: no write on render or on opening either tab (tests +
  request log: 20 POSTs per harness run, all `/auth/refresh`); enrolment
  starts only from "Set up MFA" (no checkbox exists — test); "Sign out all
  other sessions" is confirmation-gated and cancel writes nothing (test +
  harness: the **pre** build issued `DELETE /api/user/sessions` from that
  click, refused by the stub table; the **post** build issues nothing);
  every write control is `disabled`/`loading` while in flight and a second
  click does not resubmit (test).
- **RBAC**: none of these dialogs makes an authorisation decision; the server
  enforces every endpoint. Nothing client-side was added.
- CSP byte-identical; 0 off-origin requests; no `prefers-color-scheme`, no
  `ux4g-*` class, no runtime/CDN.

## 4. The one design-system change

Mounting the change-password dialog over the account dialog — both
CcureModal, both with `useFocusTrap` — overflowed the stack immediately: each
trap's `focusin` listener saw the other's portalled root as "outside" and
pulled focus back, forever. The hook now keeps a stack of active roots and
only the innermost acts on Tab and `focusin`; unmounting restores focus to
what that trap recorded (the opener inside the outer dialog) and the outer
trap resumes. Single-dialog behaviour is unchanged — the 195-state regression
across every earlier batch is IDENTICAL, and the new guardrail test exercises
the nested case (Tab stays inside the inner dialog ×6, Escape returns focus
to the opener, the outer trap is in charge again). The same nesting is what
the CcureConfirmDialog raised inside this dialog relies on.

## 5. Intentional behaviour changes

1. MFA enrolment starts from an explicit **Set up MFA** button; the checkbox
   toggle whose `onChange` fired `enableMfa` is gone. Disable is a **Disable
   MFA** button that opens the same password-confirmed form.
2. **Sign out all other sessions** asks for confirmation (CcureConfirmDialog,
   Cancel focused first).
3. A failed `enableMfa` is now reported on the security tab. The legacy
   dialog rendered `setupError` only inside the wizard, which had not opened,
   so a failed start showed nothing (baseline test proves it).
4. Overlay click no longer closes either dialog (Escape and the named close
   control do); the change-password dialog cannot be closed while the
   request is in flight.
5. Row "revoke" controls are named per session ("Revoke session: Firefox on
   Linux, 10.180.6.21"); the icon-only close controls are named.
6. The change-password confirmation mismatch is a field error (`role="alert"`,
   `aria-invalid`) rather than a coloured span; "Passwords do not match" is
   shown once.

Nothing else: no endpoint, method, payload, timing (2.2 s auto-close and 3 s
success banner kept) or `refreshUser` change.

## 6. Retirement

Whole-tree census after the rewrite: 0 JSX/JS consumers of any `pm-*` or
`cpw-*` class (the one hit is a comment in `CcureBadge.jsx`). `b14-prune.py`
removed the 125 `animations.css` rules whose every selector class is
`pm-*`/`cpw-*` and has no consumer. `dark-mode.css` is unchanged: its only
mention is a grouped hover rule shared with `.np-close`/`.hp-close`, which
the batch-12 prune also left because of the group — dead now, kept because
the rule is mixed; deferred. One `.pm-status-pill` rule stayed because the
census counts the comment mention — deferred, same reason.

## 7. Deferred

- The mixed `dark-mode.css` close-hover rule and `.pm-status-pill` (above).
- `@keyframes modalScaleIn` and `pulseAmber` now have no consumer (kept —
  keyframes are out of the prune's scope).
- The remaining Batch 15+ list is unchanged.
