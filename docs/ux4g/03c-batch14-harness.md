# Checkpoint 3C — Batch 14 harness (account dialogs)

`capture-batch14.mjs` is generated from `capture-batch13.mjs` by
`b14-parts.py`; `contrast-batch14.mjs` from `contrast-batch13.mjs`;
`diff-batch14.mjs` extends `diff-batch13.mjs`. The generator asserts every
earlier instrument property after patching.

## 1. Instrument changes (validated on the pre build before Phase C)

| #   | Change                                                                                                                                                                                                                              | Why                                                                                      | Validated by                                                                                          |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| 1   | 10 states, all reached from `/scan` through the shell's account menu → "My Account" (two settled clicks; the second targets `role="menuitem"`), then dialog-scoped clicks (`DLG_CLICK` searches the topmost `[role="dialog"]` only) | the dialog is reachable only through the shell; a prepare step must never reach the page | every state `expect`s its own text; `reject /Sign Out/` proves the menu closed                        |
| 2   | Stubs: `GET /user/profile`, `GET /user/sessions` (+ `profileFails`, `sessionsFail`); MFA-enabled is a persona (`user.mfa_enabled` from `/auth/me`), not a stub                                                                      | the pages read exactly these                                                             | pre census: 3 sessions, one current                                                                   |
| 3   | **Real focus-trap probe** (`trapProbe`): twelve genuine Tab presses via `Input.dispatchKeyEvent`, counting landings inside vs outside the topmost dialog                                                                            | a synthetic keydown cannot move focus; presence of a handler is not a trap               | pre: 0/12 inside (first Tab reached the skip link); post: 12/0; injection (trap disabled) 4/8 — named |
| 4   | Selectors for `pm-*`/`cpw-*` (legacy) and `ac-*`/`acp-*`/`.cc-tab` (migrated)                                                                                                                                                       | style deltas named by selector                                                           | `.pm-modal` / `.ac-modal` background injections named                                                 |

Comparator: `trap` joins the named summary.

## 2. States — 10 × 2 themes = 20 captures

| State                  | Persona                  | Prepare                                  | Proves                                                                                   |
| ---------------------- | ------------------------ | ---------------------------------------- | ---------------------------------------------------------------------------------------- |
| `profileOpen`          | superadmin               | menu → My Account                        | email shown; `reject /Sign Out/`; **trap probe**                                         |
| `profileEditing`       | superadmin               | + Edit Profile                           | `/Save Changes/`                                                                         |
| `profileSecurity`      | superadmin               | + Security tab                           | `/Chrome on Windows/`; MFA "Disabled"; **trap probe**                                    |
| `profileMfaEnabled`    | superadmin `mfa_enabled` | + Security                               | `/Enabled/`, `reject /Set up MFA/`                                                       |
| `profileChangePw`      | superadmin               | + Security → Change Password             | `/Current Password/`; nested dialog; **trap probe**                                      |
| `profileRevokeOthers`  | superadmin               | + Security → Sign out all other sessions | pre: the click **is** the DELETE (refused 503); post: the confirmation — never confirmed |
| `profileError`         | superadmin               | `/user/profile` 500                      | `/Failed to load profile/`                                                               |
| `profileSessionsError` | superadmin               | `/user/sessions` 500                     | `/Failed to load sessions/`                                                              |
| `profileViewer`        | viewer                   | menu → My Account                        | persona variety                                                                          |
| `profileMobile`        | superadmin, 390×844      | menu → My Account                        | narrow viewport                                                                          |

MFA enrolment, confirmation, disable and password change are **never driven**
by the harness (each is a POST); they are covered by the 26 unit tests.

## 3. Gates

| Gate        | Pre (`ccure-frontend:ux4g-b13`)                                                                                                                                    | Post (`ccure-frontend:ux4g-b14`)                                                                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Determinism | `b14-pre-a/b` byte-identical                                                                                                                                       | `b14-post-a/b` byte-identical                                                                                                                                        |
| Sensitivity | 5/5 named: dialog name + `aria-modal` (dialogs), close name (buttonNames/unnamed), tab `aria-selected` (ariaStates), style (`.pm-modal`)                           | 5/5 named: `aria-modal` removed (dialogs), close label (buttonNames), `aria-selected` removed (ariaStates), **trap disabled** (trap 12/0 → 4/8), style (`.ac-modal`) |
| Writes      | 20 POST `/auth/refresh` + **2 DELETE `/api/user/sessions`** — the legacy "Sign out all other sessions" performs the revocation on click, refused by the stub table | 20 POST `/auth/refresh` only                                                                                                                                         |
| Off-origin  | 0                                                                                                                                                                  | 0                                                                                                                                                                    |
| CSP         | byte-identical                                                                                                                                                     |                                                                                                                                                                      |
| Contrast    | 50 sub-AA / 892                                                                                                                                                    | **0** / 902                                                                                                                                                          |
| Coverage    | 20/20                                                                                                                                                              | 20/20                                                                                                                                                                |

## 4. Existing-page regression (pre 3341 vs post 3343)

auth 5 · arch 2 · b5 8 · b6 8 · b7 4 · b8 10 · b9 16 · b10 38 · b11 34 ·
b12 (shell, incl. the account menu open) 26 · b13 (admin, every CcureModal /
CcureConfirmDialog state) 44 — **195 states, all IDENTICAL**. This is also
the runtime proof that the `useFocusTrap` nesting change leaves single-dialog
behaviour untouched.
