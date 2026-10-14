# Checkpoint 3C — Batch 13 harness (admin + schedules)

`capture-batch13.mjs` is generated from `capture-batch12.mjs` by
`b13-parts.py`; `contrast-batch13.mjs` from `contrast-batch12.mjs` by
`b13-contrast-parts.py`; `diff-batch13.mjs` extends `diff-batch12.mjs`. All in
the session scratchpad. The generator asserts every earlier instrument
property after patching (frozen clock, two-byte `\s`, `qsaSelf`, ARIA census,
per-route user override, multi-step prepare with settle, refusal of every
non-GET, `expectSelector`).

## 1. Instrument changes (validated on the pre-migration build before Phase C)

| #   | Change                                                                                                                                                                                                                                                    | Why                                                                                                                               | Validated by                                                                      |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| 1   | 22 states across `/admin/users`, `/scan-schedules`, `/admin/organizations`, `/admin/audit-logs`; two personas (`ORG_ADMIN13` with users:create/update/delete, `VIEWER13` with users:read only); nine opened dialogs                                       | the subject is admin writes behind dialogs and confirmations                                                                      | every dialog state `expect`s its own title; personas `expect`/`reject` gated text |
| 2   | Stubs for the batch's reads: `/admin/users/`, `/admin/users/pending`, `/admin/roles/`, `/scan-schedules` (+`credentials`, `timezones`, `{id}/runs`); the `/admin/organizations/` fixture is a superset of the shell's (same names, plus slug/plan/limits) | pages settle on data with the fields they read                                                                                    | pre census: 4 user rows, 2 schedules, 2 runs, 2 orgs                              |
| 3   | New censuses: `dialogs` (role\|name\|aria-modal\|describedby\|tabindex), `passwordFields` (name\|autocomplete\|value set?), `textInputsNamedPassword`, `formControls` (tag:type:name\|required\|disabled for every control inside a dialog or form)       | a password control downgraded to `type=text`, a dialog losing `aria-modal`, or a field losing its label must be a **named** delta | sensitivity (§3)                                                                  |
| 4   | Selector list gains the legacy admin/form/confirm classes and the migrated `um-`/`ss-`/`of-`/`ald-` families                                                                                                                                              | computed-style deltas are named by selector                                                                                       | style injection named `.confirm-dialog` (pre) / `.um-pending` (post)              |
| 5   | State guards learn this batch's vocabulary: "Unable to load users" joins the error regex; "Nightly DMZ" joins the populated-row regex                                                                                                                     | both **add** ways to fail; neither relaxes a guard                                                                                | `usersError` refused before the change, captured after                            |
| 6   | `SET_INPUT13` targets the form's scan-kind select by its exact option set (`network,credentialed`), not "any select with a credentialed option"                                                                                                           | the first attempt hit the filter select, whose value change produces no markup change, and the "changed nothing" guard refused it | `schedNewCredentialed` `expect /Select a stored credential/`                      |

Row-button matchers were simplified (`/edit/i`, `/reset password/i`) after the
anchored form, which assumed the accessible name was the visible text alone,
found no control — the concatenated name/title/text the driver matches on is
not anchorable.

## 2. State table — 22 states × 2 themes = 44 captures

| State                       | Persona    | Prepare                          | Proves                                                      |
| --------------------------- | ---------- | -------------------------------- | ----------------------------------------------------------- |
| `usersList`                 | superadmin | –                                | 4 rows, org filter, Create/Deleted users                    |
| `usersOrgAdmin`             | org_admin  | –                                | `expect` own-org note; `reject /All Organizations/`         |
| `usersViewer`               | viewer     | –                                | `expect /Read only/`; `reject /Create user\|Deleted users/` |
| `usersEmpty` / `usersError` | superadmin | –                                | empty / "Unable to load users"                              |
| `usersPending`              | superadmin | –                                | approval queue with a flagged domain                        |
| `usersCreateOpen`           | superadmin | Create user                      | `/Create new user/`; password control census                |
| `usersEditOpen`             | superadmin | row Edit                         | `/Edit alice/`                                              |
| `usersResetPwOpen`          | superadmin | row Reset password               | `/Reset Password for alice/`                                |
| `usersResetMfaConfirm`      | superadmin | row Reset MFA                    | `/Reset MFA for alice/` — never confirmed                   |
| `usersDeactivateConfirm`    | superadmin | row Deactivate                   | `/Deactivate user/` — never confirmed                       |
| `usersDeleteConfirm`        | superadmin | row Delete                       | `/Move alice to Deleted Users/` — never confirmed           |
| `schedList` / `schedEmpty`  | superadmin | –                                | 2 schedules / empty                                         |
| `schedNew`                  | superadmin | New schedule                     | `/Targets \(one per line/`                                  |
| `schedNewCredentialed`      | superadmin | New schedule → kind=credentialed | `/Select a stored credential/`; no password field           |
| `schedEdit`                 | superadmin | row Edit                         | `/The kind cannot be changed/`                              |
| `schedHistory`              | superadmin | row History                      | `/Execution history/`                                       |
| `schedDeleteConfirm`        | superadmin | row Delete                       | `/Delete "Nightly DMZ"/` — never confirmed                  |
| `orgCreateOpen`             | superadmin | + New Organization               | `/Initial Organization Admin/`                              |
| `orgEditOpen`               | superadmin | row Edit                         | `/Edit organization/`                                       |
| `auditDetailOpen`           | superadmin | row click                        | `/Audit log details/`                                       |

**No state drives `Run now`, `Enable`/`Disable`, a submit, or a confirm
control.** The stub table refuses every non-GET regardless; the request log
proves nothing but `/auth/refresh` was ever posted.

## 3. Gates

| Gate                                     | Pre build                                                                                                                                                                                                                                                                    | Final build (`ccure-frontend:ux4g-b13`)                                                                                                                                                         |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Determinism                              | `b13-pre-a/b/c` byte-identical (×3)                                                                                                                                                                                                                                          | `b13-post-c/d` byte-identical (and `a/b` on the previous iteration)                                                                                                                             |
| Sensitivity                              | 5/5 named: button rename → `buttonNames`; `type=password`→`text` → `passwordFields`/`textInputsNamedPassword`/`formControls`; `aria-modal` removed → `dialogs`; inline background → `styles .confirm-dialog` + `inlineStyled`; header "Next run"→"Next fire" → `headerTexts` | 5/5 named: button rename; label removed → `unlabelledControls`/`controlNames`; `type=text` password → `passwordFields`; inline background → `styles .um-pending`; header rename → `headerTexts` |
| Refusal guard                            | renaming the _targeted_ "Create user" made `usersCreateOpen` refuse ("found no control") rather than capture the wrong state                                                                                                                                                 | –                                                                                                                                                                                               |
| Unchanged control states under injection | `orgCreateOpen`, `orgEditOpen`, `auditDetailOpen`, `schedEmpty` identical                                                                                                                                                                                                    | same four identical                                                                                                                                                                             |
| No writes                                | 706 requests: 662 GET, 44 POST all `/auth/refresh`                                                                                                                                                                                                                           | 700: 656 GET, 44 POST all `/auth/refresh`                                                                                                                                                       |
| Off-origin                               | 0                                                                                                                                                                                                                                                                            | 0                                                                                                                                                                                               |
| GET census                               | identical pre/post for every page read; `/notifications/stream` 78 vs 72 is the shell's SSE retry cadence (refused stream, re-tried on a timer)                                                                                                                              |                                                                                                                                                                                                 |
| Coverage                                 | 44/44                                                                                                                                                                                                                                                                        | 44/44                                                                                                                                                                                           |
| Contrast (1,906 → 1,977 pairs)           | 147 sub-AA                                                                                                                                                                                                                                                                   | **0** sub-AA (one interim failure — a bare `<a>` in the run history at 2.11:1 dark — fixed with the link token before the final build)                                                          |

## 4. Existing-page regression (pre 3331 vs post 3333, every runner serial)

| Suite                                         | States | Result    |
| --------------------------------------------- | ------ | --------- |
| auth                                          | 5      | IDENTICAL |
| arch                                          | 2      | IDENTICAL |
| b5 (admin lists incl. `/admin/organizations`) | 8      | IDENTICAL |
| b6 web-scanning                               | 8      | IDENTICAL |
| b7                                            | 4      | IDENTICAL |
| b8 ScanDetail                                 | 10     | IDENTICAL |
| b9                                            | 16     | IDENTICAL |
| b10 (incl. `/admin/audit-logs` list states)   | 38     | IDENTICAL |
| b11                                           | 34     | IDENTICAL |
| b12 shell                                     | 26     | IDENTICAL |

151 states, zero deltas: the migrated children render only inside dialogs
that none of the earlier states open, and the retired components had no
consumer left to change.
