# Checkpoint 3C — Batch 13: admin completion and legacy primitive retirement

UserManagement (+UserForm, UserTable, RoleSelector), ScanSchedules,
OrganizationForm and AuditLogDetailsModal onto CCure primitives; the seven
legacy `components/common` primitives retired on a zero-consumer census.
Instrument changes and gate results are in `03c-batch13-harness.md`.

## 1. Files changed

| File                                                                                                     | Change                                                                                                                                                 | LOC before → after             | inline / colour literals |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ | ------------------------ |
| `src/pages/admin/UserManagement.jsx`                                                                     | head (data, RBAC, handlers, approval logic) verbatim; render tail on CcureButton/Input/Select/Pagination/Modal/PasswordField/Alert/Badge/ConfirmDialog | 1029 → 910                     | 19 → 0 / 12 → 0          |
| `src/components/admin/UserForm.jsx`                                                                      | CcureInput/CcureSelect/CcurePasswordField; RoleSelector folded in as a labelled CcureSelect                                                            | 254 → 250                      | 3 → 0                    |
| `src/components/admin/UserTable.jsx`                                                                     | CcureTable (caption, scoped headers, row header), CcureBadge status, named action buttons                                                              | 230 → 238                      | 2 → 0                    |
| `src/pages/scan/ScanSchedules.jsx`                                                                       | full render on primitives; API calls, arguments and handlers unchanged; toast API corrected (§5)                                                       | 776 → 743                      | 67 → 0 / 33 → 0          |
| `src/components/admin/OrganizationForm.jsx`                                                              | CcureInput/CcureSelect/CcurePasswordField in a fieldset; same payload                                                                                  | 326 → 295                      | 4 → 0                    |
| `src/components/admin/AuditLogDetailsModal.jsx`                                                          | CcureModal + captioned CcureTable + CcureSeverityBadge; parsers verbatim                                                                               | 362 → 240                      | 23 → 0 / 5 → 0           |
| `src/styles/user-management.css`, `scan-schedules.css`, `organization-form.css`, `audit-log-details.css` | **new**, layout-only, tokens only                                                                                                                      | 218 / 108 / 59 / 91            | 0                        |
| `src/styles/scan.css`                                                                                    | census-backed prune of 6 rules the retired components alone rendered                                                                                   | 3441 → 3405                    |                          |
| `src/components/common/{Button,ConfirmDialog,FormField,RoleSelector,EmptyState,Loader,Skeleton}.jsx`     | **retired** (§4)                                                                                                                                       | 43+103+19+30+17+8+40 = 260 → 0 |                          |
| `src/__tests__/pages/admin/UserManagement.test.jsx`                                                      | **new**, 29 tests                                                                                                                                      |                                |                          |
| `src/__tests__/pages/scan/ScanSchedules.test.jsx`                                                        | **new**, 18 tests (12 regression + 6 spec)                                                                                                             |                                |                          |
| `src/__tests__/components/admin/AdminChildren.test.jsx`                                                  | **new**, 11 tests (9 regression + 2 spec)                                                                                                              |                                |                          |

Not touched: ProfileModal, ChangePasswordModal, AMTIntegration, ScanHistory,
CredentialedResults, SecurityDashboard, NetworkMap, NewScan, Phase1/2/3,
ScanContext/ScanStepper/ExportPanel/ScanQuotaBar, ComplianceWorkspace,
CVELink, the Modal and Toast shims, `api/*`, backend, CSP, nginx. The
OrganizationManagement and AuditLogs pages are unedited: their children
changed underneath them and their own suites (24 + 27 tests) still pass.

## 2. Accessibility (22 states × 2 themes)

| Measure                                            | Pre   | Post                                               |
| -------------------------------------------------- | ----- | -------------------------------------------------- |
| Unlabelled controls                                | 80    | 0                                                  |
| Inline styles                                      | 882   | 88 (all the shell's `CcureProgress` widths)        |
| Tables with a caption / scoped headers             | 6 / 6 | 38 / 38                                            |
| Row headers per user table                         | 0     | 4 (the username cell)                              |
| Roles in chrome + page                             | 154   | 188                                                |
| ARIA state attributes                              | 348   | 390                                                |
| Live regions                                       | 134   | 168                                                |
| Dialogs with `aria-describedby`                    | 0     | 10 (every confirmation, the reset-password dialog) |
| Password fields with `autocomplete="new-password"` | 0 / 6 | 6 / 6                                              |
| Text inputs named "password"                       | 0     | 0                                                  |
| Contrast failures                                  | 147   | 0                                                  |

Specifics: every row action names its subject ("Delete alice", "Run Nightly
DMZ now"); Role and Organization selects are associated with their labels
(they were `<label>`s with no `for`); "already taken" is a field error with
`role="alert"` and `aria-invalid`; confirmations open with focus on Cancel
(CcureConfirmDialog's documented rule); the search and organization filters
carry hidden labels; the audit dialog's changes table is captioned with the
field name as row header; the run-history scan link uses the link token
(the bare `<a>` was 2.11:1 in dark).

## 3. Behaviour and security confirmations

- **RBAC unchanged**: `can(user, "users", create|update|delete)`,
  `isSuperAdmin`, `isOrgAdmin` and `assignableRoles` are the same code. Tests
  run SUPERADMIN, ORG_ADMIN and VIEWER against the real `auth/permissions`:
  the viewer sees a read-only table with no create/deleted-users control; the
  org_admin gets no organization filter, no organization field, no
  superadmin role, and a created user filed under their own `org_id`; the
  superadmin gets all of it. Harness personas agree (`usersOrgAdmin`,
  `usersViewer`).
- **Confirmation-gated**: delete, deactivate/activate and MFA reset call the
  API only from the confirm control and never on cancel (tests); the harness
  opens all three and confirms none.
- **Self-protection**: the current user's row has no deactivate, delete or
  MFA-reset control (test).
- **Password handling**: the create-user password and the reset password
  reach `createUser` / `resetUserPassword` and nothing else — the test walks
  every attribute of every element and the visible text; the harness records
  `passwordFields` (type, autocomplete, value unset) and
  `textInputsNamedPassword = 0`. Both fields are `type=password` with
  `autocomplete="new-password"`. Same for OrganizationForm's
  `admin_password`.
- **ScanSchedules writes**: `createScanSchedule(form)`,
  `updateScanSchedule(id, form)`, `setScanScheduleEnabled(id, !enabled)`,
  `runScanScheduleNow(id)`, `deleteScanSchedule(id)` — same helpers, same
  arguments (tests assert the payload shapes). `Run now` is one explicit row
  button; the test proves it is never called on render, and the harness never
  drives it. Delete is confirmation-gated. No password field exists on the
  page (test + harness `passwordFields = []`).
- **No writes from the harness**: 44 POSTs per run, all `/auth/refresh`;
  no PUT/PATCH/DELETE; 0 off-origin requests.
- **CSP** byte-identical pre/post; no `prefers-color-scheme`, no `ux4g-*`
  class, no external asset in any new file.

## 4. Legacy retirement — zero-consumer proof

Repository-wide census after the migration (all of `src/`, tests included),
by import path and by bare name:

| Component       | Import consumers | Rendered classes with a remaining JSX consumer                                                                                                              |
| --------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Button`        | 0                | `.btn`, `.btn--primary/ghost/danger/secondary`, `.btn-spinner` — still written literally by other pages, **kept**; `.btn--info`, `.btn-label` — 0 consumers |
| `ConfirmDialog` | 0                | `.confirm-*` — ScanHistory's own copy still uses them, **kept**                                                                                             |
| `FormField`     | 0                | `.field` (29 consumers), `.field-label` (AssetDetail) **kept**; `.field-hint` 0                                                                             |
| `RoleSelector`  | 0                | `.role-selector-row` — 0                                                                                                                                    |
| `EmptyState`    | 0                | `.empty-state`, `-icon`, `-title` — other pages, **kept**; `.empty-state-desc` — 0                                                                          |
| `Loader`        | 0                | `.spinner` — 9 consumers, **kept**; `.loader-shell`, `.loader-label` — 0                                                                                    |
| `Skeleton`      | 0 (already dead) | `.skeleton-loader` — no CSS rule existed                                                                                                                    |

The seven files were removed (`git rm`); the post-removal import census is
empty. `b13-prune.py` then removed from `scan.css` exactly the rules whose
every selector class is in the retired set **and** has zero JSX consumers:
`.btn--info`, `.btn--info:hover`, `.role-selector-row`, `.loader-shell`,
`.loader-label`, `.empty-state-desc` (6 rules, 36 lines). `forms.css` and
`animations.css` had no such rule and are byte-identical to before the
batch. Every other legacy class the components used stays because something
else still writes it. The regression suites (151 states) are IDENTICAL after
the removal, which is the runtime proof.

## 5. Intentional behaviour changes

1. **ScanSchedules feedback and refresh now happen.** The page destructured
   `{ addToast, removeToast }` from `useToasts()`, which exports
   `{ push, dismiss }`; every success and failure path threw `TypeError`
   _after_ the API call. Measured on the baseline (six spec tests, five
   unhandled rejections): save reported "Could not save the schedule." on a
   successful create and left the form open; enable/disable, run-now and
   delete performed the write and never reloaded the list. The page now uses
   the toaster's real API. The writes themselves are unchanged; what changes
   is that the form closes, the list reloads and the message the code always
   composed is shown. Recorded as the previously-deferred "ScanSchedules
   toast" debt, closed here because the page cannot be put on a feedback
   primitive without deciding which API it calls.
2. Row action buttons carry their subject in the accessible name; visible
   labels are unchanged ("Edit", "Delete", "Run now"). The "🔑 Reset" button
   reads "Reset password" visibly now.
3. Confirmations open with focus on **Cancel** rather than the destructive
   control, and are not dismissed by an overlay click (CcureConfirmDialog).
4. The create/edit and reset-password dialogs cannot be closed while a write
   is in flight (`onClose` withheld while `busy`).
5. Pagination reads "Previous"/"Next" (CcurePagination) rather than
   "Prev"/"Next"; the page status is a polite live region.
6. UserForm no longer repeats "This username is already taken." under the
   password field (a copy-paste duplicate); it appears once, under Username.
7. `EmptyState` in ScanSchedules was passed `message=` but only ever read
   `description=`, so "Try adjusting your filters." showed instead of the
   page's own text; the CcureEmptyState now shows the intended sentence.
8. OrganizationForm's password hint text is new ("At least 6 characters…");
   the 6-character rule is the form's existing validation, stated rather
   than silent.

Nothing else: no API path, method, payload, permission check, storage or
routing change.

## 6. Deferred (unchanged from the running list)

- `scan.css`, `forms.css`, `animations.css` global retirement — out of
  scope; only the six proven-orphan rules left.
- `.btn`, `.spinner`, `.field`, `.empty-state`, `.confirm-*` legacy classes
  still written literally by unmigrated pages (ScanHistory, ComplianceWorkspace,
  the Phase pages, AssetDetail) — retire with those pages.
- The Modal and Toast shims — kept by decision; retire when their last
  consumer migrates.
- ProfileModal / ChangePasswordModal, AMTIntegration and everything on the
  batch-14+ list.
