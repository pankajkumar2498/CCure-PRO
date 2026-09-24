# Phase 7 — The master API → UI matrix

Measured 23 Sep 2026 against the running deployment. This phase adds no
feature: it sweeps every router the application serves, asks which operations
the frontend reaches, and classifies the ones it does not.

**206 of 237 operations are reached.** Every surface Phases 1–6 covered is at
100%.

## How it was measured, and how to repeat it

Two scripts, because the route table lives inside the API container and the
frontend does not:

    docker cp scripts/audit/api_surface_inventory.py ccure-api:/tmp/i.py
    docker exec -w /app ccure-api python /tmp/i.py > /tmp/routes.json
    python3 scripts/audit/api_ui_matrix.py --routes /tmp/routes.json

`/openapi.json` was not an option: this deployment answers it 404, and even
where it is enabled it says nothing about which permission atom a route
demands, which is half of what a matrix like this is for. The inventory
therefore imports the app and reads `app.routes` directly, recovering the atom
from **the closure of `require_permission`'s inner `_guard`** — its
`resource` and `action` live in `__code__.co_freevars`, and reading the
dependency's `__name__` alone gives `_guard` for every guarded route in the
product.

`require_role`'s inner function is _also_ called `_guard`, so the two are told
apart by which free variables they carry (`allowed_set` versus
`resource`/`action`) and never by the name.

Four rules in the matcher, each of which a simpler version got wrong:

- **Match paths, not words.** Grepping for `summary` or `assets` matches dozens
  of unrelated files and reports reach the operator does not have.
- **Resolve each module's own path constants**, because nearly every API module
  is `const BASE = "/scan-policies"` and then `` `${BASE}/settings` ``.
- **Ignore `__tests__`.** A path that appears only in a test is asserted about,
  not offered to anybody.
- **Collapse the trailing-slash twins**, which FastAPI registers separately
  where a router declares both.

### The measurement's own false negatives

Three, all found by hand-checking results that looked wrong, and all fixed
before any number here was trusted. They are recorded because a measurement's
false negatives are indistinguishable from the gap it is looking for:

| Shape                                                         | Reported as unreached                    |
| ------------------------------------------------------------- | ---------------------------------------- |
| `` `${BASE}/findings/${encodeURIComponent(id)}/history` ``    | 6 Remediation + 7 Scan Policy operations |
| `` `${prefix}/notifications/stream` `` — begins with the hole | both SSE endpoints                       |
| a template literal nesting another across a newline           | `/compliance/frameworks/{}/controls`     |

The first version of the matcher reported **182/237**. The corrected one
reports 206. Every one of the 24 was a tool defect, not a product gap.

## The matrix

| Tag                        | Reached | Total |     |
| -------------------------- | ------: | ----: | --- |
| Compliance                 |      30 |    47 |     |
| Authentication             |      17 |    17 | ✓   |
| Dashboard                  |      17 |    17 | ✓   |
| Assets                     |      15 |    16 |     |
| User Management            |      13 |    13 | ✓   |
| Remediation                |      12 |    12 | ✓   |
| Web Scans                  |      12 |    12 | ✓   |
| Scan Policies              |      11 |    11 | ✓   |
| Scan History               |      10 |    10 | ✓   |
| Scan Schedules             |      10 |    10 | ✓   |
| User Profile & Preferences |       8 |     8 | ✓   |
| Organization Management    |       5 |     8 |     |
| Credentials                |       7 |     7 | ✓   |
| Notifications              |       7 |     7 | ✓   |
| Admin: Email Domains       |       6 |     6 | ✓   |
| Findings                   |       5 |     5 | ✓   |
| Phase-Selective Scans      |       4 |     5 |     |
| Audit Logs                 |       4 |     4 | ✓   |
| Configuration Audit        |       4 |     4 | ✓   |
| Reports                    |       3 |     3 | ✓   |
| Network Topology           |       2 |     2 | ✓   |
| RBAC Administration        |       2 |     2 | ✓   |
| Credentialed Scans         |       1 |     1 | ✓   |
| Health                     |       1 |     1 | ✓   |
| Traditional Scans          |       0 |     4 |     |
| Admin NVD Catalog          |       0 |     2 |     |
| Documentation              |       0 |     2 |     |
| Progress                   |       0 |     1 |     |

### Phases 1–6, verified

| Phase | Surface                         | Result  |
| ----- | ------------------------------- | ------- |
| 1     | Credentialed Scans              | 1/1 ✓   |
| 2     | Reports                         | 3/3 ✓   |
| 3     | Scan History (incl. comparison) | 10/10 ✓ |
| 4     | Scan Policies                   | 11/11 ✓ |
| 5     | Remediation                     | 12/12 ✓ |
| 6     | Configuration Audit             | 4/4 ✓   |

## The 31 unreached, classified

### Correct by design — 10 operations

**Ten `/compliance/reports/*` endpoints for parked frameworks.** Eleven of the
thirteen catalogues are parked; `require_active_framework()` answers **403**
for them, so a UI offering them could only ever produce an error. Measured
live: `GET /compliance/reports/nis2` → **403**.

### Superseded or diagnostic — 8 operations

| Operations                                                        | Why                                                                                                                                                                                                                                      |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /scan/host`, `/scan/range`, `/scan/subnet`, `/scan/subnets` | `traditional_scans.py` says in its own header that it is "backward-compatible". The UI posts to `/scan/host-discovery`, which auto-chains the phases.                                                                                    |
| `POST /scan/phases`                                               | The explicit phase-selector, superseded by the same auto-chaining path.                                                                                                                                                                  |
| `GET /scan/progress/{id}`                                         | The HTTP form of what the progress WebSocket serves. Worth knowing it exists: it is the natural fallback for a socket that never connects, which is the failure CLAUDE.md records as having ended a scan view at a 600 s client timeout. |
| `GET /assets/debug-reconcile`                                     | A diagnostic.                                                                                                                                                                                                                            |
| `GET /api/pipeline-modes`, `GET /api/workflow-example`            | Self-documentation, and the only two unauthenticated routes outside the auth flow and the health root.                                                                                                                                   |

### Broken, so nothing could reach them — 2 operations

**`GET /api/v1/admin/nvd-sync-status` and `POST /api/v1/admin/sync-nvd` refuse
every caller, including a superadmin.** Measured live: **403**, with
`Admin privileges required to manage NVD catalog sync.`

`admin_nvd._verify_admin` reads

    is_admin = getattr(user, "is_superadmin", False) or getattr(user, "role", "") in ("superadmin", "org_admin")

`User` has no `is_superadmin` attribute, and `user.role` is a `Role` **object**,
not a string — everywhere else in the codebase the idiom is
`getattr(getattr(user, "role", None), "name", "")`. So both operands are
always false and the guard can never pass.

It fails **closed**, so this is not an exposure. It is a feature nobody can
use, and the reason no UI reaches it is that there is nothing to reach.

**Not fixed here, deliberately.** The correct guard widens access from "nobody"
to "org_admin and superadmin" — which is what the code intended and never
achieved — and that is an authorisation decision on a live deployment rather
than a sweep's business. It is a two-line change when you want it.

### Real gaps — 11 operations

Ranked by what an operator loses.

| #   | Operation                                          | Permission                             | What is missing                                                                                                                                                                                                                                                                                                       |
| --- | -------------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `GET/POST/PATCH/DELETE /compliance/schedules` (4)  | `compliance:read` / `manage_schedules` | **Recurring compliance scans cannot be created, listed, edited or deleted from the UI at all.** `compliance.run_scheduled_scans` runs on beat every 60 s, so the machinery is live and there is no way to drive it. CLAUDE.md records these CRUD endpoints as having been added precisely because they did not exist. |
| 2   | `GET /compliance/evidence/{id}/download`           | `compliance:read`                      | Evidence can be uploaded, listed and deleted — all three are wired — but **not retrieved**. An attestation's supporting document is write-only, which for an audit artefact is the one thing it must not be.                                                                                                          |
| 3   | `PATCH /compliance/exceptions/{id}`                | `compliance:approve_exception`         | `ExceptionsPanel` lists exceptions; nothing approves one. A permission atom that exists solely for this action is exercised by no screen.                                                                                                                                                                             |
| 4   | `GET /compliance/reports/cis_v8_1`                 | `compliance:export_report`             | **CIS Controls v8.1 is one of the three _active_ frameworks** (`DEFAULT_ACTIVE_FRAMEWORK_IDS`), and it is where every benchmark finding rolls up. Measured live: **200**, served, and unreachable. It sits in the same list as the ten parked ones and is not the same case.                                          |
| 5   | `GET/PUT /admin/organizations/{id}/scan-scope` (2) | `organizations:read` / superadmin      | The CIDR blocks an organisation may scan — the control that bounds every scan target. Editable only by API.                                                                                                                                                                                                           |
| 6   | `POST /admin/organizations/{id}/restore`           | superadmin                             | Archiving is wired (`DELETE /admin/organizations/{id}`); restoring is not. A one-way door in the UI over an operation the API makes reversible.                                                                                                                                                                       |

## Two things the sweep found that are not coverage

### Forty authenticated routes carry no permission atom

Most are legitimately self-scoped — `/auth/me`, the eight `/user/*` routes, the
seven `/notifications/*` routes: a user acting on their own records, where an
atom would add nothing. The thirteen `/web-scans` routes are authenticated-only
by design.

Three are administrative writes, and **all three are guarded, by an inline role
check in the handler body rather than by a dependency**:

- `PUT /admin/organizations/{id}/scan-scope` — refuses a non-superadmin, and
  its docstring explains why it cannot use `organizations:update`: org_admin
  holds that atom for its own organisation, so the subject of a restriction
  could widen it.
- `POST /admin/organizations/{id}/restore` — same shape.
- The two NVD routes — same shape, and broken (above).

This is the false-positive class CLAUDE.md already records for the rate-limit
inventory: _check the dependency before believing the finding_. The atom-less
list is a list of routes whose authorisation is not expressible as an atom, not
a list of unguarded routes. Noted here so the next reader of the matrix does
not have to re-derive it.

Worth one observation: on `scan-scope` the **read** is guarded by a dependency
(`organizations:read`) and the **write** by a check inside the body. Both hold,
but a reader scanning signatures sees a guarded read and an unguarded write.

### The unauthenticated surface is exactly what it should be

Fifteen routes, and no surprises: the twelve `/auth/*` routes that must be
reachable before a session exists, the two documentation endpoints, and `/` —
which is this API's health endpoint, and which CLAUDE.md records as the reason
the rate-limiter's exempt list must match exactly rather than by prefix.

## Limitations of this measurement

- **It measures reach, not rendering.** An operation counts as reached when a
  frontend source file names its path. Phase 1's `api_ui_coverage.py` is the
  field-level tool and answers the other question — whether what came back is
  shown — for one payload at a time.
- **It does not know whether a call site is live.** A path named in an API
  module that no page imports counts as reached. Spot checks found none, but
  the tool cannot prove it.
- **Query and body parameters are out of scope.** Phase 2 found `?fmt=XLSX`
  silently unfiltered because axios serialised an array as `severity[]=`; a
  path-level sweep cannot see that class of defect.
- **Path truncation at an unclosable interpolation** is a deliberate
  simplification for nested template literals. Resolving them properly needs a
  JS tokeniser, which is more machinery than a one-off audit earns.

## Recommended order, if this is picked up

1. **Compliance schedules** (4 operations) — a live beat task with no way to
   drive it is the largest single hole in the product.
2. **Evidence download** (1) — small, and write-only audit evidence is a
   compliance defect rather than an inconvenience.
3. **CIS v8.1 report** (1) — likely a one-line addition to the report picker in
   `ComplianceWorkspace`, and it is an active framework.
4. **Exception approval** (1) — a permission atom with no screen behind it.
5. **Org scan scope** (2) and **restore** (1) — superadmin operations, low
   frequency, but scan scope bounds every scan the product runs.
6. **The NVD guard** — decide who should hold it, then fix the comparison.
