# API → UI coverage programme — closeout

**Status: complete. This document is the baseline for all future work.**

---

## 1. Executive summary

**Objective.** Ensure that every operator-relevant API capability implemented in
the CCure Audit Platform has an appropriate UI representation — and that
anything deliberately left backend-only is recorded as a decision rather than
discovered later as an omission.

**Phases completed.** Seven, 21–23 Sep 2026.

| Phase | Surface                     | Commit    |
| ----- | --------------------------- | --------- |
| 1     | Credentialed scan results   | `042229e` |
| 2     | Reports and export          | `5ae993f` |
| 3     | Scan comparison             | `1f7892e` |
| 4     | Scan policies               | `675f0d1` |
| 5     | Remediation and SLA         | `c8587d3` |
| 6     | Configuration audit         | `726702c` |
| 7     | Master matrix (measurement) | `05ab46b` |

(`978d60e`, naming the authentication services a credentialed scan probed, is
the backend work Phase 1 was built on.)

**Final programme commit: `05ab46b`.**

**Final coverage: 206 of 237 operations reached.** Every Phase 1–6 surface is at
100%.

Each phase audited its surface against the **running** API before any UI was
written, drove every operation including the refusals, and recorded what was
left backend-only with the reason.

---

## 2. Coverage

### Phase surfaces

| Surface             | Operations | Coverage |
| ------------------- | ---------- | -------- |
| Credentialed Scans  | 1/1        | 100%     |
| Reports             | 3/3        | 100%     |
| Scan History        | 10/10      | 100%     |
| Scan Policies       | 11/11      | 100%     |
| Remediation         | 12/12      | 100%     |
| Configuration Audit | 4/4        | 100%     |

### Whole application, by tag

| Tag                        | Reached |   Total |     |
| -------------------------- | ------: | ------: | --- |
| Compliance                 |      30 |      47 |     |
| Authentication             |      17 |      17 | ✓   |
| Dashboard                  |      17 |      17 | ✓   |
| Assets                     |      15 |      16 |     |
| User Management            |      13 |      13 | ✓   |
| Remediation                |      12 |      12 | ✓   |
| Web Scans                  |      12 |      12 | ✓   |
| Scan Policies              |      11 |      11 | ✓   |
| Scan History               |      10 |      10 | ✓   |
| Scan Schedules             |      10 |      10 | ✓   |
| User Profile & Preferences |       8 |       8 | ✓   |
| Organization Management    |       5 |       8 |     |
| Credentials                |       7 |       7 | ✓   |
| Notifications              |       7 |       7 | ✓   |
| Admin: Email Domains       |       6 |       6 | ✓   |
| Findings                   |       5 |       5 | ✓   |
| Phase-Selective Scans      |       4 |       5 |     |
| Audit Logs                 |       4 |       4 | ✓   |
| Configuration Audit        |       4 |       4 | ✓   |
| Reports                    |       3 |       3 | ✓   |
| Network Topology           |       2 |       2 | ✓   |
| RBAC Administration        |       2 |       2 | ✓   |
| Credentialed Scans         |       1 |       1 | ✓   |
| Health                     |       1 |       1 | ✓   |
| Traditional Scans          |       0 |       4 |     |
| Admin NVD Catalog          |       0 |       2 |     |
| Documentation              |       0 |       2 |     |
| Progress                   |       0 |       1 |     |
| **Total**                  | **206** | **237** |     |

---

## 3. Classification

**These four categories must not be collapsed into one "missing UI" bucket.**
They call for four different actions: none, none, a backend fix, and UI work.

| Class                             | Count | Meaning                                                                         |
| --------------------------------- | ----: | ------------------------------------------------------------------------------- |
| **A — Reached**                   |   206 | The operation has a valid UI path.                                              |
| **B — Correctly unreached**       |    18 | Intentionally no UI: parked, superseded, diagnostic, or genuinely backend-only. |
| **C — Broken backend capability** |     2 | The endpoint exists but is unreachable because its authorisation is defective.  |
| **D — Genuine product gap**       |    11 | The capability is active and usable; there is no UI path.                       |

### B — Correctly unreached (18)

**Parked framework reports (10).** Ten of the thirteen compliance catalogues
are parked. `require_active_framework()` answers **403** for them, so a UI
offering them could only ever produce an error. Verified at closeout:
`GET /compliance/reports/nis2` → **403**.

**Superseded or diagnostic (8).**

| Operations                                                        | Why                                                                                                                                                     |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /scan/host`, `/scan/range`, `/scan/subnet`, `/scan/subnets` | `traditional_scans.py` states in its own header that it is "backward-compatible". The UI posts to `/scan/host-discovery`, which auto-chains the phases. |
| `POST /scan/phases`                                               | The explicit phase-selector, superseded by the same auto-chaining path.                                                                                 |
| `GET /scan/progress/{id}`                                         | The HTTP form of what the progress WebSocket serves. Worth knowing it exists: it is the natural fallback for a socket that never connects.              |
| `GET /assets/debug-reconcile`                                     | A diagnostic.                                                                                                                                           |
| `GET /api/pipeline-modes`, `GET /api/workflow-example`            | Self-documentation, and the only two unauthenticated routes outside the auth flow and the health root.                                                  |

---

## 4. Genuine product gaps — the 11

Backlog items. **None was implemented; this programme closed at measurement.**

### Priority group 1 — Compliance schedules (4 operations)

| Method | Path                         | Permission                    |
| ------ | ---------------------------- | ----------------------------- |
| GET    | `/compliance/schedules`      | `compliance:read`             |
| POST   | `/compliance/schedules`      | `compliance:manage_schedules` |
| PATCH  | `/compliance/schedules/{id}` | `compliance:manage_schedules` |
| DELETE | `/compliance/schedules/{id}` | `compliance:manage_schedules` |

**Recurring compliance scans cannot be created, listed, edited or deleted from
the UI at all.** `compliance.run_scheduled_scans` runs on beat **every 60
seconds**, so the machinery is live and there is no way to drive it. The
frontend contains zero references to `/compliance/schedules`.

**This is the largest known UI coverage gap in the product.**

### Priority group 2 — Evidence download (1 operation)

| Method | Path                                 | Permission        |
| ------ | ------------------------------------ | ----------------- |
| GET    | `/compliance/evidence/{id}/download` | `compliance:read` |

An **incomplete evidence workflow**. Upload, list and delete are all wired:

- `POST /compliance/controls/{id}/evidence` — wired
- `GET  /compliance/controls/{id}/evidence` — wired
- `DELETE /compliance/evidence/{id}` — wired
- `GET  /compliance/evidence/{id}/download` — **not wired**

An attestation's supporting document is write-only, which for an audit artefact
is the one thing it must not be.

### Priority group 3 — CIS Controls v8.1 report (1 operation)

| Method | Path                           | Permission                 |
| ------ | ------------------------------ | -------------------------- |
| GET    | `/compliance/reports/cis_v8_1` | `compliance:export_report` |

**This must not be classified with the ten parked framework reports.** Verified
at closeout:

- `cfw_cis_v8_1` is present in `DEFAULT_ACTIVE_FRAMEWORK_IDS`
  (`Backend/core/compliance_frameworks.py`), activated by Phase 4 because it is
  the framework hardening-benchmark findings roll up into.
- The framework row exists: `cfw_cis_v8_1` — _CIS Critical Security Controls v8.1_.
- The endpoint answers **200**, while the parked `nis2` answers **403**.

It is an **active framework whose report has no UI path**. A genuine gap.

### Additional gaps (5 operations)

| #   | Method | Path                                   | Permission                     | Note                                                                                                                                 |
| --- | ------ | -------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| 7   | PATCH  | `/compliance/exceptions/{id}`          | `compliance:approve_exception` | `ExceptionsPanel` lists exceptions; nothing approves one. A permission atom with no screen behind it.                                |
| 8   | GET    | `/admin/organizations/{id}/scan-scope` | `organizations:read`           | Organisation scan-scope **read**.                                                                                                    |
| 9   | PUT    | `/admin/organizations/{id}/scan-scope` | superadmin (inline check)      | Organisation scan-scope **write** — the CIDR blocks that bound every scan target.                                                    |
| 10  | POST   | `/admin/organizations/{id}/restore`    | superadmin (inline check)      | Archiving is wired (`DELETE /admin/organizations/{id}`); restoring is not. A one-way door in the UI over a reversible API operation. |

Counting: 4 (schedules) + 1 (evidence download) + 1 (CIS report) + 1 (exception
approval) + 2 (scan-scope read and write) + 1 (org restore) = **11**.

---

## 5. Backend authorisation defect — recorded separately

**This is not a UI coverage gap and must not be tracked as one. It needs
explicit ownership and approval before any change.**

### The two endpoints

| Method | Path                            | Observed (superadmin) |
| ------ | ------------------------------- | --------------------- |
| GET    | `/api/v1/admin/nvd-sync-status` | **403**               |
| POST   | `/api/v1/admin/sync-nvd`        | **403** (same guard)  |

Verified at closeout: the GET returns 403 with
`Admin privileges required to manage NVD catalog sync.` The POST was **not**
called, because it starts a live NVD feed sync; both routes take
`Depends(_verify_admin)` (`Backend/routers/admin_nvd.py`, lines 60 and 107), so
the guard is identical.

### The defect

`admin_nvd._verify_admin` reads:

```python
is_admin = getattr(user, "is_superadmin", False) or getattr(user, "role", "") in (
    "superadmin",
    "org_admin",
)
```

- `User` has no `is_superadmin` attribute, so the left operand is always `False`.
- `user.role` is a **`Role` object**, not a string, so the membership test is
  always `False`. Everywhere else in the codebase the idiom is
  `getattr(getattr(user, "role", None), "name", "")`.

Both operands are always false, so the guard **can never pass**.

### Why it was not fixed here

It fails **closed**, so this is not an exposure — it is a capability nobody can
use, and the reason no UI reaches it is that there is nothing to reach.

The correct guard would widen access from _nobody_ to _org_admin and
superadmin_. That is what the code intended and never achieved, but it is an
**authorisation decision on a live deployment**, not a coverage programme's
business. It requires an owner who decides who should hold the ability to
trigger an outbound feed sync, and explicit approval.

---

## 6. Measurement methodology

The inventory is **reproducible**, not a maintained number. Re-run it rather
than trusting the figures in this document:

    docker cp scripts/audit/api_surface_inventory.py ccure-api:/tmp/i.py
    docker exec -w /app ccure-api python /tmp/i.py > /tmp/routes.json
    python3 scripts/audit/api_ui_matrix.py --routes /tmp/routes.json

### Route discovery

`/openapi.json` was **not** an option. This deployment answers it **404**, and
even where it is enabled it says nothing about which permission atom a route
demands — which is half of what the matrix is for.

`scripts/audit/api_surface_inventory.py` therefore runs **inside the API
container**, imports the application and reads `app.routes` directly.

### Permission extraction

`require_permission(resource, action)` returns a nested `_guard`; the two
strings live in its **closure**, reachable through `__code__.co_freevars` and
`__closure__`. Reading the dependency's `__name__` alone yields `_guard` for
every guarded route in the product, which is the same as not measuring it.

`require_role` **also** returns an inner function named `_guard`. The two are
therefore told apart by **which free variables they carry** — `allowed_set`
versus `resource`/`action` — and never by the function name.

Dependencies are walked transitively, because a route's auth can arrive through
a router-level dependency or through another dependency rather than through its
own signature.

### Matcher methodology

`scripts/audit/api_ui_matrix.py` matches routes against path literals in the
frontend. Four rules, each of which a simpler version got wrong:

- **Match paths, not words.** Grepping for `summary` or `assets` matches dozens
  of unrelated files and reports reach the operator does not have.
- **Resolve each module's own path constants**, because nearly every API module
  is `const BASE = "/scan-policies"` and then `` `${BASE}/settings` ``.
- **Ignore `__tests__`.** A path that appears only in a test is asserted about,
  not offered to anybody.
- **Collapse the trailing-slash twins**, which FastAPI registers separately
  where a router declares both.

### The template-literal defect, and its correction

**The first matcher reported `182/237`.** Hand-verification of results that
looked wrong found that **all 24 apparent differences were tool defects, not
product gaps.** Three shapes of template literal were being dropped:

| Shape                                                         | Wrongly reported as unreached            |
| ------------------------------------------------------------- | ---------------------------------------- |
| `` `${BASE}/findings/${encodeURIComponent(id)}/history` ``    | 6 Remediation + 7 Scan Policy operations |
| `` `${prefix}/notifications/stream` `` — begins with the hole | both SSE endpoints                       |
| a template literal nesting another across a newline           | `/compliance/frameworks/{}/controls`     |

Corrected, the measurement is **`206/237`**, reproduced from the clean tree at
closeout.

**Rule carried forward: a coverage inventory must never treat a false negative
from its own measurement tool as evidence of a product gap.** Future coverage
tooling must be tested against representative route and dependency shapes —
interpolated paths, leading interpolations, nested and multi-line literals,
closure-based guards — before its output is trusted. The failure mode is
silent: a tool's false negatives are indistinguishable from the gap it is
looking for.

### Permission-atom findings, and their false-positive mode

**40 authenticated routes carry no permission atom.** Most are legitimately
self-scoped — `/auth/me`, the eight `/user/*` routes, the seven
`/notifications/*` routes — where a user acts on their own records and an atom
would add nothing. The thirteen `/web-scans` routes are authenticated-only by
design.

Three are administrative writes, and **all three are guarded, by an inline role
check in the handler body rather than by a dependency**:

- `PUT /admin/organizations/{id}/scan-scope` — refuses a non-superadmin. Its
  docstring explains why it cannot use `organizations:update`: org_admin holds
  that atom for its own organisation, so the subject of a restriction could
  widen it.
- `POST /admin/organizations/{id}/restore` — same shape.
- The two NVD routes — same shape, and defective (§5).

**The atom-less list is a list of routes whose authorisation is not expressible
as an atom, not a list of unprotected routes. The dependency and the handler
body must be inspected before declaring a permission gap.** This is the same
false-positive class CLAUDE.md already records for the rate-limit inventory.

One observation worth carrying: on `scan-scope` the **read** is guarded by a
dependency and the **write** by a check inside the body. Both hold, but a
reader scanning signatures sees a guarded read and an unguarded write.

### Limitations

- **It measures reach, not rendering.** An operation counts as reached when a
  frontend source file names its path.
  `scripts/audit/api_ui_coverage.py` is the field-level tool and answers the
  other question — whether what came back is shown — one payload at a time.
- **It does not know whether a call site is live.** A path named in an API
  module that no page imports counts as reached. Spot checks found none; the
  tool cannot prove it.
- **Query and body parameters are out of scope.** Phase 2 found `?fmt=XLSX`
  silently unfiltered because axios serialised an array as `severity[]=`; a
  path-level sweep cannot see that class of defect.
- **Path truncation at an unclosable interpolation** is a deliberate
  simplification for nested template literals.

---

## 7. Lessons learned

> **An absent answer must not be rendered as a known one.**

Most of what these seven phases fixed was that single mistake in different
clothes. The backend kept the distinction in every case; the UI threw it away:

| The API said        | The UI showed     | Where                         |
| ------------------- | ----------------- | ----------------------------- |
| not assessed        | zero findings     | configuration audit export    |
| no deadline applies | within SLA        | remediation summary           |
| withdrawn           | risk accepted     | finding remediation panel     |
| no collector        | no checks defined | configuration-check catalogue |
| timeout / unknown   | complete          | mission view                  |

The rule is now recorded permanently in `CLAUDE.md` under **UI semantic
integrity**, with `UNKNOWN ≠ ZERO`, `UNASSESSED ≠ PASS`, `UNSUPPORTED ≠ NO
FINDINGS`, `NOT CONFIGURED ≠ WITHIN SLA`, `WITHDRAWN ≠ ACCEPTED`, `NO DATA ≠
EMPTY RESULT`, `NO COLLECTOR ≠ NO CHECKS`.

Four further lessons, each paid for:

- **A vocabulary is fetched, never copied.** A UI holding its own list of
  platforms, check types, operators, severities or states silently omits what
  the backend gained and offers what it removed. Two hardcoded platform names
  put 49 database checks — a third of the catalogue — beyond reach.
- **An action the backend structurally refuses must not be offered, and its
  absence must be explained.** A control that can only produce a 400 is worse
  than no control; a control that is silently missing invites "why can I not
  close this".
- **Drive the real API before designing the screen.** Four of the behaviours
  Phase 5 was built around — the exception residue surviving a withdrawal,
  `days_remaining` counting while a risk is accepted, withdrawal returning to
  `assigned`, assignment moving the state — are the opposite of what the
  obvious implementation assumes, and none is visible from the schema.
- **Verify a measurement before believing it.** See §6.

---

## 8. Future backlog

Separated by the kind of work each needs. **Nothing here is scheduled and
nothing was started.**

### Product / UI gaps

| Priority | Item                                   | Operations |
| -------- | -------------------------------------- | ---------: |
| 1        | Compliance schedule management         |          4 |
| 2        | Evidence download                      |          1 |
| 3        | CIS Controls v8.1 report               |          1 |
| 4        | Compliance exception approval          |          1 |
| 5        | Organisation scan-scope read and write |          2 |
| 6        | Organisation restore                   |          1 |

### Backend / API gaps

- **`/remediation` has no `remediation_state` filter.** Only `overdue` and
  `pending-verification` have listing endpoints, so five of the seven states are
  reported as counts and are not drillable, and "my work across all states" is
  unavailable. `_listing` already accepts a `states` argument internally; a
  query parameter would expose it.
- **No domain vocabulary endpoint** for `/config-audit`. The UI derives the
  domain filter's options from the catalogue.
- **No search parameter** on `/config-audit/checks`; the UI filters loaded rows.
- **`/reports` findings CSV does not escape formula leaders** while the XLSX
  writer and the export endpoint do. Recorded in the GAP tracker, deliberately
  not changed, because altering an existing deliverable changes every findings
  CSV this product has produced.

### Authorisation defects

- **`admin_nvd._verify_admin` fails closed for every caller** (§5). Needs an
  owner and explicit approval before the guard is changed.
- **Consider whether the inline role checks** on `scan-scope` write and
  organisation restore should become `require_role` dependencies, so a signature
  scan and the runtime agree. No behaviour change; a legibility decision.

### Tooling improvements

- **Test coverage tooling against representative shapes before trusting it**
  (§6). The matcher's own regression corpus would have caught all three
  template-literal defects.
- **Detect dead call sites**: a path named in an API module that no page imports
  currently counts as reached.
- **Extend the sweep to query and body parameters**, the class Phase 2 found by
  hand at the wire level.
- **Wire `api_ui_matrix.py` into CI** as a reported figure rather than a gate,
  so a new unreached route is visible when it is added rather than at the next
  audit.

---

## 9. Baseline

| Item                   | Value                                                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Final programme commit | `05ab46b`                                                                                                         |
| Branch                 | `Close-Coverage_gap`                                                                                              |
| Working tree           | clean at closeout                                                                                                 |
| Frontend suite         | 2636 passed / 81 files                                                                                            |
| ESLint                 | clean over `src`                                                                                                  |
| Production build       | green                                                                                                             |
| Coverage inventory     | 206/237, reproduced from the clean tree                                                                           |
| Deployment             | the served bundle is byte-identical to a build of this commit once the build-time `VITE_API_URL` is accounted for |

Backend tests were **not** run. The programme changed no backend code, and
`Backend/tests/` is destructive — it `TRUNCATE`s `organizations` and `users`
`CASCADE`. Running it for a documentation closeout is unjustified risk.
