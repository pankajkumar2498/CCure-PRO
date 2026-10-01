# Phase 12 — Frontend shell and CCure Home

|                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**       | **Approved by the owner, 30 Sep 2026, with two corrections** (D12-8 rewritten; the 12.2 row's wording). Revision 2 added the owner's **CCure Home / Product Hub** requirement and the final URL map (§0). Implemented one step per commit with a review stop after each: **12.1 committed with this revision (§7) and live since 1 Oct 2026, 09:09 IST**, approved and verified by the owner (§7, "Live activation"). **12.2 committed (§8) and live since 1 Oct 2026, 10:26 IST**, approved and verified by the owner (§8, "Live deployment"). **12.3 (§9), 12.4 (§10) and 12.5 (§11) committed, not deployed** — the Phase 12 frontend structure is complete in the repository; production stays on the 12.2 frontend until the one deploy of 12.3–12.5 §4 plans, with the owner present. Written at HEAD `1f9a32f` from measurements of the live tree. |
| **Plan**         | [`CCURE_PLATFORM_MODULAR_ARCHITECTURE.md`](CCURE_PLATFORM_MODULAR_ARCHITECTURE.md) rev 4: Phase 12 (Stage 3) and §3.6 "Frontend and the homepage", **as amended by §0 below**; Phase 11 decision **D11-2** ("the homepage's module list endpoint is built in Phase 12, with the UI that consumes it").                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Done when**    | After sign-in, `/` is **CCure Home**, showing four cards — CCure Policy Pro, CCure Audit, CCure Rank, CCure IR — each with its name, a short description of what it is responsible for, and an entry action. Audit's opens `/audit-dashboard`, today's dashboard. The other three open their module pages, which say plainly that the product is not available yet. Every existing Audit address still works.                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **Out of scope** | Any Policy Pro, Rank or IR feature, data or settings (their teams build those); per-organisation entitlement to a product (a later platform feature); moving Audit's **backend** code (Phase 16); the IR service itself (Stage 4); module database roles (Phase 18); 10.8.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

## 0. The owner's requirement (30 Sep 2026)

The authenticated `/` page is a **CCure Platform Home / Product Hub**, not merely a
page of tiles. Its purpose is to help a user understand what the four products are
responsible for, and then choose where to go.

- **All four products are always shown after sign-in**: CCure Policy Pro, CCure
  Audit, CCure Rank, CCure IR. A product is never hidden because its functionality
  is not built yet.
- **Each card has** the product's name, a short informational description of what
  it is responsible for, and an entry action to its dashboard or entry page.
- **The cards must not imply that functionality exists when it does not.** For
  Policy Pro, Rank and IR the description is informational, and the entry page is
  a module shell that says the product is not available yet.
- **The module registry stays the source of this metadata** — names, descriptions,
  entry addresses and availability. No independent, hardcoded product catalogue in
  the frontend.

### Final URL map

| Product          | Entry address       | What it opens in Phase 12                                                                          |
| ---------------- | ------------------- | -------------------------------------------------------------------------------------------------- |
| —                | `/`                 | **CCure Home**, the Product Hub (authenticated)                                                    |
| CCure Policy Pro | `/policy-dashboard` | the Policy Pro module page: not available yet (§3.5)                                               |
| CCure Audit      | `/audit-dashboard`  | Audit's Security Dashboard — the page `/` and `/dashboard` open today                              |
| CCure Rank       | `/rank-dashboard`   | the Rank module page: not available yet                                                            |
| CCure IR         | `/ir-dashboard`     | the IR module page: not available yet                                                              |
| (compatibility)  | `/dashboard`        | redirects to `/audit-dashboard`, so bookmarks, report links and existing code keep working (D12-7) |

Every other Audit address — `/scan`, `/assets`, `/history`, `/reports`,
`/compliance`, `/web-scans/…`, `/admin/…` and the rest — is unchanged.

**This amends the master plan's §3.6**, which said a product that does not exist yet
"shows a tile that says so and cannot be clicked". Under §0 every card has an entry
action; what keeps it honest is that a not-yet-available product's entry page says
so and offers nothing that could fail (§3.4–3.5). The master plan file is not under
version control in this checkout, so the amendment is recorded here.

## 1. What Phase 12 delivers

| #   | Deliverable                                                                                                                          |
| --- | ------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | The registry carries each product's name, description, entry address and availability — IR included, as a product outside the core   |
| 2   | An authenticated endpoint that returns that list, and its vocabulary of availability states                                          |
| 3   | CCure Home at `/`: four cards, fetched, never hidden                                                                                 |
| 4   | Audit's dashboard at `/audit-dashboard`, with `/dashboard` kept as a redirect                                                        |
| 5   | Module pages at `/policy-dashboard`, `/rank-dashboard`, `/ir-dashboard`, rendered from the registry while a product is not available |
| 6   | Sign-in lands on CCure Home by default; a deep link through sign-in still lands on its page                                          |
| 7   | `Frontend/src/shell/` and `Frontend/src/modules/{policy,audit,rank,ir}/`; `modules/web-scanning` folds into `audit/`                 |

**Audit's behaviour does not change** beyond what §0 asks for: the default landing
after sign-in, and its dashboard's canonical address. Its screens, data, navigation
and every other address stay as they are.

## 2. What was measured (30 Sep 2026, HEAD `1f9a32f`)

| Fact                                                                                                                                                                                                                                                                                          | Consequence for Phase 12                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`/` and `/dashboard` both render Audit's `SecurityDashboard`**; the catch-all `*` redirects to `/` (`App.jsx`, 52 route paths). Neither route requires a permission beyond being signed in.                                                                                                 | `/` becomes CCure Home; the dashboard moves to `/audit-dashboard` with the same (lack of) route permission; `/dashboard` becomes a redirect.                           |
| **Audit's sidebar item "Security Dashboard" links to `/`** (`AppLayout.jsx`), and its active-item logic treats `/` and `/dashboard` as the dashboard. 40 pages render `AppLayout` themselves.                                                                                                 | The sidebar link must move to `/audit-dashboard` in the same step, or Audit's own navigation would leave Audit. The home page uses its own platform layout.            |
| **9 source references** name `/dashboard` (sign-in default, `PrivateRoute`'s first fallback, post-scan "back to dashboard" buttons, `SecurityDashboard` resetting its own state); **8 test files** do too.                                                                                    | All move to `/audit-dashboard` in one step; the redirect covers anything outside the repository (bookmarks, links in generated reports).                               |
| **Sign-in lands on `/dashboard` by default**, and on the page the user was sent from when there is one (`location.state.from`, or `postLoginRedirect` after an expiry) — `Login.jsx`.                                                                                                         | Only the default changes, to `/`. A test pins that a deep link through sign-in still lands on its page.                                                                |
| `PrivateRoute`'s refused-permission fallback tries `/dashboard`, `/history`, `/reports`, `/admin/users`, `/admin/audit-logs`, and finally `/login`.                                                                                                                                           | The first candidate is renamed; nothing else about it changes (D12-8): a refused signed-in user is not redirected to CCure Home.                                       |
| The registry holds **three** modules with `title` (`Ccure Policy`, `Ccure Audit`, `Ccure Rank`) and `tile_state` (`available` / `not_yet_available`). **IR is not in it**, there is **no description and no entry address**, and **no endpoint exposes it**.                                  | 12.1 adds IR (D12-2), `description` and `entry_path`, the product names of §0, and the endpoint (D12-3).                                                               |
| The frontend's nginx answers every non-file path with `index.html`; host nginx sends `/` to the frontend and `/api/` to the gateway.                                                                                                                                                          | The four `/…-dashboard` addresses need no nginx or gateway change.                                                                                                     |
| The gateway's route policy is generated from the live route table (`scripts/gateway/route_policy.py`, `--check` in CI) and **bind-mounted** into `ccure-api-gateway`; an unlisted path is `unrouted` and reaches the API without the gateway's own token check (the API still authenticates). | The endpoint needs the policy regenerated **in the same commit**, and a gateway reload to apply it (D12-6).                                                            |
| The frontend has **140** source files and **91** test files; **204** `vi.mock("../…")` calls name modules by relative path; `modules/web-scanning/` holds 14 files at `/web-scans/*`.                                                                                                         | Moving files is a large mechanical change whose worst failure — a mock that silently stops mocking — the build does not catch. Kept apart from the home page (§4).     |
| Frontend CI builds, runs Vitest and lints with `--max-warnings=0`; the UX4G screenshot harness is `Frontend/scripts/ux4g-harness/run.mjs`. The production frontend is **baked at build time**.                                                                                                | Every frontend step is gated by build + tests + lint, a move step also by the harness; users see a step only after a rebuild and redeploy of `ccure-frontend` (D12-6). |

## 3. Design

### 3.1 The registry is the catalogue

Each product's platform-owned identity gains two fields, and the names change to
§0's:

| key          | title            | kind          | tile_state          | entry_path          | description (draft, D12-9)                                                                                                                                                            |
| ------------ | ---------------- | ------------- | ------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policy_pro` | CCure Policy Pro | `core_module` | `not_yet_available` | `/policy-dashboard` | Responsible for your organisation's security policies and controls, and for the baseline — which controls apply, with what parameters — that the other products assess against.       |
| `audit`      | CCure Audit      | `core_module` | `available`         | `/audit-dashboard`  | Responsible for finding and assessing your assets: network and web scanning, vulnerability and configuration audits, compliance against frameworks, remediation tracking and reports. |
| `rank`       | CCure Rank       | `core_module` | `not_yet_available` | `/rank-dashboard`   | Responsible for scoring and ranking your organisation's security posture from the results the other products produce.                                                                 |
| `ir`         | CCure IR         | `service`     | `not_yet_available` | `/ir-dashboard`     | Responsible for incident response: recording and managing security incidents, and feeding what is learned back to the other products.                                                 |

- **Descriptions state responsibility, never capability.** "Responsible for …" says
  what the product is for; whether anything can be used is said separately, by the
  availability state, on the card and on the entry page. A description never
  names a number, a result or a feature as present.
- **The registry refuses** an empty title or description, an `entry_path` that is
  not an absolute single-segment path, and two products sharing a key or an entry
  path. Every product has an entry path, available or not (§0).
- **IR is a product outside the core** (D12-2): a separate, short, platform-owned
  list in the same stdlib-only module, holding key, title, description,
  `entry_path` and `tile_state` only. Nothing is mounted from it — IR is its own
  service (Stage 4).
- **Turning a product on is one platform change**: its `tile_state` becomes
  `available` in the same commit that ships the team's page at its `entry_path`.

### 3.2 `GET /platform/modules` (decision D12-3)

```
{
  "tile_states": ["available", "not_yet_available"],
  "modules": [
    {"key": "policy_pro", "title": "CCure Policy Pro", "kind": "core_module",
     "description": "Responsible for …", "entry_path": "/policy-dashboard", "tile_state": "not_yet_available"},
    {"key": "audit", "title": "CCure Audit", "kind": "core_module",
     "description": "Responsible for …", "entry_path": "/audit-dashboard", "tile_state": "available"},
    {"key": "rank", …, "entry_path": "/rank-dashboard", "tile_state": "not_yet_available"},
    {"key": "ir", "kind": "service", …, "entry_path": "/ir-dashboard", "tile_state": "not_yet_available"}
  ]
}
```

- Any signed-in user; no permission; order is the registry's (Policy Pro, Audit,
  Rank, IR). The vocabulary comes with the data, so the frontend holds no list of
  states.
- **Nothing about the user is in it**, and nothing is filtered by user (D12-4):
  every signed-in user sees the same four products.
- It names no backend route, table or task.

### 3.3 CCure Home (`/`)

A platform page with its own layout — CCure branding, the signed-in user, sign-out —
not Audit's sidebar. It renders exactly what the endpoint says:

| State                                         | The card shows                           | The entry action                                                                                   |
| --------------------------------------------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `available`                                   | name, description, **Available**         | **Open dashboard** → `entry_path`                                                                  |
| `not_yet_available`                           | name, description, **Not yet available** | **About this product** → `entry_path`, the module page (§3.5); never worded as opening a dashboard |
| a `tile_state` outside the fetched vocabulary | name, description, **Status unknown**    | → `entry_path`, which says the same; never rendered as available                                   |

| Page state         | Renders                                                                                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| loading            | a loading state, never placeholder cards                                                                                                                                 |
| the request failed | "The CCure product list could not be loaded" with a retry. **Not** zero cards, and **not** a built-in fallback list — that would be the hardcoded catalogue §0 rules out |

Every row has a Vitest test. The card order, names and descriptions come from the
response; the page contains no product name.

### 3.4 Audit's dashboard at `/audit-dashboard` (decision D12-7)

- `/audit-dashboard` renders today's `SecurityDashboard`, with today's (signed-in
  only) route guard.
- `/dashboard` **redirects** to `/audit-dashboard` (replace), so one page has one
  address and every old link still lands.
- Audit's sidebar "Security Dashboard" item, its active-item logic, `PrivateRoute`'s
  fallback, the post-scan buttons and the sign-in code move to `/audit-dashboard`.
- Every other Audit address is untouched.

### 3.5 Module pages for products not yet available

`/policy-dashboard`, `/rank-dashboard` and `/ir-dashboard` are rendered by one
shell component, **driven by the registry**, not by a route per product:

- A single-segment route that the static routes outrank looks the path up in the
  fetched list. A product whose `entry_path` it is and whose state is
  `not_yet_available` gets its module page; a path that is no product's entry
  keeps today's catch-all behaviour (to `/`).
- **The module page says what is true and nothing else**: the product's name and
  description, "CCure Rank is not available yet — there are no Rank features, data
  or settings in this installation", and a way back to CCure Home. No chart, no
  count, no empty table, no disabled control standing in for a feature — each of
  those reads as "the feature exists and has nothing in it".
- **An `available` product whose page this build does not have** — the registry
  says available, no static route matched — renders that mismatch explicitly,
  never a blank page and never the placeholder. A repository test checks that each
  `available` product's `entry_path` is a route in `App.jsx`, so it cannot ship.
- When a team ships its dashboard, its static route at the same `entry_path`
  outranks the shell route, and its `tile_state` becomes `available` (§3.1).

### 3.6 `shell/` and `modules/` (the folder half)

```
Frontend/src/
  shell/        CCure Home, platform layout, module pages, sign-in screens, AuthContext,
                PrivateRoute, axiosInstance + tokenStorage, permissions, design-system
  modules/
    audit/      every current Audit page, component, context and api client; web-scanning/ folds in
    policy/  rank/  ir/    README only — "nothing is built here yet"
```

- **Mechanical, and separate from CCure Home.** A move changes imports and nothing
  else. Its failure modes are a broken import (the build catches it) and a
  `vi.mock("../…")` that stops mocking because its path no longer names the module
  (the build does not). Each move step checks that every mocked path resolves, as
  well as build, tests, lint and a harness comparison.
- **Batched by risk**: shared plumbing first (`shell/`), then Audit's leaf pages,
  then the heavily shared components.
- **Path aliases** (`@shell/…`, `@audit/…`) in the Vite and Vitest configs, so a
  moved import does not depend on depth.
- **The boundary is enforced**: an ESLint `no-restricted-imports` rule — a module
  imports `shell/` and itself, never another module; `shell/` imports no module.

### 3.7 Ownership

`CODEOWNERS` gains `Frontend/src/shell/` (project owner) and
`Frontend/src/modules/{audit,policy,rank,ir}/` (each team) — placeholders, the
lines Phase 11 §3.7 marked "Phase 12 creates these".

## 4. Steps (one commit each, review stop after each)

| Step     | What                                                                                                                                                                                                                                                                                                           | Live change                                                                        | Gate                                                                                                                                                                                               |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **12.1** | Backend: registry `description`, `entry_path`, product names, IR as a product outside the core (§3.1); `GET /platform/modules` (§3.2); gateway route policy regenerated; `docs/` entries; endpoint-inventory decision; tests. This document committed.                                                         | **yes**, deliberate: one API restart and one gateway reload, owner present (D12-6) | OpenAPI diff is **additions only**; routes 273 → 274; rate-limited 93, tasks 21, beat 11 unchanged; route-policy `--check`; full suite; the endpoint answers through `:443` with the four products |
| **12.2** | Frontend: `src/shell/` with CCure Home (§3.3); the Policy Pro, Rank and IR module-entry pages (§3.5); the Audit dashboard migration to `/audit-dashboard` and the `/dashboard` compatibility redirect (§3.4); sign-in landing behaviour; Vitest for every state in §3.3–3.5 and for deep links through sign-in | **yes**: frontend rebuild and redeploy, owner present                              | build, tests, lint; harness: every Audit screen unchanged; the done-test through `:443`                                                                                                            |
| **12.3** | Move the shared plumbing into `shell/`; path aliases; the ESLint boundary rule                                                                                                                                                                                                                                 | none until the next frontend deploy                                                | build, tests, lint, every mocked path resolves; harness identical                                                                                                                                  |
| **12.4** | Move Audit's screens into `modules/audit/` in risk batches, `web-scanning/` included; every address unchanged                                                                                                                                                                                                  | none until deploy                                                                  | as 12.3, per batch                                                                                                                                                                                 |
| **12.5** | `modules/{policy,rank,ir}/` READMEs; `CODEOWNERS`; CLAUDE.md; plan status; one frontend deploy of 12.3–12.4, owner present                                                                                                                                                                                     | frontend redeploy                                                                  | full frontend suite; harness; done-test through `:443`                                                                                                                                             |

## 5. Risks

| Risk                                                                                                                         | Handling                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A card or module page implies a product works when it does not**                                                           | Descriptions state responsibility only (§3.1); availability is a separate, fetched state; the action for a product not yet available is never worded as opening a dashboard; its page has no data-shaped element (§3.5). Tested. |
| **A failed or unknown answer is rendered as a known state** — zero cards, everything "not yet available", or a fallback list | §3.3: the failure is its own state with a retry; an unknown `tile_state` is its own rendering; there is no built-in list to fall back to.                                                                                        |
| Audit's own navigation leaves Audit                                                                                          | The sidebar's dashboard link moves to `/audit-dashboard` in the same step as `/` becomes CCure Home; a test pins it.                                                                                                             |
| An old `/dashboard` link or bookmark breaks                                                                                  | It redirects (D12-7); a test pins it.                                                                                                                                                                                            |
| The registry says a product is available and the build has no page for it                                                    | Rendered explicitly (§3.5), and a repository test refuses the combination before it ships.                                                                                                                                       |
| The endpoint is live before the gateway knows it                                                                             | `./Backend` is bind-mounted, so it exists at the next API restart for any reason; until the gateway reloads its map it is `unrouted`, and the API still refuses an unauthenticated call. The reload is 12.1's live step.         |
| A moved file breaks an import only at runtime, or a moved mock stops mocking                                                 | Moves are separate from behaviour changes; build + tests + lint + a mocked-path check + harness before and after every batch.                                                                                                    |
| The frontend bundle is baked, so a merged step is invisible until rebuilt                                                    | Deploys are named in §4, with the owner present.                                                                                                                                                                                 |

## 6. Decisions

| #         | Decision                                                                                                       | State / recommendation                                                                                                                                                                                                                                                                                                                                                                                                      |
| --------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **D12-1** | The home page's address and the product URL map                                                                | **Decided by the owner, 30 Sep 2026**: CCure Home at `/`; `/policy-dashboard`, `/audit-dashboard`, `/rank-dashboard`, `/ir-dashboard` (§0)                                                                                                                                                                                                                                                                                  |
| **D12-2** | Where IR's card comes from                                                                                     | **The registry**, as a product outside the core (§3.1)                                                                                                                                                                                                                                                                                                                                                                      |
| **D12-3** | The endpoint                                                                                                   | **`GET /platform/modules`**, any signed-in user, no permission, no rate limit beyond the baseline (authenticated and cheap)                                                                                                                                                                                                                                                                                                 |
| **D12-4** | Whether a card depends on the user                                                                             | **Decided by the owner**: all four products are always shown after sign-in. Entitlement, when it comes, renders a state — it never hides a product                                                                                                                                                                                                                                                                          |
| **D12-5** | How much of the folder move is in Phase 12                                                                     | **All of it**, in 12.3–12.4 batches after CCure Home; the alternative is `shell/` and CCure Home now, the Audit move with Phase 16                                                                                                                                                                                                                                                                                          |
| **D12-6** | The live changes (API restart and gateway reload in 12.1; frontend redeploys in 12.2 and 12.5)                 | With the owner present, as 10.5–10.7 and 11.3 were                                                                                                                                                                                                                                                                                                                                                                          |
| **D12-7** | `/dashboard` after the move                                                                                    | **A redirect to `/audit-dashboard`** — one page, one address, no broken link; the alternative is serving the page at both                                                                                                                                                                                                                                                                                                   |
| **D12-8** | Authentication and authorisation behaviour                                                                     | **Decided by the owner (correction, 30 Sep 2026): unchanged.** Unauthenticated users keep today's sign-in behaviour. Authenticated users refused access keep today's 401/403 semantics; a refusal is never turned into a redirect to CCure Home, which would hide that access was denied. The UI may offer a "CCure Home" navigation option where it shows such a refusal, and Audit's header may carry a "CCure Home" link |
| **D12-9** | The wording: the four descriptions (§3.1), "Open dashboard" / "About this product", the module page's sentence | The owner approves the copy; the drafts above are written to state responsibility, never capability                                                                                                                                                                                                                                                                                                                         |

## 7. Step 12.1 as built (30 Sep 2026)

Backend only. No frontend, no Audit route, no product functionality, and no
production change: the live step (one API restart, one gateway reload) waits for
the owner's review of this record.

**Registry** (`ccure_platform/modules/`, still a stdlib-only leaf):

- `ModuleManifest` gains two **required** fields, `description` and
  `entry_path`; `ServiceProduct` is a product outside the core (key, title,
  description, entry path, availability — nothing to mount); `Product` is the
  uniform view CCure Home reads. `PRODUCT_KINDS = core_module, service`.
- Validation at construction: non-empty title and description, a description of
  at most 300 characters, an `entry_path` of one absolute path segment, a known
  `tile_state`; across all products, no shared key, title or entry path.
- The data is §3.1's table: the names of §0, the owner-approved descriptions
  (D12-9, pinned word for word by a test), the URL map, and CCure IR as the one
  `ServiceProduct`. `registry.products()` lists all four in display order;
  `registry.get("ir")` is still a `KeyError` — IR is never a core module.
- Nothing is enabled, mounted, loaded or queued that was not before.

**Endpoint** — `GET /platform/modules`, `ccure_platform/hub/router.py`, mounted
after every existing router so the route table and the gateway policy only grow at
the end. Guarded by `ccure_platform.api.current_user`. A request without
credentials is refused **403 "Not authenticated"** and an invalid token **401**,
identically to `/auth/me` and every Audit route (D12-8: no new authentication
behaviour). Response models `PlatformProduct` / `PlatformProductList`, tag
`Platform`.

**Gateway** — `gateway/policy/route_policy.{json,map}` regenerated from the live
route table: one entry appended, `http:GET:/platform/modules → bearer` at order
273; counts bearer 251 → 252, total 273 → 274; inventory hash `e64706ff…` →
`90e199d3…`. No existing route renumbered or reclassified.
`docs/architecture/phase10/route_table.json` re-dumped with the documented
`route_table.py` command: the same single entry added, nothing else changed.
`route_auth_matrix.json` is built from live credentialed probes and is not
regenerated; its consumers read only the 17 public routes, which are unchanged.

**OpenAPI** — `Backend/openapi.json` regenerated with CI's own command. Additions
only: `/platform/modules`, `PlatformProduct`, `PlatformProductList` — and **two
Phase 9 routes that were live but never recorded**, `/auth/jwks.json` and
`/auth/service-token` with their two schemas. The committed file had been stale
since Phase 9 (the drift Phase 10.5 recorded and deferred), so CI's OpenAPI diff
step was already failing at `1f9a32f`; the canonical regeneration records current
truth rather than a hand-merged partial file. No existing path or schema changed.

**Invariants, deliberately changed**: routes 273 → 274, OpenAPI paths 234 → 235
and its hash. **Unchanged**: 93 rate-limited routes, 21 Celery tasks at import,
11 beat entries, the task registry, queues and includes.

### Live activation (1 Oct 2026)

Approved by the owner, who was present (D12-6). Only the two approved actions
were taken; no code, configuration, schema, migration or Celery change, and the
frontend, workers, beat, gateway-auth and database were not touched.

- **Backup first** — `backups/ccure_db_20261001_090912_ops.dump`.
- **API restart** — `docker compose restart api` at 09:09:18 IST; `:443`
  answered again 11 s later. `alembic upgrade heads` applied nothing (no
  migration since 11.3). Trust boundary logged unchanged
  (`127.0.0.1, ::1, 172.31.254.10`); no error or traceback.
- **Gateway reload** — `nginx -t` passed, then `nginx -s reload` in
  `ccure-api-gateway` at 09:09:47 IST, picking up the bind-mounted
  `route_policy.map` committed in 12.1. No error; the only output is the
  existing warning that `user` is ignored by a non-root master.

Verified through the production `:443` path:

| Check                                       | Result                                                                                                                                                                                                                                               |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/platform/modules`, no credentials | **403** "Not authenticated", refusal `missing_bearer` — identical to `/auth/me`                                                                                                                                                                      |
| Same, invalid bearer                        | **401** "Invalid or expired token", refusal `invalid_bearer` — identical to `/auth/me`                                                                                                                                                               |
| Gateway classification                      | `class: bearer`, `policy: bearer` in the gateway access log                                                                                                                                                                                          |
| Same, the owner's own sign-in               | **200**, `X-Request-ID` present; four products in the order CCure Policy Pro, CCure Audit, CCure Rank, CCure IR; body **equal field for field** to the committed registry (titles, kinds, descriptions, `entry_path`s, `tile_state`s, `tile_states`) |
| Existing Audit access, same session         | `POST /auth/login`, `GET /auth/me`, `/dashboard/summary`, `/scan-policies`, `/scan-schedules` all **200**; the session was signed out afterwards                                                                                                     |
| Logs                                        | No error in `ccure-api`, `ccure-api-gateway` or `ccure-gateway-auth` after the restart and reload                                                                                                                                                    |

The authenticated check was run by the owner with a local script that prompts
for credentials and prints neither the password nor any token. Step 12.1 is
complete; 12.2 waits for the owner's go-ahead.

## 8. Step 12.2 as built (1 Oct 2026)

Frontend only, plus one repository test, committed as `58a369d`. The production
frontend is baked at build time, so it became visible only with the rebuild and
redeploy recorded under "Live deployment" below (D12-6). No backend route,
schema, migration, Celery or configuration change.

**`Frontend/src/shell/`** (new; the shared-plumbing move is 12.3):

- `products/productList.js` — reads `GET /platform/modules`; validates the
  body (an unreadable body is an error, never an empty list); maps each
  `tile_state` to _available_, _not yet available_ or _unknown_. A state
  outside the fetched `tile_states`, or inside it but unknown to this build, is
  **unknown**. The file holds no product name, description or address.
- `products/useProductList.js` — `loading` / `ready` / `error` plus `retry()`;
  on error there is no list at all, so nothing can fall back to a guess.
- `pages/CcureHome.jsx` — `/`. Every product the response lists, in its order,
  as a card: title, description, availability badge, and an entry action —
  **Open dashboard** (available), **About this product** (not yet available or
  unknown). Loading is a loader, not placeholder cards; a failure is "The CCure
  product list could not be loaded" with the HTTP status and **Retry**.
- `pages/ModuleEntryPage.jsx` — the single-segment route `/:entry`, outranked
  by every static route. It looks the address up in the fetched list:
  not yet available → the module page ("CCure Rank is not available yet" /
  "There are no CCure Rank features, data or settings in this installation",
  description, back to CCure Home); unknown → says so; available with no page
  in this build → says so; no product → `/`, as the catch-all did; list failed →
  error and retry, the address kept. No chart, count, table or disabled control.
- `layout/PlatformLayout.jsx` — CCure branding, the signed-in user, Sign out.
  Not Audit's sidebar.

**Routes** (`App.jsx`): `/` → CCure Home; `/audit-dashboard` →
`SecurityDashboard` (same guard as before: signed in only); `/dashboard` →
redirect to `/audit-dashboard` keeping query, fragment and router state;
`/:entry` → module entry page. Every other address is unchanged.

**Audit**: the sidebar's Security Dashboard item → `/audit-dashboard` and is
active there and on `/dashboard`; the header carries a **CCure Home** link;
`PrivateRoute`'s first refused-permission fallback, the welcome modal, and the
NewScan / CredentialedScan / Phase 1 back actions → `/audit-dashboard`. Sign-in
lands on `/` by default; `location.state.from` and the post-expiry
`postLoginRedirect` still win. A refusal is never turned into a trip to CCure
Home (D12-8).

**Copy, for the owner (D12-9)**: the module page names the product by its
registry title in both sentences ("There are no CCure Rank features…" rather
than §3.5's "no Rank features…"), because a shortened name would be product
metadata held in the frontend.

**Tests**: Vitest 91 files / 2,784 tests before → 94 / 2,883 after, all
passing; `npm run lint` clean; `npm run build` succeeds. New:
`__tests__/shell/{productList,CcureHome,AppRoutes}.test.*`, with
`fixtures/platformModules.real.json` (the live `:443` body from the 12.1
activation). `AppRoutes` renders the real `App` with Audit's pages stubbed and
pins the address map, the redirect, every module page, the catch-all, 20
unchanged Audit addresses, the three existing redirects, and D12-8 (sign-in
carries the address; refusals keep their fallback; a 403 from the list is
shown, not navigated away from). Seven deliberate mutations — unknown read as
known, vocabulary unchecked, sidebar back to `/`, sign-in default, redirect
dropping the query, no catch-all, refusal to `/` — each fail a test.
`Backend/tests/repo/test_platform_entry_routes.py`: an `available` product has a
route at its `entry_path` in `App.jsx`; a product not yet available has none
(it would outrank its module page). It skips in the API container, which does
not mount `Frontend/`, and passes on a full checkout.

**Harness** (`Frontend/scripts/ux4g-harness`; its SecurityDashboard states now
open `/audit-dashboard`): pre (HEAD `775aba6`) against post, 253 states each,
all ready, no exception, write, blocked navigation or off-origin request. Every
delta is the header's new link — one link named "CCure Home" in names and Tab
order, one design-system element, +10–11 characters of text, one contrast pair,
screenshot pixels only inside the header band (y 17–32), the header status
region moved by the link's width — plus `/dashboard` → `/audit-dashboard` in the
21 states that open the dashboard. No Audit page body changed. The
determinism and sensitivity gates were not re-run for this step.

### Live deployment (1 Oct 2026)

Approved by the owner, who was present (D12-6). Only `ccure-frontend` was
changed; the API, gateway, gateway-auth, workers, beat and database were not
touched, and no code, configuration or gateway policy changed.

- **Rollback tag first** — `ccure-audit-pro-frontend:pre-12.2`, the previous
  image `sha256:3cc1137e97c9…` (built for 10.7).
- **Build from the commit, not the working tree** — a detached checkout of
  `58a369d`, built with the repository's Dockerfile and
  `VITE_API_BASE_URL=/api`, labelled
  `org.opencontainers.image.revision=58a369d9f2b27bd5d8c9279acd9617a5f94b4a28`:
  `ccure-audit-pro-frontend:12.2-58a369d`, image
  `sha256:f681c4c012bf93f17ae4993163ee0e9f69f48e40edbfdd5b3bfc406ae9337b3d`.
  The label and the rollback tag were confirmed before promotion.
- **Deployed 1 Oct 2026, 10:26:21 IST** — tagged `:latest`, then
  `docker compose up -d --no-deps frontend`; `:443` answered 200 two seconds
  later.
- **Assets** — `index-CzaKDzq3.js` and `index-C375QD7K.css`. `index.html` and
  both bundles served through `:443` equal the image's files by SHA-256; the
  previous assets are no longer served. `/`, the four entry addresses,
  `/dashboard` and the Audit addresses all serve the new `index.html`, with the
  Content-Security-Policy header present.

Verified through `:443` in headless Chrome, signing in with the owner's own
account through the real sign-in form (credentials prompted locally, never
printed):

| Check                                                                                                                         | Result                                                           |
| ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Sign-in with no return address lands on `/`, CCure Home                                                                       | pass                                                             |
| Four cards, Policy Pro → Audit → Rank → IR                                                                                    | pass                                                             |
| Cards equal the live `GET /api/platform/modules` response of the same session (title, description, entry path, state, action) | pass                                                             |
| `/policy-dashboard`, `/rank-dashboard`, `/ir-dashboard` — not-yet-available page, description, back link, nothing data-shaped | pass                                                             |
| Audit card → `/audit-dashboard`, Security Dashboard active; `/audit-dashboard` loaded directly                                | pass                                                             |
| Audit header CCure Home link → `/`                                                                                            | pass                                                             |
| `/dashboard?x=1#y` → `/audit-dashboard?x=1#y`, as a page load and as in-app navigation                                        | pass on recheck (below)                                          |
| Audit `/scan`, `/history`, `/assets`, `/reports` render                                                                       | pass (`/reports` on recheck)                                     |
| Signed out, `/history?tab=x` → sign-in → back to `/history?tab=x`                                                             | pass                                                             |
| No 5xx, no uncaught page error                                                                                                | pass in both runs; no error in the frontend, gateway or API logs |

**Two first-run results were artefacts of the verification, not of 12.2.** The
first run reloaded the page about twenty times in a minute, and each load
repeats `/auth/refresh` and `/auth/me`. Host nginx's `ccure_auth` zone (30
requests a minute, burst 10) answered 429 — the gateway logged no 429, so the
refusal was the edge's — and the application, its refresh refused, correctly
treated the session as ended. The `/dashboard` redirect and `/reports` checks
ran after that point and ended at `/login`. A paced recheck (a 70-second wait,
one sign-in, in-app navigation; 9 auth calls, no 429) passed all nine of its
checks, including both. 12.2 changes neither authentication nor the limit.

**Rollback**: `docker tag ccure-audit-pro-frontend:pre-12.2
ccure-audit-pro-frontend:latest`, then `docker compose up -d --no-deps
frontend`.

Step 12.2 is complete. 12.3 has not started and waits for the owner.

## 9. Step 12.3 as built (1 Oct 2026)

Structure only: no route, screen, copy or behaviour changes, and nothing
deployed — production stays on the 12.2 image. No backend file changed.

**One place says where everything lives** — `Frontend/modules.config.js`: the
shell (`src/shell`), the design system (`src/design-system`), the product
modules (`src/modules/{audit,policy,rank,ir}`), the composition root
(`main.jsx`, `App.jsx`), and that until 12.4 every other file under `src/`, and
`modules/web-scanning/`, is Audit's.

**Path aliases** (built from that file in `vite.config.js`, so Vitest has them
too; mirrored in `jsconfig.json`): `@shell/…`, `@audit/…`, `@policy/…`,
`@rank/…`, `@ir/…`. Only `@shell` has code behind it yet; the module aliases
exist so 12.4's moves change no import style.

**Moved into `src/shell/`** — the shared plumbing every product uses, by
`git mv`, contents unchanged apart from import paths and the header comment:

| From                                                                                 | To                      |
| ------------------------------------------------------------------------------------ | ----------------------- |
| `api/axiosInstance.js`, `api/tokenStorage.js`, `api/auth.js`                         | `shell/api/`            |
| `context/AuthContext.jsx`, `components/auth/PrivateRoute.jsx`, `auth/permissions.js` | `shell/auth/`           |
| their two tests                                                                      | `__tests__/shell/auth/` |

287 import and `vi.mock` specifiers in 129 files were rewritten by a script that
resolves each one, never by search and replace. Outside the shell they now read
`@shell/…`. A check over the whole diff found no other changed line in those
files.

**Two genuinely shared pieces were extracted from Audit:**

- `shell/navigation/CcureHomeLink.jsx` — the way back to CCure Home (address,
  accessible name, icon, label). Audit's header uses it with its own classes;
  its DOM is unchanged.
- `shell/auth/accessFallback.jsx` — the route guard's refused-route fallback.
  `PrivateRoute` held Audit's five pages (`/audit-dashboard`, `/history`, …);
  the shell now holds only the rule (first permitted candidate, else sign-in)
  and Audit supplies its pages (`src/config/accessFallbacks.js`) through a
  provider that `App.jsx` mounts in `AuditProviders`. Behaviour is identical;
  a refusal is still never sent to CCure Home (D12-8).

**Boundaries** — `src/__tests__/architecture/moduleBoundaries.test.js`
resolves every import in `src/` (relative and alias) and enforces: the design
system imports only itself; the shell imports itself and the design system; a
module imports itself, the shell and the design system, never another product;
nothing but `main.jsx` imports the root. It also requires every import to
resolve, and every `vi.mock` / `importActual` path in the tests to name a real
module — the move's silent failure. ESLint `no-restricted-imports` overrides
repeat the alias half for editors, and the test checks they agree with
`modules.config.js`. Mutation-checked: a shell file importing an Audit page, the
design system importing the shell, Audit importing `App.jsx`, an unresolvable
alias and a stale mock path each fail it; ESLint flags `@audit` from
`modules/rank` and `@rank` from the shell.

**Deviations from §3.6, for the owner:**

- **The sign-in screens stay where they are.** They carry Audit's branding —
  "CCure Audit", "CCure Audit PRO" in the brand mark and the terms text — and
  the shell may hold no product's name (the 12.2 guard caught it). Moving them
  needs a copy decision first (platform branding), which is the owner's
  (D12-9). Their helpers (`components/auth/Auth*`, `styles/auth.css`,
  `hooks/useDebounce`) stay with them.
- **The design system stays at `src/design-system/`.** It is already a leaf with
  its own guardrails and is the future cross-product package; moving it would
  rewrite ~150 imports for no boundary gain. The new test now also enforces
  that it imports nothing of the application.

**Tests**: Vitest 95 files / 2,899 tests, all passing (12.2: 94 / 2,883); lint
clean; build succeeds; the design-system `dist/` guardrails pass against the
new build. One existing test was recomposed rather than changed: the AMT
route-permission test renders the guard on its own, so it now wraps it in
Audit's fallback provider exactly as `App.jsx` does, with the same assertion.
`test_platform_entry_routes.py` and `test_docs_integrity.py` pass.

**Harness**: the production 12.2 image (`ccure-audit-pro-frontend:12.2-58a369d`)
against a 12.3 build, 253 states each, all ready, no exception, write or
blocked navigation — **253/253 identical**; 25 screenshots differ within the
harness's own anti-aliasing tolerance (maximum channel delta 1–2).

## 10. Step 12.4 as built (1 Oct 2026)

Audit's frontend moved into `src/modules/audit/`. A move and nothing else: no
route, screen, copy, API call, permission or behaviour changes, and nothing
deployed — production stays on the 12.2 image. No backend file changed.

**Inventory and classification.** Every file under `src/` outside the shell,
the design system and the root was classified before anything moved:

| Classification | Files                                                                                                                                                                                                                                                                               | Where                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| Audit          | `api/` (17), `components/` except `auth/` (34), `config/` (2), `context/` (2), `hooks/usePagedRows`, `pages/` except sign-in (32, incl. the dev-only `DesignSystemShowcase`, which reads Audit's preferences), Audit's stylesheets (47), `utils/` (4), `modules/web-scanning/` (14) | `src/modules/audit/`  |
| Shell          | `hooks/useDebounce` — generic, used by Audit and the sign-in screens                                                                                                                                                                                                                | `src/shell/hooks/`    |
| Root           | `main.jsx`, `App.jsx`; the global stylesheet `main.jsx` loads and its seven `@import`s (`global`, `theme`, `layout`, `forms`, `scan`, `responsive`, `animations`, `dark-mode`) — every page renders under it, so it belongs to no product                                           | `src/`, `src/styles/` |
| Pending        | the five sign-in screens, `components/auth/Auth*`, `styles/auth.css`, `styles/forgot-password.css` — Audit-branded, awaiting the platform sign-in branding decision (§9)                                                                                                            | unchanged             |

**Structure** — `src/modules/audit/` keeps the shape a developer already
knows: `api/`, `components/{admin,assets,common,compliance,layout,remediation,scan}/`,
`config/`, `context/`, `hooks/`, `pages/` (with `scan/`, `admin/`),
`styles/`, `utils/`, `web-scanning/`. Tests mirror it under
`__tests__/modules/audit/`.

**How** — four batches (data and plumbing; components; pages and styles;
web scanning), each by `git mv` with its tests, each followed by the full
suite. A script re-resolved every import and mock specifier against the file's
old location: 557 specifiers across the four batches, none unresolved. Into
Audit from outside it they read `@audit/…`, into the shell `@shell/…`; within
an area they stay relative. A review of every renamed file's diff found only
specifiers, header-comment paths and the test-path fixes below.

**Tests that read source by path** counted `..` from their own location and
broke on the move (22 files). They now import anchors from
`__tests__/testPaths.js` (`SRC`, `AUDIT_SRC`, `SHELL_SRC`) — never a depth
again. Six assertions that a page imports the design system had the import's
depth in the regex (`../design-system`); the depth is incidental, so they now
accept any (`(?:\.\.\/)+design-system`). No assertion was removed.

**Boundaries** — `modules.config.js` drops the pre-12.4 "everything else is
Audit's" rule for two explicit lists, `GLOBAL_STYLES` and `PENDING` (each
pending group carries its reason). The boundary test now fails on any source
file outside a named place, so Audit code cannot reappear outside its module;
it also checks that no listed file is stale, that Audit reaches the shell only
as `@shell/…` and is reached only as `@audit/…`, and that the ESLint overrides
agree (the retired `src/**` override is replaced by one for the pending
sign-in group). 23 tests.

**Outside `Frontend/`** — tooling that reads frontend paths was updated
(`scripts/audit/api_field_coverage.py`, `api_ui_coverage.py`,
`manifests/field_coverage.json`; every manifest path exists), as were the two
living references that name them (`docs/BACKEND_API_REFERENCE.md`,
`docs/FILE_UPLOAD_AUDIT.md`). Historical records — `docs/ux4g/` batch notes,
the API→UI coverage reports, the gap tracker — describe the tree when they were
written and are unchanged. `CLAUDE.md` is 12.5's. One backend comment,
`Backend/scan_helpers.py` ("mirrors src/config/scanConfig.js"), is left stale
because 12.4 touches no backend file.

**Verification**: Vitest 95 files / 2,908 tests, all passing; lint clean;
build succeeds; design-system `dist/` guardrails pass. Harness, the production
12.2 image against the 12.4 build, 253 states each, all ready, no exception,
write or blocked navigation — **253/253 identical**, 24 screenshots within the
harness's anti-aliasing tolerance (maximum channel delta 1–2). The states cover
the dashboard, scan, history, assets, reports, compliance, scan policies and
schedules, credentialed results, admin, refused access and their navigation;
`AppRoutes.test.jsx` pins every address, the `/dashboard` redirect and the
refused-route fallback.

## 11. Step 12.5 as built (1 Oct 2026)

Documentation and ownership, plus the two guardrails a finished structure was
missing. No route, screen, behaviour or runtime change, and nothing deployed.
§4 planned the one frontend deploy of 12.3–12.4 inside this step; the owner
moved it out, so it remains outstanding.

**The final structure**, written down once in `Frontend/modules.config.js` and
described in `docs/FRONTEND_ARCHITECTURE.md` §2, `Frontend/README.md`,
`CLAUDE.md` ("Frontend modules (Phase 12)") and a `README.md` in every part:

| Part                 | Folder                                                | Alias     | May import                                  |
| -------------------- | ----------------------------------------------------- | --------- | ------------------------------------------- |
| Shell                | `src/shell/`                                          | `@shell`  | itself, design system                       |
| Design system        | `src/design-system/`                                  | —         | itself                                      |
| CCure Audit          | `src/modules/audit/`                                  | `@audit`  | itself, shell, design system, global styles |
| CCure Policy Pro     | `src/modules/policy/` (README)                        | `@policy` | itself, shell, design system, global styles |
| CCure Rank           | `src/modules/rank/` (README)                          | `@rank`   | itself, shell, design system, global styles |
| CCure IR integration | `src/modules/ir/` (README)                            | `@ir`     | itself, shell, design system, global styles |
| Composition root     | `main.jsx`, `App.jsx`, `src/styles/` (global)         | —         | everything                                  |
| Pending: sign-in     | `src/pages/`, `src/components/auth/`, two stylesheets | —         | itself, shell, design system, global styles |

No product imports another; nothing but `main.jsx` imports the root. Each
product README says how a team ships its first screen: a static route at its
registry `entry_path` and, in the same change, `tile_state: available` in the
platform registry — never product metadata in the frontend.

**Ownership** — `.github/CODEOWNERS` gains the §3.7 lines, placeholders only:
shell, design system, `modules.config.js`, `.eslintrc.json` and the
architecture tests to the project owner; each module folder and its test folder
to its team. IR has no team placeholder and none was invented: its folder is the
project owner's until one is named (D6).

**Guardrails** — the 12.3–12.4 tests already covered unclassified files, every
boundary, shell and design-system independence, the return of legacy Audit
paths, and unresolved imports and mocks. Two gaps closed:

- **The aliases are proven, not assumed.** `vite.config.js` must take them from
  `modules.config.js` and write none by hand; `jsconfig.json` must name the same
  folders; and `@shell/…` and `@audit/…` must resolve to the very module objects
  their folders hold.
- **Every part has an owner line** in `CODEOWNERS` — the frontend twin of the
  backend's `module_boundaries` check.

Each was mutation-checked (alias drift in `jsconfig.json`, a removed owner
line, a hand-written alias). No speculative rule was added.

**Stale references fixed** — the one living reference outside the frontend
that 12.4 made obsolete, the comment in `Backend/scan_helpers.py` (comment
only); `CLAUDE.md`'s path to `EmailDomainRules.jsx`; and
`docs/FRONTEND_ARCHITECTURE.md` §2–§5 (layout, providers, routing, guards),
rewritten for Phase 12, with its later file references mapped to the new
paths. Historical records — `docs/ux4g/` batch notes, the API→UI coverage
reports, the gap tracker and the feature roadmap — describe the tree when they
were written and are unchanged.

**Open decisions, recorded rather than taken:**

- **Sign-in branding (D12-9).** The sign-in screens are platform screens by
  function and carry Audit's branding; the shell may name no product. They stay
  where they are, listed under `PENDING` with the reason, until the platform's
  sign-in branding is decided. Nothing was redesigned or renamed.
- **Platform administration.** User, organisation and role management stay in
  `modules/audit/pages/admin/` because they render inside Audit's layout.
  Extracting a platform administration area is its own architectural decision.
- **The deploy of 12.3–12.5**, with the owner present.

**Verification** is recorded in the commit and the step report: the full
Vitest suite, lint, build, the backend checks that read frontend paths and
documentation, and the harness against the production 12.2 image.
