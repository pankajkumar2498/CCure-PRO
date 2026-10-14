# RBAC foundation (RBAC-1, RBAC-2, RBAC-3)

> **Historical (superseded).** The status below describes RBAC-1…RBAC-3, when the capability
> was dark or shadow-only beside a legacy check. Platform RBAC has been the **only**
> authorization model since RBAC-8, and the legacy tables were removed on 4 Oct 2026
> (`d4f8b2c6e0a1`; `backups/native_clean_reset_20261004/final-report.md`). Current state:
> `CLAUDE.md`, "RBAC capability".

**Status: dark.** RBAC-1 built the independent RBAC capability and wired it to
nothing; RBAC-2 populated its permission catalogue and role model and mapped every
legacy atom onto them (§10, and [RBAC_PERMISSION_CATALOG.md](RBAC_PERMISSION_CATALOG.md)).
**RBAC-2 is prepared, not live.** **RBAC-3 is shadow only** — the new engine is compared beside the legacy check, off by default, and changes no outcome; legacy authorization remains authoritative (the retired RBAC-3 shadow-authorization design (removed in RBAC-8; see [RBAC_CUTOVER.md](RBAC_CUTOVER.md))). The legacy authorization — `users.role_id`, `roles`, `permissions`,
`role_permissions`, `require_permission`, `require_role`, `user_has_permission` and
the frontend `can()` — is **still the only authority**. No route, no `/auth/me`
field, no frontend behaviour, no role assignment, no registration flow and no
permission changed. This document records what was built and the design it
implements (RBAC-0, frozen); it must not be read as describing live authorization.

Code: `Backend/ccure_platform/rbac/` · tables: `Backend/ccure_platform/models/rbac_tables.py`
· migrations `a7c1e5b3d9f2` (RBAC-1) and `b8d2f6a4c0e1` (RBAC-2) · catalogue: `ccure_platform/permissions.py`, `ccure_audit/permissions.py` · golden mapping: `Backend/data/rbac/golden_legacy_mapping.json` · tests: `Backend/tests/rbac/`, `tests/repo/test_rbac_*`,
`tests/modules/example/test_rbac_onboarding.py` · schema: [DATABASE_SCHEMA.md](../DATABASE_SCHEMA.md).

## 1. Ownership and independence

> RBAC is an independently usable CCure Platform capability. It is module-agnostic
> and exposes stable APIs/contracts consumed by Audit, Policy Pro, Rank and IR.

`ccure_platform.rbac` owns permission registration, roles, role assignments,
effective-permission resolution, authorization decisions, scope evaluation, RBAC
governance, RBAC audit and role lifecycle. **Audit, Policy Pro, Rank and IR own none
of it**; each owns only the permissions it _declares_.

```
Module ──imports──▶ ccure_platform.api ──▶ RBAC contract / engine ──▶ platform tables
                    (PermissionDecl, authorize, can,
                     effective_permissions, require)
```

The dependency never runs the other way. RBAC imports no product (`ccure_audit`,
`ccure_policy`, `ccure_rank`, `ccure_contracts`), no Audit router, model, service or
table, does not read the module registry, and does not import `ccure_platform.api`.
Enforced by three layer rules in `scripts/architecture/layer_rules.py` —
`rbac-is-module-agnostic`, `modules-use-rbac-api-only`, `rbac-tables-are-private` —
plus `no-module-decision-engine` and the table checks in
`tests/repo/test_rbac_boundaries.py`, and proven by a **poisoned-import test**
(`tests/rbac/test_rbac_independence.py`): in a fresh interpreter where importing any
product module raises, the whole capability still loads and decides.

One transitive dependency is out of RBAC's hands: _emitting_ an audit event goes
through the platform audit log, which loads each enabled module's audit-event
definitions by name to classify severity (`audit_log/taxonomy.py`). RBAC's engine,
resolver, governance and catalogue do not touch it.

## 2. The module registration seam

```
module manifest.toml (permission_modules)
        ▼
permission declarations — `PERMISSIONS = (PermissionDecl(...), ...)` — as data
        ▼
composition root: ccure_platform/composition.py  (reads the registry, loads by name)
        ▼
rbac.catalogue.sync(sources)  ▶  rbac_permissions / rbac_role_permissions
```

- A module's **permission namespace** (`audit`, `policy`, `rank`; `ir` reserved for
  the service; `platform` the platform's) is part of the platform-owned identity in
  `ccure_platform/modules/registry.py`. A module cannot pick another's. A product's
  namespace is reserved from the day it is registered, enabled or not.
- `permission_modules` in a module's `manifest.toml` lists the dotted modules that
  declare its catalogue (RBAC-2: `ccure_audit/permissions.py` for Audit; Policy Pro and
  Rank declare nothing, and the platform's own is `ccure_platform/permissions.py`).
- RBAC validates **generic** rules only: the three-segment grammar, that the key's
  first segment is the declaring namespace, no duplicates, valid scope metadata,
  valid role references. It knows no product by name.
- **No silent fallback.** A declaration module that cannot load, exports no
  `PERMISSIONS`, or declares something invalid stops the whole sync with every
  problem listed, and nothing is written.
- The sync writes in the caller's transaction (it never commits): new permissions
  inserted, changed metadata updated, an undeclared permission **deprecated** (never
  deleted, still honoured where granted), code-managed system roles reconciled to
  their `default_grants`, auto-grant roles given every active permission as rows,
  every changed role given a revision. A retired role is skipped and reported,
  never resurrected.

Nothing calls the sync at start-up, deliberately: a failure there would stop the API
for a capability that is still dark. The catalogue is applied by the operator script
`scripts/rbac/sync_catalogue.py` (a dry run unless `--apply`; it validates before it
writes). Wiring it into start-up is a later phase.

## 3. Role identity and lifecycle

A role has `id` (immutable DB identity, the target of every FK), `key` (immutable
technical handle: `platform.<slug>`, `custom.platform.<slug>`,
`custom.<org_id>.<slug>`) and `display_name` (mutable label, audited).

**Neither `key` nor `display_name` is ever an authorization input.** The decision
function `engine.decide(principal, grants, catalogue, permission_key, scope)` is
handed _grants_ — `Grant` has no role field — so it cannot learn which role granted
what, let alone what the role is called. The resolver walks role rows only as a join
path to permission keys. Repository ratchets (`scripts/architecture/rbac_guardrails.py`,
`tests/repo/test_rbac_role_identity.py`) hold it: **zero** role-identity decisions in
the new implementation; the legacy code's 40 sites (22 files) may only fall until
RBAC-4 removes them.

Lifecycle `active → retiring → retired` (and reactivation), enforced by a trigger and
mirrored in `governance.validate_transition`. A retiring role stays effective (no
outage); a retired role grants nothing and is never deleted — there is no hard-delete
path. Rows referencing it are `ON DELETE RESTRICT`; `rbac_role_revisions` is
append-only. The destructive lifecycle operations (rename, retire, replace) are
**not implemented** — RBAC-7 builds them on the primitives in `governance.py`.

- "Rename Superadmin to CISO" = edit `display_name` of `platform.superadmin`; no
  authorization behaviour changes (a fuzz test proves it).
- "Replace Superadmin" = create a new role, migrate assignments, verify continuity,
  retire the old one; the engine does not change.

## 4. Superadmin is permissions plus scope

There is no wildcard and no request-time "if superadmin then allow". A role that
holds everything holds **materialised grants**: `auto_grant_new_permissions` (a
platform-scope-only flag) is read by catalogue sync, which inserts the rows. The
engine reads rows, never the flag.

## 5. Scope

Organisation-scope grants apply only to their organisation. A platform-scope grant
applies in the principal's own organisation, and in another only with a
platform-scope `platform.organization.switch` — a clarification of RBAC-0 §5 (home
organisation is implicit; the switch is for every other). Naming two different
organisations is denied. **Holding a permission never reaches another tenant by
itself.** Tenant isolation (query filters, scan scope, quotas) is not part of this
work and is untouched.

## 6. Governance foundation

`governance.py` holds the pure primitives later phases call, so no endpoint
re-implements them: the **escalation ceiling** (an actor cannot grant what they do not
hold, computed from the same grants the engine uses), assignment and role-definition
checks (no self-assignment, no cross-organisation assignment, system roles immutable,
organisation roles hold only delegable organisation-scope permissions, no
self-modification), lifecycle validation, the **retirement gate** (no live
assignments, not a configured default, no continuity regression), and the **default
role** safety rules.

**Continuity** is capability-based: every frozen continuity key
(`platform.role.assign_platform`, `platform.role.create_platform`,
`platform.user.assign_role`, `platform.organization.create`) needs an active,
verified human holder at platform scope, and each active organisation needs a holder
of `platform.user.assign_role`. When nothing is declared the report is
`not_assessable` — **never `ok`**.

## 7. Migration and shadow

`rbac_legacy_map` (temporary; dropped in RBAC-8) mirrors the golden mapping in the
database; the comparison itself reads the golden file (`golden_legacy_mapping.json`),
the one source. **RBAC-3 runs the comparison**: `shadow_runtime` hands each legacy
permission check's decision to `shadow.shadow_compare`, which evaluates the new engine
and reports MATCH, MISMATCH, NOT_COMPARABLE or ERROR. **The new decision never
controls a request** — the hook returns nothing and cannot raise, runs on its own
read-only session, and is off unless `RBAC_SHADOW_MODE=observe`. Architecture, result
classifications, failure behaviour, configuration, privacy rules, the scope-deferred
cases, the RBAC-2 equivalence results and the RBAC-4 prerequisites are in
the retired RBAC-3 shadow-authorization design (removed in RBAC-8; see [RBAC_CUTOVER.md](RBAC_CUTOVER.md)). Turning role-name
checks into permissions is RBAC-4.

## 8. Configuration

The self-registration role is configured in `rbac_default_roles`, seeded to Viewer
so behaviour is unchanged; the registration flow does not read it yet. Display names
are global in v1; per-organisation presentation overrides are deferred and would be
additive presentation metadata, not an engine change.

## 9. Follow-ups RBAC-1 left, and where they went

- **User purge** — resolved in RBAC-2 (§10.3).
- **Audit attribution of platform-wide events** — resolved in RBAC-2 (§10.4).
- The catalogue was empty until RBAC-2, so the continuity report and the shadow map
  said "not assessable" and "not mapped" rather than answer. They can answer now.

## 10. RBAC-2: the catalogue and the role model

RBAC-2 is **prepared, not live**: the legacy tables and checks are untouched and
authoritative, no route uses the new engine, `/auth/me`, the frontend and the
registration flow are unchanged, no user is assigned to a new role, and nothing
populates the tables until an operator applies the catalogue.

### 10.1 The catalogue

67 permissions: 30 `platform.*` (declared in `ccure_platform/permissions.py`) and
37 `audit.*` (declared in `ccure_audit/permissions.py`), through the module
registration seam. Policy Pro, Rank and IR keep their namespaces reserved and declare
nothing. Every key — owner, scope, sensitivity, delegation, continuity, legacy source
and the reason it exists — is in [RBAC_PERMISSION_CATALOG.md](RBAC_PERMISSION_CATALOG.md).
The catalogue is **capability-level** and **derived from what the code enforces**, not
from the old vocabulary: the 17 dashboard routes are one permission; the generic
`settings:update`, which gated two unrelated things, became `audit.asset.import_amt`
and `audit.remediation.manage_sla`; thirteen role-name checks became permissions
(`platform.organization.switch`, `platform.user.move_org`, the email-domain and
vulnerability-feed administration, …) held only by the superadmin role.

### 10.2 Legacy → new, and how it is proven

66 legacy atoms — the 65 seeded and `audit_logs:read`, which exists only on the live
database and which no code reads — each end in exactly one status: **50 mapped, 6
replaced, 10 retired**. The ten retired atoms have no route, task or screen
requiring them (a test searches the source), so no role loses anything any code
checks. `rbac_legacy_map` now carries `status` and `reason`, so a retired atom is
**preserved** as a keyless row instead of dropped.

The mapping is data (`golden_legacy_mapping.json`) checked three independent ways:
internally consistent and complete (`legacy_map.validate_golden`); each role's set
**recomputed** from its legacy role (`derive_role_grants`: a key is held when all the
atoms it derives from are); and equal to the declarations' `default_grants`. Run
through the real shadow comparator in a rolled-back test, the new decision matches the
legacy one for all five roles and all 56 enforced atoms.

### 10.3 User purge

`purge_user` hard-deletes an account and `rbac_user_roles.user_id` is
`ON DELETE RESTRICT`. `ccure_platform/rbac/offboarding.py` registers an `rbac` hook
with the platform's offboarding contract (imported by the administration module that
holds the purge route). Before the user row is deleted it records each assignment in
the audit trail — role id, key and the display name _at that moment_, scope, grantor,
whether it was live — and removes the row. Role history is untouched and the foreign
key is **not weakened**: deleting a user who still has assignments any other way is
still refused.

### 10.4 Audit attribution

`audit_logs.org_id` is NOT NULL, the table is hash-partitioned on it, and the chain is
per organisation, so an event no organisation owns cannot be written there without
borrowing an organisation or inventing a pseudo-tenant — both a false statement in a
trail. The rule: **the event says who owns it, the emitter never guesses, and an event
with no owner goes to the platform's own ledger.**

- an event with an owning organisation → `audit_logs` in that organisation: a role of
  one organisation; an organisation-scope assignment; a platform-scope assignment
  (owned by the **member's own** organisation — the tenant whose person's access
  changed); a user purge;
- an event with no owner → `platform_audit_events`: a catalogue sync, a permission's
  lifecycle, a system or platform-scope role, the default role changing.

`EventDraft.org_id` is set explicitly by whoever builds the draft and defaults to
nothing; `emit` routes by it (`rbac/audit.py`), and `writer.log_platform_event` is the
second write path of the same audit service. The ledger has no owner column to fill
with a guess, records the actor's organisation only as information, and is append-only
(trigger) but **not hash-chained** — extending the per-organisation chain is a
privileged DBA bootstrap and a separate, reviewed step; recorded as a limit.

### 10.5 Lifecycle and custom roles

`governance.transition_role` moves a role along `active → retiring → retired` (and
back) behind the retirement gate and leaves history: the database refuses a state
change that does not advance the revision in the same statement, so a role cannot
retire or reactivate silently. `governance.define_custom_org_role` creates a custom
organisation role holding only delegable organisation-scope permissions the creator
holds. Both are internal primitives; there is no endpoint until RBAC-7.
