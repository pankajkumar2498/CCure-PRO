# RBAC foundation (RBAC-1)

**Status: dark.** RBAC-1 builds the independent RBAC capability and wires it to
nothing. The legacy authorization — `users.role_id`, `roles`, `permissions`,
`role_permissions`, `require_permission`, `require_role`, `user_has_permission` and
the frontend `can()` — is **still the only authority**. No route, no `/auth/me`
field, no frontend behaviour, no role assignment, no registration flow and no
permission changed. This document records what was built and the design it
implements (RBAC-0, frozen); it must not be read as describing live authorization.

Code: `Backend/ccure_platform/rbac/` · tables: `Backend/ccure_platform/models/rbac_tables.py`
· migration `a7c1e5b3d9f2` · tests: `Backend/tests/rbac/`, `tests/repo/test_rbac_*`,
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
  declare its catalogue (empty for every real module until RBAC-2).
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

Nothing calls the sync at start-up yet; RBAC-2 does, with the finalised catalogue.

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

## 7. Migration and shadow intent

`rbac_legacy_map` (temporary; dropped in RBAC-8) maps legacy role names and
`resource:action` atoms onto the new vocabulary. `shadow.shadow_compare` evaluates
the new engine beside a legacy verdict and reports match / mismatch / not_mapped /
error. **The new decision never controls a request**, and shadowing cannot break the
request it observes (a savepoint and a `try`). RBAC-1 wires it to nothing; a test
fails if anything does. Turning it on is RBAC-3.

## 8. Configuration

The self-registration role is configured in `rbac_default_roles`, seeded to Viewer
so behaviour is unchanged; the registration flow does not read it yet. Display names
are global in v1; per-organisation presentation overrides are deferred and would be
additive presentation metadata, not an engine change.

## 9. Known follow-ups (not defects of RBAC-1)

- **User purge.** `purge_user` hard-deletes a user. `rbac_user_roles.user_id` is
  `ON DELETE RESTRICT`, so once assignments exist (RBAC-2's backfill) a purge hook
  must be registered (`register_user_purge_hook`). No assignment row exists in
  production now.
- **Audit attribution of platform-wide events** (`audit_logs.org_id` is NOT NULL) is
  open; `emit` and the sync refuse to guess, and the sync writes events only when
  given an organisation.
- The catalogue is empty until RBAC-2, so the continuity report and the shadow map
  have nothing to measure yet; both say so rather than answer.
