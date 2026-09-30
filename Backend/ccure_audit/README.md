# `ccure_audit` — Ccure Audit

The CCure core module that is already a product. Unlike Policy Pro and Rank,
**most of Audit's code does not live in this package yet**: it is in `core/`,
`engines/`, `scans/`, `orchestrator/`, `routers/`, `reporting/` and
`db/models/`, and Phase 16 moves it in one capability at a time. This package
holds the two boundary layers Phase 5 added in front of that code.
Architecture: `docs/architecture/PHASE5_AUDIT_INTEGRATION_BOUNDARIES.md` and
`docs/architecture/PHASE11_MODULE_FOLDERS.md`.

## Identity (owned by the platform)

| | |
|---|---|
| Registry key | `audit` |
| Database schema | `public`, shared with the platform's identity tables (`scripts/architecture/table_ownership.yaml` says which table is whose) |
| Route prefix | none — Audit's URLs predate the registry and are never renamed |
| Celery task names | existing names (`ccure.tasks.*`, `compliance.*`, …) never change; new ones take `ccure.audit.<name>` |
| Enabled | **yes** |
| Code owner | `@TODO-audit-team` in `.github/CODEOWNERS` for `Backend/ccure_audit/` — a placeholder until the project owner supplies the real team (decision D11-3). Audit's code outside this package falls to the catch-all owner until Phase 16 |
| Schema owner | `ccure_user`, the application's role — per-module roles are Phase 18's (decision D11-1) |
| Migration history | the unlabelled history in `Backend/alembic/versions/` |

## What is here

| Folder | Holds |
|---|---|
| `services/` | answers questions about Audit's data and returns **views** — frozen `@view` dataclasses of plain values, never ORM rows |
| `integration/` | the adapter that turns views into `ccure_contracts` messages. **Nothing in production imports it** until the integration phase (plan Phase 14) |
| `manifest.toml` | Audit's half of the registry. **Deliberately empty**: `main.py` still mounts Audit's routers and `core/celery_app.py` still lists its task modules, so declaring them here too would mount every router twice |

## Rules CI enforces

- **Phase 5 layers:** `integration-is-an-adapter` (the adapter imports only
  `ccure_contracts` and `ccure_audit.services`), `services-do-not-speak-contracts`,
  and `foundations-do-not-import-audit-module` (`core`, `engines`, `scans`,
  `orchestrator`, `db` and `auth` never import `ccure_audit`).
- **Other modules are private:** nothing in Audit, inside or outside this
  package, imports `ccure_policy` or `ccure_rank` (`module-is-private:*`); data
  from another module arrives through `ccure_contracts`.
- **Tables:** Audit's tables are registered to `audit` in `table_ownership.yaml`;
  no SQL in this package names a `policy_pro` or `rank` table
  (`tests/repo/test_module_boundaries.py`). That scan covers `ccure_audit/`
  only — Audit's code still outside it is not scanned until Phase 16 moves it
  in, so do not write such a query there either.

## Audit's migrations

The history has **several heads** since Phase 11.3 — Audit's, `policy_pro@head`
and `rank@head` — and `alembic_version` holds one row per head.

- A new Audit migration goes in `alembic/versions/` on Audit's own line:
  `alembic revision --head <Audit's head> -m "…"`. Find the head with
  `alembic heads`; it is the one without a branch label.
- Always `alembic upgrade heads`; roll back with `alembic downgrade <revision>@-1`.
- An Audit migration never touches the `policy_pro` or `rank` schemas.
- A merged migration reaches production at the next API start, which runs
  `alembic upgrade heads` — take a backup first (CLAUDE.md).
