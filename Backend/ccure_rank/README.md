# `ccure_rank` — Ccure Rank

A CCure core module, owned by the Ccure Rank team. **Nothing is built here
yet**: Phase 11 of the modular-platform programme created the structure, the
registration and the guardrails, and the team builds the module.
Architecture: `docs/architecture/CCURE_PLATFORM_MODULAR_ARCHITECTURE.md` §3.3–3.4,
and `docs/architecture/PHASE11_MODULE_FOLDERS.md`.

## Identity (owned by the platform)

| | |
|---|---|
| Registry key | `rank` |
| Database schema | `rank` |
| Route prefix | `/rank` (through the gateway: `/api/rank`) |
| Celery task names | `ccure.rank.<name>` |
| Permission resource | `rank` |
| Enabled | **no** — turning the module on is a platform change in `ccure_platform/modules/registry.py` |

## What goes where

| Folder | Holds |
|---|---|
| `api/` | FastAPI routers |
| `models/` | SQLAlchemy models, on a `MetaData(schema="rank")` of this module's own |
| `schemas/` | this module's request/response models (contracts with other modules are `ccure_contracts`) |
| `services/` | application logic, transactions, persistence |
| `repositories/` | data access to this module's own tables |
| `manifest.toml` | what the module contributes: `routers`, `task_modules`, `models` |

Tests live in `Backend/tests/modules/rank/` — inside `Backend/tests/`, so the
suite's database-safety guards apply to them.

## Adding a route, a table, a migration, a task

All inside this folder; `Backend/tests/modules/example/` shows each one end to end.

1. **Route** — an `APIRouter` in `api/`; add `"ccure_rank.api.<file>:router"` to
   `routers` in `manifest.toml`. It is mounted under `/rank`.
   A new route also needs, in the same commit: the gateway route policy
   regenerated (`python -m scripts.gateway.route_policy`), entries in `docs/`
   (`test_docs_integrity.py`), and a rate-limit decision (CLAUDE.md, "Rate limiting").
2. **Table** — a model on this module's `MetaData(schema="rank")` in `models/`; add
   `"ccure_rank.models.<file>:metadata"` to `models`, and register the table as
   `rank.<table>: {owner: rank, capability: …}` in
   `scripts/architecture/table_ownership.yaml`.
3. **Migration** — in `migrations/`, this module's own Alembic branch
   (`rank`, base revision `rank_0001`, which creates the empty `rank`
   schema). `alembic revision --head rank@head -m "…"` adds the next one.
   Every table operation passes `schema="rank"`, and no SQL names another
   schema. No migration creates a role, grants, revokes or changes an owner:
   module roles are Phase 18's (decision D11-1), and `ccure_user` could not
   run one anyway, so the API would fail to start.
   `tests/repo/test_alembic_module_branches.py` checks all three.
4. **Task** — `celery.shared_task(name="ccure.rank.<name>")` in a module listed
   under `task_modules`. It runs on the `default` queue; a dedicated queue is a
   platform change made with the team.

## Rules CI enforces

- **Imports:** this package may import only itself, `ccure_platform.api`,
  `ccure_contracts`, `db.base` and third-party libraries. Never another
  module's code (`ccure_audit`, `ccure_policy`, `ccure_rank`, or Audit's `core`,
  `engines`, `scans`, `routers`, `reporting`, `db.models`, …), and nothing may
  import this package (`layer_rules`: `module-isolation:*`).
- **Tables:** only in schema `rank`, each registered to `rank`; no SQL naming another
  module's table (`tests/repo/test_module_boundaries.py`).
- **Tests:** tests that import this package live in `tests/modules/rank/`.
