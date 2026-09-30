# `tests/modules/` — each core module's own tests (Phase 11)

| Folder | Owner | Holds |
|---|---|---|
| `policy_pro/` | Ccure Policy (Policy Pro) team | tests of `ccure_policy` |
| `rank/` | Ccure Rank team | tests of `ccure_rank` |
| `example/` | platform (test infrastructure) | the **test-only** proof module `fixture/ccure_example` and the test proving a module can add a route, a table, a migration and a task inside its own folder |

Rules (enforced by `tests/repo/test_module_boundaries.py`):

- A test that imports a module package lives in that module's folder here.
  `tests/repo/` is the one exception: the guardrails inspect every module.
- These folders are inside `Backend/tests/` on purpose: `tests/conftest.py`'s
  database-safety guards apply only to tests collected here.
- The general test-layout rules still hold (`Backend/tests/README.md`,
  CLAUDE.md): **no `__init__.py`** in a group folder, and **test file basenames
  unique across the whole suite**.
- `example/fixture/ccure_example` is never an application package and is never
  registered in production. It is not Policy Pro or Rank functionality.
