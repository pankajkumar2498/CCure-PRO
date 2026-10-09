# Database Migration Process

This backend uses Alembic for database migrations.

By default, development commands use `Backend/.env.test`, so migrations are created and tested against the development/test database. The real database in `Backend/.env` is used only when `APP_ENV=production` is set in the terminal.

## Environment Selection

| Mode | Env setting | Env file used | Typical database |
| --- | --- | --- | --- |
| Development | `APP_ENV` unset | `Backend/.env.test` | `ccure_test` |
| Production/main DB | `APP_ENV=production` | `Backend/.env` | `ccure_db` |
| Explicit override | `DATABASE_URL` set | Env file value ignored | Whatever `DATABASE_URL` points to |

## Development Workflow

Use this flow while changing SQLAlchemy models.

1. Open a terminal in the backend folder.

```powershell
cd Backend
```

2. Make sure production mode is not active.

```powershell
Remove-Item Env:APP_ENV -ErrorAction SilentlyContinue
```

3. Change your SQLAlchemy models.

Common location:

```text
Backend/db/models/
```

4. Generate a migration from model changes.

```powershell
alembic revision --autogenerate -m "describe your change"
```

5. Review the generated migration file.

Generated files are created in:

```text
Backend/alembic/versions/
```

Check both `upgrade()` and `downgrade()` before applying. Alembic can miss intent for renames, dropped columns, constraints, indexes, enums, and manual SQL changes.

6. Apply the migration to the development/test database.

```powershell
alembic upgrade heads
```

7. Run the app or tests and verify the change.

## Applying Reviewed Migrations To The Real Database

Only do this after the migration has been generated, reviewed, and tested against the development/test database.

1. Open a terminal in the backend folder.

```powershell
cd Backend
```

2. Switch this terminal session to production mode.

```powershell
$env:APP_ENV="production"
```

3. Apply the already-reviewed migrations.

```powershell
alembic upgrade heads
```

4. Clear production mode after finishing.

```powershell
Remove-Item Env:APP_ENV
```

## Important Rules

- Use `alembic revision --autogenerate` against the development/test database.
- Use `alembic upgrade heads` against the real database only after reviewing the generated migration.
- Do not edit `config.py` or `alembic/env.py` just to switch databases.
- Do not keep `APP_ENV=production` permanently set in your normal development terminal.
- If `DATABASE_URL` is set in the terminal, it overrides both `.env.test` and `.env`.

## Several Heads: Each Core Module Has Its Own Branch

Since Phase 11.3 the history is not a single line. Audit's revisions live in
`alembic/versions/`; Policy Pro's and Rank's live in `ccure_policy/migrations/`
(branch `policy_pro`) and `ccure_rank/migrations/` (branch `rank`), each with a
base revision that creates only its module's empty schema. `version_locations`
in `alembic.ini` lists the three folders once the branches are activated
(`python -m scripts.db.alembic_module_branches --status`).

- Always `alembic upgrade heads` / `alembic stamp heads`. `head` (singular)
  fails once there is more than one head.
- `alembic downgrade -1` is ambiguous with several heads. Name the branch or
  revision: `alembic downgrade rank@-1`, `alembic downgrade <revision>@-1`.
- A new module migration: `alembic revision --head <branch>@head -m "..."`.
  An Audit migration: `alembic revision --head <audit head> -m "..."`.
- `alembic_version` holds one row per head.

## Quick Command Reference

Development/test database:

```powershell
cd Backend
Remove-Item Env:APP_ENV -ErrorAction SilentlyContinue
alembic revision --autogenerate -m "your change"
alembic upgrade heads
```

Real/main database:

```powershell
cd Backend
$env:APP_ENV="production"
alembic upgrade heads
Remove-Item Env:APP_ENV
```
