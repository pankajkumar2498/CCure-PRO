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
alembic upgrade head
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
alembic upgrade head
```

4. Clear production mode after finishing.

```powershell
Remove-Item Env:APP_ENV
```

## Important Rules

- Use `alembic revision --autogenerate` against the development/test database.
- Use `alembic upgrade head` against the real database only after reviewing the generated migration.
- Do not edit `config.py` or `alembic/env.py` just to switch databases.
- Do not keep `APP_ENV=production` permanently set in your normal development terminal.
- If `DATABASE_URL` is set in the terminal, it overrides both `.env.test` and `.env`.

## Quick Command Reference

Development/test database:

```powershell
cd Backend
Remove-Item Env:APP_ENV -ErrorAction SilentlyContinue
alembic revision --autogenerate -m "your change"
alembic upgrade head
```

Real/main database:

```powershell
cd Backend
$env:APP_ENV="production"
alembic upgrade head
Remove-Item Env:APP_ENV
```
