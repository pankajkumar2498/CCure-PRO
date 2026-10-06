# Backend test suite

**Read [`../CLAUDE.md`](../../CLAUDE.md) before running this suite.** It
`TRUNCATE`s `organizations` and `users` `CASCADE`, and the live application
database is called `ccure_test` — a name that looks disposable and is not.
Three guards in [`conftest.py`](conftest.py) keep the run on the scratch
database; do not weaken them.

## Layout

Tests are grouped by the module they cover. The group a file sits in is the
answer to "what breaks if this fails".

| Group             | Covers                                                                                                                                                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth/`           | Login, MFA, password reset, mailbox verification, email-domain screening, the platform's own endpoints (`/platform/modules`)                                                                                                                                                                |
| `security/`       | RBAC route coverage, tenant isolation, organization lifecycle, CORS and security headers, file upload validation                                                                                                                                                                            |
| `compliance/`     | The policy compliance engine, framework activation and parking, and the per-catalogue suites                                                                                                                                                                                                |
| `scans/`          | Discovery and port phases, scope, progress, Celery tasks, OT probe safety, NVD sync                                                                                                                                                                                                         |
| `assets/`         | MAC normalisation, OUI lookup, device classification, IP resolution                                                                                                                                                                                                                         |
| `topology/`       | Network map API, client, graph engine, vendor quirks                                                                                                                                                                                                                                        |
| `credentialed/`   | Authenticated collection, version matching, package and process identity                                                                                                                                                                                                                    |
| `web/`            | The web-application scanning module                                                                                                                                                                                                                                                         |
| `reports/`        | PDF/CSV generation, layout limits, download access rules                                                                                                                                                                                                                                    |
| `repo/`           | Repository-wide invariants: documentation coverage, schema drift                                                                                                                                                                                                                            |
| `rbac/`           | The new RBAC capability (`ccure_platform/rbac/`, RBAC-1, dark): schema and triggers, the decision engine, catalogue sync, governance, shadow, independence, and a characterization that the legacy authorization is still the authority. Its fixtures live in `rbac_testing.py` — see below |
| `audit_boundary/` | The CCure Audit module's boundary layers (`ccure_audit/`): views, application services, integration mappers                                                                                                                                                                                 |

## Two rules the layout depends on

**The grouping directories carry no `__init__.py`, and must not gain one.**
As packages, `tests/auth` and `tests/scans` collide with Backend's own `auth`
and `scans` packages: pytest would name the module `auth.test_auth`, Python
would resolve `auth` to the application package, and every test in the group
would fail to import. Without the markers pytest imports each file under its
bare basename, so **test file basenames must stay unique across all groups**.

**Never spell a path as `os.path.dirname(os.path.dirname(__file__))`.** A
module's depth below `tests/` is no longer a constant, and that expression
silently resolves to `tests/` rather than `Backend/` — a confusing "file not
found" rather than an import error. Import the anchors instead:

```python
from testpaths import BACKEND_ROOT, SCRIPTS_DIR, REPO_ROOT
```

[`testpaths.py`](testpaths.py) derives them from its own location, which stays
directly in `tests/`. `conftest.py` puts this directory on `sys.path`, so the
import works from any group.

## Running

```powershell
pytest                             # the whole suite
pytest tests/compliance -v         # one group
pytest tests/repo/test_docs_integrity.py -v
```

## RBAC tests run in a transaction that is never committed

`tests/rbac/` imports `rbac_db` from [`rbac_testing.py`](rbac_testing.py) — a
session inside an outer transaction that is **always rolled back**. It is not a
`conftest.py` fixture on purpose: `test_schema_drift` does `import conftest`, and a
second `conftest.py` would replace the first in `sys.modules`.

The rollback is load-bearing. The `rbac_*` tables reference `organizations` and
`users` `ON DELETE RESTRICT`, and role history and roles refuse deletes outright,
so a row one of these tests _committed_ would make the suite's per-test purge
(`DELETE FROM organizations`, `DELETE FROM users`) fail in an unrelated test. Never
`commit()` in an RBAC test, and never use the committed `test_org` / `test_user`
fixtures with the `rbac_*` tables.

## Provisioning the disposable database

`test_development_reset.py` (and anything touching audit retention) needs the audit
chain and retention machinery, which the application role cannot create. On a fresh
scratch database a DBA applies, as a superuser:

    for f in bootstrap_chain bootstrap_chain_retention bootstrap_chain_retention_chained; do
      docker exec -i ccure-db psql -U postgres -d <scratch_db> -v ON_ERROR_STOP=1 \
        < Backend/scripts/audit/$f.sql
    done

Without them `audit_retention.retention_holds` does not exist and that test fails with
`UndefinedTable` — an environment gap, not a defect. Never run these against the live
database from a test setup.

## Route-policy tests and `ENV`

The gateway policy describes the **production** route set. `test_gateway_route_policy.py`
builds that application itself (it re-executes `main.py` once with `ENV=production`), so
it passes whether the session runs as `development` or `production`.

## Browser suite

Build exactly as `docs/ux4g/UX4G_STANDARD.md` says — `VITE_API_BASE_URL=/api npm run build`.
A build made with the developer's `Frontend/.env.local` calls `http://localhost:8000`,
which the harness's CSP blocks, and every page then lands on "Sign in".
