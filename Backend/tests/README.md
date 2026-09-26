# Backend test suite

**Read [`../CLAUDE.md`](../../CLAUDE.md) before running this suite.** It
`TRUNCATE`s `organizations` and `users` `CASCADE`, and the live application
database is called `ccure_test` — a name that looks disposable and is not.
Three guards in [`conftest.py`](conftest.py) keep the run on the scratch
database; do not weaken them.

## Layout

Tests are grouped by the module they cover. The group a file sits in is the
answer to "what breaks if this fails".

| Group           | Covers |
|-----------------|--------|
| `auth/`         | Login, MFA, password reset, mailbox verification, email-domain screening |
| `security/`     | RBAC route coverage, tenant isolation, organization lifecycle, CORS and security headers, file upload validation |
| `compliance/`   | The policy compliance engine, framework activation and parking, and the per-catalogue suites |
| `scans/`        | Discovery and port phases, scope, progress, Celery tasks, OT probe safety, NVD sync |
| `assets/`       | MAC normalisation, OUI lookup, device classification, IP resolution |
| `topology/`     | Network map API, client, graph engine, vendor quirks |
| `credentialed/` | Authenticated collection, version matching, package and process identity |
| `web/`          | The web-application scanning module |
| `reports/`      | PDF/CSV generation, layout limits, download access rules |
| `repo/`         | Repository-wide invariants: documentation coverage, schema drift |
| `audit_boundary/` | The CCure Audit module's boundary layers (`ccure_audit/`): views, application services, integration mappers |

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
