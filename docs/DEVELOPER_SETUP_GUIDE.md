# Developer Setup Guide

**CCure-Audit-PRO** — getting a working development environment, verified against
the repository's actual scripts, Dockerfiles, CI workflow and configuration files.

> Every command below exists in this repository or is a standard invocation of a
> tool the repository declares as a dependency. Nothing is aspirational.

---

## 1. Prerequisites

| Requirement             | Version                                | Why                                                                                                                                                  |
| ----------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Python**              | **3.11** (host worker) / **3.12** (CI) | The Backend image is `python:3.11-slim`; the `start_host_scanner_worker.ps1` error message says `py -3.11 -m venv .venv`; GitHub Actions uses `3.12` |
| **Node.js**             | **20** (image) / **22** (CI)           | `Frontend/Dockerfile` uses `node:20-slim`; CI's `setup-node` pins `22`                                                                               |
| **npm**                 | Bundled with Node                      | `package-lock.json` is committed; CI uses `npm ci`                                                                                                   |
| **PostgreSQL**          | 15 (container) or 18 (host)            | Compose ships `postgres:15-alpine`; the reference host deployment runs PostgreSQL 18                                                                 |
| **Redis**               | 7                                      | `redis:7-alpine` — Celery broker, result backend and Pub/Sub                                                                                         |
| **Docker + Compose v2** | current                                | The `docker compose` (space) form is used throughout                                                                                                 |
| **Nmap**                | any recent                             | Phase 2/3 port and service scanning. Optional — PortEngine falls back to async TCP connect                                                           |
| **Npcap**               | current                                | **Windows only.** Scapy cannot open raw sockets without it, which disables ARP/ICMP/SYN discovery                                                    |
| **Git**                 | any                                    |                                                                                                                                                      |

Optional external binaries — each absent tool is a **coverage gap, not an error**,
except Nuclei in the DAST pipeline where it is essential:

| Tool                | Used by                             | Install                                                |
| ------------------- | ----------------------------------- | ------------------------------------------------------ |
| `nuclei`            | Network `nuclei_probe`, DAST DETECT | https://github.com/projectdiscovery/nuclei/releases    |
| `subfinder`         | DAST RECON                          | https://github.com/projectdiscovery/subfinder/releases |
| `ffuf`              | DAST CRAWL                          | https://github.com/ffuf/ffuf/releases                  |
| `sqlmap`            | DAST DETECT                         | pip (`sqlmap>=1.9` is in `requirements.txt`)           |
| Playwright Chromium | DAST CRAWL                          | `playwright install chromium`                          |

After installing Nuclei, fetch its templates once:
`nuclei -update-templates -ud <dir>` (~13 510 templates when fully installed).

---

## 2. Repository layout

```
CCure-Audit-PRO/
├── Backend/            FastAPI application, engines, Celery tasks, Alembic
│   ├── .env            ← the file config.py loads (git-ignored)
│   ├── .env.example    Annotated template
│   ├── requirements.txt
│   ├── alembic.ini · alembic/versions/  (32 revisions)
│   ├── scripts/        seeds · admin · verification · vuln feeds · compile_docs.py
│   └── tests/          57 modules incl. test_docs_integrity.py
├── Frontend/           React 18 + Vite SPA
│   ├── .env.local      VITE_API_BASE_URL
│   └── package.json
├── docs/               This documentation set
├── nginx/gateway.conf  Reverse-proxy config for the compose gateway
├── scripts/            backup_db.ps1 · install_backup_schedule.ps1 ·
│                       install_feed_schedule.ps1 · start/stop_host_scan_stack.ps1 ·
│                       docker-postgres-init.sql · host-nginx/
├── .env                docker-compose variables ONLY (git-ignored)
├── .env.example        Template for the above
├── docker-compose.yml
├── .pre-commit-config.yaml
└── .github/workflows/ci.yml
```

> **CAUTION — two `.env` files, two audiences.** `Backend/config.py` loads
> **`Backend/.env`**. The repository-root `.env` is consumed by docker-compose
> only. A token placed in the root file is silently ignored by every Python script
> in `Backend/`, and vice versa.

---

## 3. Path A — Docker Compose (fastest start)

### 3.1 Configure

```bash
cp .env.example .env
cp Backend/.env.example Backend/.env
```

Compose refuses to start without five variables, each declared `${VAR:?message}`:

| Variable                    | Set in      | Note                                                                                        |
| --------------------------- | ----------- | ------------------------------------------------------------------------------------------- |
| `POSTGRES_USER`             | root `.env` |                                                                                             |
| `POSTGRES_PASSWORD`         | root `.env` |                                                                                             |
| `POSTGRES_DB`               | root `.env` |                                                                                             |
| `MFA_ENCRYPTION_KEY`        | root `.env` | `python -c "import secrets; print(secrets.token_urlsafe(48))"` — never change it afterwards |
| `COMPLIANCE_ENCRYPTION_KEY` | root `.env` | **Must match `Backend/.env`** on the host scanner worker                                    |

> **CAUTION:** `COMPLIANCE_ENCRYPTION_KEY` was previously defaulted to empty. The
> API then encrypted stored credentials under the fallback key hardcoded in
> `core/security_crypto.py` while the host worker decrypted with the real key from
> `Backend/.env`, so every credentialed scan failed with _"Invalid encrypted
> payload or authentication tag"_ and silently completed as an unauthenticated
> audit. Changing the key also makes credentials encrypted under the old key
> unreadable — re-enter stored credentials after setting it.

Two routing switches in the root `.env` deserve attention:

| Variable                | Values                         | Meaning                                                                                          |
| ----------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------ |
| `DATABASE_HOST`         | blank / `host.docker.internal` | Blank → the containerized `db`. `host.docker.internal` → a native PostgreSQL on the Windows host |
| `POSTGRES_PORT_BINDING` | `5432` / `5433`                | Use `5433` if a native PostgreSQL already owns 5432                                              |

### 3.2 Start

```bash
docker compose up -d                       # redis, db, api, frontend, gateway
docker compose --profile container-scanner up -d   # + worker and web-worker
```

The scanner workers sit behind the `container-scanner` profile because raw-socket
discovery and Nmap need direct access to the physical network. The supported
production layout runs the scanner worker on the host instead (§5).

`api` runs `Backend/start.sh`, which executes
`python db/migrate_production_schema.py` — Alembic migrations plus RBAC and
default-org seeding — before launching uvicorn with `--proxy-headers
--forwarded-allow-ips='*'`.

### 3.3 Verify

```bash
docker compose ps
curl -s http://127.0.0.1:8000/ | head           # system info
curl -s http://127.0.0.1:8000/api/pipeline-modes
docker compose logs -f api
```

| Surface           | URL                                                                      |
| ----------------- | ------------------------------------------------------------------------ |
| API               | `http://127.0.0.1:8000`                                                  |
| Swagger UI        | `http://127.0.0.1:8000/docs` (**disabled when `ENV=production`**)        |
| ReDoc             | `http://127.0.0.1:8000/redoc`                                            |
| OpenAPI JSON      | `http://127.0.0.1:8000/openapi.json`                                     |
| Frontend (direct) | `http://127.0.0.1:3200`                                                  |
| Gateway (opt-in)  | `http://127.0.0.1:${GATEWAY_PORT:-8082}` — needs `--profile alt-gateway` |

### 3.4 Rebuild rules

| Change                                                                            | Action                                                                                                      |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Python under `Backend/`                                                           | `docker compose restart api` — `./Backend` is bind-mounted                                                  |
| JSX/CSS under `Frontend/src/`                                                     | `docker compose build frontend && docker compose up -d --no-deps frontend` — assets are baked at build time |
| `VITE_API_BASE_URL`                                                               | Same as above; Vite inlines it at build time                                                                |
| `requirements.txt`                                                                | `docker compose build api worker web-worker`                                                                |
| Anything under `core/`, `scans/`, `orchestrator/` while using the **host** worker | Restart the host worker (§5)                                                                                |

---

## 4. Path B — Local development without containers

### 4.1 Backend

```powershell
cd Backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1        # Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Then create `Backend/.env` from `Backend/.env.example` and set at minimum
`DATABASE_URL`, `MFA_ENCRYPTION_KEY`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`.

Initialise the database (migrations + RBAC + default org):

```bash
python db/migrate_production_schema.py
```

Run the API:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
# or, equivalently for a one-off:
python main.py            # __main__ block runs uvicorn on 0.0.0.0:8000
```

Run a worker:

```bash
celery -A core.celery_app worker --loglevel=info \
       --queues=scanner,default,compliance --concurrency=20 --prefetch-multiplier=1

celery -A core.celery_app worker --loglevel=info \
       --queues=web_recon,web_crawl,web_dast,web_audit --concurrency=4 --prefetch-multiplier=1
```

Celery Beat (compliance schedules and log pruning):

```bash
celery -A core.celery_app beat --loglevel=info
```

> **IMPORTANT:** Raw-socket discovery needs elevation. Run the worker as
> root (Linux/macOS) or from an **elevated** PowerShell (Windows, with Npcap
> installed). Without privileges `can_raw` is false and Phase 1 falls back to TCP
> connect only.

### 4.2 Frontend

```bash
cd Frontend
npm install                 # or `npm ci` to honour package-lock.json exactly
npm run dev                 # http://localhost:3000
```

`vite.config.js` proxies eleven prefixes to `http://localhost:8000`: `/auth`,
`/scan`, `/scans`, `/web-scans`, `/reports`, `/admin`, `/dashboard`, `/assets`,
`/findings`, `/notifications`, `/topology`.

> **NOTE:** `/user`, `/compliance` and `/api` are **not** proxied. Set
> `VITE_API_BASE_URL=http://localhost:8000` in `Frontend/.env.local` so profile,
> preferences, session, compliance and NVD-admin calls reach the backend.

---

## 5. Host scanner worker (Windows)

The reference production layout runs the scanner worker outside Docker so Scapy
and Nmap get raw-socket access to the physical network.

```powershell
.\Backend\scripts\scan\start_host_scanner_worker.ps1
.\Backend\scripts\scan\start_host_scanner_worker.ps1 -Force   # replace a running worker
```

The script requires `Backend\.venv\Scripts\python.exe` and **refuses to start a
second worker** on the `scanner` queue. Two workers on one queue is a real hazard:
tasks go to whichever grabs them first, and if the two were started from different
working directories they can be running different code — so editing `Backend/` and
restarting "the" worker would silently leave the other serving stale code. The
guard counts only top-level Celery processes, because a single worker also shows a
child `python.exe` under the venv's base interpreter.

Whole-stack helpers:

```powershell
.\scripts\start_host_scan_stack.ps1
.\scripts\stop_host_scan_stack.ps1
```

Restart the host worker after changing anything under `core/`, `scans/` or
`orchestrator/`.

---

## 6. Environment variables

Read by `Backend/config.py`. `_selected_env_file()` picks `Backend/.env.test` when
`APP_ENV` is `test`/`testing` and that file exists, otherwise `Backend/.env`,
otherwise `.env.test`. `SKIP_DOTENV_LOAD` disables loading entirely.

### Application

| Variable                          | Default                                                 | Effect                                                                                 |
| --------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `APP_ENV` / `ENVIRONMENT` / `ENV` | `development`                                           | `production` disables `/docs`, `/redoc`, `/openapi.json` and hard-fails a weak JWT key |
| `LOG_LEVEL`                       | `INFO`                                                  |                                                                                        |
| `LOG_FORMAT`                      | `text`                                                  | `json` switches to single-line JSON records                                            |
| `ACCESS_LOG_LEVEL`                | `WARNING`                                               | uvicorn access logger                                                                  |
| `TRUSTED_PROXIES`                 | `127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Client-IP resolution for audit logs and rate limiting                                  |
| `CORS_ALLOW_ORIGINS`              | six localhost origins                                   | Comma-separated                                                                        |
| `FRONTEND_URL`                    | `http://localhost:3000`                                 | Base for password-reset links                                                          |
| `PORT`                            | `8000`                                                  | Read by `start.sh`                                                                     |
| `RELOAD`                          | `false`                                                 | `true` runs uvicorn with `--reload`                                                    |

### Database

| Variable                                              | Default                                | Effect                                                                                                  |
| ----------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                        | `sqlite:///Backend/ccure_users.db`     | PostgreSQL enables pool tuning: `pool_pre_ping`, `pool_size=10`, `max_overflow=20`, `pool_recycle=3600` |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | —                                      | Compose-only; required                                                                                  |
| `DATABASE_HOST`                                       | `db`                                   | Compose routing switch                                                                                  |
| `POSTGRES_PORT_BINDING`                               | `5433`                                 | Host bind for the `db` container                                                                        |
| `TEST_DATABASE_URL`                                   | pinned to `ccure_pytest_db` in compose | See §9                                                                                                  |

### Vulnerability intelligence

| Variable                                                                            | Default                                                | Effect                                                    |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------- |
| `VULNERABILITY_INTEL_DATABASE_URL`                                                  | —                                                      | Explicit URL; always wins                                 |
| `VULN_DB_HOST` / `_PORT` / `_NAME` / `_USER` / `_PASSWORD`                          | `localhost` / `5432` / `ccure_test` / `ccure_user` / … | Setting **any** of these selects the dedicated database   |
| `PGHOST` / `PGPORT` / `PGDATABASE` / `PGUSER` / `PGPASSWORD`                        | —                                                      | Fallbacks for the above                                   |
| `NVD_API_KEY`                                                                       | —                                                      | Raises the NVD rate limit                                 |
| `VULNCHECK_API_TOKEN`                                                               | —                                                      | Required by `sync_vulncheck.py`, which exits 2 without it |
| `CCURE_FEED_DIR`                                                                    | `<repo>/feeds`                                         | Feed staging root (~2 GB)                                 |
| `OSV_STAGING_DIR` · `MSRC_STAGING_DIR` · `EXPLOIT_STAGING_DIR` · `CSAF_STAGING_DIR` | derived                                                | Per-feed overrides                                        |

### Authentication

| Variable                                         | Default                    | Effect                                                                                              |
| ------------------------------------------------ | -------------------------- | --------------------------------------------------------------------------------------------------- |
| `ACCESS_TOKEN_EXPIRES_MINUTES`                   | `30`                       |                                                                                                     |
| `REFRESH_TOKEN_EXPIRES_DAYS`                     | `7`                        |                                                                                                     |
| `MFA_ENCRYPTION_KEY`                             | none (required)            | The API refuses to start without it; never change it — every enrolled TOTP secret would be orphaned |
| `REFRESH_COOKIE_NAME`                            | `ccure_refresh_token`      |                                                                                                     |
| `REFRESH_COOKIE_PATH`                            | `/`                        |                                                                                                     |
| `REFRESH_COOKIE_SAMESITE`                        | `lax`                      |                                                                                                     |
| `REFRESH_COOKIE_SECURE`                          | `false`                    | **Set `true` behind HTTPS**                                                                         |
| `REFRESH_COOKIE_DOMAIN`                          | unset                      |                                                                                                     |
| `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` | empty                      | Seeds the first superadmin at startup                                                               |
| `COMPLIANCE_ENCRYPTION_KEY`                      | fallback (logged at ERROR) | AES-256-GCM master key for stored credentials                                                       |
| `SCAN_KEY_DIR`                                   | user home                  | Directory `key_path` must resolve under                                                             |

### Scanning

| Variable                                                      | Default                | Effect                                                 |
| ------------------------------------------------------------- | ---------------------- | ------------------------------------------------------ |
| `NMAP_TIMEOUT`                                                | `300`                  | Also sets Celery `task_time_limit = NMAP_TIMEOUT + 60` |
| `NMAP_THREADS`                                                | `20`                   |                                                        |
| `MAX_NMAP_PROCESSES`                                          | `20`                   | Redis-backed process limiter                           |
| `NMAP_PROCESS_WAIT_TIMEOUT`                                   | `900`                  |                                                        |
| `NMAP_CACHE_ENABLED`                                          | `True`                 |                                                        |
| `NMAP_CACHE_TTL_HOURS`                                        | `72`                   |                                                        |
| `SCAN_IP_BLACKLIST`                                           | empty                  | Comma-separated IPs/CIDRs never scanned                |
| `PASSIVE_FIRST_DEFAULT`                                       | `False`                | OT-safety default                                      |
| `NUCLEI_BINARY`                                               | `nuclei`               | Network plugin                                         |
| `NUCLEI_TEMPLATES`                                            | `~/nuclei-templates`   | Network plugin                                         |
| `NUCLEI_SEVERITIES`                                           | `critical,high,medium` | ~7 460 of ~13 510 templates                            |
| `NUCLEI_TIMEOUT` / `NUCLEI_RATE_LIMIT` / `NUCLEI_CONCURRENCY` | `900` / `150` / `50`   | Network plugin                                         |
| `CCURE_SNMP_WALK_CONCURRENCY`                                 | `8`                    | Topology                                               |
| `CCURE_SNMP_WALK_TIMEOUT`                                     | `240`                  | Topology                                               |

### Web scanning (DAST)

| Variable                                                                            | Default                         |
| ----------------------------------------------------------------------------------- | ------------------------------- |
| `NUCLEI_TEMPLATES_DIR`                                                              | `/opt/nuclei-templates`         |
| `SUBFINDER_BINARY` / `FFUF_BINARY` / `SQLMAP_BINARY`                                | `subfinder` / `ffuf` / `sqlmap` |
| `FFUF_WORDLIST`                                                                     | `/opt/wordlists/common.txt`     |
| `PLAYWRIGHT_TIMEOUT`                                                                | `60000` ms                      |
| `PLAYWRIGHT_BROWSERS_PATH`                                                          | `/opt/playwright` (image)       |
| `MAX_CRAWL_DEPTH` / `MAX_CRAWL_URLS` / `CRAWL_CONCURRENCY` / `CRAWL_SETTLE_TIMEOUT` | `5` / `500` / `3` / `5000` ms   |
| `WEB_SCAN_TIMEOUT`                                                                  | `14400` (4 h)                   |
| `WEB_SCAN_RATE_LIMIT` / `WEB_STEALTH_RATE_LIMIT`                                    | `5` / `2` req/s                 |
| `MAX_RESPONSE_BODY_SIZE`                                                            | `10240` bytes of evidence       |
| `OAST_ENABLED` / `OAST_SERVER` / `OAST_TOKEN`                                       | `True` / empty / empty          |
| `NUCLEI_SEVERITY` (DAST)                                                            | `medium,high,critical`          |
| `NUCLEI_CONCURRENCY` / `NUCLEI_BULK_SIZE` / `NUCLEI_TIMEOUT` (DAST)                 | `25` / `25` / `7200`            |
| `SQLMAP_LEVEL` / `SQLMAP_RISK` / `SQLMAP_TIMEOUT`                                   | `3` / `2` / `600`               |

### Task queue and mail

| Variable                                      | Default                    |
| --------------------------------------------- | -------------------------- |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` |
| `SCANNER_WORKER_CONCURRENCY`                  | `NMAP_THREADS` (20)        |
| `SCANNER_WORKER_PREFETCH_MULTIPLIER`          | `1`                        |
| `WEB_WORKER_CONCURRENCY`                      | `4` (compose)              |
| `CELERY_TASK_ALWAYS_EAGER`                    | `False`                    |
| `SMTP_HOST` / `SMTP_PORT`                     | `localhost` / `1025`       |
| `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_SECURE` | empty / empty / `False`    |
| `SMTP_FROM_EMAIL`                             | `no-reply@ccureaudit.pro`  |

### Frontend

| Variable            | Default            | Effect                                         |
| ------------------- | ------------------ | ---------------------------------------------- |
| `VITE_API_BASE_URL` | `""` (same-origin) | Baked at **build** time. Compose passes `/api` |

---

## 7. Database

### Initialisation

```bash
cd Backend
python db/migrate_production_schema.py
```

Branches on whether the `public` schema has tables:

- **Empty** → `Base.metadata.create_all()`, `create_partitions()` (8 hash
  partitions each for `audit_logs` and `asset_vulnerabilities`), then
  `alembic stamp heads`.
- **Existing** → `alembic upgrade heads`.

It then runs the four additive helpers (`ensure_user_schema`,
`ensure_mac_vendor_schema`, `ensure_scan_schema`, `ensure_topology_schema`),
seeds RBAC and the default organization, and prints a table summary.

### Alembic

```bash
cd Backend
alembic current
alembic history --verbose
alembic heads                       # one per branch: Audit's, then each core module's
alembic upgrade heads
alembic downgrade <head revision>@-1  # a bare -1 is ambiguous with several heads
alembic revision --autogenerate -m "describe the change"
```

`alembic.ini` leaves `sqlalchemy.url` blank; `alembic/env.py` reads
`AppConfig.DATABASE_URL`. Head is `c3h4i5j6k7l8`, root `7f96fc2fa41a`, 32 revisions.

### Seeding

| Command                                | Effect                                                               |
| -------------------------------------- | -------------------------------------------------------------------- |
| `python -m scripts.seed_compliance`    | Frameworks and controls from the twelve `*_controls_seed.json` files |
| `python -m scripts.seed_real_rules`    | Compliance rules, then evaluates them                                |
| `python scripts/admin/create_admin.py` | Create an administrator interactively                                |
| `python scripts/print_admin.py`        | Print the seeded admin account                                       |
| `python scripts/seed_mock_findings.py` | Sample findings for UI work                                          |

Framework seeding also runs automatically in the API lifespan when any framework's
control count falls below its threshold.

### Backups

```powershell
$env:PGPASSWORD = '<password>'
.\scripts\backup_db.ps1 -SkipReferenceData   # fast: operational data only
.\scripts\install_backup_schedule.ps1        # register the 6-hourly scheduled task
Get-ScheduledTask -TaskName 'CCure DB Backup' | Get-ScheduledTaskInfo
```

Restore: `pg_restore --clean --if-exists -d ccure_test <file>.dump`.

> **CAUTION:** `archive_mode` is `off` on the reference deployment, so recovery
> granularity is "since the last dump", not point-in-time. Take an ad-hoc dump
> before any migration, bulk delete or test run.

---

## 8. Vulnerability feeds

The `vuln_intel` database is **not under this repo's Alembic control** — its
`alembic_version` names a revision that exists nowhere in the tree. Each sync
script asserts the tables it needs, so the feeds can be rebuilt onto an empty
server.

```bash
cd Backend
python scripts/vuln/download_nvd.py           # NVD bulk
python scripts/vuln/sync_osv.py               # osv.dev; --list shows ecosystems
python scripts/vuln/sync_msrc.py              # Microsoft Security Update Guide
python scripts/vuln/sync_exploit_intel.py     # ExploitDB + Metasploit + Nuclei + KEV
python scripts/vuln/sync_csaf.py              # Siemens, CISA, Red Hat
python scripts/vuln/sync_vulncheck.py         # VulnCheck KEV (needs a token)
python scripts/vuln/backfill_finding_intel.py # Backfill existing findings
```

```powershell
.\scripts\install_feed_schedule.ps1           # register recurring feed sync
```

Budget ~2 GB for the staged archives; `vuln_intel` itself reaches ~10 GB once
every feed has run. Grant access with
`Backend/scripts/grant_vuln_intel_access.sql`.

---

## 9. Testing

```bash
cd Backend
pytest                                  # whole suite
pytest tests/scans/test_scans.py -v
pytest --cov=. --cov-report=xml -v --reruns 1   # the CI invocation
```

`pytest.ini`: `python_files = test_*.py`, `addopts = --ignore=test_output.txt`.
CI installs `pytest==7.4.4`, `pytest-cov`, `pytest-rerunfailures`, `bandit`,
`ruff` on top of `requirements.txt`, and sets `MOCK_SCANNERS=true`.

> **CAUTION — the test suite is destructive.** It `TRUNCATE`s `organizations` and
> `users` `CASCADE`, which reaches `scans`, `scan_phases`, `assets`, `services`,
> `asset_change_log`, `audit_logs` and `notifications`. On 10 Aug 2026 a full-suite
> run inherited the API container's `DATABASE_URL`, was accepted by a guard that
> matched `_test$`, and destroyed all users, orgs, scans and assets. There was no
> recovery.
>
> Three layers in `Backend/tests/conftest.py` now prevent a repeat:
>
> 1. `TEST_DB_NAME_PATTERN` accepts only `^pytest_`, `_pytest`, `_pytest_db`.
> 2. `FORBIDDEN_DB_NAMES` rejects `ccure_test`, `ccure_db`, `vuln_intel`, … even if
>    renamed into the pattern.
> 3. `_assert_database_is_disposable()` refuses any database holding rows in
>    `users` / `scans` / `assets` / `services` unless it carries the
>    `_pytest_scratch_marker` sentinel table.
>
> `docker-compose.yml` also pins `TEST_DATABASE_URL` to `ccure_pytest_db` on `api`,
> `worker` and `web-worker`, so `docker exec … pytest` cannot inherit the live URL.
> **Take a backup before running the suite anyway.**

### Frontend

```bash
cd Frontend
npm test          # vitest run
```

### Disposable scan targets

```powershell
docker start ccure-rocky-target    # Rocky 9.8,   ssh 127.0.0.1:2222  root / ccure-test-only
docker start ccure-ubuntu-target   # Ubuntu 24.04, ssh 127.0.0.1:2223  root / ccure-test-only
docker start ccure-nuclei-target   # nginx on 127.0.0.1:8099 serving .env and .git/config
```

Expected: Rocky **48 findings (4 Critical)**, Ubuntu **7** (all with no upstream
fix), Nuclei target **4 findings, all Confirmed at QoD 99**. Zero from any of them
is a regression, not a clean host. These targets are deliberately never updated —
an up-to-date target cannot distinguish "matching works and the host is clean" from
"matching is broken".

### Verification scripts

| Script                                            | Checks                     |
| ------------------------------------------------- | -------------------------- |
| `scripts/verification/verify_install.py`          | Installation prerequisites |
| `scripts/verification/verify_permissions.py`      | RBAC seeding               |
| `scripts/verification/check_schema.py`            | Schema state               |
| `scripts/verification/check_compliance_data.py`   | Compliance catalog         |
| `scripts/verification/check_cve_source.py`        | Feed connectivity          |
| `scripts/verification/check_target_asset.py`      | One asset's record         |
| `scripts/verification/test_scan_execution.py`     | End-to-end scan            |
| `scripts/verification/verify_report_integrity.py` | Report generation          |

---

## 10. Linting and formatting

### Pre-commit

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

`.pre-commit-config.yaml` hooks:

| Hook                                                                                | Scope                                                             | Configuration                                                                                                                                                          |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `check-yaml`, `check-added-large-files`, `end-of-file-fixer`, `trailing-whitespace` | all                                                               | pre-commit-hooks v4.6.0                                                                                                                                                |
| `black`                                                                             | `^Backend/`                                                       | 24.4.2                                                                                                                                                                 |
| `ruff`                                                                              | `^Backend/`                                                       | v0.4.8, `--fix`, ignoring `E402,F401,F841,E711,E712,E741,F601,E722,F821`                                                                                               |
| `bandit`                                                                            | `^Backend/`                                                       | 1.7.9, `-lll`, excluding `tests`, skipping `B324,B501,B507`                                                                                                            |
| `prettier`                                                                          | `^(Frontend/\|docs/.*\.md$)`                                      | prettier@3.2.5                                                                                                                                                         |
| `eslint`                                                                            | `^Frontend/`                                                      | eslint@8.57.0 + react + react-hooks, `--max-warnings=0`                                                                                                                |
| `openapi-contract` (local, runs last)                                               | backend `.py` except `tests/`, `openapi.json`, `requirements.txt` | regenerates `Backend/openapi.json` exactly as CI does and stages it if it changed; needs `Backend/.venv` with `requirements.txt` installed (or `CCURE_BACKEND_PYTHON`) |

> **The API contract is regenerated for you.** When a commit touches backend
> code, `openapi-contract` rebuilds `Backend/openapi.json` from what is being
> committed, stages it if it changed and names the operations added or
> removed. If it cannot (no backend environment, a FastAPI or Pydantic version
> other than the pins, or the application fails to import) the commit stops
> with the reason. `SKIP=openapi-contract git commit …` commits without it,
> and CI's OpenAPI Schema Diff Check still compares the contract. By hand:
> `cd Backend && python -m scripts.openapi.generate` (or `--check`).

> **NOTE:** Prettier covers `docs/*.md`, so this documentation set is
> auto-formatted on commit.

### Direct invocation

```bash
black Backend/
ruff check Backend/ --select=E,F,W --ignore=E402,F401,F841,E711,E712,E741,F601,E722,F821,E501
bandit -r Backend/ -x Backend/tests -lll --skip B324,B501,B507,B110,B112,B605,B608,B104,B105,B106,B314,B113,B601,B310
```

CI uses a broader Bandit skip list than pre-commit — the CI form above is the
authoritative one to reproduce locally.

---

## 11. Documentation build

```bash
cd Backend
python scripts/compile_docs.py
pytest tests/repo/test_docs_integrity.py -v
```

`compile_docs.py` compiles nine Markdown files from `docs/` into
`docs/CCure_Audit_PRO_Documentation.docx`, in this order:
`SYSTEM_ARCHITECTURE`, `BACKEND_API_REFERENCE`, `DATABASE_SCHEMA`,
`AUTHENTICATION_AND_AUTHORIZATION`, `FRONTEND_ARCHITECTURE`,
`DEVELOPER_SETUP_GUIDE`, `RBAC_Management_Permissions`, `SCAN_ENGINE_DEEP_DIVE`,
`QA_REGRESSION_STRATEGY`. It installs `python-docx` on demand if absent.

`test_docs_integrity.py` is the drift guard and asserts three things:

1. every path in `app.routes` (except `/docs*`, `/redoc`, `/openapi.json`) appears
   in `BACKEND_API_REFERENCE.md`;
2. every key of `Base.metadata.tables` appears in `DATABASE_SCHEMA.md`;
3. every permission string in `ROLE_PERMISSIONS` appears in
   `RBAC_Management_Permissions.md`.

> **NOTE:** `docker-compose.yml` mounts `./docs:/docs:ro` on the `api` service.
> Without that mount the test cannot find the files inside the container and fails
> on all three — which reads as documentation drift when it is a missing volume.

---

## 12. CI pipeline

`.github/workflows/ci.yml`, on push and PR against `main`/`master`. Two jobs.

### `backend-validation` (ubuntu-latest, Python 3.12)

Services: `postgres:15-alpine` and `redis:7-alpine` with health checks.

1. Install `requirements.txt` plus `pytest==7.4.4`, `pytest-cov`,
   `pytest-rerunfailures`, `bandit`, `ruff`.
2. **Bandit** static security analysis.
3. **Ruff** lint.
4. Verify the database connection and create the `admin` and `root` PostgreSQL
   roles the feed scripts expect.
5. `python db/migrate_production_schema.py`, `python -m scripts.seed_compliance`,
   `python -m scripts.seed_real_rules`.
6. **Alembic integrity** — `alembic downgrade <rev>@-1` for every head, then
   `alembic upgrade heads`, so the newest migration on each branch must be reversible.
7. **OpenAPI schema diff** — dumps `app.openapi()` deterministically and `diff`s
   against the committed `Backend/openapi.json`. A mismatch **fails the build**.
8. `pytest --cov=. --cov-report=xml -v --reruns 1` with `MOCK_SCANNERS=true`.
9. `python scripts/compile_docs.py` and `pytest tests/repo/test_docs_integrity.py -v`.

> **IMPORTANT:** Step 7 means **any** route change must be accompanied by a
> regenerated `Backend/openapi.json`:
>
> ```bash
> cd Backend
> python - <<'PY' > openapi.json
> import json
> from main import app
> print(json.dumps(app.openapi(), sort_keys=True, indent=2, ensure_ascii=False))
> PY
> ```

### `frontend-validation` (ubuntu-latest, Node 22)

`npm ci` → `npm audit --audit-level=high` (non-blocking) → `npm run lint`
(non-blocking; no `lint` script exists in `package.json`).

---

## 13. Common tasks

| Task                          | Command                                                                    |
| ----------------------------- | -------------------------------------------------------------------------- |
| Interactive scan CLI          | `cd Backend && python scripts/cli.py`                                      |
| Create an admin               | `python scripts/admin/create_admin.py`                                     |
| Clear test data               | `python scripts/admin/clear_ccure_test_data.py`                            |
| Clean up legacy findings      | `python scripts/cleanup_legacy_findings.py`                                |
| Inspect a scan's schema state | `python scripts/verification/check_schema.py`                              |
| Tail API logs                 | `docker compose logs -f api`                                               |
| Tail worker logs              | `docker compose logs -f worker`                                            |
| Open a DB shell               | `docker compose exec db psql -U $POSTGRES_USER -d $POSTGRES_DB`            |
| Restart after Python edits    | `docker compose restart api`                                               |
| Rebuild the frontend          | `docker compose build frontend && docker compose up -d --no-deps frontend` |

---

## 14. Troubleshooting

| Symptom                                               | Cause                                                                                      | Fix                                                              |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| API container starts but every request 500s           | `SELECT 1` failed at startup; the lifespan logs the error and continues so you can exec in | Check `DATABASE_URL` and that `db` is healthy                    |
| Compose refuses to start                              | One of the five `${VAR:?}` variables is unset                                              | Set it in the root `.env`                                        |
| Credentialed scans complete as unauthenticated audits | `COMPLIANCE_ENCRYPTION_KEY` differs between API and host worker                            | Make them identical, then re-enter stored credentials            |
| Phase 1 finds nothing on a LAN                        | No raw-socket privilege, or Npcap missing on Windows                                       | Run elevated / install Npcap                                     |
| Port scan is slow and version-poor                    | `nmap` not on PATH — PortEngine logged a warning and fell back to TCP connect              | Install nmap                                                     |
| `nuclei_probe` produces nothing                       | Binary absent (logged as a coverage gap), or a two-argument `run()` was introduced         | Install nuclei; keep the three-argument serial signature         |
| Web scan reports a tool gap                           | `ToolCoverage` recorded `unavailable`                                                      | Install the tool, or accept the recorded gap                     |
| CVE lookups return nothing                            | `VULN_DB_*` unset, so `VulnIntelConfig` fell through to `DATABASE_URL`                     | Set `VULN_DB_NAME` et al., or `VULNERABILITY_INTEL_DATABASE_URL` |
| Frontend calls hit the Vite server and 404            | `/user`, `/compliance`, `/api` are not proxied                                             | Set `VITE_API_BASE_URL`                                          |
| Frontend still points at the old API URL              | `VITE_API_BASE_URL` is inlined at build time                                               | `docker compose build frontend`                                  |
| `test_docs_integrity` fails on three missing files    | `./docs` not mounted into the container                                                    | Confirm the `./docs:/docs:ro` volume                             |
| CI fails on "Breaking OpenAPI changes detected"       | Routes changed without regenerating the baseline                                           | Regenerate `Backend/openapi.json`                                |
| Two workers serving different code                    | A second host worker was started                                                           | Use `start_host_scanner_worker.ps1 -Force`                       |
| Scan History shows the download time as the scan date | Report generation was made unconditional                                                   | Serve the stored PDF; regenerate only when missing               |

---

## 15. Related documents

- [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md)
- [BACKEND_API_REFERENCE.md](BACKEND_API_REFERENCE.md)
- [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)
- [AUTHENTICATION_AND_AUTHORIZATION.md](AUTHENTICATION_AND_AUTHORIZATION.md)
- [RBAC_Management_Permissions.md](RBAC_Management_Permissions.md)
- [SCAN_ENGINE_DEEP_DIVE.md](SCAN_ENGINE_DEEP_DIVE.md)
- [FRONTEND_ARCHITECTURE.md](FRONTEND_ARCHITECTURE.md)
