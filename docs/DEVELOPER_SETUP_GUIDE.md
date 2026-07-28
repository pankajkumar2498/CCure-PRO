# CCure-Audit-PRO — Developer Setup Guide

> This guide covers both **Docker Compose (recommended)** and **local manual setup** for development and production deployment. All paths are relative to the repository root.

## 1. Prerequisites

### Host-level requirements

| Requirement    | Minimum Version | Notes                                                              |
| -------------- | --------------- | ------------------------------------------------------------------ |
| Docker         | 24.x            | Required for all deployment modes                                  |
| Docker Compose | v2 (plugin)     | `docker compose` (not `docker-compose`)                            |
| PostgreSQL     | 14.x            | Must run on the **host machine**, not in Docker (see note below)   |
| Node.js        | 18.x LTS        | Frontend development only                                          |
| Python         | 3.11+           | Backend development only                                           |
| nmap           | 7.x             | Required on Celery worker host (auto-installed in Docker image)    |
| Scapy          | —               | Installed via pip; requires raw-socket access (root / CAP_NET_RAW) |

> **Why PostgreSQL runs on the host:** The Celery worker containers run with raw socket access as root. Placing the database inside Docker would complicate network isolation. Docker containers connect to host PostgreSQL via `host.docker.internal:5432` (mapped to `host-gateway` in `docker-compose.yml`).

### PostgreSQL databases required

Two separate databases must exist on the host PostgreSQL instance:

| Database                                     | Variable       | Purpose                                                   |
| -------------------------------------------- | -------------- | --------------------------------------------------------- |
| Application DB (e.g. `ccure_test`)           | `POSTGRES_DB`  | All app data (users, scans, assets, findings)             |
| Vulnerability Intelligence DB (`vuln_intel`) | `VULN_DB_NAME` | CVE/EPSS/KEV data (external data pipeline populates this) |

Create them:

```sql
CREATE DATABASE ccure_test;
CREATE USER ccure_user WITH PASSWORD 'ccure_admin_2026';
GRANT ALL PRIVILEGES ON DATABASE ccure_test TO ccure_user;

CREATE DATABASE vuln_intel;
GRANT CONNECT ON DATABASE vuln_intel TO admin;
```

---

## 2. Docker Compose Setup (Recommended)

### Step 1 — Clone the repository

```bash
git clone <repo-url> CCure-Audit-PRO
cd CCure-Audit-PRO
```

### Step 2 — Create the environment file

```bash
cp Backend/.env.example .env
```

Edit `.env` and fill in **all required values**:

```dotenv
# ── Database ──────────────────────────────────────────────────────
POSTGRES_USER=ccure_user
POSTGRES_PASSWORD=ccure_admin_2026
POSTGRES_DB=ccure_test

# ── Vulnerability Intel DB ────────────────────────────────────────
VULN_DB_HOST=host.docker.internal
VULN_DB_PORT=5432
VULN_DB_NAME=vuln_intel
VULN_DB_USER=admin
VULN_DB_PASSWORD=root_secure_password

# ── Security — MUST change in production ─────────────────────────
# Generate: openssl rand -hex 32
JWT_SECRET_KEY=REPLACE_WITH_LONG_RANDOM_STRING_32_CHARS_MINIMUM

# ── Initial superadmin (only used if the users table is empty) ────
DEFAULT_ADMIN_EMAIL=admin@company.com
DEFAULT_ADMIN_PASSWORD=SecretPassword123

# ── Frontend & CORS ───────────────────────────────────────────────
CORS_ALLOW_ORIGINS=http://localhost:3000
FRONTEND_URL=http://localhost:3000
VITE_API_BASE_URL=/api

# ── Gateway port (public entry point) ────────────────────────────
GATEWAY_PORT=80

# ── SMTP (for password reset emails) ─────────────────────────────
SMTP_HOST=host.docker.internal
SMTP_PORT=1025          # MailHog/Maildev for dev
SMTP_FROM_EMAIL=no-reply@ccureaudit.pro

# ── Scanner tuning ────────────────────────────────────────────────
SCANNER_WORKER_CONCURRENCY=20
MAX_NMAP_PROCESSES=20
NMAP_THREADS=20
```

### Step 3 — Start the core services (API + Redis + Frontend + Gateway)

The default profile starts: `redis`, `api`, `frontend`, `gateway`.

```bash
docker compose up -d
```

Access the application at `http://localhost` (gateway, port 80) or `http://localhost:3200` (frontend direct) and `http://localhost:8000` (API direct).

### Step 4 — Start the scan workers (optional, needed for actual scanning)

The `worker` (network scans) and `web-worker` (DAST) services are in the `container-scanner` Docker Compose profile. They run as root (required for raw sockets).

```bash
docker compose --profile container-scanner up -d
```

**Without workers:** The API starts fine. Scans are dispatched to Celery queues but will sit pending until a worker picks them up.

### Step 5 — Database migration and seed

Database schema creation and RBAC seeding happen **automatically at startup** via the FastAPI lifespan handler (`main.py`). The sequence is:

1. If the database is empty → `Base.metadata.create_all()` bootstraps the schema + stamps Alembic head.
2. If the database has tables → `alembic upgrade head` runs any pending migrations.
3. `seed_rbac()` — creates 5 roles + 40 permissions + role-permission assignments (idempotent).
4. `seed_default_org()` — creates the default org (`org_king`, plan `pro`).
5. If `DEFAULT_ADMIN_EMAIL` is set and no user exists with that email → creates the first `superadmin` user.

You can also run the migration script manually:

```bash
docker compose exec api python db/migrate_production_schema.py
```

### Step 6 — Verify

```bash
# Check all containers are healthy
docker compose ps

# Tail API logs
docker compose logs -f api

# Confirm API is responding
curl http://localhost:8000/health
# Expected: {"status":"ok","version":"...","environment":"production"}
```

---

## 3. Local Development Setup (Without Docker)

For rapid iteration on backend or frontend code without rebuilding Docker images.

### 3a. Backend (FastAPI)

**Requirements:** Python 3.11+, nmap installed on the host system, a running PostgreSQL instance.

```bash
cd Backend

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Create local .env (copy from example and edit)
cp .env.example .env
# Edit .env — set DATABASE_URL to point to your local PostgreSQL
# e.g. DATABASE_URL=postgresql://ccure_user:ccure_admin_2026@localhost:5432/ccure_test

# Start Redis (if not already running)
docker run -d -p 6379:6379 redis:7-alpine

# Run database migrations and seed (first time)
python db/migrate_production_schema.py

# Start the FastAPI development server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

API is now available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs` (Swagger UI).

**Run the Celery worker locally:**

```bash
# In a separate terminal (same venv, Backend/ directory)
# Must run as root (or with CAP_NET_RAW) for Scapy/Nmap
sudo .venv/bin/celery -A core.celery_app worker \
  --loglevel=info \
  --queues=scanner \
  --concurrency=4
```

**Run the web scan worker locally:**

```bash
sudo .venv/bin/celery -A core.celery_app worker \
  --loglevel=info \
  --queues=web_recon,web_crawl,web_dast,web_audit \
  --concurrency=2
```

> **Note on Playwright:** The web worker requires `playwright install chromium` to be run once after `pip install -r requirements.txt`:
>
> ```bash
> playwright install chromium
> ```

### 3b. Frontend (React / Vite)

**Requirements:** Node.js 18+, npm or yarn.

```bash
cd Frontend

# Install dependencies
npm install

# Create local env file
cp .env.example .env.local
# Set VITE_API_URL=http://localhost:8000

# Start dev server
npm run dev
# Dev server: http://localhost:5173
# API proxy: /api/* → http://localhost:8000/*
```

**Build for production:**

```bash
npm run build
# Output: Frontend/dist/
```

---

## 4. Environment Variable Reference

### Backend Environment Variables

All variables read from environment by `Backend/config.py`. Variables marked **Yes (Required)** will cause startup failures or broken features if absent.

| Variable                             | Required   | Default                                                 | Description                                                                   |
| ------------------------------------ | ---------- | ------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `DATABASE_URL`                       | **Yes**    | —                                                       | PostgreSQL connection string (e.g. `postgresql://user:pass@host:5432/dbname`) |
| `CELERY_BROKER_URL`                  | **Yes**    | `redis://localhost:6379/0`                              | Redis URL for Celery task broker                                              |
| `CELERY_RESULT_BACKEND`              | **Yes**    | `redis://localhost:6379/0`                              | Redis URL for Celery result storage                                           |
| `JWT_SECRET_KEY`                     | **Yes**    | —                                                       | HS256 signing key — must be ≥32 random chars (`openssl rand -hex 32`)         |
| `APP_ENV`                            | No         | `development`                                           | `production` = Secure cookie flag + no debug output                           |
| `ENV` / `ENVIRONMENT`                | No         | `development`                                           | Alias; `APP_ENV` takes precedence                                             |
| `LOG_LEVEL`                          | No         | `INFO`                                                  | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`)                        |
| `DEFAULT_ADMIN_EMAIL`                | First boot | —                                                       | Seeds first superadmin user. Remove after first boot.                         |
| `DEFAULT_ADMIN_PASSWORD`             | First boot | —                                                       | Seeds first superadmin password. Remove after first boot.                     |
| `ACCESS_TOKEN_EXPIRES_MINUTES`       | No         | `30`                                                    | JWT access token lifetime in minutes                                          |
| `REFRESH_TOKEN_EXPIRES_DAYS`         | No         | `7`                                                     | Refresh token lifetime in days                                                |
| `REFRESH_COOKIE_NAME`                | No         | `ccure_refresh_token`                                   | Name of the JWT refresh token HTTP-only cookie                                |
| `FRONTEND_URL`                       | No         | `http://localhost:3000`                                 | Used for constructing password reset email links                              |
| `TRUSTED_PROXIES`                    | No         | `127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Comma-separated list of trusted proxies for client IP parsing                 |
| `SKIP_DOTENV_LOAD`                   | No         | —                                                       | Set to any value to skip `.env` file loading (for container use)              |
| `SMTP_HOST`                          | No         | `localhost`                                             | SMTP server hostname                                                          |
| `SMTP_PORT`                          | No         | `1025`                                                  | SMTP port (1025 = MailHog dev; 587 = TLS submission; 465 = SSL)               |
| `SMTP_USER`                          | No         | —                                                       | SMTP authentication username                                                  |
| `SMTP_PASSWORD`                      | No         | —                                                       | SMTP authentication password                                                  |
| `SMTP_SECURE`                        | No         | `False`                                                 | `True` for SSL/TLS on port 465                                                |
| `SMTP_FROM_EMAIL`                    | No         | `no-reply@ccureaudit.pro`                               | Sender address for system emails                                              |
| `VULN_DB_HOST`                       | No         | `host.docker.internal`                                  | Vulnerability intel PostgreSQL host                                           |
| `VULN_DB_PORT`                       | No         | `5432`                                                  | Vulnerability intel PostgreSQL port                                           |
| `VULN_DB_NAME`                       | No         | `vuln_intel`                                            | Vulnerability intel database name (`PGDATABASE` is an alias)                  |
| `VULN_DB_USER`                       | No         | `admin`                                                 | Vulnerability intel database user (`PGUSER` is an alias)                      |
| `VULN_DB_PASSWORD`                   | No         | `root`                                                  | Vulnerability intel database password (`PGPASSWORD` is an alias)              |
| `PGHOST`                             | No         | `localhost`                                             | Alias for `VULN_DB_HOST` (legacy)                                             |
| `SCANNER_WORKER_CONCURRENCY`         | No         | system CPU count                                        | Celery worker concurrency for the `scanner` queue                             |
| `SCANNER_WORKER_PREFETCH_MULTIPLIER` | No         | `1`                                                     | Celery task prefetch (keep at 1 for long-running scans)                       |
| `MAX_NMAP_PROCESSES`                 | No         | `20`                                                    | Max parallel Nmap processes                                                   |
| `NMAP_THREADS`                       | No         | `20`                                                    | Nmap thread count per process                                                 |
| `NMAP_TIMEOUT`                       | No         | `300`                                                   | Nmap timeout in seconds (Celery task time limit = this + 60)                  |
| `NMAP_CACHE_ENABLED`                 | No         | `True`                                                  | Cache Nmap scan results to avoid redundant scans                              |
| `NMAP_CACHE_TTL_HOURS`               | No         | `72`                                                    | Nmap result cache lifetime in hours                                           |
| `NMAP_PROCESS_WAIT_TIMEOUT`          | No         | `900`                                                   | Max seconds to wait for an Nmap process to start                              |
| `NUCLEI_BINARY`                      | No         | `nuclei`                                                | Path to Nuclei binary (must be in PATH or absolute)                           |
| `NUCLEI_TEMPLATES_DIR`               | No         | `/opt/nuclei-templates`                                 | Path to Nuclei template library                                               |
| `NUCLEI_CONCURRENCY`                 | No         | `25`                                                    | Nuclei parallel template execution                                            |
| `NUCLEI_BULK_SIZE`                   | No         | `25`                                                    | Nuclei bulk request size                                                      |
| `NUCLEI_SEVERITY`                    | No         | `medium,high,critical`                                  | Default Nuclei severity filter                                                |
| `NUCLEI_TIMEOUT`                     | No         | `7200`                                                  | Nuclei max run time in seconds                                                |
| `SUBFINDER_BINARY`                   | No         | `subfinder`                                             | Path to subfinder binary for subdomain enumeration                            |
| `FFUF_BINARY`                        | No         | `ffuf`                                                  | Path to ffuf binary for directory brute-forcing                               |
| `FFUF_WORDLIST`                      | No         | `/opt/wordlists/common.txt`                             | Wordlist path for ffuf                                                        |
| `SQLMAP_BINARY`                      | No         | `sqlmap`                                                | Path to sqlmap binary for SQL injection testing                               |
| `SQLMAP_LEVEL`                       | No         | `2`                                                     | sqlmap detection level (1–5)                                                  |
| `SQLMAP_RISK`                        | No         | `2`                                                     | sqlmap risk level (1–3)                                                       |
| `SQLMAP_TIMEOUT`                     | No         | `600`                                                   | sqlmap max run time in seconds                                                |
| `PLAYWRIGHT_TIMEOUT`                 | No         | `60000`                                                 | Playwright browser operation timeout in milliseconds                          |
| `MAX_CRAWL_DEPTH`                    | No         | `5`                                                     | Web crawler maximum link depth                                                |
| `MAX_CRAWL_URLS`                     | No         | `500`                                                   | Web crawler maximum URLs to visit per scan                                    |
| `CRAWL_CONCURRENCY`                  | No         | `3`                                                     | Web crawler parallel browser tabs                                             |
| `MAX_RESPONSE_BODY_SIZE`             | No         | `10240`                                                 | Max response body stored in WebFinding (bytes)                                |
| `WEB_SCAN_RATE_LIMIT`                | No         | `5`                                                     | Default requests/second for DAST scans                                        |
| `WEB_STEALTH_RATE_LIMIT`             | No         | `2`                                                     | Reduced rate for WAF-detected targets                                         |
| `WEB_SCAN_TIMEOUT`                   | No         | `14400`                                                 | Max total web scan time in seconds (4 hours)                                  |

### Frontend Environment Variables

| Variable            | Default                 | Description                             |
| ------------------- | ----------------------- | --------------------------------------- |
| `VITE_API_URL`      | `http://localhost:8000` | Backend API base URL (dev server)       |
| `VITE_API_BASE_URL` | `/api`                  | Backend API base URL (production build) |

---

## 5. Common Workflows

### Reset and re-seed the database

```bash
# Drop and recreate the application database
psql -U postgres -c "DROP DATABASE IF EXISTS ccure_test;"
psql -U postgres -c "CREATE DATABASE ccure_test OWNER ccure_user;"

# Restart the API — schema and seed runs automatically
docker compose restart api
```

### Seeding Compliance standards and baselines

During development, you must run the following seeding commands from the `Backend/` directory (with the virtual environment active) to populate the framework catalog, baseline policies, and rules:

```bash
# 1. Seed base RBAC roles and permissions (registers 51 total permissions)
python db/migrate_production_schema.py

# 2. Seed framework catalog (ISO 27001 standard controls)
python -m scripts.seed_compliance

# 3. Seed baseline check rules and remediation scripts
python -m scripts.seed_real_rules

# 4. Seed mock compliance findings (for dashboard testing)
python -m scripts.seed_mock_findings
```

### Run Alembic migrations manually

```bash
# Inside the api container
docker compose exec api alembic upgrade head

# Or generate a new revision after model changes
docker compose exec api alembic revision --autogenerate -m "add_new_column"
```

### Inspect Celery task queue

```bash
# Active tasks
docker compose exec worker celery -A core.celery_app inspect active

# Pending tasks
docker compose exec worker celery -A core.celery_app inspect reserved

# Revoke a stuck task
docker compose exec worker celery -A core.celery_app control revoke <task-id> --terminate
```

### View scan worker logs

```bash
docker compose logs -f worker
docker compose logs -f web-worker
```

### SMTP development with MailHog

```bash
# Run MailHog (catches all outgoing email in a local UI)
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Set in .env
SMTP_HOST=localhost
SMTP_PORT=1025

# View emails at: http://localhost:8025
```

---

## 6. Production Checklist

Before deploying to production:

- [ ] Generate a cryptographically strong `JWT_SECRET_KEY` (`openssl rand -hex 32`)
- [ ] Set `APP_ENV=production` (enables Secure cookie, disables debug)
- [ ] Configure real SMTP credentials (not MailHog)
- [ ] Set `CORS_ALLOW_ORIGINS` to your actual domain(s) only
- [ ] Set `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` — **remove these env vars** after the first boot (the admin account is already created; these are not needed again)
- [ ] Enable HTTPS on the nginx gateway (update `nginx/gateway.conf`, add TLS certificate volume)
- [ ] Set `REFRESH_COOKIE_PATH=/` and ensure the cookie `Secure` flag is active (`APP_ENV=production`)
- [ ] Use a dedicated PostgreSQL user with minimal privileges (`GRANT` only on required tables)
- [ ] Configure a firewall so that ports 6379 (Redis) and 5432 (PostgreSQL) are **not** exposed publicly — only `8000` (API) and `80/443` (gateway) should be externally accessible, and even `8000` should be gateway-only in production
- [ ] Configure PostgreSQL connection pooling (PgBouncer) if deploying at scale
- [ ] Set `SCANNER_WORKER_CONCURRENCY` based on available CPU cores and target scan volume
- [ ] Mount a persistent volume for `./Backend/reports` (PDF reports are stored here)

---

## 7. Running Tests & Quality Gates

The CCure Audit PRO backend uses `pytest` for automated test execution.

### Local Test Execution & Mock Scanners

If you do not have raw scanning binaries (`nmap`, `nuclei`, `subfinder`, etc.) installed on your local host system, or if you lack raw socket network access (`CAP_NET_RAW` / `CAP_NET_ADMIN` required by `Scapy`), you can run the test suite in mock mode by defining `MOCK_SCANNERS=true`:

```bash
# Windows (PowerShell):
$env:MOCK_SCANNERS="true"
pytest

# Linux/macOS:
export MOCK_SCANNERS=true
pytest
```

When this variable is set to `"true"` (or when the scanner binaries are missing on the developer's system), the tests will bypass actual process execution and utilize static XML/JSON parser fixtures in `Backend/tests/conftest.py`.

### Generating OpenAPI Schema for API contract checks

To extract the OpenAPI schema from the FastAPI application configuration for validation checks or contract diffs, execute the following command from the `Backend` directory:

```bash
python -c "import json; from main import app; print(json.dumps(app.openapi()))" > openapi_new.json
```

Compare `openapi_new.json` against a tracked baseline schema `openapi.json` to detect breaking contract changes before merging.

### Local Git Pre-commit Hooks

To enable automated local formatting, styling, and security checks before you can commit code, you must install and register the pre-commit configuration:

```bash
# 1. Install pre-commit framework
pip install pre-commit

# 2. Register the hooks in your local .git directory
pre-commit install
```

#### Troubleshooting WinError 5 Permission Denied

If you encounter `PermissionError: [WinError 5] Access is denied` pointing to `C:\Users\<user>\.cache\pre-commit` when executing pre-commit, redirect the pre-commit cache folder to your local project directory by setting the `PRE_COMMIT_HOME` environment variable before running installation:

```bash
# Windows (PowerShell):
$env:PRE_COMMIT_HOME="$pwd\.pre-commit-cache"
pre-commit install

# Linux/macOS:
export PRE_COMMIT_HOME="$PWD/.pre-commit-cache"
pre-commit install
```

Once registered, every `git commit` command will automatically run formatting (Black, Prettier), linting (Ruff, ESLint), and static AST security analysis (Bandit).
