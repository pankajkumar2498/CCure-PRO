# Developer Setup Guide

**CCure-Audit-PRO** — getting a working development environment, verified against
the repository's actual scripts, Dockerfiles, CI workflow and configuration files.

> Every command below exists in this repository or is a standard invocation of a
> tool the repository declares as a dependency. Nothing is aspirational. Last
> checked against the code on 15 Oct 2026.

---

## 1. Prerequisites

| Requirement             | Version                                              | Why                                                                                                                                                             |
| ----------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Python**              | **3.11** (image, local venv) / **3.12** (CI)         | The Backend image is `python:3.11-slim`; create `Backend/.venv` with `python3.11 -m venv .venv`; GitHub Actions uses `3.12`                                     |
| **Node.js**             | **26** (image) / **22** (CI)                         | `Frontend/Dockerfile` builds on `node:26-slim` (pinned by digest); CI's `setup-node` pins `22`                                                                  |
| **npm**                 | Bundled with Node                                    | `package-lock.json` is committed; CI uses `npm ci`                                                                                                              |
| **PostgreSQL**          | **18**                                               | Compose ships `postgres:18-alpine` (the VM's `ccure-db`) and CI uses the same; `Backend/tests/repo/test_ci_postgres_version.py` keeps them on one major version |
| **Redis**               | 7                                                    | `redis:7-alpine` — Celery broker, result backend, Pub/Sub and rate-limit counters                                                                               |
| **Docker + Compose v2** | Verified with Docker 29.9 and the Compose plugin 5.6 | The `docker compose` (space) form is used throughout. The scanner worker needs a **Linux** Docker host (host networking, raw sockets)                           |
| **Nmap**                | any recent                                           | Path B only (the image ships it). Phase 2/3 port and service scanning; PortEngine falls back to async TCP connect without it                                    |
| **Npcap**               | current                                              | Path B on **Windows only.** Scapy cannot open raw sockets without it, which disables ARP/ICMP/SYN discovery                                                     |
| **Git**                 | any                                                  | The primary remote is CDAC GitLab; see the README's collaboration section                                                                                       |

Optional external binaries for Path B — the backend image already contains them.
Each absent tool is a **coverage gap, not an error**, except Nuclei in the DAST
pipeline where it is essential:

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
│   ├── alembic.ini · alembic/versions/  (Audit's history; Policy Pro and Rank
│   │                   keep theirs in ccure_policy/ and ccure_rank/migrations/)
│   ├── scripts/        seeds · RBAC · security keys · verification · vuln feeds ·
│   │                   audit chain · compile_docs.py
│   └── tests/          grouped by module (auth/, scans/, repo/, …; 332 test files)
├── Frontend/           React 18 + Vite SPA
│   ├── .env.local      VITE_API_BASE_URL for the dev server (git-ignored)
│   └── package.json
├── docs/               This documentation set
├── gateway/            API gateway (Phase 10): nginx config, route policy, gateway-auth
├── scripts/            backup_db.sh · install_backup_schedule.sh ·
│                       install_feed_schedule.sh · run_feed_sync.sh ·
│                       docker-postgres-init.sql ·
│                       audit/ · ci/ · db/ · gateway/ · git/ · host-nginx/ ·
│                       linux/ · security/ · tls/
├── .env                docker-compose variables ONLY (git-ignored)
├── .env.example        Template for the above
├── docker-compose.yml
├── .pre-commit-config.yaml
└── .github/workflows/  ci · security · images · gateway · browser-matrix
```

> **CAUTION — two `.env` files, two audiences.** The repository-root `.env` is
> read by Docker Compose, which passes to a container only the variables
> `docker-compose.yml` names. `Backend/config.py` loads **`Backend/.env`**: on the
> host, and in the `api` container, where `./Backend` is bind-mounted. `worker`,
> `web-worker` and `beat` set `SKIP_DOTENV_LOAD=1` and never read it. Where both
> reach the API, the value Compose passes wins (`load_dotenv(override=False)`).
> A token placed in the root file is silently ignored by every Python script in
> `Backend/`, and vice versa.

---

## 3. Path A — Docker Compose (fastest start)

### 3.1 Configure

```bash
cp .env.example .env
cp Backend/.env.example Backend/.env
chmod 600 .env Backend/.env
```

Compose refuses to start without seven variables, each declared `${VAR:?message}`:

| Variable                      | Set in      | Note                                                                                         |
| ----------------------------- | ----------- | -------------------------------------------------------------------------------------------- |
| `POSTGRES_USER`               | root `.env` | `ccure_user`                                                                                 |
| `POSTGRES_PASSWORD`           | root `.env` | The application role's password                                                              |
| `POSTGRES_DB`                 | root `.env` | `ccure_db`                                                                                   |
| `POSTGRES_SUPERUSER_PASSWORD` | root `.env` | The bootstrap superuser's password, deliberately a different role from the application's     |
| `MFA_ENCRYPTION_KEY`          | root `.env` | `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` — never change it afterwards |
| `COMPLIANCE_ENCRYPTION_KEY`   | root `.env` | Same generator. Passed to `api`, `worker`, `web-worker` and `beat` alike                     |
| `CCURE_TOKEN_KEYS_HOST_DIR`   | root `.env` | Absolute path of the token signing keyset directory (§3.2)                                   |

> **CAUTION:** `COMPLIANCE_ENCRYPTION_KEY` encrypts stored scan credentials.
> It was once defaulted to empty: the API then encrypted credentials under the
> fallback key hardcoded in `core/security_crypto.py` while the scanner worker
> decrypted with the real key, so every credentialed scan failed with _"Invalid
> encrypted payload or authentication tag"_ and silently completed as an
> unauthenticated audit. Changing the key also makes credentials encrypted under
> the old key unreadable — re-enter stored credentials after setting it.

Settings in the root `.env` that a fresh setup needs as shipped in `.env.example`:

| Variable                   | Value               | Meaning                                                                                                                                          |
| -------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `COMPOSE_PROFILES`         | `container-scanner` | Starts `worker` and `web-worker` with the rest of the stack                                                                                      |
| `PGSSLMODE`                | `disable`           | The compose default `verify-full` needs a server certificate a fresh database lacks; the database is published on loopback only                  |
| `CELERY_TASK_ALWAYS_EAGER` | `False`             | Tasks run on the workers. The compose default `True` runs each task in the process that queued it                                                |
| `DATABASE_HOST`            | blank               | Blank → the containerized `db`                                                                                                                   |
| `POSTGRES_PORT_BINDING`    | `5432` / `5433`     | The loopback port PostgreSQL is published on; the scanner worker (host networking) connects through it. Use `5433` if the host already owns 5432 |

In `Backend/.env`, set `DEFAULT_ADMIN_EMAIL` and `DEFAULT_ADMIN_PASSWORD` to have
the first administrator created on the first start (only while the database has
no users).

### 3.2 Prepare the host (once)

Build the images first; the key tool runs inside the backend image:

```bash
docker compose build
```

**Token signing keyset.** The API signs and verifies ES256 tokens with keys from
`CCURE_TOKEN_KEYS_HOST_DIR` and refuses to start without an active one. Keep the
directory outside the repository; the private key is owned by the container user
(uid 1000) with mode 600:

```bash
mkdir -p ~/ccure-keys && chmod 711 ~/ccure-keys
docker run --rm -u 0 -v ~/ccure-keys:/keys -v "$PWD/Backend":/app:ro -w /app \
  ccure-audit-pro-backend:latest \
  python -m scripts.security.manage_token_keys --keys-dir /keys generate --state active --owner 1000:1000
docker run --rm -u 0 -v ~/ccure-keys:/keys -v "$PWD/Backend":/app:ro -w /app \
  ccure-audit-pro-backend:latest \
  python -m scripts.security.manage_token_keys --keys-dir /keys list      # prints "keyset valid"
```

Rotation and escrow are in the script's docstring and
[architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md](architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md).

**Gateway socket directory.** `api-gateway` bind-mounts `/var/lib/ccure-edge`
with `create_host_path: false`, so it refuses to start until the directory
exists. This is the first step of `scripts/linux/gateway_edge_switch.sh harden`
(which also requires the `www-data` group to be gid 33):

```bash
sudo install -d -m 0770 -o root -g www-data /var/lib/ccure-edge
```

**Portainer's volume** is declared `external`, so Compose will not create it:

```bash
docker volume create portainer_data
```

**The CA file the services mount.** `certs/ccure-internal-ca.crt` is mounted into
`api`, `worker`, `web-worker` and `beat`. With `PGSSLMODE=disable` it is not
read, but it must exist as a file, or Docker creates a directory in its place:

```bash
mkdir -p certs && touch certs/ccure-internal-ca.crt
```

### 3.3 Start

```bash
docker compose up -d        # with COMPOSE_PROFILES=container-scanner: redis, db, api, worker,
                            # web-worker, beat, frontend, gateway-auth, api-gateway, portainer
docker compose ps
docker compose logs -f api
```

The scanner workers sit behind the `container-scanner` profile because raw-socket
discovery and Nmap need direct access to the physical network; `worker` runs with
`network_mode: host` and `NET_ADMIN`/`NET_RAW` (§5).

`api` runs `Backend/start.sh`, which executes
`python db/migrate_production_schema.py` (§7) and then launches uvicorn on
`API_BIND_HOST` (the API's address on the internal `gateway` network,
`172.31.254.20`) with `--no-proxy-headers`; `core/trusted_proxy.py` resolves the
client address from `TRUSTED_PROXIES` instead. The API's startup then applies the
RBAC catalogue and system roles, creates the first administrator from
`DEFAULT_ADMIN_EMAIL`/`DEFAULT_ADMIN_PASSWORD` while there are no users, and seeds
the compliance catalogues.

Then, once, as the database superuser, install the audit-log chain (§7).

### 3.4 Verify

```bash
docker compose ps
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3200/     # 200: the frontend
curl -s http://127.0.0.1:3200/api/ | head                           # system info, through the gateway
curl -s http://127.0.0.1:3200/api/api/pipeline-modes                # the API's own /api/pipeline-modes
docker compose logs -f api
```

The API publishes no port: everything reaches it through `api-gateway`, which the
frontend's `/api/` proxy calls over the internal `gateway` network. Every
published port is bound to loopback.

| Surface            | URL                                                                                                                                             |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend           | `http://127.0.0.1:3200`                                                                                                                         |
| API (via gateway)  | `http://127.0.0.1:3200/api/…` — the `/api` prefix is the gateway's; the API's own `/api/…` routes become `/api/api/…`                           |
| Swagger UI / ReDoc | `http://127.0.0.1:3200/api/docs`, `/api/redoc` — **only when the API runs with `ENV` other than `production`**; the image sets `ENV=production` |
| OpenAPI JSON       | Committed as `Backend/openapi.json`; served at `/api/openapi.json` under the same condition                                                     |
| PostgreSQL         | `127.0.0.1:${POSTGRES_PORT_BINDING}`                                                                                                            |
| Redis              | `127.0.0.1:6379`                                                                                                                                |
| Portainer          | `https://127.0.0.1:9443`                                                                                                                        |

From another machine, forward the port over SSH or serve it over HTTPS through host
nginx as the production VM does ([TLS_SETUP.md](TLS_SETUP.md),
`gateway/edge/host-nginx/`, `scripts/linux/gateway_edge_switch.sh`).

### 3.5 Rebuild rules

| Change                                              | Action                                                                                                                  |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Python under `Backend/`                             | `docker compose restart api` — `./Backend` is bind-mounted                                                              |
| Anything under `core/`, `scans/` or `orchestrator/` | Also `docker compose restart worker` (and `web-worker` for web-scan code)                                               |
| JSX/CSS under `Frontend/src/`                       | `docker compose build frontend && docker compose up -d --no-deps frontend` — assets are baked at build time             |
| `VITE_API_BASE_URL`                                 | Same as above; Vite inlines it at build time                                                                            |
| `requirements.txt`                                  | `docker compose build api worker web-worker beat`                                                                       |
| A root `.env` value                                 | Recreate the service: `docker compose up -d --no-deps --force-recreate <service>` (a restart keeps the old environment) |

> **NOTE — the production VM is different.** Since 13 Oct 2026 it runs released
> images with only data paths mounted, so editing files there changes nothing
> live. Releases are built, deployed and rolled back as described in CLAUDE.md,
> "Deployment: Linux VM" → "Releases"; never deploy with a plain
> `docker compose up`. It is also a development installation (`ENV` and
> `APP_ENV` are `development`), so it serves the Swagger UI.

---

## 4. Path B — Local development without containers

### 4.1 Backend

```bash
cd Backend
python3.11 -m venv .venv
source .venv/bin/activate           # Windows PowerShell: py -3.11 -m venv .venv; .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Then create `Backend/.env` from `Backend/.env.example` and set at minimum:

| Variable                                      | Note                                                                                                                                           |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                | A PostgreSQL URL. Unset, it falls back to a SQLite file                                                                                        |
| `MFA_ENCRYPTION_KEY`                          | The API refuses to start without it                                                                                                            |
| `COMPLIANCE_ENCRYPTION_KEY`                   | Required whenever `APP_ENV` is `production` (as the example sets) or `staging`; otherwise a published fallback key is used and logged at ERROR |
| `CCURE_TOKEN_KEYS_DIR`                        | A keyset directory with an active key: `python -m scripts.security.manage_token_keys --keys-dir <dir> generate --state active`; no default     |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | `redis://127.0.0.1:6379/0` against the compose Redis (the example's `redis://redis:6379/0` resolves only inside the Compose network)           |

Initialise the database (migrations, additive schema, default org, RBAC catalogue):

```bash
python db/migrate_production_schema.py
```

Run the API:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
# or, equivalently for a one-off:
python main.py            # __main__ block runs uvicorn on 0.0.0.0:8000
```

`/docs`, `/redoc` and `/openapi.json` are served unless `ENV=production`.

Run a worker:

```bash
celery -A core.celery_app worker --loglevel=info \
       --queues=scanner,default,compliance --concurrency=20 --prefetch-multiplier=1

celery -A core.celery_app worker --loglevel=info \
       --queues=web_recon,web_crawl,web_dast,web_audit --concurrency=4 --prefetch-multiplier=1
```

Celery Beat (scheduled scans, compliance schedules, the stalled-scan reaper and
purges):

```bash
celery -A core.celery_app beat --loglevel=info
```

Run **exactly one** beat: two schedulers publish every task twice.

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

> **NOTE:** `/user`, `/compliance`, `/platform` and `/api` are **not** proxied.
> Set `VITE_API_BASE_URL=http://localhost:8000` in `Frontend/.env.local` so those
> calls reach the backend. The dev server sets no Content-Security-Policy; the
> image's nginx does (`connect-src 'self'`).

> **CAUTION:** `npm run build` also reads `Frontend/.env.local`. A bundle built
> with `http://localhost:8000` is blocked by that policy once served by the image
> or the browser-test server, and nearly every browser test then fails. Build
> for those with `VITE_API_BASE_URL=/api npm run build`.

---

## 5. Scanner worker

The scanner worker is the `worker` compose service, run with `network_mode: host`
and `NET_ADMIN`/`NET_RAW` so Scapy and Nmap get raw-socket access to the
physical network. It and `web-worker` sit behind the `container-scanner` profile,
which `COMPOSE_PROFILES=container-scanner` in `.env` turns on.

```bash
docker compose up -d                  # the whole stack, workers included
docker compose restart worker         # after changing core/, scans/ or orchestrator/
docker compose down
```

Under host networking Compose DNS does not resolve, so the worker reaches
PostgreSQL at `127.0.0.1:${POSTGRES_PORT_BINDING}` and Redis at `127.0.0.1:6379`.

Run **one** worker on the `scanner` queue. Two workers on one queue is a real
hazard: tasks go to whichever grabs them first, and if they were started from
different code they can be running different code, so restarting "the" worker
silently leaves the other serving stale code. (The Windows deployment's
`start_host_scanner_worker.ps1` guarded against this; it was retired on
9 Oct 2026 with that deployment.)

---

## 6. Environment variables

Read by `Backend/config.py`. `_selected_env_file()` picks `Backend/.env.test` when
`APP_ENV` is `test`/`testing` and that file exists, otherwise `Backend/.env`,
otherwise `.env.test`. `SKIP_DOTENV_LOAD` disables loading entirely. In Docker,
only the variables `docker-compose.yml` names reach a container from the root
`.env` (§2).

### Application

| Variable                  | Default                    | Effect                                                                                                                            |
| ------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `ENV`                     | `development`              | `production` disables `/docs`, `/redoc` and `/openapi.json`. The backend image sets `ENV=production`                              |
| `APP_ENV` / `ENVIRONMENT` | `development`              | `production` or `staging` makes `COMPLIANCE_ENCRYPTION_KEY` mandatory. Compose sets `APP_ENV=production` on every backend service |
| `LOG_LEVEL`               | `INFO`                     |                                                                                                                                   |
| `LOG_FORMAT`              | `text`                     | `json` switches to single-line JSON records                                                                                       |
| `ACCESS_LOG_LEVEL`        | `WARNING`                  | uvicorn access logger                                                                                                             |
| `TRUSTED_PROXIES`         | `127.0.0.1,::1,172.18.0.1` | Exact peers allowed to assert the client address and scheme. Compose sets `127.0.0.1,::1,172.31.254.10` (the gateway) on the API  |
| `CORS_ALLOW_ORIGINS`      | six localhost origins      | Comma-separated                                                                                                                   |
| `FRONTEND_URL`            | `http://localhost:3000`    | Base for links in verification and password-reset mail                                                                            |
| `PORT`                    | `8000`                     | Read by `start.sh`                                                                                                                |
| `API_BIND_HOST`           | `0.0.0.0`                  | Read by `start.sh`; Compose sets the API's gateway-network address                                                                |
| `RELOAD`                  | `false`                    | `true` runs uvicorn with `--reload`                                                                                               |

### Database

| Variable                                              | Default                                | Effect                                                                                                  |
| ----------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                        | `sqlite:///Backend/ccure_users.db`     | PostgreSQL enables pool tuning: `pool_pre_ping`, `pool_size=10`, `max_overflow=20`, `pool_recycle=3600` |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | —                                      | Compose-only; required                                                                                  |
| `POSTGRES_SUPERUSER` / `POSTGRES_SUPERUSER_PASSWORD`  | `postgres` / —                         | Compose-only; the bootstrap superuser of the `db` container; the password is required                   |
| `DATABASE_HOST`                                       | `db`                                   | Compose routing switch                                                                                  |
| `POSTGRES_PORT_BINDING`                               | `5433`                                 | Host bind for the `db` container (loopback only)                                                        |
| `PGSSLMODE`                                           | `verify-full` (compose)                | TLS to PostgreSQL; `.env.example` sets `disable`                                                        |
| `TEST_DATABASE_URL`                                   | pinned to `ccure_pytest_db` in compose | See §9                                                                                                  |

### Vulnerability intelligence

| Variable                                                                            | Default                                                | Effect                                                    |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------- |
| `VULNERABILITY_INTEL_DATABASE_URL`                                                  | —                                                      | Explicit URL; always wins                                 |
| `VULN_DB_HOST` / `_PORT` / `_NAME` / `_USER` / `_PASSWORD`                          | `localhost` / `5432` / `ccure_test` / `ccure_user` / … | Setting **any** of these selects the dedicated database   |
| `PGHOST` / `PGPORT` / `PGDATABASE` / `PGUSER` / `PGPASSWORD`                        | —                                                      | Fallbacks for the above                                   |
| `NVD_API_KEY`                                                                       | —                                                      | Raises the NVD rate limit                                 |
| `VULNCHECK_API_TOKEN`                                                               | —                                                      | Required by `sync_vulncheck.py`, which exits 2 without it |
| `CCURE_FEED_DIR`                                                                    | `<repo>/feeds`                                         | Feed staging root (~3 GB)                                 |
| `OSV_STAGING_DIR` · `MSRC_STAGING_DIR` · `EXPLOIT_STAGING_DIR` · `CSAF_STAGING_DIR` | derived                                                | Per-feed overrides                                        |

### Authentication

| Variable                                         | Default                    | Effect                                                                                                                    |
| ------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `ACCESS_TOKEN_EXPIRES_MINUTES`                   | `30`                       |                                                                                                                           |
| `REFRESH_TOKEN_EXPIRES_DAYS`                     | `7`                        |                                                                                                                           |
| `CCURE_TOKEN_KEYS_DIR`                           | none                       | The ES256 signing keyset; the API refuses to start without an active key. Compose mounts `CCURE_TOKEN_KEYS_HOST_DIR` here |
| `CCURE_SERVICE_REGISTRY_DIR`                     | unset                      | Service identities; unset means every service assertion is refused                                                        |
| `MFA_ENCRYPTION_KEY`                             | none (required)            | The API refuses to start without it; never change it — every enrolled TOTP secret would be orphaned                       |
| `REFRESH_COOKIE_NAME`                            | `ccure_refresh_token`      |                                                                                                                           |
| `REFRESH_COOKIE_PATH`                            | `/`                        |                                                                                                                           |
| `REFRESH_COOKIE_SAMESITE`                        | `lax`                      |                                                                                                                           |
| `REFRESH_COOKIE_SECURE`                          | `false`                    | **Set `true` behind HTTPS**                                                                                               |
| `REFRESH_COOKIE_DOMAIN`                          | unset                      |                                                                                                                           |
| `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` | empty                      | Create the first administrator at startup, only while the database has no users                                           |
| `COMPLIANCE_ENCRYPTION_KEY`                      | none in production/staging | AES-256-GCM master key for stored credentials; outside production a published fallback is used and logged at ERROR        |
| `SCAN_KEY_DIR`                                   | user home                  | Directory `key_path` must resolve under                                                                                   |

There is no JWT secret: tokens are ES256 only, and HS256 was removed.

### Scanning

| Variable                                                                                   | Default                                           | Effect                                                                      |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------- | --------------------------------------------------------------------------- |
| `NMAP_TIMEOUT`                                                                             | `300`                                             | The lease on a single nmap invocation                                       |
| `SCAN_TIME_LIMIT_DISCOVERY` / `_PORT_SCAN` / `_VULN_AUDIT` / `_CREDENTIALED` / `_TOPOLOGY` | `1800` / `7200` / `14400` / `7200` / `1800`       | Per-task soft time limits in seconds; there is no global Celery limit       |
| `SCAN_STALL_TIMEOUT_MINUTES` / `SCAN_QUEUE_TIMEOUT_MINUTES`                                | `90` / `15`                                       | The reaper on beat fails a scan that stalls, or that no worker collects     |
| `NMAP_THREADS`                                                                             | `20`                                              |                                                                             |
| `MAX_NMAP_PROCESSES`                                                                       | `20`                                              | Redis-backed process limiter                                                |
| `NMAP_PROCESS_WAIT_TIMEOUT`                                                                | `900`                                             |                                                                             |
| `NMAP_CACHE_ENABLED`                                                                       | `True`                                            |                                                                             |
| `NMAP_CACHE_TTL_HOURS`                                                                     | `72`                                              |                                                                             |
| `SCAN_IP_BLACKLIST`                                                                        | empty                                             | Comma-separated IPs/CIDRs never scanned                                     |
| `PASSIVE_FIRST_DEFAULT`                                                                    | `False`                                           | OT-safety default                                                           |
| `NUCLEI_BINARY`                                                                            | `nuclei`                                          | Network plugin                                                              |
| `NUCLEI_TEMPLATES`                                                                         | `NUCLEI_TEMPLATES_DIR`, else `~/nuclei-templates` | Network plugin; the image sets `NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates` |
| `NUCLEI_SEVERITIES`                                                                        | `critical,high,medium`                            | ~7 460 of ~13 510 templates                                                 |
| `NUCLEI_TIMEOUT` / `NUCLEI_RATE_LIMIT` / `NUCLEI_CONCURRENCY`                              | `900` / `150` / `50`                              | Network plugin                                                              |
| `CCURE_SNMP_WALK_CONCURRENCY`                                                              | `8`                                               | Topology                                                                    |
| `CCURE_SNMP_WALK_TIMEOUT`                                                                  | `240`                                             | Topology                                                                    |

### Web scanning (DAST)

| Variable                                                                            | Default                                             |
| ----------------------------------------------------------------------------------- | --------------------------------------------------- |
| `NUCLEI_TEMPLATES_DIR`                                                              | `/opt/nuclei-templates`                             |
| `SUBFINDER_BINARY` / `FFUF_BINARY` / `SQLMAP_BINARY`                                | `subfinder` / `ffuf` / `sqlmap`                     |
| `FFUF_WORDLIST`                                                                     | `/opt/wordlists/common.txt`                         |
| `PLAYWRIGHT_TIMEOUT`                                                                | `60000` ms                                          |
| `PLAYWRIGHT_BROWSERS_PATH`                                                          | `/opt/playwright` (image)                           |
| `MAX_CRAWL_DEPTH` / `MAX_CRAWL_URLS` / `CRAWL_CONCURRENCY` / `CRAWL_SETTLE_TIMEOUT` | `5` / `500` / `3` / `5000` ms                       |
| `WEB_SCAN_TIMEOUT`                                                                  | `14400` (4 h)                                       |
| `WEB_SCAN_RATE_LIMIT` / `WEB_STEALTH_RATE_LIMIT`                                    | `5` / `2` req/s (Compose passes `10` for the first) |
| `MAX_RESPONSE_BODY_SIZE`                                                            | `10240` bytes of evidence                           |
| `OAST_ENABLED` / `OAST_SERVER` / `OAST_TOKEN`                                       | `True` / empty / empty                              |
| `NUCLEI_SEVERITY` (DAST)                                                            | `medium,high,critical`                              |
| `NUCLEI_CONCURRENCY` / `NUCLEI_BULK_SIZE` / `NUCLEI_TIMEOUT` (DAST)                 | `25` / `25` / `7200`                                |
| `SQLMAP_LEVEL` / `SQLMAP_RISK` / `SQLMAP_TIMEOUT`                                   | `3` / `2` / `600`                                   |

### Task queue and mail

| Variable                                      | Default                                                                                                |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0`                                                                             |
| `SCANNER_WORKER_CONCURRENCY`                  | `NMAP_THREADS` (20)                                                                                    |
| `SCANNER_WORKER_PREFETCH_MULTIPLIER`          | `1`                                                                                                    |
| `WEB_WORKER_CONCURRENCY`                      | `4` (compose)                                                                                          |
| `CELERY_TASK_ALWAYS_EAGER`                    | `False` (code); Compose defaults it to `True` on api, worker and web-worker, and fixes `False` on beat |
| `SMTP_HOST` / `SMTP_PORT`                     | `localhost` / `1025` (compose: `host.docker.internal`, or `127.0.0.1` for the worker)                  |
| `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_SECURE` | empty / empty / `False`                                                                                |
| `SMTP_FROM_EMAIL`                             | `no-reply@ccureaudit.pro`                                                                              |

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

The API's `start.sh` runs this on every start. On a new Docker volume,
`scripts/docker-postgres-init.sql` has already created the application role
(`ccure_user`, `NOSUPERUSER`), the `admin` role, the `vuln_intel` database and the
`pg_trgm`, `pgcrypto` and `uuid-ossp` extensions.

The script branches on whether the `public` schema has tables:

- **Empty** → `Base.metadata.create_all()`, `create_partitions()` (8 hash
  partitions each for `audit_logs` and `asset_vulnerabilities`) and the triggers
  and grants metadata cannot express, then it stamps Audit's Alembic heads and
  runs `alembic upgrade heads`, so the Policy Pro and Rank branches create their
  schemas as real migrations.
- **Existing** → `alembic upgrade heads`.

It then runs the four additive helpers (`ensure_user_schema`,
`ensure_mac_vendor_schema`, `ensure_scan_schema`, `ensure_topology_schema`),
seeds the default organisation, applies the RBAC catalogue
(`python -m scripts.rbac.sync_catalogue --apply`) and prints a table summary.

### Audit-log chain (once, as the database superuser)

The tamper-evidence chain's privileged half — its own roles and `SECURITY
DEFINER` functions — cannot be created by the application role, so a database
administrator installs it once, after the first start. Until then the API logs a
WARNING at startup and audit events carry no hash.

```bash
for f in bootstrap_chain.sql bootstrap_chain_retention.sql bootstrap_chain_retention_chained.sql; do
  docker exec -i ccure-db psql -X -v ON_ERROR_STOP=1 -U postgres -d ccure_db < Backend/scripts/audit/$f
done
docker exec ccure-api python scripts/audit/verify_chain_bootstrap.py    # N/N checks passed
docker compose restart api
```

`-U` is `POSTGRES_SUPERUSER` and `-d` is `POSTGRES_DB`.
`scripts/audit/verify_retention_bootstrap.py` checks the retention half.
Retention itself is installed but disabled (CLAUDE.md, "Audit-log retention").

### Alembic

```bash
cd Backend
alembic current
alembic history --verbose
alembic heads                       # one per branch: Audit's, then policy_pro and rank
alembic upgrade heads
alembic downgrade <head revision>@-1  # a bare -1 is ambiguous with several heads
alembic revision --autogenerate -m "describe the change"
```

`alembic.ini` leaves `sqlalchemy.url` blank; `alembic/env.py` takes
`DATABASE_URL` from the environment, or from `Backend/.env`. In Docker:
`docker exec -w /app ccure-api alembic heads`.

### Seeding

| Command                                                                          | Effect                                                                                             |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `python -m scripts.seed_compliance`                                              | Frameworks and controls from the fourteen `*_controls_seed.json` files in `data/compliance_seeds/` |
| `python -m scripts.seed_real_rules`                                              | Compliance rules, then evaluates them                                                              |
| `python -m scripts.rbac.bootstrap_admin --email … --reason … --allow-database …` | Make an existing account the platform administrator (first run or recovery)                        |
| `python scripts/print_admin.py`                                                  | Print the seeded admin account                                                                     |

Framework seeding also runs automatically in the API lifespan when any framework's
control count falls below its threshold.

### Backups

```bash
scripts/backup_db.sh --skip-reference-data   # fast: operational data only
scripts/install_backup_schedule.sh           # the 6-hourly and nightly crontab entries
crontab -l; tail backups/backup.log
```

Restore into a fresh database, never over the one serving, by the procedure in
CLAUDE.md, "Backups on the VM". An operational (`_ops`) dump cannot be restored on
its own: it lacks the catalogue tables its findings reference.

> **CAUTION:** `archive_mode` is `off` on the reference deployment, so recovery
> granularity is "since the last dump", not point-in-time. Take an ad-hoc dump
> before any migration, bulk delete or test run.

---

## 8. Vulnerability feeds

The `vuln_intel` database is **not under this repo's Alembic control** — its
`alembic_version` names a revision that exists nowhere in the tree. Each sync
script asserts the tables it needs, so the feeds can be rebuilt onto an empty
server.

The scripts run on the host, from `Backend/` in `Backend/.venv`, and read
`Backend/.env` for the `vuln_intel` connection (`VULN_DB_*`, through the published
loopback port) and any API tokens.

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

```bash
scripts/install_feed_schedule.sh   # from the repository root: schedule the nightly syncs (user crontab)
scripts/run_feed_sync.sh sync_msrc 60   # run one now, exactly as scheduled
```

Budget ~3 GB for the staged archives (`feeds/`); `vuln_intel` itself was about
8 GB with every feed synced (15 Oct 2026). `docker-postgres-init.sql` grants the
application role read access to tables the `admin` role creates there;
`Backend/scripts/grant_vuln_intel_access.sql` grants it on an existing database.

---

## 9. Testing

Run the smallest meaningful test set for a change first:
`python scripts/ci/select_tests.py --files <paths>` (from the repository root)
prints the backend groups and frontend scope, the same mapping CI uses
(CLAUDE.md, "Test targeted-first").

```bash
cd Backend
pytest tests/scans/test_scans.py -v     # one file
pytest tests/repo tests/security        # the groups every change runs
pytest                                  # whole suite, about 28 minutes on a hosted runner
```

The CI invocation is `pytest <targets> [--cov=. --cov-report=xml] -v --reruns 1 -rR`
with two reset tests deselected (they run in the separate Disposable Reset
Validation job). `pytest.ini`: `python_files = test_*.py`,
`addopts = --ignore=test_output.txt`. CI installs `pytest==7.4.4`, `pytest-cov`,
`pytest-rerunfailures`, `bandit==1.9.4` and `ruff` on top of `requirements.txt`,
and sets `MOCK_SCANNERS=true`.

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
> `worker`, `web-worker` and `beat`, so `docker exec … pytest` cannot inherit the
> live URL. That database is not created automatically:
> `docker exec ccure-db psql -U postgres -c "CREATE DATABASE ccure_pytest_db OWNER ccure_user"`.
> **Take a backup before running the suite anyway.**

### Frontend

```bash
cd Frontend
npm test                                         # vitest run (builds the UX4G assets first)
npx vitest related --run <changed files>         # only the tests a change touches
npm run lint
npm run ux4g:check -- --dependencies-only        # after npm ci
VITE_API_BASE_URL=/api npm run build             # then:
npm run ux4g:verify && npm run ux4g:check -- --dist && npm run ux4g:architecture
npm run test:browser                             # Playwright, against the built dist/
```

[Frontend/README.md](../Frontend/README.md) and [ux4g/UX4G_STANDARD.md](ux4g/UX4G_STANDARD.md)
describe the UX4G gates.

### Disposable scan targets

Validation targets are disposable containers, created when needed and destroyed
after use; none is part of this repository. CLAUDE.md records how each phase built
its targets (for example the SCAP validation's `rockylinux/rockylinux:9` and
`ubuntu:24.04` containers, the middleware and database targets) and the findings
each produced. Generate credentials at run time and never write them into
source, configuration, logs or git. A target must stay **un-updated**: an
up-to-date target cannot distinguish "matching works and the host is clean" from
"matching is broken", and zero findings from a known-weak target is a
regression, not a clean host.

### Verification scripts

From `Backend/`:

| Script                                                                           | Checks                                                            |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `scripts/verification/verify_install.py`                                         | Installation prerequisites                                        |
| `scripts/verification/verify_permissions.py`                                     | RBAC seeding                                                      |
| `scripts/verification/check_compliance_data.py`                                  | Compliance catalog                                                |
| `scripts/verification/check_cve_source.py`                                       | Feed connectivity                                                 |
| `scripts/verification/check_target_asset.py`                                     | One asset's record                                                |
| `scripts/verification/verify_compliance_scan_execution.py --allow-database NAME` | One compliance scan end to end; **writes** a run and its findings |
| `scripts/verification/verify_report_integrity.py`                                | Report generation                                                 |
| `scripts/audit/verify_chain_bootstrap.py`                                        | The audit-log chain's privileged objects                          |

---

## 10. Linting and formatting

### Pre-commit

```bash
Backend/.venv/bin/pip install pre-commit
Backend/.venv/bin/python -m pre_commit install
Backend/.venv/bin/python -m pre_commit run --all-files
```

`pre-commit install` installs two hook types, `pre-commit` and `commit-msg`
(`default_install_hook_types`). A clone set up before 9 Oct 2026 has only the
first: run `pre-commit install` once more to add the commit-message check.

`.pre-commit-config.yaml` hooks:

| Hook                                                                                | Scope                                                                                                    | Configuration                                                                                                                                                                         |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gitleaks`                                                                          | all                                                                                                      | v8.30.1, secret detection on the staged changes                                                                                                                                       |
| `check-yaml`, `check-added-large-files`, `end-of-file-fixer`, `trailing-whitespace` | all                                                                                                      | pre-commit-hooks v4.6.0                                                                                                                                                               |
| `black`                                                                             | `^Backend/`                                                                                              | 24.4.2                                                                                                                                                                                |
| `ruff`                                                                              | `^Backend/`                                                                                              | v0.4.8, `--fix`, `--select=E,F,W` (the selection CI runs), ignoring `E402,F401,F841,E711,E712,E741,F601,E722,F821,E501`                                                               |
| `bandit`                                                                            | `^Backend/`                                                                                              | 1.9.4, `-lll`, excluding `tests`; no rule skipped (exceptions are `# nosec` on the line)                                                                                              |
| `prettier`                                                                          | `^(Frontend/\|docs/.*\.md$)`, except the dated audit record under `docs/audits/plugin-audit-2026-10-14/` | prettier@3.2.5                                                                                                                                                                        |
| `eslint`                                                                            | `^Frontend/`                                                                                             | eslint@8.57.0 + react + react-hooks, `--max-warnings=0`                                                                                                                               |
| `no-ai-coauthor` (local, commit-msg stage)                                          | the commit message                                                                                       | rejects a `Co-authored-by` trailer naming an AI agent (Claude, Anthropic, Codex, OpenAI, Copilot, …); human co-authors pass. `scripts/git/check_ai_coauthors.py`; rule in `CLAUDE.md` |
| `openapi-contract` (local, runs last)                                               | backend `.py` except `tests/`, `openapi.json`, `requirements.txt`                                        | regenerates `Backend/openapi.json` exactly as CI does and stages it if it changed; needs `Backend/.venv` with `requirements.txt` installed (or `CCURE_BACKEND_PYTHON`)                |

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

The commands CI's Backend Validation runs:

```bash
black Backend/
ruff check Backend/ --select=E,F,W --ignore=E402,F401,F841,E711,E712,E741,F601,E722,F821,E501
bandit -r Backend/ -x Backend/tests -lll
```

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
3. every registered RBAC permission key (from the modules' permission
   declarations) appears in `RBAC_Management_Permissions.md`.

> **NOTE:** `docker-compose.yml` mounts `./docs:/docs:ro` on the `api` service.
> Without that mount the test cannot find the files inside the container and fails
> on all three — which reads as documentation drift when it is a missing volume.

---

## 12. CI pipelines

Five GitHub Actions workflows live in `.github/workflows/`. **Current state:** the
primary repository is CDAC GitLab, where no CI/CD is configured yet, and the
GitHub Actions account has no minutes left, so no pipeline is running. Until one
is, run the same checks locally (§9, §10) before opening a merge request.

| Workflow             | Runs on                                                                   | Does                                                                                      |
| -------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `ci.yml`             | pull request, push to master (targeted); nightly, `v*` tag, manual (full) | Backend Validation, Frontend Validation and Disposable Reset Validation (below)           |
| `security.yml`       | pull request, push, nightly, manual                                       | gitleaks over the commits, pip-audit and npm audit gates, a Bandit medium-severity report |
| `images.yml`         | nightly, `v*` tag, manual                                                 | Builds the three images, Trivy gate on fixable critical/high, smoke tests                 |
| `gateway.yml`        | push to master touching the gateway, nightly, manual                      | The gateway and trust-boundary Docker harnesses                                           |
| `browser-matrix.yml` | nightly, manual                                                           | The browser suite in Chromium, Firefox and WebKit                                         |

`ci.yml` first runs `scripts/ci/select_tests.py` to choose the scope
([ci/CI_SCOPE.md](ci/CI_SCOPE.md)):

- **Backend Validation** (Python 3.12, PostgreSQL 18 and Redis 7 services):
  Bandit and ruff; the schema bootstrap and seeds; the Alembic round-trip (every
  head down one and back up) on a full run or when a migration changed; the
  OpenAPI schema diff; the selected pytest groups (all of them on a full run,
  with coverage); the hermetic gateway suites; the documentation build and
  integrity test.
- **Frontend Validation** (Node 22): the UX4G dependency check, build, asset
  verification, the selected unit tests, `ux4g:architecture`, Chromium browser
  tests when the change warrants them, and ESLint.
- **Disposable Reset Validation**: the two development-reset tests, against a
  database prepared with a separate DBA role and the audit-chain bootstraps.

> **IMPORTANT:** the OpenAPI diff means **any** route change must be accompanied
> by a regenerated `Backend/openapi.json` (the pre-commit hook does it;
> `cd Backend && python -m scripts.openapi.generate` by hand). Otherwise CI fails
> with "API schema changed but the tracked contract was not updated."

---

## 13. Common tasks

| Task                       | Command                                                                                                                                                                          |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Interactive scan CLI       | `cd Backend && python scripts/cli.py`                                                                                                                                            |
| Make an admin              | `python -m scripts.rbac.bootstrap_admin --help`                                                                                                                                  |
| Show the schema revision   | `docker exec -w /app ccure-api alembic current`                                                                                                                                  |
| Tail API logs              | `docker compose logs -f api`                                                                                                                                                     |
| Tail worker logs           | `docker compose logs -f worker`                                                                                                                                                  |
| Open a DB shell            | `docker compose exec db psql -U ccure_user -d ccure_db`                                                                                                                          |
| Restart after Python edits | `docker compose restart api`                                                                                                                                                     |
| Rebuild the frontend       | `docker compose build frontend && docker compose up -d --no-deps frontend`                                                                                                       |
| List the signing keys      | `docker run --rm -u 0 -v ~/ccure-keys:/keys -v "$PWD/Backend":/app:ro -w /app ccure-audit-pro-backend:latest python -m scripts.security.manage_token_keys --keys-dir /keys list` |

---

## 14. Troubleshooting

| Symptom                                                            | Cause                                                                                                        | Fix                                                                                                                     |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| Compose refuses to start: `required variable … is missing a value` | One of the seven `${VAR:?}` variables is unset                                                               | Set it in the root `.env` (§3.1)                                                                                        |
| Compose: external volume `portainer_data` not found                | The volume is declared `external`                                                                            | `docker volume create portainer_data`                                                                                   |
| `api-gateway` will not start                                       | `/var/lib/ccure-edge` does not exist and Compose may not create it                                           | §3.2                                                                                                                    |
| The API exits: the token keyset has no active key                  | No key, or `CCURE_TOKEN_KEYS_HOST_DIR` wrong                                                                 | §3.2; an absolute path, directory mode 711, key owned by uid 1000, mode 600                                             |
| The API keeps restarting, or logs `Database connection failed`     | `start.sh` cannot reach PostgreSQL: often `PGSSLMODE` unset, so `verify-full` against a database without TLS | `PGSSLMODE=disable` in the root `.env`, then `docker compose up -d`                                                     |
| No administrator after the first start                             | `DEFAULT_ADMIN_EMAIL`/`PASSWORD` were empty                                                                  | Set them in `Backend/.env` and restart the API while there are still no users; otherwise `scripts.rbac.bootstrap_admin` |
| The API logs a WARNING that the audit chain is not installed       | The superuser bootstrap was never run                                                                        | §7, "Audit-log chain"                                                                                                   |
| Credentialed scans complete as unauthenticated audits              | `COMPLIANCE_ENCRYPTION_KEY` changed after the credentials were stored                                        | Restore the old value, or re-enter the stored credentials                                                               |
| Phase 1 finds nothing on a LAN                                     | No raw-socket privilege, Npcap missing on Windows, or the worker not on a Linux host                         | Run elevated / install Npcap; the compose worker needs a Linux Docker host                                              |
| Port scan is slow and version-poor                                 | `nmap` not on PATH — PortEngine logged a warning and fell back to TCP connect                                | Install nmap                                                                                                            |
| `nuclei_probe` produces nothing                                    | Binary absent (logged as a coverage gap), or a two-argument `run()` was introduced                           | Install nuclei; keep the three-argument serial signature                                                                |
| Web scan reports a tool gap                                        | `ToolCoverage` recorded `unavailable`                                                                        | Install the tool, or accept the recorded gap                                                                            |
| CVE lookups return nothing                                         | `VULN_DB_*` unset, so `VulnIntelConfig` fell through to `DATABASE_URL`                                       | Set `VULN_DB_NAME` et al., or `VULNERABILITY_INTEL_DATABASE_URL`                                                        |
| Frontend calls hit the Vite server and 404                         | `/user`, `/compliance`, `/platform`, `/api` are not proxied                                                  | Set `VITE_API_BASE_URL` in `Frontend/.env.local`                                                                        |
| The built frontend's API calls fail with CSP errors                | Built with `VITE_API_BASE_URL` other than `/api` (for example from `.env.local`)                             | `VITE_API_BASE_URL=/api npm run build`, or `docker compose build frontend`                                              |
| Frontend still points at the old API URL                           | `VITE_API_BASE_URL` is inlined at build time                                                                 | `docker compose build frontend`                                                                                         |
| `test_docs_integrity` fails on three missing files                 | `./docs` not mounted into the container                                                                      | Confirm the `./docs:/docs:ro` volume                                                                                    |
| CI: "API schema changed but the tracked contract was not updated." | Routes changed without regenerating the baseline                                                             | Regenerate `Backend/openapi.json` (§12)                                                                                 |
| Two workers serving different code                                 | A second worker was started on the `scanner` queue                                                           | Stop the extra one; `docker compose ps` shows one `worker`                                                              |
| Scan History shows the download time as the scan date              | Report generation was made unconditional                                                                     | Serve the stored PDF; regenerate only when missing                                                                      |

---

## 15. Related documents

- [README.md](../README.md) and [CLAUDE.md](../CLAUDE.md)
- [architecture/README.md](architecture/README.md)
- [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md)
- [BACKEND_API_REFERENCE.md](BACKEND_API_REFERENCE.md)
- [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)
- [AUTHENTICATION_AND_AUTHORIZATION.md](AUTHENTICATION_AND_AUTHORIZATION.md)
- [RBAC_Management_Permissions.md](RBAC_Management_Permissions.md)
- [SCAN_ENGINE_DEEP_DIVE.md](SCAN_ENGINE_DEEP_DIVE.md)
- [FRONTEND_ARCHITECTURE.md](FRONTEND_ARCHITECTURE.md)
- [TLS_SETUP.md](TLS_SETUP.md)
- [ci/CI_SCOPE.md](ci/CI_SCOPE.md)
