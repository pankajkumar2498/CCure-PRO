# Master System Architecture & Container/Deployment Architecture

> Part of the CCure Audit PRO architecture documentation package. See
> [README.md](../../architecture/README.md) for the package index. Component-level detail and
> citations live in [00_INVENTORY.md](00_INVENTORY.md); this document is the
> diagrams built on top of that inventory.

---

## A. Master System Architecture Diagram

This shows the full request path, every currently-started process, and the
trust boundary each arrow crosses. Dashed edges are asynchronous or
best-effort (Celery dispatch, Pub/Sub, background sync). Components drawn with
a dotted border are defined in `docker-compose.yml` but **not started** by the
supported startup path (`scripts/start_host_scan_stack.ps1`) — see
[00_INVENTORY.md §1](00_INVENTORY.md#1-runtime-topology-as-it-actually-starts).

```mermaid
graph TB
    USER["User — Analyst / Admin / Superadmin"]
    BROWSER["Browser<br/>React 18 SPA (Vite build)"]

    subgraph EDGE["Edge — Windows host, routable interface"]
        NGINX["Host Nginx (CCureNginx service)<br/>TLS :443 terminate, :80→301<br/>rate zones: ccure_auth 30r/m, ccure_api 20r/s<br/>HSTS 300s, security headers, WS/SSE passthrough"]
    end

    subgraph DOCKER["Docker Compose network — every published port bound to 127.0.0.1"]
        FE["frontend container<br/>nginx:stable-alpine :3200→80<br/>serves built SPA, CSP on index.html"]

        subgraph API_BOX["api container :8000 — FastAPI + uvicorn"]
            MW["Middleware chain (outer→inner):<br/>BaselineRateLimitMiddleware (600/min)<br/>→ CORSMiddleware (allow-list)<br/>→ request-ID + PNA preflight + security headers"]
            AUTHZ["Auth: HTTPBearer → get_current_user<br/>Authz: require_permission / require_role"]
            ROUTERS["21 routers, 175 HTTP ops + 2 WS<br/>(auth, scans, assets, findings, dashboard,<br/>web-scans, compliance, admin-*, audit, ...)"]
            LIFESPAN["Lifespan: schema bootstrap, RBAC seed,<br/>compliance catalogue seed, HostDiscoveryAPI,<br/>cleanup loop, 24h NVD sync loop"]
        end

        REDIS[("redis:7-alpine :6379<br/>Celery broker + result backend<br/>+ Pub/Sub (progress, notifications)<br/>+ rate-limit counters")]
        BEAT["beat container<br/>Celery beat — publishes only, 7 schedules"]
        WEBWORKER["web-worker container<br/>Celery: web_recon, web_crawl, web_dast, web_audit<br/>Playwright · Nuclei · ffuf · sqlmap · SSLyze · subfinder"]

        DBC["ccure-db container<br/>postgres:15-alpine :5433"]:::unused
        WORKERC["worker container<br/>queues: scanner,default,compliance"]:::unused
        GWC["gateway container :8082"]:::unused
        CLAMAVC["clamav container"]:::optional
    end

    subgraph HOST["Windows host — outside Docker"]
        HOSTWORKER["Host scanner worker<br/>Celery: scanner, default, compliance<br/>raw sockets — Scapy + Nmap"]
        ENGINES["Engines: discovery · port · vulnerability (15 plugins)<br/>credentialed (SSH) · topology (SNMP) · compliance rules"]
        HOSTPG[("PostgreSQL 18 — D:\PostgreSQL\18\data<br/>TLS verify-full<br/>ccure_test (app, 47 tables) + vuln_intel")]
        TOOLS["nmap · nuclei · subfinder · ffuf · sqlmap<br/>Paramiko(SSH) · pysnmp"]
        BACKUP["Scheduled Task: CCure DB Backup<br/>pg_dump every 6h → backups/*.dump"]
    end

    subgraph EXTERNAL["External systems"]
        SMTP["SMTP relay<br/>password reset, email OTP, registration"]
        NVD["NVD API"]
        VULNCHECK["VulnCheck KEV API"]
        FEEDS["OSV · MSRC · CSAF (Siemens/CISA/Red Hat)<br/>ExploitDB/Metasploit/Nuclei-tags"]
    end

    USER --> BROWSER
    BROWSER -->|HTTPS :443| NGINX
    NGINX -->|"/ (SPA)"| FE
    NGINX -->|"/api/*, /api/auth/*"| MW
    FE -.->|VITE_API_BASE_URL baked at build| MW

    MW --> AUTHZ --> ROUTERS
    ROUTERS -->|SQLAlchemy, TLS verify-full| HOSTPG
    ROUTERS -.->|".delay() task dispatch"| REDIS
    ROUTERS -.->|SSE / WS ticket auth| REDIS

    REDIS -.-> BEAT
    REDIS -.->|scanner,default,compliance| HOSTWORKER
    REDIS -.->|web_recon,web_crawl,web_dast,web_audit| WEBWORKER

    HOSTWORKER --> ENGINES --> HOSTPG
    ENGINES --> TOOLS
    WEBWORKER --> HOSTPG

    ROUTERS --> SMTP
    HOSTWORKER -.->|"24h loop + admin trigger"| NVD
    HOSTWORKER -.->|"feed sync scripts"| VULNCHECK
    HOSTWORKER -.->|"feed sync scripts"| FEEDS

    BACKUP -.->|pg_dump, read-only to app| HOSTPG

    classDef unused stroke-dasharray: 5 5,fill:#eee,color:#888
    classDef optional stroke-dasharray: 2 2,fill:#eef,color:#448
```

### Reading this diagram

- **One TLS boundary.** Host Nginx is the only listener on a routable
  interface (`0.0.0.0:443`); every container port is bound to `127.0.0.1`, so
  nothing inside Docker is reachable except through it or from the host itself.
- **Two execution planes for scanning.** The network/credentialed/compliance
  pipelines run on the Windows host (raw-socket requirement); the DAST pipeline
  runs inside a container. Both read/write the same host PostgreSQL, so the
  data model is unified even though the compute is split.
- **One database server, two databases**, both TLS `verify-full`: `ccure_test`
  (this repo's Alembic-controlled schema) and `vuln_intel` (fed by separate
  sync scripts, no Alembic control of its own).
- **Redis is a single point of coordination, not of truth.** Every progress/
  notification publisher catches `RedisError` and degrades to a log line — the
  authoritative state for scans, findings and compliance runs is always
  PostgreSQL. An outage here delays live updates, it does not lose data.
- **Grey dashed boxes** (`ccure-db`, `worker`, `gateway`) are real
  `docker-compose.yml` services that do not participate in this deployment's
  actual request or task flow. They are drawn to show they exist, not because
  traffic reaches them.

---

## B. Container / Deployment Architecture

### B.1 What actually starts, in order

```mermaid
sequenceDiagram
    participant Op as Operator
    participant Script as start_host_scan_stack.ps1
    participant Compose as docker compose
    participant HW as start_host_scanner_worker.ps1

    Op->>Script: run (optionally -Rebuild / -Recreate)
    Script->>Compose: up -d redis api frontend web-worker beat
    Note over Compose: db comes up too — declared dependency<br/>of api, never queried
    Compose-->>Script: containers healthy (redis, db healthchecks gate api/worker start)
    Script->>HW: launch in current/new window
    Note over HW: Celery worker, --queues=scanner,default,compliance<br/>runs as the interactive/service user with<br/>raw-socket privilege (Npcap on Windows)
    Note over Op: Host Nginx and PostgreSQL are Windows services,<br/>started independently of this script (already running)
```

`worker` and `gateway` are named explicitly in the compose args' complement —
i.e. they are the two services the script's `$composeArgs` construction
excludes by design (see [00_INVENTORY.md §1](00_INVENTORY.md#1-runtime-topology-as-it-actually-starts)).
Anyone running a bare `docker compose up -d` instead of this script will start
`worker` too, which the script's own comments warn corrupts scan results by
racing the host worker for the same queue.

### B.2 Container inventory

| Service      | Container name     | Image / build                                                            | Published bind      | Restart policy   | Profile gate        | Runs in this deployment?                       |
| ------------ | ------------------ | ------------------------------------------------------------------------ | ------------------- | ---------------- | ------------------- | ---------------------------------------------- |
| `redis`      | `ccure-redis`      | `redis:7-alpine`                                                         | `127.0.0.1:6379`    | `no`             | none                | **Yes**                                        |
| `db`         | `ccure-db`         | `postgres:15-alpine`                                                     | `127.0.0.1:5433`    | `no`             | none                | Started (dependency), traffic never reaches it |
| `api`        | `ccure-api`        | `./Backend/Dockerfile`                                                   | `127.0.0.1:8000`    | `no`             | none                | **Yes**                                        |
| `worker`     | `ccure-worker`     | `./Backend/Dockerfile`, runs as `root`                                   | —                   | `no`             | `container-scanner` | **No**                                         |
| `beat`       | `ccure-beat`       | `./Backend/Dockerfile`, starts as `root`, drops to `ccure` via `setpriv` | —                   | `no`             | none                | **Yes**                                        |
| `web-worker` | `ccure-web-worker` | `./Backend/Dockerfile`, runs as `root`                                   | —                   | `no`             | `container-scanner` | **Yes** — started explicitly by name           |
| `frontend`   | `ccure-frontend`   | `./Frontend/Dockerfile`                                                  | `127.0.0.1:3200:80` | `no`             | none                | **Yes**                                        |
| `gateway`    | `ccure-gateway`    | `nginx:stable-alpine`                                                    | `127.0.0.1:8082:80` | `no`             | `alt-gateway`       | **No**                                         |
| `clamav`     | `ccure-clamav`     | `clamav/clamav:stable`                                                   | — (internal)        | `unless-stopped` | `av`                | **No**, optional                               |

All restart policies are deliberately `"no"` except `clamav`
(`unless-stopped`) — this stack is manual-start end to end, specifically so
`beat` cannot resurrect itself after a host reboot with no worker consuming its
queue (see `docker-compose.yml`'s inline comment on the `beat` service).

### B.3 Volumes

| Volume                                 | Type         | Mounted by                            | Purpose                                                                                                       |
| -------------------------------------- | ------------ | ------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `pgdata`                               | named volume | `db`                                  | Persists the (unused) containerized Postgres data dir                                                         |
| `backend_venv`                         | named volume | `api`, `worker`, `beat`, `web-worker` | Python virtualenv, avoids reinstalling deps on every container recreate                                       |
| `beat_state`                           | named volume | `beat`                                | `celerybeat-schedule` file — kept out of the bind-mounted repo tree so it can't be committed by accident      |
| `clamav_db`                            | named volume | `clamav`                              | Signature database (~2 GB resident)                                                                           |
| `./Backend:/app`                       | bind mount   | `api`, `worker`, `beat`, `web-worker` | Live-reload of Python source; no rebuild needed for backend changes                                           |
| `./Backend/reports:/app/reports`       | bind mount   | `api`, `worker`, `web-worker`         | Generated PDF/CSV output, shared with the host filesystem                                                     |
| `./docs:/docs:ro`                      | bind mount   | `api`                                 | Read-only, lets `test_docs_integrity.py` find the doc files from inside the container                         |
| `./backups:/backups:ro`                | bind mount   | `api`, `worker`                       | Read-only; `audit_retention.assert_backup_recent` checks the newest dump's mtime here before allowing a purge |
| `./certs/ccure-internal-ca.crt:...:ro` | bind mount   | `api`, `worker`, `beat`, `web-worker` | Trust anchor for `sslmode=verify-full` against the host PostgreSQL                                            |

### B.4 What happens when a container restarts

- **`api` restart** — picks up Python source changes immediately (bind-mounted,
  no image rebuild). Re-runs the full lifespan sequence: schema bootstrap,
  RBAC/compliance seeding (idempotent, self-heals if control counts are below
  threshold), re-registers the two background asyncio loops. In-flight HTTP
  requests are dropped; in-flight Celery tasks are unaffected (they run in the
  worker process, not the API process).
- **`frontend` restart alone does _not_ pick up JSX changes** — the SPA is
  baked at Docker _build_ time (`VITE_API_BASE_URL` is a build arg), so a
  restart only re-serves the same static bundle. Requires
  `docker compose build frontend && docker compose up -d --no-deps frontend`.
- **`redis` restart** — every Celery task in flight loses its broker
  connection; `RATE_LIMIT_MEMORY_FALLBACK` (20/minute, per-worker-process)
  takes over rate limiting until Redis returns, logged once on the transition
  (`RATE_LIMIT_DEGRADED`). SSE/WebSocket progress streams degrade to
  heartbeat-only; nothing already committed to PostgreSQL is lost.
- **`beat` restart** — resumes from `beat_state` volume (last-run times
  survive), so a task already due fires promptly rather than waiting a full
  interval.
- **Host scanner worker restart (not a container)** — any scan whose task was
  mid-execution on that process is abandoned; `core/scan_control.py`'s
  cooperative-cancellation design means nothing auto-resumes it. The
  `compliance` queue also stops being consumed, since it's bound only here, not
  by any started container.

### B.5 External access summary

| Path                                                | Who reaches it               | TLS                    | Notes                                                                   |
| --------------------------------------------------- | ---------------------------- | ---------------------- | ----------------------------------------------------------------------- |
| `https://ccurepro.cdacb.in` / `https://10.180.6.14` | Any LAN client               | Yes, private-CA issued | HSTS only pins the hostname form (RFC 6797 §8.1.1 excludes IP literals) |
| `http://<host>:80`                                  | Any LAN client               | No                     | 301 redirect to 443 only                                                |
| `127.0.0.1:8000` (API direct)                       | Local tooling only           | No                     | Not reachable off-host; local dev/debug path                            |
| `127.0.0.1:3200` (frontend direct)                  | Local tooling only           | No                     | Same                                                                    |
| `127.0.0.1:8082` (gateway)                          | Nobody — service not started | No                     | Defined for deployments that terminate TLS elsewhere; unused here       |

---

_Previous: [00_INVENTORY.md](00_INVENTORY.md) — component inventory and
enabled/disabled matrix. Next in the package: per-module architecture
diagrams (Section D of the package), Authentication & Authorization, Database
Architecture, Audit Architecture, Compliance Architecture, Security
Architecture, and the remaining sections per the package README._
