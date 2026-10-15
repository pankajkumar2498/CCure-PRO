# CCure Audit PRO

CCure Audit PRO is a network security assessment platform. It discovers the
hosts on a network, identifies their services and installed software, finds
vulnerabilities and configuration weaknesses (with or without credentials for
the host), maps the results to compliance frameworks, and tracks each finding
through remediation to a verified fix. Results are exported as PDF, CSV, XLSX
and JSON reports.

It is the **Audit** product of the common CCure platform, which also hosts
CCure Policy Pro, CCure Rank and CCure IR (see [Platform and modules](#platform-and-modules)).

**Contents**

1. [Application overview](#1-application-overview)
2. [Installation and setup](#2-installation-and-setup)
3. [Day-to-day operation](#3-day-to-day-operation)
4. [Git collaboration workflow (CDAC GitLab)](#4-git-collaboration-workflow-cdac-gitlab)
5. [Further documentation](#5-further-documentation)

---

## 1. Application overview

### What it does

**Network assessment** — a scan runs in up to three chained phases, selected
by its pipeline mode (`basic`, `asset`, `vulnerability_audit`):

- **Host discovery** with Scapy (ARP, ICMP, TCP and UDP probes).
- **Asset and service discovery** with Nmap: open ports, services, products
  and the CPE identifiers nmap reports, plus SNMP, mDNS and NetBIOS enrichment.
- **Vulnerability audit**: installed products are matched against the
  vulnerability intelligence database, network checks probe for exposed
  conditions (anonymous FTP, weak SSH algorithms, SMBv1, TLS weaknesses through
  sslyze and more), and Nuclei templates confirm reachable vulnerabilities.

**Credentialed assessment** — with a stored credential, the scanner logs in and
reads the host itself:

- Linux and Unix over SSH (with `sudo`, `dzdo` or `pfexec` elevation).
- Windows natively over WinRM, or over SMB, Remote Registry and WMI, including
  patch assessment against Microsoft's published fixed builds.
- Databases: PostgreSQL, MySQL/MariaDB and Microsoft SQL Server.

**Configuration audit** — one engine evaluates hardening rules on the
credentialed session: a built-in rule pack, local privilege-escalation checks,
middleware configuration (nginx, Apache httpd, Tomcat, Docker daemon),
container and Kubernetes checks, benchmark packs loaded as data, and
STIG/SCAP content converted from published XCCDF/OVAL datastreams.

**Web application scanning** — a separate four-phase pipeline (recon, crawl,
detect, audit) using subfinder, ffuf, Nuclei, sqlmap, sslyze and a headless
browser.

**Compliance** — controls, rules, evidence uploads, attestations and reports
(PDF/DOCX). ISO/IEC 27001:2022 (with a Statement of Applicability), NIST CSF
2.0 and CIS Controls v8.1 are active; further catalogues (PCI DSS, the HIPAA
Security Rule and others) are seeded and can be enabled.

**Findings and remediation** — scan scheduling (time-zone aware), reusable
scan policies, scan-to-scan comparison, ownership and SLA deadlines (including
CISA KEV dates), risk acceptance, and fixes that are verified only by a later
scan, never by a person.

**Assets** — an inventory keyed by organisation and address, change history,
service and certificate views, and a network topology map.

**Platform** — multi-organisation tenancy, role-based access control
(permission keys, roles and scoped assignments), TOTP multi-factor
authentication, a tamper-evident audit log, notifications, a self-registration
policy and email-domain screening.

**Vulnerability intelligence** — a separate `vuln_intel` database, filled by
sync scripts from NVD, OSV (22 ecosystems), the Microsoft Security Update
Guide, CSAF advisories (Siemens ProductCERT, CISA ICS/OT, Red Hat), CISA KEV,
VulnCheck KEV and exploit sources (ExploitDB, Metasploit, Nuclei templates).

### Platform and modules

After sign-in, **CCure Home** (`/`) lists the platform's products from the
backend's module registry (`GET /platform/modules`).

| Product          | State                                                                                |
| ---------------- | ------------------------------------------------------------------------------------ |
| CCure Audit      | The product described here. Its dashboard is `/audit-dashboard`.                     |
| CCure Policy Pro | Module folder and registry entry only; shown as "Not yet available".                 |
| CCure Rank       | Module folder and registry entry only; shown as "Not yet available".                 |
| CCure IR         | A separate service, listed on CCure Home; shown as "Not yet available" until built.  |

User, organisation, role, email-domain and audit-log administration are shared
platform capabilities under **Administration** (`/admin/*`).

### Technology stack

| Layer           | Technology                                                                                                                       |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Frontend        | React 18, React Router 6, Vite 8, the UX4G design system ([standard](docs/ux4g/UX4G_STANDARD.md)); Vitest and Playwright tests   |
| Backend API     | Python 3.11, FastAPI, Pydantic 2, SQLAlchemy 2, Alembic, uvicorn                                                                  |
| Background work | Celery 5 workers and Celery beat, with Redis 7 as broker and result backend                                                       |
| Database        | PostgreSQL 18: the application database and the `vuln_intel` database                                                            |
| Scanning tools  | Scapy, Nmap (python-nmap), Nuclei, sslyze, subfinder, ffuf, sqlmap, Playwright with Chrome, paramiko (SSH), pywinrm, impacket       |
| Reports         | ReportLab (PDF), openpyxl (XLSX), python-docx (DOCX), CSV and JSON                                                               |
| Gateway         | nginx (`api-gateway`) with a token-checking service (`gateway-auth`) that verifies ES256 access tokens                           |
| Packaging       | Docker and Docker Compose                                                                                                        |

### Architecture

```
 Browser
    │  http://127.0.0.1:3200            (production: https://<host> through host nginx)
    ▼
 frontend  (nginx serving the built React app; /api/ is proxied on)
    │
    ▼
 api-gateway  (nginx, 172.31.254.10)  ──auth_request──▶  gateway-auth (172.31.254.11)
    │                                                     checks the token against the
    ▼                                                     API's published keys (JWKS)
 api  (FastAPI, 172.31.254.20:8000)
    │   PostgreSQL ─ db (ccure_db + vuln_intel)
    │   Redis ───── redis (Celery broker, rate-limit counters)
    ▼
 worker (network scans, host networking) · web-worker (web scans) · beat (schedules)
```

| Service       | Container            | Role                                                                                     | Published on              |
| ------------- | -------------------- | ---------------------------------------------------------------------------------------- | ------------------------- |
| `frontend`    | `ccure-frontend`     | Serves the React app and proxies `/api/` to the gateway                                  | `127.0.0.1:3200`          |
| `api-gateway` | `ccure-api-gateway`  | The only ingress to the API; asks `gateway-auth` to decide each request                   | nothing (internal network) |
| `gateway-auth`| `ccure-gateway-auth` | Verifies access tokens against the API's public keys                                     | nothing                   |
| `api`         | `ccure-api`          | FastAPI application; runs database migrations and seeding at start                       | nothing                   |
| `worker`      | `ccure-worker`       | Celery worker for scans and compliance (queues `scanner`, `default`, `compliance`); host networking for raw-socket scanning | — |
| `web-worker`  | `ccure-web-worker`   | Celery worker for web application scans                                                   | —                         |
| `beat`        | `ccure-beat`         | Celery beat: scheduled scans, stalled-scan reaper, purges                                 | —                         |
| `db`          | `ccure-db`           | PostgreSQL 18                                                                            | `127.0.0.1:${POSTGRES_PORT_BINDING}` |
| `redis`       | `ccure-redis`        | Redis 7                                                                                  | `127.0.0.1:6379`          |
| `portainer`   | `portainer`          | Container management UI                                                                  | `127.0.0.1:9443`          |
| `clamav`      | `ccure-clamav`       | Optional malware scanning of evidence uploads (`av` profile)                             | nothing                   |

Every port is bound to loopback. On the production VM, host nginx terminates
TLS on port 443 and reaches the gateway over a unix socket; see
[docs/TLS_SETUP.md](docs/TLS_SETUP.md) and CLAUDE.md, "Rate limiting" and
"Deployment: Linux VM".

### Repository layout

```
Backend/        FastAPI application, scan engines, Celery tasks, Alembic migrations, tests
  ccure_platform/   shared platform: identity, RBAC, administration, audit log, module registry
  ccure_audit/      Audit module boundary; most Audit code is still in core/, engines/, scans/
  scripts/          operator scripts: seeding, RBAC, security keys, vulnerability feeds, audit chain
Frontend/       React application (shell, design system, modules/audit), unit and browser tests
gateway/        API gateway: nginx configuration, route policy, gateway-auth, test harnesses
scripts/        host scripts: database backups, feed schedule, PostgreSQL init SQL, Linux and TLS helpers
docs/           architecture records, setup guide, UX4G standard, CI notes
docker-compose.yml   the whole stack
.env.example         template for the Compose environment (root .env)
```

---

## 2. Installation and setup

This section takes a fresh clone to a running application on one Linux host.
Every command below is taken from the repository's own files.

### 2.1 Prerequisites

| Requirement               | Version                                                   | Why                                                                                                                                      |
| ------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Linux host                | Ubuntu 24.04 is the deployment target                     | The scanner worker uses host networking and the `NET_ADMIN`/`NET_RAW` capabilities to put raw-socket scans on the real network interface |
| Docker Engine and Compose | Verified with Docker 29.9 and the Compose plugin 5.6      | The stack is defined in `docker-compose.yml` and started with `docker compose`                                                           |
| Git                       | any recent                                                |                                                                                                                                          |
| `python3`                 | any (on the host)                                         | Only to generate secrets; the application itself runs in the images                                                                     |
| `sudo`                    |                                                           | Once, to create the gateway's socket directory                                                                                           |
| Hardware                  | The compose file is sized for 8 CPUs and 15 GB of RAM     | PostgreSQL is configured with 2 GB of shared buffers; a fully synced `vuln_intel` database is about 8 GB                                 |
| Network                   | Outbound HTTPS                                            | Docker images, Python and npm packages during the build, vulnerability feeds; plus routes to the networks you scan                       |

For tooling outside Docker (the git hooks, tests, feed scripts): Python 3.11
for `Backend/.venv` (the image's version) and Node.js 22 with npm for
`Frontend/` (the version CI uses; the frontend image builds on Node 26).

### 2.2 Get the code

```bash
git clone https://git.cdacb.in/pnjkumar/CCure-PRO.git
cd CCure-PRO
```

If the clone fails with `unable to get local issuer certificate`, see
[Access to CDAC GitLab](#41-access-to-cdac-gitlab).

### 2.3 Configure the environment

There are **two** environment files, for two audiences:

| File           | Read by                                                                | Holds                                                                                               |
| -------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `.env` (root)  | Docker Compose, which passes each value it uses to the services        | Database passwords, encryption keys, the token key directory, web and mail settings                 |
| `Backend/.env` | The `api` container (it is bind-mounted) and scripts run on the host   | Application settings Compose does not pass: the first administrator, feed tokens, rate limits, logging |

Both are git-ignored. `worker`, `web-worker` and `beat` set
`SKIP_DOTENV_LOAD=1` and never read `Backend/.env`. Where both files set a
variable, the value Compose passes wins.

```bash
cp .env.example .env
cp Backend/.env.example Backend/.env
chmod 600 .env Backend/.env
```

**Root `.env` — values you must set** (Compose refuses to start without them):

| Variable                      | What to put                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------- |
| `POSTGRES_USER`, `POSTGRES_DB` | Keep `ccure_user` and `ccure_db`                                                             |
| `POSTGRES_PASSWORD`           | A new password for the application role                                                       |
| `POSTGRES_SUPERUSER_PASSWORD` | A different password for the database superuser                                               |
| `MFA_ENCRYPTION_KEY`          | A generated secret. **Never change it later**: stored MFA secrets would become unreadable     |
| `COMPLIANCE_ENCRYPTION_KEY`   | A generated secret. Encrypts stored scan credentials; changing it means re-entering them      |
| `CCURE_TOKEN_KEYS_HOST_DIR`   | The absolute path of the key directory you create in [2.4](#24-prepare-the-host)              |

Also set `VULN_DB_PASSWORD`, and the `SMTP_*` values if the application should
send mail. Generate each secret with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

The example already sets `COMPOSE_PROFILES=container-scanner` (starts the
scanner workers), `PGSSLMODE=disable` (the database is reachable only from
loopback and the Compose network) and `CELERY_TASK_ALWAYS_EAGER=False` (tasks
run on the workers). Every variable is explained in the file.

**`Backend/.env` — values to set:**

| Variable                                        | What to put                                                                                                    |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD` | The first administrator. Used only on the first start, while the database has no users                         |
| `POSTGRES_PASSWORD`, `VULN_DB_PASSWORD`         | The same values as the root `.env`; used by scripts run on the host                                            |
| `VULN_DB_PORT`, and the port in `DATABASE_URL`  | The root `.env`'s `POSTGRES_PORT_BINDING` (host scripts reach PostgreSQL through the published loopback port) |
| `NVD_API_KEY`, `VULNCHECK_API_TOKEN`            | Optional feed credentials (commented out in the example)                                                       |

### 2.4 Prepare the host

These steps happen once per host. Build the images first; the key tool runs
inside the backend image.

```bash
docker compose build
```

**Create the token signing key.** The API signs and verifies access tokens
with an ES256 key from this directory and refuses to start without an active
one. The directory stays outside the repository; the private key is owned by
the container user (uid 1000) with mode 600, so it is readable by the API but
not by your host account.

```bash
mkdir -p ~/ccure-keys && chmod 711 ~/ccure-keys
docker run --rm -u 0 -v ~/ccure-keys:/keys -v "$PWD/Backend":/app:ro -w /app \
  ccure-audit-pro-backend:latest \
  python -m scripts.security.manage_token_keys --keys-dir /keys generate --state active --owner 1000:1000
docker run --rm -u 0 -v ~/ccure-keys:/keys -v "$PWD/Backend":/app:ro -w /app \
  ccure-audit-pro-backend:latest \
  python -m scripts.security.manage_token_keys --keys-dir /keys list      # prints "keyset valid"
```

Set `CCURE_TOKEN_KEYS_HOST_DIR` in the root `.env` to that directory's absolute
path, for example `/home/<you>/ccure-keys`. Keep an offline copy of the private
key file; rotation is described in the script's docstring and
[docs/architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md](docs/architecture/PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md).

**Create the gateway's socket directory.** `api-gateway` mounts
`/var/lib/ccure-edge` and refuses to start if it does not exist (Docker is told
not to create it, because a directory it made would have the wrong owner):

```bash
sudo install -d -m 0770 -o root -g www-data /var/lib/ccure-edge
```

This is the first step of `scripts/linux/gateway_edge_switch.sh harden`, which
also expects the `www-data` group to be gid 33, as on Ubuntu.

**Create Portainer's volume.** It is declared `external` in
`docker-compose.yml`, so Compose will not create it:

```bash
docker volume create portainer_data
```

**Create the CA file the services mount.** The compose file mounts
`certs/ccure-internal-ca.crt` into the API and workers for TLS to PostgreSQL.
With `PGSSLMODE=disable` it is not read, but it must exist as a file: otherwise
Docker creates a directory in its place.

```bash
mkdir -p certs && touch certs/ccure-internal-ca.crt
```

To turn TLS to PostgreSQL on, put your internal CA certificate there and set
`PGSSLMODE=verify-full`. The PowerShell scripts in `scripts/tls/`
(`new_internal_ca.ps1`, `new_postgres_cert.ps1`) issue the certificates, and
[docs/TLS_SETUP.md](docs/TLS_SETUP.md) describes the setup.

### 2.5 Start the stack

```bash
docker compose up -d
docker compose ps
docker compose logs -f api        # watch the first start
```

`db`, `redis` and `gateway-auth` report `healthy`; the other services report
`Up`. With `COMPOSE_PROFILES=container-scanner` in `.env`, `worker` and
`web-worker` start too.

### 2.6 What the first start does

Nothing has to be run by hand for the schema or the catalogues:

1. **PostgreSQL initialises its volume** (first start only) and runs
   `scripts/docker-postgres-init.sql`. That creates the application role
   (`ccure_user`, not a superuser), the `admin` role and the `vuln_intel`
   database, and the `pg_trgm`, `pgcrypto` and `uuid-ossp` extensions.
2. **The API runs `Backend/start.sh`**, which runs
   `python db/migrate_production_schema.py` before starting uvicorn. On an empty
   database it builds the schema from the models and stamps Audit's Alembic
   head; it then runs `alembic upgrade heads` (the history has three heads:
   Audit, Policy Pro and Rank). It does this on **every** start, so a merged
   migration is applied at the next API restart.
3. **The API's startup** creates the default organisation, applies the RBAC
   permission catalogue and system roles, creates the first administrator from
   `DEFAULT_ADMIN_EMAIL`/`DEFAULT_ADMIN_PASSWORD` (only while the database has
   no users) and seeds the compliance catalogues.

If the administrator variables were empty, the API logs
`Database has no users and DEFAULT_ADMIN_EMAIL/PASSWORD are not set. No admin seeded.`
Set them in `Backend/.env` and run `docker compose restart api`.

### 2.7 Install the audit-log chain (once, as the database superuser)

Audit events are hash-chained so tampering is detectable, but the privileged
half of the chain (its own roles and `SECURITY DEFINER` functions) cannot be
created by the application role. Until a database administrator installs it,
the API logs a WARNING at start and audit events carry no hash. After the first
start:

```bash
for f in bootstrap_chain.sql bootstrap_chain_retention.sql bootstrap_chain_retention_chained.sql; do
  docker exec -i ccure-db psql -X -v ON_ERROR_STOP=1 -U postgres -d ccure_db < Backend/scripts/audit/$f
done
docker exec ccure-api python scripts/audit/verify_chain_bootstrap.py    # reports every check passed
docker compose restart api
```

`-U` is your `POSTGRES_SUPERUSER` and `-d` your `POSTGRES_DB`. Audit-log
retention is installed but disabled; CLAUDE.md, "Audit-log retention", explains
why.

### 2.8 Access the application and verify it works

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3200/    # 200: the frontend
curl -s http://127.0.0.1:3200/api/                                 # the API's status JSON, through the gateway
```

Then open **http://127.0.0.1:3200** in a browser on the same host and sign in
with `DEFAULT_ADMIN_EMAIL` and `DEFAULT_ADMIN_PASSWORD`. You land on CCure
Home; open **CCure Audit** for the dashboard, and **Administration** to add
organisations, users and roles.

Every port is bound to loopback. From another machine, either forward the
port over SSH (`ssh -L 3200:127.0.0.1:3200 <user>@<host>`, then
`http://localhost:3200`) or serve it over HTTPS through host nginx, as the
production VM does: [docs/TLS_SETUP.md](docs/TLS_SETUP.md),
`gateway/edge/host-nginx/` and `scripts/linux/gateway_edge_switch.sh`. Add that
address to `CORS_ALLOW_ORIGINS`, set `FRONTEND_URL` to it and
`REFRESH_COOKIE_SECURE=True`, then recreate the API
(`docker compose up -d --no-deps --force-recreate api`).

The image runs with `ENV=production`, so the interactive API documentation is
not served; the API contract is committed as `Backend/openapi.json`.

### 2.9 Load vulnerability intelligence

Vulnerability matching reads the `vuln_intel` database, which starts empty.
The feed scripts run on the host, from `Backend/` in the backend virtual
environment ([3.6](#36-local-checks-tests-and-git-hooks) creates it), and read
`Backend/.env` for the `vuln_intel` connection and any API tokens.

From `Backend/`, the NVD download runs in batches:

```bash
# Download next 1000 (offset 3300)
python scripts/vuln/download_nvd.py --limit 1000 --offset 3300

# Then next batch (offset shown in output)
python scripts/vuln/download_nvd.py --limit 1000 --offset 4300

# Then next batch (offset shown in output)
python scripts/vuln/download_nvd.py --limit 1000 --offset 12500
# And so on...

python scripts/verification/check_cve_source.py    # Confirm which CVE source is in use
```

The other feeds (OSV, MSRC, CSAF, exploit intelligence, VulnCheck) are the
`scripts/vuln/sync_*.py` scripts; CLAUDE.md, "Vulnerability feeds", says what
each needs. A user crontab runs them nightly, one after another from 03:00, and
each run logs to `Backend/logs/<sync>_scheduled.log`:

```bash
scripts/install_feed_schedule.sh --dry-run     # show the entries
scripts/install_feed_schedule.sh               # install or replace them
scripts/run_feed_sync.sh sync_msrc 60          # run one now, exactly as scheduled
```

VulnCheck is scheduled only once `VULNCHECK_API_TOKEN` is set in
`Backend/.env`; re-run the installer after adding it.

### 2.10 Optional services

- **Malware scanning of evidence uploads:**
  `docker compose --profile av up -d clamav`, then set `CLAMAV_HOST=clamav` in
  `Backend/.env` and restart the API. Until then each upload reports
  `malware_scan: not_configured`. Leave `UPLOAD_AV_REQUIRED` at its default
  until clamd is confirmed healthy.
- **Portainer** at `https://127.0.0.1:9443`. A new instance must be given an
  admin user within 5 minutes of starting, using the setup token from
  `docker logs portainer`; otherwise it locks until `docker restart portainer`.
- **Database backups:** see [3.4](#34-backups-and-restore).

### 2.11 Credentials and external services

No real credential is in the repository; both example files hold placeholders.

| What                                                    | Where                                    | Needed for                                                          |
| ------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------- |
| Database passwords                                      | root `.env` (and `Backend/.env` for host scripts) | The database and every service                              |
| `MFA_ENCRYPTION_KEY`, `COMPLIANCE_ENCRYPTION_KEY`       | root `.env`                              | Stored MFA secrets and stored scan credentials                       |
| Token signing key                                       | `CCURE_TOKEN_KEYS_HOST_DIR`              | Every sign-in                                                        |
| First administrator                                     | `Backend/.env`                           | The first sign-in                                                    |
| SMTP account                                            | root `.env` `SMTP_*`                     | Verification and password-reset mail                                 |
| NVD API key (optional)                                  | `Backend/.env` `NVD_API_KEY`             | Faster NVD downloads; NVD works without one, heavily rate limited    |
| VulnCheck token (optional, free tier)                   | `Backend/.env` `VULNCHECK_API_TOKEN`     | The VulnCheck KEV feed                                               |
| Scan credentials (SSH, WinRM/SMB, database, SNMP)       | Entered in the application               | Credentialed scans; stored encrypted                                 |
| CDAC GitLab account                                     | [git.cdacb.in](https://git.cdacb.in)     | Contributing ([section 4](#4-git-collaboration-workflow-cdac-gitlab)) |

### 2.12 Troubleshooting

| Symptom                                                                                              | Cause and fix                                                                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `required variable … is missing a value` from any `docker compose` command                          | A required variable is empty in the root `.env`. Set the values in [2.3](#23-configure-the-environment).                                                                                                                                  |
| Compose reports that the external volume `portainer_data` is not found                              | Run `docker volume create portainer_data`.                                                                                                                                                                                                |
| `api-gateway` will not start; the bind source `/var/lib/ccure-edge` does not exist                  | Create it with the `install` command in [2.4](#24-prepare-the-host).                                                                                                                                                                      |
| The API logs `Database connection failed` or a TLS error connecting to PostgreSQL                  | `PGSSLMODE` is unset, so the compose default `verify-full` applies to a database without TLS. Set `PGSSLMODE=disable` in the root `.env`, then `docker compose up -d`.                                                                  |
| The API exits saying the token keyset has no active key                                             | Generate the key ([2.4](#24-prepare-the-host)). Check `CCURE_TOKEN_KEYS_HOST_DIR` is an absolute path, the directory is mode 711 and the key file is owned by uid 1000 with mode 600.                                                    |
| No administrator after the first start                                                              | See [2.6](#26-what-the-first-start-does). Once any user exists, the variables are ignored; promote an existing verified account with `python -m scripts.rbac.bootstrap_admin` (read its docstring first: it refuses a live database without an approval reference). |
| Signed out after about 30 minutes when using the app over plain HTTP from another machine          | The refresh cookie is `Secure` and the browser will not store it over plain HTTP. Use HTTPS, or an SSH port forward to `localhost`.                                                                                                       |
| Scans stay queued or never start                                                                    | The workers are not running. Check `COMPOSE_PROFILES=container-scanner` in `.env`, `docker compose ps worker` and `docker compose logs worker`. A scan no worker collects is failed by the reaper after 15 minutes.                      |
| Host discovery finds nothing                                                                        | The scanner worker needs a Linux Docker host: ARP does not cross a bridge network, which is why `worker` uses host networking and the `NET_ADMIN`/`NET_RAW` capabilities.                                                               |
| `port is already allocated` for 5432                                                                | Another PostgreSQL owns the port. Set `POSTGRES_PORT_BINDING=5433` in the root `.env`, and the same port in `Backend/.env` for host scripts.                                                                                              |
| The page loads but every API call fails, with Content-Security-Policy errors in the browser console | The frontend was built with a `VITE_API_BASE_URL` other than `/api`. Set `/api`, then `docker compose build frontend && docker compose up -d --no-deps frontend`.                                                                       |
| The API logs a WARNING that the audit chain is not installed                                        | Run [2.7](#27-install-the-audit-log-chain-once-as-the-database-superuser).                                                                                                                                                                |
| Credentialed scans fail with `Invalid encrypted payload or authentication tag`                      | `COMPLIANCE_ENCRYPTION_KEY` changed after credentials were stored. Restore the old value, or re-enter the credentials.                                                                                                                  |
| `git clone` or `git fetch` from git.cdacb.in fails with `unable to get local issuer certificate`    | See [4.1](#41-access-to-cdac-gitlab).                                                                                                                                                                                                     |

[docs/DEVELOPER_SETUP_GUIDE.md](docs/DEVELOPER_SETUP_GUIDE.md) covers more
detail, including running without containers. Parts of it predate the API
gateway: the API no longer publishes port 8000, so use the frontend address
above to reach it.

---

## 3. Day-to-day operation

### 3.1 Running the stack

```bash
docker compose up -d       # the whole stack; COMPOSE_PROFILES=container-scanner in .env adds worker and web-worker
docker compose down
docker compose logs -f api
```

From a clone, `Backend/` is bind-mounted into the containers:

- **Python changes** take effect on restart: `docker compose restart api`.
  Restart the scanner worker after changing anything under `core/`, `scans/`
  or `orchestrator/`: `docker compose restart worker`.
- **Frontend changes** are baked into the image at build time:
  `docker compose build frontend && docker compose up -d --no-deps frontend`.
- **`requirements.txt` changes** need new images:
  `docker compose build api worker web-worker beat`.
- **Scanner worker concurrency** is `SCANNER_WORKER_CONCURRENCY` (default 20),
  and the global Nmap process cap is `MAX_NMAP_PROCESSES` (default 20), both
  read from `.env` by `docker-compose.yml`. Recreate the worker after changing
  them.

Frontend development follows the permanent [UX4G standard](docs/ux4g/UX4G_STANDARD.md).
All modules share the exact approved release, central asset pipeline and CCure
adapters. See [Frontend/README.md](Frontend/README.md) for required CI checks
and [the final migration report](docs/ux4g/B7_B10_FINAL_CLOSURE.md) for validation.

**The production VM is different.** It runs on the Linux VM `ccurepro`
(`https://ccurepro.cdac.in`), everything in Docker, and since 13 Oct 2026 from
**released images**, not from the working tree: editing files there changes
nothing live. Releases are built, deployed and rolled back as described in
CLAUDE.md, "Deployment: Linux VM" → "Releases". The Windows-host deployment it
ran on until 17 Sep 2026 was retired on 9 Oct 2026, and its PowerShell start,
host-worker, backup and nginx scripts were removed with it; git history keeps
them. `scripts/tls/*.ps1` remain, for Windows client machines that must trust
the private CA.

### 3.2 Registration policy

The Docker deployment's registration default is `ALLOW_SELF_REGISTRATION` in
the repository-root `.env`: `true` enables signup and `false` disables it
(the default). Compose passes it to the API explicitly. After changing the
deployment default, recreate the API with
`docker compose up -d --no-deps --force-recreate api`, preserving any `-f`
overrides and environment variables used by that deployment. A restart alone
does not update the container environment.

For immediate changes, a Superadmin can open **Administration → User Management**,
select **Registration settings** in the page toolbar, change **Allow self-registration**,
and select **Save changes** in the dialog. The old `/admin/registration-settings`
address redirects to this dialog; there is no separate registration navigation item.
The saved platform-wide policy overrides `.env`, persists in PostgreSQL across
restarts, and controls both the login link and every self-service signup route.
**Use deployment default** clears the override. Existing accounts keep their
sign-in access, and changing this policy does not bypass email verification
or change the separate administrator-approval setting.

The dialog and API require the platform-scope `platform.registration.read` and
`platform.registration.manage` permissions. Only the system Superadmin role
receives these grants by default; organisation roles cannot hold them. Changes
use existing authenticator reauthentication and the platform audit ledger.
Conflicting saves return 409 and require reloading the current policy.

### 3.3 Database migrations

Every API start runs `alembic upgrade heads`, so a merged migration is applied
at the next `docker compose restart api`. To run it by hand, back up first:

```bash
scripts/backup_db.sh --skip-reference-data
docker exec -w /app ccure-api alembic upgrade heads
```

### 3.4 Backups and restore

A user crontab dumps the database every six hours and in full nightly
(`scripts/install_backup_schedule.sh`). Restoring, and why an operational dump
cannot be restored on its own, is in CLAUDE.md, "Backups on the VM". Restore into
a fresh database and rename it; never restore over `ccure_db` while it is
serving.

### 3.5 Preparing a Windows scan target for credentialed scanning over SSH

Windows targets no longer need OpenSSH: the scanner reaches them natively over
WinRM or SMB (CLAUDE.md, "Windows credentialed collection"). Use the steps below
only where SSH is the transport you want.

```powershell
# Enable OpenSSH Server (manually, on the target machine)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Set PowerShell as default shell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

# Open Firewall Port 22
New-NetFirewallRule -Name "OpenSSH-In" -DisplayName "Allow OpenSSH Port 22" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -ErrorAction SilentlyContinue

Restart-Service sshd

# Run inside PowerShell (on the target machine)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force
```

To make the change from the scanning side instead (SSH must already be enabled
on the target), connect with `ssh username@IP`, then either:

1. Switch shell: type `powershell` in the SSH session, then run:

   ```powershell
   New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
   Restart-Service sshd
   ```

2. Or run them from the current cmd prompt, wrapped in `powershell -Command`:

   ```
   powershell -Command "New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force"
   powershell -Command "Restart-Service sshd"
   ```

**Important:** because these commands modify registry keys under HKLM and
restart a system service, the account must have Administrator privileges and
UAC must allow remote elevation. If you receive an "Access Denied" error, apply
the `LocalAccountTokenFilterPolicy` registry fix first.

### 3.6 Local checks, tests and git hooks

The backend virtual environment is for local tooling and the git hooks.
Python 3.11 matches the backend image.

```bash
cd Backend
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install pre-commit
```

The backend tests are **destructive**: they truncate the organisations and
users of whatever database they run against. Point them at a disposable
database whose name matches `^pytest_`, `_pytest` or `_pytest_db`; CLAUDE.md,
"Running the test suite", explains the guards and the 10 Aug 2026 incident
behind them. Run the smallest test set for a change first; CLAUDE.md, "Test
targeted-first", and `scripts/ci/select_tests.py` say which.

```bash
cd Backend
TEST_DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/ccure_pytest_db MOCK_SCANNERS=true \
  .venv/bin/python -m pytest tests/security/test_rbac_routes.py tests/compliance/test_remediation_safety.py tests/reports/test_report_limits.py -v
```

Register the git hooks once, from the repository root, so formatting, linting,
security checks and the OpenAPI contract run before every commit:

```bash
Backend/.venv/bin/python -m pre_commit install
Backend/.venv/bin/python -m pre_commit run --all-files    # optional: check everything now
```

---

## 4. Git collaboration workflow (CDAC GitLab)

**CDAC GitLab is the primary repository:**
`https://git.cdacb.in/pnjkumar/CCure-PRO` (private). The GitHub repository
`https://github.com/pankajkumar2498/CCure-PRO` is a **backup**, updated by a
maintainer. Clone from, push to and open merge requests on GitLab.

The rules GitLab enforces:

| Branch         | Who can push         | Who can merge                      | Force-push |
| -------------- | -------------------- | ---------------------------------- | ---------- |
| `master`       | **No one** directly  | Maintainers, through merge requests | Not allowed |
| `Improvements` | Developers, Maintainers | Developers, Maintainers          | Not allowed |
| your branches  | You                  | —                                  | Avoid      |

Every discussion thread on a merge request must be resolved before it can be
merged. CI/CD is not configured on GitLab yet, so no pipeline runs and none is
required to merge.

### 4.1 Access to CDAC GitLab

Ask a project Maintainer to add you to the project (role **Developer** to push
branches and open merge requests, **Maintainer** to merge into `master`).
Authenticate with your own account: over HTTPS with a
[personal access token](https://git.cdacb.in/-/user_settings/personal_access_tokens)
(scopes `read_repository` and `write_repository`) as the password, or over SSH
(`git@git.cdacb.in:pnjkumar/CCure-PRO.git`) with a key added to your profile.

**Certificate error on Linux and macOS.** The GitLab server sends its
certificate without the intermediate certificate that links it to a trusted
root, so tools built on OpenSSL fail with `unable to get local issuer
certificate` (browsers, and Git for Windows, usually fetch the intermediate
themselves). Until the server is fixed, give git that intermediate for this
one host, without turning verification off. On Debian or Ubuntu:

```bash
mkdir -p ~/.config/ccure
curl -fsSL http://cacerts.rapidssl.com/RapidSSLTLSRSACAG1.crt \
  | openssl x509 -inform DER -out ~/.config/ccure/rapidssl-intermediate.pem
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt ~/.config/ccure/rapidssl-intermediate.pem   # must print OK
cat ~/.config/ccure/rapidssl-intermediate.pem /etc/ssl/certs/DigiCert_Global_Root_G2.pem \
  > ~/.config/ccure/git.cdacb.in-ca.pem
git config --global http."https://git.cdacb.in/".sslCAInfo "$HOME/.config/ccure/git.cdacb.in-ca.pem"
```

The `openssl verify` step proves the downloaded certificate is genuine (it is
signed by DigiCert Global Root G2, which your system already trusts). Never
set `http.sslVerify false`.

**Switching an existing GitHub clone to GitLab** (keeps your branches and
local work; GitHub stays available as `github`):

```bash
git remote rename origin github
git remote add origin https://git.cdacb.in/pnjkumar/CCure-PRO.git
git fetch origin
git branch -u origin/master master
git config remote.pushDefault origin
git remote -v                      # origin → git.cdacb.in, github → github.com
```

### 4.2 Contributing a change

**1. Check your state and synchronise with `master`.**

```bash
git status                         # commit or stash anything in progress first
git switch master
git pull --ff-only origin master   # bring master up to date; refuses if it would need a merge
```

**2. Create a feature branch** from the up-to-date `master`. Name it for the
change, for example `fix/scan-timeout` or `docs/setup-guide`.

```bash
git switch -c fix/scan-timeout
```

**3. Make and commit your changes.** Stage only what belongs in the change and
check it before committing. The pre-commit hooks ([3.6](#36-local-checks-tests-and-git-hooks))
run on every commit; if they reformat a file, stage it again and re-run the
commit. Never bypass them with `--no-verify`.

```bash
git status
git add path/to/changed/file
git diff --staged                  # review exactly what will be committed
git commit -m "fix(scans): settle a scan whose worker stopped"
```

The repository's commit messages follow `type(scope): summary`
(`fix`, `feat`, `docs`, `test`, `chore`, `ci`).

**4. Push the branch to GitLab.** `-u` makes it track the GitLab branch, so
later pushes are just `git push`.

```bash
git push -u origin fix/scan-timeout
```

**5. Open a merge request targeting `master`.** GitLab prints a
"create a merge request" link after the push. Or open the project, select
**Code → Merge requests → New merge request**, choose your branch as the source
and `master` as the target. Describe what changed and why, and assign a
reviewer.

**6. Review and resolve every discussion thread.** Reviewers comment on the
merge request. Address each comment by pushing more commits to the same branch
(`git commit`, then `git push`); the merge request updates itself. Resolve each
thread once it is dealt with: the merge stays blocked until all are resolved.
If `master` moved on in the meantime, bring it into your branch with a merge
rather than rewriting history:

```bash
git fetch origin
git merge origin/master
git push
```

**7. A Maintainer merges the request.** Only Maintainers can merge into
`master`. GitLab creates a merge commit and deletes the source branch by
default.

**8. Pull the updated `master` and tidy up.**

```bash
git switch master
git pull --ff-only origin master
git branch -d fix/scan-timeout     # delete the merged local branch
git fetch --prune origin           # forget remote branches deleted on GitLab
```

### 4.3 Keeping the GitHub backup current (Maintainers)

GitHub is not updated automatically. After merges, a Maintainer pushes the
protected branches to it:

```bash
git push github master Improvements
```

GitHub Actions are configured there but cannot currently run (the account's
Actions minutes are exhausted), so a red run on GitHub is not a code failure.

### 4.4 What never goes into a commit

Real `.env` files, credentials, private keys and certificates, database dumps
(`backups/`), local databases, generated reports and logs. The `.gitignore`
covers these and the gitleaks hook scans every commit; check `git diff --staged`
before each commit anyway. Never use `git push --force` on a shared branch,
`git push --mirror`, `git clean` or `git reset --hard` on work that is not
backed up.

---

## 5. Further documentation

| Document                                                                     | What it covers                                                                       |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| [CLAUDE.md](CLAUDE.md)                                                       | Repository-wide rules and the engineering record behind them                         |
| [docs/architecture/README.md](docs/architecture/README.md)                   | Module responsibilities, contracts, boundaries and runbooks                          |
| [docs/DEVELOPER_SETUP_GUIDE.md](docs/DEVELOPER_SETUP_GUIDE.md)               | More setup detail, including running without containers (parts predate the gateway) |
| [docs/TLS_SETUP.md](docs/TLS_SETUP.md)                                       | The private CA and HTTPS                                                             |
| [Frontend/README.md](Frontend/README.md)                                     | The frontend, its checks and development server                                      |
| [docs/ux4g/UX4G_STANDARD.md](docs/ux4g/UX4G_STANDARD.md)                     | The UX4G design standard every frontend change follows                               |
| [Backend/tests/README.md](Backend/tests/README.md)                           | Test layout and what belongs where                                                   |
| [docs/ci/CI_SCOPE.md](docs/ci/CI_SCOPE.md)                                   | The GitHub Actions pipelines (not configured on GitLab)                              |
