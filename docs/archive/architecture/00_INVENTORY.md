# Architecture Inventory

> Part of the CCure Audit PRO architecture documentation package. See
> [README.md](../../architecture/README.md) for the full package index and methodology.
>
> Every row below was verified against source on 2026-08-27: `docker-compose.yml`,
> `Backend/main.py`, `Backend/config.py`, `Backend/core/celery_app.py`, the 20
> router modules under `Backend/routers/` plus `Backend/auth/router.py`, the
> `Backend/db/models/` package, `Backend/alembic/versions/` (41 migrations),
> `scripts/host-nginx/nginx-host.conf`, `scripts/start_host_scan_stack.ps1`,
> `Backend/scripts/audit/bootstrap_chain*.sql`, and the Dockerfiles. Where a claim
> comes from `CLAUDE.md` or `docs/*.md` rather than direct inspection, it is
> marked **[doc-only]**. Anything neither confirmed in source nor documented is
> marked **Not Verified**.

---

## 1. Runtime topology, as it actually starts

This is the single most consequential fact for every diagram in this package, and
it does not match a bare `docker compose up`. The supported startup path is
`scripts/start_host_scan_stack.ps1`, which runs:

```
docker compose up -d redis api frontend web-worker beat
& Backend/scripts/scan/start_host_scanner_worker.ps1
```

Two containers defined in `docker-compose.yml` are **deliberately excluded by
name**, not by profile alone — the script's own comments explain why:

- **`worker`** (the containerized network-scanner) is never started. It would
  consume the same `scanner`/`default` queues as the host worker, and a task
  landing in the container instead of the host silently loses raw-socket access
  — "empty or wrong results intermittently, with nothing in the logs to explain
  it." (`scripts/start_host_scan_stack.ps1:83-89`)
- **`gateway`** is never started. Host Nginx already publishes the app on 443;
  the container gateway would only add a colliding port binding.
  (`:91-94`)

One container starts as a side effect and is otherwise inert: **`db`** (the
Postgres container) comes up because `api` and `worker` declare `depends_on: db`
in `docker-compose.yml`, but neither the API nor the host worker ever connects to
it — both use `DATABASE_HOST`/host PostgreSQL. The script's own comment confirms
this is known and accepted, not an oversight (`:95-97`).

**`web-worker` (DAST) runs in the container**, not on the host — it needs
Playwright/nuclei/ffuf/sqlmap, none of which need raw sockets. This means the
**network scan pipeline and the web/DAST pipeline execute in physically
different processes on different sides of the Docker boundary**, a distinction
no earlier document in this repo states explicitly.

The host worker (`Backend/scripts/scan/start_host_scanner_worker.ps1`) binds
`--queues=scanner,default,compliance` **[doc-only, per CLAUDE.md's Policy
Compliance Engine section — not re-verified against the script's argument list
in this pass; treat as high-confidence, not independently re-confirmed]**.

---

## 2. Containers & host processes

| Component                         | Type                           | Container/Host                                                 | Port (published)                           | Protocol              | Depends on                                               | Database touched                                                   | Status                                                                                                                                                                        |
| --------------------------------- | ------------------------------ | -------------------------------------------------------------- | ------------------------------------------ | --------------------- | -------------------------------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ccure-redis`                     | Container                      | `redis:7-alpine`                                               | `127.0.0.1:6379`                           | TCP (Redis)           | —                                                        | — (broker/backend/pub-sub only)                                    | **Enabled** — always started                                                                                                                                                  |
| `ccure-db`                        | Container                      | `postgres:15-alpine`                                           | `127.0.0.1:${POSTGRES_PORT_BINDING:-5433}` | TCP (Postgres)        | —                                                        | Its own empty schema, seeded by `scripts/docker-postgres-init.sql` | **Started but unused** — nothing connects to it in this deployment                                                                                                            |
| `ccure-api`                       | Container                      | FastAPI+uvicorn (`Backend/Dockerfile`)                         | `127.0.0.1:8000`                           | HTTP                  | redis (healthy), db (healthy, unused)                    | Host PostgreSQL: app DB + reads `vuln_intel`                       | **Enabled** — core service                                                                                                                                                    |
| `ccure-beat`                      | Container                      | Celery beat (same image as api)                                | — (no published port)                      | —                     | redis, db                                                | none directly (publishes task messages)                            | **Enabled** — started explicitly; not profile-gated                                                                                                                           |
| `ccure-web-worker`                | Container                      | Celery worker, queues `web_recon,web_crawl,web_dast,web_audit` | —                                          | —                     | redis, db                                                | Host PostgreSQL (app DB)                                           | **Enabled** — started explicitly despite carrying `profiles: ["container-scanner"]` in the compose file (the start script names it directly, which bypasses the profile gate) |
| `ccure-worker`                    | Container                      | Celery worker, queues `scanner,default,compliance`             | —                                          | —                     | redis, db                                                | Host PostgreSQL                                                    | **Present in compose, never started** — superseded by the host worker                                                                                                         |
| `ccure-frontend`                  | Container                      | nginx:stable-alpine serving Vite build                         | `127.0.0.1:3200:80`                        | HTTP                  | api (soft)                                               | —                                                                  | **Enabled** — core service                                                                                                                                                    |
| `ccure-gateway`                   | Container                      | nginx:stable-alpine (opt-in reverse proxy)                     | `127.0.0.1:${GATEWAY_PORT:-8082}:80`       | HTTP (no TLS)         | api, frontend                                            | —                                                                  | **Defined, not used** — behind `alt-gateway` profile, superseded by host Nginx                                                                                                |
| `ccure-clamav`                    | Container                      | clamav/clamav:stable                                           | — (internal only)                          | TCP (clamd INSTREAM)  | —                                                        | —                                                                  | **Optional, off by default** — behind `av` profile; `UPLOAD_AV_REQUIRED=False` until confirmed healthy                                                                        |
| Host scanner worker               | Host process (Windows)         | `Backend/scripts/scan/start_host_scanner_worker.ps1`           | —                                          | Celery over Redis     | redis, host PostgreSQL                                   | Host PostgreSQL (app DB), reads `vuln_intel`                       | **Enabled** — started separately from the compose stack; required for network/credentialed/compliance task execution                                                          |
| Host PostgreSQL 18                | Host service (Windows service) | `D:\PostgreSQL\18\data`                                        | (bound per `pg_hba.conf`, `hostssl` only)  | TCP+TLS (verify-full) | —                                                        | Hosts both `ccure_test` (app DB) and `vuln_intel`                  | **Enabled** — the real database for every environment                                                                                                                         |
| Host Nginx (`CCureNginx` service) | Host service (Windows service) | `scripts/host-nginx/nginx-host.conf`                           | `0.0.0.0:443` (TLS), `:80` (redirect only) | HTTPS/HTTP            | api container, frontend container (both via `127.0.0.1`) | —                                                                  | **Enabled** — the sole listener on a routable interface                                                                                                                       |
| `CCure DB Backup` scheduled task  | Host scheduled task            | `scripts/backup_db.ps1`                                        | —                                          | —                     | Host PostgreSQL                                          | Reads app DB (pg_dump)                                             | **Enabled** — every 6h, 30-day retention                                                                                                                                      |

---

## 3. Backend routers (HTTP surface)

All 21 router objects registered in `Backend/main.py` (20 files under
`Backend/routers/` plus `Backend/auth/router.py`). "Ops" excludes WebSocket
endpoints, counted separately.

| Router file                      | Prefix                 | Ops      | Primary auth mechanism                                                                                              | Rate-limited endpoints                                                                          | Module                   |
| -------------------------------- | ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------ |
| `auth/router.py`                 | `/auth`                | 15       | mixed (public + `get_current_user`)                                                                                 | login 10/min, register 5/min, forgot-password 3/min, MFA/OTP 5/min, check-username/email 20/min | Authentication           |
| `routers/scan_history.py`        | `/scans`               | 8 + 1 WS | `require_permission("scans", …)`; WS via hand-rolled ticket auth                                                    | none                                                                                            | Scan History             |
| `routers/health.py`              | _(none)_               | 4        | 2 public, 1 permission-gated                                                                                        | none                                                                                            | Health / Docs            |
| `routers/traditional_scans.py`   | _(none)_               | 4        | `require_permission("scans","execute")`                                                                             | all 4 @ 5/min                                                                                   | Legacy Scans             |
| `routers/phase_scans.py`         | _(none)_               | 5        | `require_permission("scans","execute"/"read")`                                                                      | 4 of 5 @ 5/min                                                                                  | Phase-Selective Scans    |
| `routers/credentialed.py`        | _(none)_               | 1        | `require_permission("scans","execute")`                                                                             | 5/min                                                                                           | Credentialed Scan        |
| `routers/reports.py`             | _(none)_               | 2        | `get_current_user_flexible` (ticket-or-bearer)                                                                      | download @ 20/min                                                                               | Reports                  |
| `routers/admin_users.py`         | `/admin/users`         | 13       | `require_permission("users", …)`                                                                                    | none                                                                                            | User Management          |
| `routers/admin_email_domains.py` | `/admin/email-domains` | 6        | `require_role("superadmin")` (router-level + per-route)                                                             | none                                                                                            | Email Domain Guard admin |
| `routers/admin_rbac.py`          | `/admin/roles`         | 2        | `require_permission("roles","read")`                                                                                | none                                                                                            | RBAC Admin               |
| `routers/admin_orgs.py`          | `/admin/organizations` | 8        | mixed: `require_permission` (5 routes) + manual inline superadmin check (3 routes: delete/restore/scan-scope-write) | none                                                                                            | Org Management           |
| `routers/admin_nvd.py`           | `/api/v1/admin`        | 2        | custom `_verify_admin` (superadmin or org_admin)                                                                    | none                                                                                            | Vuln Feed Admin          |
| `routers/audit.py`               | `/admin/audit-logs`    | 4        | 3 × `require_permission("audit", …)`, 1 × `require_role("superadmin")` for retention preview                        | export 5/min, retention-preview 5/min                                                           | Audit Logs               |
| `routers/user_profile.py`        | `/user`                | 8        | `get_current_user` (no permission gate)                                                                             | none                                                                                            | Self-service Profile     |
| `routers/notifications.py`       | `/notifications`       | 7        | `get_current_user` (no permission gate)                                                                             | none                                                                                            | Notifications            |
| `routers/dashboard.py`           | `/dashboard`           | 15       | `require_permission("dashboard","read")`                                                                            | none                                                                                            | Dashboard                |
| `routers/assets.py`              | `/assets`              | 16       | `require_permission("assets"/"findings"/"settings", …)`                                                             | AMT import 3/min                                                                                | Asset Registry           |
| `routers/findings.py`            | `/findings`            | 5        | `require_permission("findings", …)`                                                                                 | none                                                                                            | Findings                 |
| `routers/web_scans.py`           | `/web-scans`           | 8 + 1 WS | `get_current_user` (no permission gate); WS via hand-rolled ticket auth                                             | start 5/min, report 10/min                                                                      | Web/DAST Scans           |
| `routers/topology.py`            | _(none)_               | 2        | `require_permission("scans","read")`                                                                                | none                                                                                            | Network Topology         |
| `routers/compliance.py`          | `/compliance`          | 47       | `require_permission("compliance", …)` exclusively                                                                   | 17 of 47 rate-limited                                                                           | Compliance Engine        |

**Total: 21 routers, 175 HTTP operations + 2 WebSocket endpoints** — this
supersedes `docs/SYSTEM_ARCHITECTURE.md`'s figure of "155 HTTP operations", which
predates `admin_email_domains.py` and undercounts `compliance.py` (see §7,
finding G-1).

---

## 4. Backend modules (non-HTTP)

| Module                               | Path                                                                              | Purpose                                                                                                  | Type                   |
| ------------------------------------ | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------- |
| Discovery (Phase 1)                  | `Backend/core/discovery/`, `engines/discovery/`                                   | Scapy-based ARP/ICMP/TCP/UDP host discovery, 8 probe techniques                                          | Engine                 |
| Port scan (Phase 2)                  | `Backend/engines/port/port_engine.py`, `core/nmap/wrapper.py`                     | Nmap wrapper with async-TCP-connect fallback                                                             | Engine                 |
| Vulnerability audit (Phase 3)        | `Backend/engines/vulnerability/`                                                  | `vulnerability_engine.py` + `plugin_selector.py` + 15 plugins                                            | Engine                 |
| Topology mapping (Phase 4, optional) | `Backend/core/topology/`                                                          | SNMP-based ARP/LLDP/CDP/FDB correlation                                                                  | Engine                 |
| Credentialed audit                   | `Backend/engines/credentialed/`                                                   | SSH-based Linux/Windows collectors, CSAF/CVE package matching                                            | Engine                 |
| Web/DAST scan                        | `Backend/core/web/`, `orchestrator/web_orchestrator.py`                           | 4-phase pipeline: recon→crawl→detect→audit, 7 tool wrappers                                              | Engine                 |
| Scan orchestration                   | `Backend/orchestrator/scan_orchestrator.py`, `core/tasks.py`                      | Chains phases 1→2→3(→4) for the network pipeline                                                         | Orchestrator           |
| Asset registry sync                  | `Backend/scans/asset_syncer.py`                                                   | Reconciles scan payloads into `assets`/`services`                                                        | Service                |
| Finding normalization                | `Backend/scans/finding_normalizer.py`                                             | Standardizes findings across all engines                                                                 | Service                |
| CVE/vuln matching                    | `Backend/core/cve_database.py`, `scans/cve_engine/`                               | CPE matching, CVSS parsing, vuln_intel queries                                                           | Service                |
| Reporting                            | `Backend/reporting/`                                                              | PDF (ReportLab) + CSV generators, network + web                                                          | Service                |
| Compliance evidence adapter          | `Backend/core/compliance_evidence.py`                                             | Normalizes scan output into rule-evaluable payloads                                                      | Service                |
| Compliance rule engine               | `Backend/core/compliance_tasks.py`                                                | Evaluates rules against evidence, writes findings                                                        | Engine                 |
| Audit trail                          | `Backend/core/audit.py`, `db/audit_hardening.py`                                  | Single write path; append-only + hash-chain enforcement                                                  | Service + DB triggers  |
| Audit retention (phase 6a/6b/6c)     | `Backend/core/audit_retention.py`, `scripts/audit/bootstrap_chain_retention*.sql` | Legacy-row purge (6a, shipped disabled) + chained-row purge behind verified archive (6b/6c, per git log) | Service + DB functions |
| Email domain guard                   | `Backend/auth/email_domain_guard.py`, `core/email_security_tasks.py`              | Inline blocklist check + deferred MX/RDAP enrichment                                                     | Service                |
| RBAC                                 | `Backend/auth/rbac.py`                                                            | `require_permission`/`require_role` dependency factories                                                 | Middleware             |
| Rate limiting (app layer)            | `Backend/core/rate_limit_middleware.py`, `scan_helpers.limiter`                   | Baseline 600/min + per-route SlowAPI limits                                                              | Middleware             |
| Vulnerability feed sync              | `Backend/scripts/vuln/*.py`, `scans/nvd_sync.py`                                  | NVD, OSV, MSRC, CSAF, exploit-intel, VulnCheck KEV ingestion into `vuln_intel`                           | Batch job              |

---

## 5. Background processing (Celery)

**7 declared queues** (`Backend/core/celery_app.py`): `default`, `scanner`,
`web_recon`, `web_crawl`, `web_dast`, `web_audit`, `compliance`.

| Queue                                             | Consumed by                  | Task modules                                                                |
| ------------------------------------------------- | ---------------------------- | --------------------------------------------------------------------------- |
| `scanner`, `default`, `compliance`                | Host scanner worker          | `core/tasks.py`, `core/compliance_tasks.py`, `core/email_security_tasks.py` |
| `web_recon`, `web_crawl`, `web_dast`, `web_audit` | `ccure-web-worker` container | `core/web/tasks.py`                                                         |

**Beat schedule** (`core/celery_app.py:47-100`) — 7 entries, published by
`ccure-beat`, executed by whichever worker consumes the queue:

| Schedule                                     | Task                                          | Cadence                                                |
| -------------------------------------------- | --------------------------------------------- | ------------------------------------------------------ |
| `prune-compliance-remediation-logs-weekly`   | `compliance.prune_remediation_logs`           | Sun 00:00                                              |
| `run-scheduled-compliance-scans-every-5-min` | `compliance.run_scheduled_scans`              | every 5 min                                            |
| `purge-stale-unverified-accounts-daily`      | `ccure.tasks.purge_stale_unverified_accounts` | daily 03:30                                            |
| `purge-stale-unapproved-accounts-daily`      | `ccure.tasks.purge_stale_unapproved_accounts` | daily 03:45                                            |
| `purge-expired-refresh-sessions-daily`       | `ccure.tasks.purge_expired_refresh_sessions`  | daily 04:00                                            |
| `sync-disposable-email-domains-weekly`       | `ccure.tasks.sync_disposable_domains`         | Mon 04:15                                              |
| `purge-expired-audit-logs-daily`             | `ccure.tasks.purge_expired_audit_logs`        | daily 04:30 — no-op while `AUDIT_LOG_RETENTION_DAYS=0` |

This table **supersedes** `docs/SYSTEM_ARCHITECTURE.md`'s beat table (see §7,
finding G-2): the compliance-scan cadence changed from every-minute to
every-5-minutes, and two entries (refresh-session purge, audit-log purge) are
missing from that document entirely.

---

## 6. External systems and tool dependencies

| System                                     | Required?                                          | Failure behavior                                                         |
| ------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------------------ |
| Nmap                                       | Optional                                           | `PortEngine` falls back to async TCP connect                             |
| Scapy / Npcap                              | Required for Phase 1                               | Raw-socket discovery techniques unavailable without it                   |
| Nuclei                                     | Optional (network scan); **essential** (DAST)      | DAST: absence recorded via `ToolCoverage`, finding emitted               |
| subfinder / ffuf / sqlmap                  | Optional (DAST)                                    | Coverage gap recorded, not an error                                      |
| SSLyze                                     | Optional (DAST, in-process)                        | —                                                                        |
| Playwright/Chromium                        | Required (DAST crawl phase)                        | Build-time Dockerfile gate fails the image build if missing              |
| Paramiko (SSH)                             | Required (credentialed scan)                       | `POST /scan/credentialed` returns 503 without it                         |
| pysnmp-lextudio                            | Required (topology mapping)                        | Phase 4 unavailable without it                                           |
| SMTP relay                                 | Required (password reset, email OTP, registration) | `MAIL_INLINE_FALLBACK` sends inline if no worker consumes the mail queue |
| ClamAV (clamd)                             | Optional                                           | No `CLAMAV_HOST` → `malware_scan: not_configured`, honest no-scan state  |
| NVD API                                    | Optional (key improves rate limit)                 | —                                                                        |
| VulnCheck API                              | Required token, or sync script exits 2             | —                                                                        |
| OSV / MSRC / CSAF (Siemens, CISA, Red Hat) | Optional, feed-sync only                           | Missing feed = stale/absent data for that source                         |

---

## 7. Preliminary findings feeding into the Gaps section (§20/R)

These surfaced during inventory verification and will be developed further in
the dedicated findings document, but are recorded here since they affect how
several diagrams must be drawn:

- **G-1 (Informational).** `docs/SYSTEM_ARCHITECTURE.md`'s router table
  (§3) omits `routers/admin_email_domains.py` entirely and its "155 HTTP
  operations" total is stale — current count is 175 (see §3 above). The doc
  also cites `scans/router.py` as the Scan History router; the actual file is
  `routers/scan_history.py` (`Backend/scans/` has no `router.py` at all).
- **G-2 (Informational).** `docs/SYSTEM_ARCHITECTURE.md`'s Celery beat table
  (§5) is stale in two ways: `run-scheduled-compliance-scans-every-minute` is
  now `every-5-min` in source, and it is missing
  `purge-expired-refresh-sessions-daily` and `purge-expired-audit-logs-daily`
  entirely (see §5 above).
- **G-3 (Informational).** `docs/SYSTEM_ARCHITECTURE.md` reports "32
  migrations, head `c3h4i5j6k7l8`". Source shows **41 migrations**, head
  `d0e1f2a3b4c5` (`audit_retention_chained_tip_guard.py`) — consistent with
  five audit-retention-chain commits (`ca652f3`, `a710ffb`, `ef14eb9`,
  `f9efa21` and the tip-guard head) that landed after that document was last
  regenerated.
- **G-4 (Requires confirmation).** CLAUDE.md's "Audit-log retention (phase
  6a)" section describes only the legacy-row (`record_hash IS NULL`) purge as
  shipped, and states chained-record deletion is "phase 6b and needs its own
  approval." Source now contains
  `scripts/audit/bootstrap_chain_retention_chained.sql` (functions
  `audit_chain.audit_chain_is_tip_v1`, `audit_retention.purge_chained_v1`,
  etc.) and the git log shows commits titled "phase 6c — chained-record
  deletion, behind a verified archive" and two related fixes. This module's
  actual current scope (is chained-row purge live, or built-but-unapproved?)
  needs a dedicated read of `core/audit_retention.py` and the compliance
  approval trail before the Audit Architecture document can state its status
  as fact rather than inference.
- **G-5 (Informational).** `docker-compose.yml` marks `ccure-web-worker` with
  `profiles: ["container-scanner"]`, which normally means `docker compose up`
  will not start it. In practice it **is** started, because
  `scripts/start_host_scan_stack.ps1` names it explicitly rather than using a
  bare `up -d`. The profile annotation is accurate for a bare compose
  invocation but misleading read in isolation — the supported startup path
  overrides it.

---

## 8. Enabled / Disabled / Optional / Parked matrix

| Component / Module                                                                                                            |                 Present |                          Enabled (this deployment) |                                          Containerized |                                                                 Verified |
| ----------------------------------------------------------------------------------------------------------------------------- | ----------------------: | -------------------------------------------------: | -----------------------------------------------------: | -----------------------------------------------------------------------: |
| API (FastAPI)                                                                                                                 |                     Yes |                                                Yes |                                                    Yes |                                                                   Source |
| Frontend (React SPA)                                                                                                          |                     Yes |                                                Yes |                                                    Yes |                                                                   Source |
| Redis (broker/cache/pub-sub)                                                                                                  |                     Yes |                                                Yes |                                                    Yes |                                                                   Source |
| Celery beat                                                                                                                   |                     Yes |                                                Yes |                                                    Yes |                                                                   Source |
| Network scan pipeline (Phases 1-3)                                                                                            |                     Yes |                                                Yes |                                       No — host worker |                                                                   Source |
| Topology mapping (Phase 4)                                                                                                    |                     Yes |   Optional (SNMP creds required in `scan.options`) |                                       No — host worker |                                                                   Source |
| Credentialed scan (SSH)                                                                                                       |                     Yes |                                                Yes |                                       No — host worker |                                                                   Source |
| Web/DAST scan pipeline                                                                                                        |                     Yes |                                                Yes |                 **Yes** — `ccure-web-worker` container |                                                                   Source |
| Compliance engine (framework evaluation)                                                                                      |                     Yes |                                                Yes |                  No — host worker (`compliance` queue) |                                                                   Source |
| Compliance frameworks: ISO/IEC 27001:2022                                                                                     |                     Yes |                                         **Active** |                                                      — |                                 Source (`core/compliance_frameworks.py`) |
| Compliance frameworks: NIST CSF 2.0                                                                                           |                     Yes |                                         **Active** |                                                      — |                                                                   Source |
| Compliance frameworks: SOC 2, PCI-DSS v4, CERT-In, DPDP, GDPR, NIST 800-53, IEC 62443, NIST 800-82, NERC-CIP, NIS2 (10 total) |            Yes (seeded) |      **Parked** — not offered/scannable/reportable |                                                      — |                                                       Source + CLAUDE.md |
| Audit trail (hash chain, append-only)                                                                                         |                     Yes |                                                Yes |                             No — DB triggers/functions |                                                                   Source |
| Audit retention — legacy rows (phase 6a)                                                                                      |                     Yes |        **Disabled** (`AUDIT_LOG_RETENTION_DAYS=0`) |                           No — DB function + beat task |                                                                   Source |
| Audit retention — chained rows (phase 6b/6c)                                                                                  | Yes (SQL objects exist) |                 **Not Verified** — see finding G-4 |                                                     No |                                                                  Partial |
| Email domain guard                                                                                                            |                     Yes |                                Yes, mode=`enforce` |                          No — inline + `default` queue |                                                                   Source |
| Self-service registration                                                                                                     |                     Yes |     **Disabled** (`ALLOW_SELF_REGISTRATION=False`) |                                                      — |                                                                   Source |
| Malware scanning (ClamAV)                                                                                                     |                     Yes |                       **Optional, off by default** |                               Yes, behind `av` profile |                                                                   Source |
| Containerized network-scan worker (`ccure-worker`)                                                                            |           Yes (defined) |           **Disabled** — superseded by host worker | Yes, behind `container-scanner` profile, never started |                                                                   Source |
| Container gateway (`ccure-gateway`)                                                                                           |           Yes (defined) |            **Disabled** — superseded by host Nginx |       Yes, behind `alt-gateway` profile, never started |                                                                   Source |
| `ccure-db` container (Postgres)                                                                                               |           Yes (defined) | **Started, but unused** — app uses host PostgreSQL |                                                    Yes |                                                                   Source |
| Host Nginx (TLS edge)                                                                                                         |                     Yes |                                                Yes |                                   No — Windows service |                                                       Source + CLAUDE.md |
| DB backup schedule                                                                                                            |                     Yes |                                      Yes, every 6h |                            No — Windows scheduled task |                                                       Source + CLAUDE.md |
| `archive_mode` (Postgres WAL archiving / PITR)                                                                                |                     N/A |                **Off** — no point-in-time recovery |                                                      — |                                                                CLAUDE.md |
| Scan-scope enforcement (`REQUIRE_SCAN_SCOPE`)                                                                                 |                     Yes |                            **Disabled** by default |                                                      — |                                             Source (`config.py:716-718`) |
| Rate-limit Redis-outage fallback                                                                                              |                     Yes |   Enabled (`RATE_LIMIT_MEMORY_FALLBACK=20/minute`) |                                                      — |                                                                   Source |
| Excel/XLSX report export                                                                                                      |         **Not present** |                                                  — |                                                      — | Source (`docs/SYSTEM_ARCHITECTURE.md` §11, confirmed no exporter exists) |

---

_Next in the package: [01_MASTER_ARCHITECTURE.md](01_MASTER_ARCHITECTURE.md) —
Master System Architecture Diagram and Container/Deployment Architecture._
