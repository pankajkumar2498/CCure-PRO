---
paths:
  - "docker-compose*.yml"
  - "Backend/Dockerfile"
  - "Frontend/Dockerfile"
  - ".env.example"
  - "Backend/.env.example"
  - "Backend/start.sh"
  - "Backend/core/celery_app.py"
  - "Backend/core/web/self_check.py"
  - "scripts/backup_db.sh"
  - "scripts/install_backup_schedule.sh"
  - "scripts/install_feed_schedule.sh"
  - "scripts/run_feed_sync.sh"
  - "scripts/docker-postgres-init.sql"
  - "scripts/linux/**"
  - "scripts/validation/**"
---

# Deployment on the Linux VM

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 1091–1226, 1341–1360, 1420–1432) and is maintained here. Frozen original: `docs/archive/engineering-record/deployment-linux-vm.md`, `docs/archive/engineering-record/releases.md`, `docs/archive/engineering-record/runtime-architecture-and-edge-security.md`. The repository-wide rules in `CLAUDE.md` still apply.

> If TLS to PostgreSQL ever comes back (see the TLS bullet below), the Windows deployment's
> `verify-full` set-up and the three things that bit it (backslashes in a libpq URI, every
> hostname a client dials on the certificate, checking `pg_stat_ssl` before `hostssl`) are
> in the **Database** bullet of
> `docs/archive/engineering-record/runtime-architecture-and-edge-security.md`.

## Deployment: Linux VM (`ccurepro`, 10.180.22.127) — since 17 Sep 2026

The application now runs on an Ubuntu 24.04 VM (15 GB, 8 CPUs) with
**everything in Docker**, reached from a Windows workstation over SSH. The
"Architecture" section below still describes the Windows-host deployment it
was written for — PostgreSQL on the host, the scanner worker as a host
process, PowerShell scripts, `D:\PostgreSQL`. Where the two disagree, this
section is the VM's answer.

- **PostgreSQL 18 is the `ccure-db` container**, volume `pgdata18`, published
  on `127.0.0.1:5432` only. The bootstrap superuser is `postgres`, not
  `ccure_user` — `scripts/docker-postgres-init.sql` says why that cannot be
  corrected after initdb. The PG15 `pgdata` volume (383 MB) was kept unmounted
  for rollback until a verified full dump existed, then removed on 17 Sep 2026
  (below); only `ccure-audit-pro_pgdata18` remains.

- **TLS to PostgreSQL is off here, and that is a recorded decision.** The
  Windows rule (`verify-full`, `hostssl` only) exists because that server
  listened on `*` and the LAN could reach it. The container is reachable from
  loopback and the Compose bridge (`172.18.0.0/16`) and from nowhere else, so
  there is no hop for a certificate to authenticate. `PGSSLMODE=disable` in
  `.env`, `ssl=off` in the server. **If the port binding is ever widened past
  `127.0.0.1`, this decision is void and TLS comes back first** —
  `scripts/tls/` still issues the certificates, and the compose file still
  mounts `/etc/ssl/ccure/ccure-internal-ca.crt` for the day it does.

- **The scanner worker runs in Docker with `network_mode: host` and
  `NET_ADMIN`/`NET_RAW`** — the Linux equivalent of the Windows host worker,
  for the reasons in the compose file. **Since 13 Oct 2026 its code is baked
  into the image** (see "Releases" below): a change under `core/`, `scans/` or
  `orchestrator/` reaches it only through a release, and restarting the
  container restarts the same code. The Windows start scripts were retired on
  9 Oct 2026; every service is `restart: unless-stopped` so a reboot brings it
  all back together.

- **`docker-compose.yml` sizes PostgreSQL for this VM** — `shared_buffers=2GB`,
  `effective_cache_size=6GB`, `work_mem=16MB`, `shm_size: 1gb`. The `shm_size`
  line is the one that will look removable: Docker's default `/dev/shm` is
  64 MB, and a parallel query past it fails with "could not resize shared
  memory segment … No space left on device", which reads as a full disk.

- **Reaching things from the Windows workstation.** The app is
  `https://ccurepro.cdac.in` (host nginx on 443, 301 from 80). Portainer is
  reached through the tunnel below, **not** on the LAN. VS Code uses Remote
  SSH to the same host. `psql` on the VM is the 16 client and talks to the 18
  server fine; `pg_dump` 16 does not.

- **PostgreSQL and Portainer from the workstation are one SSH tunnel with a
  dedicated key.** `C:\Users\pankaj\.ssh\ccure_vm_tunnel` (generated on the
  workstation; the private half has never left it) is in the VM's
  `~/.ssh/authorized_keys` as `restrict,port-forwarding,permitopen=
"127.0.0.1:5432",permitopen="127.0.0.1:9443",command="/bin/false"` — it can
  forward to those two ports and do nothing else (a forward to Redis answers
  `administratively prohibited`, a shell request exits 1; both measured), which
  is why VS Code keeps its own credentials rather than reusing it.
  `ssh -N ccure-vm` on the workstation (`ccure-vm-db` is an alias of the same
  entry) forwards **15432 → PostgreSQL** and **9443 → Portainer**; then
  `https://127.0.0.1:9443` for Portainer. Verified from the workstation on
  17 Sep 2026:

  - **pgAdmin 4** (9.14, bundled with the workstation's PostgreSQL 18) has a
    server entry **CCure VM (ccure_db)** in group _CCure VM_ that opens the
    tunnel itself through its bundled `sshtunnel`. Imported with
    `setup.py load-servers`; `pgadmin4.db.bak-20260917` beside the config DB
    is the state before.
  - **psql / DBeaver**: `ssh -N ccure-vm`, then connect to
    **`127.0.0.1:15432`**. Not 5432 — the
    workstation's own PostgreSQL 18 still listens there, and a client pointed
    at 5432 is talking to the _old_ Windows database without any error saying
    so.

  Role `ccure_user`, password `POSTGRES_PASSWORD` in the VM's root `.env`
  (`Backend/.env` repeats it in `POSTGRES_PASSWORD` and `DATABASE_URL`; the
  compose file builds every service's `DATABASE_URL` and `TEST_DATABASE_URL`
  from the root value). The `ccure-db` container's own `POSTGRES_PASSWORD` is
  the bootstrap superuser's, fed from `POSTGRES_SUPERUSER_PASSWORD`, and is a
  different value. `sslmode=disable` on the client side, per the TLS decision
  above.

  **Rotated 14 Oct 2026, 07:59 UTC**, because it had been printed into six
  local assistant session transcripts (and so sent off-host with them); it was
  in no repository file, git history, backup or container log. The role now
  holds a SCRAM verifier computed client-side, passed over stdin, so the
  plaintext reached no command line or server log. Old `.env` files and the
  old verifier are in `~/ccure-secret-backups/rotation-20261014_132850/` (700)
  for rollback. The old value survives, inert, in those files, in two JSON files of
  `backups/native_clean_reset_20261004/` (600), in the `ccure-db` container's
  `CCURE_APP_PASSWORD`, in `~/ccure-migration/restore*.sh`, and in local
  Claude and Codex session transcripts; it is in no repository file, git
  history or dump (checked 14 Oct 2026). `~/ccure-migration/` (17 Sep) was
  664 with `.env` backups holding the still-live `SMTP_PASSWORD` and
  `VULN_DB_PASSWORD`; it is 700 now and the `.env` backups are in
  `~/ccure-secret-backups/migration-20260917/`. **Clients outside the VM — pgAdmin and DBeaver on the
  workstation — need the new value from the root `.env`.** The `ccure-db`
  container still carries the old value as `CCURE_APP_PASSWORD`, which only
  initdb reads; it updates the next time that container is recreated.

  **`vuln_intel` is read-only from that entry, by design.** Its 22 tables are
  owned by `admin` — the role the feed sync scripts and the application's
  `VULN_DB_USER` use — and `ccure_user` holds SELECT through
  `ALTER DEFAULT PRIVILEGES FOR ROLE admin`, so a table a sync creates next
  month is readable the moment it exists. Note what did _not_ grant that:
  `GRANT ALL PRIVILEGES ON DATABASE vuln_intel TO ccure_user` had been in
  `docker-postgres-init.sql` all along and confers CONNECT, CREATE and TEMP
  only; every SELECT still failed with 42501 until 18 Sep 2026. The
  application role stays unable to write the catalogue its findings rest on.
  For writes, the second pgAdmin entry **CCure VM (vuln_intel as admin)**
  connects as the owner (`VULN_DB_PASSWORD` in `.env`).

- **The desktop is not part of the deployment.**
  `sudo scripts/linux/disable_desktop.sh` sets `multi-user.target` and keeps
  the packages; GNOME and TigerVNC were holding 1–2 GB and a listener on
  `0.0.0.0:5901`.

- **Portainer is a service in `docker-compose.yml`, on `127.0.0.1:9443`.** It
  holds the Docker socket, which is root on the VM, so it is deliberately not
  on the LAN — it was `0.0.0.0:9443` while it was a hand-run container. Its
  volume `portainer_data` is declared `external` because it predates the
  compose entry and holds the admin user and the self-signed certificate.
  **"Cannot access Portainer" was the 5-minute lock**: a fresh instance needs
  an admin user within 5 minutes of starting, plus the `setup_token` printed
  in `docker logs portainer`; miss either and it serves a lock page until
  restarted. `docker restart portainer` reopens the window.

- **Every container's log is rotated** (`x-logging` anchor, json-file, 20 MB
  × 5). Docker's default is the same driver with no cap, so a scanner worker
  that logs every probe fills the disk one line at a time and the first
  symptom is PostgreSQL refusing writes. A new service must carry
  `logging: *default-logging`; there is no daemon-level default on this VM.

- **`docker compose up -d` is the whole stack**, Portainer included, and
  `COMPOSE_PROFILES=container-scanner` in `.env` is what makes it start the
  worker and web-worker. The PG15 `pgdata` volume and the anonymous leftovers
  were removed on 17 Sep 2026 once a verified full dump existed; nothing
  outside compose-declared volumes holds state.


**Open issues (known, not fixed):**

- `/scan/:scanId/credentialed-results` is kept as a compatibility redirect;
  nothing generates it.
- The workstation's pgAdmin and DBeaver entries need the rotated
  `ccure_user` password. Not verifiable from the VM: no failed `ccure_user`
  login since the rotation, `log_connections` is off, and no pgAdmin or
  DBeaver session or tunnel was open on 14 Oct 2026.
- **The web worker's start-up self-check reports `playwright_chromium`
  missing** (`core/web/self_check.py`): it looks for a bundled Chromium under
  `/opt/playwright`, which the image deliberately replaced with Chrome Stable
  (`CCURE_BROWSER_CHANNEL=chrome`). Every image since at least `6d816e2` logs
  it; it gates nothing, but the log line says scans "must not be read as
  clean".
- **`nuclei_probe` reports `nuclei_templates_run: True` when Nuclei loaded no
  template** — the shape that hid the unreadable templates. Measured on the
  `6d816e2` image as `ccure`: 0 findings in 0 s, `ran: True`.
- RHEL's OpenSSH banner names no distribution, so an unauthenticated RHEL
  finding is graded against the upstream version (memory note, unchanged).


## Architecture

- **API** — `ccure-api` container. **Since 13 Oct 2026 the code is baked into
  the image** and only data paths are mounted (`Backend/reports`, `logs`,
  `data/feeds`, `data/compliance_evidence`, `db/cves.db`, `Backend/.env`,
  `backups/`); a code change needs a release ("Deployment: Linux VM" →
  "Releases"). On the VM since Phase 10.7 it publishes no port
  and listens on `172.31.254.20:8000` only; reach it through
  `https://10.180.22.127/api/` (the gateway), or at that address from the host
  for tooling.
- **Frontend** — `ccure-frontend`, `localhost:3200`. Assets are **baked at build
  time**; a JSX change ships as a release ("Deployment: Linux VM" →
  "Releases"), built with `VITE_API_BASE_URL=/api`.
