# CCure Audit PRO — Compliance Engine Deployment & Operations Guide

How the Policy Compliance Engine is released and operated. It is part of CCure Audit,
not a separately deployed service: it ships in the same backend image and runs in the
same `api`, `worker` and `beat` containers. The release procedure, rollback and the
deployed-version table are in [`CLAUDE.md`](../../CLAUDE.md), "Deployment: Linux VM" →
"Releases"; this guide covers only what is specific to compliance.

---

## 1. What a release does

1. **Schema.** Every API start runs `alembic upgrade heads`, so a merged migration is
   live at the next restart. The history has several heads: always `heads`, never
   `head`. Back up first (`scripts/backup_db.sh`, and confirm a full dump from today).
2. **Catalogues.** `main.py` seeds the framework catalogues at start when its bootstrap
   condition finds one missing. To seed by hand, run inside the API container:
   ```bash
   python -m scripts.seed_compliance                     # every catalogue
   python -m scripts.seed_compliance --seed-file <path>  # one
   ```
   The seed files are in `Backend/data/compliance_seeds/`. A seed file the bootstrap
   cannot find makes its condition permanently true and re-runs the seeder on every
   start; that is a slow boot, not an error.
3. **Workers.** The `worker` service consumes `scanner,default,compliance`, and runs
   only with `COMPOSE_PROFILES=container-scanner`. Exactly one `beat` runs; it drives
   `compliance.run_scheduled_scans` every 60 s. If the `compliance` queue grows, the
   worker is not running.

## 2. Which frameworks are available

A catalogue is available only if it is on the active list
(`core/compliance_frameworks.py`, overridable with `COMPLIANCE_ACTIVE_FRAMEWORKS`) and
enabled for the tenant. Parked catalogues stay seeded but are not offered, scannable or
reportable. To change the list use
`python -m scripts.set_active_frameworks --framework <id>` (dry run) and then `--apply`;
see "Which frameworks are switched on" in `CLAUDE.md`.

## 3. Rollback

There is no compliance feature flag. Roll back with the release procedure
(`compose.sh --fallback`, previous release's images). No database change is involved
unless the release says so; if one is, downgrade by revision or branch name
(`alembic downgrade <revision-or-branch>@-1`), after a backup.

## 4. Monitoring

- Scheduled scans and findings appear in the audit log and in the compliance scan
  history; a scheduled framework that was uninstalled or parked is skipped.
- A compliance run records its own state; a run that could not assess something reports
  it as not assessed, never as passed.
- The application exports no Prometheus metrics. Watch the `compliance` queue length in
  Redis and the worker log.
- Evidence uploads are scanned by ClamAV when `CLAMAV_HOST` is set
  (`docker compose --profile av up -d clamav`); with a scanner configured and down,
  uploads are refused with 503. See "File uploads" in `CLAUDE.md`.
