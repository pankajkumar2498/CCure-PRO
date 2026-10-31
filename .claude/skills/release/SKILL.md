---
name: release
description: Deploying a CCure release to the Linux VM (ccurepro): building the backend and frontend images from a committed HEAD, backups and idle checks before deploying, compose.sh, verification, rollback with --fallback, and the release ledger. Use before any deployment, image rebuild or recreation of the api, worker, web-worker, beat or frontend containers.
---

> Task instructions. Claude Code loads this skill when it is invoked (`/release`) or judged relevant; every other agent is routed here by `AGENTS.md`. Moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 1227–1283) and maintained here.

> **Status (31 Oct 2026):** the ledger was brought up to date from the release directories under `backups/` and the running containers. Where a directory records no time or outage the row says so; nothing was inferred. Check the running image IDs (`docker inspect -f '{{.Image}}' ccure-api ccure-frontend`) before trusting the bold row.

### Releases (since 13 Oct 2026)

Since release `48879df` (13 Oct 2026, 03:35–03:39 UTC, a 264 s outage) the
application runs from **images, not bind-mounted source**: editing `Backend/`
or `Frontend/` changes nothing live, and a change reaches the VM only as a
release. That release's own record is
`backups/rbac-release-48879df…/development-update-plan.md`.

- **A release is a directory** `backups/release-<rev>-<name>/` (mode 700):
  `compose.sh`, `artifact-inputs.env` (the image IDs), `fallback-artifact-inputs.env`
  (the previous release's), `current-runtime-settings.review.json`,
  `development-artifacts.compose.yml`, and `support` → the frozen compose and
  docs in `backups/rbac-release-48879df…/support`. `compose.sh` reads the root
  `.env`. **Never deploy with a plain `docker compose up`**: it reattaches the
  source mounts or builds a different candidate.
- **Building.** The backend is an overlay on the verified base image
  `ccure-audit-pro-backend:48879df…`: `/app` replaced from
  `git archive HEAD Backend`, dependencies, tools and browsers unchanged. The
  frontend is a full build of `git archive HEAD Frontend` with
  `VITE_API_BASE_URL=/api`. Build from a committed HEAD only.
- **Deploying.** Backup (`scripts/backup_db.sh`, and confirm a full dump from
  today), confirm both workers idle (`celery inspect active`) and no scan
  running or queued, then
  `compose.sh up --no-start --no-deps --no-build --pull never --force-recreate api worker web-worker beat frontend`,
  `compose.sh start api`, wait for `https://ccurepro.cdac.in/api/` to answer
  200, then `compose.sh start frontend worker web-worker beat`. Exactly one
  beat. A frontend-only release recreates `frontend` alone.
- **Rollback** is the same with `compose.sh --fallback`, which uses the
  previous release's images. No database change is involved unless a release
  says so.

| Release directory                   | Backend (image)           | Frontend (image)          | Live (UTC)         | Outage |
| ----------------------------------- | ------------------------- | ------------------------- | ------------------ | ------ |
| `rbac-release-48879df…`             | `48879df` (`d40f93451400`) | `48879df` (`051f9feac0b7`) | 13 Oct 03:39       | 264 s  |
| `release-5c062d5-e2e-fixes`         | `5c062d5` (`ea8746c86d0e`) | `5c062d5` (`c98838e696be`) | 13 Oct 08:44       | 32 s   |
| `release-26a877c-e2e-fixes2`        | `26a877c` (`c007fed58b80`) | `26a877c` (`3c21462f8678`) | 13 Oct 09:42       | 25 s   |
| `release-fbf72ba-ui`                | `26a877c` (`c007fed58b80`) | `fbf72ba` (`94b412011ddd`) | 13 Oct 11:30       | ~1 s   |
| `release-d77b50e-followups`         | `d77b50e` (`9dd7649fc559`) | `d77b50e` (`a21479ea76c8`) | 14 Oct 07:59       | 38 s   |
| `release-6d816e2-finalize`          | `6d816e2` (`e19b9b49c73c`) | `d77b50e` (`a21479ea76c8`) | 14 Oct 08:43       | 25 s   |
| `release-72eb2bb-followups2`        | `72eb2bb` (`17989e0eebef`) | `72eb2bb` (`12cd34b5bb79`) | 14 Oct 14:13       | 28 s   |
| `release-3212d6b-platform-plugin`   | `3212d6b` (`3a0dde6d4580`) | `3212d6b` (`4ce1221e709f`) | 14 Oct 18:20       | 30 s   |
| `release-84bad17-host-security-assessment` | `3212d6b` (`3a0dde6d4580`) | `84bad17` (`5c875eee5bfb`) | 23 Oct, time not recorded | not recorded |
| `release-9040eb9-host-card-layout`  | `3212d6b` (`3a0dde6d4580`) | `9040eb9` (`58f0ab034c82`) | 23 Oct, time not recorded | not recorded |
| `release-a835ad5-available-templates` | `3212d6b` (`3a0dde6d4580`) | `a835ad5` (`5e3bd5018467`) | 23 Oct, time not recorded | not recorded |
| **`release-f5c6e88-credentialed-mac`** | `f5c6e88` (`1a83ead7972d`) | `a835ad5` (`5e3bd5018467`) | **28 Oct 04:57**   | 26 s   |

`gateway-auth` (`40b686e08a4a`) and `api-gateway` are unchanged throughout.

The rows after `72eb2bb` come from each directory's `artifact-inputs.env`,
`release-notes.txt`, `DEPLOYMENT_REPORT.md` and `cutover.log`:

- `3212d6b` (backend overlay on `72eb2bb`, full frontend build): cutover
  18:19:49–18:20:19 UTC, 30.1 s, no rollback.
- `84bad17`, `9040eb9`, `a835ad5`: frontend-only releases, each replacing
  `ccure-frontend` alone; their notes record no deployment time. `9040eb9`'s
  first verification was wrong and it was briefly rolled back before the
  corrected check passed.
- `f5c6e88`: backend-only hotfix, an overlay on the `3212d6b` image (the
  credentialed pass records the MAC it read, no schema change); cutover
  04:57:18–04:57:45 UTC, 26.4 s, API answering 200 after 25.0 s.
- `rbac-release-2f3523db…` (created 13 Oct, before `48879df`) holds a candidate
  and support archives but no deployment record, so it is not a row here.
- On 31 Oct 2026 `ccure-api` and `ccure-frontend` show a start time of
  29 Oct 05:19 UTC with the `f5c6e88` / `a835ad5` images unchanged, and the
  workers 28 Oct 04:57. That restart is not a release; nothing records why.
The `ccure_user` password was rotated in the `d77b50e` window (see the
PostgreSQL bullet above).
`5c062d5` applied migration `a7c9e1b3d5f8` (one finding row per CVE per
product) at API start; `72eb2bb` applied `c4d6e8f0a2b4` (`fix_state`) and
`d5e7f9a1b3c6` (services outlive their scan). No other release changed the
schema.

**`72eb2bb` is a full base-image build, not an overlay.** Its backend image
was built from `Backend/Dockerfile` at that commit, so it carries `61bf9ca`'s
template permissions; later overlays should use it as their base. The rebuild
moved two Python packages (`playwright` 1.63.0 → 1.64.0, `wrapt` 2.5.0 →
2.5.1). Built on the VM, not by the hosted Images workflow: the full suite ran
inside the image, CI's `scripts/ci/smoke_backend.sh` and
`check_browser_runtime.py` passed, and Trivy was not run here.
