# Engineering record: Releases since 13 Oct 2026

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 1227–1360, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 1227-1360 -->
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
| **`release-72eb2bb-followups2`**    | `72eb2bb` (`17989e0eebef`) | `72eb2bb` (`12cd34b5bb79`) | **14 Oct 14:13**   | 28 s   |

`gateway-auth` (`40b686e08a4a`) and `api-gateway` are unchanged throughout.
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

What the 13–14 Oct releases changed (each commit names its measurement and
its test):

- `5c062d5`: the end-to-end validation's fixes (SNMP BER decoding, NUL-safe
  sync, OSV source binding and the withdrawn-advisory purge, per-product
  finding rows, `ruled_out`, report and viewer corrections).
- `26a877c`: forked Celery children no longer share the parent's database
  connection (`75aab31`); Nuclei finds the image's templates (`1cf7d24`); a
  failed feed lookup is reported as not assessed, OSV ranges compare the
  source version, the OSV row cap is explicit, only the running kernel is
  assessed.
- `fbf72ba`: the credentialed page renders absent fields as not recorded.
- `d77b50e`: unauthenticated candidate truncation is recorded and reported,
  OS CPEs are searched per host, an SNMP `sysDescr` is never a search term
  (`959c3ec`); a CVE shared by several packages names each (`50f29ea`); the
  legacy credentialed-results address redirects (`2f8337d`); an
  unauthenticated rescan no longer retires credentialed findings (`d77b50e`).
- `6d816e2`: a scan reads complete only after its findings are written, and
  `completed_at` follows them.
- `72eb2bb`: the Nuclei base-image rebuild; every CPE nmap reports reaches the
  scan (`0178fdf`); recycle, restore and purge of a scan are audited
  (`204bb92`); `fix_state` and the "No fix released" filter (`969b1d9`);
  purging a scan detaches rather than deletes services (`be0aa48`).

Verified live after `d77b50e`/`6d816e2` with credentialed and unauthenticated
scans of 10.180.6.45 and 10.180.6.30, run concurrently: payload, database,
findings API, CSV and export agree on every scan; the credentialed findings
of the first pair stayed open after the unauthenticated pair; the kernel
search's truncation is in the stored host record, the technical PDF and the
export summary; no row of the final scan was written after its `completed_at`;
no target, application or database password appears in any log, report,
export, database row or UI capture.

Verified live after `72eb2bb` (14 Oct 2026, scans #1–#4 of `org_development`,
kept): as `ccure`, the image lists 13,831 Nuclei templates (the previous
image: none) and its Nuclei probe finds both planted exposures with no
network; an unauthenticated audit of 10.180.6.45 now records
`cpe:/a:openbsd:openssh:9.6p1` on 22/tcp and reports 17 OpenSSH CVEs as
Potential (before: 0); the credentialed audit stores 2,241
`no_fix_released`, 114 `fix_released` and 34 unrecorded findings, which the
API's `fix_state` filter returns exactly, severities untouched; recycle,
restore and purge each wrote one event in the scan's organisation and the
audit chain verifies; payload, database, CSV and export agree on every scan;
no application or target password appears in any log, report, export or
database row. The credentialed rescans rebuilt the two assets' service
inventory: 96 of the 104 purged rows came back identical, the other 8 are
ports no longer listening (7070 closed, 502 and 56238 not in the host's own
socket table) or ephemeral loopback ports that moved.

**Test data removed 14 Oct 2026** (approved): the 25 validation scans and the
two `e2e-*` stored credentials, through the application's own recycle/purge
and credential-delete routes. Evidence first: `backups/e2e-evidence-20261013/`
(API payloads, findings, PDF/CSV/XLSX/JSON exports, database rows,
`MANIFEST.sha256`); restore point `backups/ccure_db_20261014_153304_full.dump`.
The two asset records were kept; their 104 `services` rows went with the
scans, which `be0aa48` makes impossible and the rescans above rebuilt.

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

<!-- /verbatim -->
