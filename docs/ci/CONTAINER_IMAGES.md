# Container images

How CI builds, scans, tags and smoke-tests the application's Docker images,
what was changed to get there, and what was deliberately left alone. The
workflow is `.github/workflows/images.yml`.

    Git commit → build → vulnerability scan → image tagged with the commit SHA → smoke test

Publishing to a registry, and deploying from it, are later phases. When they
arrive, they push and run **this** image, the one built and verified here, and
never rebuild it anywhere else.

## What gets built

Two images are built from this repository. Everything else in
`docker-compose.yml` is an upstream image the repository only configures.

| Image                      | Built from            | Compose services using it                                                                       | Runs as                                                  |
| -------------------------- | --------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `ccure-audit-pro-backend`  | `Backend/Dockerfile`  | `api`                                                                                           | `ccure` (image default)                                  |
|                            |                       | `worker`, `web-worker`                                                                          | root (compose `user:`; raw sockets, `cap_add NET_ADMIN`) |
|                            |                       | `beat`                                                                                          | root, then `setpriv` to `ccure`                          |
| `ccure-audit-pro-frontend` | `Frontend/Dockerfile` | `frontend`                                                                                      | nginx (master root, workers `nginx`)                     |
| —                          | upstream              | `db` (postgres:18-alpine), `redis`, `clamav`, `portainer`, `api-gateway` (nginx, digest-pinned) | —                                                        |

The backend is **one image in four roles**, chosen by command. That's why it
has no `HEALTHCHECK`: an HTTP check would mark the worker and beat containers
unhealthy. Per-role health checks belong in the compose file the deployment
phase writes.

## Tagging: the commit SHA is the identity

CI tags each image `<name>:<full commit SHA>`, for example
`ccure-audit-pro-backend:3b5a297…`, and labels it with
`org.opencontainers.image.revision` and `.source`. `latest` is never the
identity of an artifact: it names whatever was built last, so it can't say
which code is running, and it can't be promoted without doubt.

There is deliberately no build timestamp label, because it would make two
builds of the same commit differ for no reason.

## The gap between these images and what runs today

**The deployment doesn't run these images' code yet.** `docker-compose.yml`
bind-mounts `./Backend:/app` over the image for `api`, `worker`, `beat` and
`web-worker`, tags every build `:latest`, and builds on the VM itself. So the
code executing is the working copy on the VM's disk, not the image.

That's how development on the VM works today (edit, then restart), and it
wasn't changed here. Promoting a CI-built image means a production compose
configuration **without** the bind mounts, referring to the image by SHA. That
belongs to the deployment phases, and until it exists, "the image CI verified"
and "what runs" are not the same thing.

## CI: what each run does

For both images, after every merge to `master` (push), nightly at 02:30 IST,
and on demand (Actions → Images → Run workflow). **Not on pull requests:** a PR
is gated on what it changes in the application, while an image scan reports on
OS packages and binaries whose advisories arrive with no commit, so as a PR
check it failed PRs for advisories nobody had introduced. See
[BRANCH_PROTECTION.md](BRANCH_PROTECTION.md#what-gates-a-pr-and-what-runs-after-it).

1. **Build** with BuildKit, loaded into the runner's Docker. Nothing is pushed.
   The GitHub Actions layer cache is scoped to the UTC day, so the day's first
   build installs current OS packages; the nightly build uses no cache. A
   long-lived cache kept serving packages from the day a layer was first built
   (8 Oct 2026: a cached Chromium 153 carried 80 HIGH/CRITICAL findings fixed in
   154), which failed the gate on findings a fresh build does not have. The
   refresh changes what is installed, never what is scanned or how.
2. **Report** every vulnerability Trivy finds, counted by package type,
   severity and fix availability, in the job summary. This never fails.
3. **Gate:** fail on CRITICAL or HIGH findings **with a published fix**, minus
   the reviewed exceptions for that image.
4. **Smoke test** the image the way compose runs it.
5. **Record** the tag, image ID, size and revision label in the job summary.

`Backend Image` and `Frontend Image` are **not** required checks: they do not
run on pull requests, so a required one would never report and every PR would
wait for it. A red run on `master` or at night is a finding to fix; run the
workflow manually on the commit being released.

## Vulnerability policy

| Finding                                    | What happens                                                 | Why                                                                                                                              |
| ------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| CRITICAL or HIGH, fix published            | **Fails the run**, unless it's in the image's exception file | Someone can act on it.                                                                                                           |
| CRITICAL or HIGH, no fix published         | Reported                                                     | Blocking leaves the build red with nothing anyone can do. It reaches the image through a base-image update.                      |
| MEDIUM, LOW, UNKNOWN                       | Reported                                                     | Visible in every run's summary; not a merge decision.                                                                            |
| Python packages in the app's site-packages | Left to pip-audit (`security.yml`)                           | They already have a reviewed backlog there. Gating them twice would put one advisory under two exception lists that drift apart. |

The Python base image's **own** tooling (its setuptools and the packages that
setuptools bundles) isn't an application requirement, so pip-audit never sees
it. It's gated here.

### Vulnerability exceptions

`.github/security/trivy-backend.yaml` and `trivy-frontend.yaml`, one file per
image, so an exception for one can't hide a finding in the other. Every entry:

- names **one vulnerability ID**, and on the backend is scoped to **one path**
  (the binary or package carrying it). The same CVE in another binary is
  still caught, as a test that moved an exception to the wrong binary showed;
- says **why** it's accepted and **how it is removed**;
- **expires** (`expired_at`). On that date it stops applying and the gate goes
  red again, so an exception is a dated decision, not a permanent silence.

Adding or renewing one: check the remediation first (is there a new upstream
release? a new base digest?), write the statement, set an expiry no more than
about a month out, and never add one only to make a build pass.

Tested: the gate passes as configured, and fails when an entry is removed,
when one has expired, and when one names the wrong binary.

### Exceptions at introduction (24 Sep 2026)

| Image    | What                                                                     | Count           | Remediation                                                                                       | Expires    |
| -------- | ------------------------------------------------------------------------ | --------------- | ------------------------------------------------------------------------------------------------- | ---------- |
| backend  | subfinder v2.6.7: Go stdlib, `x/crypto`, `x/net` compiled in             | 45 (2 critical) | Upgrade to v2.16.0. Not done here: it changes subdomain enumeration and needs its own validation. | 2026-10-24 |
| backend  | nuclei v3.11.1: Go stdlib and modules compiled in                        | 14              | Already the newest release; take the next one                                                     | 2026-10-24 |
| backend  | ffuf v2.3.0: `golang.org/x/net` compiled in                              | 8               | Already the newest release; take the next one                                                     | 2026-10-24 |
| backend  | `jaraco.context`, `wheel` vendored in the base image's setuptools 79.0.1 | 2               | A python:3.11-slim digest with a fixed setuptools (Dependabot)                                    | 2026-10-24 |
| frontend | libexpat 2.8.4 in nginx:stable-alpine                                    | 1               | The newest nginx:stable-alpine still ships it; Alpine has the fix, so the next digest bump        | 2026-10-08 |

The scanner-tool exceptions are the largest item. These binaries talk to hosts
under assessment, which are untrusted by definition, so upgrading them is the
first follow-up.

### Base-image packages patched in the Dockerfiles (7 Oct 2026)

Both base images are pinned by digest, so a fix the distribution publishes
after the pin never arrives on its own. Where the gate flags a base-image
package that has a published fix, the Dockerfile upgrades **that package
only** and leaves the rest of the base as pinned:

| Image    | Packages                                                    | Advisories                                      | Step                                    |
| -------- | ----------------------------------------------------------- | ----------------------------------------------- | --------------------------------------- |
| frontend | `pcre2` 10.48-r0 → 10.49-r0, `libexpat` 2.8.4-r0 → 2.8.5-r0 | CVE-2026-103111, CVE-2026-93990                 | `apk upgrade --no-cache pcre2 libexpat` |
| backend  | `openssl` and `pcre2` packages                              | CVE-2026-75804, CVE-2026-84782, CVE-2026-103111 | `apt-get install --only-upgrade …`      |

The frontend libexpat entry above was an exception until this patch made it
unnecessary; it was removed a day before it expired, and
`trivy-frontend.yaml` holds no exceptions now. Drop each upgrade once the
digest moves to a base that already carries the fix.

## Changes made, with the evidence for each

Measured on this VM on 24 Sep 2026, building from the committed tree.

| Change                                                                                                                        | Evidence                                                                                                                                                                                                   | Effect                                                                                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `COPY --chown` instead of `COPY` then `RUN chown -R`                                                                          | Each recursive chown wrote a second full copy of its files: 488 MB of Python packages, 690 MB of Playwright browser, 90 MB of app code                                                                     | Backend **5,270 MB → 3,223 MB**                                                                                                                                                                                                                |
| Compiler toolchain (`gcc`, `python3-dev`, `libpq-dev`) moved to the builder stage; `wget`, `unzip`, `curl` to the tools stage | Nothing at runtime uses them (`psycopg2-binary` bundles libpq; the scanner builds `curl …` reproduction commands as text). `linux-libc-dev`, pulled in by `python3-dev`, carried 88 of 191 HIGH advisories | Backend Debian findings: CRITICAL 2 → 1, HIGH 191 → 69, MEDIUM 1,593 → 118. No compiler in production                                                                                                                                          |
| `.dockerignore`: tenant data, local databases, logs; `**/` for nested patterns                                                | The image deployed today contains **125 compliance-evidence uploads and 3 SQLite databases** from the VM's working copy; `__pycache__` and `*.log` only ever matched the top level                         | A build from the same directory now contains none of them; tracked seed data unaffected                                                                                                                                                        |
| SHA-256 checks on the nuclei, subfinder and ffuf downloads                                                                    | A version pin says which release was requested; only a checksum says the bytes are that release                                                                                                            | A tampered or corrupted download fails the build                                                                                                                                                                                               |
| ffuf wordlist pinned to a SecLists commit and checksummed                                                                     | Fetched from `master` with `\|\| echo skipped`, so it changed upstream and a failed download shipped an image whose ffuf had nothing to try                                                                | Byte-identical to what the image carried before (checked)                                                                                                                                                                                      |
| Base images pinned by digest; Dependabot `docker` ecosystem                                                                   | Tags move; a rebuild of one commit could start from different bytes                                                                                                                                        | Reproducible base; security rebuilds of the same version line arrive as reviewed PRs. Version changes (Python 3.11 → 3.14, Node 22 → 25) are excluded: Dependabot's first run proposed both, and 3.14 fails to build Pillow 10.3.0 from source |
| Frontend `npm ci` (was `npm install`) on Node 22 (was 20)                                                                     | `npm install` may re-resolve and rewrite the lock during a build; CI tests on 22                                                                                                                           | Same bundle hash as before (`index-B--j4ngv.js`), now guaranteed by the lock                                                                                                                                                                   |
| `/app` handed to `ccure` explicitly                                                                                           | `--chown` covers copied files, not the directory copied into; `start.sh`'s `sed -i` needs to write there                                                                                                   | Ownership of every file identical to before (compared file by file)                                                                                                                                                                            |

**Checked for parity against the previous image:** same file ownership and
modes across `/app`, the Python packages, Playwright, the templates and the
wordlist; identical scanner binaries; identical nmap file capabilities; and the
smoke test passes on both.

## Kept deliberately

- **Workers run as root.** Raw-socket scanning needs it; the reasons are in
  `docker-compose.yml`. `beat` drops to `ccure` with `setpriv`.
- **nmap's file capabilities.** They make `execve` fail with EPERM in any
  container lacking `NET_ADMIN`, the api included, as root or not. That's
  unchanged, and only the worker, which has `cap_add NET_ADMIN`, runs nmap.
  The smoke test checks it there.
- **Debian's `chromium`.** Playwright drives its own browser under
  `/opt/playwright`, but the Debian package is what installs the shared
  libraries that browser needs. Removing it means listing those libraries by
  hand; it's a size optimisation with a breakage risk, not a security fix.
- **Nuclei templates fetched at build time.** They're a detection feed, and
  freezing them trades new coverage for reproducibility. The snapshot an image
  carries is fixed by its SHA.
- **Python dependencies without a lock file.** Unchanged, as in Phase 2.
  Measured: over eight days four transitive packages resolved to newer patch
  versions (Mako, soupsieve, watchfiles, wcwidth). Images are reproducible from
  their SHA once built; a rebuild of an old commit may differ in these.
- **`pytest` in the runtime image.** It comes from `requirements.txt`; moving
  it is the Phase 2 follow-up.
- **The `PYTHONPATH` warning.** The trailing `:` it complains about is what
  makes `/app` importable for `start.sh`; see the comment in the Dockerfile.
- **The frontend's nginx master runs as root.** An unprivileged nginx image
  listens on 8080, which changes the compose mapping and host nginx. That's a
  deployment change, not an image one.

## Smoke tests

`scripts/ci/smoke_backend.sh <image>` and `scripts/ci/smoke_frontend.sh <image>`
run in CI and work the same way locally.

**Backend:**

- **api**, as the image's default user and command: it migrates a fresh
  schema (67 tables) and answers `GET /` with JSON on port 8000.
- **worker**, as compose runs it (root, `NET_ADMIN`/`NET_RAW`): it answers a
  Celery ping, and nmap executes.
- **beat**, with compose's own `setpriv` command: it starts, and runs as
  `ccure`.
- **Scanners:** nuclei, ffuf, subfinder and sqlmap execute.
- **Secrets:** no generated secret appears in any container's log.

**Database safety** follows the Phase 1 rule. The script creates its own
PostgreSQL on a private Docker network, with no published port and
credentials generated per run. It builds `DATABASE_URL` from that container
alone, reads nothing from the caller's environment, and refuses to run if the
URL names anything else.

**Frontend:** the SPA shell with its Content-Security-Policy and `nosniff`
headers (the CSP was once silently lost to nginx's `add_header` inheritance),
client-side route fallback, an immutable-cached bundle, `/api/` reaching the
API gateway at `172.31.254.10:8080` with its `/api` prefix kept (Phase 10.7;
the stand-in owns that address on its own loopback and the frontend shares its
network namespace, so the test needs `NET_ADMIN` and no host network on the
live subnet), and no `[emerg]` or `[crit]` from nginx.

**Both scripts were tested against broken images:** missing `sqlmap` fails;
a `start.sh` that prints the JWT key fails; a frontend without its CSP
fails. The secret check first **passed** the leaking image. Under
`set -o pipefail`, `printf … | grep -q` makes the producer die of SIGPIPE at
the first match, so a match reads as failure. Every such check now reads a
here-string.

## Running it locally

```bash
docker buildx build --load -t ccure-audit-pro-backend:local Backend/
bash scripts/ci/smoke_backend.sh ccure-audit-pro-backend:local
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/.github/security:/cfg:ro" \
  aquasec/trivy:0.74.0 image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed \
  --exit-code 1 --ignorefile /cfg/trivy-backend.yaml \
  --skip-dirs /home/ccure/.local/lib/python3.11/site-packages ccure-audit-pro-backend:local
```

Build from a clean checkout (or `git archive`) when the result matters. A build
from a working copy on the VM uses that working copy's files, which is exactly
how the evidence uploads got into the deployed image.
