# Live scan validation

A change on a scan path is checked by scanning real hosts with the code before
the change and the code after it, and comparing what the scans stored. Unit
tests and the full suite cannot do this, because they replace the network: a
probe that stops sending, a frame that stops being published, or a finding that
stops being written still passes them. The modular-refactoring plan requires a
live check for B2, B3, C2, C3 and C6
([analysis §11](../architecture/MODULE_INDEPENDENCE_ANALYSIS.md)). Its first use
is recorded in [the refactoring log](../architecture/MODULAR_REFACTORING_LOG.md)
§6, under B2.

The tooling is in `scripts/validation/`. It needs Docker and the backend image,
and nothing else.

## The targets

`scripts/validation/targets.sh up|status|down` manages disposable containers on
an internal Docker network. `scripts/validation/targets.env` defines them in one
place:

| Address         | Container                | What it exercises                                                          |
| --------------- | ------------------------ | -------------------------------------------------------------------------- |
| `172.30.250.10` | `ccure-validation-ssh`   | Ubuntu 24.04 running OpenSSH: banner, version, the SSH probe               |
| `172.30.250.11` | `ccure-validation-web`   | nginx serving a dummy `.env` and `.git/config`: Nuclei and the HTTP checks |
| `172.30.250.12` | `ccure-validation-redis` | Redis with no authentication: a critical network check                     |
| `172.30.250.13` | `ccure-validation-pg`    | PostgreSQL: service detection and the default-credential probe             |
| `.14`, `.15`    | none                     | Empty addresses, which must stay inactive                                  |

**Isolation.**

- **The network is `--internal`.** There is no route off the host and no
  published port, so no target can reach anything else and nothing outside the
  machine can reach a target.
- **Nothing real.** The targets hold no real data and no real secret: the
  dotenv file is written into the nginx container at start-up with dummy values,
  and the PostgreSQL password is random per start and used by nobody.
- **The host is never scanned.** Docker gives the host an address on the bridge
  even on an internal network (`172.30.250.1`). That address is the VM itself, so
  every scan excludes it.

**Repeatability.**

- **Images are pinned by digest** in `targets.env`.
- **The SSH target is the one exception.** It installs `openssh-server` from the
  Ubuntu archive when its image is built, so its OpenSSH build can change at a
  rebuild. `targets.sh` keeps the built image (`ccure-validation-ssh:ubuntu-24.04`)
  between runs, and `down --images` removes it.
- **The before and after runs of one check use the same running targets**, so
  the comparison is never between two builds.

`tests/repo/test_live_scan_tooling.py` holds the isolation properties in code:

- an internal, private subnet that overlaps none of the installation's networks;
- the host address never a target;
- digests on every image;
- no published port and no host network in any container command.

## Running a check

From the repository root, with the targets up:

```bash
scripts/validation/targets.sh up                     # idempotent; prints a probe of each target
scripts/validation/live_scan.sh before <parent-commit> <out-dir>
scripts/validation/live_scan.sh after  <change-commit> <out-dir>
python3 scripts/validation/compare_live_scans.py <out-dir>/before.json <out-dir>/after.json
scripts/validation/targets.sh down                    # when finished
```

**What `live_scan.sh` sets up.**

- **The code** is `git archive` of the commit, so a result belongs to a hash.
- **The image** is the backend image (`CCURE_TEST_IMAGE`, default
  `ccure-audit-pro-backend:latest`), so its nmap, Nuclei templates and Scapy
  apply.
- **How it runs:** like the scanner worker, as root with `NET_RAW` and
  `NET_ADMIN` and the worker's scanner settings. Celery runs eagerly, so a whole
  scan runs in one process.
- **What it runs against:** a throwaway PostgreSQL 18 and Redis 7, on a second
  internal network made for that run. Their schema and catalogue are
  bootstrapped as CI does.
- **Network order.** The scanner joins the targets' network first. Scapy's raw
  ARP, ICMP and SYN leave by the default interface, as they do on the worker's
  host network. With the database network first, the BALANCED and AGGRESSIVE
  discovery profiles find no host at all (measured during B2).
- **Clean-up.** The run removes its containers, its network and its code copy,
  whatever the outcome.

**The harness** (`live_scan_harness.py`) then runs two scans, created and
dispatched exactly as `POST /scan/host-discovery` creates and dispatches them:

1. **full**: a vulnerability audit of the four targets and the two empty
   addresses;
2. **cancel**: basic discovery of the whole /24 (253 addresses, the host
   excluded). It is stopped the way `POST /scans/{id}/stop` stops a scan, as soon
   as the first discovery frame is published.

It records every frame on `scan_progress:*`. It then reads back the scan row, its
phases, and the assets, services and findings, and writes `<out-dir>/<label>.json`
and `<label>.log`.

**The comparison** checks each run's scan row, phases, assets, services,
findings, task result and every progress frame in order. It excludes only
wall-clock values. It exits 1 and names each difference.

## What to expect

A vulnerability audit of these targets, measured on 19 Oct 2026 with
`ccure-audit-pro-backend:3212d6b…` (`3a0dde6d4580`). It is the same on `98f33d1`,
`6986194`, `22aa824` and `ad4aab7`, apart from the variation described below.

- **Hosts:** 3 phases complete. 4 hosts are active (`.10`–`.13`) and 2 inactive.
- **Services:** OpenSSH 9.6p1 on 22, nginx on 80, Redis 7.4 on 6379, PostgreSQL
  on 5432.
- **7 findings:**
  - Redis without authentication (critical);
  - Nuclei, the exposed `.env` (high) and `.git/config` (medium);
  - the sensitive-path check (high);
  - HTTP in cleartext (medium);
  - missing security headers and a server version disclosure (low).
- **13 progress frames** across the three phases.

The stopped sweep ends `cancelled` with no phase recorded. Discovery stops at the
batch boundary after the stop.

These figures depend on the image's tools and templates. A comparison is between
two commits run on the same image and the same targets, not against this list.

## Known variation between runs

Two differences can appear between runs of the same code. B3 measured both
(refactoring log §6). Before reading either as a regression, repeat the runs in
alternation (before, after, before, after).

- **An extra Nuclei finding on the Redis target**, most often
  `CCURE-CHK-NUCLEI-CVE-2025-46817`.
  - **Why it happens.** The Nuclei probe hands a non-HTTP port to Nuclei as a
    bare `host:port`, and Nuclei runs its HTTP templates against it too. Each
    one fails, and after its per-host error cutoff Nuclei drops the host.
    Whether a Redis template has run by then depends on scheduling.
  - **Measured.** Run on its own, as the probe runs it, Nuclei matched nothing
    on Redis in five runs. With only the non-HTTP template types it matched 10
    templates in 27 s.
  - **Status.** This is a coverage defect in the probe, recorded in the log's
    §7. Until it is fixed, a run may report 7 or 8 findings.
- **The stopped sweep's frames.** The ARP technique marks each answering host
  active only after looking up its MAC vendor. For the targets' random MACs, that
  lookup queries the database. The first frame, sampled at a 150 ms tick, holds
  however many hosts those lookups have let through: one in some runs, all four
  in others. The stop is issued on that frame, so three things follow it:

  - the frame count, 3 or 4;
  - the stop's `after_discovered`;
  - the settle time after the stop, about 0.6 s apart.

  The outcome does not change: `cancelled`, with no phase recorded.

**Compare only against the same running targets.** Docker gives each target a
random MAC address whenever it is created, so `targets.sh down` then `up` changes
every asset's MAC.

## Limits

- **No vulnerability feed.** The vulnerability-intelligence database is the
  throwaway one, so a run matches no CVE. A change to CVE matching needs the feed
  as well.
- **Not covered:** credentialed audits, web application scans and compliance
  scans.
- **The stop is one sample.** Where it lands relative to a batch boundary
  depends on timing. The orchestrator-level tests
  (`tests/scans/test_engine_progress_and_cancellation.py`) pin the before,
  during and between-batch cases deterministically.
- **The scanner is not the deployed worker.** It is the image the worker runs,
  with the commit's code. It shows what the code does. It does not show what a
  release does.
