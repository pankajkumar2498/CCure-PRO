# Live scan validation

A change on a scan path is checked by scanning real hosts with the code before
the change and the code after it, and comparing what the scans stored. Unit
tests and the full suite cannot do this, because they replace the network: a
probe that stops sending, a frame that stops being published, or a finding that
stops being written still passes them. The modular-refactoring plan requires a
live check for B2, B3, C2, C3 and C6
([analysis §11](../architecture/MODULE_INDEPENDENCE_ANALYSIS.md)). Its first use
is recorded in [the refactoring log](../architecture/MODULAR_REFACTORING_LOG.md)
§6, under B2. Since T0 (22 Oct 2026) it also runs credentialed scans
concurrently with the unauthenticated one, with throwaway credentials, as §11
asks.

The tooling is in `scripts/validation/`. It needs Docker and the backend image,
and nothing else.

## The targets

`scripts/validation/targets.sh up|status|down` manages disposable containers on
an internal Docker network. `scripts/validation/targets.env` defines them in one
place:

| Address         | MAC                 | Container                | What it exercises                                                                                                                  |
| --------------- | ------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `172.30.250.10` | `02:42:ac:1e:fa:0a` | `ccure-validation-ssh`   | Ubuntu 24.04 running OpenSSH: banner, version, the SSH probe; the credentialed host audit, through the audit account `ccure-audit` |
| `172.30.250.11` | `02:42:ac:1e:fa:0b` | `ccure-validation-web`   | nginx serving a dummy `.env` and `.git/config`: Nuclei and the HTTP checks                                                         |
| `172.30.250.12` | `02:42:ac:1e:fa:0c` | `ccure-validation-redis` | Redis with no authentication: a critical network check                                                                             |
| `172.30.250.13` | `02:42:ac:1e:fa:0d` | `ccure-validation-pg`    | PostgreSQL: service detection and the default-credential probe; the database audit, through the role `ccure_audit`                 |
| `.14`, `.15`    | none                | none                     | Empty addresses, which must stay inactive                                                                                          |

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
- **The SSH target is the one exception.** It installs `openssh-server`, `sudo`
  and `iproute2` from the Ubuntu archive when its image is built, so its OpenSSH
  build can change at a rebuild. `targets.sh` keeps the built image
  (`ccure-validation-ssh:ubuntu-24.04-audit`) between runs, and `down --images`
  removes it. The tag changes whenever its Dockerfile does, so `up` builds the
  new image instead of keeping a container from the old one. The image before
  T0 (`ccure-validation-ssh:ubuntu-24.04`, no audit account) is no longer used.
- **No account on a target can log in outside a run.** The SSH target's root has
  no password and no key; its audit account is created locked (its password
  field is `!`). The PostgreSQL audit role is created by the first run and left
  `NOLOGIN` with no password by every run. A run gives both a throwaway password
  and takes it back (below). `targets.sh status` shows their state:
  `L` and `nologin` (or `absent`) outside a run.
- **Each target's MAC is fixed** in `targets.env`. The form is Docker's classic
  `02:42:<IPv4 in hex>`. It is locally administered, so no vendor's, and it is
  not in the bundled OUI registry, so discovery looks it up as it did Docker's
  random MACs. Before 20 Oct 2026 Docker chose a random MAC whenever a target was
  created, and every asset's MAC changed with each `down` and `up`.
- **`up` replaces a target that does not hold its defined address, MAC and
  image**, for example one created by hand, before the MACs were fixed, or from
  the SSH image before the audit account. A target that holds all three is left
  running.
- **A re-created target is the same target to an unauthenticated scan.** A `down`
  and `up` between two runs changes nothing such a scan stores. One thing changes
  what a credentialed scan stores: Docker's embedded DNS listens inside every
  container on `127.0.0.11`, on a TCP port chosen when the container starts, and
  the host audit records it from the socket table. So run a before and an after
  against the same targets, with no `down` between them (see "Known variation").
  `down --images` changes more: the next `up` rebuilds the SSH image.

`tests/repo/test_live_scan_tooling.py` holds the isolation properties in code:

- an internal, private subnet that overlaps none of the installation's networks;
- the host address never a target;
- digests on every image;
- no published port and no host network in any container command;
- a fixed, locally administered MAC per target, outside the OUI registry;
- `up` run against a stand-in for `docker`: it starts each target at its address,
  MAC and image, leaves a correct one alone and replaces a wrong one, including
  an SSH target from the image before the audit account;
- the audit account created locked, with password-gated `sudo` and no key or
  password in the image;
- where a throwaway credential may go (below), and that the leak check finds one
  planted in a target's log or the throwaway database.

## Running a check

From the repository root, with the targets up:

```bash
scripts/validation/targets.sh up                     # idempotent; prints a probe of each target
scripts/validation/live_scan.sh before <parent-commit> <out-dir>
scripts/validation/live_scan.sh after  <change-commit> <out-dir>
python3 scripts/validation/compare_live_scans.py <out-dir>/before.json <out-dir>/after.json
scripts/validation/targets.sh down                    # when finished
```

`live_scan.sh` exits:

- **0** when the run completed;
- **1** when it could not run (the harness failed or the bootstrap did);
- **2** on bad arguments;
- **3** when a throwaway credential was found anywhere it was searched for;
- **4** when the credentials' revocation could not be confirmed (a run that had
  already failed keeps its own code; the revocation's state is printed either
  way);
- **5** when a credentialed scan did not authenticate.

Only exit 0 produces a result worth comparing.

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
- **Scapy's interface is set, not inferred.** Discovery's raw ARP leaves by
  Scapy's default interface.
  - **Production.** On the worker's host network that is the interface of the
    default route, the one facing the targets.
  - **The scanner container.** It has no default route, so Scapy takes the
    interface whose multicast route it lists first, which is whichever network
    Docker attached first. Docker does not guarantee that order. With the
    database network first, ARP gets no reply and discovery finds no host (B2,
    B5).
  - **What the harness does.** Before any scan it sets Scapy's interface to the
    one holding the scanner's address on the targets' network
    (`CCURE_LIVE_SCANNER_ADDRESS`, `.5`), and refuses to run if no interface
    holds it.
  - **What is recorded.** The result's `interface` says which interface was
    used (`pinned`) and which Scapy would have used (`scapy_default`).
- **Throwaway credentials** for the credentialed scans, made for this run only
  (next section).
- **Clean-up.** The run revokes the credentials and removes its containers, its
  network and its code copy, whatever the outcome.

**The throwaway credentials.**

- **Made per run.** `live_scan.sh` generates two random passwords (16 bytes,
  hex) into shell variables. They are never exported, never written to a file
  and only ever given to `printf`, a shell builtin, so they appear in no
  process's arguments.
- **Granted over stdin**, after the throwaway database is bootstrapped:
  - `chpasswd` on the SSH target sets the audit account's password;
  - `psql` on the PostgreSQL target creates the audit role if it is missing,
    grants it `pg_read_all_settings` and `pg_read_all_stats`, and sets its
    password. The session first sets `log_statement` to `none` and
    `log_min_error_statement` to `panic`, so not even a failing statement can
    carry the password into the server's log.
- **Handed to the harness** as one JSON line on its stdin (`docker start -a -i`).
  The harness stores both with `core.credential_vault.create`, the application's
  own path: validated, encrypted with the run's random key, audited. It then
  keeps only the ids. The scans resolve the credentials by id, as production
  does, so no password is in any task's arguments.
- **Searched for** after the scans. Neither password may appear in:

  - the run's log or result;
  - the logs, since the run began, of the four targets, the scanner and the
    throwaway database and broker;
  - the scanner's container configuration;
  - a full dump of the throwaway database (the stored credentials are
    ciphertext).

  The check reports where it found one, never what. A find fails the run with
  exit 3.

- **Revoked on exit**, however the run ends. The account's password field is set
  back to `!` and its processes are ended; the role is set `NOLOGIN` with no
  password and its sessions are ended. The run then reads both back from the
  targets and prints the state. Revocation it cannot confirm fails the run with
  exit 4.

**The harness** (`live_scan_harness.py`) then runs four scans at once, one
thread each, each created and dispatched exactly as its route creates and
dispatches it:

1. **full**: an unauthenticated vulnerability audit of the four targets and the
   two empty addresses (`POST /scan/host-discovery`);
2. **credentialed**: a vulnerability audit of the SSH target with the stored SSH
   credential in `options.credentials`, so the pipeline's own credentialed
   enrichment (Phase 3.5) authenticates to it;
3. **host**: the standalone credentialed audit of the SSH target
   (`POST /scan/credentialed` with `credential_id`);
4. **database**: the same route with the stored database credential, against
   the PostgreSQL target: the database audit.

Then, alone:

5. **cancel**: basic discovery of the whole /24 (253 addresses, the host
   excluded). It is stopped the way `POST /scans/{id}/stop` stops a scan, as soon
   as the first discovery frame is published.

It records every frame on `scan_progress:*`. For each scan it reads back the scan
row and its phases. For each credentialed scan it reads its configuration
verdicts the way the export reads them (`export_payload`, the compliance
dataset), keeping only the columns that describe the host and the check. After
the four it reads the organisation's assets, services and findings once, as
`concurrent`: four scans of overlapping hosts share those rows, and which scan
wrote a row last is timing. It writes `<out-dir>/<label>.json` and
`<label>.log`.

**A credentialed scan that did not authenticate fails the run** (exit 5, after
the result is written). A run that never logged in proves nothing about
credentialed code. The result's `authenticated` record says which check failed:

- the SSH host recorded as credentialed `success`;
- each credentialed scan holding configuration verdicts.

**The comparison** checks each run's scan row, phases, task result and every
progress frame in order, each credentialed scan's verdicts, the concurrent
state, the cancel run's own state and the `authenticated` record. It excludes
wall-clock values: the frames' arrival time and the `timestamp` the credentialed
task stamps on its frames, elapsed times and durations. It exits 1 and names each
difference.

**What it tolerates: two things B3 measured as timing alone.** A difference in
either is printed as `tolerated:` and does not fail the comparison:

- **Discovery's sampled frames.** While a batch runs, discovery publishes the
  hosts found so far every 150 ms, so the number of these frames, and how many
  hosts the first one holds, varies.
  - A phase-1 `running` frame is treated as a sample when the next phase-1
    `running` frame covers it completely: the same or more hosts, the same or
    higher counters, the same sweep size and fields. A sample may be present in
    one run and absent in the other.
  - The cancel run's stop is issued on the first sample, so the stop's
    `after_discovered` is a sample too.
- **Where the stop route's frame lands.** It is published from another thread, so
  its position among the engine's frames varies. Whether it was sent, and how
  many times, is still compared.

**Everything else is compared exactly**, including:

- the last sample of every run of samples, and a sample the next one does not
  cover (a host reported and then gone, or another sweep size);
- every frame of the port scan and the audit, whose counters move once per host;
- every terminal frame;
- every stored row, findings included. The Nuclei variation below therefore
  still fails a comparison.

`--strict` compares everything exactly, as the comparison did before.

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

The credentialed scans, measured on 22 Oct 2026 on `3541224` with the same image:

- **credentialed** (Phase 3.5): 3 phases complete, 86 configuration verdicts for
  the SSH host;
- **host**: complete, the same 86 verdicts, 16 progress frames;
- **database**: complete, 49 verdicts against PostgreSQL 18;
- **after the four:** 4 assets, the SSH host `Ubuntu 24.04.5 LTS` and
  credentialed `success`; 5 services; 13 findings.

The fifth service is the host audit's own: Docker's embedded DNS listener on
`127.0.0.11` (below). Port 22's service name reads `0.0.0.0:*` after a
credentialed audit. That is a product defect, recorded in the refactoring log's
§7: the collector takes the last column of `ss -tlnp` as the process, and when the
scanning account cannot see process names that column is the peer address.

No credentialed scan matches a CVE here: package matching needs the
vulnerability feed, which the throwaway database does not have, and it reports
that as not assessed.

These figures depend on the image's tools and templates. A comparison is between
two commits run on the same image and the same targets, not against this list.

## Known variation between runs

Three differences can appear between runs of the same code. B3 measured the
first two and T0 the third (refactoring log §6). The comparison tolerates the
second and reports the other two. Before reading a reported one as a regression,
repeat the runs in alternation (before, after, before, after).

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
  active only after looking up its MAC vendor. For the targets' MACs, which are
  in no registry, that lookup queries the database. The first frame, sampled at a 150 ms tick, holds
  however many hosts those lookups have let through: one in some runs, all four
  in others. The stop is issued on that frame, so three things follow it:

  - the frame count, 3 or 4;
  - the stop's `after_discovered`;
  - the settle time after the stop, about 0.6 s apart.

  The outcome does not change: `cancelled`, with no phase recorded. The
  comparison tolerates the first two and prints them. The settle time is
  wall-clock and is not compared at all.

- **Which template the web target's `.env` finding is stored under.**
  - **Why it happens.** Several Nuclei templates match the exposed `.env`
    (`codeigniter-env`, `laravel-env`, `generic-env`). The probe merges them into
    one finding and keeps the most severe template. On a tie it keeps the first in
    Nuclei's output order, and that order is scheduling.
  - **Measured.** Every run from B3 to B10, and T0's first run, stored
    `CCURE-CHK-NUCLEI-CODEIGNITER-ENV`. The next two T0 runs, with four scans
    loading the host at once, stored `CCURE-CHK-NUCLEI-LARAVEL-ENV`. The evidence
    of the one run read for it names all three templates as matching.
  - **Status.** A defect in the probe's tie-break, recorded in the log's §7.

**The SSH target's DNS listener port.** Docker's embedded DNS listens inside every
container on `127.0.0.11`, on a TCP port chosen when the container starts. The host
audit reads the socket table and records it as a `host_only` service. The port
stays for the container's life, so two runs against the same targets agree. A
`down` and `up` between a before and an after changes it, and the comparison
reports the difference. Run the pair against the same targets.

**A run used to fail outright now and then.** B5 found it (refactoring log §6).

- **The symptom.** The full audit ended `unreachable` with no host found.
- **The cause.** Scapy sent ARP from the database network whenever Docker
  attached that network first.
- **Fixed.** The harness now sets Scapy's interface itself (above).
- **If a run ends `unreachable` again,** read its `interface` record before
  anything else.

## Limits

- **No vulnerability feed.** The vulnerability-intelligence database is the
  throwaway one, so a run matches no CVE, unauthenticated or credentialed. A
  change to CVE matching needs the feed as well.
- **Credentialed coverage is Linux over SSH and PostgreSQL.** There is no Windows
  target, so WinRM and SMB are not exercised, and no MySQL or SQL Server target.
- **Not covered:** web application scans and compliance scans.
- **The concurrency is threads in one process.** The worker runs scans in
  separate processes. The four scans overlap in time and in the rows they write,
  which is what the concurrent check is for; process-level isolation is not
  tested here.
- **The stop is one sample.** Where it lands relative to a batch boundary
  depends on timing. The orchestrator-level tests
  (`tests/scans/test_engine_progress_and_cancellation.py`) pin the before,
  during and between-batch cases deterministically.
- **The scanner is not the deployed worker.** It is the image the worker runs,
  with the commit's code. It shows what the code does. It does not show what a
  release does.
