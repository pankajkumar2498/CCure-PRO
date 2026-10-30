---
paths:
  - "Backend/scans/**"
  - "Backend/orchestrator/**"
  - "Backend/core/scan_control.py"
  - "Backend/core/tasks.py"
  - "Backend/core/task_names.py"
  - "Backend/core/phase_handoff.py"
  - "Backend/core/scheduling/**"
  - "Backend/core/discovery/**"
  - "Backend/core/nmap/**"
  - "Backend/engines/port/**"
  - "Backend/config.py"
  - "Backend/routers/phase_scans.py"
  - "Backend/routers/traditional_scans.py"
  - "Backend/routers/scan_schedules.py"
  - "Backend/routers/scan_progress.py"
  - "Backend/tests/scans/**"
---

# Scan terminal state, scan pipeline and scheduling

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 1982–2100, 2449–2512) and is maintained here. Frozen original: `docs/archive/engineering-record/scan-lifecycle.md`. The repository-wide rules in `CLAUDE.md` still apply.

## A scan must always reach a terminal state

On 4 Sep 2026 two Basic Network Scans and a Vulnerability Audit against
`10.180.5.83` sat in `running` indefinitely, showing "LIVE SCANNING" stuck at
10%. The host was up the whole time — 33 ms ICMP, ARP-resolved — and the
discovery engine finds it in **2.2 seconds**. Nothing was ever wrong with the
scanner.

The worker was started at 00:27, before commit `9c40fe3` added
`foreign_keys="AssetVulnerability.scan_id"` to `Scan.vulnerabilities`, so it
held a mapper that could not resolve its join condition. Four things then
compounded, and each is worth keeping in mind separately:

- **A failure path that shares a dependency with the thing it is recovering
  from is not a failure path.** The task raised `InvalidRequestError` on its
  first query; the `except` handler called `mark_scan_failed`, which raised the
  identical error on _its_ first query. Nothing was written.
  `core.scan_control.force_terminal_status` is the answer: plain SQL against
  `scans`, no mapper, no relationship, no model attribute. It is deliberately
  the only helper there written that way. `_settle_failure`
  (`scans/tasks/common.py`) tries
  the ORM first (an audit entry and a notification are worth having) and falls
  back to it. **Never call `mark_scan_failed` directly from an `except` block.**

- **`task_time_limit` was inert on Windows and is not inert on the VM.** This
  is the one item in this section the Linux move invalidated, and it was a
  latent kill switch for nine months. Celery's hard limit is delivered by
  signalling a billiard _process_, so it did nothing under the Windows
  `--pool=threads` host worker — which is why the comment beside it and the
  `test_scan_stall_recovery` docstring both called it inert. The VM worker
  passes no `--pool`, so it runs **prefork, where the limit fires**. Measured
  22 Sep 2026 on this VM: a task was SIGKILLed at exactly 360s with
  `TimeLimitExceeded(360)`.

  The global was `NMAP_TIMEOUT + 60`, and that formula is a **unit error**.
  `NMAP_TIMEOUT` is the lease on a _single_ nmap invocation
  (`core/nmap/wrapper.py` passes it as `lease_seconds`); a scan task spawns
  many, and can wait up to `NMAP_PROCESS_WAIT_TIMEOUT` (900s) just to acquire
  one slot. So the budget for a whole task sat below the queue wait for one of
  its own subprocesses. Against this deployment's own history it would have
  killed **11 of 48** completed scans, the longest 11,714s (3h15m); the
  average completed scan was already 426s, and the longest credentialed scan
  358s — two seconds under the cliff.

  **The hard limit cannot settle a scan, and that is why the soft limit is the
  load-bearing half.** A hard kill delivers `SystemExit`, which is a
  `BaseException` and **not** caught by the `except Exception` handler every
  scan task uses to call `_settle_failure` — so a scan killed by it is never
  marked failed and sits `running` until the reaper. `SoftTimeLimitExceeded`
  _is_ an `Exception`, so the soft limit routes through the task's own error
  handling and records an honest failure. Each scan task therefore declares
  both, from `SCAN_TIME_LIMIT_*` in `config.py`, with the hard limit
  `SCAN_TIME_LIMIT_HARD_MARGIN` (300s) behind the soft one as a backstop for a
  task wedged in uninterruptible code — never as the working deadline.

  **There is deliberately no global `task_time_limit` any more.** One value
  covering every task has to be sized for the longest, at which point it bounds
  nothing that matters, and the failure it produces is the silent kind above.
  Phases chain as _separate_ tasks (`run_host_discovery` → `run_asset_discovery`
  → `run_vulnerability_audit`, dispatched by `scans.pipeline.hand_over`), so
  each budget covers one phase,
  not the pipeline — the 11,714s scan was wall-clock across three tasks.
  **A new scan task must declare its own limits**; nothing inherits one now.

  `ccure.tasks.reap_stalled_scans` remains the deployment's real scan timeout,
  on beat every two minutes: `SCAN_STALL_TIMEOUT_MINUTES` (90) for a running
  scan and `SCAN_QUEUE_TIMEOUT_MINUTES` (15) for one no worker ever collected —
  two deadlines because "the scan hung" and "no scanner is running" send the
  operator to different places. It only ever moves a scan _out of_ a
  non-terminal state; a real outcome always wins. It is still the only
  mechanism that can settle a scan whose worker died or was restarted, which
  no Celery limit of any kind can see.

- **`run_asset_discovery_task` did not settle the scan at all.** Its `except`
  handler just returned. That is the same defect whose fix is documented in a
  comment inside the _Vulnerability Audit_ handler ("returning the failure
  without marking it left the scan running for ever") — phase 2 was missed when
  phase 3 was fixed.

- **The mission view could only end via the WebSocket.** A task that died
  without publishing a terminal frame left the screen live until a 600 s
  client-side timeout, which then mapped `timeout` and `unknown` to
  **`complete`** — reporting a scan as finished when nothing had been heard from
  it for ten minutes. `startHostPolling` now reads `scan.status` on every tick,
  so the UI is correct within 2.5 s whatever happened to the socket, and the
  scan record is authoritative over the socket's word.

`POST /scans/{id}/stop` now publishes a `cancelled` frame, and the progress
WebSocket sends the _scan-level_ status on connect (previously only the last
phase's, and only when a phase row existed — so a browser reconnecting to a
finished scan was told it was running).

Two operational notes: the start script's duplicate-worker guard deliberately
does not count the child `python.exe` a single worker spawns under the venv's
base interpreter, so two PIDs is normal. And **restart the host worker after
changing anything under `core/`, `scans/` or `orchestrator/`** — this whole
episode was a worker running code from before a commit that fixed it.

## Scan pipeline

`pipeline_mode` selects the phases: `basic` = 1, `asset` = 1+2,
`vulnerability_audit` = 1+2+3. The UI posts to `/scan/host-discovery` and the
backend chains the later phases through `scans/pipeline.py` (G5).

- **Phase 1** — `core/discovery/engine.py`, Scapy only (ARP/ICMP/TCP/UDP). No
  Nmap, no port scanning.
- **Phase 2** — `core/nmap/wrapper.py` via `engines/port/port_engine.py`. Normal
  intensity scans ports 1-1024 plus a curated high-port list from
  `PORT_DB` (~1,127 ports), with OT ports excluded by default.
  **python-nmap keeps only a service's last `<cpe>`**, and nmap lists the
  application before the OS it inferred, so Ubuntu's OpenSSH arrived as
  `cpe:/o:linux:linux_kernel` alone and got no OpenSSH CVE search.
  `_service_cpes_by_port` reads every CPE back from python-nmap's raw XML
  (`0178fdf`); never read a port's identity from python-nmap's `cpe` field.
- **Enrichment** — `core/discovery/enrichment.py`. When adding a probe, pass the
  real transport to `_register_open_port(..., protocol="udp")`. SNMP, mDNS and
  NetBIOS-NS are UDP; recording them as TCP claims an open TCP port that is
  usually filtered, and that claim reaches the asset registry and the reports.


## Scan scheduling (`core/scheduling/`)

Recurring network and credentialed scans. Phase 1 of the gap-closure
programme; tracker in [`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

- **Scheduling adds no scan engine.** `core/scheduling/dispatcher.py` calls
  `run_host_discovery_task.delay(...)` and `run_credentialed_scan_task.delay(...)`
  — the same tasks the manual routes call. A scheduled run is an ordinary
  `Scan` row and shows up in Scan History, reports and the dashboard like any
  other, marked `options.origin = "schedule"`. If you add a scan kind, add a
  dispatch branch; do not add a pipeline.

- **`scan_schedules` is deliberately not `compliance_scan_schedules`.** That
  table's `framework_id` and `policy_id` are NOT NULL FKs into the compliance
  catalogue and a network scan has no framework. Six of its behaviours are
  defects this table does not repeat, each documented at the point of the
  decision: no time zones, `monthly` as a 30-day `timedelta`, a
  `cron_expression` nothing reads, no duplicate-execution guard, no execution
  history, and a bare `except` reporting `success: False`.

- **A schedule stores a credential _reference_, never a secret.**
  `run_credentialed_scan_task` already resolved `credential_id` worker-side, so
  nothing had to change to make this true. `POST /scan/credentialed` still
  accepts a plaintext password and puts it in the task arguments; a schedule
  doing that would put it in the database, in every backup, and in the broker
  payload on every run.

- **Scope and quota are re-checked at every dispatch, never inherited.** A
  schedule written in March and firing in November is a stored intent, not a
  standing authorisation — narrowing an org's `scan_scope_cidrs` must take
  effect on the next run.

- **`next_run_at IS NULL` means dormant, not due.** The compliance scheduler
  treats NULL as due (`or_(next_run_at.is_(None), ...)`), so any row written
  without a computed next run fires on the very next tick regardless of the
  time the user chose. Here NULL is a one-time schedule that has fired, or a
  custom recurrence nothing can place yet.

- **Wall-clock time is preserved across DST, and the awkward hours have
  defined answers.** `core/scheduling/recurrence.py` computes in the schedule's
  IANA zone: a skipped hour (spring forward) is pushed to the first instant
  that exists rather than skipping the day; a repeated hour (autumn back) fires
  once, at the earlier instant; day 31 clamps to the month's last day. Zones
  are IANA names only — a fixed offset cannot express daylight saving and is
  refused.

- **Next run is computed from _now_, not from the previous `next_run_at`.** A
  worker down for a week comes back and runs once, not seven times.

- **Duplicate dispatch is prevented by `pg_try_advisory_xact_lock`**, not by
  assuming one beat process. Transaction-scoped, never session-scoped —
  `pg_advisory_lock` releases when the _connection_ closes and SQLAlchemy pools
  connections, so a session-scoped lock leaks onto the next unrelated request.

- **`custom` (cron) is stored but not yet placed.** `compute_next_run` returns
  None for it, so such a schedule stays dormant rather than firing at an
  arbitrary time. Parsing cron needs a dependency decision that has not been
  taken.

- **Body models are prefixed `ScanSchedule` and must stay that way.** FastAPI
  keys OpenAPI component schemas by class name; a `ScheduleCreate` here
  silently replaced `routers/compliance.py`'s in the generated contract. The CI
  contract gate caught it — a regeneration showing _deletions_ is the signal.
