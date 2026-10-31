---
paths:
  - "Backend/engines/credentialed/database_executor.py"
  - "Backend/core/config_audit/collectors/database.py"
  - "Backend/core/config_audit/builtin/database_*.py"
  - "Backend/scripts/measure_database_coverage.py"
---

# Database assessment

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 4210–4390) and is maintained here. Frozen original: `docs/archive/engineering-record/database-assessment.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Database assessment (`engines/credentialed/database_executor.py`)

Authenticated configuration and privilege assessment of database instances.
Phase 7 of the gap-closure programme, closing GAP-10; tracker in
[`docs/gap_closure/GAP_TRACKER.md`](docs/gap_closure/GAP_TRACKER.md).

**No new engine, and no new finding model.** A database check is an ordinary
Phase 3 `ConfigCheck` with `check_type = database_query` and
`target_platform = database`, run by the same `ConfigAuditEngine`, reaching the
same evidence → finding → risk → remediation → report path. 49 checks across
PostgreSQL, MySQL/MariaDB and Microsoft SQL Server.

- **The whole persistence cost was one CHECK constraint.** `credential_type`
  has admitted `database` since Phase 2 and `compliance_rules` has admitted
  `database_query` and `target_platform = 'database'` since Phase 3's
  `b4c5d6e7f8a9`. Migration `f8a9b0c1d2e3` adds five `transport` values and
  nothing else. That is what the reservations were for — keep making them.

- **Engine targeting reuses `os_match`; do not add a second mechanism.** The
  instance's product string becomes `os_name` and its version
  `os_version_id`, so the Phase 4 targeting written for "Ubuntu 22.04 versus
  RHEL 9" places "PostgreSQL 16 versus MySQL 8" unchanged.

- **`product_name` is not the version banner, and that distinction was load
  bearing.** `SELECT version()` answers `PostgreSQL 16.15 on x86_64…` on
  PostgreSQL but a bare `8.0.46` on MySQL. Targeting on the raw banner made
  **all fifteen MySQL rules NOT_APPLICABLE** — a complete rule set that
  silently never ran, and which looked perfect on PostgreSQL alone. MariaDB is
  labelled separately even though PyMySQL drives it and it normalises to the
  `mysql` engine: its version series is its own, and a "MySQL 8.0 or later"
  rule would read MariaDB 10.11 as ancient.

- **`sslrootcert` is passed explicitly on every PostgreSQL connection, and
  must stay that way.** `Backend/.env` sets `PGSSLROOTCERT` to this
  deployment's private CA for the _application_ database; loading config puts
  it in the environment, and libpq applies it to any connection that does not
  set it. Every PostgreSQL **target** was therefore verified against our own CA
  and failed with "certificate verify failed", which reads as a fault on the
  target. Note the asymmetry that hid it: passing `sslmode` explicitly _does_
  override `PGSSLMODE`, so the mode was right and only the trust anchor was
  wrong — and under `prefer` libpq still verifies once a root certificate is
  configured.

- **TLS is preferred, never required, and both halves matter.** Requiring it
  makes the scanner unable to assess a correctly hardened MySQL
  (`require_secure_transport = ON`); refusing to fall back makes it unable to
  assess the instance whose _missing_ TLS is the finding most worth reporting.
  PyMySQL has no `prefer` mode, so it is implemented by hand — TLS first, then
  plaintext, and **never a retry after an authentication failure**, which would
  only produce a second identical rejection and a second entry in the server's
  failed-login log.

- **Read-only is enforced in three layers, and every shipped rule is tested
  against the guard.** `assert_read_only` admits one statement beginning
  SELECT/SHOW/WITH/VALUES with comments and literals stripped first; rule
  values are bound parameters, never interpolated; and the session itself is
  opened read-only. A refused statement is UNAVAILABLE → **ERROR**, never a
  verdict — a defect in a rule must not manufacture a finding about a
  customer's database. The guard is also why SQL Server login auditing is
  unassessed: the conventional read is `EXEC xp_instance_regread`, and the
  guard is worth more than the check.

- **An empty result set is the most dangerous value in this package.** A
  hardened instance answers "which accounts have an empty password" with no
  rows; so does a refused query, and so does a catalogue view this engine
  version does not have. Only `QueryResult.ok` separates them, and there is
  deliberately no method that returns a bare list of rows. Reading the rows
  instead reports a clean bill of health for an instance nobody was allowed to
  inspect.

- **Four error types, and they must stay four.** A refused password, an
  authenticated account without the privilege, nothing listening, and a driver
  that is not installed need four different actions. Two collapses were found
  and fixed: an ordinary SQL error on a _healthy_ session was reported as an
  unreachable database (the classifier's fallback is now context-dependent —
  only a positive connectivity match becomes a transport error), and
  PostgreSQL's `no pg_hba.conf entry` was reported as a connection failure when
  the instance had answered and declined.

- **Findings mint `CCURE-CFG-…`, including the privilege and grant rules.**
  `privilege_check` was considered and rejected: it files under the report
  family "Local Privilege", and an over-granted role on a remote database
  server is not a local privilege-escalation condition on the scanning host.

- **Dispatch adds no route and no task.** `run_credentialed_scan_task` branches
  on the credential's type and calls `audit_database_target`. So
  `POST /scan/credentialed` and `core/scheduling/dispatcher.py` are unchanged,
  and a recurring database audit works today through the existing
  `credentialed` schedule kind. `SCAN_KIND_DATABASE` stays reserved.

- **A database target is excluded from the asset-registry sync, deliberately.**
  Both sync helpers write an OS, a package inventory and a MAC-based identity
  onto an `Asset` row. Letting a database audit through would overwrite the
  record of the machine hosting it with an audit that never looked at the
  machine.

- **`coverage.scope` says what was not assessed.** A database audit examines
  the instance's configuration and says nothing about the operating system
  underneath it. A report that does not say so reads as a complete audit of the
  machine.

### Content, and the false positives real targets caught

**No CIS Benchmark content here either** — same licensing position as Phase 4.
These are CCURE-authored rules written from vendor documentation, and every
statement was run against a live instance before its rule was written. Five
conditions were dropped or rescoped because they are _stock defaults_ and a
check that fires on every host is worse than one that misses:

| Would have reported                            | Reality                                                  |
| ---------------------------------------------- | -------------------------------------------------------- |
| PUBLIC holds CONNECT on `postgres`/`template0` | The default on every PostgreSQL installation             |
| `trust` on `local` and `127.0.0.1`             | The postgres image default; how `docker exec psql` works |
| `guest` holds CONNECT in SQL Server            | Mandatory in `master`; cannot be revoked there           |
| `BUILTIN\*` and `NT AUTHORITY\*` are sysadmin  | Provisioned by SQL Server itself                         |
| `VIEW ANY DATABASE` granted to `public`        | A default grant on every instance                        |

Two more worth knowing:

- **`information_schema.user_privileges` returns 132 `is_grantable` rows on a
  stock MySQL**, all root's. That measurement is why `db.priv.grant_option` is
  excluded from the coverage denominator rather than implemented badly.
- **`secure_file_priv` inverted its own verdict.** `not_empty` treats SQL NULL
  as empty, and NULL is the _most_ hardened state — file access disabled
  outright. A locked-down instance and a wide-open one (`''`) failed
  identically until NULL was folded to a token first.

Three PostgreSQL rules also read `pg_hba_file_rules` with overlapping
predicates, so one permissive line produced three findings and made the
remediation look three times larger than it was.

**Version-currency boundaries have a shelf life and say so.** PostgreSQL 14,
MySQL 8.0 and SQL Server 2017 were the oldest supported releases as at
29 August 2026; each rule states that date and links the vendor's lifecycle
page.

### Test targets

_History: the commands below were run on the Windows host. None of these containers exists on the VM (checked 31 Oct 2026); the VM's standing scan targets are `scripts/validation/` (`docs/ci/LIVE_SCAN_VALIDATION.md`)._

Disposable containers only. Credentials are generated at run time and
destroyed with the container — never in source, configuration, logs, Celery
arguments or git.

```powershell
docker run -d --name ccure-pg-target    -p 127.0.0.1:15432:5432 -e POSTGRES_PASSWORD=... postgres:16-alpine
docker run -d --name ccure-mysql-target -p 127.0.0.1:13306:3306 -e MYSQL_ROOT_PASSWORD=... mysql:8.0
docker run -d --name ccure-mssql-target -p 127.0.0.1:11433:1433 -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD=... mcr.microsoft.com/mssql/server:2022-latest
```

Measured weak → hardened: PostgreSQL **12 → 0**, MySQL **11 → 0**, SQL Server
**12 → 0**. A run returning zero against a _weakened_ instance is a regression,
not a clean database.

Two things that cost time and will again:

- **`mysqladmin ping` succeeds against MySQL's temporary init server**, which
  then shuts down before the real one starts. Wait for
  `ready for connections.*port: 3306` in the container log; `port: 0` is the
  temporary server.
- **SQL Server on Linux refuses to start if it cannot read its TLS
  certificate**, and `/etc/ssl/private` is not traversable by the `mssql` user.
  Put the certificate and key under `/var/opt/mssql/`. `xp_cmdshell` and OLE
  Automation are also unsupported on Linux, so the dangerous-features rule is
  exercised through `clr enabled`, `cross db ownership chaining` and
  `Ad Hoc Distributed Queries`.

### Coverage

`scripts/measure_database_coverage.py`, denominator frozen at 31 areas before
implementation and including **eight areas this build does not implement**,
each with a recorded reason. **0% → 74.2%** (23/31), implemented _and_ tested.
Engine breadth is reported separately and never folded in: an area answered on
one engine is implemented, and answering it on three does not make it three
areas.

**Oracle and MongoDB are reserved, not shipped.** Drivers exist for both
(`oracledb` thin mode needs no Instant Client), and the transport vocabulary
names them so the phase that adds them adds a collector rather than a
migration. Neither could be stood up as a disposable target here, so neither
was validated, and `USABLE_TRANSPORTS` stops the API creating such a
credential.
