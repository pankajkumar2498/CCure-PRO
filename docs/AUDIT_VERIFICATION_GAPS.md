# Audit module — open verification gaps

Recorded 24 Aug 2026, at the close of phase 3 (indexes + append-only
enforcement). These are items the phase implemented but did **not** prove. They
are listed here rather than in the phase report so they stay visible until
they are closed, and so nothing in the module is described as "verified"
on the strength of a test that was never run.

Each entry names what is unproven, why it was not proven, and what closing it
would take. None of them is a known defect — an unverified control is not a
broken one, but it is not an assured one either.

---

## 1. Concurrent-load testing — NOT PERFORMED

**Unproven.** Every phase-3 measurement was taken from a single session
against an idle database. Nothing in the module has been exercised under
simultaneous load.

Specifically unmeasured:

- The audit list/detail endpoints under the 100+ concurrent users the module
  is specified for. All query timings (4.4 ms indexed page, 324 ms pager
  `COUNT` at 1M rows) are single-client figures and include no queueing,
  no connection-pool contention and no lock waits.
- Write throughput. `log_audit_event` is called on the request path of most
  mutating endpoints, so audit insert latency is user-visible latency, and it
  has only ever been measured one insert at a time (median 2.6 ms).
- The append-only trigger's cost under concurrency. It runs a subquery against
  `organizations` on every DELETE, which is not on the insert path — but the
  `BEFORE UPDATE OR DELETE` trigger's existence on a hot table has not been
  load-tested.

**Why not done:** phase 3's scope was index selection, and the benchmark
harness (`Backend/scripts/audit/bench_audit_queries.py`) is deliberately
single-threaded so its timings are attributable to the query plan rather than
to scheduling.

**To close:** a concurrent harness driving the two endpoints and the insert
path at a stated concurrency, reporting p50/p95/p99 rather than a mean. This
matters most before phase 4: the hash chain adds a per-organisation row lock
to every insert, which converts audit writes for one tenant from parallel to
serialised. Phase 4's plan already carries a multi-org concurrency test for
exactly this reason, and that test is the natural place to establish the
baseline this gap describes — **the phase-4 concurrency tests should be run
against a pre-chain baseline captured first**, or the chain's cost cannot be
separated from the module's existing cost.

---

## 2. Migration downgrade — WRITTEN, NEVER EXECUTED

**Unproven.** `alembic/versions/f5a6b7c8d9e0_audit_indexes_and_immutability.py`
has a `downgrade()` that drops the two partitioned indexes (detaching each
partition's index first) and removes the trigger functions, triggers and
grant changes via `remove_audit_immutability()`. It has been written and
reviewed. It has never been run.

The same is true of `e4f5a6b7c8d9`'s downgrade (severity + request_id).

**Why not done:** the only PostgreSQL instance available is the live
application database (`ccure_test`). Running a downgrade there to test it
would drop columns holding real audit data.

**To close:** restore the phase-3 backup
(`backups/ccure_test_20260824_212028_ops.dump`) into a disposable
`pytest_`-prefixed database, run `alembic downgrade -1` twice and
`alembic upgrade head` again, and confirm the schema, the partition indexes'
`indisvalid`, and the trigger set match. Until then the migrations are
correctly described as _forward-verified only_.

Note the pre-existing caveat that applies once this is exercised: a downgrade
is schema-reversible but not data-loss-free. Dropping `severity` and
`request_id` discards those values permanently, and re-upgrading cannot
reconstruct them.

---

## 3. Fresh-install path — NOT TESTED

**Unproven.** The append-only enforcement has two installation routes, and
only one of them has been executed.

- **Migrated install** — `alembic upgrade head` calls
  `apply_audit_immutability()`. Verified live on `ccure_test`: 18 triggers,
  both indexes valid, 9/9 tamper attempts refused.
- **Fresh install** — `db/migrate_production_schema.py` builds the schema with
  `Base.metadata.create_all()` + `create_partitions()` and stamps Alembic
  head, so the migration never runs. A call to `apply_audit_immutability()`
  was added to that branch for this reason. **It has never executed.**

This is the precise divergence `tests/repo/test_schema_drift.py` exists to
catch for columns, and which it cannot catch for triggers and grants, because
neither is expressible in SQLAlchemy metadata. A fresh install that silently
skipped the hardening would present as a fully working system whose audit
table is quietly mutable.

**Why not done:** it requires building a database from empty, which the
available instance is not.

**To close:** create an empty `pytest_`-prefixed database, run the fresh-install
bootstrap against it, and assert the same structural properties the migrated
path was checked for — the row trigger on the parent, a TRUNCATE trigger on
the parent and on all eight partitions, and TRUNCATE revoked. Two of those
assertions already exist as tests
(`test_every_partition_carries_a_truncate_trigger`, and the index-validity
pair in `tests/audit/test_audit_immutability.py`); they currently _skip_ when
the hardening is absent rather than fail, so they will not report this gap on
their own.

---

## 4. The tamper-evidence chain is NOT INSTALLED on this deployment

Added 25 Aug 2026, at the close of phase 4. This is the largest open item, and
it is a deployment step rather than a defect.

**Unproven.** Everything the application's own database role can do has been
applied and verified: the actor-snapshot columns, the backfill, organisation
archival, and the append-only enforcement from phase 3. The **chain itself is
not installed**, so no audit event on this host carries a hash and none can be
cryptographically verified.

The reason is a deliberate privilege boundary. The chain needs a dedicated
`audit_chain_writer` role that owns `audit_chain_heads` and the `SECURITY
DEFINER` hash functions, and `ccure_user` holds neither SUPERUSER nor
CREATEROLE. Measured:

```
CREATE ROLE probe_chain_writer     -> permission denied to create role
ALTER TABLE audit_logs OWNER TO …  -> must be able to SET ROLE "admin"
```

Granting `ccure_user` CREATEROLE would defeat the control: from PostgreSQL 16 a
CREATEROLE role becomes admin of the roles it creates and could `SET ROLE` into
the writer.

**To close:** a database administrator runs, as a superuser:

```
psql -h 127.0.0.1 -p 5432 -U postgres -d ccure_test \
     -v ON_ERROR_STOP=1 -f Backend/scripts/audit/bootstrap_chain.sql
```

then, as the application role:

```
docker exec ccure-api python scripts/audit/verify_chain_bootstrap.py
docker exec ccure-api python -m pytest tests/audit -q
```

**What is blocked until then**, all currently reported as skips and none of
them as passes:

| Suite                                   | Skipped | Covers                                 |
| --------------------------------------- | ------- | -------------------------------------- |
| `test_audit_chain_privileges.py`        | 38      | the whole privilege boundary           |
| `test_audit_chain_tamper.py`            | 21      | all 14 canonical fields, forged hashes |
| `test_audit_canonicalization.py`        | 14      | determinism, timezone, JSONB           |
| `test_audit_chain_legacy_boundary.py`   | 6       | pre-chain history handling             |
| `test_audit_chain_concurrency.py`       | 5       | fork prevention, first-event race      |
| `test_audit_second_session_deadlock.py` | 5       | the C2 lock-timeout guard              |
| **Total**                               | **89**  |                                        |

The **cross-role `SECURITY DEFINER` path is the specific thing that has never
executed**: a trigger on a `ccure_user`-owned table invoking a function owned by
`audit_chain_writer` that writes a table `ccure_user` cannot touch. It could not
be prototyped without role-creation rights. `verify_chain_bootstrap.py` exists
to prove it first, before anything else is believed.

What _has_ been proven about the chain SQL, as `ccure_user` in a rolled-back
transaction: every object in `bootstrap_chain.sql` creates without error, the
trigger chains events correctly with one genesis and correct links, the head
tracks `event_count`/`last_event_id`/`genesis_event_id`, and hashes reproduce
identically under four session timezones and four `DateStyle` settings. That is
the algorithm, not the privilege boundary.

**CLOSED 25 Aug 2026.** The bootstrap was executed by a DBA on both databases.
`verify_chain_bootstrap.py` passes 38/38, the cross-role `SECURITY DEFINER`
path is proven end to end, and all 89 previously-skipped tests now execute
(222 passed, 1 skipped — see §6 for the one that remains NOT VERIFIED).

Startup now reports:

```
INFO  Audit tamper-evidence chain ARMED — 3 organisation(s), 1 chained
event(s), 515 legacy event(s) predating the chain (not verifiable)
```

Two things about the installation are recorded because they were not obvious:

- The **first** run on `ccure_test` succeeded partly by accident. The script
  granted `audit_chain_writer` no `USAGE` on schema `public` and relied on
  inheritance; `ccure_test` grants `USAGE` to `PUBLIC`, `ccure_pytest_db` does
  not, so the same script failed there with
  `permission denied for schema public` from inside the legacy seeder. The
  grant is now explicit and asserted.
- The 515 pre-existing rows were never the blocker and were never touched.

---

## 5. Per-endpoint atomicity coverage is partial (phase 4.1)

**Partly proven.** Twenty-one handlers wrote their audit event after the commit
that would have persisted it, so the row was flushed and discarded. All 21 are
fixed and covered by a **structural guard**
(`test_no_handler_audits_after_its_last_commit`) that walks every handler in
the application and fails on the pattern — which also covers any handler added
later.

**Endpoint-level HTTP tests exist for 2 of the 21** — `update_asset` and
`import_amt_inventory`, both with a success case and a failure case, read back
through an independent session. The other 19 are compliance and findings
handlers whose endpoint tests need framework/control/finding/remediation
scaffolding that does not exist in the suite today.

**To close:** build the compliance fixture scaffolding and add a success/failure
pair per handler. Until then the per-site claim is "structurally guaranteed and
guarded, not individually driven over HTTP".

---

## 6. The privilege boundary depends on schema ownership

Found 25 Aug 2026, during post-bootstrap verification. Not a defect in the
chain — a precondition of it that was previously undocumented.

**A PostgreSQL schema owner may `DROP` any object in that schema, regardless of
who owns the object.** Owning `audit_chain_heads` and the hash functions as
`audit_chain_writer` is therefore _not sufficient_ on its own: if the
application role owns the schema those objects live in, it can remove them.

Measured on this cluster, same roles, same script:

| Database          | `public` owner      | `DROP FUNCTION audit_record_hash_v1` as `ccure_user` |
| ----------------- | ------------------- | ---------------------------------------------------- |
| `ccure_test`      | `pg_database_owner` | **refused** — `must be owner`                        |
| `ccure_pytest_db` | `ccure_user`        | **ALLOWED**                                          |

`ALTER FUNCTION … RENAME` is refused in both — that one does require object
ownership. It is specifically `DROP` that the schema owner inherits.

**What this does and does not weaken.** Hashes are still computed and verified,
and tampering with existing rows is still detected, because those depend on the
functions being _correct_, not on their being _undeletable_. What is absent
where the precondition fails is protection against the application role
removing the machinery outright — after which new events would simply be
written unchained, which `verify_chain.py` reports as unhashed rows sitting
after genesis, and which the startup line reports as a count of unverifiable
events.

**CLOSED 25 Aug 2026.** The machinery was moved into a dedicated `audit_chain`
schema owned by `audit_chain_writer`, on **both** databases. The application
role owns nothing there and belongs to no role that does, so the precondition
now holds everywhere:

```
DROP SCHEMA audit_chain    -> must be owner of schema audit_chain
DROP TABLE  …_heads        -> must be owner of table audit_chain_heads
DROP FUNCTION …hash_v1     -> must be owner of function audit_chain.audit_record_hash_v1
CREATE OR REPLACE …        -> permission denied for schema audit_chain
```

The move was a catalogue operation — `ALTER … SET SCHEMA` plus
`CREATE OR REPLACE`, with **zero DROP statements** — and preserved chain state
byte-for-byte. `trigger_function_oid` was unchanged at 3194421, which is the
direct evidence the trigger binding followed the function rather than being
recreated. Both fingerprints survived intact:

```
event fingerprint : baf3ae314755dc9989ec6903ed7cfba630be5faf98879798c8e71c9ff9117d86
head  fingerprint : f3a92a310d755e17490eda662f97f4d253412184d33a8ed4c707164ce288719a
517 total / 515 legacy / 2 chained    (unchanged)
```

**One thing the move changed that is worth recording**, because it briefly
looked like a security regression and was not: with the real functions gone
from `public`, `ccure_user` _can_ create a decoy `public._audit_field_v1` on a
database where it owns that schema. It is inert — every chain reference is
schema-qualified — and
`test_a_public_decoy_function_cannot_affect_the_real_chain` now pins that down
directly. The old assertion "cannot create `public._audit_field_v1`" was
meaningful only while the real function lived there; afterwards it reported a
compromise that did not exist.

`bootstrap_chain.sql` reports this at install time — `NOTICE` when protected,
`WARNING` naming the consequence when not. Both databases now report
`app role can remove : no`.

### How it was found

By a test that destroyed the thing it was checking. `_denied()` ran
`execute(sql)` then `commit()` inside `pytest.raises`, so a statement that
turned out to be _permitted_ was committed before the assertion failed —
`test_app_role_cannot_drop_the_canonical_functions` genuinely dropped
`_audit_field_v1` and broke 24 unrelated tests.

Every "expect refusal" helper in `tests/audit/` now rolls back unconditionally
in a `finally`, before any assertion, and an AST sweep confirms no remaining
`commit()` inside a `pytest.raises` block performs destructive DDL or a tamper.
**A test that verifies "X is refused" must never be the thing that performs X.**

---

## Status summary

| Gap                                  | State                                                    | Blocks                         |
| ------------------------------------ | -------------------------------------------------------- | ------------------------------ |
| Chain installed on `ccure_test`      | **DONE** 25 Aug 2026                                     | —                              |
| Chain installed on `ccure_pytest_db` | **DONE** 25 Aug 2026                                     | —                              |
| Cross-role SECURITY DEFINER path     | **VERIFIED** — 38/38 acceptance checks                   | —                              |
| Schema-ownership precondition (§6)   | **CLOSED** — isolated in `audit_chain` on both databases | —                              |
| Concurrent-load testing              | Not performed                                            | Chain lock-cost acceptance     |
| Migration downgrade execution        | Written, never run                                       | Production rollback confidence |
| Fresh-install hardening              | Code in place, never run                                 | Any new deployment             |
| Per-endpoint atomicity (19 of 21)    | Structural guard only                                    | Nothing; belt-and-braces       |

None blocks the work already deployed on this host, which was verified
directly. The first two block any claim that audit records are
tamper-**evident**; until the bootstrap runs, the accurate statement is that
they are append-only under normal application-role privileges, with no
cryptographic verification available.
