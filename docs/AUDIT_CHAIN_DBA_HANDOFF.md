# DBA handoff — install the audit tamper-evidence chain

**One command, run once, by a database superuser.** Everything else in phase 4
is already applied. This is the only remaining step, and the application role
cannot perform it.

---

## Why a DBA is needed

The chain's security rests on the application role being _unable_ to write the
chain state. That requires a dedicated `audit_chain_writer` role which owns the
chain-head table and the hash functions, and `ccure_user` holds neither
SUPERUSER nor CREATEROLE. Measured on this database:

```
CREATE ROLE audit_chain_writer   -> permission denied to create role
ALTER TABLE audit_logs OWNER TO  -> must be able to SET ROLE
```

Granting `ccure_user` CREATEROLE instead would defeat the control it exists to
build: from PostgreSQL 16 a CREATEROLE role becomes admin of the roles it
creates, so it could `SET ROLE audit_chain_writer` and write chain heads
directly. **Do not grant CREATEROLE as a workaround.**

---

## Before you start

Take a backup. The script is a single transaction and rolls itself back on any
error, but a dump costs a minute:

```bash
# Runs the container's own pg_dump over its Unix socket: no password is asked
# for or stored. No superuser or application password belongs in version control.
scripts/backup_db.sh --skip-reference-data
```

The `postgres` password for the bootstrap itself is likewise never stored: `psql`
prompts for it, and it must not be added to `.pgpass`, an environment variable
in any committed file, or a scheduled task.

The most recent verified backup at time of writing:
`backups/ccure_test_20260825_225000_ops.dump` (655 TOC entries).

---

## The command

TLS is mandatory on this cluster — `pg_hba.conf` is `hostssl` only — so the
connection string carries `sslmode=verify-full`. Note **forward slashes** in the
certificate path: backslashes are escape characters in a libpq URI and
`D:\PostgreSQL\…` silently becomes `D:PostgreSQL…`.

```bash
psql "postgresql://postgres@127.0.0.1:5432/ccure_test?sslmode=verify-full&sslrootcert=D:/PostgreSQL/18/data/root.crt" \
     -v ON_ERROR_STOP=1 \
     -f Backend/scripts/audit/bootstrap_chain.sql
```

**`-v ON_ERROR_STOP=1` is not optional.** The whole script is one transaction and
several steps are guards that `RAISE`; without it `psql` carries on past a
refusal and commits a half-built chain.

Run it from the repository root so the `-f` path resolves.

---

## Expected output

```
NOTICE:  application role detected as: ccure_user
NOTICE:  created role audit_chain_writer
NOTICE:  rerun guard: no chained events yet, nothing to reproduce
NOTICE:  legacy seed: 3 new head row(s) created (existing rows untouched)
NOTICE:  --------------------------------------------------------
NOTICE:  audit chain bootstrap complete
NOTICE:    application role      : ccure_user
NOTICE:    chain head rows       : 3
NOTICE:    legacy (unverifiable) : 515
NOTICE:    chained events        : 0
NOTICE:    trigger armed         : audit_logs_chain
```

The three head rows must come out as:

| org_id             | legacy_event_count |
| ------------------ | ------------------ |
| `org_default`      | 319                |
| `org_self-service` | 91                 |
| `org_test_org.com` | 105                |
| **total**          | **515**            |

If those numbers differ, stop and report them — they were measured immediately
before handoff and should not have moved unless the application wrote new audit
events in between (which is normal and would raise the counts slightly; a
_lower_ count is not normal).

---

## What it changes

| Object                                                                  | Action                                                                                              |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `audit_chain_writer`                                                    | created, `NOLOGIN` — nothing ever connects as it                                                    |
| `audit_chain_heads`                                                     | created, owned by `audit_chain_writer`                                                              |
| `_audit_field_v1`, `audit_canonical_payload_v1`, `audit_record_hash_v1` | created, owned by the writer role                                                                   |
| `audit_chain_advance_v1`, `audit_chain_seed_legacy_v1`                  | created, `SECURITY DEFINER`, pinned `search_path`                                                   |
| `audit_logs_chain`                                                      | `BEFORE INSERT` trigger armed on the parent (clones to all 8 partitions)                            |
| Grants                                                                  | `ccure_user` gets `SELECT` on the head table and `EXECUTE` on four functions; `PUBLIC` gets nothing |

## What it does NOT change

- **No existing audit row is modified or deleted.** All 515 stay exactly as
  they are, unhashed, and are recorded as legacy.
- No schema change to `audit_logs` (the columns were added by migration
  `a7b8c9d0e1f2`, already applied).
- `ccure_user` is **not** granted membership in `audit_chain_writer`. That is
  deliberate: membership would let it `SET ROLE` around the whole boundary.
- No application restart required. The trigger takes effect immediately.

---

## Safety properties

- **Single transaction.** `BEGIN` … `COMMIT`. Any failure leaves the database
  exactly as it was.
- **Takes `SHARE ROW EXCLUSIVE` on `audit_logs` for the duration**, so no audit
  event can be written while it runs. Expect it to complete in well under a
  second at this data volume; concurrent writers block briefly rather than fail.
- **Idempotent, and cannot reset chain state.** The role, the table and the head
  rows are never dropped. The legacy seed is `INSERT … ON CONFLICT DO NOTHING`,
  so a rerun cannot overwrite `event_count`, `last_record_hash` or
  `genesis_event_id`.
- **Rerun guard.** If the file's hash functions ever stop reproducing hashes
  already stored, the whole transaction is refused with a message naming how
  many rows disagree. Rerunning is also the supported repair path if the trigger
  is ever dropped.

---

## If it fails

The transaction rolls back; nothing is left behind. Capture the full `psql`
output and hand it back. Do not re-run with `ON_ERROR_STOP` removed.

## To undo (should it ever be necessary)

```sql
BEGIN;
DROP TRIGGER IF EXISTS audit_logs_chain ON public.audit_logs;
DROP FUNCTION IF EXISTS public.audit_chain_advance_v1();
DROP FUNCTION IF EXISTS public.audit_chain_seed_legacy_v1();
DROP FUNCTION IF EXISTS public.audit_record_hash_v1(text, public.audit_logs);
DROP FUNCTION IF EXISTS public.audit_canonical_payload_v1(public.audit_logs);
DROP FUNCTION IF EXISTS public._audit_field_v1(text);
DROP TABLE IF EXISTS public.audit_chain_heads;   -- destroys chain state
DROP ROLE IF EXISTS audit_chain_writer;
COMMIT;
```

Note that dropping `audit_chain_heads` discards the chain tips permanently.
Events already written keep their `record_hash`, but the independent
head-versus-tip cross-check is lost. Only do this on a test database.

---

---

## Second run: the test database (`ccure_pytest_db`)

**Required.** The chain objects are _per-database_. Only `audit_chain_writer`
is cluster-wide, so after the first run it already exists and the second run
reports `role audit_chain_writer already exists (left alone)`.

Without this, the 89 chain tests in `tests/audit` continue to skip — they run
against `ccure_pytest_db`, not `ccure_test` (pinned in `docker-compose.yml` so
`docker exec … pytest` cannot inherit the live URL).

```bash
psql "postgresql://postgres@127.0.0.1:5432/ccure_pytest_db?sslmode=verify-full&sslrootcert=D:/PostgreSQL/18/data/root.crt" \
     -v ON_ERROR_STOP=1 \
     -f Backend/scripts/audit/bootstrap_chain.sql
```

> **If you ran this before 25 Aug 2026 and hit
> `ERROR: permission denied for schema public`** — that was a bug in this
> script, now fixed. It granted no `USAGE` on schema `public` to
> `audit_chain_writer`, and relied on that role inheriting it. On `ccure_test`
> it did inherit it (schema owned by `pg_database_owner`, `USAGE` granted to
> `PUBLIC`); on `ccure_pytest_db` the schema is owned by `ccure_user` with a
> NULL ACL, so it did not. The single transaction rolled back cleanly and
> nothing was left behind. **Just re-run the command below** — the script now
> grants `USAGE` explicitly and asserts it before continuing.

This database is disposable and currently holds **0 audit rows**, so expect:

```
NOTICE:  role audit_chain_writer already exists (left alone)
NOTICE:  rerun guard: no chained events yet, nothing to reproduce
NOTICE:  legacy seed: 0 new head row(s) created (existing rows untouched)
NOTICE:    chain head rows       : 0
NOTICE:    legacy (unverifiable) : 0
```

Zero head rows is correct here: there are no pre-chain rows to seed, and heads
are created on first write by the trigger's own initialisation path.

No backup is needed for this one — the suite rebuilds it, and
`tests/conftest.py` refuses to run against any database that is not
`pytest_`-prefixed and holds real data.

---

## Hand back to the engineer when done

Paste the `psql` output. Verification then runs as the **application** role:

```bash
docker exec ccure-api python scripts/audit/verify_chain_bootstrap.py   # 12 checks, must exit 0
docker exec ccure-api python scripts/audit/verify_chain.py
docker exec ccure-api python -m pytest tests/audit -q                  # 89 skips become live
docker restart ccure-api                                               # startup line flips to ARMED
```

Until `verify_chain_bootstrap.py` exits 0, the cross-role `SECURITY DEFINER`
path is unproven and no chain claim should be made.
