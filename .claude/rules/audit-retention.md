---
paths:
  - "Backend/ccure_platform/audit_log/**"
  - "Backend/core/audit_retention.py"
  - "Backend/scripts/audit/**"
  - "scripts/audit/**"
---

# Audit-log retention (phase 6a)

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 5057–5144) and is maintained here. Frozen original: `docs/archive/engineering-record/audit-log-retention.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Audit-log retention (phase 6a)

**Retention is installed but disabled, and that is the shipped state.**
`AUDIT_LOG_RETENTION_DAYS` is `0`; nothing purges anything until a period is
agreed with the business or compliance owner. ISO 27001 A.5.33 and A.8.15
require a _defined_ period and do not supply one, so choosing a number in code
would be inventing a compliance position. `AUDIT_RETENTION_MIN_DAYS` (90) is a
floor the same setting cannot lower — "9" for "90" is not a recoverable typo.

**Legacy rows only.** Phase 6a removes rows with `record_hash IS NULL`, written
before the tamper-evidence chain existed. Nothing can ever link to one:
`prev_hash` references a `record_hash` value and a legacy row has none, so
removing them cannot break a chain _for any dataset_, past or future. That is
structural, not a property of the current data. Chained-record deletion is
phase 6b and needs its own approval.

**`audit_logs` is HASH partitioned on `org_id`, so partition-drop retention is
impossible.** There is no time-based partition to detach; retention is
row-level `DELETE`, batched.

**The privileged half is a second DBA bootstrap**,
`scripts/audit/bootstrap_chain_retention.sql`, run as a superuser exactly like
`bootstrap_chain.sql`. It creates the `audit_maintenance` role (NOLOGIN,
deliberately **not** `audit_chain_writer` — separation of duties between the
role that computes hashes and the role that can delete rows), the
`audit_retention` schema owned by it, the anchor and hold tables, and
`audit_retention.purge_legacy_v1`. Verify with
`scripts/audit/verify_retention_bootstrap.py`. Without it every retention path
reports "not installed" and refuses, which is the safe direction.

**The function is the boundary; the trigger is defence in depth.** `ccure_user`
may EXECUTE `purge_legacy_v1` — the Celery task has to — but cannot alter it,
cannot drop it (it does not own the schema), and is not a member of
`audit_maintenance`. Every precondition lives inside the function where the
caller cannot reach it, and the Python checks in `core/audit_retention.py` are
duplicates for a better error message, never the control.

**The append-only trigger's DELETE escape has two conditions and both matter.**
`current_user = 'audit_maintenance'` is true only inside the SECURITY DEFINER
function. `OLD.record_hash IS NULL` is the phase boundary _as a database
constraint_: during 6a the maintenance role cannot delete a chained row even
through its own function, even if that function's predicate were wrong. Do not
relax either half without the phase-6b approval.

**An anchor is an accounting record, not preserved content.** For a legacy row
there was never any cryptographic continuity to preserve, and no copy of the
event exists anywhere afterwards. Never describe a legacy anchor as preserving
deleted audit contents. Phase 6b's chained anchors _do_ carry continuity
evidence and will require an archive artefact.

**The anchor is written before the delete, in the same transaction.** So an
anchor without its deletion is impossible and a deletion without its anchor is
impossible. One transaction **per batch**, never per run: the purge holds the
organisation's chain-head `FOR UPDATE` lock for a batch, and for as long as it
does, no audit event can be written for that tenant.

**An unaccounted deletion is detectable, and that is what the accounting buys.**
`audit_chain_note_legacy_purge_v1` decrements `legacy_event_count` in the same
transaction as the deletion, and nothing else can reach the head. So a
privileged out-of-band removal leaves the head _ahead_ of the surviving rows,
and `verify_chain.py` reports it as a break. The check is **directional**: a
head _behind_ the row count means rows were inserted with the chain trigger
disabled — how real pre-chain history and every legacy test fixture come to
exist — and is a note, not a break.

**Retention defers to exports rather than racing them.** The export takes a
shared, **transaction-scoped** advisory lock; the purge takes an exclusive,
**non-blocking** one and skips that organisation until the next run. Never use
session-scoped advisory locks here: they release when the _connection_ closes,
and SQLAlchemy pools connections, so one would leak onto the next unrelated
request that drew the same connection.

**No HTTP endpoint deletes an audit row.** `/admin/audit-logs/retention/preview`
is read-only and superadmin-only; execution is beat
(`ccure.tasks.purge_expired_audit_logs`, defined in
`ccure_platform/audit_log/tasks.py` since the task-hub split) or
`scripts/audit/purge_audit_retention.py --apply`. Destroying audit history
therefore needs shell access to the host as well as the role.

**Dry run is the default everywhere** and writes nothing at all — no delete, no
anchor, no head update, no audit event. The backup precondition
(`AUDIT_RETENTION_REQUIRE_BACKUP_HOURS`) is deliberately checked only on the
mutating path: a dry run is exactly what an operator does _before_ taking a
backup.

`archive_mode` is still `off`, so a purge is recoverable only back to the last
dump. That is why the backup check is a hard refusal rather than a warning.
