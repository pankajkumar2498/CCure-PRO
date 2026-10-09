# Clean development reset

This procedure applies only to the disposable local development installation.
It removes all existing accounts, organizations and their owned data. Never use
it for customer or production data. Historical Alembic files remain unchanged;
`d4f8b2c6e0a1`, after `c9e3a7b5d1f2`, removes the four legacy RBAC tables and
`users.role_id`. Fresh metadata contains native RBAC only.

The reviewed scope is
`Backend/data/rbac/development_reset_manifest.json`, checked against
`Backend/scripts/architecture/table_ownership.yaml` and actual physical tables.
An unknown table, unknown orphan organization, active retention hold, custom
role, broken FK, disabled guard or missing privileged audit bootstrap blocks
the reset. System roles and revision history are preserved. All module schemas,
global vulnerability and compliance catalogues, identity domain catalogues,
audit functions, owners, ACLs and retention accounting records are preserved.
Catalogues are compared using counts and complete row fingerprints.

Organization-owned audit history is disposable tenant data in this operation.
The tool deletes organizations through their existing FK ownership cascades;
the audit guard explicitly permits these cascades. It never disables a guard,
directly deletes audit history, or truncates a database. A summary of the reset,
snapshot digest and removed counts is appended to the platform audit ledger.
Retention anchors remain as historical accounting records with their old
organization identifiers; an active hold prevents the reset.

First restore a private PostgreSQL custom-format dump into a new database named
`ccure_dev_rehearsal_<identifier>`. Verify its SHA-256, successful restore,
schema, ownership, counts and audit bootstrap. Record a private adjacent
`<dump>.verified.json` containing `sha256`, `restore_verified: true`, and the
restore target and verification evidence. Rehearse using copies of artifacts
and an isolated broker database. Artifact roots and recovery directories must
be under `/tmp` for a disposable rehearsal.

Set `ENV=development`, `APP_ENV=development`, `SKIP_DOTENV_LOAD=1`,
`DEFAULT_ORG_NAME=CCure Development`, and `DEFAULT_ORG_SLUG=development`.
Supply the exact local `DATABASE_URL` and `CELERY_BROKER_URL` securely. Keep
encryption, signing and certificate configuration intact. Never print credentials
or put them in version control.

Run from `Backend`, substituting reviewed absolute paths and database identity:

```bash
python -m scripts.rbac.development_reset plan \
  --target-database "$RESET_DATABASE" \
  --confirm-development "RESET DEVELOPMENT $RESET_DATABASE" \
  --snapshot "$RESET_SNAPSHOT" --snapshot-sha256 "$RESET_SNAPSHOT_SHA256" \
  --reports-root "$RESET_REPORTS" --evidence-root "$RESET_EVIDENCE" \
  --broker-url "$CELERY_BROKER_URL" \
  --admin-email "$RESET_ADMIN_EMAIL" --admin-username "$RESET_ADMIN_USERNAME" \
  --plan "$RESET_PLAN" --disposable
```

Review every count, organization/user/scan identifier, orphan, artifact digest,
broker entry and preserved fingerprint. `plan` is read-only and writes a private
JSON review artifact. `apply` accepts the same arguments plus
`--plan-sha256`, `--password-file`, and a new `--recovery-directory`.
The password file must have mode 0600 and satisfy the application password
policy. Apply rechecks the plan and database identity under table locks, and
requires no other database sessions and stopped API/worker/beat containers for
that database. There is no production override.

Only recognized generated reports, per-scan XSS screenshots and per-organization
compliance evidence are quarantined; symlinks and path escapes are refused.
Unknown files remain untouched. Recovery includes exact broker DUMP values and
TTLs. Queue cleanup removes exact owned messages and acknowledged task-result
keys, retaining malformed or unrelated messages and global broker state. Scan
progress is stored in PostgreSQL; Redis pub/sub channels are not keys to delete.
An unsuccessful database transaction restores quarantined files. If database
commit succeeds but broker cleanup fails, keep services stopped and review the
recovery artifacts before retrying cleanup; do not claim a completed reset.

Bootstrap uses the application catalogue sync, five code-managed roles, Viewer
default, default-organization initializer, password hashing and audited native
administrator provisioning. The administrator holds an ordinary revocable
platform assignment with exactly 67 materialized grants. No role name bypass,
legacy permission translation or `users.role_id` authority is introduced.

Complete schema, FK, frozen-grant, effective-permission, security, tenant,
audit and application checks in the rehearsal. Any unexpected loss, FK, RBAC or
security failure stops the rollout; leave the main database untouched.
Only after every rehearsal gate passes, take and restore-verify a fresh main
development snapshot, stop API/workers/beat, migrate to all three expected heads,
then plan/apply the main reset without `--disposable`.

The base Compose configuration has production-shaped defaults. For the local
development deployment, after all rehearsal gates pass, use the explicit
`docker-compose.development-rbac.yml` override with reviewed source directories
for API/workers/beat and the frontend build. Keep the original gateway, keys,
certificates, database and broker configuration. Verify the merged settings
before creating stopped containers and restarting after database verification.
The override sets both environment labels to development, disables dotenv
loading, and leaves automatic administrator credentials empty. The reset's
explicit native bootstrap creates the fresh administrator. Review merged
settings against the existing container configuration; retain any existing
local service settings through a private operator override rather than changing
the shared base Compose file.

The privileged audit test bootstrap must be installed as DBA on the dedicated
pytest database only, using the three existing audit bootstrap SQL scripts.
Verify global role attributes/membership and the main database's audit definitions
are unchanged. Run tests on that pytest database, never on the rehearsal or main
database; fixtures intentionally rebuild schemas. Existing retention acceptance
probes can seed historical events by disabling a trigger inside a rolled-back
test transaction, so those probes belong only on the pytest database. Main
verification must leave every protection enabled.

Rollback of the removal migration cannot reconstruct discarded data. Restore the
verified recovery dump into a separate database, restore quarantined owned files
and broker state as needed, verify integrity, and explicitly reconfigure the
development deployment. Never overwrite a working database as an implicit rollback.
