# Organisation settings

The platform owns organisation identity and two independent settings:

- Authorised scan targets are stored in `organizations.scan_scope_cidrs`.
  `ccure_platform.organisation_settings.scan_scope` reads and writes them.
  Audit enforces the returned scope through `core.scan_scope`.
- Remediation SLA configuration is stored in the organisation's settings JSON.
  `ccure_platform.organisation_settings.remediation_sla` exposes it through
  `ccure_platform.api`; Audit computes deadlines through `core.remediation.sla`.

Neither setting depends on a subscription or scan allowance. Keep their
permissions, tenant isolation, audit events and API contracts independent of
scan execution. `test_organisation_settings_containment.py` holds the boundary;
`test_organisation_settings.py` verifies the platform setting APIs.

Subscription fields and scan allowances were retired on 12 October 2026.
Migration `f6a8c0e2b4d7` removes the five retired organisation columns while
preserving organisation IDs, foreign keys, scope, settings and assessment data.
Apply all Alembic heads when deploying the matching backend and frontend.
Existing API clients must stop sending the retired organisation fields; the
organisation request schemas reject unknown fields. Deploy the migration
before serving requests with the new backend, since older schemas require
the retired columns when creating organisations.
Take a database backup first: removed subscription values cannot be recovered
by a downgrade, so rollback requires the pre-migration backup.

Historical migrations and dated implementation reports document earlier states;
they do not define the current application or authorise reintroducing entitlements.

Verification included the scan/authentication/security regression suite,
frontend unit and Chromium browser suites, repository guardrails, and a
restored-schema migration rehearsal with synthetic organisation, user, asset
and scan records. The rehearsal preserved the remaining columns, foreign
keys and seeded data, and verified that repeating the upgrade changes nothing.
The live database was not migrated during the initial implementation. Deployment
was verified on 12 October 2026: the live database already held revision
`f6a8c0e2b4d7` at the start of the deployment check, and all five retired columns
were absent. The API, scanner worker, web worker and scheduler were refreshed;
the frontend was rebuilt and deployed, and the gateway was recreated to replace
its stale file bind mount with the current route policy.

The full deployment backup is
`backups/plan-removal-deployment-20261012/ccure_db_20261012_140247_full.dump`.
Organisation data fingerprints and organisation/user/scan/asset counts matched
before and after service updates. Verification covered the built frontend
image, public live HTTPS/API checks, worker readiness and successful scheduled
background tasks. Authenticated regression checks ran in a dedicated disposable
database; no live account was impersonated for verification.
