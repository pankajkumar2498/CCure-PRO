# Repository instructions for contributors and AI agents

**Read and follow [CLAUDE.md](CLAUDE.md) before any change, in any part of the
repository.** It is the primary instruction document and the source of truth for
repository-wide rules: commits, test-database safety, architecture guardrails,
deployment, and the rest. This file only routes; it adds no rules of its own.

Then read the specialist documents for the area you are changing:

| Area | Read |
| ---- | ---- |
| Frontend (anything under `Frontend/`) | [Frontend/AGENTS.md](Frontend/AGENTS.md), [docs/FRONTEND_ARCHITECTURE.md](docs/FRONTEND_ARCHITECTURE.md) |
| UX4G and the CCure Design System | [docs/ux4g/UX4G_STANDARD.md](docs/ux4g/UX4G_STANDARD.md), the standard; [Frontend/ux4g-baseline.json](Frontend/ux4g-baseline.json), the binding release pin and checksums |
| Backend tests | [Backend/tests/README.md](Backend/tests/README.md) |
| Which tests to run for a change (targeted first) | [CLAUDE.md](CLAUDE.md), "Test targeted-first"; [docs/ci/CI_SCOPE.md](docs/ci/CI_SCOPE.md) |
| CI, branch protection, security gates | [docs/ci/](docs/ci/) |

## Module and task instructions

The module rules that used to sit in `CLAUDE.md` are in `.claude/rules/`, one file per area,
and the task procedures in `.claude/skills/`. **Those files are the only copy**; nothing else
restates them. Claude Code loads a rule by itself when it reads or edits a file matching the
rule's `paths`, and a skill when it is invoked or relevant. **Every other agent reads the rule
file before changing a file that matches any of its paths, and the skill before doing its
task.** A change can match several rules; read all of them.

| Read | Covers | Before changing files matching |
| ---- | ------ | ------------------------------ |
| [`.claude/rules/backend-tests.md`](.claude/rules/backend-tests.md) | Backend test layout | `Backend/tests/**`, `Backend/pytest.ini` |
| [`.claude/rules/architecture-boundaries.md`](.claude/rules/architecture-boundaries.md) | Architecture guardrails (modular-platform programme) | `Backend/**`, `scripts/ci/**`, `.github/workflows/**` |
| [`.claude/rules/identity-platform.md`](.claude/rules/identity-platform.md) | Identity boundary, tokens, MFA, RBAC and platform extraction | `Backend/ccure_platform/**`, `Backend/auth/**`, `Backend/routers/**`, `Backend/main.py`, `Backend/db/models/**`, `Backend/tests/rbac/**`, `Backend/tests/auth/**`, `Backend/scripts/rbac/**`, `Backend/scripts/security/**`, `Backend/data/rbac/**`, `gateway/**`, `Frontend/src/shell/auth/**`, `Frontend/src/shell/admin/**` |
| [`.claude/rules/modules-contracts.md`](.claude/rules/modules-contracts.md) | Audit boundary layers, core modules and integration contracts | `Backend/ccure_audit/**`, `Backend/ccure_policy/**`, `Backend/ccure_rank/**`, `Backend/ccure_contracts/**`, `Backend/ccure_platform/modules/**`, `Backend/ccure_platform/hub/**`, `Backend/alembic/**`, `Backend/alembic.ini`, `Backend/scripts/db/**`, `Backend/scripts/contracts/**`, `Backend/scripts/integration/**`, `Backend/tests/modules/**`, `scripts/db/**`, `.github/CODEOWNERS` |
| [`.claude/rules/deployment.md`](.claude/rules/deployment.md) | Deployment on the Linux VM | `docker-compose*.yml`, `Backend/Dockerfile`, `Frontend/Dockerfile`, `.env.example`, `Backend/.env.example`, `Backend/start.sh`, `Backend/core/celery_app.py`, `Backend/core/web/self_check.py`, `scripts/backup_db.sh`, `scripts/install_backup_schedule.sh`, `scripts/install_feed_schedule.sh`, `scripts/run_feed_sync.sh`, `scripts/docker-postgres-init.sql`, `scripts/linux/**`, `scripts/validation/**` |
| [`.claude/rules/api-security.md`](.claude/rules/api-security.md) | Authentication, rate limiting, sessions, email screening, beat and CORS | `Backend/routers/**`, `Backend/main.py`, `Backend/scan_helpers.py`, `Backend/config.py`, `Backend/core/rate_limiter.py`, `Backend/core/rate_limit_middleware.py`, `Backend/core/rate_limit_audit.py`, `Backend/core/ip_resolver.py`, `Backend/core/trusted_proxy.py`, `Backend/core/throttle.py`, `Backend/core/user_agent.py`, `Backend/core/celery_app.py`, `Backend/ccure_platform/identity/**`, `Backend/auth/**`, `Backend/tests/security/**` |
| [`.claude/rules/edge-gateway.md`](.claude/rules/edge-gateway.md) | Host nginx, the gateway, TLS and response headers | `gateway/**`, `scripts/host-nginx/**`, `scripts/linux/**`, `scripts/tls/**`, `scripts/gateway/**`, `Frontend/nginx.conf`, `docker-compose*.yml`, `Backend/start.sh`, `Backend/core/trusted_proxy.py`, `Backend/core/ip_resolver.py`, `docs/TLS_SETUP.md` |
| [`.claude/rules/scan-lifecycle.md`](.claude/rules/scan-lifecycle.md) | Scan terminal state, scan pipeline and scheduling | `Backend/scans/**`, `Backend/orchestrator/**`, `Backend/core/scan_control.py`, `Backend/core/tasks.py`, `Backend/core/task_names.py`, `Backend/core/phase_handoff.py`, `Backend/core/scheduling/**`, `Backend/core/discovery/**`, `Backend/core/nmap/**`, `Backend/engines/port/**`, `Backend/config.py`, `Backend/routers/phase_scans.py`, `Backend/routers/traditional_scans.py`, `Backend/routers/scan_schedules.py`, `Backend/routers/scan_progress.py`, `Backend/tests/scans/**` |
| [`.claude/rules/credentialed.md`](.claude/rules/credentialed.md) | Credentialed collection: WinRM, SMB, authentication, transport, elevation, Windows patches | `Backend/engines/credentialed/**`, `Backend/core/credential_vault.py`, `Backend/db/models/credentials.py`, `Backend/scans/tasks/credentialed.py`, `Backend/scans/tasks/credentialed_sync.py`, `Backend/routers/credentialed.py`, `Backend/routers/credentials.py`, `Backend/core/config_audit/collectors/windows.py`, `Backend/core/config_audit/collectors/linux.py`, `Backend/tests/credentialed/**` |
| [`.claude/rules/config-audit.md`](.claude/rules/config-audit.md) | Configuration audit engine, benchmark content and local privilege checks | `Backend/core/config_audit/**`, `Backend/core/benchmarks/**`, `Backend/core/compliance_catalogue/**`, `Backend/core/compliance_sync.py`, `Backend/data/benchmarks/**`, `Backend/scripts/benchmarks/**`, `Backend/scripts/measure_privilege_coverage.py` |
| [`.claude/rules/middleware-containers.md`](.claude/rules/middleware-containers.md) | Middleware configuration, container and Kubernetes assessment | `Backend/core/config_audit/structured.py`, `Backend/core/config_audit/containers.py`, `Backend/core/config_audit/collectors/middleware.py`, `Backend/core/config_audit/collectors/container.py`, `Backend/core/config_audit/builtin/middleware_*.py`, `Backend/core/config_audit/builtin/container_*.py`, `Backend/scripts/measure_middleware_coverage.py`, `Backend/scripts/measure_container_coverage.py` |
| [`.claude/rules/scap.md`](.claude/rules/scap.md) | STIG and SCAP content | `Backend/core/scap/**`, `Backend/core/config_audit/collectors/scap.py`, `Backend/scripts/benchmarks/**`, `Backend/scripts/measure_scap_coverage.py`, `Backend/tests/scans/test_scap_*.py` |
| [`.claude/rules/scan-policy.md`](.claude/rules/scan-policy.md) | Scan policy | `Backend/core/scan_policy/**`, `Backend/routers/scan_policies.py`, `Backend/scripts/measure_scan_policy_coverage.py`, `Backend/tests/scans/test_scan_policy*.py` |
| [`.claude/rules/findings-remediation.md`](.claude/rules/findings-remediation.md) | Remediation and SLA, scan comparison, finding lifecycle and data model | `Backend/core/findings/**`, `Backend/core/remediation/**`, `Backend/db/models/**`, `Backend/routers/findings.py`, `Backend/routers/remediation.py`, `Backend/routers/assets.py`, `Backend/scans/asset_syncer.py`, `Backend/scripts/measure_remediation_coverage.py` |
| [`.claude/rules/reporting.md`](.claude/rules/reporting.md) | Exports and reports | `Backend/reporting/**`, `Backend/routers/reports.py`, `Backend/scripts/measure_export_coverage.py` |
| [`.claude/rules/checks-network-tls.md`](.claude/rules/checks-network-tls.md) | Assessment framework, network checks, deep TLS and Nuclei | `Backend/core/checks/**`, `Backend/engines/vulnerability/**`, `Backend/engines/tls/**`, `Backend/core/web/sslyze/**`, `Backend/scripts/measure_network_check_coverage.py`, `Backend/scripts/measure_tls_coverage.py` |
| [`.claude/rules/vuln-feeds.md`](.claude/rules/vuln-feeds.md) | Vulnerability feeds (vuln_intel) | `Backend/scripts/vuln/**`, `Backend/core/vuln_intel.py`, `Backend/core/vuln_intel_repository.py`, `Backend/core/vuln_scoring.py`, `Backend/scans/nvd_sync.py`, `Backend/engines/credentialed/csaf_matcher.py`, `Backend/engines/credentialed/vuln_matcher.py`, `scripts/run_feed_sync.sh`, `scripts/install_feed_schedule.sh` |
| [`.claude/rules/database-assessment.md`](.claude/rules/database-assessment.md) | Database assessment | `Backend/engines/credentialed/database_executor.py`, `Backend/core/config_audit/collectors/database.py`, `Backend/core/config_audit/builtin/database_*.py`, `Backend/scripts/measure_database_coverage.py` |
| [`.claude/rules/compliance.md`](.claude/rules/compliance.md) | Policy Compliance Engine, ISO 27001, active frameworks and NIST CSF 2.0 | `Backend/core/compliance*.py`, `Backend/core/compliance_catalogue/**`, `Backend/core/nist_csf*.py`, `Backend/core/asset_evidence.py`, `Backend/ccure_audit/evidence_providers.py`, `Backend/routers/compliance*.py`, `Backend/reporting/compliance/**`, `Backend/data/compliance_seeds/**`, `Backend/scripts/seed_*.py`, `Backend/scripts/enrich_*.py`, `Backend/scripts/set_active_frameworks.py`, `Backend/scripts/cleanup_*.py`, `Backend/scripts/fix_csf_11_crosswalks.py`, `Backend/tests/compliance/**` |
| [`.claude/rules/uploads.md`](.claude/rules/uploads.md) | File uploads | `Backend/core/upload_guard.py`, `Backend/routers/compliance_attestation.py`, `Backend/routers/assets.py`, `Backend/tests/security/test_upload_validation.py` |
| [`.claude/rules/audit-retention.md`](.claude/rules/audit-retention.md) | Audit-log retention (phase 6a) | `Backend/ccure_platform/audit_log/**`, `Backend/core/audit_retention.py`, `Backend/scripts/audit/**`, `scripts/audit/**` |

| Read | Before doing this |
| ---- | ----------------- |
| [`.claude/skills/release/SKILL.md`](.claude/skills/release/SKILL.md) | Deploying a CCure release to the Linux VM (ccurepro): building the backend and frontend images from a committed HEAD, backups and idle checks before deploying, compose.sh, verification, rollback with --fallback, and the release ledger. Use before any deployment, image rebuild or recreation of the api, worker, web-worker, beat or frontend containers. |
| [`.claude/skills/db-backup-restore/SKILL.md`](.claude/skills/db-backup-restore/SKILL.md) | Backing up and restoring the CCure PostgreSQL databases on the VM: backup_db.sh, the 6-hourly operational and daily full tiers, why an ops dump cannot be restored alone, the two proven restore procedures, and the push to the workstation. Use before a test run, migration, bulk delete or any restore. |

`Frontend/AGENTS.md` holds the frontend rules for everyone; Claude Code reads it through
`Frontend/CLAUDE.md`. The text `CLAUDE.md` held before the split is kept verbatim in
[`docs/archive/engineering-record/`](docs/archive/engineering-record/README.md), with an index
from each original section to where it lives now.

`.pre-commit-config.yaml`, the architecture guardrails in
`Backend/scripts/architecture/` and the repository tests enforce many of these
rules and are authoritative for the rules they enforce.
