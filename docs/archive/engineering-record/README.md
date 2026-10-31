# Engineering record (CLAUDE.md before the instruction split)

On 30 Oct 2026 the repository's `CLAUDE.md` (5,157 lines, about 120k tokens loaded into every
Claude Code session) was split into a short global file, path-scoped rules under
`.claude/rules/`, task skills under `.claude/skills/`, and the frontend section of
`Frontend/AGENTS.md`. This folder keeps the file as it was, **verbatim and complete**, so that
no decision, measurement, incident or command is lost.

- **Source:** `CLAUDE.md` at `9bb84d9`, 5157 lines, SHA-256 `913763decb6d01d1f36cbfaaafee77dca257fadae64127b600c2f9e02ffcbe68`.
- **Frozen.** Nothing here is maintained. The live text is wherever the last column says; edit
  it there. A live rule may since have changed, and when it differs from this record the live
  text is right.
- **Provable.** Every file wraps its content in `<!-- verbatim: CLAUDE.md@9bb84d9 lines A-B -->`
  blocks. `Backend/tests/repo/test_engineering_record_archive.py` reassembles them, checks they
  cover every line exactly once, and compares the SHA-256 above.
- **Not formatted.** `.pre-commit-config.yaml` excludes this folder from Prettier, which would
  otherwise re-pad the tables and re-wrap code spans.

Content that lives **only** here (each with its reason; everything else is also live):

| Original lines | Reason |
| --- | --- |
| 1–45 | Superseded by the new organisation section of CLAUDE.md; its rules (the check-wins rule, the history caveats) are restated there |
| 149–176 | Known test-suite failures: the three resolved entries and how each was resolved; history |
| 1284–1340 | What the 13-14 Oct releases changed, live verification of those releases, test-data removal: release evidence |
| 1433–1470 | Scanner worker and database on the retired Windows host; marked as history in the original |

## Index of the original sections

| Original lines | Section | Archive file | Live location |
| --- | --- | --- | --- |
| 3–45 | How these instructions are organised | [`core-instructions.md`](core-instructions.md) | archive only, lines 3–45 |
| 46–60 | Commits made by AI agents | [`core-instructions.md`](core-instructions.md) | `CLAUDE.md` |
| 61–115 | ⚠️ Running the test suite | [`core-instructions.md`](core-instructions.md) | `CLAUDE.md` |
| 116–148 | Test targeted-first (AI agents and developers) | [`core-instructions.md`](core-instructions.md) | `CLAUDE.md` |
| 149–176 | Known test-suite failures | [`core-instructions.md`](core-instructions.md) | archive only, lines 149–176 |
| 177–235 | UI semantic integrity | [`core-instructions.md`](core-instructions.md) | `CLAUDE.md` |
| 236–261 | Test layout | [`core-instructions.md`](core-instructions.md) | `.claude/rules/backend-tests.md` |
| 262–620 | Architecture guardrails (modular-platform programme) | [`architecture-guardrails.md`](architecture-guardrails.md) | `.claude/rules/architecture-boundaries.md`; `.claude/rules/identity-platform.md` |
| 621–641 | Audit boundary layers (`Backend/ccure_audit/`) — Phase 5 | [`modules-and-contracts.md`](modules-and-contracts.md) | `.claude/rules/modules-contracts.md` |
| 642–714 | Core modules: Policy Pro, Audit, Rank (Phase 11) | [`modules-and-contracts.md`](modules-and-contracts.md) | `.claude/rules/modules-contracts.md` |
| 715–866 | RBAC capability (`ccure_platform/rbac/`) — **the only authorization model since RBAC-8** | [`identity-and-rbac.md`](identity-and-rbac.md) | `.claude/rules/identity-platform.md` |
| 867–906 | Backend platform extraction (backend alignment, steps 1–2) | [`identity-and-rbac.md`](identity-and-rbac.md) | `.claude/rules/identity-platform.md` |
| 907–1033 | Frontend modules (Phase 12) | [`frontend-modules.md`](frontend-modules.md) | `Frontend/AGENTS.md` |
| 1034–1072 | Integration contracts (`Backend/ccure_contracts/`) — Phase 4, draft | [`modules-and-contracts.md`](modules-and-contracts.md) | `.claude/rules/modules-contracts.md` |
| 1073–1090 | Where things live | [`core-instructions.md`](core-instructions.md) | `CLAUDE.md` |
| 1091–1226 | Deployment: Linux VM (`ccurepro`, 10.180.22.127) — since 17 Sep 2026 | [`deployment-linux-vm.md`](deployment-linux-vm.md) | `.claude/rules/deployment.md` |
| 1227–1360 | Releases (since 13 Oct 2026) | [`releases.md`](releases.md) | `.claude/rules/deployment.md`; `.claude/skills/release/SKILL.md`; archive only, lines 1284–1340 |
| 1361–1419 | Backups on the VM | [`backups.md`](backups.md) | `.claude/skills/db-backup-restore/SKILL.md` |
| 1420–1981 | Architecture | [`runtime-architecture-and-edge-security.md`](runtime-architecture-and-edge-security.md) | `.claude/rules/deployment.md`; `.claude/rules/api-security.md`; `.claude/rules/edge-gateway.md`; archive only, lines 1433–1470 |
| 1982–2079 | A scan must always reach a terminal state | [`scan-lifecycle.md`](scan-lifecycle.md) | `.claude/rules/scan-lifecycle.md` |
| 2080–2100 | Scan pipeline | [`scan-lifecycle.md`](scan-lifecycle.md) | `.claude/rules/scan-lifecycle.md` |
| 2101–2149 | Windows credentialed collection (`engines/credentialed/winrm_executor.py`) | [`credentialed-collection.md`](credentialed-collection.md) | `.claude/rules/credentialed.md` |
| 2150–2238 | Windows over SMB / Remote Registry / WMI (`engines/credentialed/smb_executor.py`) | [`credentialed-collection.md`](credentialed-collection.md) | `.claude/rules/credentialed.md` |
| 2239–2276 | Credential authentication methods | [`credentialed-collection.md`](credentialed-collection.md) | `.claude/rules/credentialed.md` |
| 2277–2376 | Credentialed transport and port resolution (`engines/credentialed/transport_resolver.py`) | [`credentialed-collection.md`](credentialed-collection.md) | `.claude/rules/credentialed.md` |
| 2377–2448 | Elevation on the credentialed path | [`credentialed-collection.md`](credentialed-collection.md) | `.claude/rules/credentialed.md` |
| 2449–2512 | Scan scheduling (`core/scheduling/`) | [`scan-lifecycle.md`](scan-lifecycle.md) | `.claude/rules/scan-lifecycle.md` |
| 2513–2629 | Configuration audit engine (`core/config_audit/`) | [`configuration-audit.md`](configuration-audit.md) | `.claude/rules/config-audit.md` |
| 2630–2718 | Benchmark content (`core/benchmarks/`) | [`configuration-audit.md`](configuration-audit.md) | `.claude/rules/config-audit.md` |
| 2719–2798 | Local privilege checks (`core/config_audit/collectors/privilege_*.py`) | [`configuration-audit.md`](configuration-audit.md) | `.claude/rules/config-audit.md` |
| 2799–2861 | Middleware configuration assessment (`core/config_audit/structured.py`) | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 2862–2885 | Five things real containers settled, each of which had shipped looking right | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 2886–2905 | Content | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 2906–2930 | Test targets | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 2931–2938 | Coverage | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 2939–3001 | Container and Kubernetes assessment (`core/config_audit/containers.py`) | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 3002–3018 | Three things real targets settled | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 3019–3029 | Content | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 3030–3058 | Test targets | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 3059–3066 | Coverage | [`middleware-and-containers.md`](middleware-and-containers.md) | `.claude/rules/middleware-containers.md` |
| 3067–3133 | STIG and SCAP content (`core/scap/`) | [`stig-scap.md`](stig-scap.md) | `.claude/rules/scap.md` |
| 3134–3161 | Applicability is not optional, and the measurement says so | [`stig-scap.md`](stig-scap.md) | `.claude/rules/scap.md` |
| 3162–3202 | Six defects real content found, and one a warning found | [`stig-scap.md`](stig-scap.md) | `.claude/rules/scap.md` |
| 3203–3237 | Validation | [`stig-scap.md`](stig-scap.md) | `.claude/rules/scap.md` |
| 3238–3252 | Coverage | [`stig-scap.md`](stig-scap.md) | `.claude/rules/scap.md` |
| 3253–3353 | The Windows OVAL schema (Phase 15) | [`stig-scap.md`](stig-scap.md) | `.claude/rules/scap.md` |
| 3354–3370 | Reporting is part of done | [`stig-scap.md`](stig-scap.md) | `.claude/rules/scap.md` |
| 3371–3491 | Scan policy (`core/scan_policy/`) | [`scan-policy.md`](scan-policy.md) | `.claude/rules/scan-policy.md` |
| 3492–3606 | Remediation and SLA (`core/remediation/`) | [`findings-and-remediation.md`](findings-and-remediation.md) | `.claude/rules/findings-remediation.md` |
| 3607–3720 | Exports (`reporting/exports.py`, `reporting/xlsx_generator.py`) | [`reporting-and-exports.md`](reporting-and-exports.md) | `.claude/rules/reporting.md` |
| 3721–3825 | Scan comparison and finding lifecycle (`core/findings/`) | [`findings-and-remediation.md`](findings-and-remediation.md) | `.claude/rules/findings-remediation.md` |
| 3826–3879 | Assessment framework (`core/checks/`) | [`checks-network-tls.md`](checks-network-tls.md) | `.claude/rules/checks-network-tls.md` |
| 3880–3951 | Data model notes | [`findings-and-remediation.md`](findings-and-remediation.md) | `.claude/rules/findings-remediation.md` |
| 3952–4121 | Vulnerability feeds (`vuln_intel`) | [`vulnerability-feeds.md`](vulnerability-feeds.md) | `.claude/rules/vuln-feeds.md` |
| 4122–4209 | Network checks (`engines/vulnerability/network_checks.py`) | [`checks-network-tls.md`](checks-network-tls.md) | `.claude/rules/checks-network-tls.md` |
| 4210–4310 | Database assessment (`engines/credentialed/database_executor.py`) | [`database-assessment.md`](database-assessment.md) | `.claude/rules/database-assessment.md` |
| 4311–4345 | Content, and the false positives real targets caught | [`database-assessment.md`](database-assessment.md) | `.claude/rules/database-assessment.md` |
| 4346–4374 | Test targets | [`database-assessment.md`](database-assessment.md) | `.claude/rules/database-assessment.md` |
| 4375–4390 | Coverage | [`database-assessment.md`](database-assessment.md) | `.claude/rules/database-assessment.md` |
| 4391–4475 | Deep TLS on the network path | [`checks-network-tls.md`](checks-network-tls.md) | `.claude/rules/checks-network-tls.md` |
| 4476–4520 | Active template verification (Nuclei) | [`checks-network-tls.md`](checks-network-tls.md) | `.claude/rules/checks-network-tls.md` |
| 4521–4543 | Test targets | [`checks-network-tls.md`](checks-network-tls.md) | `.claude/rules/checks-network-tls.md` |
| 4544–4553 | Coverage figures | [`checks-network-tls.md`](checks-network-tls.md) | `.claude/rules/checks-network-tls.md` |
| 4554–4575 | Windows assessment | [`credentialed-collection.md`](credentialed-collection.md) | `.claude/rules/credentialed.md` |
| 4576–4659 | Policy Compliance Engine | [`policy-compliance.md`](policy-compliance.md) | `.claude/rules/compliance.md` |
| 4660–4718 | ISO/IEC 27001:2022 | [`policy-compliance.md`](policy-compliance.md) | `.claude/rules/compliance.md` |
| 4719–4834 | Which frameworks are switched on | [`policy-compliance.md`](policy-compliance.md) | `.claude/rules/compliance.md` |
| 4835–4913 | NIST CSF 2.0 | [`policy-compliance.md`](policy-compliance.md) | `.claude/rules/compliance.md` |
| 4914–5056 | File uploads | [`file-uploads.md`](file-uploads.md) | `.claude/rules/uploads.md` |
| 5057–5144 | Audit-log retention (phase 6a) | [`audit-log-retention.md`](audit-log-retention.md) | `.claude/rules/audit-retention.md` |
| 5145–5157 | Reports | [`reporting-and-exports.md`](reporting-and-exports.md) | `.claude/rules/reporting.md` |

## Corrections since the split

Statements in the live files that were corrected after the split, on evidence
recorded below. The original wording stays in the verbatim blocks above;
`scripts/docs/check_instruction_preservation.py` reads this table and reports
these lines as corrected rather than missing. A row is added here in the same
change as the correction.

| Original lines | Live file | Correction | Evidence (31 Oct 2026) |
| --- | --- | --- | --- |
| 664–665 | `.claude/rules/modules-contracts.md` | 282 → 284 API routes, with the table's history; the 286 `app.routes` figure dated 7 Oct and marked not re-measured | `route_table.json` held 282 entries at `a12fb6e` (3 Oct), 285 at `ef58cfc` (11 Oct), 284 at `d8a6294` (12 Oct, unchanged since); `test_gateway_route_policy.py` pins the total at 284 and passes |
| 1075–1079 | `CLAUDE.md` | thirteen → fourteen seed files | `Backend/data/compliance_seeds/` holds 14 `*_controls_seed.json`; `main.py` names 14 (HIPAA added 28 Sep 2026) |
| 4792–4792 | `.claude/rules/compliance.md` | thirteen → fourteen seed files | As above |
| 1917–1918 | `.claude/rules/edge-gateway.md` | The application is reached at `https://10.180.22.127`, a temporary address until an approved domain is available (owner, 31 Oct 2026); `ccurepro.cdac.in` described as unpublished, `ccurepro.cdacb.in` as the Windows deployment's | Host nginx `server_name ccurepro.cdac.in 10.180.22.127 localhost`; the certificate's SAN is `ccurepro.cdac.in`, `localhost`, 10.180.22.127, 127.0.0.1; `ccurepro.cdac.in` resolves only through the VM's `/etc/hosts` (`resolvectl`: synthetic), and the owner states it is not an available domain; `ccurepro.cdacb.in` does not resolve |
| 1133–1133 | `.claude/rules/deployment.md` | The app is `https://10.180.22.127`, temporary until an approved domain is available | As above |
| 1247–1251 | `.claude/skills/release/SKILL.md` | The post-start check polls `https://10.180.22.127/api/` | As above; host nginx serves the IP as a `server_name` |
| 1922–1927 | `.claude/rules/edge-gateway.md` | The private address named for both deployments | As above; the Windows host address 10.180.6.14 is retired (backups push to 10.180.6.30) |
| 1937–1940 | `.claude/rules/edge-gateway.md` | HSTS note covers both IP literals; "`FRONTEND_URL` is the hostname" restated as Windows-era, with the VM's value `https://10.180.22.127`, kept by the owner's decision of 31 Oct 2026 as a temporary address; the `ccurepro.cdac.in` token and schema identifiers explained | `FRONTEND_URL=https://10.180.22.127` in the root `.env`, `Backend/.env` and the running api's environment |
| 2074–2074 | `.claude/rules/scan-lifecycle.md` | The start-script and "restart the host worker" notes marked as the Windows deployment's, with the VM's release path | `ccure-worker` mounts no source (`/backups`, `/app/.env`, logs, reports, evidence, feeds, `cves.db`, the CA certificate); code arrives only as an image |

Additions made at the same time, which change no original line: a history note
under each "Test targets" heading (database-assessment, checks-network-tls,
middleware-containers twice); the VM feed schedule in `vuln-feeds.md`; the VM
schedule scripts in `CLAUDE.md`'s reading note; the recorded `AppLayout`
intermittent test under "Known test-suite failures"; the release ledger rows
after `72eb2bb` and their sources in the `release` skill.

## Open verification register (30 Oct 2026, re-checked 31 Oct 2026)

What each statement carried into the live files turned out to be. Status is one
of *confirmed current*, *confirmed historical*, *incorrect* or *requires owner
confirmation*; "Done" names the correction above, where one was made.

| # | Statement (live file) | Evidence, 31 Oct 2026 | Status | Done |
| --- | --- | --- | --- | --- |
| 1 | App reached at `ccurepro.cdacb.in` (edge-gateway, TLS) | Not on the VM's nginx or certificate and does not resolve; `cdacb.in` remains only in the Windows-era `scripts/host-nginx/nginx-host.conf` and `scripts/tls/*.ps1`. `ccurepro.cdac.in` resolves only through the VM's `/etc/hosts` and is not an available domain (owner, 31 Oct 2026) | Incorrect for the VM; confirmed historical for Windows | Corrected (1917–1918, 1133, 1247–1251): the application URL is `https://10.180.22.127` |
| 2 | Host address `10.180.6.14` (edge-gateway, TLS) | Retired; the workstation is 10.180.6.30 (backup crontab) and the VM is 10.180.22.127 | Confirmed historical | Marked (1922–1927, 1937–1940) |
| 3 | "`FRONTEND_URL` is the hostname" (edge-gateway, TLS) | `FRONTEND_URL=https://10.180.22.127` in both `.env` files and the running api | Incorrect for the VM as configured | Corrected (1937–1940). **Decided 31 Oct 2026 (owner): keep `https://10.180.22.127`**, temporary until an approved domain is available; no configuration was changed |
| 4 | Release ledger ends at `72eb2bb` (`release` skill) | Release directories for `3212d6b`, `84bad17`, `9040eb9`, `a835ad5`, `f5c6e88`; running backend `1a83ead7972d` and frontend `5e3bd5018467` are `f5c6e88`'s | Incorrect (incomplete) | Rows added from the directories; three frontend-only releases record no time or outage and say so. Investigated 31 Oct 2026: `rbac-release-2f3523db…` was `48879df`'s fallback candidate, never deployed, its images deleted on 15 Oct; the 29 Oct 05:19 UTC event was an explicit stop-and-start of eight containers, not a release. **Who issued it requires root-readable logs** (the release skill names them) |
| 5 | "the thirteen `*_controls_seed.json` files" (`CLAUDE.md`; compliance) | 14 files; `main.py` names 14 | Incorrect | Corrected (1075–1079, 4792) |
| 6 | "282 API routes" (modules-contracts) | 284 since `d8a6294`, pinned by a passing test | Incorrect | Corrected (664–665); `len(app.routes)` on the live installation not re-measured |
| 7 | Known test-suite failures: none (`CLAUDE.md`) | The refactoring log records the intermittent frontend `AppLayout` test as open (F1 and its follow-up list) | Incorrect (incomplete) | Added under "Known test-suite failures" |
| 8 | "Restart the host worker after changing anything under `core/`, `scans/` or `orchestrator/`" (scan-lifecycle) | The worker mounts no source; code is baked into the image since 13 Oct 2026 | Confirmed historical; incorrect on the VM | Marked (2074) |
| 9 | Test-target containers and PowerShell commands (middleware-containers, database-assessment, checks-network-tls) | None of the 12 named containers exists; four `ccure-validation-*` containers run | Confirmed historical | History note added under each heading |
| 10 | pgAdmin, DBeaver and the tunnel key on the workstation (deployment) | VM side re-checked 31 Oct 2026: one `authorized_keys` entry, `ccure-vm-tunnel@pankaj`, with exactly the documented `restrict,port-forwarding,permitopen=…5432,…9443,command="/bin/false"`; no pgAdmin or DBeaver session connected | VM side confirmed current; **workstation side requires the workstation** | Recorded in the deployment rule's open issues |
| 11 | "feed-schedule scripts were retired" (`CLAUDE.md` reading note) | True of the Windows scripts. The VM schedule is `scripts/install_feed_schedule.sh` → `scripts/run_feed_sync.sh`, four crontab entries, all four exiting 0 on 31 Oct; no live instruction described it | Confirmed historical; the VM schedule was undocumented | Documented in `vuln-feeds.md`; reading note names the VM scripts |
| 12 | Containers never read `Backend/.env`; host scripts do (identity-platform, vuln-feeds) | `SKIP_DOTENV_LOAD=1` in api, worker, web-worker and beat; `config.py` loads `Backend/.env` only when it is unset | Confirmed current | None needed |
| 13 | Portainer on `127.0.0.1:9443`, the api publishes no port, PostgreSQL on `127.0.0.1:5432`, `PGSSLMODE=disable`, one beat, `COMPOSE_PROFILES=container-scanner` | Observed on the running containers and `.env` | Confirmed current | None needed |
| 14 | HS256 and `JWT_SECRET_KEY` are gone (identity-platform) | Only docstring history in `ccure_platform/identity/`; neither key in either `.env` | Confirmed current | None needed |

Found while verifying, outside the 14: `docs/FRONTEND_ARCHITECTURE.md`
described `isSuperAdmin`, `hasRole`, `superadminOnly`, a superadmin bypass in
`can()`, the `resource:manage` wildcard and the legacy `resource:action`
permission atoms, all of which RBAC-6/8 removed. Codex flagged it during the
31 Oct instruction check; it was corrected on 31 Oct 2026 against
`shell/auth/authorization.js`, `PrivateRoute.jsx`, `navVisibility.js`,
`AuthContext.jsx`, `App.jsx`, Audit's sidebar and access fallbacks, and the
tests under `__tests__/shell/auth/`.
