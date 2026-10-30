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
