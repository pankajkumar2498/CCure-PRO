# CCure Audit PRO plugin remediation — 14 October 2026

The 15 confirmed conditions D01–D15 have code fixes and corrected regression
assertions. No defect is deferred. Execution failures and missing evidence remain
visible as incomplete coverage; passing tests do not establish production
readiness, independent vendor verification, or Nessus parity.

The baseline is the completed [audit](../plugin-audit-2026-10-14/REPORT.md),
[inventory](../plugin-audit-2026-10-14/INVENTORY.md),
[Nessus comparison](../plugin-audit-2026-10-14/NESSUS_COMPARISON.md), and
[test report](../plugin-audit-2026-10-14/TEST_REPORT.md). All four were read before
changes. The baseline audit describes revision
`6d816e23dcbc61a4f96ff106af1f0bc3a1c44ce1`; the remediation began on
`ef63e5ad2addf08ef3b7c4a8970188f13b94f095` with existing branding edits and the audit
directory present. Historical audit scripts and results remain historical
evidence, not acceptance tests for corrected behavior.

## Resolutions, in remediation order

Test references below point to
[P0 regressions](../../../Backend/tests/scans/test_plugin_remediation_p0.py),
[P1 regressions](../../../Backend/tests/scans/test_plugin_remediation_p1.py), and
[pipeline regressions](../../../Backend/tests/scans/test_plugin_remediation_pipeline.py).
Parametrized cases include positive, negative, unsupported, error, and malformed
responses as applicable. Original assertions that demonstrated defective behavior
are inverted in these regressions.

| Defect                                           | Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Corrected regression evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **D06, P0 — DNS evidence**                       | AXFR requires an actual non-root authoritative zone, an authoritative response, matching opening/closing SOAs, bounded in-zone records, and no records after closure. Empty NOERROR and incomplete transfers are unknown. Recursion requires a valid response to the external question and relevant answer evidence.                                                                                                                                                                    | P0 `test_d06_complete_authoritative_axfr_has_boundaries_and_zone`, `test_d06_empty_or_incomplete_axfr_is_unknown_not_vulnerable`, `test_d06_refused_and_timeout_are_distinct`, `test_d06_root_zone_is_unsupported`, `test_d06_recursion_requires_a_valid_external_answer`.                                                                                                                                                                                                           |
| **D07, P0 — LDAP evidence and LDAPS**            | Anonymous bind and rootDSE access do not prove directory disclosure. A bounded search on the same anonymous connection must return an actual non-rootDSE entry with directory attributes. LDAPS uses TLS. Access denial, unsupported driver, timeout, and protocol errors retain distinct outcomes. UI and report labels require `directory_readable === true`.                                                                                                                         | P0 `test_d07_bind_and_rootdse_do_not_prove_directory_disclosure`, `test_d07_ldaps_uses_tls_and_refused_bind_is_negative`; corrected network-promotion tests and Phase3 UI tests.                                                                                                                                                                                                                                                                                                     |
| **D08, P0 — MongoDB protocol and authorization** | PyMongo constructs valid modern wire messages. Only successful decoded `listDatabases` results from the authorization-requiring command support unauthenticated database access. Handshake replies, `ok: 0`, malformed database lists, and driver failures do not.                                                                                                                                                                                                                      | P0 `test_d08_command_success_and_decoded_database_list_are_required`, `test_d08_driver_errors_do_not_become_clean_or_vulnerable`, `test_d08_real_driver_uses_valid_modern_op_msg_against_local_fixture` for allowed/refused authorization.                                                                                                                                                                                                                                           |
| **D09, P0 — execution visibility**               | Every selected plugin receives a structured outcome. Import failures, invalid returns, exceptions, timeouts, skips, unsupported targets, and partial results are visible. Legacy results without completion evidence remain incomplete. Findings can survive failed or partial execution. Outcomes and coverage survive host formatting, phase snapshots, scan APIs, live/history UI, JSON/XLSX exports and PDF reports. Incomplete scans do not retire existing network findings.      | P0 `test_d09_errors_have_outcomes_and_cannot_assert_clean`, `test_d09_completed_empty_partial_and_skipped_remain_distinct`, `test_d09_invalid_plugin_result_is_a_failed_assessment`, `test_d09_invalid_targets_fail_before_any_plugin_dispatch`; pipeline `test_d09_failed_outcome_survives_persistence_scan_api_and_exports`, `test_d09_incomplete_scan_does_not_retire_existing_findings`, `test_d09_completed_negative_can_retire_previous_finding`; coverage unit/browser tests. |
| **D13, P0 — credential scope**                   | The entire credential plan is validated before any secret resolution. Supplied scope must be a nonempty list of canonical IP addresses/networks. Null, empty, hostname, host-bit network, invalid type, and unknown fields fail closed. Invalid target IPs cannot match credentials. Omission retains global matching only within admitted scan targets. API requests reject malformed scope before task dispatch; workers also fail closed. Tenant-aware resolution remains unchanged. | P0 `test_d13_supplied_invalid_scope_is_rejected_before_secrets`, `test_d13_valid_and_omitted_scopes_preserve_intended_matching`, `test_d13_unknown_scope_keys_cannot_be_misread_as_omitted_scope`; pipeline `test_d13_invalid_scope_is_rejected_by_api_before_dispatch`; existing enrichment and credential transport tests.                                                                                                                                                         |
| **D15, P0 — import isolation**                   | Plugin exports load lazily. A missing dependency or failed import affects only that plugin and is recorded as unsupported/failed coverage. Other eligible plugins continue. Existing public exports and run2/run3 contracts remain.                                                                                                                                                                                                                                                     | P0 `test_d15_fresh_import_failure_affects_only_requested_plugin`; existing plugin-contract tests.                                                                                                                                                                                                                                                                                                                                                                                    |
| **D01, P1 — HTTP/HTTPS selection**               | HTTPS-only services select HTTP analysis, and both HTTP and HTTPS endpoints are examined with the correct scheme, including detected custom ports. Multi-endpoint results retain the existing primary result keys.                                                                                                                                                                                                                                                                      | P1 `test_d01_https_only_selects_http_analysis`, `test_d01_d02_all_http_and_https_endpoints_are_probed`.                                                                                                                                                                                                                                                                                                                                                                              |
| **D02, P1 — authentication-check selection**     | HTTP/HTTPS services select the implemented authentication check. A Basic challenge is required before bounded default pairs are sent. Public pages, unsupported auth schemes, redirects, and request failures cannot become a default-password finding. TLS and custom web ports use their detected identity.                                                                                                                                                                           | P1 `test_d02_web_only_selects_authentication_check`, `test_d02_real_basic_auth_positive_negative_and_unsupported`, `test_d01_d02_all_http_and_https_endpoints_are_probed`.                                                                                                                                                                                                                                                                                                           |
| **D03, P1 — transport and service identity**     | Selection preserves TCP/UDP and discovered service identity. UDP port numbers do not select TCP probes. Known conflicting service identity overrides a conventional port guess. The Nmap parsers retain SSL tunnel identity in the existing service value. HTTP, SSH, LDAP, FTP, SMB, TLS and authentication probes receive actual eligible endpoints. FTP evidence requires an FTP banner.                                                                                             | P1 `test_d03_udp_numbers_do_not_dispatch_tcp_probes`, `test_d03_service_identity_overrides_number_and_reaches_custom_port`, `test_d03_nmap_xml_retains_tls_service_identity`, `test_d03_python_nmap_retains_tls_service_identity`, `test_d03_ftp_custom_endpoints_require_ftp_evidence`; existing topology/TLS tests.                                                                                                                                                                |
| **D04, P1 — late UDP discovery**                 | One bounded follow-up selects DNS when UDP discovery makes it newly eligible. Previously attempted DNS, including failed imports, is not executed twice. There is no recursive scheduling loop or repeat UDP discovery.                                                                                                                                                                                                                                                                 | P1 `test_d04_late_udp_discovery_dispatches_dns_once`, with and without initially eligible DNS.                                                                                                                                                                                                                                                                                                                                                                                       |
| **D05, P1 — SSH framing and algorithms**         | Bounded exact reads handle fragmented banners and packets. KEXINIT validates all ten name-lists and reads client/server cipher lists at indices 2/3 and MAC lists at 4/5. Truncated, invalid, and unsupported protocol responses remain failed/unsupported.                                                                                                                                                                                                                             | P1 `test_d05_correct_directional_mac_lists_and_fragmented_reads`, `test_d05_unsupported_or_truncated_ssh_does_not_assert_clean`.                                                                                                                                                                                                                                                                                                                                                     |
| **D10, P1 — endpoint evidence integrity**        | Each endpoint is verified before findings are aggregated by logical identity. Distinct port/protocol/path/service observations and proofs survive normalization, persistence, authenticated API retrieval and export. The existing primary service FK remains compatible; other service bindings are retained in endpoint observations and evidence. Long evidence is not truncated across endpoints. Explicitly derived evidence stays derived.                                        | P1 `test_d10_dedup_retains_both_endpoint_evidence_and_paths`, `test_d10_each_endpoint_is_verified_before_logical_aggregation`, `test_d10_aggregation_does_not_relabel_derived_evidence_as_captured`; pipeline `test_d10_endpoint_evidence_survives_verification_db_api_and_export`.                                                                                                                                                                                                  |
| **D11, P1 — active-probe prerequisites**         | Eligible HTTP/HTTPS and implicit/STARTTLS services select applicable probes. A negative first endpoint does not stop later endpoints. Heartbleed requires complete framed handshake evidence and negotiated heartbeat permission, then validates an actual heartbeat response and payload. Shellshock requires nonce execution evidence plus a reflection control. Redirects do not forward the active request.                                                                         | P1 `test_d11_supported_active_probe_ports_are_selected`, `test_d11_first_negative_does_not_hide_second_affected_endpoint`, `test_d11_coalesced_handshake_fragmented_tls_and_actual_heartbeat_payload`, `test_d11_no_heartbeat_negotiation_means_no_active_request`, `test_d11_shellshock_requires_execution_and_negative_reflection_control`.                                                                                                                                        |
| **D12, P1 — SMB framing**                        | Requests have the correct SMB header, word/byte counts, dialect data and derived NetBIOS length. Bounded reads validate successful SMB1/SMB2 negotiation replies. Port 139 first requires an accepted NetBIOS session; retargets are not followed. Negotiation alone does not claim null-session access.                                                                                                                                                                                | P1 `test_d12_correct_request_is_accepted_by_length_aware_local_smb_fixture`, `test_d12_malformed_or_error_reply_does_not_claim_smbv1`, `test_d12_netbios_session_must_be_established_first`.                                                                                                                                                                                                                                                                                         |
| **D14, P1 — partial Nuclei results**             | Valid JSONL matches survive nonzero exit, timeout and malformed neighboring lines. Nonzero exits including 1, fatal stderr, and missing binaries/templates produce failed/unsupported/incomplete outcomes. Successful empty execution is distinct. `nuclei_templates_run` is true only for completed execution.                                                                                                                                                                         | P1 `test_d14_partial_nuclei_matches_survive_error_and_timeout`, `test_d14_empty_result_requires_successful_execution`, `test_d14_malformed_lines_do_not_discard_valid_partial_matches`.                                                                                                                                                                                                                                                                                              |

## Outcome semantics and compatibility

The outcome ledger uses `completed_with_findings`, `completed_with_no_findings`,
`skipped`, `unsupported`, `failed`, and `timed_out`. It also carries
`coverage_complete`, endpoint context and a bounded detail message. Verified
finding counts are reconciled after promotion. A completed empty result applies
only to the executed checks and their supported scope. It is not a whole-host
security assessment. Findings remain visible when execution is incomplete.

`plugin_outcomes`, `plugin_coverage`, `network_plugin_coverage`, and endpoint
observations are additive JSON/report fields. Existing routes, database tables,
migrations, logical finding identities and legacy primary result keys remain.
Authentication, RBAC, tenant-aware credential resolution and scan policies are
preserved. Invalid credential scope now returns validation failure intentionally.
Network plugins remain separate from credentialed assessment, configuration
auditing and web scanning. No plugin architecture rewrite was performed.

The UI uses existing CCure components and the unchanged UX4G 3.0.2 baseline.
The authorization inventory update contains source-location offsets, without
permission changes. The historical-report browser fixture now supplies the
actual read-only scan API response; view-only protections were not relaxed.

The [owned source file list](changed-files.txt) and
[source SHA256 manifest](source-manifest.json) identify this remediation.
Other branding, registry, architecture and documentation edits appeared in the
shared working tree and were preserved. They are not represented as plugin
remediation changes. No commit, merge or deployment was performed by this task.

## Validation and independent runtime limits

Exact commands, counts, corrected intermediate failures and evidence hashes are
in [TEST_REPORT.md](TEST_REPORT.md) and [test-summary.json](test-summary.json).

| Final check                                                  |    Passed | Failed | Skipped |
| ------------------------------------------------------------ | --------: | -----: | ------: |
| Relevant Backend suite, including architecture/schema guards |     4,779 |      0 |       0 |
| Final focused negative regressions and report integrity      |       169 |      0 |       0 |
| Frontend unit suite (122 files)                              |     3,171 |      0 |       0 |
| Full Chromium browser suite                                  |       240 |      0 |       0 |
| Coverage feature: Chromium / Firefox / WebKit                | 4 / 4 / 4 |      0 |       0 |

Focused tests and Chromium feature tests overlap their full suites; their counts
are not added as unique acceptance tests. Python/Frontend lint, high-severity
Bandit, Gitleaks, UX4G and authorization-inventory checks passed. The dependency
audit found zero new unaccepted advisories, with four existing accepted ASN.1
advisories retained.

| Capability                 | Evidence obtained                                                                                                     | Independent runtime status                                                                             |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| HTTP Basic authentication  | Real loopback HTTP server; positive credentials, public page and unsupported challenge; HTTP/HTTPS selection doubles  | HTTP Basic loopback verified; HTTPS authentication against an independent vendor target **unverified** |
| MongoDB wire/authorization | Actual PyMongo OP_MSG exchange with a local length-aware synthetic server; authorization success/refusal              | Driver wire exchange verified; independent MongoDB deployment **unverified**                           |
| SMB negotiation            | Real local TCP exchange with a length-aware synthetic SMB1/SMB2 server and fragmented replies                         | Synthetic framing verified; independent SMB server and patch-state detection **unverified**            |
| DNS AXFR/recursion         | Protocol message fixtures and driver doubles for authoritative boundaries, refusal, timeout and invalid answers       | Independent authoritative/recursive DNS runtime **unverified**                                         |
| LDAP/LDAPS                 | LDAP driver/session fixtures for bind, rootDSE, directory reads, TLS selection and denial                             | Independent LDAP/LDAPS directory runtime **unverified**                                                |
| SSH                        | Fragmented packet/banner fixtures and both-direction algorithm assertions                                             | Independent SSH server runtime **unverified**                                                          |
| Heartbleed/Shellshock      | Framed TLS fixtures, handshake prerequisite checks, actual heartbeat-payload checks and reflection/execution controls | Vulnerable and patched OpenSSL/CGI lab targets **unverified**                                          |
| Nuclei                     | Process doubles verify partial/error handling; the baseline audit separately exercised one authored loopback template | Full deployed template corpus, coverage and Nessus equivalence **unverified**                          |
| Persistence/API/export     | Dedicated PostgreSQL test DB, authenticated scan/finding APIs, JSON/XLSX and PDF flowable assertions                  | Tested pipeline seams verified; production-data acceptance **unverified**                              |
| Scan coverage UI           | Unit tests and Chromium/Firefox/WebKit feature tests at 320/1440px in light/dark modes, keyboard and axe checks       | Automated engine checks verified; manual screen-reader review and branded Safari **unverified**        |

All network fixtures use mocks or loopback. No unauthorized external target was
scanned, and no intrusive check was dispatched through a live scan worker.

## Remaining limitations and release requirements

- Some existing deep protocol helpers do not expose independently established
  completion evidence. Their findings remain usable, but their outcomes remain
  incomplete/unverified rather than clean. DNS auto-discovery uses an
  authoritative reverse-zone SOA; forward-only zone enumeration is not proved.
  AXFR has a 256-record and five-second budget. TLS enumeration retains its
  existing budget. Shellshock checks the selected root endpoint.
- Incomplete network coverage conservatively prevents automatic retirement of
  prior network findings. This can retain old findings until a complete
  assessment or authorized review. Endpoint aggregation preserves all proof
  while retaining one primary service FK for compatibility.
- Plugin-owned network/subprocess operations are bounded. A general forced
  cancellation mechanism for an arbitrary hung Python plugin thread is outside
  this change; it is not represented as independently verified timeout handling.
- Four distinct existing accepted ASN.1 advisories remain under the repository's
  pre-existing exceptions. The newly audited protocol-driver dependency set has
  no new unaccepted advisory. No security exception or dependency constraint was
  weakened to obtain a pass.
- Deployment must use the normal reviewed release process. Rebuild the backend
  dependency/base image to include `ldap3>=2.9.1,<3` and `pymongo>=4.10,<5`, while
  retaining `pyasn1>=0.4.8,<0.6.0`; rebuild API and scanning workers from the same
  release source. Build frontend assets with `VITE_API_BASE_URL=/api` and the
  pinned package lock/UX4G baseline. Take the required backup and perform
  authorized staging/vendor-lab acceptance before release. There is no new
  database migration; rollback uses coherent prior application images.

All confirmed defect conditions have resolutions above. Runtime verification
limits are explicit and are not approved defect deferrals or claims of Nessus
parity.
