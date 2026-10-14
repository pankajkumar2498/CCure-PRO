# CCure Pro plugin audit and Nessus capability comparison

Audit date: **14 October 2026 (India time)**. Source baseline:
`6d816e23dcbc61a4f96ff106af1f0bc3a1c44ce1`. This assesses the checked-out
scanner source, not historical claims in CLAUDE.md. The scanner's deployed code
is baked into its image; tests ran against a temporary copy of this checkout.
No production scanner code, API, schema, credential, policy or deployment was
changed. Existing user edits were preserved.

## Executive summary and verdict

**The system is partially functional and does not yet justify an unrestricted
production-readiness claim.** Real HTTP, TLS and Nuclei findings survived the
engine's verification and scoring on a controlled loopback fixture. The
configuration pipeline has explicit error/unavailable semantics, typed findings,
policy filtering, credential transports, package matching, persistence and
reporting, backed by substantial regression coverage. It is not an empty plugin
directory or a completely broken scanner.

However, **15 confirmed defect conditions** remain: **12 High and 3 Medium**,
with no demonstrated Critical defect. They include unreachable HTTP checks on
HTTPS-only hosts, incorrect SSH algorithm parsing, unsupported DNS/LDAP/MongoDB
vulnerability claims, malformed SMB framing, loss of endpoint evidence, and
credential scope widening after malformed input. The legacy engine also cannot
tell a failed plugin from one that returned no findings. Those are material
false-negative, false-positive and credential-control risks even though every
existing test in the relevant regression groups passes.

The right remediation is focused gate/parser/coverage fixes, followed by
independent weak-versus-hardened target validation. A scanner rewrite is not
warranted by this evidence. **No complete Nessus parity is established.**

## Exact counts and their meaning

Counts are separate denominators. A rule, a collector, an engine, a template and
a plugin module are not interchangeable units.

| Population / evidence class | Exact count | Criteria and evidence |
|---|---:|---|
| Legacy network plugin implementations | **15** | Python modules defining run() in engines/vulnerability/plugins; exclude __init__.py |
| Named in the real selector / callable and loadable | **15 / 15** | Selector tables + actual import/signature inspection in the container; 178 targeted tests |
| Structurally reachable through a supported scan path | **15 / 15** | Active-host engine path and at least one dispatch condition; reachability does not mean every supported endpoint selects the plugin |
| Whole legacy modules orphaned or missing a registry entry | **0** | All 15 files correspond to dispatch names; individual branches are unreachable as documented below |
| Legacy modules entirely disabled by source defaults | **0** | Subchecks are separately gated; anonymous FTP write is off by default |
| Legacy modules positively exercised with actual loopback services through detection -> normalization -> scoring in this audit | **3** | http_analyzer, tls_scanner, nuclei_probe; dependencies present; unrelated probes/feed queries explicitly replaced |
| Legacy modules independently verified through a real external host, dispatch, persistence, API and final report in one live run | **0** | That full deployed end-to-end experiment was not performed |
| Legacy modules with directly demonstrated partial/unreliable behavior | **10** | default_creds, dns_probe, heartbleed_probe, http_analyzer, ldap_probe, nuclei_probe, smb_probe, ssh_probe, tls_scanner, udp_scanner; shared error handling also affects the other five |
| Remaining legacy modules with no newly demonstrated module-specific failure and no adequate real-target proof | **5** | cve_engine, eternalblue_probe, ftp_checker, icmp_probe, snmp_probe; classify UNVERIFIED, not working |
| Legacy modules qualified as fully working across their advertised capabilities by this audit | **0 verified** | This is a proof count, not an assertion that all 15 fail |
| Metadata-only legacy modules | **2** | icmp_probe and udp_scanner emit intelligence, not normalized findings |
| Network catalogue check areas | **57** | Belong to 13 finding-producing modules; include two dynamic families, not all feed CVEs/templates |
| Unique built-in ConfigCheck definitions | **155** | Loaded builtin_checks() list and unique check_id count agree |
| Reusable configuration collector implementations / registered platform-type pairs | **28 / 29** | CollectorRegistry; one SCAP implementation serves both Windows and Linux |
| Individually live-target-verified built-in rules in this audit | **0** | Generic engine/pack/collector fixtures do not prove all 155 commands on real supported platforms |
| Built-in rules whose individual real-target status remains unverified | **155** | All accessible as source definitions; selected by credentials, platform, OS and policy |
| Built-in definitions with a direct literal check-ID reference in existing tests | **11** | String-search evidence only; **144 without such a literal are not 144 untested rules**: many tests enumerate packs or reference generated suffixes/areas |
| Baseline legacy modules lacking a direct module-named behavioral test reference | **2** | icmp_probe, udp_scanner; generic signature tests apply to both |
| Current database configuration rule rows / active rows | **955 / 955** | Read-only aggregate query on ccure_db; imported content, not 955 new code modules |
| Enabled tenant benchmark installations in that database | **0** | Hence benchmark content is not installed for selection there; active rule rows alone do not make those rules run |
| Source files in the detection-support manifest | **172** | AST symbol/path inventory; a manifest count, not a working-plugin count |

The 155 source rules break down as follows. Windows/Linux memberships overlap
on **36** middleware rules, so **56 + 86 + 49 = 191 memberships**, not 191 rules.

| Built-in pack | Unique checks |
|---|---:|
| Windows host / Linux host | 10 / 10 |
| Windows privilege / Linux privilege | 10 / 12 |
| PostgreSQL / MySQL-MariaDB / SQL Server | 21 / 15 / 13 |
| nginx / Apache / Tomcat / Docker daemon / middleware-common | 10 / 8 / 9 / 9 / 4 |
| Docker-Kubernetes runtime / kubelet-containerd configuration | 17 / 7 |
| **Total** | **155** |

By domain: **133 host_configuration**, **22 local_privilege**. By platform:
**56 Windows**, **86 Linux**, **49 database memberships**. This corrects stale
documentation describing the current built-in pack as only 20 rules or Docker
daemon content as 10 rules.

Two intentional overlapping detection pairs exist: anonymous FTP
(ftp_checker/default_creds) and SMBv1 (smb_probe/eternalblue_probe). Shared IDs
avoid double counting the same condition. This is not four orphaned plugins.
The endpoint loss caused by overly broad deduplication is a separate defect.

## Inventory and audit scope

The complete requested per-entry inventory is [INVENTORY.md](INVENTORY.md),
with a [170-row CSV](plugin-inventory.csv) containing all **14 requested
columns** for every module and every source built-in definition. The
[machine-readable catalogue](inventory.json) retains exact collection
parameters, expectations, absence policy, credentials, platforms, OS targeting,
references, remediation, tests and source locations, plus all 57 network areas
and all 28 collector implementations. [AUXILIARY_COMPONENTS.md](AUXILIARY_COMPONENTS.md)
individually maps the other discovery, OT, credentialed, web and topology detectors. Source checksums identify the examined
detector files. CSV contents are evidence, not a count of Nessus-equivalent units.

The source manifest includes discovery, port, vulnerability, credentialed,
configuration, SCAP, web, topology and CPE support. The execution trace below
also examines routers, Celery tasks, policies, persistence, API and reporting
outside that manifest. Parsers, transports, orchestrators, registries, risk
functions, feed ingestion and identity utilities are classified as support,
not counted as separate security plugins merely because they are Python files.

Database-loaded benchmark content and installed third-party Nuclei templates
are runtime content populations. Their individual content was not copied into
the repository or counted as implementation modules; this audit does not
certify each imported rule or each third-party template. Exact imported-row
counts are reported above rather than inferred from old documentation.

## Execution flow verified against source

### Network scan

`routers/phase_scans.py:388 scan_host_discovery` validates target/scope,
authorization, quota and scan parameters, creates a Scan, records the effective
policy and dispatches the scanner task. The mode resolves to basic (phase 1),
asset (1+2), or vulnerability_audit (1+2+3). An interactive execution can finish
at a phase and require an authorized continuation; the default background path
auto-chains separate Celery tasks. `/scan/asset-discovery` and
`/scan/vulnerability-audit` are continuation entry points; they are not a
second unrelated plugin architecture.

1. **Discovery:** `core/tasks.py:1242 run_host_discovery_task` ->
   `ScanOrchestrator.run_host_discovery_only` ->
   `core/discovery/engine.py:225 DiscoveryEngine.run`. Profile/zone/raw-socket
   conditions choose ARP, ICMP, TCP SYN, TCP connect, UDP and NBNS; ARP cache and
   passive L2 observations supplement identity. Evidence records activity,
   confirmation, MAC/name/OS hints. Target admission is reapplied when phase
   continuations use host records. Host discovery is not CVE scanning.
2. **Ports/services:** `run_asset_discovery_task` ->
   `ScanOrchestrator.run_asset_discovery_only` -> `engines/port/port_engine.py`
   `PortEngine.run`. Nmap through `core/nmap/wrapper.py` handles port/service
   and optional OS detection; fallback TCP/Scapy UDP is weaker identification.
   Intensity, custom/excluded ports and OT policy bound the port universe.
   Parsed services carry port, protocol, state, product, version, banner and CPE.
3. **Network checks:** `core/tasks.py:2388 run_vulnerability_audit_task` ->
   `orchestrator/scan_orchestrator.py:825 run_vulnerability_audit_only`.
   Nmap pre-enrichment finishes **before** `VulnerabilityEngine.run`.
   Only is_active hosts run plugins. Missing IP returns without plugins.
   `VulnerabilityEngine._run_plugins` computes selection once.
4. **Selection/execution:** `plugin_selector.py select_plugins` attempts lazy module imports and caches
   successes **and failures**. The package initializer eagerly imports every
   module first, defeating failure isolation in a fresh worker (D15). SNMP, UDP and ICMP are
   always selected. Other parallel modules are selected by integer port alone,
   not service identity or OS; TCP/UDP metadata is lost at this gate. Host pool
   size is at most 20, per-host parallel plugin pool at most 12. Parallel run()
   receives `(ip, open_ports)`. Serial Nuclei then CVE run() receives
   `(ip, open_ports, original_port_details)`. CVE generation does **not** receive
   the complete merged host dictionary despite comments about aggregated banners.
5. **Merge/evidence:** top-level cves and udp_services are extended; other keys
   overwrite. Nested metadata is not automatically a finding. No rescheduling
   occurs after UDP discovers a new service. Exceptions from parallel plugins
   return `{}`; serial exceptions log at DEBUG. There is no per-plugin
   structured outcome ledger or future deadline. Socket/subprocess/whole-task
   bounds provide partial protection; a thread stuck beyond its own network
   deadline can hold pool shutdown until the task/reaper acts.
6. **Normalize/risk:** `core/risk.py:324 deduplicate_cves` ->
   `core/checks/finding_normalizer.py verify_host_findings` -> calculate_risk
   and device classification. Version/CPE claims need supporting service/version
   evidence; rejected candidates remain in suppressed_cves. Active checks are
   authoritative and receive high confidence, so a false predicate in a probe
   can become a confidently wrong finding. CVSS vector validation, severity,
   remediation provenance, EPSS/KEV and exploit enrichment are separate from
   demonstrating exploitability of the host.
7. **Optional phase 3.5:** `_apply_credentialed_enrichment` runs sequentially
   over active hosts when scan.options.credentials names in-scope stored
   credentials. Stored material is decrypted worker-side and tenant-scoped.
   Database credentials are skipped for host enrichment. The current main
   enrichment path resolves an endpoint for the stored **transport**; the
   standalone path can additionally discover a transport. These capabilities
   should not be described as identical. Failed/skipped hosts carry coverage
   reasons; successfully collected package/process/OS evidence can refine
   network fingerprint findings before results are persisted.
8. **Persist/output:** reports are rendered from final results; then
   `scans/db_helpers.py update_scan_phase` stores sanitized host payloads under
   ScanPhase.summary and synchronizes the asset/finding projection through
   `scans/asset_syncer.py:2070 sync_vulnerability_audit`. Typed catalogue entries
   keep genuine CVE IDs separate from CCURE check IDs. Finding upserts refresh
   evidence, source family, severity and last-observed scan while preserving
   first-seen identity. Current services are a projection; per-scan evidence is
   the phase snapshot. Findings/scan-detail APIs and `routers/reports.py` read
   these records; reporting/exports.py generates shared CSV/JSON/XLSX payloads.

`core/celery_app.py` loads core.tasks, web.tasks and compliance_tasks. Network
tasks use the scanner queue; web tasks use web; compliance scheduling/evaluation
is separate. Whole-scan tasks declare soft/hard limits, and stalled/queued scan
reapers are scheduled. A task failure attempts terminal settlement with a plain
SQL fallback when ORM failure prevents the normal route. These controls do not
repair a missing plugin outcome.

### Credentialed and configuration scans

`routers/credentialed.py:162 scan_credentialed` validates targets, scope,
credential reference/material and policy, then dispatches
`core/tasks.py:4536 run_credentialed_scan_task`. Targets run sequentially;
one failed target is recorded without abandoning successful hosts. A scan fails
when no target can be audited. Transport discovery and conventional-port fallback
use reachability, not repeated password attempts; authentication rejection is
not a reason to try the secret on every service.

`audit_credentialed_host` chooses SSHScanner, WinRMExecutor or SMBExecutor.
Windows is established by WinRM/SMB; SSH uses requested/detected OS.
LinuxCollector and WindowsCollector collect selected sections concurrently.
Linux package enumeration includes distribution/source/RPM epoch and running
kernel evidence; Windows uses uninstall-registry software and OS build plus UBR.
SSH supports password/key and controlled elevation; WinRM uses thread-local
sessions; SMB uses native WMI/Remote Registry/SCMR without remote service
creation. SMB serves only a subset of the Windows named items and records
unsupported items. Valid credential does not prove sufficient privilege.

**Inside the open authenticated connection**, `_run_configuration_audit`
selects built-ins and installed/active benchmark rules by policy, platform, OS,
domain, tags, ID and severity. `ConfigAuditEngine` resolves a registered collector,
preserves COLLECTED/ABSENT/UNSUPPORTED/UNAVAILABLE and emits
PASS/FAIL/MANUAL_REVIEW/NOT_APPLICABLE/ERROR. Only FAIL becomes a vulnerability
finding; ERROR is never a pass or vulnerability verdict. Commands keep exit
status and sentinel framing through ShellRunner. Configuration collectors do
not elevate; insufficient read privilege must remain an assessment gap.

After collection, VulnMatcher uses installed package identity, release-scoped
OSV advisories and distro-version comparison, plus CPE/range matching. CSAF
matches normalized whole product names and release lines. WindowsPatchMatcher
uses MSRC fixed builds within the observed servicing line, rather than relying
on Get-HotFix as a complete patch catalogue. Missing/unusable feed evidence
reduces coverage. Matchers/parsers are supporting detection engines, not extra
network plugin files.

`audit_database_target` is the database branch of the same task, using
read-only PostgreSQL/MySQL/SQL Server sessions and 49 source checks. It assesses
instance configuration, not the host OS. Oracle/MongoDB database transports are
reserved and not supported by this implementation. Database results do not
overwrite a host asset's OS/package identity.

Benchmark selection requires enabled tenant installation and active framework
plus active rule. **955 active rule rows with zero enabled benchmark installs
resolve no benchmark content on the observed installation.** Governance
compliance uses core/compliance_evidence.py to adapt existing scan evidence and
core/compliance_tasks.py to evaluate rules/attestations. It is not a live scanner.
Configuration results are synchronized through compliance_sync rather than
re-evaluated as ordinary evidence rules. SCAP provides XCCDF/OVAL conversion and
16 supported test types (10 Unix/independent, 6 Windows); it is not a complete
OVAL engine and rejects unsupported constructs explicitly.

### Persistence and reporting limits

Existing tests cover real PostgreSQL fixture persistence, typed definitions,
current evidence updates, credentialed source-family handling, scan snapshots,
scope-aware sweeps, API visibility and report/export reconciliation. The
network-check pipeline test uses synthesized evidence rather than real service
parsing. The credentialed end-to-end suite explicitly replaces SSH and package
matching. These prove important seams but **do not prove every network predicate
or every credentialed command on a target**.

Network deduplication currently preserves only one port/evidence set per ID;
thus downstream layers cannot reconstruct all affected endpoints. This is
confirmed loss before persistence, not speculation that PostgreSQL drops rows.
Configuration outcomes export explicit NOT_ASSESSED/ERROR rather than empty
success. The network path lacks that same comprehensive execution ledger.

## Confirmed defect register

Each D ID has a deterministic reproduction in [characterize.py](characterize.py).
These are **characterization assertions of current defects**, not green release
acceptance tests. The proposed regression must invert the corresponding
assertion after the focused fix. No production fixes were made during this audit.

| ID | Severity | Confirmed behavior / impact | Source and smallest recommended fix / regression |
|---|---|---|---|
| D01 | High | Host with only TCP443/8443 never selects http_analyzer, despite internal HTTPS support; headers/files/cookies checks absent | plugin_selector.py _PORT_MAP; http_analyzer.py:395 run. Register both TLS web ports; assert selector and engine produce a synthetic HTTPS finding on a host with no plaintext ports; iterate each identified HTTP endpoint in a separate small follow-up |
| D02 | High | Default HTTP auth check is absent on HTTP-only hosts; selected by unrelated FTP/SSH/etc. gates. HTTPS-only run never calls HTTP auth helper | plugin_selector.py _PORT_MAP; default_creds.py:51 run. Add intended HTTP gates and a TLS branch; test no unrelated service required, both schemes, positive 230/HTTP response and rejected credentials; explicitly control guessed-login attempts |
| D03 | High | Port gates ignore protocol; UDP22 selects a TCP SSH probe, UDP443 selects TLS. udp_services53 can select DNS but is absent from run's port list, so DNS immediately returns {} | plugin_selector.py select_plugins; vulnerability_engine.py _run_plugins. Preserve (port,protocol,service) in a narrow adapter; require TCP for TCP probes and route DNS UDP evidence properly; test TCP/UDP same-number and UDP-only cases |
| D04 | Medium | DNS discovered by always-run udp_scanner arrives after one-time selection and never triggers dns_probe | vulnerability_engine.py _run_plugins; udp_scanner.py:28 run. Add one bounded follow-up selection for newly established services, excluding executed modules; assert discovery -> DNS execution exactly once |
| D05 | High | KEXINIT name-list 3 is server-to-client cipher, not MAC; a fixture with hmac-md5 at correct positions reports no weak algorithm | ssh_probe.py:69 _probe_ssh, assignments near 122. Parse cipher indices 2/3 and MAC4/5; read the framed packet fully; test independent directional offerings and split TCP reads. RFC4253 §7.1 confirms the field order |
| D06 | High | AXFR NOERROR with no answer records is marked zone-transfer vulnerable and evidence claims a returned zone | dns_probe.py:81 _check_zone_transfer. Select an actual authoritative zone and validate complete AXFR answer framing/SOA boundaries before promoting; preserve refused/error/unknown; regression NOERROR-empty and genuine transfer controls |
| D07 | High | Successful anonymous LDAP bind emits “returned directory content” before any successful search; a no-content fixture still raises finding. Port636 uses raw LDAP BER without TLS | ldap_probe.py:31 run, :74 _check_anonymous_bind, :141 _query_root_dse. TLS-wrap LDAPS; parse successful search entries and actual allowed content on the bound session; distinguish permissible RootDSE discovery from sensitive directory access; test bind-only, denied search, allowed entry and LDAPS |
| D08 | High | MongoDB helper marks a BSON body containing ok even when its value is zero as no-auth; outbound BSON declared length is wrong. isMaster handshake alone is not proof of unauthenticated database access | default_creds.py:236 _check_mongo_noauth. Use valid modern wire framing/BSON parsing and an auth-requiring read-only command; assess actual success/auth failure. Regression error {ok:0}, secure handshake, allowed read, malformed reply and modern OP_MSG |
| D09 | High | A parallel plugin RuntimeError becomes {} with no per-plugin error result; scan can finish with identical output to a clean/no-result host | vulnerability_engine.py _run_single_plugin/_run_plugins; selector _load also caches failure. Return/persist structured run/skipped/error coverage and warning; keep findings independent of status; inject timeout/import/exception and assert API/report “not assessed,” not clean |
| D10 | Medium | Same expired-cert ID on443 and8443 collapses to one port and one evidence string; second endpoint disappears before persistence/report | core/risk.py:324 deduplicate_cves; vulnerability_engine.py _verify_host. Preserve endpoint observations under one logical ID or include endpoint identity where API contract permits; test two endpoint evidence records survive normalization, snapshot/export and service association without schema break |
| D11 | High | Heartbleed/Shellshock module internally supports ports465/993/995/8000/8888 but these do not select it. It stops at first non-None result, including negative, and misses later vulnerable endpoint | selector _PORT_MAP; heartbleed_probe.py:43 run. Align gates and iterate eligible endpoints; test first safe/second affected and each single supported port. Add positive/negative framed TLS and reflection controls before treating the CVEs as confirmed |
| D12 | High | smb_probe advertises NBSS payload133 but sends a shorter payload; compliant stream framing can wait and timeout, leaving no SMBv1 finding | smb_probe.py:69 _probe_smb. Derive NBSS length and build a correct 32-byte SMB header/dialect body or reuse a read-only protocol library; assert complete frame with a length-aware loopback server and dialect controls. **eternalblue_probe's negotiate frame length is correct**; the initial broader hypothesis was rejected |
| D13 | High | Malformed credential targets are dropped; an all-invalid list becomes networks=None and that credential matches any host in the scan | core/tasks.py:1730 _credentialed_plan_for_scan and :1948 _credential_for_host. Treat omitted scope as explicit all-in-scan; reject/quarantine any supplied invalid scope without widening, and record coverage error; test all-invalid/mixed/valid/omitted cases. This does not bypass scan-scope target admission, but it widens where a secret may be offered |
| D14 | Medium | Nuclei exit1 with no JSONL file is accepted as nuclei_templates_run=True and empty cves; timeout discards any partial results and has no structured completion state | nuclei_probe.py:346 run. Accept only documented success semantics; inspect error/partial status and retain validated findings from a partial run while marking coverage incomplete; regression fatal-exit/no-file, success-empty, partial-file, timeout. Plugin acceptance was reproduced with a process double; a real target-free missing-template invocation independently returned fatal exit1 |
| D15 | High | A fresh process with an LDAP-only import failure cannot load unrelated ssh_probe; the selector negatively caches SSH as unavailable because plugins/__init__.py eagerly imports every module | engines/vulnerability/plugins/__init__.py; plugin_selector.py _load. Keep package initialization import-free or lazily export modules; let the selector import only requested modules. Regression injects one module failure in a fresh subprocess and requires unrelated modules still load while only the failed module is withheld |

**Confirmed totals: 15, of which 12 High and 3 Medium.** D07 contains two closely
related LDAP defects under one remediation item. This is a count of register
items, not a count of lines of code or all possible manifestations.

### Suspected or unverified concerns (not included in confirmed totals)

| Concern | Evidence / limit | Validation and bounded recommendation |
|---|---|---|
| MS17-010 fingerprint promoted as Confirmed | eternalblue_probe calls STATUS_INVALID_PARAMETER a likely fingerprint; no independently known vulnerable/patched target was used | Compare protocol transcript and verdict against both controlled target states; do not claim that dialect alone demonstrates the CVE |
| Shellshock marker reflection / Heartbleed record parsing | Fixed string in body and raw record length checks are not independent execution/leak proof; mock promotion tests bypass predicate | Nonexecuting echo endpoint versus real CGI; fragmented/coalesced valid TLS records and patched controls; withhold unsupported active claims |
| UDP response provenance / descriptor lifecycle | udp_scanner uses coarse lengths/any datagram for several protocols, no protocol field, and closes sockets inside success paths | Wrong-source/transaction-ID replies, arbitrary datagrams and timeout cleanup; verify service persistence remains UDP |
| Repeated automatic guessed logins | FTP tries eight pairs and default HTTP tests ten; not controlled by intrusive write policy; SNMP guesses15 communities | Source-confirmed behavior; account lockout/OT impact not measured. Add explicit policy and attempt budgets; tests must never spray real accounts |
| Single endpoint and vhost coverage | HTTP/LDAP/SMB pick one port; HTTP/TLS use target IP; custom HTTP/SSH/TLS ports can bypass fixed gates | Validate different services on two ports and SNI/Host identities before declaring endpoint coverage; choose service evidence over a global port assumption |
| Credentialed bulk command failure vs empty inventory | LinuxCollector._run and WindowsCollector._run command path can return stdout/empty without preserving item success as strongly as ShellRunner/native SMB | Permission-denied/nonzero-exit/partial stdout fixtures through package coverage and compliance; record per-item availability before a missing list becomes a clean fact |
| Import-failure cache never retries in a worker | selector caches None for process lifetime | Confirm hot dependency repair behavior; scoped cache reset/restart and persistent coverage state, not a blanket scan failure |

## Prioritized roadmap

| Order | Work | Exit criterion |
|---|---|---|
| P0 | D13 credential scope; D06/D07/D08 unsupported vulnerability claims; D09 coverage/outcome visibility; D15 import isolation | Invalid scopes never widen; rejected/error replies cannot create Confirmed findings; failed plugins visible in scan/API/report |
| P1 | D01/D02/D03/D04/D05/D11/D12 gates, transport and parsers | Each endpoint/service prerequisite has positive, negative and unsupported fixture; correct SSH/MAC and SMB framing; no TCP credential on UDP-only evidence |
| P1 | D10/D14 endpoint preservation and partial Nuclei execution | All observed endpoint evidence reaches export/persistence; partial runs retain valid observations and say incomplete |
| P2 | Independent protocol/credentialed validation | Known affected and patched SMB/TLS/CGI targets, real SSH valid/invalid/limited users, Windows WinRM and SMB-only/DCOM-blocked configurations; do not count mocks as target coverage |
| P2 | Runtime content/install and feed operations | Explicit installed/selected/assessed counts; selected benchmarks load successfully; feed freshness/completeness and parser version visible; no “active means running” assumption |
| P3 | Nessus-family breadth gaps | Prioritize service-driven custom-port checks, authenticated appliance assessment/SNMPv3 vulnerability evidence, per-plugin policy/dependency controls, Windows file-version/AD breadth, additional approved database/platform collectors |

Ownership and dates should be assigned by the project team; this audit does not
invent commitments. Preserve current APIs, database compatibility and read-only
target behavior. Promote the characterization cases to conventional regression
tests when the corresponding focused fix is implemented.

## Evidence and test report

The separate [TEST_REPORT.md](TEST_REPORT.md) records exact commands, results,
scope, no-skip totals, the corrected rejected hypothesis, dependency availability,
and areas that remain unverified. [NESSUS_COMPARISON.md](NESSUS_COMPARISON.md)
contains the official-reference comparison matrix. Do not cite passing tests
alone as proof that these plugins work on all target types or that the product
has Nessus parity.
