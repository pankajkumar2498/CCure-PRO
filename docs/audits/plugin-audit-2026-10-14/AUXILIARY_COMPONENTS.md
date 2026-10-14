# Other detectors, collectors and support components

These are reachable components outside the 15 legacy network plugin modules.
They are explicitly inventoried to avoid classifying every Python file as a
plugin. Their paths/symbol line numbers are in inventory.json's source manifest;
named Linux/Windows collection commands are exported there too. Generic
configuration collectors and all155 built-in rules are separately enumerated
in INVENTORY.md.

Unless specifically stated, the status is **implemented/reachable,
fixture-tested where indicated, real-target behavior unverified by this audit**.
There is no additive “working plugin” total for this table: several entries are
shared wrappers or acquisition stages, not independent security checks.

## Discovery and host identification

All technique rows enter through DiscoveryEngine.run / _discover_batch under
ScanOrchestrator's host-discovery phase. Profile, target zone and raw capability
select the applicable technique; successful activity can skip later methods.
They require no credential. Results populate host identity/activity metadata,
not normalized vulnerability findings or CVE claims. Timeouts/no replies do
not establish a vulnerability or prove a host permanently dead.

| Detector | Source / entry | Purpose / evidence | Exact prerequisite or trigger |
|---|---|---|---|
| ARP | core/discovery/techniques/arp.py probe | Local-link activity/MAC | ARP technique, LAN and raw capability |
| ICMP | techniques/icmp.py probe | Echo/timestamp/TTL hints | ICMP technique and raw capability |
| TCP SYN | techniques/tcp_syn.py probe | SYN/ACK or RST activity | TCP_SYN technique and raw capability; configured enterprise/web probe ports |
| TCP connect | techniques/tcp_conn.py probe | Successful socket reachability | TCP_CONN profile/fallback; no raw privilege |
| UDP | techniques/udp_probe.py probe | UDP or ICMP reply activity | UDP_PROBE profile and raw capability; zone constraints |
| NBNS | techniques/nbns.py probe | NetBIOS activity/name | NBNS technique / zone eligibility; UDP137 |
| ARP cache | techniques/arp_cache.py probe/get_mac_from_arp_cache | Best-effort existing neighbor MAC | Cache fallback for unresolved MAC; cached value is weaker than direct observation |
| Passive L2 | engines/discovery/l2_sniffer.py:55 sniff_l2_infrastructure | LLDP/CDP/STP/DHCP/mDNS infrastructure intelligence | Discovery's passive enrichment; interface/raw capture availability; bounded3s |
| SNMP lightweight | core/discovery/enrichment.py:434 _snmp_lightweight_probe | sysDescr/sysName/device platform | enrich_host/port-engine enrichment; UDP161 response |
| Reverse DNS | enrichment.py:589 _ptr_lookup | PTR identity candidate | Enrichment enabled; resolver response; forward-confirmation/source precedence govern confidence |
| mDNS host | enrichment.py:627 _mdns_query | mDNS identity | Enrichment enabled; UDP5353 response |
| mDNS service | enrichment.py:680 _mdns_service_query | DNS-SD service names/ports | Service-enrichment branch and responder |
| NetBIOS name | enrichment.py:720 _netbios_query | Names/workgroup identity | Enrichment enabled; UDP137 response |
| OS transport hints | enrichment.py:791 _os_probe_full; port_engine fingerprint_os_confidence | TTL/window/protocol/Nmap OS evidence | Requested OS detection/probe capability; not a package inventory |
| Authenticated OS | engines/credentialed/os_detection.py detect_os | ver/uname/PowerShell response | SSH audit; WinRM/SMB already establish Windows. Darwin/BSD map to Linux-shaped collector; inconclusive fallback is Linux, not proof |

Host-identity precedence, forward confirmation, OUI lookup, device_classifier,
asset correlation, MAC normalization and registries are **support utilities**.
They do not independently demonstrate a CVE. Existing host/port/OT/identity tests
ran in the4592-test regression group. No live discovery sweep was performed.

## OT protocol identity detectors

Entry: `core/discovery/enrichment.py:184 _ot_protocol_probes`, reached from
allowed enrichment and PortEngine._ot_enrichment_check. A prior _ot_probed/ot_info
record prevents duplicate probing. Candidate port state must be open,
open|filtered, filtered or unknown; unknown TCP state first needs reachability.
Probes are sequential, read-only protocol identification, with approximately1s
per probe; S7 precedes MMS on shared102. They record protocol/vendor/model/firmware
and classification evidence; this alone is **not a vulnerability finding**.
No credential is supplied. CPE/version inference later requires independent
evidence through the CVE path; no dedicated OT vulnerability module is registered
in the reserved selector port lists.

Every function below is in `core/discovery/techniques/ot_probes.py`.

| Probe | Transport/port | Evidence/purpose | Status / tests |
|---|---|---|---|
| probe_modbus | TCP502 | Modbus identity/read response | Fixture-supported; test_ot_probes/test_ot_safety; actual PLC unverified |
| probe_s7 | TCP102 | S7 system/product response | Same; first shared-port attempt |
| probe_ethernetip | UDP44818 | EtherNet/IP identity | Same |
| probe_bacnet | UDP47808 | BACnet discovery/vendor identity | Same |
| probe_dnp3 | TCP then UDP20000 | DNP3 response identity | Same |
| probe_opcua | TCP4840 | OPC-UA protocol response | Same |
| probe_iec104 | TCP2404 | IEC104 protocol response | Same |
| probe_ge_srtp | TCP18245 | GE SRTP identity | Same |
| probe_fins | TCP9600 | Omron FINS response | Same; do not infer UDP support from the product name |
| probe_melsec | TCP5007 | Mitsubishi MELSEC response | Same |
| probe_codesys | TCP2455 | CODESYS response | Same |
| probe_mms | TCP102 | MMS fallback response | Same; only after S7 yielded no identity |

## Credentialed transports, inventory and matching

| Component | Classification / entry | Purpose / prerequisites / evidence | Finding/output path and limit |
|---|---|---|---|
| SSHScanner | Transport; audit_credentialed_host | Password/key-authenticated SSH, connectivity, bounded run/run_sudo; sudo/dzdo/pfexec support; unsupported elevation refused | CommandResult, not a finding; safe secret-on-stdin tests ran; no real SSH authentication here |
| WinRMExecutor | Transport; audit_credentialed_host | Windows session; NTLM/password; HTTP/TLS policy; per-thread sessions | CommandResult into same WindowsCollector; Kerberos not usable in current credential API; no real Windows target here |
| SMBExecutor | Transport; audit_credentialed_host | SMB credentials or NTLM hash; Remote Registry/WMI/SCMR according to subsystem reachability/privilege | Named readings into WindowsCollector; unsupported items explicit; run() refuses remote service creation |
| DatabaseSession | Transport/query executor; audit_database_target | PostgreSQL/MySQL/SQL Server read-only login and queries | QueryResult.ok differentiates failed query and empty rows; 49 ConfigChecks; actual instance unverified |
| LinuxCollector | Inventory collector; authenticated collect_all | Selected system/packages/services/ports/users/security/network/history sections; parallel sections; dpkg/RPM/source/epoch/kernel/process/package evidence | Inventory and configuration context to matcher/report; each named command in inventory.json; bulk command availability needs additional independent proof |
| WindowsCollector | Inventory collector; authenticated collect_all | PowerShell or SMB native named readings; registry uninstall/software, processes/services/listeners, build/UBR and posture | Same inventory/matching/report; unsupported SMB data must remain absent/unknown; thread-safe transport fixtures passed |
| VulnMatcher | Advisory-matching engine; audit_credentialed_host | Installed packages, distribution/release/kernel and available CPE/OSV feeds; version ranges and package/source/epoch scoping | to_report_format -> normalization -> findings; SQL failures/caps recorded in coverage; no complete live feed evaluation here |
| CsafProductMatcher | Advisory-matching engine; audit_credentialed_host | Exact normalized product/release-line and parseable vendor version constraints | Vendor findings/enrichment -> common findings; unorderable constraints counted unassessed; no real OT software estate here |
| Windows patch matcher | Advisory-matching engine; engines/credentialed/windows_patch.py | Full build+UBR, same MSRC servicing line, applicable product | OS CVEs + os_assessed coverage; not equivalent to DLL-level assessment or all Microsoft products |
| package_identity / coverage | Identity/scope utilities | Source/binary/version precision/process ownership and network-bound listener reachability | Supports match confidence; not separate vulnerability plugins |
| CPE matcher / NVD client / CVSS/remediation resolver | Matching/intelligence utilities; scans/cve_engine | Product identity, ranges, published vector/remediation | Network/package normalization support; not independently scheduled checks |

Credentialed tests for successful/invalid authentication, WinRM/SMB, transport
selection, package identity, version/source/epoch scope, kernel scope and
status synchronization all ran. They establish fixture behavior; no real
SSH/WinRM/SMB target was authenticated during this audit.

## Configuration, benchmarks, SCAP and compliance

ConfigAuditEngine, CollectorRegistry, CollectionContext, expectation operators,
ShellRunner and finding adapters are engines/contracts. The actual rules are
the155 definitions in INVENTORY.md and imported content selected from the
database. Benchmark loader/selection and SCAP XCCDF/OVAL translation/evaluation
are content infrastructure, not extra plugins.

SCAP evaluates16 explicitly supported test types: independent textfilecontent54,
xmlfilecontent, yamlfilecontent, family and external-variable; Unix file/uname;
Linux rpminfo/dpkginfo/systemdunitproperty; Windows registry,
auditeventpolicysubcategories, userright, passwordpolicy, lockoutpolicy and wmi57.
Applicability preserves UNKNOWN separately from false. Unsupported test/object/
variable shapes are refused; this is partial standard support. Each type's
collector/probe path is `core/scap/{oval,probes,evaluate}.py`, reached only via
a selected ConfigCheck(check_type=scap_rule) and an authenticated target.

Middleware JSON/XML/nginx/Apache/YAML/TOML parsers are collectors' support.
Container/docker/kubectl enumeration is reached through a selected container
rule on Linux, not an unauthenticated remote image scanner. Governance rules
and manual attestations in compliance_tasks evaluate existing evidence; they do
not launch equivalent Nessus security plugins. The reserved api collector and
network_device/cloud/container target platforms must not be described as
implemented just because the schema accepts them.

## Web plugin-like detectors and stages

Entry: `routers/web_scans.py:449 start_web_scan` ->
`core/web/tasks.py` recon/crawl/detect/audit tasks ->
`orchestrator/web_orchestrator.py WebScanOrchestrator`. Web findings use separate
WebFinding persistence (`_persist_web_findings`), statistics, finding API and
web report generator. They are **not** automatically invoked by network
VulnerabilityEngine. Most are async; external wrappers launch bounded
subprocesses. WebSessionManager supplies authenticated headers/cookies where
configured. ToolCoverage and scheduler record ran/partial/skipped/unavailable/
failed states; timeout/cancellation and policy budgets bound assessment. The
4592-test suite exercised all web test modules; none of these stages was run
against an external app in this audit.

| Component / category | Source entry | Logic/evidence/purpose | Trigger/prerequisites/credentials |
|---|---|---|---|
| Subdomain discovery | core/web/subfinder/wrapper.py SubfinderWrapper.run | External passive subdomain output -> recon scope | Recon, domain target, binary; external-source behavior not exercised here |
| WAF discovery | core/web/waf/detector.py WAFDetector; NucleiWrapper.run_waf_detect | Header/body fingerprints affect scan rate/safety | Recon response; optional binary fallback; no vulnerability solely from WAF presence |
| Technology fingerprint | core/web/fingerprint/engine.py TechFingerprinter; NucleiWrapper.run_tech_detect | Header/body/assets/technology templates | Recon; target response; software identity alone is not a CVE |
| Browser crawling | core/web/crawling/browser.py PlaywrightCrawler.crawl | DOM/network/form/SPA surface and parameters | Crawl, browser runtime; optional logged-in session |
| Content discovery | core/web/ffuf/wrapper.py FfufWrapper.run | Bounded wordlist/status/body differential -> paths/recrawl | Crawl/depth and binary availability; propagated auth where configured |
| API surface/fuzz | core/web/api_scan/engine.py ApiScanEngine.run and fuzz.py | OpenAPI/GraphQL operations and bounded request cases | enable_api_scan default true; discovered/imported API; authorization/scope rules |
| Workflow/auth navigation | core/web/workflow/engine.py WorkflowEngine.run | Operator steps/assertions and captured response/surface | Explicit valid workflow; authenticated session when required; stage support, not a CVE detector alone |
| Session/authentication validation | core/web/auth/session_manager.py WebSessionManager | Login/session validation, CSRF/MFA/OAuth/header/cookie state | auth_config; failure/expiry recorded; secret handling helpers are support |
| Nuclei web vulnerability templates | core/web/nuclei/wrapper.py NucleiWrapper.run | Auth-aware template match/request/extraction, bounded profile and partial coverage | Detect phase, binary/templates, selected discovered targets; independent from legacy nuclei_probe |
| SQL injection | core/web/sqlmap/wrapper.py SqlmapWrapper.run | Injection tests and tool-derived proof | enable_sqli default true; injectable query/form/JSON targets, caps/policy; optional auth |
| XSS | core/web/xss/engine.py XssEngine.scan | Reflection/browser execution evidence | enable_xss default true, candidate parameters and browser/context prerequisites |
| Other injection | core/web/injection/engine.py InjectionEngine.scan | Payload-specific response/control evidence | enable_injection default true, selected parameter locations/policy and budgets |
| Access control / IDOR | core/web/access_control/engine.py AccessControlEngine.scan | Owner/peer/anonymous response comparison with resource ownership/control | enable_access_control default true plus additional configured authenticated identities; skips when no peer authenticated |
| HTTP method checks | core/web/http_methods/engine.py HttpMethodEngine.scan | Method and differential response evidence | enable_http_methods default true; endpoints; request budget |
| JavaScript dependency vulnerabilities | core/web/js_deps/engine.py JsDependencyEngine.scan | Detected JS dependency/version and advisory evidence | enable_js_deps default true; retrieved/captured scripts; feed identity/range prerequisites |
| Out-of-band checks | core/web/oast/engine.py OastEngine.scan | Correlated callback/proof rather than reflection | enable_oast default true but usable permitted OAST configuration/service required; no external callback test here |
| Security headers | web_orchestrator.py:2559 _check_security_headers | Sampled URL response/header configuration | Detect; scheduler/scope sampling; no credential or propagated session |
| Cookies | core/web/cookies/analyzer.py; web_orchestrator._check_cookies | Cookie transport/flags and response evidence | Cookie-bearing responses/session; distinct from network analyzer |
| CORS | web_orchestrator.py:2704 _check_cors | Origin/credential response controls and evidence | Detect; selected endpoints; optional session |
| Open redirect | web_orchestrator.py:619 open_redirect_findings | Crawl out-of-scope redirect chain validation | Crawl observations; scope and control evidence |
| TLS audit | core/web/sslyze/wrapper.py SSLyzeWrapper.run | Certificate/protocol/cipher evidence | Audit phase, HTTPS target and SSLyze available; same wrapper reused by legacy tls_scanner |

Correlation, standards/CWE mapping, finding_view, request_model, JS route/DOM
parsers, auth/secrets, coverage ledgers, rate scheduler, payload catalogues,
browser_runtime, policy, timeout, OAST receiver/session and base_wrapper are
**supporting utilities**, not additional check implementations. Tool availability
is not a count of templates executed or of security findings demonstrated.

## Topology and vulnerability-feed infrastructure

`core/topology/client.py walk_target/probe_snmp` uses configured SNMP credentials
and OID walks to collect ARP, LLDP/CDP/EDP/FDB/VLAN/interface information;
`core/topology/engine.py run_topology_mapping` merges/persists links. It is an
optional configured phase, not an automatic SNMPv3 vulnerability audit. The
topology tests ran, but no real switch was walked.

NVD sync and scripts/vuln sync_osv/sync_msrc/sync_csaf/sync_exploit_intel/
sync_vulncheck populate intelligence used by matchers. They are feeds,
not per-target plugins; no sync was run or claimed complete during this audit.
KEV/EPSS/exploit presence annotates a CVE and does not prove the host exploitable.
