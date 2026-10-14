# Individual plugin and check inventory

Baseline: 14 October 2026, source revision `6d816e23dcbc61a4f96ff106af1f0bc3a1c44ce1`. 15 module implementations + 155 built-in rule definitions. These are two different granularities, not 170 Nessus-equivalent plugins. The CSV has all 14 requested columns. Every check's raw parameters, expectation, remediation and source references are also in inventory.json.

The common execution and persistence paths are analyzed in REPORT.md. Entry paths below are static reachability; only the three stated loopback scenarios were independently exercised live. A passing fixture or import is not full target validation.

## cve_engine

| Field | Evidence |
|---|---|
| Plugin ID/name | cve_engine |
| Category | Vulnerability correlation |
| Purpose | Version/CPE CVE candidates |
| Detection logic | Search each original port detail by application CPE, banner or service; split OS CPEs into host searches; record row caps |
| Target requirements | Service/product identity; known versions for non-authoritative confirmation; populated vulnerability feeds |
| Trigger conditions | Every active host, serial; No live feed/target validation this audit; original port_details only, rather than the full merged host |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> cve_engine.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Service port/protocol, CPE, version, candidate source and truncation |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | cve.version_inference -> dynamic CVE/template ID |
| Execution status | Unverified on a real target; reachable and test-supported |
| Test coverage | tests/reports/test_candidate_truncation_reporting.py; tests/scans/test_nvd_checkpoint.py; tests/scans/test_cve_engine_candidates.py; tests/scans/test_network_check_pipeline.py; tests/scans/test_nvd_cvss_v4.py; tests/scans/test_snmp_platform.py; tests/scans/test_nvd_sync.py |
| Code reference | Backend/engines/vulnerability/plugins/cve_engine.py:82 run() |

## default_creds

| Field | Evidence |
|---|---|
| Plugin ID/name | default_creds |
| Category | Authentication/exposure |
| Purpose | Anonymous FTP, Telnet, Redis/MongoDB/MQTT/Memcached access and HTTP Basic defaults |
| Detection logic | Protocol login or command reply; Telnet from supplied port; HTTP tests first plaintext web port only |
| Target requirements | Recognized conventional service ports; no operator credential |
| Trigger conditions | Any selected port number in [22, 21, 23, 6379, 27017, 1883, 11211, 3306, 5432]; HTTP/HTTPS dispatch missing; HTTPS branch absent; malformed Mongo BSON and substring success test; SSH/MySQL/PostgreSQL trigger ports do not themselves implement auth checks |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> default_creds.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Login status, command response, accepted account and endpoint |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | http.default_credentials -> CCURE-CHK-HTTP-DEFAULT-CREDENTIALS; ftp.anonymous_login -> CCURE-CHK-FTP-ANONYMOUS-LOGIN; telnet.cleartext_exposed -> CCURE-CHK-TELNET-EXPOSED; redis.no_authentication -> CCURE-CHK-REDIS-NO-AUTHENTICATION; mongodb.no_authentication -> CCURE-CHK-MONGODB-NO-AUTHENTICATION; mqtt.no_authentication -> CCURE-CHK-MQTT-NO-AUTHENTICATION; memcached.no_authentication -> CCURE-CHK-MEMCACHED-NO-AUTHENTICATION |
| Execution status | Partially working/unreliable: D02,D08 |
| Test coverage | tests/web/test_cwe_mapping.py; tests/scans/test_network_check_pipeline.py; tests/scans/test_network_check_promotion.py; tests/scans/test_scan_time_verification.py; tests/scans/test_tls_starttls.py |
| Code reference | Backend/engines/vulnerability/plugins/default_creds.py:51 run() |

## dns_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | dns_probe |
| Category | DNS security |
| Purpose | Zone-transfer disclosure and recursion |
| Detection logic | Root-zone TCP AXFR uses RCODE=0 alone; UDP google.com recursion uses RA plus ANCOUNT |
| Target requirements | 53; resolver/authoritative service; authorized source perspective |
| Trigger conditions | Any selected port number in [53]; Zero-answer success is a false disclosure claim; no real authoritative-zone selection; newly discovered UDP may never reach it |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> dns_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | RCODE or recursion flag; no actual zone record proof |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | dns.zone_transfer -> CCURE-CHK-DNS-ZONE-TRANSFER; dns.open_recursion -> CCURE-CHK-DNS-OPEN-RECURSION |
| Execution status | Partially working/unreliable: D03,D04,D06 |
| Test coverage | tests/scans/test_network_check_promotion.py; tests/scans/test_scan_time_verification.py |
| Code reference | Backend/engines/vulnerability/plugins/dns_probe.py:31 run() |

## eternalblue_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | eternalblue_probe |
| Category | SMB/CVE active check |
| Purpose | SMBv1, signing and MS17-010 fingerprint |
| Detection logic | SMBv1 negotiate security mode; malformed Trans2 status 0xC000000D treated as MS17-010 likely |
| Target requirements | 445; SMBv1 implementation for CVE fingerprint |
| Trigger conditions | Any selected port number in [445]; No known vulnerable/patched SMB target validation here; fingerprint reliability is unverified, not established from the promotion tests |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> eternalblue_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Dialect index, security mode, NT status |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | smb.signing_disabled -> CCURE-CHK-SMB-SIGNING-NOT-REQUIRED; smb.eternalblue -> CVE-2017-0144 |
| Execution status | Unverified on a real target; reachable and test-supported |
| Test coverage | tests/scans/test_network_check_promotion.py; tests/scans/test_scan_time_verification.py |
| Code reference | Backend/engines/vulnerability/plugins/eternalblue_probe.py:38 run() |

## ftp_checker

| Field | Evidence |
|---|---|
| Plugin ID/name | ftp_checker |
| Category | FTP security |
| Purpose | Anonymous/weak login, optional anonymous write, cleartext protocol |
| Detection logic | 220 banner and 230 login; tries 8 weak pairs; opt-in MKD/RMD; cleartext notice |
| Target requirements | 21; FTP server; SCAN_ALLOW_INTRUSIVE/policy for write probe |
| Trigger conditions | Any selected port number in [21]; No real FTP target here; weak-login attempts are automatic; anonymous login also checked by default_creds |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> ftp_checker.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Banner, accepted accounts, write tri-state and cleanup response |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | ftp.anonymous_write -> CCURE-CHK-FTP-ANONYMOUS-WRITE; ftp.weak_credentials -> CCURE-CHK-FTP-WEAK-CREDENTIALS; ftp.cleartext_protocol -> CCURE-CHK-FTP-CLEARTEXT-PROTOCOL |
| Execution status | Unverified on a real target; reachable and test-supported |
| Test coverage | tests/scans/test_network_check_pipeline.py; tests/scans/test_network_check_promotion.py; tests/scans/test_ftp_write_safety.py |
| Code reference | Backend/engines/vulnerability/plugins/ftp_checker.py:61 run() |

## heartbleed_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | heartbleed_probe |
| Category | Active CVE probes |
| Purpose | Heartbleed and Shellshock |
| Detection logic | Raw TLS hello/heartbeat record length; marker in HTTP root response after Bash header payload |
| Target requirements | Implicit TLS 443/8443/465/993/995 internally; HTTP 80/8080/8000/8888/443/8443 internally |
| Trigger conditions | Any selected port number in [443, 8443, 80, 8080]; Selection omits several internally supported ports; stops at first non-None endpoint; marker reflection and TLS framing need independent validation |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> heartbleed_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | TLS record length or fixed Shellshock marker |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | tls.heartbleed -> CVE-2014-0160; http.shellshock -> CVE-2014-6271 |
| Execution status | Partially working/unreliable: D11 |
| Test coverage | tests/scans/test_network_check_promotion.py; tests/scans/test_scan_time_verification.py |
| Code reference | Backend/engines/vulnerability/plugins/heartbleed_probe.py:43 run() |

## http_analyzer

| Field | Evidence |
|---|---|
| Plugin ID/name | http_analyzer |
| Category | HTTP security |
| Purpose | Headers, cookies, cleartext, exposed files/listings, methods, banner disclosure |
| Detection logic | HEAD response then fixed-path GET fingerprints and method statuses; picks first HTTPS else first HTTP endpoint |
| Target requirements | Internally 443/8443/80/8080/8000/8888; selector only plaintext HTTP ports |
| Trigger conditions | Any selected port number in [80, 8080, 8000, 8888]; HTTPS-only hosts never select it; one endpoint only; actual loopback positive and hardened cases passed |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> http_analyzer.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Headers, path/body excerpt, status, methods, Server banner |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | http.missing_security_headers -> CCURE-CHK-HTTP-MISSING-SECURITY-HEADERS; http.cleartext_service -> CCURE-CHK-HTTP-CLEARTEXT-SERVICE; http.insecure_cookie_flags -> CCURE-CHK-HTTP-INSECURE-COOKIE-FLAGS; http.sensitive_path_exposed -> CCURE-CHK-HTTP-SENSITIVE-PATH-EXPOSED; http.directory_listing -> CCURE-CHK-HTTP-DIRECTORY-LISTING; http.dangerous_methods -> CCURE-CHK-HTTP-DANGEROUS-METHODS; http.server_version_disclosure -> CCURE-CHK-HTTP-SERVER-VERSION-DISCLOSURE |
| Execution status | Partially working/unreliable: D01; live loopback scenario verified through engine normalization/scoring, persistence separately fixture-tested |
| Test coverage | tests/scans/test_network_check_promotion.py |
| Code reference | Backend/engines/vulnerability/plugins/http_analyzer.py:395 run() |

## icmp_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | icmp_probe |
| Category | Host intelligence |
| Purpose | ICMP timestamp response metadata |
| Detection logic | Scapy ICMP type 13; any answered pair marks response |
| Target requirements | Scapy/raw-socket capability and answering target |
| Trigger conditions | Every active host; No findings emitted; no direct behavioral tests found; runtime unverified |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> icmp_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | responds and coarse os_hint |
| Finding generation | Metadata only; no normalized vulnerability finding |
| CVE/CPE mapping | None |
| Execution status | Unverified on a real target; reachable and test-supported |
| Test coverage | No direct module-named tests in baseline |
| Code reference | Backend/engines/vulnerability/plugins/icmp_probe.py:24 run() |

## ldap_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | ldap_probe |
| Category | LDAP security |
| Purpose | Anonymous directory disclosure |
| Detection logic | BER anonymous BindResponse resultCode=0 immediately emits disclosure; later root-DSE byte-count request is optional |
| Target requirements | 389/636 internally; plain socket even on 636 |
| Trigger conditions | Any selected port number in [389, 636]; Claims content without a successful search; LDAPS lacks TLS; chooses one endpoint |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> ldap_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Bind result; optional response byte count |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | ldap.anonymous_bind -> CCURE-CHK-LDAP-ANONYMOUS-BIND |
| Execution status | Partially working/unreliable: D07 |
| Test coverage | tests/scans/test_network_check_promotion.py; tests/scans/test_scan_time_verification.py |
| Code reference | Backend/engines/vulnerability/plugins/ldap_probe.py:31 run() |

## nuclei_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | nuclei_probe |
| Category | Active template verification |
| Purpose | External Nuclei template matches |
| Detection logic | Safe-tag/severity-filtered serial subprocess; JSONL parse and corroborating-result collapse; first CVE is primary |
| Target requirements | Binary and template directory; at least one open port; inferred URL scheme |
| Trigger conditions | Every active host, serial; Real synthetic template positive/negative passed; exit 1 without output marked run; timeout discards findings and provides no structured coverage; no full vendor-corpus validation |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> nuclei_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Template ID, matched URL, request/extracted fields, CVE IDs |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | nuclei.template_verification -> dynamic CVE/template ID |
| Execution status | Partially working/unreliable: D09,D14; live loopback scenario verified through engine normalization/scoring, persistence separately fixture-tested |
| Test coverage | tests/scans/test_network_check_pipeline.py; tests/scans/test_nuclei_template_location.py |
| Code reference | Backend/engines/vulnerability/plugins/nuclei_probe.py:346 run() |

## smb_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | smb_probe |
| Category | SMB configuration |
| Purpose | SMB dialect metadata and SMBv1 enabled |
| Detection logic | Handcrafted negotiate reply magic; status kept as null_session metadata |
| Target requirements | 445 else 139; handshake implementation |
| Trigger conditions | Any selected port number in [445, 139]; Advertised NBSS payload length exceeds actual frame; not a real null-session or signing test; 139 session setup unverified |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> smb_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | SMB magic, dialect label and NT status |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | smb.v1_enabled -> CCURE-CHK-SMB-V1-ENABLED |
| Execution status | Partially working/unreliable: D12 |
| Test coverage | tests/credentialed/test_smb_transport.py; tests/scans/test_network_check_promotion.py |
| Code reference | Backend/engines/vulnerability/plugins/smb_probe.py:27 run() |

## snmp_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | snmp_probe |
| Category | SNMP/network intelligence |
| Purpose | Default community and v1 exposure plus interface/host metadata |
| Detection logic | BER GET/GETNEXT with 15 guessed communities; bound OID walks; decoded sysDescr/platform |
| Target requirements | UDP161; SNMPv1-accessible community; no SNMPv3 here |
| Trigger conditions | Every active host; No real SNMP agent here; separate topology client supports configured SNMP credentials; cannot infer write access from GET |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> snmp_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Community, system OIDs, interfaces, IPs/masks, enterprise and bridge data |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | snmp.default_community -> CCURE-CHK-SNMP-DEFAULT-COMMUNITY; snmp.v1_v2c_in_use -> CCURE-CHK-SNMP-V1-V2C-IN-USE; snmp.information_disclosure -> CCURE-CHK-SNMP-INFORMATION-DISCLOSURE |
| Execution status | Unverified on a real target; reachable and test-supported |
| Test coverage | tests/scans/test_network_check_promotion.py; tests/scans/test_snmp_ber_decoding.py |
| Code reference | Backend/engines/vulnerability/plugins/snmp_probe.py:494 run() |

## ssh_probe

| Field | Evidence |
|---|---|
| Plugin ID/name | ssh_probe |
| Category | SSH configuration |
| Purpose | Weak KEX/cipher/MAC offerings |
| Detection logic | Banner and first received KEXINIT packet; compare name-lists with weak sets |
| Target requirements | 22 TCP only internally; no credential |
| Trigger conditions | Any selected port number in [22]; MAC list index is the server-to-client cipher list; partial TCP reads and other ports unhandled |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> ssh_probe.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Banner, offered algorithms and weak_algos |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | ssh.weak_algorithms -> CCURE-CHK-SSH-WEAK-ALGORITHMS |
| Execution status | Partially working/unreliable: D05 |
| Test coverage | tests/scans/test_network_check_promotion.py; tests/scans/test_database_areas.py |
| Code reference | Backend/engines/vulnerability/plugins/ssh_probe.py:38 run() |

## tls_scanner

| Field | Evidence |
|---|---|
| Plugin ID/name | tls_scanner |
| Category | TLS/certificates |
| Purpose | Protocol, cipher, certificate, key exchange and TLS features |
| Detection logic | Fast socket handshake plus SSLyze; 26 declared areas; implicit TLS then 6 STARTTLS service groups sharing deep budget |
| Target requirements | TLS or STARTTLS conventional ports; SSLyze dependency; TLS_DEEP_SCAN/TLS_STARTTLS_SCAN enabled; budget defaults 4 |
| Trigger conditions | Any selected port number in [443, 8443, 465, 993, 995, 989, 990, 5986, 8883, 25, 587, 2525, 143, 110, 21, 389, 636, 5432]; Actual loopback SSLyze/socket execution passed; fixed ports/SNI by IP, budget skips and shared endpoint dedup limit coverage |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> tls_scanner.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Certificate identity/chain/time/key, protocols/ciphers and feature tri-states per endpoint |
| Finding generation | Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings API and reports |
| CVE/CPE mapping | tls.deprecated_protocol -> CCURE-CHK-TLS-DEPRECATED-PROTOCOL; tls.no_secure_protocol -> CCURE-CHK-TLS-NO-SECURE-PROTOCOL; tls.weak_cipher_suite -> CCURE-CHK-TLS-WEAK-CIPHER-SUITE; tls.certificate_expired -> CCURE-CHK-TLS-CERTIFICATE-EXPIRED; tls.certificate_self_signed -> CCURE-CHK-TLS-CERTIFICATE-SELF-SIGNED; tls.certificate_weak_signature -> CCURE-CHK-TLS-CERTIFICATE-WEAK-SIGNATURE; tls.certificate_hostname_mismatch -> CCURE-CHK-TLS-CERTIFICATE-HOSTNAME-MISMATCH; tls.robot -> CCURE-CHK-TLS-ROBOT; tls.compression_crime -> CCURE-CHK-TLS-COMPRESSION-ENABLED; tls.certificate_untrusted_chain -> CCURE-CHK-TLS-CERTIFICATE-UNTRUSTED-CHAIN; tls.certificate_chain_order -> CCURE-CHK-TLS-CERTIFICATE-CHAIN-ORDER; tls.certificate_sha1_chain -> CCURE-CHK-TLS-CERTIFICATE-SHA1-CHAIN; tls.certificate_not_yet_valid -> CCURE-CHK-TLS-CERTIFICATE-NOT-YET-VALID; tls.certificate_weak_key -> CCURE-CHK-TLS-CERTIFICATE-WEAK-KEY; tls.ocsp_stapling_absent -> CCURE-CHK-TLS-OCSP-STAPLING-ABSENT; tls.must_staple_unhonoured -> CCURE-CHK-TLS-MUST-STAPLE-UNHONOURED; tls.fallback_scsv_unsupported -> CCURE-CHK-TLS-FALLBACK-SCSV-UNSUPPORTED; tls.client_renegotiation_dos -> CCURE-CHK-TLS-CLIENT-RENEGOTIATION-DOS; tls.weak_ecdh_curve -> CCURE-CHK-TLS-WEAK-ECDH-CURVE; tls.no_forward_secrecy -> CCURE-CHK-TLS-NO-FORWARD-SECRECY; tls.ccs_injection -> CVE-2014-0224; tls.early_data_enabled -> CCURE-CHK-TLS-EARLY-DATA-ENABLED; tls.extended_master_secret_absent -> CCURE-CHK-TLS-EXTENDED-MASTER-SECRET-ABSENT; tls.certificate_expiring_soon -> CCURE-CHK-TLS-CERTIFICATE-EXPIRING-SOON; tls.weak_dh_parameters -> CCURE-CHK-TLS-WEAK-DH-PARAMETERS; tls.insecure_renegotiation -> CCURE-CHK-TLS-INSECURE-RENEGOTIATION |
| Execution status | Partially working/unreliable: D10; live loopback scenario verified through engine normalization/scoring, persistence separately fixture-tested |
| Test coverage | tests/scans/test_tls_name_failures.py; tests/scans/test_network_check_promotion.py; tests/scans/test_tls_deep.py; tests/scans/test_tls_starttls.py |
| Code reference | Backend/engines/vulnerability/plugins/tls_scanner.py:813 run() |

## udp_scanner

| Field | Evidence |
|---|---|
| Plugin ID/name | udp_scanner |
| Category | Service discovery |
| Purpose | 9 conventional UDP responders |
| Detection logic | Sequential DNS/DHCP/TFTP/Kerberos/NTP/SNMP/LDAP/IKE/mDNS datagrams; mostly coarse response/length tests |
| Target requirements | Answering UDP service; always runs even with no listed open ports |
| Trigger conditions | Every active host; Result lacks protocol; late discovery never reselects dependent checks; several replies are not transaction/source validated; advisory prose is not a tested vulnerability |
| Execution entry point | POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> udp_scanner.run |
| Required credentials | None; automatic guessed defaults where stated |
| Evidence collected | Port, service, advisory prose; no vulnerability finding |
| Finding generation | Metadata only; no normalized vulnerability finding |
| CVE/CPE mapping | None |
| Execution status | Partially working/unreliable: D03,D04 |
| Test coverage | No direct module-named tests in baseline |
| Code reference | Backend/engines/vulnerability/plugins/udp_scanner.py:28 run() |

## Every built-in check

Shared trigger: an authenticated host/database audit with the built-in pack allowed by policy. Shared result path: collector -> ConfigAuditEngine -> explicit outcome/evidence -> FAIL finding -> normalizer/persistence/report. None is individually marked target-verified.

| Check ID | Purpose | Platform | Type/collection | Expected state; absence | Code reference |
|---|---|---|---|---|---|
| ccure.win.uac.enabled | User Account Control is enabled | windows | registry: {"path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "value": "EnableLUA"} | {"description": "EnableLUA = 1", "operator": "equals", "value": 1}; manual_review | Backend/core/config_audit/builtin/windows_host.py:47 |
| ccure.win.rdp.nla_required | RDP requires Network Level Authentication | windows | registry: {"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "value": "UserAuthentication"} | {"description": "UserAuthentication = 1", "operator": "equals", "value": 1}; manual_review | Backend/core/config_audit/builtin/windows_host.py:79 |
| ccure.win.smbv1.server_disabled | SMBv1 server is disabled | windows | registry: {"path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "value": "SMB1"} | {"description": "SMB1 = 0", "operator": "equals", "value": 0}; manual_review | Backend/core/config_audit/builtin/windows_host.py:105 |
| ccure.win.lsa.restrict_anonymous_sam | Anonymous enumeration of SAM accounts is restricted | windows | registry: {"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "value": "RestrictAnonymousSAM"} | {"description": "RestrictAnonymousSAM = 1", "operator": "equals", "value": 1}; manual_review | Backend/core/config_audit/builtin/windows_host.py:132 |
| ccure.win.firewall.service_running | Windows Firewall service is running | windows | service: {"attribute": "status", "name": "MpsSvc"} | {"description": "", "operator": "equals", "value": "Running"}; fail | Backend/core/config_audit/builtin/windows_host.py:155 |
| ccure.win.telnet.server_absent | Telnet server is not installed | windows | service: {"attribute": "status", "name": "TlntSvr"} | {"description": "", "operator": "not_equals", "value": "Running"}; pass | Backend/core/config_audit/builtin/windows_host.py:174 |
| ccure.win.remote_registry.not_running | Remote Registry service is not running | windows | service: {"attribute": "status", "name": "RemoteRegistry"} | {"description": "", "operator": "not_equals", "value": "Running"}; pass | Backend/core/config_audit/builtin/windows_host.py:196 |
| ccure.win.password.minimum_length | Minimum password length is at least 14 characters | windows | security_policy: {"setting": "min_length"} | {"description": "at least 14 characters", "operator": "gte", "value": 14}; manual_review | Backend/core/config_audit/builtin/windows_host.py:219 |
| ccure.win.password.history | Password history retains at least 24 passwords | windows | security_policy: {"setting": "history_length"} | {"description": "", "operator": "gte", "value": 24}; manual_review | Backend/core/config_audit/builtin/windows_host.py:240 |
| ccure.win.lockout.threshold | Account lockout threshold is set and workable | windows | security_policy: {"setting": "lockout_threshold"} | {"description": "between 1 and 10 failed attempts", "operator": "between", "value": [1, 10]}; manual_review | Backend/core/config_audit/builtin/windows_host.py:257 |
| ccure.linux.ssh.permit_root_login | SSH does not permit password-based root login | linux | config_file: {"key": "PermitRootLogin", "path": "/etc/ssh/sshd_config", "separator": ""} | {"description": "no, prohibit-password or forced-commands-only", "operator": "in", "value": ["no", "prohibit-password", "without-password", "forced-commands-only"]}; manual_review | Backend/core/config_audit/builtin/linux_host.py:43 |
| ccure.linux.ssh.password_authentication | SSH password authentication is disabled | linux | config_file: {"key": "PasswordAuthentication", "path": "/etc/ssh/sshd_config", "separator": ""} | {"description": "no", "operator": "is_false", "value": null}; manual_review | Backend/core/config_audit/builtin/linux_host.py:70 |
| ccure.linux.ssh.max_auth_tries | SSH limits authentication attempts per connection | linux | config_file: {"key": "MaxAuthTries", "path": "/etc/ssh/sshd_config", "separator": ""} | {"description": "at most 4", "operator": "lte", "value": 4}; manual_review | Backend/core/config_audit/builtin/linux_host.py:90 |
| ccure.linux.passwd.permissions | /etc/passwd is not group- or world-writable | linux | permission: {"attribute": "mode", "path": "/etc/passwd"} | {"description": "0644 or stricter", "operator": "in", "value": ["644", "0644", "444", "0444"]}; fail | Backend/core/config_audit/builtin/linux_host.py:107 |
| ccure.linux.shadow.permissions | /etc/shadow is not readable by unprivileged users | linux | permission: {"attribute": "mode", "path": "/etc/shadow"} | {"description": "0640 or stricter", "operator": "in", "value": ["0", "000", "400", "0400", "600", "0600", "640", "0640"]}; fail | Backend/core/config_audit/builtin/linux_host.py:127 |
| ccure.linux.auditd.running | The audit daemon is running | linux | service: {"attribute": "status", "name": "auditd"} | {"description": "", "operator": "equals", "value": "active"}; fail | Backend/core/config_audit/builtin/linux_host.py:148 |
| ccure.linux.telnet.port_closed | No telnet daemon is listening | linux | port: {"port": 23} | {"description": "", "operator": "not_equals", "value": "listening"}; pass | Backend/core/config_audit/builtin/linux_host.py:167 |
| ccure.linux.password.max_age | Password maximum age is set | linux | security_policy: {"setting": "pass_max_days"} | {"description": "at most 365 days", "operator": "lte", "value": 365}; manual_review | Backend/core/config_audit/builtin/linux_host.py:186 |
| ccure.linux.password.min_length | Password quality enforces a minimum length | linux | security_policy: {"setting": "minlen"} | {"description": "at least 14 characters", "operator": "gte", "value": 14}; manual_review | Backend/core/config_audit/builtin/linux_host.py:203 |
| ccure.linux.cron.permissions | /etc/crontab is not writable by unprivileged users | linux | permission: {"attribute": "mode", "path": "/etc/crontab"} | {"description": "0644 or stricter", "operator": "in", "value": ["600", "0600", "644", "0644"]}; not_applicable | Backend/core/config_audit/builtin/linux_host.py:220 |
| ccure.priv.win.service.acl | No service grants configuration rights to a non-administrator | windows | privilege: {"probe": "service_permissions"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:80 |
| ccure.priv.win.service.binary.acl | No service executable is writable by a non-administrator | windows | privilege: {"probe": "service_binary_permissions"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:104 |
| ccure.priv.win.always.install.elevated | AlwaysInstallElevated is not enabled | windows | privilege: {"probe": "always_install_elevated"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:126 |
| ccure.priv.win.service.unquoted.path | No service has an exploitable unquoted image path | windows | privilege: {"probe": "unquoted_service_path"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:147 |
| ccure.priv.win.task.binary.acl | No scheduled-task executable is writable by a non-administrator | windows | privilege: {"probe": "scheduled_task_permissions"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:173 |
| ccure.priv.win.writable.path | No directory on the system PATH is writable by a non-administrator | windows | privilege: {"probe": "writable_path"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:194 |
| ccure.priv.win.unattend.files | No unattended-install answer file remains on disk | windows | privilege: {"probe": "unattend_files"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:214 |
| ccure.priv.win.cached.logons | Cached logon count is limited | windows | privilege: {"probe": "cached_logons"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:235 |
| ccure.priv.win.lsa.protection | LSA runs as a protected process (RunAsPPL) | windows | privilege: {"probe": "lsa_protection"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:252 |
| ccure.priv.win.powershell.logging | PowerShell script-block logging is enabled | windows | privilege: {"probe": "powershell_logging"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_windows.py:269 |
| ccure.priv.linux.writable.path | No directory on root's PATH is writable by a non-root user | linux | privilege: {"probe": "writable_path"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:68 |
| ccure.priv.linux.sudo.nopasswd | No sudo rule grants command execution without a password | linux | privilege: {"probe": "sudo_nopasswd"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:90 |
| ccure.priv.linux.suid.unexpected | No unexpected binary carries the SUID bit | linux | privilege: {"probe": "suid_binaries"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:112 |
| ccure.priv.linux.worldwritable.dirs | No world-writable directory is missing the sticky bit | linux | privilege: {"probe": "world_writable_dirs"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:134 |
| ccure.priv.linux.root.path.integrity | Root's PATH contains no relative or empty entry | linux | privilege: {"probe": "root_path_integrity"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:155 |
| ccure.priv.linux.systemd.unit.writable | No systemd unit file is writable by a non-root user | linux | privilege: {"probe": "writable_systemd_units"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:175 |
| ccure.priv.linux.sgid.unexpected | No unexpected binary carries the SGID bit | linux | privilege: {"probe": "sgid_binaries"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:196 |
| ccure.priv.linux.worldwritable.files | No world-writable regular file outside pseudo-filesystems | linux | privilege: {"probe": "world_writable_files"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:213 |
| ccure.priv.linux.account.files.ownership | Account database files are root-owned and correctly permissioned | linux | privilege: {"probe": "sensitive_file_modes"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:227 |
| ccure.priv.linux.file.capabilities | No binary carries a privilege-granting file capability | linux | privilege: {"probe": "file_capabilities"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:249 |
| ccure.priv.linux.unowned.files | No file is owned by a user that does not exist | linux | privilege: {"probe": "unowned_files"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:273 |
| ccure.priv.linux.ungrouped.files | No file is owned by a group that does not exist | linux | privilege: {"probe": "ungrouped_files"} | {"description": "no offending items", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/privilege_linux.py:290 |
| ccure.db.postgresql.empty_password | No PostgreSQL login role has an empty password | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolpassword IS NULL"} | {"description": "no login role without a password", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:79 |
| ccure.db.postgresql.password_encryption | PostgreSQL stores passwords with SCRAM rather than MD5 | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'password_encryption'"} | {"description": "scram-sha-256", "operator": "equals", "value": "scram-sha-256"}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:117 |
| ccure.db.postgresql.md5_roles | No PostgreSQL role still holds an MD5 password verifier | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolpassword LIKE 'md5%'"} | {"description": "no role on an MD5 verifier", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:150 |
| ccure.db.postgresql.trust_authentication | PostgreSQL does not accept unauthenticated remote connections | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT type \|\| ' ' \|\| COALESCE(address, '') \|\| ' ' \|\| auth_method FROM pg_hba_file_rules WHERE auth_method IN ('trust', 'password') AND type <> 'local' AND COALESCE(address, '') NOT IN ('127.0.0.1', '::1', 'samehost', 'localhost')"} | {"description": "no remote trust or cleartext-password rule", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:188 |
| ccure.db.postgresql.log_connections | PostgreSQL records authentication attempts | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'log_connections'"} | {"description": "on", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:233 |
| ccure.db.postgresql.superuser_roles | PostgreSQL superuser is limited to the bootstrap role | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin AND rolname <> 'postgres'"} | {"description": "no login superuser besides postgres", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:255 |
| ccure.db.postgresql.filesystem_roles | No PostgreSQL role holds server filesystem or program privileges | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT m.rolname \|\| ' in ' \|\| r.rolname FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member WHERE r.rolname IN ('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program')"} | {"description": "no member of the filesystem roles", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:293 |
| ccure.db.postgresql.untrusted_languages | PostgreSQL has no untrusted procedural language installed | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT lanname FROM pg_language WHERE lanispl AND NOT lanpltrusted"} | {"description": "no untrusted procedural language", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:337 |
| ccure.db.postgresql.public_schema_create | PUBLIC cannot create objects in a PostgreSQL schema | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT nspname FROM pg_namespace WHERE has_schema_privilege('public', nspname, 'CREATE') AND nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'"} | {"description": "no schema where PUBLIC may create", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:374 |
| ccure.db.postgresql.public_table_grants | PUBLIC holds no privileges on user tables in PostgreSQL | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT table_schema \|\| '.' \|\| table_name \|\| ' ' \|\| privilege_type FROM information_schema.table_privileges WHERE grantee = 'PUBLIC' AND table_schema NOT IN ('pg_catalog', 'information_schema')"} | {"description": "no PUBLIC grant on user data", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:409 |
| ccure.db.postgresql.ssl_enabled | PostgreSQL offers TLS to clients | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'ssl'"} | {"description": "on", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:444 |
| ccure.db.postgresql.ssl_required | PostgreSQL requires TLS for remote connections | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT type \|\| ' ' \|\| COALESCE(address, '') \|\| ' ' \|\| auth_method FROM pg_hba_file_rules WHERE type IN ('host', 'hostnossl') AND auth_method <> 'reject' AND COALESCE(address, '') NOT IN ('127.0.0.1', '::1', 'samehost', 'localhost')"} | {"description": "every remote rule is hostssl", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:468 |
| ccure.db.postgresql.ssl_min_version | PostgreSQL refuses TLS below 1.2 | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'ssl_min_protocol_version'"} | {"description": "TLSv1.2 or TLSv1.3", "operator": "in", "value": ["tlsv1.2", "tlsv1.3"]}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:508 |
| ccure.db.postgresql.log_statement | PostgreSQL logs schema and privilege changes | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'log_statement'"} | {"description": "ddl, mod or all", "operator": "in", "value": ["ddl", "mod", "all"]}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:535 |
| ccure.db.postgresql.log_disconnections | PostgreSQL records session end and duration | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'log_disconnections'"} | {"description": "on", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:562 |
| ccure.db.postgresql.log_rotation | PostgreSQL rotates its log files | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'log_rotation_age'"} | {"description": "greater than 0 minutes", "operator": "gt", "value": 0}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:586 |
| ccure.db.postgresql.listen_addresses | PostgreSQL does not listen on every interface | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'listen_addresses'"} | {"description": "a named address, not a wildcard", "operator": "not_in", "value": ["*", "0.0.0.0", "::"]}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:611 |
| ccure.db.postgresql.version_supported | PostgreSQL is a release still receiving fixes | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'server_version_num'"} | {"description": "PostgreSQL 14 or later (as at 2026-08)", "operator": "gte", "value": 140000}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:650 |
| ccure.db.postgresql.system_table_mods | PostgreSQL does not permit direct system catalogue modification | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'allow_system_table_mods'"} | {"description": "off", "operator": "is_false", "value": null}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:685 |
| ccure.db.postgresql.superuser_reserved | PostgreSQL reserves connection slots for administrators | database | database_query: {"engine": "postgresql", "sql": "SELECT setting FROM pg_settings WHERE name = 'superuser_reserved_connections'"} | {"description": "at least one reserved slot", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/database_postgresql.py:713 |
| ccure.db.postgresql.sample_databases | PostgreSQL carries no sample database | database | database_query: {"engine": "postgresql", "result": "rows", "sql": "SELECT datname FROM pg_database WHERE datname IN ('pagila', 'dellstore', 'dellstore2', 'sakila', 'northwind', 'adventureworks', 'chinook', 'employees')"} | {"description": "no sample database", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_postgresql.py:746 |
| ccure.db.mysql.empty_password | No MySQL account has an empty password | database | database_query: {"engine": "mysql", "result": "rows", "sql": "SELECT CONCAT(user, '@', host) FROM mysql.user WHERE authentication_string = '' AND plugin NOT IN ('auth_socket', 'unix_socket', 'mysql_no_login')"} | {"description": "no account without a password", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mysql.py:73 |
| ccure.db.mysql.anonymous_accounts | MySQL has no anonymous account | database | database_query: {"engine": "mysql", "result": "rows", "sql": "SELECT CONCAT('anonymous@', host) FROM mysql.user WHERE user = ''"} | {"description": "no anonymous account", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mysql.py:110 |
| ccure.db.mysql.weak_auth_plugin | No MySQL account uses a legacy authentication plugin | database | database_query: {"engine": "mysql", "result": "rows", "sql": "SELECT CONCAT(user, '@', host, ' uses ', plugin) FROM mysql.user WHERE plugin IN ('mysql_native_password', 'mysql_old_password')"} | {"description": "no account on a legacy plugin", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mysql.py:142 |
| ccure.db.mysql.root_remote | MySQL root is restricted to the local host | database | database_query: {"engine": "mysql", "result": "rows", "sql": "SELECT CONCAT(user, '@', host) FROM mysql.user WHERE user = 'root' AND host NOT IN ('localhost', '127.0.0.1', '::1')"} | {"description": "root@localhost only", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mysql.py:181 |
| ccure.db.mysql.validate_password | MySQL enforces a password policy | database | database_query: {"engine": "mysql", "result": "count", "sql": "SELECT plugin_name AS item FROM information_schema.plugins WHERE plugin_name LIKE 'validate_password%' AND plugin_status = 'ACTIVE' UNION ALL SELECT component_urn AS item FROM mysql.component WHERE component_urn LIKE '%validate_password%'"} | {"description": "the password plugin or component is active", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:217 |
| ccure.db.mysql.super_privilege | No ordinary MySQL account holds administrative privileges | database | database_query: {"engine": "mysql", "result": "rows", "sql": "SELECT CONCAT(grantee, ' holds ', privilege_type) FROM information_schema.user_privileges WHERE privilege_type IN ('SUPER', 'SHUTDOWN', 'PROCESS') AND grantee NOT LIKE '''root''@%' AND grantee NOT LIKE '''mysql.%'"} | {"description": "no non-root account with SUPER", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mysql.py:269 |
| ccure.db.mysql.file_privilege | No ordinary MySQL account holds the FILE privilege | database | database_query: {"engine": "mysql", "result": "rows", "sql": "SELECT CONCAT(user, '@', host) FROM mysql.user WHERE File_priv = 'Y' AND user <> 'root' AND user NOT LIKE 'mysql.%'"} | {"description": "no non-root FILE holder", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mysql.py:308 |
| ccure.db.mysql.secure_file_priv | MySQL confines server-side file access to one directory | database | database_query: {"engine": "mysql", "sql": "SELECT COALESCE(@@GLOBAL.secure_file_priv, 'DISABLED')"} | {"description": "a directory, or NULL to disable file access entirely", "operator": "not_equals", "value": ""}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:344 |
| ccure.db.mysql.have_ssl | MySQL offers TLS to clients | database | database_query: {"engine": "mysql", "sql": "SELECT @@GLOBAL.have_ssl"} | {"description": "YES", "operator": "in", "value": ["yes", "1"]}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:390 |
| ccure.db.mysql.require_secure_transport | MySQL requires encrypted client connections | database | database_query: {"engine": "mysql", "sql": "SELECT @@GLOBAL.require_secure_transport"} | {"description": "ON", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:416 |
| ccure.db.mysql.tls_version | MySQL offers no TLS version below 1.2 | database | database_query: {"engine": "mysql", "sql": "SELECT @@GLOBAL.tls_version"} | {"description": "no TLSv1 or TLSv1.1 in the offered list", "operator": "not_matches", "value": "TLSv1(\\.1)?(,\|$)"}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:448 |
| ccure.db.mysql.local_infile | MySQL does not permit LOAD DATA LOCAL | database | database_query: {"engine": "mysql", "sql": "SELECT @@GLOBAL.local_infile"} | {"description": "OFF", "operator": "is_false", "value": null}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:474 |
| ccure.db.mysql.bind_address | MySQL does not listen on every interface | database | database_query: {"engine": "mysql", "sql": "SELECT @@GLOBAL.bind_address"} | {"description": "a named address, not a wildcard", "operator": "not_in", "value": ["*", "0.0.0.0", "::"]}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:501 |
| ccure.db.mysql.version_supported | MySQL is a release still receiving fixes | database | database_query: {"engine": "mysql", "sql": "SELECT @@GLOBAL.version"} | {"description": "MySQL 8.0 or later (as at 2026-08)", "operator": "version_gte", "value": "8.0"}; manual_review | Backend/core/config_audit/builtin/database_mysql.py:531 |
| ccure.db.mysql.sample_databases | MySQL carries no sample schema | database | database_query: {"engine": "mysql", "result": "rows", "sql": "SELECT schema_name FROM information_schema.schemata WHERE schema_name IN ('test', 'world', 'world_x', 'sakila', 'employees', 'menagerie')"} | {"description": "no sample schema", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mysql.py:561 |
| ccure.db.mssql.blank_password | No SQL Server login has a blank password | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT name FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1 AND is_disabled = 0"} | {"description": "no login with a blank password", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:74 |
| ccure.db.mssql.login_named_password | No SQL Server login uses its own name as the password | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT name FROM sys.sql_logins WHERE PWDCOMPARE(name, password_hash) = 1 AND is_disabled = 0"} | {"description": "no login whose password is its name", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:109 |
| ccure.db.mssql.password_policy | SQL Server logins are subject to the password policy | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0 AND is_disabled = 0"} | {"description": "every enabled login has CHECK_POLICY on", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:140 |
| ccure.db.mssql.sa_enabled | The SQL Server sa login is disabled | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT name FROM sys.sql_logins WHERE sid = 0x01 AND is_disabled = 0"} | {"description": "sa is disabled", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:175 |
| ccure.db.mssql.sysadmin_members | SQL Server sysadmin membership is limited | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT p.name FROM sys.server_role_members m JOIN sys.server_principals r ON r.principal_id = m.role_principal_id JOIN sys.server_principals p ON p.principal_id = m.member_principal_id WHERE r.name = 'sysadmin' AND p.name <> 'sa' AND p.name NOT LIKE 'NT AUTHORITY\\%' AND p.name NOT LIKE 'NT SERVICE\\%' AND p.name NOT LIKE 'BUILTIN\\%'"} | {"description": "no sysadmin beyond sa and service accounts", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:213 |
| ccure.db.mssql.public_server_permissions | SQL Server public role holds no granted server permission | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT pe.permission_name FROM sys.server_permissions pe JOIN sys.server_principals pr ON pr.principal_id = pe.grantee_principal_id WHERE pr.name = 'public' AND pe.state_desc = 'GRANT' AND pe.permission_name NOT LIKE 'CONNECT%' AND pe.permission_name <> 'VIEW ANY DATABASE'"} | {"description": "no non-default grant to public", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:257 |
| ccure.db.mssql.bulk_operations | SQL Server bulk filesystem access is not granted broadly | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT pr.name FROM sys.server_permissions pe JOIN sys.server_principals pr ON pr.principal_id = pe.grantee_principal_id WHERE pe.permission_name = 'ADMINISTER BULK OPERATIONS' AND pe.state_desc = 'GRANT' AND pr.name <> 'sa'"} | {"description": "no principal holds bulk operations", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:298 |
| ccure.db.mssql.dangerous_features | SQL Server command-execution features are disabled | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT name FROM sys.configurations WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures', 'clr enabled', 'Ad Hoc Distributed Queries', 'cross db ownership chaining', 'scan for startup procs') AND value_in_use <> 0"} | {"description": "none of the listed options is enabled", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:338 |
| ccure.db.mssql.connection_encrypted | SQL Server encrypts client connections | database | database_query: {"engine": "mssql", "sql": "SELECT CAST(encrypt_option AS VARCHAR(10)) FROM sys.dm_exec_connections WHERE session_id = @@SPID"} | {"description": "TRUE", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/database_mssql.py:386 |
| ccure.db.mssql.audit_running | SQL Server has a running audit | database | database_query: {"engine": "mssql", "result": "count", "sql": "SELECT name FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED'"} | {"description": "at least one audit is started", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/database_mssql.py:429 |
| ccure.db.mssql.audit_specification | SQL Server audit has an enabled specification | database | database_query: {"engine": "mssql", "result": "count", "sql": "SELECT name FROM sys.server_audit_specifications WHERE is_state_enabled = 1"} | {"description": "at least one enabled specification", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/database_mssql.py:461 |
| ccure.db.mssql.version_supported | SQL Server is a release still receiving fixes | database | database_query: {"engine": "mssql", "sql": "SELECT CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR(64)), 4) AS INT)"} | {"description": "SQL Server 2017 or later (as at 2026-08)", "operator": "gte", "value": 14}; manual_review | Backend/core/config_audit/builtin/database_mssql.py:500 |
| ccure.db.mssql.sample_databases | SQL Server carries no sample database | database | database_query: {"engine": "mssql", "result": "rows", "sql": "SELECT name FROM sys.databases WHERE name IN ('AdventureWorks', 'AdventureWorksDW', 'AdventureWorks2019', 'AdventureWorks2022', 'Northwind', 'pubs', 'WideWorldImporters', 'WideWorldImportersDW')"} | {"description": "no sample database", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/database_mssql.py:539 |
| ccure.mw.nginx.server_tokens | nginx does not advertise its version | linux,windows | structured_config: {"directive": "server_tokens", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value"} | {"description": "off", "operator": "is_false", "value": null}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:103 |
| ccure.mw.nginx.stub_status | nginx does not expose the stub_status endpoint | linux,windows | structured_config: {"directive": "stub_status", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "count"} | {"description": "no stub_status location", "operator": "lte", "value": 0}; pass | Backend/core/config_audit/builtin/middleware_nginx.py:125 |
| ccure.mw.nginx.run_as_user | nginx worker processes do not run as root | linux,windows | structured_config: {"directive": "user", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value", "scope": []} | {"description": "a non-root account", "operator": "not_in", "value": ["root", "root root"]}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:148 |
| ccure.mw.nginx.ssl_protocols | nginx offers no TLS version below 1.2 | linux,windows | structured_config: {"directive": "ssl_protocols", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value"} | {"description": "no SSLv2/3, TLSv1.0 or TLSv1.1", "operator": "not_matches", "value": "(^\|\\s)(SSLv[23]\|TLSv1(\\.1)?)(\\s\|$)"}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:169 |
| ccure.mw.nginx.ssl_ciphers | nginx excludes null, export and anonymous cipher suites | linux,windows | structured_config: {"directive": "ssl_ciphers", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value"} | {"description": "no NULL, EXPORT, LOW, RC4, DES or MD5 suites", "operator": "not_matches", "value": "(^\|:)(NULL\|aNULL\|eNULL\|EXP(ORT)?\|LOW\|RC4\|DES\|MD5)(:\|$)"}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:193 |
| ccure.mw.nginx.ssl_prefer_server_ciphers | nginx enforces its own cipher preference order | linux,windows | structured_config: {"directive": "ssl_prefer_server_ciphers", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value"} | {"description": "on", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:221 |
| ccure.mw.nginx.access_log | nginx records access to served content | linux,windows | structured_config: {"directive": "access_log", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value", "scope": ["http"]} | {"description": "a log destination", "operator": "not_equals", "value": "off"}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:242 |
| ccure.mw.nginx.error_log | nginx records errors at a usable level | linux,windows | structured_config: {"directive": "error_log", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value", "scope": []} | {"description": "notice, info, warn or error \u2014 not only the fatal levels", "operator": "not_contains", "value": ["emerg", "alert", "crit"]}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:265 |
| ccure.mw.nginx.client_max_body_size | nginx bounds the size of a request body | linux,windows | structured_config: {"directive": "client_max_body_size", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value"} | {"description": "a non-zero limit (0 means unlimited)", "operator": "not_equals", "value": "0"}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:289 |
| ccure.mw.nginx.keepalive_timeout | nginx closes idle keep-alive connections | linux,windows | structured_config: {"directive": "keepalive_timeout", "format": "nginx", "path": ["/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/opt/nginx/conf/nginx.conf"], "result": "value", "scope": ["http"]} | {"description": "a non-zero timeout (0 disables keep-alive)", "operator": "not_equals", "value": "0"}; manual_review | Backend/core/config_audit/builtin/middleware_nginx.py:313 |
| ccure.mw.apache.server_tokens | Apache does not advertise its version and modules | linux,windows | structured_config: {"directive": "ServerTokens", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "value"} | {"description": "Prod", "operator": "in", "value": ["prod", "productonly"]}; manual_review | Backend/core/config_audit/builtin/middleware_apache.py:97 |
| ccure.mw.apache.server_status | Apache does not expose server-status or server-info | linux,windows | structured_config: {"directive": "SetHandler", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "values"} | {"description": "no server-status or server-info handler", "operator": "not_contains", "value": ["server-status", "server-info"]}; pass | Backend/core/config_audit/builtin/middleware_apache.py:120 |
| ccure.mw.apache.run_as_user | Apache does not run its workers as root | linux,windows | structured_config: {"directive": "User", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "value"} | {"description": "a non-root account", "operator": "not_in", "value": ["root", "#0"]}; manual_review | Backend/core/config_audit/builtin/middleware_apache.py:147 |
| ccure.mw.apache.allow_override | Apache does not honour .htaccess overrides | linux,windows | structured_config: {"directive": "AllowOverride", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "values", "scope": ["Directory"]} | {"description": "None or a named directive group, never All", "operator": "not_contains", "value": ["all"]}; manual_review | Backend/core/config_audit/builtin/middleware_apache.py:173 |
| ccure.mw.apache.log_level | Apache logs at a level that records rejected requests | linux,windows | structured_config: {"directive": "LogLevel", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "value"} | {"description": "warn, info or debug", "operator": "not_in", "value": ["emerg", "alert", "crit", "error"]}; manual_review | Backend/core/config_audit/builtin/middleware_apache.py:202 |
| ccure.mw.apache.custom_log | Apache records access to served content | linux,windows | structured_config: {"directive": "CustomLog", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "count"} | {"description": "at least one access log", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/middleware_apache.py:223 |
| ccure.mw.apache.error_log | Apache records errors to a defined destination | linux,windows | structured_config: {"directive": "ErrorLog", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "count"} | {"description": "an error log destination", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/middleware_apache.py:248 |
| ccure.mw.apache.timeout | Apache bounds how long a request may take | linux,windows | structured_config: {"directive": "Timeout", "format": "apache", "path": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf"], "result": "value"} | {"description": "120 seconds or less", "operator": "lte", "value": 120}; manual_review | Backend/core/config_audit/builtin/middleware_apache.py:269 |
| ccure.mw.tomcat.shutdown_command | Tomcat does not use the default shutdown command | linux,windows | structured_config: {"attribute": "shutdown", "format": "xml", "path": ["/usr/local/tomcat/conf/server.xml", "/opt/tomcat/conf/server.xml", "/etc/tomcat10/server.xml", "/etc/tomcat9/server.xml", "/var/lib/tomcat9/conf/server.xml"], "result": "value", "xpath": "."} | {"description": "anything but the default word", "operator": "not_equals", "value": "SHUTDOWN"}; manual_review | Backend/core/config_audit/builtin/middleware_tomcat.py:101 |
| ccure.mw.tomcat.shutdown_port | Tomcat's shutdown port is disabled | linux,windows | structured_config: {"attribute": "port", "format": "xml", "path": ["/usr/local/tomcat/conf/server.xml", "/opt/tomcat/conf/server.xml", "/etc/tomcat10/server.xml", "/etc/tomcat9/server.xml", "/var/lib/tomcat9/conf/server.xml"], "result": "value", "xpath": "."} | {"description": "-1 (disabled)", "operator": "equals", "value": "-1"}; manual_review | Backend/core/config_audit/builtin/middleware_tomcat.py:129 |
| ccure.mw.tomcat.default_accounts | Tomcat defines no accounts in tomcat-users.xml | linux,windows | structured_config: {"attribute": "username", "format": "xml", "path": ["/usr/local/tomcat/conf/tomcat-users.xml", "/opt/tomcat/conf/tomcat-users.xml", "/etc/tomcat10/tomcat-users.xml", "/etc/tomcat9/tomcat-users.xml", "/var/lib/tomcat9/conf/tomcat-users.xml"], "result": "values", "xpath": ".//user"} | {"description": "no user defined", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/middleware_tomcat.py:155 |
| ccure.mw.tomcat.access_log_valve | Tomcat records access to deployed applications | linux,windows | structured_config: {"format": "xml", "path": ["/usr/local/tomcat/conf/server.xml", "/opt/tomcat/conf/server.xml", "/etc/tomcat10/server.xml", "/etc/tomcat9/server.xml", "/var/lib/tomcat9/conf/server.xml"], "result": "count", "xpath": ".//Valve[@className='org.apache.catalina.valves.AccessLogValve']"} | {"description": "an AccessLogValve is configured", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/middleware_tomcat.py:182 |
| ccure.mw.tomcat.connector_server_header | Tomcat connectors do not advertise the product | linux,windows | structured_config: {"attribute": "server", "format": "xml", "path": ["/usr/local/tomcat/conf/server.xml", "/opt/tomcat/conf/server.xml", "/etc/tomcat10/server.xml", "/etc/tomcat9/server.xml", "/var/lib/tomcat9/conf/server.xml"], "result": "value", "xpath": ".//Connector"} | {"description": "a neutral Server header, or none", "operator": "not_matches", "value": "(apache-?coyote\|tomcat)"}; manual_review | Backend/core/config_audit/builtin/middleware_tomcat.py:212 |
| ccure.mw.tomcat.manager_app | Tomcat does not deploy the manager application | linux,windows | directory: {"attribute": "exists", "path": "/usr/local/tomcat/webapps/manager"} | {"description": "manager is not deployed", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/middleware_tomcat.py:300 |
| ccure.mw.tomcat.host_manager_app | Tomcat does not deploy the host-manager application | linux,windows | directory: {"attribute": "exists", "path": "/usr/local/tomcat/webapps/host-manager"} | {"description": "host-manager is not deployed", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/middleware_tomcat.py:313 |
| ccure.mw.tomcat.examples_app | Tomcat does not deploy the examples application | linux,windows | directory: {"attribute": "exists", "path": "/usr/local/tomcat/webapps/examples"} | {"description": "examples is not deployed", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/middleware_tomcat.py:326 |
| ccure.mw.tomcat.docs_app | Tomcat does not deploy the documentation application | linux,windows | directory: {"attribute": "exists", "path": "/usr/local/tomcat/webapps/docs"} | {"description": "docs is not deployed", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/middleware_tomcat.py:339 |
| ccure.mw.docker.tcp_socket | The Docker daemon does not listen on a TCP socket | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "hosts", "result": "values"} | {"description": "unix socket only", "operator": "not_matches", "value": "tcp://"}; pass | Backend/core/config_audit/builtin/middleware_docker.py:88 |
| ccure.mw.docker.socket_tls | The Docker daemon requires TLS client certificates | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "tlsverify", "result": "value"} | {"description": "true", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/middleware_docker.py:114 |
| ccure.mw.docker.inter_container_communication | Docker restricts traffic between containers on the default bridge | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "icc", "result": "value"} | {"description": "false", "operator": "is_false", "value": null}; manual_review | Backend/core/config_audit/builtin/middleware_docker.py:143 |
| ccure.mw.docker.insecure_registries | Docker trusts no registry over plain HTTP | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "insecure-registries", "result": "values"} | {"description": "no insecure registry", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/middleware_docker.py:169 |
| ccure.mw.docker.no_new_privileges | Docker containers cannot gain new privileges by default | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "no-new-privileges", "result": "value"} | {"description": "true", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/middleware_docker.py:191 |
| ccure.mw.docker.userns_remap | Docker remaps container root to an unprivileged host user | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "userns-remap", "result": "value"} | {"description": "a remap user, commonly 'default'", "operator": "not_empty", "value": null}; manual_review | Backend/core/config_audit/builtin/middleware_docker.py:211 |
| ccure.mw.docker.log_driver | Docker sends container output to a defined log driver | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "log-driver", "result": "value"} | {"description": "a named driver", "operator": "not_empty", "value": null}; pass | Backend/core/config_audit/builtin/middleware_docker.py:234 |
| ccure.mw.docker.log_level | The Docker daemon logs at a usable level | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "log-level", "result": "value"} | {"description": "info, warn or debug", "operator": "not_in", "value": ["fatal", "panic", "error"]}; pass | Backend/core/config_audit/builtin/middleware_docker.py:257 |
| ccure.mw.docker.default_ulimits | Docker applies default resource limits to containers | linux,windows | structured_config: {"format": "json", "missing_file": "absent", "path": ["/etc/docker/daemon.json"], "pointer": "default-ulimits", "result": "count"} | {"description": "at least one default ulimit", "operator": "gte", "value": 1}; manual_review | Backend/core/config_audit/builtin/middleware_docker.py:277 |
| ccure.mw.nginx.config_permissions | The nginx configuration file is not world-readable | linux | permission: {"attribute": "mode", "path": "/etc/nginx/nginx.conf"} | {"description": "no access for 'other'", "operator": "in", "value": ["600", "640", "660", "400", "440", "460", "700", "740", "750", "770", "500", "540", "550"]}; not_applicable | Backend/core/config_audit/builtin/middleware_common.py:96 |
| ccure.mw.apache.config_permissions | The Apache configuration file is not world-readable | linux | permission: {"attribute": "mode", "path": "/etc/apache2/apache2.conf"} | {"description": "no access for 'other'", "operator": "in", "value": ["600", "640", "660", "400", "440", "460", "700", "740", "750", "770", "500", "540", "550"]}; not_applicable | Backend/core/config_audit/builtin/middleware_common.py:102 |
| ccure.mw.tomcat.config_permissions | The Tomcat users file is not world-readable | linux | permission: {"attribute": "mode", "path": "/usr/local/tomcat/conf/tomcat-users.xml"} | {"description": "no access for 'other'", "operator": "in", "value": ["600", "640", "660", "400", "440", "460", "700", "740", "750", "770", "500", "540", "550"]}; not_applicable | Backend/core/config_audit/builtin/middleware_common.py:108 |
| ccure.mw.docker.config_permissions | The Docker daemon configuration is not world-writable | linux | permission: {"attribute": "mode", "path": "/etc/docker/daemon.json"} | {"description": "no access for 'other'", "operator": "in", "value": ["600", "640", "660", "400", "440", "460", "700", "740", "750", "770", "500", "540", "550"]}; not_applicable | Backend/core/config_audit/builtin/middleware_common.py:114 |
| ccure.ctr.docker.privileged | No container runs with --privileged | linux | container: {"probe": "docker.privileged", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:82 |
| ccure.ctr.docker.host_namespaces | No container shares the host PID, IPC or UTS namespace | linux | container: {"probe": "docker.host_namespaces", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:105 |
| ccure.ctr.docker.host_network | No container shares the host network namespace | linux | container: {"probe": "docker.host_network", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:126 |
| ccure.ctr.docker.socket_mount | No container has the Docker socket mounted into it | linux | container: {"probe": "docker.docker_socket", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:146 |
| ccure.ctr.docker.sensitive_mounts | No container bind-mounts a sensitive host path | linux | container: {"probe": "docker.sensitive_mounts", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:171 |
| ccure.ctr.docker.run_as_root | No container runs its process as uid 0 | linux | container: {"probe": "docker.run_as_root", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:194 |
| ccure.ctr.docker.added_capabilities | No container is granted a capability that reaches the host | linux | container: {"probe": "docker.added_capabilities", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:216 |
| ccure.ctr.docker.no_new_privileges | Containers are started with no-new-privileges | linux | container: {"probe": "docker.no_new_privileges", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:241 |
| ccure.ctr.docker.readonly_rootfs | Containers run with a read-only root filesystem | linux | container: {"probe": "docker.readonly_rootfs", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:260 |
| ccure.ctr.k8s.privileged_pods | No workload pod runs a privileged container | linux | container: {"probe": "k8s.privileged_pods", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:281 |
| ccure.ctr.k8s.host_namespace_pods | No workload pod shares a host namespace | linux | container: {"probe": "k8s.host_namespace_pods", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:305 |
| ccure.ctr.k8s.root_pods | Workload pods declare that they do not run as root | linux | container: {"probe": "k8s.root_pods", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:327 |
| ccure.ctr.k8s.pod_security | Namespaces enforce a Pod Security standard | linux | container: {"probe": "k8s.pod_security_namespaces", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:351 |
| ccure.ctr.k8s.cluster_admin | cluster-admin is not bound beyond the cluster's own bindings | linux | container: {"probe": "k8s.cluster_admin_bindings", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:377 |
| ccure.ctr.k8s.wildcard_roles | No custom role grants wildcard verbs on wildcard resources | linux | container: {"probe": "k8s.wildcard_roles", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:400 |
| ccure.ctr.k8s.default_sa_automount | Default ServiceAccounts do not automount their token | linux | container: {"probe": "k8s.default_sa_automount", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:423 |
| ccure.ctr.k8s.rbac_enabled | The cluster enforces RBAC authorization | linux | container: {"probe": "k8s.rbac_disabled", "result": "rows"} | {"description": "nothing offending", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_runtime.py:450 |
| ccure.ctr.kubelet.anonymous_auth | The kubelet refuses anonymous requests | linux | structured_config: {"format": "yaml", "path": ["/var/lib/kubelet/config.yaml", "/etc/kubernetes/kubelet/kubelet-config.yaml", "/var/lib/rancher/k3s/agent/kubelet.config.yaml"], "pointer": "authentication.anonymous.enabled"} | {"description": "false", "operator": "is_false", "value": null}; manual_review | Backend/core/config_audit/builtin/container_config.py:96 |
| ccure.ctr.kubelet.authorization_mode | The kubelet authorizes requests through the API server | linux | structured_config: {"format": "yaml", "path": ["/var/lib/kubelet/config.yaml", "/etc/kubernetes/kubelet/kubelet-config.yaml", "/var/lib/rancher/k3s/agent/kubelet.config.yaml"], "pointer": "authorization.mode"} | {"description": "Webhook", "operator": "equals", "value": "Webhook"}; manual_review | Backend/core/config_audit/builtin/container_config.py:122 |
| ccure.ctr.kubelet.readonly_port | The kubelet read-only port is disabled | linux | structured_config: {"format": "yaml", "path": ["/var/lib/kubelet/config.yaml", "/etc/kubernetes/kubelet/kubelet-config.yaml", "/var/lib/rancher/k3s/agent/kubelet.config.yaml"], "pointer": "readOnlyPort"} | {"description": "0 (disabled)", "operator": "equals", "value": 0}; manual_review | Backend/core/config_audit/builtin/container_config.py:142 |
| ccure.ctr.kubelet.client_ca | The kubelet verifies client certificates against a CA | linux | structured_config: {"format": "yaml", "path": ["/var/lib/kubelet/config.yaml", "/etc/kubernetes/kubelet/kubelet-config.yaml", "/var/lib/rancher/k3s/agent/kubelet.config.yaml"], "pointer": "authentication.x509.clientCAFile"} | {"description": "a CA file path", "operator": "not_empty", "value": null}; manual_review | Backend/core/config_audit/builtin/container_config.py:162 |
| ccure.ctr.kubelet.rotate_certificates | The kubelet rotates its client certificate | linux | structured_config: {"format": "yaml", "path": ["/var/lib/kubelet/config.yaml", "/etc/kubernetes/kubelet/kubelet-config.yaml", "/var/lib/rancher/k3s/agent/kubelet.config.yaml"], "pointer": "rotateCertificates"} | {"description": "true", "operator": "is_true", "value": null}; manual_review | Backend/core/config_audit/builtin/container_config.py:185 |
| ccure.ctr.containerd.config_readable | The containerd configuration is present and parseable | linux | structured_config: {"format": "toml", "path": ["/etc/containerd/config.toml", "/var/lib/rancher/k3s/agent/etc/containerd/config.toml"], "pointer": "version"} | {"description": "config schema version 2 or later", "operator": "gte", "value": 2}; manual_review | Backend/core/config_audit/builtin/container_config.py:207 |
| ccure.ctr.containerd.insecure_mirrors | containerd verifies TLS for every registry mirror | linux | structured_config: {"format": "toml", "path": ["/etc/containerd/config.toml", "/var/lib/rancher/k3s/agent/etc/containerd/config.toml"], "pointer": ["plugins", "io.containerd.grpc.v1.cri", "registry", "configs"], "result": "values"} | {"description": "no per-registry TLS override configured", "operator": "is_empty", "value": null}; pass | Backend/core/config_audit/builtin/container_config.py:243 |

## Every network check area

These 57 catalogue entries belong to 13 of the 15 modules; they are not 57 additional implementation modules. ICMP and UDP modules emit intelligence only. Dynamic areas denote CVE and Nuclei families, not all individual feed/template records.

| Area | Plugin | Purpose | Identifier/CVE | Severity | Remediation |
|---|---|---|---|---|---|
| tls.deprecated_protocol | tls_scanner | Deprecated TLS/SSL protocol version offered | CCURE-CHK-TLS-DEPRECATED-PROTOCOL | medium | Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 on this listener and offer TLS 1.2 and TLS 1.3 only. |
| tls.no_secure_protocol | tls_scanner | No modern TLS protocol offered | CCURE-CHK-TLS-NO-SECURE-PROTOCOL | critical | Enable TLS 1.2 and TLS 1.3 on this listener. |
| tls.weak_cipher_suite | tls_scanner | Weak TLS cipher suite offered | CCURE-CHK-TLS-WEAK-CIPHER-SUITE | high | Restrict the cipher list to AEAD suites (AES-GCM, ChaCha20-Poly1305) with forward secrecy, and remove RC4, DES, 3DES, EXPORT, anon and NULL suites. |
| tls.certificate_expired | tls_scanner | TLS certificate has expired | CCURE-CHK-TLS-CERTIFICATE-EXPIRED | medium | Renew the certificate and automate renewal before expiry. |
| tls.certificate_self_signed | tls_scanner | TLS certificate is self-signed | CCURE-CHK-TLS-CERTIFICATE-SELF-SIGNED | medium | Issue the certificate from a CA the clients trust. Where a public CA cannot be used, deploy an internal CA and distribute its root to every client. |
| tls.certificate_weak_signature | tls_scanner | TLS certificate signed with a weak algorithm | CCURE-CHK-TLS-CERTIFICATE-WEAK-SIGNATURE | medium | Re-issue the certificate with a SHA-256 or stronger signature. |
| tls.certificate_hostname_mismatch | tls_scanner | TLS certificate does not match the host | CCURE-CHK-TLS-CERTIFICATE-HOSTNAME-MISMATCH | medium | Re-issue the certificate with every name and address clients use in its subjectAltName extension. |
| tls.heartbleed | heartbleed_probe | OpenSSL Heartbleed memory disclosure | CVE-2014-0160 | critical | Upgrade OpenSSL to 1.0.1g or later and rotate every key and credential the affected process held. |
| tls.robot | tls_scanner | Bleichenbacher RSA oracle (ROBOT) | CCURE-CHK-TLS-ROBOT | high | Disable RSA key-exchange cipher suites, or apply the vendor patch for the TLS stack in use. |
| tls.compression_crime | tls_scanner | TLS compression enabled (CRIME) | CCURE-CHK-TLS-COMPRESSION-ENABLED | medium | Disable TLS compression on this listener. |
| tls.certificate_untrusted_chain | tls_scanner | Server certificate does not chain to a trusted root | CCURE-CHK-TLS-CERTIFICATE-UNTRUSTED-CHAIN | medium | Serve the full chain including intermediates, or replace the certificate with one issued by a CA the clients trust. A deliberately private CA is a legitimate answer — distribute its root to the clients that need it. |
| tls.certificate_chain_order | tls_scanner | Certificate chain is sent out of order | CCURE-CHK-TLS-CERTIFICATE-CHAIN-ORDER | low | Concatenate the leaf first, then each issuer in turn. |
| tls.certificate_sha1_chain | tls_scanner | SHA-1 signature in the verified certificate chain | CCURE-CHK-TLS-CERTIFICATE-SHA1-CHAIN | medium | Reissue from a chain signed with SHA-256 or better; ask the CA for a cross-signed intermediate if the old one is still served. |
| tls.certificate_not_yet_valid | tls_scanner | Server certificate is not yet valid | CCURE-CHK-TLS-CERTIFICATE-NOT-YET-VALID | high | Correct the server clock, or wait for the validity window to open. If the certificate was issued early, reissue it. |
| tls.certificate_weak_key | tls_scanner | Server certificate uses a key below the modern floor | CCURE-CHK-TLS-CERTIFICATE-WEAK-KEY | high | Reissue with a 2048-bit RSA key or a P-256 curve, at least. |
| tls.ocsp_stapling_absent | tls_scanner | Server staples no OCSP response | CCURE-CHK-TLS-OCSP-STAPLING-ABSENT | low | Enable OCSP stapling on the listener. |
| tls.must_staple_unhonoured | tls_scanner | Certificate requires OCSP stapling and the server provides none | CCURE-CHK-TLS-MUST-STAPLE-UNHONOURED | high | Enable OCSP stapling, or reissue without the must-staple extension. Leaving it as it is means an outage for correct clients. |
| tls.fallback_scsv_unsupported | tls_scanner | Listener does not honour TLS_FALLBACK_SCSV | CCURE-CHK-TLS-FALLBACK-SCSV-UNSUPPORTED | medium | Upgrade the TLS library to one supporting RFC 7507, and remove the older protocol versions the downgrade would target. |
| tls.client_renegotiation_dos | tls_scanner | Client-initiated renegotiation is permitted | CCURE-CHK-TLS-CLIENT-RENEGOTIATION-DOS | medium | Disable client-initiated renegotiation. Most modern stacks refuse it by default; a server permitting it is usually running an older OpenSSL or an explicit override. |
| tls.weak_ecdh_curve | tls_scanner | Ephemeral ECDH group is below the modern floor | CCURE-CHK-TLS-WEAK-ECDH-CURVE | medium | Restrict the curve list to P-256, P-384, X25519 or better. |
| tls.no_forward_secrecy | tls_scanner | No forward-secret cipher suite is offered | CCURE-CHK-TLS-NO-FORWARD-SECRECY | medium | Offer ECDHE or DHE suites and prefer them. On TLS 1.3 this is automatic; on 1.2 it is a cipher-list change. |
| tls.ccs_injection | tls_scanner | OpenSSL ChangeCipherSpec injection (CVE-2014-0224) | CVE-2014-0224 | high | Upgrade OpenSSL to 1.0.1h or later. |
| tls.early_data_enabled | tls_scanner | TLS 1.3 0-RTT early data is accepted | CCURE-CHK-TLS-EARLY-DATA-ENABLED | low | Disable 0-RTT, or confirm that every endpoint reachable through early data is safe to replay. |
| tls.extended_master_secret_absent | tls_scanner | Extended master secret is not supported | CCURE-CHK-TLS-EXTENDED-MASTER-SECRET-ABSENT | low | Enable the extended master secret extension, or move to TLS 1.3. |
| tls.certificate_expiring_soon | tls_scanner | Server certificate expires within 30 days | CCURE-CHK-TLS-CERTIFICATE-EXPIRING-SOON | low | Renew the certificate and confirm automated renewal is running. |
| tls.weak_dh_parameters | tls_scanner | Ephemeral Diffie-Hellman group is too small (Logjam) | CCURE-CHK-TLS-WEAK-DH-PARAMETERS | medium | Generate a 2048-bit or larger DH parameter file, or drop DHE in favour of ECDHE. |
| tls.insecure_renegotiation | tls_scanner | Secure renegotiation (RFC 5746) is not supported | CCURE-CHK-TLS-INSECURE-RENEGOTIATION | medium | Upgrade the TLS library; every current one supports RFC 5746. |
| http.missing_security_headers | http_analyzer | HTTP security headers absent | CCURE-CHK-HTTP-MISSING-SECURITY-HEADERS | low | Set the missing headers at the server or reverse proxy. Note that an nginx `location` block containing any add_header replaces the parent's whole set, so headers declared at server level must be repeated inside it. |
| http.cleartext_service | http_analyzer | Service offered over cleartext HTTP | CCURE-CHK-HTTP-CLEARTEXT-SERVICE | medium | Terminate TLS in front of this service and redirect HTTP to HTTPS permanently. |
| http.insecure_cookie_flags | http_analyzer | Session cookie missing HttpOnly or Secure | CCURE-CHK-HTTP-INSECURE-COOKIE-FLAGS | medium | Set HttpOnly and Secure on every session cookie, and SameSite where the application allows. |
| http.sensitive_path_exposed | http_analyzer | Sensitive file exposed over HTTP | CCURE-CHK-HTTP-SENSITIVE-PATH-EXPOSED | high | Remove the file from the document root, or deny it at the web server. Rotate any credential the exposed content disclosed. |
| http.directory_listing | http_analyzer | Directory listing enabled | CCURE-CHK-HTTP-DIRECTORY-LISTING | medium | Disable automatic directory indexing (`autoindex off`, `Options -Indexes`). |
| http.dangerous_methods | http_analyzer | Dangerous HTTP methods accepted | CCURE-CHK-HTTP-DANGEROUS-METHODS | medium | Restrict the accepted method set to those the application needs, typically GET, HEAD and POST. |
| http.server_version_disclosure | http_analyzer | Server header discloses a product version | CCURE-CHK-HTTP-SERVER-VERSION-DISCLOSURE | low | Suppress the version in the Server header (`server_tokens off`, `ServerTokens Prod`). |
| http.default_credentials | default_creds | Default HTTP credentials accepted | CCURE-CHK-HTTP-DEFAULT-CREDENTIALS | critical | Change the account's password immediately and audit what the account has been used for. |
| http.shellshock | heartbleed_probe | Bash Shellshock via CGI | CVE-2014-6271 | critical | Patch Bash to a version that rejects the trailing-function parse, and disable unused CGI handlers. |
| ftp.anonymous_login | default_creds | Anonymous FTP login accepted | CCURE-CHK-FTP-ANONYMOUS-LOGIN | high | Disable anonymous access, or confine it to a directory holding only material intended to be public. |
| ftp.anonymous_write | ftp_checker | Anonymous FTP session has write access | CCURE-CHK-FTP-ANONYMOUS-WRITE | critical | Remove write permission from the anonymous FTP root immediately. |
| ftp.weak_credentials | ftp_checker | FTP accepts documented default credentials | CCURE-CHK-FTP-WEAK-CREDENTIALS | critical | Change the account's password immediately, or disable the account if it is unused. |
| ftp.cleartext_protocol | ftp_checker | FTP transmits credentials in cleartext | CCURE-CHK-FTP-CLEARTEXT-PROTOCOL | low | Replace FTP with SFTP or FTPS. |
| smb.v1_enabled | smb_probe | SMBv1 offered by the server | CCURE-CHK-SMB-V1-ENABLED | high | Disable the SMBv1 client and server components and confirm no remaining device requires them. |
| smb.signing_disabled | eternalblue_probe | SMB signing not required | CCURE-CHK-SMB-SIGNING-NOT-REQUIRED | medium | Require SMB signing on both server and client. |
| smb.eternalblue | eternalblue_probe | MS17-010 SMBv1 remote code execution (EternalBlue) | CVE-2017-0144 | critical | Apply MS17-010 and disable SMBv1. |
| snmp.default_community | snmp_probe | SNMP accepts a default or guessable community string | CCURE-CHK-SNMP-DEFAULT-COMMUNITY | high | Replace the community string with an unguessable value, restrict the agent to known managers by source address, and move to SNMPv3 with authentication and privacy. |
| snmp.v1_v2c_in_use | snmp_probe | SNMPv1/v2c in use — community sent in cleartext | CCURE-CHK-SNMP-V1-V2C-IN-USE | medium | Move to SNMPv3 with authPriv and disable v1 and v2c. |
| snmp.information_disclosure | snmp_probe | SNMP discloses system and network detail without authentication | CCURE-CHK-SNMP-INFORMATION-DISCLOSURE | medium | Restrict the agent to known managers, limit the exposed view to the OIDs monitoring needs, and move to SNMPv3. |
| ssh.weak_algorithms | ssh_probe | SSH offers weak key exchange, cipher or MAC algorithms | CCURE-CHK-SSH-WEAK-ALGORITHMS | medium | Restrict KexAlgorithms, Ciphers and MACs in sshd_config to the modern set, then restart sshd. |
| telnet.cleartext_exposed | default_creds | Telnet reachable — credentials in cleartext | CCURE-CHK-TELNET-EXPOSED | high | Disable Telnet and use SSH. |
| redis.no_authentication | default_creds | Redis accepts commands without authentication | CCURE-CHK-REDIS-NO-AUTHENTICATION | critical | Set requirepass, bind the instance to a loopback or private interface, and enable protected-mode. |
| mongodb.no_authentication | default_creds | MongoDB accepts unauthenticated access | CCURE-CHK-MONGODB-NO-AUTHENTICATION | critical | Enable authorization, create administrative users, and bind the instance to a private interface. |
| mqtt.no_authentication | default_creds | MQTT broker accepts anonymous connections | CCURE-CHK-MQTT-NO-AUTHENTICATION | high | Disable anonymous access, require credentials, and apply per-topic access control. |
| memcached.no_authentication | default_creds | Memcached reachable without authentication | CCURE-CHK-MEMCACHED-NO-AUTHENTICATION | high | Bind to a private interface, disable the UDP listener, and enable SASL authentication. |
| ldap.anonymous_bind | ldap_probe | Directory readable via anonymous bind | CCURE-CHK-LDAP-ANONYMOUS-BIND | medium | Disable anonymous bind, or restrict what an anonymous bind may read to the root DSE. |
| dns.zone_transfer | dns_probe | DNS zone transfer permitted to an arbitrary client | CCURE-CHK-DNS-ZONE-TRANSFER | high | Restrict zone transfers to the secondary nameservers by address, and require TSIG. |
| dns.open_recursion | dns_probe | DNS server performs recursion for arbitrary clients | CCURE-CHK-DNS-OPEN-RECURSION | medium | Restrict recursion to the client networks the resolver serves. |
| cve.version_inference | cve_engine | CVE candidates from fingerprinted service versions | dynamic | unscored |  |
| nuclei.template_verification | nuclei_probe | Conditions verified by an active Nuclei template | dynamic | unscored |  |

## Collector implementation inventory

Collectors are reusable acquisition methods, not independent vulnerability plugins. Their registration is by (check type, platform); 28 implementations serve 29 pairs.

| Collector | Check type | Platform | Implementation |
|---|---|---|---|
| WindowsRegistryCollector | registry | windows | Backend/core/config_audit/collectors/windows.py :: WindowsRegistryCollector.collect |
| WindowsFileCollector | file | windows | Backend/core/config_audit/collectors/windows.py :: WindowsFileCollector.collect |
| WindowsDirectoryCollector | directory | windows | Backend/core/config_audit/collectors/windows.py :: WindowsDirectoryCollector.collect |
| WindowsPermissionCollector | permission | windows | Backend/core/config_audit/collectors/windows.py :: WindowsPermissionCollector.collect |
| WindowsServiceCollector | service | windows | Backend/core/config_audit/collectors/windows.py :: WindowsServiceCollector.collect |
| WindowsProcessCollector | process | windows | Backend/core/config_audit/collectors/windows.py :: WindowsProcessCollector.collect |
| WindowsPackageCollector | package | windows | Backend/core/config_audit/collectors/windows.py :: WindowsPackageCollector.collect |
| WindowsPortCollector | port | windows | Backend/core/config_audit/collectors/windows.py :: WindowsPortCollector.collect |
| WindowsSecurityPolicyCollector | security_policy | windows | Backend/core/config_audit/collectors/windows.py :: WindowsSecurityPolicyCollector.collect |
| WindowsConfigFileCollector | config_file | windows | Backend/core/config_audit/collectors/windows.py :: WindowsConfigFileCollector.collect |
| WindowsCommandCollector | command | windows | Backend/core/config_audit/collectors/windows.py :: WindowsCommandCollector.collect |
| LinuxFileCollector | file | linux | Backend/core/config_audit/collectors/linux.py :: LinuxFileCollector.collect |
| LinuxDirectoryCollector | directory | linux | Backend/core/config_audit/collectors/linux.py :: LinuxDirectoryCollector.collect |
| LinuxPermissionCollector | permission | linux | Backend/core/config_audit/collectors/linux.py :: LinuxPermissionCollector.collect |
| LinuxServiceCollector | service | linux | Backend/core/config_audit/collectors/linux.py :: LinuxServiceCollector.collect |
| LinuxProcessCollector | process | linux | Backend/core/config_audit/collectors/linux.py :: LinuxProcessCollector.collect |
| LinuxPackageCollector | package | linux | Backend/core/config_audit/collectors/linux.py :: LinuxPackageCollector.collect |
| LinuxPortCollector | port | linux | Backend/core/config_audit/collectors/linux.py :: LinuxPortCollector.collect |
| LinuxSecurityPolicyCollector | security_policy | linux | Backend/core/config_audit/collectors/linux.py :: LinuxSecurityPolicyCollector.collect |
| LinuxConfigFileCollector | config_file | linux | Backend/core/config_audit/collectors/linux.py :: LinuxConfigFileCollector.collect |
| LinuxCommandCollector | command | linux | Backend/core/config_audit/collectors/linux.py :: LinuxCommandCollector.collect |
| WindowsPrivilegeCollector | privilege | windows | Backend/core/config_audit/collectors/privilege_windows.py :: WindowsPrivilegeCollector.collect |
| LinuxPrivilegeCollector | privilege | linux | Backend/core/config_audit/collectors/privilege_linux.py :: LinuxPrivilegeCollector.collect |
| DatabaseQueryCollector | database_query | database | Backend/core/config_audit/collectors/database.py :: DatabaseQueryCollector.collect |
| LinuxStructuredConfigCollector | structured_config | linux | Backend/core/config_audit/collectors/middleware.py :: LinuxStructuredConfigCollector.collect |
| WindowsStructuredConfigCollector | structured_config | windows | Backend/core/config_audit/collectors/middleware.py :: WindowsStructuredConfigCollector.collect |
| ContainerCollector | container | linux | Backend/core/config_audit/collectors/container.py :: ContainerCollector.collect |
| ScapRuleCollector | scap_rule | linux,windows | Backend/core/config_audit/collectors/scap.py :: ScapRuleCollector.collect |
