"""Render the exported source inventory into reviewable tables."""

import csv
import json
from pathlib import Path

ROOT = Path(__file__).parent
data = json.loads((ROOT / "inventory.json").read_text())
# category, purpose, logic, requirements, evidence, limitations, confirmed defects
DETAILS = {
    "cve_engine": ("Vulnerability correlation", "Version/CPE CVE candidates", "Search each original port detail by application CPE, banner or service; split OS CPEs into host searches; record row caps", "Service/product identity; known versions for non-authoritative confirmation; populated vulnerability feeds", "Service port/protocol, CPE, version, candidate source and truncation", "No live feed/target validation this audit; original port_details only, rather than the full merged host", ""),
    "default_creds": ("Authentication/exposure", "Anonymous FTP, Telnet, Redis/MongoDB/MQTT/Memcached access and HTTP Basic defaults", "Protocol login or command reply; Telnet from supplied port; HTTP tests first plaintext web port only", "Recognized conventional service ports; no operator credential", "Login status, command response, accepted account and endpoint", "HTTP/HTTPS dispatch missing; HTTPS branch absent; malformed Mongo BSON and substring success test; SSH/MySQL/PostgreSQL trigger ports do not themselves implement auth checks", "D02,D08"),
    "dns_probe": ("DNS security", "Zone-transfer disclosure and recursion", "Root-zone TCP AXFR uses RCODE=0 alone; UDP google.com recursion uses RA plus ANCOUNT", "53; resolver/authoritative service; authorized source perspective", "RCODE or recursion flag; no actual zone record proof", "Zero-answer success is a false disclosure claim; no real authoritative-zone selection; newly discovered UDP may never reach it", "D03,D04,D06"),
    "eternalblue_probe": ("SMB/CVE active check", "SMBv1, signing and MS17-010 fingerprint", "SMBv1 negotiate security mode; malformed Trans2 status 0xC000000D treated as MS17-010 likely", "445; SMBv1 implementation for CVE fingerprint", "Dialect index, security mode, NT status", "No known vulnerable/patched SMB target validation here; fingerprint reliability is unverified, not established from the promotion tests", ""),
    "ftp_checker": ("FTP security", "Anonymous/weak login, optional anonymous write, cleartext protocol", "220 banner and 230 login; tries 8 weak pairs; opt-in MKD/RMD; cleartext notice", "21; FTP server; SCAN_ALLOW_INTRUSIVE/policy for write probe", "Banner, accepted accounts, write tri-state and cleanup response", "No real FTP target here; weak-login attempts are automatic; anonymous login also checked by default_creds", ""),
    "heartbleed_probe": ("Active CVE probes", "Heartbleed and Shellshock", "Raw TLS hello/heartbeat record length; marker in HTTP root response after Bash header payload", "Implicit TLS 443/8443/465/993/995 internally; HTTP 80/8080/8000/8888/443/8443 internally", "TLS record length or fixed Shellshock marker", "Selection omits several internally supported ports; stops at first non-None endpoint; marker reflection and TLS framing need independent validation", "D11"),
    "http_analyzer": ("HTTP security", "Headers, cookies, cleartext, exposed files/listings, methods, banner disclosure", "HEAD response then fixed-path GET fingerprints and method statuses; picks first HTTPS else first HTTP endpoint", "Internally 443/8443/80/8080/8000/8888; selector only plaintext HTTP ports", "Headers, path/body excerpt, status, methods, Server banner", "HTTPS-only hosts never select it; one endpoint only; actual loopback positive and hardened cases passed", "D01"),
    "icmp_probe": ("Host intelligence", "ICMP timestamp response metadata", "Scapy ICMP type 13; any answered pair marks response", "Scapy/raw-socket capability and answering target", "responds and coarse os_hint", "No findings emitted; no direct behavioral tests found; runtime unverified", ""),
    "ldap_probe": ("LDAP security", "Anonymous directory disclosure", "BER anonymous BindResponse resultCode=0 immediately emits disclosure; later root-DSE byte-count request is optional", "389/636 internally; plain socket even on 636", "Bind result; optional response byte count", "Claims content without a successful search; LDAPS lacks TLS; chooses one endpoint", "D07"),
    "nuclei_probe": ("Active template verification", "External Nuclei template matches", "Safe-tag/severity-filtered serial subprocess; JSONL parse and corroborating-result collapse; first CVE is primary", "Binary and template directory; at least one open port; inferred URL scheme", "Template ID, matched URL, request/extracted fields, CVE IDs", "Real synthetic template positive/negative passed; exit 1 without output marked run; timeout discards findings and provides no structured coverage; no full vendor-corpus validation", "D09,D14"),
    "smb_probe": ("SMB configuration", "SMB dialect metadata and SMBv1 enabled", "Handcrafted negotiate reply magic; status kept as null_session metadata", "445 else 139; handshake implementation", "SMB magic, dialect label and NT status", "Advertised NBSS payload length exceeds actual frame; not a real null-session or signing test; 139 session setup unverified", "D12"),
    "snmp_probe": ("SNMP/network intelligence", "Default community and v1 exposure plus interface/host metadata", "BER GET/GETNEXT with 15 guessed communities; bound OID walks; decoded sysDescr/platform", "UDP161; SNMPv1-accessible community; no SNMPv3 here", "Community, system OIDs, interfaces, IPs/masks, enterprise and bridge data", "No real SNMP agent here; separate topology client supports configured SNMP credentials; cannot infer write access from GET", ""),
    "ssh_probe": ("SSH configuration", "Weak KEX/cipher/MAC offerings", "Banner and first received KEXINIT packet; compare name-lists with weak sets", "22 TCP only internally; no credential", "Banner, offered algorithms and weak_algos", "MAC list index is the server-to-client cipher list; partial TCP reads and other ports unhandled", "D05"),
    "tls_scanner": ("TLS/certificates", "Protocol, cipher, certificate, key exchange and TLS features", "Fast socket handshake plus SSLyze; 26 declared areas; implicit TLS then 6 STARTTLS service groups sharing deep budget", "TLS or STARTTLS conventional ports; SSLyze dependency; TLS_DEEP_SCAN/TLS_STARTTLS_SCAN enabled; budget defaults 4", "Certificate identity/chain/time/key, protocols/ciphers and feature tri-states per endpoint", "Actual loopback SSLyze/socket execution passed; fixed ports/SNI by IP, budget skips and shared endpoint dedup limit coverage", "D10"),
    "udp_scanner": ("Service discovery", "9 conventional UDP responders", "Sequential DNS/DHCP/TFTP/Kerberos/NTP/SNMP/LDAP/IKE/mDNS datagrams; mostly coarse response/length tests", "Answering UDP service; always runs even with no listed open ports", "Port, service, advisory prose; no vulnerability finding", "Result lacks protocol; late discovery never reselects dependent checks; several replies are not transaction/source validated; advisory prose is not a tested vulnerability", "D03,D04"),
}

COLUMNS = ["Plugin ID/name", "Category", "Purpose", "Detection logic", "Target requirements", "Trigger conditions", "Execution entry point", "Required credentials", "Evidence collected", "Finding generation", "CVE/CPE mapping", "Execution status", "Test coverage", "Code reference"]
rows = []
for plugin in data["plugins"]:
    name = plugin["name"]
    category, purpose, logic, requirements, evidence, limitations, defects = DETAILS[name]
    areas = [c for c in data["network_checks"] if c["plugin"] == name]
    trigger = "Every active host" if plugin["always"] else ("Every active host, serial" if plugin["serial"] else "Any selected port number in " + str(plugin["trigger_ports"]))
    entry = "POST /scan/host-discovery or /scan/vulnerability-audit -> core.tasks.run_vulnerability_audit_task -> ScanOrchestrator.run_vulnerability_audit_only -> VulnerabilityEngine._run_plugins -> select_plugins -> " + name + ".run"
    finding = "Top-level cves -> deduplicate_cves -> verify_host_findings -> risk -> phase summary -> sync_vulnerability_audit -> findings endpoint and reports" if areas else "Metadata only; no normalized vulnerability finding"
    mapping = "; ".join(c["area"] + " -> " + (c["cve_id"] or ("dynamic CVE/template ID" if c["dynamic"] else "CCURE-CHK-" + c["check_id"])) for c in areas) or "None"
    status = "Partially working/unreliable: " + defects if defects else "Unverified on a real target; reachable and test-supported"
    if name in ("http_analyzer", "tls_scanner", "nuclei_probe"):
        status += "; live loopback scenario verified through engine normalization/scoring, persistence separately fixture-tested"
    row = [name, category, purpose, logic, requirements, trigger + "; " + limitations, entry, "None; automatic guessed defaults where stated", evidence, finding, mapping, status, "; ".join(plugin["test_references"]) or "No direct module-named tests in baseline", f"Backend/{plugin['path']}:{plugin['run_line']} run()"]
    rows.append(row)

for check in data["builtin_checks"]:
    platforms = ",".join(check["platforms"])
    logic = "Collect " + json.dumps(check["collect"], sort_keys=True) + "; compare " + json.dumps(check["expect"], sort_keys=True) + "; absent=" + check["absent"]
    entry = "POST /scan/credentialed -> run_credentialed_scan_task -> audit_database_target" if "database" in check["platforms"] else "POST /scan/credentialed or network phase 3.5 -> audit_credentialed_host -> _run_configuration_audit"
    row = [check["check_id"], check["domain"], check["title"] + "; " + check["description"], logic, "platform=" + platforms + "; os_match=" + json.dumps(check["os_match"]), "Authenticated session; builtin included by effective policy; platform/domain/severity/tag/id filters; applicability satisfied; collector resolves", entry + " -> builtin_checks/select_checks -> ConfigAuditEngine.run -> resolved collector.collect", "Database login" if "database" in check["platforms"] else "SSH for Linux; WinRM/SMB/SSH for Windows; transport must serve this check", "CollectedState with source/raw/observed/expected; exit status via ShellRunner; ConfigAudit result evidence", "FAIL only -> CCURE-CFG/CCURE-PRV definition -> cve_list -> standardized finding -> persistence/compliance sync/export; ERROR/MANUAL/N/A remain distinct", "No CVE/CPE inference; finding_type=" + check["finding_type"] + "; references=" + "; ".join(check["references"]), "Reachable; individual real target execution unverified", "Direct literal ID references: " + ("; ".join(check["test_references"]) or "none") + "; pack/collector/engine tests provide additional coverage; see test report", "; ".join(check["code_references"])]
    rows.append(row)

with (ROOT / "plugin-inventory.csv").open("w", newline="") as stream:
    writer = csv.writer(stream)
    writer.writerow(COLUMNS)
    writer.writerows(rows)

def cell(value):
    return str(value).replace("|", "\\|").replace("\n", "<br>")

text = ["# Individual plugin and check inventory", "", "Baseline: 14 October 2026, source revision `6d816e23dcbc61a4f96ff106af1f0bc3a1c44ce1`. 15 module implementations + 155 built-in rule definitions. These are two different granularities, not 170 Nessus-equivalent plugins. The CSV has all 14 requested columns. Every check's raw parameters, expectation, remediation and source references are also in inventory.json.", "", "The common execution and persistence paths are analyzed in REPORT.md. Entry paths below are static reachability; only the three stated loopback scenarios were independently exercised live. A passing fixture or import is not full target validation.", ""]
for row in rows[:15]:
    text += ["## " + row[0], "", "| Field | Evidence |", "|---|---|"]
    text += ["| " + cell(k) + " | " + cell(v) + " |" for k, v in zip(COLUMNS, row)]
    text += [""]
text += ["## Every built-in check", "", "Shared trigger: an authenticated host/database audit with the built-in pack allowed by policy. Shared result path: collector -> ConfigAuditEngine -> explicit outcome/evidence -> FAIL finding -> normalizer/persistence/report. None is individually marked target-verified.", "", "| Check ID | Purpose | Platform | Type/collection | Expected state; absence | Code reference |", "|---|---|---|---|---|---|"]
for c in data["builtin_checks"]:
    text.append("| " + " | ".join(cell(v) for v in [c["check_id"], c["title"], ",".join(c["platforms"]), c["check_type"] + ": " + json.dumps(c["collect"], sort_keys=True), json.dumps(c["expect"], sort_keys=True) + "; " + c["absent"], "; ".join(c["code_references"])]) + " |")
text += ["", "## Every network check area", "", "These 57 catalogue entries belong to 13 of the 15 modules; they are not 57 additional implementation modules. ICMP and UDP modules emit intelligence only. Dynamic areas denote CVE and Nuclei families, not all individual feed/template records.", "", "| Area | Plugin | Purpose | Identifier/CVE | Severity | Remediation |", "|---|---|---|---|---|---|"]
for c in data["network_checks"]:
    text.append("| " + " | ".join(cell(v) for v in [c["area"], c["plugin"], c["title"], c["cve_id"] or ("dynamic" if c["dynamic"] else "CCURE-CHK-" + c["check_id"]), c["severity"], c["remediation"]]) + " |")
text += ["", "## Collector implementation inventory", "", "Collectors are reusable acquisition methods, not independent vulnerability plugins. Their registration is by (check type, platform); 28 implementations serve 29 pairs.", "", "| Collector | Check type | Platform | Implementation |", "|---|---|---|---|"]
for c in data["collectors"]:
    text.append("| " + " | ".join(cell(v) for v in [c["name"], c["check_type"], ",".join(c["platforms"]), "Backend/" + c["module"].replace(".", "/") + ".py :: " + c["name"] + ".collect"]) + " |")
(ROOT / "INVENTORY.md").write_text("\n".join(text) + "\n")
print(json.dumps({"individual_inventory_rows": len(rows), "module_rows": 15, "rule_rows": len(data["builtin_checks"]), "network_area_rows": len(data["network_checks"])}))
