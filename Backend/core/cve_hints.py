"""
core/cve_hints.py
-----------------
The fallback CVE hint table: candidate CVEs by service, used when the CVE
database cannot be reached (``core.cve_database``'s fallback search and the
network checks' ``engines.vulnerability.cve_lookup``).

Vulnerability intelligence, not a scan-domain constant: it moved here from
``core/constants.py`` so the CVE database no longer imports the scan kernel
(which also loads Scapy) for its fallback, and the scan kernel and
vulnerability intelligence stop depending on each other. For production, use
``Backend/scripts/vuln/download_nvd.py`` to populate cves.db.

Standard library only.
"""

CVE_HINTS: dict[str, list[dict]] = {
    # SSH
    "openssh_7": [
        {"cve": "CVE-2023-38408", "cvss": 9.8, "desc": "OpenSSH <9.3p2 ssh-agent RCE"}
    ],
    "openssh_8.0": [
        {
            "cve": "CVE-2023-51385",
            "cvss": 6.5,
            "desc": "OpenSSH OS command injection via user names",
        }
    ],
    "dropbear": [
        {
            "cve": "CVE-2020-36254",
            "cvss": 7.5,
            "desc": "Dropbear <2020.80 format string",
        }
    ],
    # HTTP Servers
    "apache/2.4.4": [
        {
            "cve": "CVE-2022-31813",
            "cvss": 9.8,
            "desc": "Apache mod_proxy forward smuggling",
        }
    ],
    "apache/2.4.5": [
        {
            "cve": "CVE-2023-25690",
            "cvss": 9.8,
            "desc": "Apache HTTP Server request smuggling",
        }
    ],
    "nginx/1.18": [
        {"cve": "CVE-2021-23017", "cvss": 7.7, "desc": "Nginx off-by-one heap write"}
    ],
    "nginx/1.14": [
        {
            "cve": "CVE-2019-20372",
            "cvss": 5.3,
            "desc": "Nginx read request body before 400",
        }
    ],
    "iis/7": [
        {"cve": "CVE-2017-7269", "cvss": 9.8, "desc": "IIS 6.0 WebDAV buffer overflow"}
    ],
    "iis/10": [
        {"cve": "CVE-2022-21907", "cvss": 9.8, "desc": "IIS HTTP Protocol Stack RCE"}
    ],
    # FTP
    "vsftpd 2.3.4": [
        {"cve": "CVE-2011-2523", "cvss": 10.0, "desc": "vsftpd 2.3.4 backdoor RCE"}
    ],
    "proftpd": [
        {"cve": "CVE-2020-9273", "cvss": 8.8, "desc": "ProFTPD use-after-free"}
    ],
    # SMB
    "smb": [
        {
            "cve": "CVE-2017-0144",
            "cvss": 9.3,
            "desc": "EternalBlue SMBv1 RCE (MS17-010)",
        },
        {"cve": "CVE-2020-0796", "cvss": 10.0, "desc": "SMBGhost SMBv3.1.1 LPE/RCE"},
    ],
    # RDP
    "rdp": [
        {"cve": "CVE-2019-0708", "cvss": 9.8, "desc": "BlueKeep RDP pre-auth RCE"},
        {"cve": "CVE-2020-0609", "cvss": 9.8, "desc": "RD Gateway pre-auth RCE"},
    ],
    # Telnet
    "telnet": [
        {
            "cve": "CVE-2020-10188",
            "cvss": 9.8,
            "desc": "Telnetd overflow / memory disclosure",
        }
    ],
    # Redis
    "redis": [
        {"cve": "CVE-2022-0543", "cvss": 10.0, "desc": "Redis Lua sandbox escape RCE"}
    ],
    # MongoDB
    "mongodb": [
        {
            "cve": "CVE-2021-20328",
            "cvss": 6.8,
            "desc": "MongoDB client-side field-level encryption bypass",
        }
    ],
    # Tomcat
    "apache tomcat": [
        {"cve": "CVE-2020-1938", "cvss": 9.8, "desc": "Ghostcat AJP file inclusion/RCE"}
    ],
    # PHP
    "php/7": [
        {"cve": "CVE-2021-21703", "cvss": 7.0, "desc": "PHP-FPM local priv escalation"}
    ],
    "php/8.0": [
        {
            "cve": "CVE-2022-31625",
            "cvss": 9.8,
            "desc": "PHP use-after-free in Postgres ext",
        }
    ],
    # OpenSSL
    "openssl/1.0": [
        {"cve": "CVE-2014-0160", "cvss": 7.5, "desc": "Heartbleed TLS heap read"}
    ],
    "openssl/1.1": [
        {
            "cve": "CVE-2022-0778",
            "cvss": 7.5,
            "desc": "OpenSSL infinite loop in BN_mod_sqrt",
        }
    ],
}
