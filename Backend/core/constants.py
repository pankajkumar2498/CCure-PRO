"""
core/constants.py
-----------------
All shared lookup tables and numeric constants.
Nothing here imports from other project modules - safe to import anywhere.
"""

from typing import Dict, List

# -- Optional scapy (checked once here, re-used everywhere) -------------------
try:
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import (
        ARP,
        DNS,
        DNSQR,
        ICMP,
        IP,
        TCP,
        UDP,
        Ether,
        RandShort,
        conf,
        fragment,
        send,
        sr,
        srp,
    )

    conf.verb = 0
    SCAPY_AVAILABLE = True
except (ImportError, PermissionError):
    SCAPY_AVAILABLE = False

# -- Optional PDF --------------------------------------------------------------
try:
    from reporting.pdf_generator import ScanReportGenerator

    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# -- CVE Database (SQLite with automatic fallback) ----------------------------
try:
    from core.cve_database import get_cve_database

    CVE_DB = get_cve_database()
    CVE_DATABASE_AVAILABLE = CVE_DB.db_available
except ImportError:
    CVE_DB = None
    CVE_DATABASE_AVAILABLE = False

# =============================================================================
# CVE / Vulnerability Intelligence  (Fallback hardcoded hints)
# =============================================================================
# NOTE: These are used as fallback when SQLite database is unavailable.
# For production, use Backend/scripts/vuln/download_nvd.py to populate cves.db
# =============================================================================

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

# =============================================================================
# Port Risk Database  (Nessus-style criticality per port)
# =============================================================================

PORT_DB: dict[int, dict] = {
    # FTP / File Transfer
    20: {"service": "FTP-Data", "risk": "High", "note": "FTP data channel, cleartext"},
    21: {
        "service": "FTP",
        "risk": "High",
        "note": "Cleartext auth, anon access possible",
    },
    69: {
        "service": "TFTP",
        "risk": "High",
        "note": "No auth, firmware exfiltration risk",
    },
    115: {"service": "SFTP", "risk": "Medium", "note": "Simple FTP over SSH"},
    989: {"service": "FTPS-Data", "risk": "Low", "note": "FTP-SSL data channel"},
    990: {"service": "FTPS", "risk": "Low", "note": "FTP over TLS"},
    # Remote Access
    22: {
        "service": "SSH",
        "risk": "Medium",
        "note": "Encrypted; check key algos & version",
    },
    23: {
        "service": "Telnet",
        "risk": "Critical",
        "note": "Cleartext protocol, no encryption",
    },
    512: {
        "service": "rexec",
        "risk": "Critical",
        "note": "Remote execution no encryption",
    },
    513: {"service": "rlogin", "risk": "Critical", "note": "Trust-based remote login"},
    514: {
        "service": "rsh/syslog",
        "risk": "Critical",
        "note": "Plaintext remote shell",
    },
    992: {"service": "Telnet-TLS", "risk": "Medium", "note": "Telnet over TLS"},
    2222: {"service": "SSH-Alt", "risk": "Medium", "note": "Alternate SSH port"},
    3389: {"service": "RDP", "risk": "Critical", "note": "BlueKeep, NLA bypass risk"},
    5900: {
        "service": "VNC",
        "risk": "Critical",
        "note": "Screen sharing, weak auth common",
    },
    5901: {"service": "VNC-1", "risk": "Critical", "note": "VNC display :1"},
    5985: {
        "service": "WinRM-HTTP",
        "risk": "High",
        "note": "Windows Remote Management HTTP",
    },
    5986: {
        "service": "WinRM-HTTPS",
        "risk": "Medium",
        "note": "Windows Remote Management HTTPS",
    },
    # Email
    25: {"service": "SMTP", "risk": "Medium", "note": "Open relay / auth bypass risk"},
    110: {"service": "POP3", "risk": "High", "note": "Cleartext email retrieval"},
    143: {"service": "IMAP", "risk": "Medium", "note": "Cleartext email access"},
    465: {"service": "SMTPS", "risk": "Low", "note": "SMTP over TLS"},
    587: {
        "service": "SMTP-Submit",
        "risk": "Medium",
        "note": "Mail submission; check auth",
    },
    993: {"service": "IMAPS", "risk": "Low", "note": "IMAP over TLS"},
    995: {"service": "POP3S", "risk": "Low", "note": "POP3 over TLS"},
    # Web
    80: {
        "service": "HTTP",
        "risk": "Medium",
        "note": "Cleartext web; check security headers",
    },
    443: {
        "service": "HTTPS",
        "risk": "Low",
        "note": "Check TLS version, cert, ciphers",
    },
    591: {"service": "FileMaker-HTTP", "risk": "Medium", "note": "FileMaker HTTP alt"},
    631: {"service": "IPP", "risk": "Medium", "note": "Internet Printing Protocol"},
    2082: {
        "service": "cPanel",
        "risk": "High",
        "note": "cPanel web hosting control panel",
    },
    2083: {"service": "cPanel-TLS", "risk": "Medium", "note": "cPanel over TLS"},
    2086: {"service": "WHM", "risk": "High", "note": "WebHost Manager"},
    2087: {"service": "WHM-TLS", "risk": "Medium", "note": "WebHost Manager TLS"},
    4848: {"service": "GlassFish", "risk": "High", "note": "GlassFish admin console"},
    7001: {"service": "WebLogic", "risk": "High", "note": "Oracle WebLogic admin"},
    7002: {"service": "WebLogic-TLS", "risk": "Medium", "note": "Oracle WebLogic TLS"},
    8000: {"service": "HTTP-Dev", "risk": "Medium", "note": "Common dev server port"},
    8008: {"service": "HTTP-Alt2", "risk": "Medium", "note": "HTTP alternate"},
    8080: {
        "service": "HTTP-Alt",
        "risk": "Medium",
        "note": "Dev/proxy server; check headers",
    },
    8081: {"service": "HTTP-Alt3", "risk": "Medium", "note": "HTTP proxy / dev"},
    8443: {
        "service": "HTTPS-Alt",
        "risk": "Low",
        "note": "Alt HTTPS; check TLS config",
    },
    8888: {"service": "HTTP-Alt4", "risk": "Medium", "note": "Jupyter / dev server"},
    9443: {"service": "HTTPS-Alt2", "risk": "Low", "note": "Alt HTTPS"},
    10000: {"service": "Webmin", "risk": "High", "note": "Webmin admin interface"},
    # DNS
    53: {
        "service": "DNS",
        "risk": "Medium",
        "note": "Zone transfer / amplification risk",
    },
    853: {"service": "DNS-TLS", "risk": "Low", "note": "DNS over TLS"},
    # Network Services
    67: {
        "service": "DHCP-Server",
        "risk": "High",
        "note": "DHCP server; rogue server risk",
    },
    68: {"service": "DHCP-Client", "risk": "Medium", "note": "DHCP client port"},
    88: {
        "service": "Kerberos",
        "risk": "High",
        "note": "Kerberos auth; ticket attack surface",
    },
    111: {
        "service": "RPCBind",
        "risk": "High",
        "note": "Remote procedure call exposure",
    },
    123: {"service": "NTP", "risk": "Medium", "note": "NTP amplification / mode6 risk"},
    135: {"service": "MSRPC", "risk": "High", "note": "DCOM/RPC attack surface"},
    137: {"service": "NetBIOS-NS", "risk": "High", "note": "NetBIOS name service"},
    138: {"service": "NetBIOS-DGM", "risk": "High", "note": "NetBIOS datagram"},
    139: {
        "service": "NetBIOS",
        "risk": "High",
        "note": "Legacy SMB / NBT session service",
    },
    161: {
        "service": "SNMP",
        "risk": "High",
        "note": "Community string / MIB disclosure",
    },
    162: {"service": "SNMP-Trap", "risk": "Medium", "note": "SNMP trap receiver"},
    177: {
        "service": "XDMCP",
        "risk": "Critical",
        "note": "X Display Manager, unencrypted GUI",
    },
    179: {"service": "BGP", "risk": "High", "note": "Border Gateway Protocol"},
    389: {"service": "LDAP", "risk": "High", "note": "LDAP directory; null bind risk"},
    445: {
        "service": "SMB",
        "risk": "Critical",
        "note": "EternalBlue / SMBGhost attack surface",
    },
    500: {"service": "IKE", "risk": "Medium", "note": "IPsec IKE VPN"},
    520: {"service": "RIP", "risk": "High", "note": "Routing Information Protocol"},
    554: {
        "service": "RTSP",
        "risk": "High",
        "note": "Real-time streaming; camera exposure",
    },
    623: {
        "service": "IPMI",
        "risk": "Critical",
        "note": "IPMI/BMC; cipher-0 auth bypass risk",
    },
    636: {"service": "LDAPS", "risk": "Medium", "note": "LDAP over TLS"},
    749: {
        "service": "Kerberos-Admin",
        "risk": "High",
        "note": "Kerberos admin service",
    },
    873: {
        "service": "rsync",
        "risk": "High",
        "note": "rsync; unauthenticated module access",
    },
    902: {"service": "VMware-Auth", "risk": "High", "note": "VMware ESXi auth daemon"},
    903: {"service": "VMware-UI", "risk": "High", "note": "VMware Remote Console"},
    1080: {"service": "SOCKS", "risk": "High", "note": "SOCKS proxy; open proxy risk"},
    # Databases
    1433: {
        "service": "MSSQL",
        "risk": "High",
        "note": "Database exposure, sa brute risk",
    },
    1434: {"service": "MSSQL-UDP", "risk": "High", "note": "MSSQL Browser Service"},
    1521: {
        "service": "Oracle-DB",
        "risk": "High",
        "note": "TNS listener attack surface",
    },
    2483: {"service": "Oracle-TLS", "risk": "Medium", "note": "Oracle DB TLS"},
    2638: {"service": "Sybase", "risk": "High", "note": "Sybase SQL Anywhere"},
    3050: {"service": "Firebird", "risk": "High", "note": "Firebird database"},
    3306: {"service": "MySQL", "risk": "High", "note": "Database exposure"},
    5432: {
        "service": "PostgreSQL",
        "risk": "Medium",
        "note": "DB exposure; check auth",
    },
    5433: {
        "service": "PostgreSQL-Alt",
        "risk": "Medium",
        "note": "PostgreSQL alternate port",
    },
    6379: {
        "service": "Redis",
        "risk": "Critical",
        "note": "No auth default, RCE via config write",
    },
    6380: {"service": "Redis-TLS", "risk": "Medium", "note": "Redis over TLS"},
    7474: {"service": "Neo4j-HTTP", "risk": "High", "note": "Neo4j graph DB HTTP"},
    7687: {"service": "Neo4j-Bolt", "risk": "High", "note": "Neo4j Bolt protocol"},
    8086: {
        "service": "InfluxDB",
        "risk": "High",
        "note": "InfluxDB time-series; no auth default",
    },
    9042: {
        "service": "Cassandra",
        "risk": "High",
        "note": "Cassandra CQL; no auth default",
    },
    9160: {
        "service": "Cassandra-Thrift",
        "risk": "High",
        "note": "Cassandra Thrift API",
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "Critical",
        "note": "No auth default, data exposure",
    },
    9300: {
        "service": "Elasticsearch-Cluster",
        "risk": "Critical",
        "note": "Elasticsearch cluster transport",
    },
    27017: {
        "service": "MongoDB",
        "risk": "Critical",
        "note": "No auth default in older versions",
    },
    27018: {
        "service": "MongoDB-Shard",
        "risk": "Critical",
        "note": "MongoDB shard server",
    },
    27019: {
        "service": "MongoDB-Config",
        "risk": "Critical",
        "note": "MongoDB config server",
    },
    # Message Queues / Middleware
    1883: {
        "service": "MQTT",
        "risk": "High",
        "note": "MQTT broker; no auth common on IoT",
    },
    4369: {
        "service": "Erlang-EPMD",
        "risk": "High",
        "note": "Erlang port mapper; RabbitMQ exposure",
    },
    5044: {"service": "Logstash", "risk": "Medium", "note": "Logstash Beats input"},
    5601: {"service": "Kibana", "risk": "High", "note": "Kibana UI; check auth"},
    5672: {
        "service": "AMQP",
        "risk": "High",
        "note": "RabbitMQ AMQP; guest:guest default",
    },
    5673: {"service": "AMQP-TLS", "risk": "Medium", "note": "AMQP over TLS"},
    6443: {
        "service": "Kubernetes-API",
        "risk": "Critical",
        "note": "Kubernetes API server",
    },
    8161: {"service": "ActiveMQ-Web", "risk": "High", "note": "ActiveMQ web console"},
    9092: {"service": "Kafka", "risk": "High", "note": "Apache Kafka broker"},
    15672: {
        "service": "RabbitMQ-Mgmt",
        "risk": "High",
        "note": "RabbitMQ management UI",
    },
    61616: {
        "service": "ActiveMQ",
        "risk": "High",
        "note": "ActiveMQ broker; default creds",
    },
    # Out-of-band management. These sit above 1024 and outside Nmap's top-1000,
    # so a default scan missed them entirely — on a host whose AMT web UI was
    # wide open. AMT grants pre-boot control independent of the host OS, which
    # makes it exactly the exposure an asset inventory must not skip.
    16992: {
        "service": "Intel-AMT-HTTP",
        "risk": "Critical",
        "note": "Intel AMT web UI (cleartext); out-of-band host control",
    },
    16993: {
        "service": "Intel-AMT-HTTPS",
        "risk": "High",
        "note": "Intel AMT web UI (TLS); out-of-band host control",
    },
    16994: {
        "service": "Intel-AMT-Redir",
        "risk": "High",
        "note": "Intel AMT redirection (SOL/IDE-R), cleartext",
    },
    16995: {
        "service": "Intel-AMT-Redir-TLS",
        "risk": "Medium",
        "note": "Intel AMT redirection (SOL/IDE-R) over TLS",
    },
    664: {
        "service": "IPMI-Secure",
        "risk": "Medium",
        "note": "ASF/IPMI secure port; BMC management",
    },
    7070: {
        "service": "RealServer/AMT-SOAP",
        "risk": "Medium",
        "note": "RTSP/RealServer or AMT SOAP endpoint",
    },
    # Monitoring / DevOps / Containers
    2375: {
        "service": "Docker-HTTP",
        "risk": "Critical",
        "note": "Docker daemon unencrypted -- RCE",
    },
    2376: {"service": "Docker-TLS", "risk": "High", "note": "Docker daemon TLS"},
    2379: {
        "service": "etcd",
        "risk": "Critical",
        "note": "etcd K/V store; no auth default",
    },
    2380: {
        "service": "etcd-Peer",
        "risk": "Critical",
        "note": "etcd peer communication",
    },
    9090: {
        "service": "Prometheus",
        "risk": "Medium",
        "note": "Prometheus metrics / admin",
    },
    9100: {
        "service": "Prometheus-Node",
        "risk": "Medium",
        "note": "Prometheus node exporter / JetDirect",
    },
    10250: {
        "service": "Kubelet",
        "risk": "Critical",
        "note": "Kubernetes Kubelet API -- RCE",
    },
    10255: {
        "service": "Kubelet-RO",
        "risk": "High",
        "note": "Kubernetes Kubelet read-only",
    },
    # IoT / Industrial / SCADA
    102: {
        "service": "S7comm",
        "risk": "Critical",
        "note": "Siemens S7 PLC -- ICS/SCADA",
    },
    502: {
        "service": "Modbus",
        "risk": "Critical",
        "note": "Modbus TCP -- ICS/SCADA no auth",
    },
    4840: {
        "service": "OPC-UA",
        "risk": "High",
        "note": "OPC Unified Architecture -- ICS",
    },
    44818: {
        "service": "EtherNet-IP",
        "risk": "Critical",
        "note": "Rockwell/Allen-Bradley ICS",
    },
    47808: {"service": "BACnet", "risk": "High", "note": "Building automation BACnet"},
    20000: {
        "service": "DNP3",
        "risk": "Critical",
        "note": "DNP3 outstation -- ICS/SCADA",
    },
    2404: {
        "service": "IEC-104",
        "risk": "Critical",
        "note": "IEC 60870-5-104 -- ICS/SCADA",
    },
    18245: {"service": "GE-SRTP", "risk": "Critical", "note": "GE SRTP PLC protocol"},
    9600: {"service": "FINS", "risk": "Critical", "note": "Omron FINS PLC protocol"},
    5007: {
        "service": "MELSEC",
        "risk": "Critical",
        "note": "Mitsubishi MELSEC PLC protocol",
    },
    2455: {"service": "CoDeSys", "risk": "Critical", "note": "CoDeSys PLC runtime"},
    # Security / Backdoors
    4444: {
        "service": "Metasploit",
        "risk": "Critical",
        "note": "Known backdoor/C2 port",
    },
    1337: {
        "service": "Leet",
        "risk": "Critical",
        "note": "Known backdoor / hacker tool port",
    },
    31337: {"service": "Back-Orifice", "risk": "Critical", "note": "Back Orifice RAT"},
    # VPN / Tunneling
    1194: {"service": "OpenVPN", "risk": "Medium", "note": "OpenVPN; check config"},
    1701: {"service": "L2TP", "risk": "Medium", "note": "Layer 2 Tunneling Protocol"},
    1723: {"service": "PPTP", "risk": "High", "note": "PPTP VPN -- weak crypto (MPPE)"},
    4500: {"service": "IPsec-NAT", "risk": "Medium", "note": "IPsec NAT traversal"},
    # Printing
    515: {"service": "LPD", "risk": "High", "note": "Line Printer Daemon"},
    # Misc / Legacy / Dev
    79: {"service": "Finger", "risk": "High", "note": "User info disclosure"},
    119: {"service": "NNTP", "risk": "Medium", "note": "Usenet news transfer"},
    194: {"service": "IRC", "risk": "Medium", "note": "Internet Relay Chat"},
    548: {"service": "AFP", "risk": "High", "note": "Apple Filing Protocol"},
    2049: {"service": "NFS", "risk": "High", "note": "World-readable export possible"},
    2181: {
        "service": "Zookeeper",
        "risk": "Critical",
        "note": "ZooKeeper; no auth, RCE via config",
    },
    2375: {
        "service": "Docker-HTTP",
        "risk": "Critical",
        "note": "Docker daemon unencrypted -- RCE",
    },
    3000: {
        "service": "HTTP-Dev2",
        "risk": "Medium",
        "note": "Dev server (Rails/Node/Grafana)",
    },
    3001: {"service": "HTTP-Dev3", "risk": "Medium", "note": "Dev server alternate"},
    3128: {
        "service": "Squid-Proxy",
        "risk": "High",
        "note": "Squid proxy; open proxy risk",
    },
    3268: {"service": "LDAP-GC", "risk": "High", "note": "LDAP Global Catalog"},
    3269: {"service": "LDAPS-GC", "risk": "Medium", "note": "LDAP Global Catalog TLS"},
    5000: {
        "service": "HTTP-Dev4",
        "risk": "Medium",
        "note": "Dev server (Flask/Docker registry)",
    },
    5060: {
        "service": "SIP",
        "risk": "High",
        "note": "SIP VoIP; toll fraud / eavesdrop",
    },
    5061: {"service": "SIP-TLS", "risk": "Medium", "note": "SIP over TLS"},
    6000: {
        "service": "X11",
        "risk": "Critical",
        "note": "X Window System; keystroke capture",
    },
    8009: {
        "service": "AJP",
        "risk": "Critical",
        "note": "Tomcat AJP -- Ghostcat CVE-2020-1938",
    },
    8069: {"service": "Odoo", "risk": "High", "note": "Odoo ERP; check auth"},
    8089: {"service": "Splunk-Mgmt", "risk": "High", "note": "Splunk management port"},
    8500: {
        "service": "Consul",
        "risk": "Critical",
        "note": "Consul service mesh; no auth default",
    },
    9000: {
        "service": "PHP-FPM",
        "risk": "Critical",
        "note": "PHP-FPM; RCE if exposed directly",
    },
    9001: {"service": "Supervisor", "risk": "High", "note": "Supervisord XML-RPC"},
    11211: {
        "service": "Memcached",
        "risk": "Critical",
        "note": "Memcached; no auth, DRDoS amplifier",
    },
    50000: {"service": "SAP", "risk": "High", "note": "SAP Dispatcher"},
    50070: {
        "service": "Hadoop-HDFS",
        "risk": "Critical",
        "note": "Hadoop NameNode HTTP; no auth",
    },
}

# Top-68 quick scan - highest-value ports for fast triage
SCAN_PORTS_QUICK = sorted(
    [
        21,
        22,
        23,
        25,
        53,
        67,
        80,
        88,
        110,
        111,
        123,
        135,
        137,
        139,
        143,
        161,
        179,
        389,
        443,
        445,
        465,
        512,
        513,
        514,
        515,
        587,
        636,
        993,
        995,
        1080,
        1433,
        1521,
        1883,
        2049,
        2222,
        2375,
        2379,
        3000,
        3128,
        3268,
        3306,
        3389,
        4444,
        5432,
        5601,
        5672,
        5900,
        5985,
        5986,
        6379,
        6443,
        7001,
        8009,
        8080,
        8081,
        8086,
        8089,
        8161,
        8443,
        8500,
        9000,
        9042,
        9090,
        9092,
        9200,
        9300,
        10250,
        11211,
        15672,
        27017,
        50070,
    ]
)

# All named ports in PORT_DB - NORMAL scan
SCAN_PORTS_FULL = sorted(set(PORT_DB.keys()))

# All 65535 TCP ports - DEEP scan (set in port_engine per intensity)
SCAN_PORTS_DEEP = list(range(1, 65536))

SCAN_PORTS_WEB = [
    80,
    443,
    591,
    2082,
    2083,
    8000,
    8008,
    8080,
    8081,
    8443,
    8888,
    9443,
    10000,
]
SCAN_PORTS_DB = [
    1433,
    1434,
    1521,
    2638,
    3050,
    3306,
    5432,
    5433,
    6379,
    6380,
    7474,
    7687,
    8086,
    9042,
    9160,
    9200,
    9300,
    11211,
    27017,
    27018,
    27019,
]
SCAN_PORTS_OT = [102, 502, 2404, 2455, 4840, 5007, 9600, 18245, 20000, 44818, 47808]
SCAN_PORTS_IT = [
    21,
    22,
    23,
    25,
    53,
    67,
    80,
    88,
    110,
    111,
    123,
    135,
    137,
    139,
    143,
    161,
    389,
    443,
    445,
    465,
    587,
    623,
    636,
    902,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    5985,
    5986,
    6379,
    8080,
    8443,
    27017,
]

# UDP services probed by udp_scanner plugin
UDP_PROBE_PORTS = {
    53: "DNS",
    67: "DHCP",
    88: "Kerberos",
    123: "NTP",
    161: "SNMP",
    389: "LDAP",
    500: "IKE",
    5353: "mDNS",
    69: "TFTP",
}

# =============================================================================
# OS Fingerprinting Tables
# =============================================================================

OS_TTL_MAP = [
    (32, "Windows 9x / Embedded"),
    (64, "Linux / Android / macOS / FreeBSD"),
    (128, "Windows (NT/2000/XP/7/8/10/11)"),
    (200, "Solaris / AIX"),
    (255, "Cisco IOS / Network Appliance"),
]

TCP_WINDOW_OS = {
    # Windows
    65535: "Windows (classic stack)",
    64240: "Windows 10/11 (modern stack)",
    65392: "Windows 10/11",
    8192: "Windows XP",
    16384: "Windows Vista/7",
    32768: "Windows Vista/7",
    # Linux
    5840: "Linux 2.4 kernel",
    5720: "Linux 2.6 kernel",
    14600: "Linux 3.x kernel",
    29200: "Linux 4.x+",
    43690: "Linux 5.x / Android",
    65160: "Linux (RACK/BBR)",
    # BSD/macOS
    65228: "FreeBSD",
    65535: "macOS / FreeBSD",
    # Network appliances
    4096: "Cisco IOS",
    8760: "Cisco IOS (alt)",
}

# Priority 2-D: TCP option combo fingerprints.
# Checked bottom-up after TTL+window narrowing — first match wins.
# Columns: (mss_lo, mss_hi, wscale, sack_ok, refined_label, confidence)
#   wscale=None means "any value" (present or absent).
TCP_OPTIONS_FINGERPRINT = [
    # Windows — never sends Timestamps in SYN-ACK
    (1440, 1460, 8, True, "Windows 10/11", "High"),
    (1440, 1460, 8, False, "Windows Server 2016+", "High"),
    (1440, 1460, 2, False, "Windows 7 / Server 2012", "High"),
    (1, 9999, 0, False, "Windows XP / 2003", "High"),
    # Linux — always sends SAckOK; wscale >= 6 on modern kernels
    (1380, 1460, 8, True, "Linux 5.x (modern)", "High"),
    (1380, 1460, 7, True, "Linux 4.x / 5.x", "High"),
    (1380, 1460, 6, True, "Linux 4.x", "High"),
    (1380, 1460, 2, True, "Linux 2.6", "Medium"),
    # macOS / iOS — wscale=5, always SAckOK, TS present
    (1380, 1460, 5, True, "macOS / iOS", "High"),
    # FreeBSD
    (1380, 1460, 6, False, "FreeBSD", "Medium"),
    # Cisco / network appliances — small MSS, no wscale
    (1, 536, None, False, "Cisco IOS / Appliance", "Medium"),
    # Generic fallback
    (1, 9999, None, True, "Linux / Unix", "Low"),
]

# =============================================================================
# Risk Scoring Constants
# =============================================================================

RISK_WEIGHTS: dict[str, int] = {
    "Critical": 25,
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}

RISK_LEVELS = [
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (10, "Low"),
    (0, "Info"),
]

# =============================================================================
# Version Extraction Regex Patterns
# =============================================================================

import re

VER_PATTERNS = [
    re.compile(r"(OpenSSH[_/]\S+)", re.IGNORECASE),
    re.compile(r"(Apache/[\d.]+)", re.IGNORECASE),
    re.compile(r"(nginx/[\d.]+)", re.IGNORECASE),
    re.compile(r"(Microsoft-IIS/[\d.]+)", re.IGNORECASE),
    re.compile(r"(PHP/[\d.]+)", re.IGNORECASE),
    re.compile(r"(OpenSSL/[\d.]+[a-z]*)", re.IGNORECASE),
    re.compile(r"(vsftpd\s[\d.]+)", re.IGNORECASE),
    re.compile(r"(ProFTPD\s[\d.]+)", re.IGNORECASE),
    re.compile(r"(Dropbear\s[\d.]+)", re.IGNORECASE),
    re.compile(r"(Redis\s[\d.]+)", re.IGNORECASE),
    re.compile(r"(MongoDB\s[\d.]+)", re.IGNORECASE),
]
