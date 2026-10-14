"""Keep transport/service evidence while preserving legacy list[int] calls."""

SERVICE_ALIASES = {
    "http": {"http", "http-alt", "http-proxy"},
    "https": {"https", "https-alt", "ssl/http", "http/ssl"},
    "ssh": {"ssh", "openssh"},
    "dns": {"dns", "domain"},
    "ldap": {"ldap"},
    "ldaps": {"ldaps", "ssl/ldap"},
    "smb": {"smb", "microsoft-ds", "netbios-ssn"},
    "ftp": {"ftp"},
    "telnet": {"telnet"},
    "redis": {"redis"},
    "mongodb": {"mongodb", "mongo"},
    "mqtt": {"mqtt"},
    "memcached": {"memcached"},
    "postgres": {"postgres", "postgresql"},
    "smtps": {"smtps", "ssl/smtp"},
    "imaps": {"imaps", "ssl/imap"},
    "pop3s": {"pop3s", "ssl/pop3"},
    "ftps": {"ftps", "ssl/ftp"},
    "mqtts": {"mqtts", "ssl/mqtt"},
}


def service_identity(endpoint):
    service = (
        str(endpoint.get("service") or endpoint.get("service_name") or "")
        .strip()
        .lower()
    )
    if service in {"", "unknown", "unknown service", "unidentified", "tcpwrapped"}:
        return ""
    for identity, aliases in SERVICE_ALIASES.items():
        if service in aliases:
            return identity
    return service


class ProbePorts(list):
    def __init__(self, host):
        self.endpoints = []
        seen = set()
        for key, default_protocol in (("open_ports", "tcp"), ("udp_services", "udp")):
            for raw in host.get(key) or []:
                if not isinstance(raw, dict):
                    continue
                port = raw.get("port")
                protocol = str(raw.get("protocol") or default_protocol).lower()
                if (
                    isinstance(port, bool)
                    or not isinstance(port, int)
                    or not 1 <= port <= 65535
                ):
                    continue
                if protocol not in {"tcp", "udp"} or raw.get("state", "open") != "open":
                    continue
                endpoint = {**raw, "port": port, "protocol": protocol}
                identity = (port, protocol)
                if identity in seen:
                    continue
                seen.add(identity)
                self.endpoints.append(endpoint)
        super().__init__(e["port"] for e in self.endpoints if e["protocol"] == "tcp")


def endpoints_for(ports, identities, defaults, protocols=("tcp",)):
    endpoints = getattr(ports, "endpoints", None)
    if endpoints is None:
        endpoints = [{"port": p, "protocol": "tcp"} for p in ports]
    return [
        e
        for e in endpoints
        if e["protocol"] in protocols
        and (
            service_identity(e) in identities
            or (not service_identity(e) and e["port"] in defaults)
        )
    ]


def uses_tls(endpoint, tls_ports):
    identity = service_identity(endpoint)
    return (
        identity in {"https", "ldaps"}
        or str(endpoint.get("tunnel") or "").lower() in {"ssl", "tls"}
        or (not identity and endpoint["port"] in tls_ports)
    )


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("truncated protocol frame")
        data.extend(chunk)
    return bytes(data)
