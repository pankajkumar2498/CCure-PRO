import pytest
from core.device_classifier import classify_device


def test_classify_vmware_oui():
    """Verify that a VMware OUI maps to virtual_machine category with ESXi OS fallback."""
    host = {
        "mac": "00:50:56:12:34:56",  # VMware prefix
        "mac_vendor": "VMware, Inc.",
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "virtual_machine"
    assert host["device_category_signal"] == "oui"
    assert host["os_family"] == "ESXi"
    assert host["os_confidence"] == "Medium"


def test_classify_netbios_server_service():
    """Verify NetBIOS <20> (Server) maps to server category with Medium confidence Windows OS fallback."""
    host = {
        "netbios_names": [
            {"name": "MYSERVER", "type": 0x20, "flags": 0}
        ],
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "server"
    assert host["device_category_signal"] == "netbios"
    assert host["os_family"] == "Windows"
    assert host["os_confidence"] == "Medium"


def test_classify_netbios_master_browser():
    """Verify NetBIOS <1D> (Master Browser) maps to server category with High confidence Windows OS fallback."""
    host = {
        "netbios_names": [
            {"name": "MYDOMAIN", "type": 0x1D, "flags": 0x8000}
        ],
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "server"
    assert host["device_category_signal"] == "netbios"
    assert host["os_family"] == "Windows"
    assert host["os_confidence"] == "High"


def test_classify_netbios_workstation_only():
    """Verify NetBIOS <00> (Workstation) without <20> maps to endpoint category."""
    host = {
        "netbios_names": [
            {"name": "MYLAPTOP", "type": 0x00, "flags": 0}
        ],
        "os_family": "",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "endpoint"
    assert host["device_category_signal"] == "netbios"
    assert host["os_family"] == "Windows"
    assert host["os_confidence"] == "Medium"


def test_classify_mdns_printer():
    """Verify mDNS _printer service maps to printer category with High confidence Embedded OS fallback."""
    host = {
        "mdns_services": ["_printer._tcp.local"],
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "printer"
    assert host["device_category_signal"] == "mdns"
    assert host["os_family"] == "Embedded"
    assert host["os_confidence"] == "High"


def test_classify_mdns_workstation_apple():
    """Verify mDNS _workstation service on Apple hardware maps to endpoint category and macOS OS."""
    host = {
        "mdns_services": ["_workstation._tcp.local"],
        "mac_vendor": "Apple, Inc.",
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "endpoint"
    assert host["device_category_signal"] == "mdns"
    assert host["os_family"] == "macOS"
    assert host["os_confidence"] == "Medium"


def test_classify_mdns_workstation_generic():
    """Verify mDNS _workstation service on non-Apple hardware maps to endpoint category and Linux OS."""
    host = {
        "mdns_services": ["_workstation._tcp.local"],
        "mac_vendor": "Intel Corporation",
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "endpoint"
    assert host["device_category_signal"] == "mdns"
    assert host["os_family"] == "Linux"
    assert host["os_confidence"] == "Medium"


def test_priority_mdns_over_netbios():
    """Verify that mDNS (Signal 2) takes precedence over NetBIOS (Signal 3)."""
    host = {
        "mdns_services": ["_printer._tcp.local"],
        "netbios_names": [
            {"name": "MYSERVER", "type": 0x20, "flags": 0}
        ],
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "printer"
    assert host["device_category_signal"] == "mdns"


def test_classify_nmap_cpe():
    """Verify that Nmap OS CPE maps to correct device category."""
    host = {
        "os_cpe": ["cpe:/o:fortinet:fortios:6.4"],
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "firewall"
    assert host["device_category_signal"] == "nmap_cpe"

    host2 = {
        "os_cpe": ["cpe:/o:cisco:ios:15.2"],
        "os_family": "Unknown",
        "open_ports": []
    }
    category2 = classify_device(host2)
    assert category2 == "router"
    assert host2["device_category_signal"] == "nmap_cpe"


def test_classify_snmp_info_lightweight():
    """Verify that SNMP info dict structures map to correct device category."""
    host = {
        "snmp_info": {
            "open": True,
            "ip_forwarding": 1,
            "if_count": 8,
            "bridge_mib": False
        },
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "router"
    assert host["device_category_signal"] == "snmp"

    host2 = {
        "snmp_info": {
            "open": True,
            "ip_forwarding": 2,
            "if_count": 8,
            "bridge_mib": True
        },
        "os_family": "Unknown",
        "open_ports": []
    }
    category2 = classify_device(host2)
    assert category2 == "switch"
    assert host2["device_category_signal"] == "snmp"


def test_priority_netbios_over_cpe_over_ports():
    """Verify signal priority order: NetBIOS > CPE > Port Profile."""
    # NetBIOS takes precedence over CPE
    host = {
        "netbios_names": [
            {"name": "MYSERVER", "type": 0x20, "flags": 0}
        ],
        "os_cpe": ["cpe:/o:cisco:ios:15.2"], # cpe maps to router, netbios to server
        "os_family": "Unknown",
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "server"
    assert host["device_category_signal"] == "netbios"

    # CPE takes precedence over Port Profile
    host2 = {
        "os_cpe": ["cpe:/o:fortinet:fortios:6.4"], # cpe maps to firewall
        "open_ports": [{"port": 179}] # BGP port maps to router
    }
    category2 = classify_device(host2)
    assert category2 == "firewall"
    assert host2["device_category_signal"] == "nmap_cpe"


def test_classify_scada_ics():
    """Verify that Modbus/S7comm ports, Siemens vendor name, and scada keywords map to scada_ics category."""
    # Test port profile
    host_port = {
        "open_ports": [{"port": 502}]
    }
    assert classify_device(host_port) == "scada_ics"
    assert host_port["device_category_signal"] == "port_profile"

    # Test vendor OUI classification
    host_vendor = {
        "mac_vendor": "Siemens AG",
        "os_family": "Unknown",
        "open_ports": []
    }
    assert classify_device(host_vendor) == "scada_ics"
    assert host_vendor["device_category_signal"] == "oui"

    # Test banner keyword
    host_banner = {
        "open_ports": [{"port": 80, "banner": "PLC s7-1200 Web Server"}]
    }
    assert classify_device(host_banner) == "scada_ics"
    assert host_banner["device_category_signal"] == "banner"


def test_docker_host_ip_forwarding_not_router():
    """Verify that a Linux workstation running Docker (IP forwarding = 1) is classified as endpoint, not router."""
    host = {
        "hostname": "atharv-desktop.blr.cdac.in",
        "vendor": "HP Inc.",
        "mac_vendor": "HP Inc.",
        "os_family": "Linux",
        "snmp_info": {
            "open": True,
            "ip_forwarding": 1,
            "sys_descr": "Linux ubuntu 5.15.0-generic #117-Ubuntu SMP x86_64",
        },
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "endpoint"
    assert host["device_category_signal"] == "snmp"


def test_weak_signals_remain_unknown():
    """Verify that signals yielding a score below 40 are categorized as unknown."""
    # Only TTL is present (yields 30 points)
    host = {
        "tcp_fingerprint": {"ttl": 64},
        "open_ports": []
    }
    category = classify_device(host)
    assert category == "unknown"
    assert host["device_category_signal"] == "none"


def test_credentialed_classification_override():
    """Verify that credentialed scan metadata takes immediate precedence and forces accurate categorization."""
    host = {
        "discovery_method": "credentialed",
        "os_family": "Windows Server",
        "os_name": "Windows Server 2022 Datacenter",
        "hostname": "win-server-ad",
        "open_ports": [{"port": 179}]  # Port 179 usually maps to router
    }
    category = classify_device(host)
    assert category == "server"
    assert host["device_category_signal"] == "credentialed"


if __name__ == "__main__":
    test_classify_vmware_oui()
    test_classify_netbios_server_service()
    test_classify_netbios_master_browser()
    test_classify_netbios_workstation_only()
    test_classify_mdns_printer()
    test_classify_mdns_workstation_apple()
    test_classify_mdns_workstation_generic()
    test_priority_mdns_over_netbios()
    test_classify_nmap_cpe()
    test_classify_snmp_info_lightweight()
    test_priority_netbios_over_cpe_over_ports()
    test_classify_scada_ics()
    test_docker_host_ip_forwarding_not_router()
    test_weak_signals_remain_unknown()
    test_credentialed_classification_override()
    print("All device classifier tests passed successfully!")
