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


if __name__ == "__main__":
    test_classify_vmware_oui()
    test_classify_netbios_server_service()
    test_classify_netbios_master_browser()
    test_classify_netbios_workstation_only()
    test_classify_mdns_printer()
    test_classify_mdns_workstation_apple()
    test_classify_mdns_workstation_generic()
    test_priority_mdns_over_netbios()
    print("All device classifier tests passed successfully!")
