"""
cli.py
------
Interactive CLI for Ccure Audit.

Run::

    python cli.py

No extra dependencies - uses TCP scan mode without root.
With root + scapy: full ARP/ICMP/SYN capability.
"""

import asyncio
import json
import logging
import sys
from typing import Any, Dict

from api.host_discovery_api import HostDiscoveryAPI
from core.models import ScanIntensity

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)


def print_active_hosts(result: dict[str, Any]):
    """Display active hosts in a formatted table in terminal."""
    if not result.get("success"):
        print(f"\n❌ Scan failed: {result.get('error', 'Unknown error')}")
        return

    data = result.get("data", [])
    summary = result.get("summary", {})

    # Handle single host result (dict) vs multiple hosts (list)
    if isinstance(data, dict):
        hosts = [data]
    elif isinstance(data, list):
        hosts = data
    else:
        hosts = []

    # Filter active hosts
    active_hosts = [h for h in hosts if h.get("is_active")]

    print("\n" + "=" * 100)
    print("SCAN SUMMARY")
    print("=" * 100)
    print(f"Scan Type:      {summary.get('scan_type', 'N/A')}")
    print(f"Scan Duration:  {summary.get('scan_duration', 0):.2f} seconds")
    print(f"Total Hosts:    {summary.get('total_hosts', 0)}")
    print(f"Active Hosts:   {summary.get('active_hosts', 0)} ✓")
    print(f"Inactive Hosts: {summary.get('inactive_hosts', 0)}")
    print(f"Critical Hosts: {summary.get('critical_hosts', 0)} ⚠")
    print(f"High Risk:      {summary.get('high_risk_hosts', 0)} ⚠")
    print("=" * 100)

    if active_hosts:
        print("\n" + "=" * 100)
        print("ACTIVE HOSTS DETAILS")
        print("=" * 100)

        # Print table header
        print(
            f"{'IP Address':<18} {'Hostname':<30} {'MAC Address':<18} {'Risk Level':<12} {'Open Ports':<15}"
        )
        print("-" * 100)

        # Print each active host
        for host in active_hosts:
            ip = host.get("ip_address", "N/A")
            hostname = host.get("hostname", "Unknown")[:29]
            mac = host.get("mac_address", "N/A")
            risk = host.get("host_risk_level", "Unknown")
            ports = host.get("open_ports", [])
            port_str = f"{len(ports)} ports" if ports else "None"

            # Color risk levels with symbols
            risk_symbol = (
                "🔴"
                if risk == "Critical"
                else "🟠" if risk == "High" else "🟡" if risk == "Medium" else "🟢"
            )

            print(
                f"{ip:<18} {hostname:<30} {mac:<18} {risk_symbol} {risk:<10} {port_str:<15}"
            )

        # Show detailed port information for active hosts
        print("\n" + "=" * 100)
        print("DETAILED OPEN PORTS")
        print("=" * 100)
        for host in active_hosts:
            ip = host.get("ip_address", "N/A")
            ports = host.get("open_ports", [])
            if ports:
                print(f"\n🔗 {ip}")
                print(f"   {len(ports)} open port(s):")
                for port in ports:
                    port_num = port.get("port", "N/A")
                    service = port.get("service", "unknown")
                    banner = port.get("banner", "N/A")
                    print(f"   • {port_num:>5}/tcp  -  {service:<20} {banner}")
    else:
        print("\n⚠️  No active hosts found in scan results.")

    print("\n" + "=" * 100)

    # Show report paths if available
    reports = result.get("reports", {})
    if reports:
        print("\n📄 GENERATED REPORTS")
        print("=" * 100)
        if reports.get("json_pdf"):
            print(f"JSON Report: {reports['json_pdf']}")
        if reports.get("xml_pdf"):
            print(f"XML Report:  {reports['xml_pdf']}")
        print("=" * 100)


def main():
    scanner = HostDiscoveryAPI(silent=False)

    print("\n" + "=" * 72)
    print("  CCURE AUDIT PRO")
    print("=" * 72)
    print(json.dumps(scanner.get_system_info(), indent=2))

    print("\nChoose operation:")
    print("  1. Scan single host / hostname")
    print("  2. Scan IP range  (e.g. 10.180.1.1-50)")
    print("  3. Scan full subnet  (e.g. 10.180.1.0/24)")
    print("  4. Scan subnets of a subnet")

    choice = input("\nEnter choice (1-4): ").strip()
    scan_type = (
        input(
            "Scan type [ping/arp/tcp/full/adaptive/stealth] (default: adaptive): "
        ).strip()
        or "adaptive"
    )
    intensity = (
        input("Intensity [light/normal/deep] (default: normal): ").strip() or "normal"
    )

    if intensity in ("light", "normal", "deep"):
        scanner._orch.intensity = ScanIntensity(intensity)

    if choice == "1":
        target = input("Enter IP Address or hostname: ").strip()
        result = asyncio.run(scanner.scan_single_host(target, scan_type))
        print_active_hosts(result)

    elif choice == "2":
        target = input("Enter IP range (e.g. 10.180.1.1-50): ").strip()
        result = asyncio.run(scanner.scan_ip_range(target, scan_type))
        print_active_hosts(result)

    elif choice == "3":
        target = input("Enter subnet CIDR (e.g. 10.180.1.0/24): ").strip()
        result = asyncio.run(scanner.scan_subnet(target, scan_type))
        print_active_hosts(result)

    elif choice == "4":
        target = input("Enter parent network CIDR (e.g. 10.0.0.0/16): ").strip()
        prefix = int(input("Subnet prefix (e.g. 24): ").strip() or "24")
        result = asyncio.run(scanner.scan_subnets_of_subnet(target, prefix, scan_type))

        # For subnets of subnet, show summary first
        if result.get("success"):
            summary = result.get("summary", {})
            print("\n" + "=" * 100)
            print("SUBNETS SCAN SUMMARY")
            print("=" * 100)
            print(f"Scan Duration:  {summary.get('scan_duration', 0):.2f} seconds")
            print(f"Total Hosts:    {summary.get('total_hosts', 0)}")
            print(f"Active Hosts:   {summary.get('active_hosts', 0)} ✓")
            print(f"Critical Hosts: {summary.get('critical_hosts', 0)} ⚠")
            print("=" * 100)

            # Show per-subnet breakdown
            subnets_data = result.get("data", [])
            if subnets_data and isinstance(subnets_data, list):
                for subnet_info in subnets_data:
                    print(f"\n📍 Subnet: {subnet_info.get('subnet', 'N/A')}")
                    print(f"   Total Found:    {subnet_info.get('total_found', 0)}")
                    print(f"   Active:         {subnet_info.get('active_hosts', 0)} ✓")
                    print(f"   Inactive:       {subnet_info.get('inactive_hosts', 0)}")

                    # Show active hosts in this subnet
                    hosts = subnet_info.get("hosts", [])
                    active = [h for h in hosts if h.get("is_active")]
                    if active:
                        print(
                            f"   Active IPs: {', '.join([h.get('ip_address', 'N/A') for h in active])}"
                        )
        else:
            print_active_hosts(result)

    else:
        print("Invalid choice.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
