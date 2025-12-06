#!/usr/bin/env python3
"""
Network Scanner - Scans IP/URL/Domain for services, versions, OS details
Requires: python-nmap library and nmap installed on system
"""

import nmap
import socket
import sys
import re
from urllib.parse import urlparse

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def parse_target(self, target):
        """
        Parse input to extract IP or domain
        Handles IP addresses, URLs, and domains
        """
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path

        # Remove port if present
        target = target.split(':')[0]

        # Try to resolve domain to IP
        try:
            ip = socket.gethostbyname(target)
            print(f"[*] Resolved {target} to {ip}")
            return ip, target
        except socket.gaierror:
            # If resolution fails, assume it's already an IP
            return target, target

    def scan_target(self, target, scan_type='default'):
        """
        Perform comprehensive scan on target
        scan_type: 'default', 'aggressive', 'quick'
        """
        ip, hostname = self.parse_target(target)

        print(f"\n{'='*60}")
        print(f"Starting scan on: {hostname} ({ip})")
        print(f"{'='*60}\n")

        # Different scan profiles
        if scan_type == 'aggressive':
            # -A: Aggressive scan (OS, version, script, traceroute)
            # -T4: Faster timing
            arguments = '-A -T4 -p-'
        elif scan_type == 'quick':
            # Quick scan of common ports
            arguments = '-sV -T4 --top-ports 100'
        else:
            # Default: Service version detection on common ports
            arguments = '-sV -O -T4 --top-ports 1000'

        try:
            print(f"[*] Scanning with arguments: {arguments}")
            print("[*] This may take a few minutes...\n")

            # Perform the scan
            self.nm.scan(ip, arguments=arguments)

            # Display results
            self.display_results(ip)

        except nmap.PortScannerError as e:
            print(f"[!] Nmap error: {e}")
            print("[!] Make sure nmap is installed on your system")
        except Exception as e:
            print(f"[!] Error during scan: {e}")

    def display_results(self, ip):
        """Display formatted scan results"""

        if ip not in self.nm.all_hosts():
            print("[!] No results found for target")
            return

        host = self.nm[ip]

        # Host Status
        print(f"\n{'='*60}")
        print(f"HOST: {ip}")
        print(f"{'='*60}")
        print(f"State: {host.state()}")

        # Hostnames
        if 'hostnames' in host:
            hostnames = [h['name'] for h in host['hostnames'] if h['name']]
            if hostnames:
                print(f"Hostnames: {', '.join(hostnames)}")

        # OS Detection
        if 'osmatch' in host:
            print(f"\n{'─'*60}")
            print("OS DETECTION:")
            print(f"{'─'*60}")
            for osmatch in host['osmatch']:
                print(f"  • {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
                if 'osclass' in osmatch:
                    for osclass in osmatch['osclass']:
                        print(f"    - Type: {osclass.get('type', 'N/A')}")
                        print(f"    - Vendor: {osclass.get('vendor', 'N/A')}")
                        print(f"    - OS Family: {osclass.get('osfamily', 'N/A')}")
                        print(f"    - OS Gen: {osclass.get('osgen', 'N/A')}")

        # Port and Service Information
        print(f"\n{'─'*60}")
        print("OPEN PORTS AND SERVICES:")
        print(f"{'─'*60}")
        print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'VERSION':<30}")
        print(f"{'-'*10} {'-'*10} {'-'*20} {'-'*30}")

        for proto in host.all_protocols():
            ports = sorted(host[proto].keys())

            for port in ports:
                port_info = host[proto][port]
                state = port_info['state']

                if state == 'open':
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('product', '')
                    if port_info.get('version'):
                        version += f" {port_info['version']}"
                    if port_info.get('extrainfo'):
                        version += f" ({port_info['extrainfo']})"

                    port_str = f"{port}/{proto}"
                    print(f"{port_str:<10} {state:<10} {service:<20} {version:<30}")

        # Additional Information
        if 'uptime' in host:
            print(f"\n{'─'*60}")
            print(f"Uptime: {host['uptime'].get('lastboot', 'N/A')}")

        # TCP Sequence
        if 'tcp_sequence' in host:
            print(f"\n{'─'*60}")
            print("TCP SEQUENCE:")
            print(f"  Difficulty: {host['tcp_sequence'].get('difficulty', 'N/A')}")

        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}\n")


def print_banner():
    """Print program banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║           NETWORK RECONNAISSANCE SCANNER              ║
    ║          Scan IP/URL/Domain for Services & OS         ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    print_banner()

    # Get target from user
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scan_type = sys.argv[2] if len(sys.argv) > 2 else 'default'
    else:
        target = input("Enter IP address, URL, or domain to scan: ").strip()
        print("\nSelect scan type:")
        print("1. Default (Recommended - 1000 common ports)")
        print("2. Quick (100 most common ports)")
        print("3. Aggressive (All ports + scripts - SLOW)")
        choice = input("Enter choice (1-3) [default: 1]: ").strip() or '1'

        scan_types = {'1': 'default', '2': 'quick', '3': 'aggressive'}
        scan_type = scan_types.get(choice, 'default')

    if not target:
        print("[!] No target specified. Exiting.")
        sys.exit(1)

    # Create scanner and run
    scanner = NetworkScanner()
    scanner.scan_target(target, scan_type)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
