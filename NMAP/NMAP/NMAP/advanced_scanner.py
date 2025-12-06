#!/usr/bin/env python3
"""
Advanced Network Scanner - Professional reconnaissance tool with stealth capabilities
Features: Stealth scanning, evasion, fragmentation, decoys, export, logging
Requires: python-nmap library and nmap installed on system
"""

import nmap
import socket
import sys
import re
import json
import csv
import logging
import argparse
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple, Dict, Optional, List
import ipaddress
import random


class AdvancedNetworkScanner:
    """Advanced network scanner with stealth and evasion capabilities"""

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        """Initialize scanner with logging configuration"""
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("[!] ERROR: Nmap not found. Please install nmap.")
            sys.exit(1)

        self.verbose = verbose
        self.scan_results = {}
        self.setup_logging(log_file)

    def setup_logging(self, log_file: Optional[str]):
        """Configure logging system"""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        log_format = '%(asctime)s - %(levelname)s - %(message)s'

        handlers = [logging.StreamHandler(sys.stdout)]
        if log_file:
            handlers.append(logging.FileHandler(log_file))

        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=handlers
        )
        self.logger = logging.getLogger(__name__)

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_cidr(self, cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    def sanitize_input(self, target: str) -> str:
        """Sanitize and validate input target"""
        # Remove dangerous characters
        target = re.sub(r'[;&|`$(){}[\]<>]', '', target.strip())

        # Remove excessive whitespace
        target = ' '.join(target.split())

        if not target:
            raise ValueError("Empty target after sanitization")

        return target

    def parse_target(self, target: str) -> Tuple[str, str]:
        """
        Parse and validate input to extract IP or domain
        Handles IP addresses, CIDR, URLs, and domains
        Returns: (ip/cidr, original_hostname)
        """
        try:
            target = self.sanitize_input(target)
        except ValueError as e:
            self.logger.error(f"Invalid target: {e}")
            raise

        original_target = target

        # Check if it's a URL
        if target.startswith(('http://', 'https://', 'ftp://')):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path
            self.logger.debug(f"Extracted hostname from URL: {target}")

        # Remove port if present
        if ':' in target and not self.validate_cidr(target):
            target = target.split(':')[0]

        # Check if it's CIDR notation
        if '/' in target:
            if self.validate_cidr(target):
                self.logger.info(f"[*] CIDR range detected: {target}")
                return target, original_target
            else:
                raise ValueError(f"Invalid CIDR notation: {target}")

        # Check if it's already a valid IP
        if self.validate_ip(target):
            self.logger.info(f"[*] Valid IP address: {target}")
            return target, target

        # Try to resolve domain to IP
        try:
            ip = socket.gethostbyname(target)
            self.logger.info(f"[*] Resolved {target} to {ip}")
            print(f"[*] Resolved {target} to {ip}")
            return ip, target
        except socket.gaierror as e:
            self.logger.error(f"Failed to resolve {target}: {e}")
            raise ValueError(f"Cannot resolve hostname: {target}")

    def generate_decoys(self, count: int = 5) -> str:
        """Generate random decoy IP addresses"""
        decoys = []
        for _ in range(count):
            decoy = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            decoys.append(decoy)
        return ','.join(decoys)

    def build_scan_arguments(self, scan_config: Dict) -> str:
        """Build nmap arguments based on scan configuration"""
        args = []

        # Scan type
        scan_type = scan_config.get('type', 'default')
        stealth_mode = scan_config.get('stealth', False)

        # Stealth scan techniques
        if stealth_mode:
            stealth_technique = scan_config.get('stealth_technique', 'syn')
            if stealth_technique == 'syn':
                args.append('-sS')  # SYN stealth scan
            elif stealth_technique == 'fin':
                args.append('-sF')  # FIN scan
            elif stealth_technique == 'null':
                args.append('-sN')  # NULL scan
            elif stealth_technique == 'xmas':
                args.append('-sX')  # Xmas scan
            elif stealth_technique == 'ack':
                args.append('-sA')  # ACK scan

        # Service version detection
        if scan_config.get('version_detection', True):
            args.append('-sV')
            if scan_config.get('version_intensity'):
                args.append(f"--version-intensity {scan_config['version_intensity']}")

        # OS detection
        if scan_config.get('os_detection', True):
            args.append('-O')
            if scan_config.get('aggressive_os'):
                args.append('--osscan-guess')

        # Timing template (0-5: paranoid, sneaky, polite, normal, aggressive, insane)
        timing = scan_config.get('timing', 4)
        args.append(f'-T{timing}')

        # Port specification
        if scan_config.get('all_ports'):
            args.append('-p-')
        elif scan_config.get('port_range'):
            args.append(f"-p {scan_config['port_range']}")
        elif scan_type == 'quick':
            args.append('--top-ports 100')
        elif scan_type == 'aggressive':
            args.append('-p-')
        else:
            args.append('--top-ports 1000')

        # Evasion techniques
        if scan_config.get('fragment'):
            args.append('-f')  # Fragment packets

        if scan_config.get('mtu'):
            args.append(f"--mtu {scan_config['mtu']}")  # Custom MTU

        if scan_config.get('decoy'):
            if scan_config.get('decoy') == 'random':
                decoys = self.generate_decoys()
                args.append(f'-D {decoys},ME')
            else:
                args.append(f"-D {scan_config['decoy']}")

        if scan_config.get('spoof_ip'):
            args.append(f"-S {scan_config['spoof_ip']}")

        if scan_config.get('spoof_mac'):
            args.append(f"--spoof-mac {scan_config['spoof_mac']}")

        if scan_config.get('randomize_hosts'):
            args.append('--randomize-hosts')

        # Firewall/IDS evasion
        if scan_config.get('bad_sum'):
            args.append('--badsum')

        if scan_config.get('data_length'):
            args.append(f"--data-length {scan_config['data_length']}")

        # Script scanning
        if scan_config.get('scripts'):
            args.append(f"--script={scan_config['scripts']}")
        elif scan_config.get('vuln_scan'):
            args.append('--script=vuln')

        # Aggressive scan
        if scan_config.get('aggressive'):
            args.append('-A')

        # Host discovery options
        if scan_config.get('skip_ping'):
            args.append('-Pn')

        if scan_config.get('no_dns'):
            args.append('-n')

        # Performance
        if scan_config.get('min_rate'):
            args.append(f"--min-rate {scan_config['min_rate']}")

        if scan_config.get('max_retries'):
            args.append(f"--max-retries {scan_config['max_retries']}")

        return ' '.join(args)

    def scan_target(self, target: str, scan_config: Dict) -> Dict:
        """
        Perform comprehensive scan on target with advanced options
        """
        try:
            ip, hostname = self.parse_target(target)
        except ValueError as e:
            self.logger.error(f"Target parsing failed: {e}")
            return {'error': str(e)}

        print(f"\n{'='*70}")
        print(f"Starting Advanced Scan: {hostname} ({ip})")
        print(f"{'='*70}\n")

        # Build scan arguments
        arguments = self.build_scan_arguments(scan_config)

        self.logger.info(f"Scan arguments: {arguments}")
        print(f"[*] Scan mode: {scan_config.get('type', 'default')}")
        if scan_config.get('stealth'):
            print(f"[*] Stealth technique: {scan_config.get('stealth_technique', 'syn').upper()}")
        print(f"[*] Arguments: {arguments}")
        print("[*] Scanning... This may take several minutes...\n")

        try:
            # Perform the scan with error handling
            self.nm.scan(hosts=ip, arguments=arguments)

            # Store results
            self.scan_results = {
                'scan_time': datetime.now().isoformat(),
                'target': target,
                'ip': ip,
                'hostname': hostname,
                'scan_config': scan_config,
                'nmap_command': self.nm.command_line(),
                'results': {}
            }

            # Process results
            for host in self.nm.all_hosts():
                self.scan_results['results'][host] = self.nm[host]

            # Display results
            self.display_results(ip)

            return self.scan_results

        except nmap.PortScannerError as e:
            error_msg = f"Nmap scan error: {e}"
            self.logger.error(error_msg)
            print(f"[!] {error_msg}")
            print("[!] Ensure nmap is installed and you have sufficient privileges")
            return {'error': error_msg}

        except Exception as e:
            error_msg = f"Unexpected error during scan: {e}"
            self.logger.error(error_msg)
            print(f"[!] {error_msg}")
            return {'error': error_msg}

    def display_results(self, ip: str):
        """Display formatted scan results with enhanced information"""

        if ip not in self.nm.all_hosts():
            print("[!] No results found for target")
            print("[!] Possible reasons: Host is down, firewall blocking, or no open ports")
            self.logger.warning(f"No results for {ip}")
            return

        host = self.nm[ip]

        # Host Status
        print(f"\n{'='*70}")
        print(f"HOST: {ip}")
        print(f"{'='*70}")
        print(f"State: {host.state()}")

        # Hostnames
        if 'hostnames' in host:
            hostnames = [h['name'] for h in host['hostnames'] if h.get('name')]
            if hostnames:
                print(f"Hostnames: {', '.join(hostnames)}")

        # MAC Address
        if 'addresses' in host:
            if 'mac' in host['addresses']:
                print(f"MAC Address: {host['addresses']['mac']}")
                if host.get('vendor'):
                    print(f"Vendor: {host['vendor'].get(host['addresses']['mac'], 'Unknown')}")

        # OS Detection
        if 'osmatch' in host and host['osmatch']:
            print(f"\n{'─'*70}")
            print("OS DETECTION:")
            print(f"{'─'*70}")
            for idx, osmatch in enumerate(host['osmatch'][:3], 1):  # Top 3 matches
                print(f"  {idx}. {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
                if 'osclass' in osmatch:
                    for osclass in osmatch['osclass']:
                        print(f"     Type: {osclass.get('type', 'N/A')} | "
                              f"Vendor: {osclass.get('vendor', 'N/A')} | "
                              f"Family: {osclass.get('osfamily', 'N/A')} | "
                              f"Gen: {osclass.get('osgen', 'N/A')}")
        else:
            print("\n[!] OS detection unsuccessful (try with sudo/admin privileges)")

        # Port and Service Information
        print(f"\n{'─'*70}")
        print("OPEN PORTS AND SERVICES:")
        print(f"{'─'*70}")
        print(f"{'PORT':<12} {'STATE':<10} {'SERVICE':<18} {'VERSION':<30}")
        print(f"{'-'*12} {'-'*10} {'-'*18} {'-'*30}")

        open_ports_count = 0

        for proto in host.all_protocols():
            ports = sorted(host[proto].keys())

            for port in ports:
                port_info = host[proto][port]
                state = port_info['state']

                if state in ['open', 'filtered', 'open|filtered']:
                    open_ports_count += 1
                    service = port_info.get('name', 'unknown')

                    # Build version string
                    version_parts = []
                    if port_info.get('product'):
                        version_parts.append(port_info['product'])
                    if port_info.get('version'):
                        version_parts.append(port_info['version'])
                    if port_info.get('extrainfo'):
                        version_parts.append(f"({port_info['extrainfo']})")

                    version = ' '.join(version_parts) if version_parts else 'N/A'

                    port_str = f"{port}/{proto}"
                    print(f"{port_str:<12} {state:<10} {service:<18} {version[:30]}")

                    # Display script results if available
                    if 'script' in port_info and self.verbose:
                        for script_name, script_output in port_info['script'].items():
                            print(f"    └─ Script: {script_name}")
                            for line in script_output.split('\n')[:3]:
                                print(f"       {line}")

        if open_ports_count == 0:
            print("    No open ports detected")
        else:
            print(f"\nTotal open/filtered ports: {open_ports_count}")

        # Additional Information
        if 'uptime' in host:
            print(f"\n{'─'*70}")
            print(f"Uptime: {host['uptime'].get('lastboot', 'N/A')}")

        # TCP/IP Fingerprinting
        if 'tcp_sequence' in host:
            print(f"\n{'─'*70}")
            print("TCP/IP FINGERPRINTING:")
            print(f"  Difficulty: {host['tcp_sequence'].get('difficulty', 'N/A')}")
            print(f"  Index: {host['tcp_sequence'].get('index', 'N/A')}")

        # Traceroute
        if 'trace' in host and self.verbose:
            print(f"\n{'─'*70}")
            print("TRACEROUTE:")
            for hop in host['trace'].get('hops', []):
                print(f"  {hop.get('ttl')} - {hop.get('ipaddr')} ({hop.get('host', 'N/A')}) - {hop.get('rtt')}ms")

        print(f"\n{'='*70}")
        print(f"SCAN COMPLETE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Command: {self.nm.command_line()}")
        print(f"{'='*70}\n")

    def export_json(self, filename: str):
        """Export scan results to JSON"""
        try:
            # Convert nmap objects to dict
            export_data = {
                'scan_info': {
                    'scan_time': self.scan_results.get('scan_time'),
                    'target': self.scan_results.get('target'),
                    'ip': self.scan_results.get('ip'),
                    'hostname': self.scan_results.get('hostname'),
                    'nmap_command': self.scan_results.get('nmap_command')
                },
                'results': {}
            }

            for host in self.nm.all_hosts():
                export_data['results'][host] = dict(self.nm[host])

            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

            print(f"[+] Results exported to JSON: {filename}")
            self.logger.info(f"Exported to JSON: {filename}")

        except Exception as e:
            self.logger.error(f"JSON export failed: {e}")
            print(f"[!] Failed to export JSON: {e}")

    def export_csv(self, filename: str):
        """Export scan results to CSV"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Hostname', 'Port', 'Protocol', 'State', 'Service', 'Version', 'Product', 'Extra Info'])

                for host in self.nm.all_hosts():
                    host_data = self.nm[host]
                    hostnames = [h['name'] for h in host_data.get('hostnames', []) if h.get('name')]
                    hostname = hostnames[0] if hostnames else ''

                    for proto in host_data.all_protocols():
                        for port in sorted(host_data[proto].keys()):
                            port_info = host_data[proto][port]
                            writer.writerow([
                                host,
                                hostname,
                                port,
                                proto,
                                port_info.get('state', ''),
                                port_info.get('name', ''),
                                port_info.get('version', ''),
                                port_info.get('product', ''),
                                port_info.get('extrainfo', '')
                            ])

            print(f"[+] Results exported to CSV: {filename}")
            self.logger.info(f"Exported to CSV: {filename}")

        except Exception as e:
            self.logger.error(f"CSV export failed: {e}")
            print(f"[!] Failed to export CSV: {e}")

    def export_html(self, filename: str):
        """Export scan results to HTML"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Results - {self.scan_results.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; margin: 20px; background: #0a0a0a; color: #00ff00; }}
        .header {{ background: #1a1a1a; padding: 20px; border: 2px solid #00ff00; margin-bottom: 20px; }}
        .section {{ background: #1a1a1a; padding: 15px; margin: 10px 0; border: 1px solid #00ff00; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #00ff00; padding: 8px; text-align: left; }}
        th {{ background: #004400; }}
        .command {{ background: #002200; padding: 10px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Scan Results</h1>
        <p><strong>Target:</strong> {self.scan_results.get('target', 'N/A')}</p>
        <p><strong>IP:</strong> {self.scan_results.get('ip', 'N/A')}</p>
        <p><strong>Scan Time:</strong> {self.scan_results.get('scan_time', 'N/A')}</p>
        <div class="command">
            <strong>Command:</strong> {self.scan_results.get('nmap_command', 'N/A')}
        </div>
    </div>
"""

            for host in self.nm.all_hosts():
                host_data = self.nm[host]
                html_content += f"""
    <div class="section">
        <h2>Host: {host}</h2>
        <p><strong>State:</strong> {host_data.state()}</p>
"""

                # OS Detection
                if 'osmatch' in host_data and host_data['osmatch']:
                    html_content += "<h3>OS Detection</h3><ul>"
                    for osmatch in host_data['osmatch'][:3]:
                        html_content += f"<li>{osmatch['name']} (Accuracy: {osmatch['accuracy']}%)</li>"
                    html_content += "</ul>"

                # Ports table
                html_content += """
        <h3>Open Ports</h3>
        <table>
            <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
"""

                for proto in host_data.all_protocols():
                    for port in sorted(host_data[proto].keys()):
                        port_info = host_data[proto][port]
                        if port_info['state'] in ['open', 'filtered']:
                            version = f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                            html_content += f"""
            <tr>
                <td>{port}/{proto}</td>
                <td>{port_info['state']}</td>
                <td>{port_info.get('name', 'unknown')}</td>
                <td>{version or 'N/A'}</td>
            </tr>
"""

                html_content += """
        </table>
    </div>
"""

            html_content += """
</body>
</html>
"""

            with open(filename, 'w') as f:
                f.write(html_content)

            print(f"[+] Results exported to HTML: {filename}")
            self.logger.info(f"Exported to HTML: {filename}")

        except Exception as e:
            self.logger.error(f"HTML export failed: {e}")
            print(f"[!] Failed to export HTML: {e}")


def print_banner():
    """Print program banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║        ADVANCED NETWORK RECONNAISSANCE SCANNER v2.0           ║
    ║     Stealth Scanning | Evasion | Advanced Fingerprinting     ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_stealth_modes():
    """Print available stealth modes"""
    print("\n[STEALTH TECHNIQUES]")
    print("  1. SYN Scan      - Half-open scan (default stealth)")
    print("  2. FIN Scan      - FIN flag only")
    print("  3. NULL Scan     - No flags set")
    print("  4. Xmas Scan     - FIN, PSH, URG flags")
    print("  5. ACK Scan      - Firewall detection")


def print_timing_templates():
    """Print timing templates"""
    print("\n[TIMING TEMPLATES]")
    print("  0. Paranoid  - Very slow, IDS evasion")
    print("  1. Sneaky    - Slow, IDS evasion")
    print("  2. Polite    - Slower, less bandwidth")
    print("  3. Normal    - Default timing")
    print("  4. Aggressive- Faster (recommended)")
    print("  5. Insane    - Very fast, may miss results")


def interactive_mode():
    """Interactive mode with advanced options"""
    print_banner()

    # Get target
    target = input("\n[*] Enter target (IP/Domain/URL/CIDR): ").strip()
    if not target:
        print("[!] No target specified. Exiting.")
        sys.exit(1)

    # Scan configuration
    scan_config = {}

    # Basic or Advanced mode
    print("\n[MODE SELECTION]")
    print("1. Quick Scan")
    print("2. Standard Scan")
    print("3. Aggressive Scan")
    print("4. Stealth Scan")
    print("5. Custom Advanced Scan")

    mode = input("\nSelect mode (1-5) [default: 2]: ").strip() or '2'

    if mode == '1':
        scan_config = {'type': 'quick', 'timing': 4}

    elif mode == '2':
        scan_config = {'type': 'default', 'timing': 4, 'version_detection': True, 'os_detection': True}

    elif mode == '3':
        scan_config = {'type': 'aggressive', 'aggressive': True, 'all_ports': True, 'timing': 4, 'vuln_scan': True}

    elif mode == '4':
        print_stealth_modes()
        stealth_choice = input("\nSelect stealth technique (1-5) [default: 1]: ").strip() or '1'
        techniques = {'1': 'syn', '2': 'fin', '3': 'null', '4': 'xmas', '5': 'ack'}

        print_timing_templates()
        timing = input("\nSelect timing (0-5) [default: 2]: ").strip() or '2'

        scan_config = {
            'type': 'stealth',
            'stealth': True,
            'stealth_technique': techniques.get(stealth_choice, 'syn'),
            'timing': int(timing),
            'version_detection': True,
            'randomize_hosts': True
        }

    elif mode == '5':
        # Advanced custom configuration
        print("\n[ADVANCED CONFIGURATION]")

        # Stealth
        if input("Enable stealth scanning? (y/n) [n]: ").lower() == 'y':
            print_stealth_modes()
            stealth_choice = input("Select technique (1-5) [1]: ").strip() or '1'
            techniques = {'1': 'syn', '2': 'fin', '3': 'null', '4': 'xmas', '5': 'ack'}
            scan_config['stealth'] = True
            scan_config['stealth_technique'] = techniques.get(stealth_choice, 'syn')

        # Timing
        print_timing_templates()
        timing = input("Select timing (0-5) [4]: ").strip() or '4'
        scan_config['timing'] = int(timing)

        # Evasion
        if input("\nEnable evasion techniques? (y/n) [n]: ").lower() == 'y':
            if input("  - Fragment packets? (y/n) [n]: ").lower() == 'y':
                scan_config['fragment'] = True

            if input("  - Use decoy scanning? (y/n) [n]: ").lower() == 'y':
                scan_config['decoy'] = 'random'

            if input("  - Randomize host order? (y/n) [n]: ").lower() == 'y':
                scan_config['randomize_hosts'] = True

            if input("  - Spoof MAC address? (y/n) [n]: ").lower() == 'y':
                scan_config['spoof_mac'] = '0'

        # Port range
        port_choice = input("\nPort selection:\n1. Top 100\n2. Top 1000\n3. All ports\n4. Custom range\nChoice [2]: ").strip() or '2'
        if port_choice == '1':
            pass  # Will use default
        elif port_choice == '3':
            scan_config['all_ports'] = True
        elif port_choice == '4':
            port_range = input("Enter port range (e.g., 1-1000 or 80,443,8080): ").strip()
            scan_config['port_range'] = port_range

        # Scripts
        if input("\nRun vulnerability scripts? (y/n) [n]: ").lower() == 'y':
            scan_config['vuln_scan'] = True

        scan_config['version_detection'] = True
        scan_config['os_detection'] = True

    else:
        scan_config = {'type': 'default', 'timing': 4}

    # Output options
    export_format = input("\nExport format (json/csv/html/none) [none]: ").strip().lower()

    # Verbose mode
    verbose = input("Enable verbose mode? (y/n) [n]: ").lower() == 'y'

    # Log file
    log_file = input("Log file path (leave empty to skip): ").strip() or None

    # Create scanner and run
    print("\n[*] Initializing advanced scanner...")
    scanner = AdvancedNetworkScanner(verbose=verbose, log_file=log_file)

    results = scanner.scan_target(target, scan_config)

    # Export if requested
    if export_format and export_format != 'none' and 'error' not in results:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if export_format == 'json':
            scanner.export_json(f"scan_{timestamp}.json")
        elif export_format == 'csv':
            scanner.export_csv(f"scan_{timestamp}.csv")
        elif export_format == 'html':
            scanner.export_html(f"scan_{timestamp}.html")


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Advanced Network Reconnaissance Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t scanme.nmap.org
  %(prog)s -t 192.168.1.0/24 --stealth syn -T2
  %(prog)s -t example.com --aggressive --export json
  %(prog)s -t 10.0.0.1 --stealth fin --decoy random --fragment
  %(prog)s  (interactive mode)
        """
    )

    parser.add_argument('-t', '--target', help='Target IP/Domain/URL/CIDR')
    parser.add_argument('--stealth', choices=['syn', 'fin', 'null', 'xmas', 'ack'], help='Stealth scan technique')
    parser.add_argument('-T', '--timing', type=int, choices=range(0, 6), default=4, help='Timing template (0-5)')
    parser.add_argument('--aggressive', action='store_true', help='Aggressive scan (-A)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (top 100 ports)')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 80,443)')
    parser.add_argument('--decoy', help='Use decoy scanning (use "random" for random IPs)')
    parser.add_argument('--fragment', action='store_true', help='Fragment packets')
    parser.add_argument('--spoof-mac', help='Spoof MAC address')
    parser.add_argument('--randomize', action='store_true', help='Randomize host scan order')
    parser.add_argument('--vuln', action='store_true', help='Run vulnerability detection scripts')
    parser.add_argument('--export', choices=['json', 'csv', 'html'], help='Export format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--log', help='Log file path')

    args = parser.parse_args()

    # If no target specified, run interactive mode
    if not args.target:
        interactive_mode()
        return

    # Build scan configuration from arguments
    scan_config = {
        'timing': args.timing,
        'version_detection': True,
        'os_detection': True
    }

    if args.stealth:
        scan_config['stealth'] = True
        scan_config['stealth_technique'] = args.stealth

    if args.aggressive:
        scan_config['aggressive'] = True
        scan_config['all_ports'] = True

    if args.quick:
        scan_config['type'] = 'quick'

    if args.all_ports:
        scan_config['all_ports'] = True

    if args.ports:
        scan_config['port_range'] = args.ports

    if args.decoy:
        scan_config['decoy'] = args.decoy

    if args.fragment:
        scan_config['fragment'] = True

    if args.spoof_mac:
        scan_config['spoof_mac'] = args.spoof_mac

    if args.randomize:
        scan_config['randomize_hosts'] = True

    if args.vuln:
        scan_config['vuln_scan'] = True

    # Create and run scanner
    print_banner()
    scanner = AdvancedNetworkScanner(verbose=args.verbose, log_file=args.log)
    results = scanner.scan_target(args.target, scan_config)

    # Export if requested
    if args.export and 'error' not in results:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if args.export == 'json':
            scanner.export_json(f"scan_{timestamp}.json")
        elif args.export == 'csv':
            scanner.export_csv(f"scan_{timestamp}.csv")
        elif args.export == 'html':
            scanner.export_html(f"scan_{timestamp}.html")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        logging.exception("Fatal error occurred")
        sys.exit(1)
