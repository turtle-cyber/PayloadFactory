"""
Network Scanner Module
Performs IP/Port scanning with service detection, version enumeration, and banner grabbing.
Integrates the Advanced Network Scanner for comprehensive service fingerprinting.
NOTE: STRICTLY REQUIRES NMAP BINARY.
"""

import socket
import sys
import re
import json
import logging
import ipaddress
import random
import csv
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple, Dict, Optional, List
from dataclasses import dataclass, asdict

# Try to import python-nmap
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[!] ERROR: python-nmap library not found. Please pip install python-nmap.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ServiceInfo:
    """Container for service information detected on a port"""
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: str = "unknown"
    product: str = "unknown"
    banner: str = ""
    cpe: List[str] = None  # Common Platform Enumeration
    extra_info: Dict = None

    def __post_init__(self):
        if self.cpe is None:
            self.cpe = []
        if self.extra_info is None:
            self.extra_info = {}

class NetworkScanner:
    """
    Advanced network scanner with stealth and evasion capabilities.
    Replaces legacy scanner with pure Nmap-based engine.
    """

    def __init__(self, use_nmap=True, verbose: bool = False, log_file: Optional[str] = None):
        """Initialize scanner"""
        self.verbose = verbose
        if not NMAP_AVAILABLE:
            self.nm = None
            logger.critical("Nmap python library not available.")
            return

        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.critical("Nmap binary not found in PATH! Please install Nmap.")
            self.nm = None
        except Exception as e:
            logger.critical(f"Failed to initialize nmap: {e}")
            self.nm = None

        self.setup_logging(log_file)

    def setup_logging(self, log_file: Optional[str]):
        """Configure logging system"""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        if not logging.getLogger().handlers:
            logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    # --- Advanced Scanner Helper Methods ---
    def validate_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_cidr(self, cidr: str) -> bool:
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    def sanitize_input(self, target: str) -> str:
        target = re.sub(r'[;&|`$(){}[\]<>]', '', target.strip())
        target = ' '.join(target.split())
        if not target:
            raise ValueError("Empty target after sanitization")
        return target

    def parse_target(self, target: str) -> Tuple[str, str]:
        try:
            target = self.sanitize_input(target)
        except ValueError as e:
            self.logger.error(f"Invalid target: {e}")
            raise

        original_target = target
        if target.startswith(('http://', 'https://', 'ftp://')):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path
            if ':' in target: target = target.split(':')[0]

        if ':' in target and not self.validate_cidr(target):
            target = target.split(':')[0]

        if '/' in target:
            if self.validate_cidr(target):
                return target, original_target
            else:
                raise ValueError(f"Invalid CIDR notation: {target}")

        if self.validate_ip(target):
            return target, target

        try:
            ip = socket.gethostbyname(target)
            return ip, target
        except socket.gaierror as e:
            self.logger.error(f"Failed to resolve {target}: {e}")
            raise ValueError(f"Cannot resolve hostname: {target}")

    def generate_decoys(self, count: int = 5) -> str:
        decoys = []
        for _ in range(count):
            decoys.append(f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}")
        return ','.join(decoys)

    def build_scan_arguments(self, scan_config: Dict) -> str:
        """Build nmap arguments based on scan configuration"""
        args = []

        scan_type = scan_config.get('type', 'default')
        stealth_mode = scan_config.get('stealth', False)

        if stealth_mode:
            stealth_technique = scan_config.get('stealth_technique', 'syn')
            if   stealth_technique == 'syn': args.append('-sS')
            elif stealth_technique == 'fin': args.append('-sF')
            elif stealth_technique == 'null': args.append('-sN')
            elif stealth_technique == 'xmas': args.append('-sX')
            elif stealth_technique == 'ack': args.append('-sA')

        if scan_config.get('version_detection', True):
            args.append('-sV')
            if scan_config.get('version_intensity'):
                args.append(f"--version-intensity {scan_config['version_intensity']}")

        if scan_config.get('os_detection', True):
            args.append('-O')
            if scan_config.get('aggressive_os'):
                args.append('--osscan-guess')

        timing = scan_config.get('timing', 4)
        args.append(f'-T{timing}')

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

        if scan_config.get('fragment'): args.append('-f')
        if scan_config.get('mtu'): args.append(f"--mtu {scan_config['mtu']}")
        
        if scan_config.get('decoy'):
            if scan_config.get('decoy') == 'random':
                decoys = self.generate_decoys()
                args.append(f'-D {decoys},ME')
            else:
                args.append(f"-D {scan_config['decoy']}")

        if scan_config.get('spoof_ip'): args.append(f"-S {scan_config['spoof_ip']}")
        if scan_config.get('spoof_mac'): args.append(f"--spoof-mac {scan_config['spoof_mac']}")
        if scan_config.get('randomize_hosts'): args.append('--randomize-hosts')
        if scan_config.get('bad_sum'): args.append('--badsum')
        if scan_config.get('data_length'): args.append(f"--data-length {scan_config['data_length']}")

        if scan_config.get('scripts'):
            args.append(f"--script={scan_config['scripts']}")
        elif scan_config.get('vuln_scan'):
            args.append('--script=vuln')

        if scan_config.get('aggressive'): args.append('-A')
        if scan_config.get('skip_ping'): args.append('-Pn')
        if scan_config.get('no_dns'): args.append('-n')
        if scan_config.get('min_rate'): args.append(f"--min-rate {scan_config['min_rate']}")
        if scan_config.get('max_retries'): args.append(f"--max-retries {scan_config['max_retries']}")

        return ' '.join(args)

    # --- Main Scan Method (Adapted for API Compatibility) ---
    def scan_target(self, ip: str, ports: Optional[List[int]] = None, deep_scan: bool = False) -> List[ServiceInfo]:
        """
        Scan a target IP address using STRICTLY Nmap.
        
        Args:
            ip: Target IP address
            ports: List of ports to scan
            deep_scan: Enable aggressive/deep scanning options
            
        Returns:
            List of ServiceInfo objects. Returns empty list if Nmap fails or is missing.
        """
        if not self.nm:
            logger.error("Scan aborted: Nmap not initialized. Make sure Nmap binary is in PATH.")
            # We return empty list to indicate no results, instead of fake fallback data
            return []

        try:
            # Prepare configuration - REQUIRES ADMIN for best results
            # NOTE: SYN scan (-sS) provides better version detection but needs admin privileges
            # Run Python/FastAPI server as Administrator for optimal scanning
            config = {
                'type': 'default',
                'stealth': True,  # Enable stealth SYN scan (requires admin)
                'stealth_technique': 'syn',  # -sS = half-open scan
                'version_detection': True,  # Always attempt version detection
                'version_intensity': 9,  # Maximum version probing intensity (0-9)
                'os_detection': False,  # Skip OS detection initially
                'timing': 4,  # T4 = aggressive timing
                'skip_ping': True,  # Assume host is up
                'no_dns': True,  # Skip DNS resolution for speed
                'scripts': 'default,banner',  # Run default scripts + banner grabbing
            }

            if deep_scan:
                config['type'] = 'aggressive'
                config['aggressive'] = True  # -A (includes version detection + scripts)
                config['os_detection'] = True  # Enable OS detection for deep scan
                config['scripts'] = 'default,vuln,banner'  # More scripts for deep scan
            
            if ports:
                # Handle large port lists by converting to range string efficiently
                port_str = ",".join(map(str, ports))
                config['port_range'] = port_str
            else:
                if deep_scan:
                    config['all_ports'] = True
                else:
                    config['type'] = 'quick'  # Quick scan if no ports specified

            # Resolve Target and Build Args
            clean_ip, hostname = self.parse_target(ip)
            arguments = self.build_scan_arguments(config)
            
            self.logger.info(f"Nmap Command: nmap {arguments} {clean_ip}")
            
            # Execute Nmap
            self.nm.scan(hosts=clean_ip, arguments=arguments)
            
            # Process Results
            services = []
            
            for host in self.nm.all_hosts():
                if host not in [clean_ip, hostname]:
                     # Sometimes nmap returns other hosts if subnet scanned, but we targeted specific IP
                     if clean_ip not in host: continue

                host_data = self.nm[host]
                
                # Report Host Status
                self.logger.info(f"Host {host} is {host_data.state()}")
                if 'osmatch' in host_data and host_data['osmatch']:
                    os_name = host_data['osmatch'][0]['name']
                    self.logger.info(f"OS Detected: {os_name}")

                for proto in ['tcp', 'udp']:
                    if proto not in host_data: continue
                    
                    for port, info in host_data[proto].items():
                        if info['state'] not in ['open', 'open|filtered']:
                            continue
                            
                        # Extract advanced details
                        service_name = info.get('name', 'unknown')
                        product = info.get('product', 'unknown')
                        version = info.get('version', 'unknown')
                        extrainfo = info.get('extrainfo', '')
                        script_out = info.get('script', {})
                        
                        # Build comprehensive banner
                        banner = f"{product} {version}".strip()
                        if extrainfo: banner += f" ({extrainfo})"
                        if script_out:
                             banner += f" | {str(script_out)}"
                        
                        svc = ServiceInfo(
                            port=int(port),
                            protocol=proto,
                            service=service_name,
                            version=version,
                            product=product,
                            banner=banner,
                            extra_info={
                                'extrainfo': extrainfo,
                                'conf': info.get('conf'),
                                'cpe': info.get('cpe', ''),
                                'scripts': script_out
                            }
                        )
                        services.append(svc)
            
            self.logger.info(f"Scan complete. Found {len(services)} services.")
            return services

        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            return []

    def format_results(self, services: List[ServiceInfo]) -> str:
        """Format scan results as human-readable text."""
        output = []
        output.append("=" * 60)
        output.append("NETWORK SCAN RESULTS (Strict Nmap)")
        output.append("=" * 60)

        if not services:
            if not self.nm:
                output.append("\n[!] CRITICAL: Nmap binary is missing or not found.")
                output.append("    Please install Nmap from https://nmap.org/download.html")
            else:
                output.append("\nNo open ports found or scan failed.")
        
        for svc in services:
            output.append(f"\nPort {svc.port}/{svc.protocol}")
            output.append(f"  Service: {svc.service}")
            output.append(f"  Product: {svc.product}")
            output.append(f"  Version: {svc.version}")
            if svc.banner:
                output.append(f"  Banner: {svc.banner[:200]}")

        output.append("\n" + "=" * 60)
        return "\n".join(output)

if __name__ == "__main__":
    scanner = NetworkScanner(verbose=True)
    # Demo strict nmap scan
    res = scanner.scan_target("127.0.0.1", ports=[80, 443])
    print(scanner.format_results(res))
