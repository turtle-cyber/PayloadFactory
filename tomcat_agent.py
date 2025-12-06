#!/usr/bin/env python3
"""
Tomcat-Specific Agent - Lightweight log monitor for Apache Tomcat fuzzing.
Focuses ONLY on Tomcat logs with minimal overhead.

Usage:
    sudo python3 tomcat_agent.py --server http://FUZZER_IP:8000 --catalina-path /opt/tomcat/logs/catalina.out
"""
import time
import requests
import socket
import argparse
import os
import glob
import re
from datetime import datetime

# Tomcat-specific error patterns (optimized for fuzzing feedback)
TOMCAT_CRITICAL_PATTERNS = {
    # RCE Indicators
    'RCE': [
        r'Runtime\.getRuntime\(\)\.exec',
        r'ProcessBuilder',
        r'uid=\d+',
        r'gid=\d+',
        r'/bin/(bash|sh)',
        r'command execution',
    ],
    # Memory Crashes
    'CRASH': [
        r'OutOfMemoryError',
        r'StackOverflowError',
        r'java\.lang\.Error',
        r'SEVERE.*exception',
        r'FATAL',
    ],
    # Path Traversal
    'PATH_TRAVERSAL': [
        r'\.\./\.\.',
        r'WEB-INF',
        r'directory traversal',
        r'Invalid path',
    ],
    # Authentication Bypass
    'AUTH_BYPASS': [
        r'authentication.*fail',
        r'authorization.*fail',
        r'access denied',
        r'permission denied',
        r'401.*Unauthorized',
        r'403.*Forbidden',
    ],
    # Deserialization
    'DESERIALIZATION': [
        r'ObjectInputStream',
        r'readObject',
        r'serialization',
        r'InvalidClassException',
    ],
    # DoS
    'DOS': [
        r'too many.*connection',
        r'timeout',
        r'resource.*unavailable',
        r'thread.*pool.*exhausted',
    ],
    # EL Injection
    'EL_INJECTION': [
        r'ELException',
        r'\$\{.*\}',
        r'expression.*evaluation',
    ],
}

class TomcatAgent:
    def __init__(self, server_url, catalina_path=None, access_log_path=None, verbose=False):
        self.server_url = server_url
        self.catalina_path = catalina_path
        self.access_log_path = access_log_path
        self.verbose = verbose
        self.hostname = socket.gethostname()
        self.ip = socket.gethostbyname(self.hostname)

        # File handles
        self.catalina_file = None
        self.access_file = None

        # Compiled regex patterns for performance
        self.patterns = {}
        for category, patterns in TOMCAT_CRITICAL_PATTERNS.items():
            self.patterns[category] = [re.compile(p, re.IGNORECASE) for p in patterns]

    def auto_discover_logs(self):
        """Automatically discover Tomcat log files."""
        search_patterns = [
            "/opt/tomcat*/logs/catalina.out",
            "/var/log/tomcat*/catalina.out",
            "/usr/share/tomcat*/logs/catalina.out",
            "/var/lib/tomcat*/logs/catalina.out",
        ]

        for pattern in search_patterns:
            matches = glob.glob(pattern)
            if matches:
                self.catalina_path = matches[0]
                print(f"[+] Auto-discovered catalina.out: {self.catalina_path}")

                # Try to find access log in same directory
                log_dir = os.path.dirname(self.catalina_path)
                access_logs = glob.glob(os.path.join(log_dir, "localhost_access_log*.txt"))
                if access_logs:
                    # Get most recent access log
                    access_logs.sort(key=os.path.getmtime, reverse=True)
                    self.access_log_path = access_logs[0]
                    print(f"[+] Auto-discovered access log: {self.access_log_path}")
                break

    def categorize_log(self, line):
        """Fast pattern matching to categorize log entries."""
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.search(line):
                    return category, pattern.pattern
        return None, None

    def send_log(self, log_file, content, category=None, matched_keyword=None, priority="high"):
        """Send log to fuzzer server."""
        payload = {
            "metadata": {
                "hostname": self.hostname,
                "ip": self.ip,
            },
            "type": "log",
            "log_file": log_file,
            "content": content,
            "priority": priority,
            "category": category or "GENERIC",
            "matched_keyword": matched_keyword,
            "timestamp": time.time()
        }

        try:
            requests.post(self.server_url, json=payload, timeout=2)
            if category:
                print(f"[!] {category}: {matched_keyword} -> {content[:80]}...")
        except Exception as e:
            if self.verbose:
                print(f"[!] Failed to send log: {e}")

    def monitor_catalina(self):
        """Monitor catalina.out for errors."""
        try:
            self.catalina_file = open(self.catalina_path, 'r', errors='ignore')
            self.catalina_file.seek(0, os.SEEK_END)  # Start at end
            print(f"[+] Monitoring: {self.catalina_path}")

            while True:
                line = self.catalina_file.readline()
                if line:
                    line = line.strip()
                    if not line:
                        continue

                    # Check for critical patterns
                    category, keyword = self.categorize_log(line)

                    if category:
                        # High-priority: Send immediately
                        self.send_log(self.catalina_path, line, category, keyword, "high")
                    elif self.verbose:
                        # Verbose mode: Send everything
                        self.send_log(self.catalina_path, line, None, None, "verbose")

                time.sleep(0.05)  # 50ms polling

        except PermissionError:
            print(f"[!] Permission denied: {self.catalina_path}")
            print("[*] Try running with sudo: sudo python3 tomcat_agent.py ...")
            return False
        except Exception as e:
            print(f"[!] Error monitoring catalina: {e}")
            return False

    def run(self):
        """Main monitoring loop."""
        print("="*60)
        print("Tomcat Fuzzing Agent")
        print("="*60)
        print(f"Server: {self.server_url}")
        print(f"Hostname: {self.hostname} ({self.ip})")
        print(f"Verbose: {self.verbose}")
        print("="*60)

        # Auto-discover if paths not provided
        if not self.catalina_path:
            print("[*] No catalina path specified, attempting auto-discovery...")
            self.auto_discover_logs()

        if not self.catalina_path:
            print("[!] Could not find Tomcat logs. Please specify --catalina-path")
            print("[*] Run tomcat_log_finder.py to locate your Tomcat logs")
            return

        # Verify file exists
        if not os.path.exists(self.catalina_path):
            print(f"[!] File not found: {self.catalina_path}")
            return

        print("\n[*] Starting monitoring... (Press Ctrl+C to stop)")

        try:
            self.monitor_catalina()
        except KeyboardInterrupt:
            print("\n[*] Agent stopped.")
        finally:
            if self.catalina_file:
                self.catalina_file.close()

def main():
    parser = argparse.ArgumentParser(
        description="Tomcat-specific log monitoring agent for fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover logs:
  sudo python3 tomcat_agent.py --server http://192.168.1.100:8000

  # Specify exact path:
  sudo python3 tomcat_agent.py --server http://192.168.1.100:8000 --catalina-path /opt/tomcat/logs/catalina.out

  # Verbose mode (send all logs):
  sudo python3 tomcat_agent.py --server http://192.168.1.100:8000 --verbose
        """
    )

    parser.add_argument(
        "--server",
        required=True,
        help="Fuzzer server URL (e.g., http://192.168.1.100:8000)"
    )

    parser.add_argument(
        "--catalina-path",
        help="Path to catalina.out (auto-discovered if not specified)"
    )

    parser.add_argument(
        "--access-log",
        help="Path to access log (optional)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Send ALL log lines (not just errors)"
    )

    args = parser.parse_args()

    # Ensure endpoint
    url = args.server
    if not url.endswith("/agent/logs"):
        url = url.rstrip("/") + "/agent/logs"

    agent = TomcatAgent(
        server_url=url,
        catalina_path=args.catalina_path,
        access_log_path=args.access_log,
        verbose=args.verbose
    )

    agent.run()

if __name__ == "__main__":
    main()
