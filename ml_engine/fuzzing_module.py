import subprocess
import random
import string
import logging
import time
import socket

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

    NASTY_STRINGS = [
        b"%n" * 10, # Format String
        b"A" * 1024, # Buffer Overflow
        b"' OR '1'='1", # SQL Injection
        b"$(reboot)", # Command Injection
        b"../../../../etc/passwd", # Path Traversal
        b"\x00", # Null Byte Injection
        b"\xff" * 10, # Integer Overflow potential
        b"{{7*7}}", # SSTI
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

    def send_payload(self, payload):
        """
        Sends payload to the target via TCP socket.
        Returns dict: {"crash": bool, "data": bytes, "time_ms": float}
        """
        result = {"crash": False, "data": None, "time_ms": 0.0}
        
        if not self.target_ip or not self.target_port:
            return result

        start_time = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0) # 2 second timeout
            s.connect((self.target_ip, self.target_port))
            s.send(payload)
            
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
            result["crash"] = True # CRASHED! Port closed
        except Exception as e:
            logger.debug(f"Socket error: {e}")
            result["crash"] = True # Treat other errors as potential crashes
            
        end_time = time.time()
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
                    logger.warning(f"POSSIBLE CRASH detected at iteration {i}!")
                    crashes.append({
                        "iteration": i,
                        "payload": mutated_payload.hex(),
                        "error": "Connection Refused / Socket Error",
                        "metrics": result
                    })
                    return crashes # Stop on first crash
                
                # 2. Check for Latency Spike (DoS / Heavy Processing)
                if result["time_ms"] > 1500: # > 1.5 seconds
                    logger.warning(f"Iteration {i}: High Latency ({result['time_ms']:.2f}ms) detected!")
                
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
                            if "root" in response_str or "uid=" in response_str or "2025" in response_str:
                                logger.critical(f"RCE CONFIRMED! Target returned suspicious data: {response_str[:100]}")
                                crashes.append({
                                    "iteration": i,
                                    "payload": mutated_payload.hex(),
                                    "error": "RCE Confirmed (Suspicious Response)",
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

if __name__ == "__main__":
    fuzzer = Fuzzer()
    base = b"User: admin Pass: password"
    print(fuzzer.run_fuzzing_session(base, iterations=50))
