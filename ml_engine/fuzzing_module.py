import subprocess
import random
import string
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import socket

class Fuzzer:
    def __init__(self, target_ip=None, target_port=None):
        self.target_ip = target_ip
        self.target_port = target_port
        if self.target_ip:
            logger.info(f"Fuzzer initialized for target: {self.target_ip}:{self.target_port}")

    def mutate_payload(self, payload, mutation_rate=0.1):
        """
        Mutates the given payload (bytes).
        """
        if isinstance(payload, str):
            payload = payload.encode()
            
        chars = bytearray(payload)
        for i in range(len(chars)):
            if random.random() < mutation_rate:
                # Random byte
                chars[i] = random.randint(0, 255)
        return bytes(chars)

    def send_payload(self, payload):
        """
        Sends payload to the target via TCP socket.
        Returns (is_crash, response_data)
        """
        if not self.target_ip or not self.target_port:
            return False, None

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0) # 2 second timeout
            s.connect((self.target_ip, self.target_port))
            s.send(payload)
            
            # Check for response
            try:
                data = s.recv(4096) # Read response
                s.close()
                return False, data # Alive, returned data
            except socket.timeout:
                s.close()
                return False, None # Timeout but alive (maybe)
                
        except ConnectionRefusedError:
            return True, None # CRASHED! Port closed
        except Exception as e:
            logger.debug(f"Socket error: {e}")
            return True, None # Treat other errors as potential crashes
            
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
                is_crash, response = self.send_payload(mutated_payload)
                if is_crash:
                    logger.warning(f"POSSIBLE CRASH detected at iteration {i}!")
                    crashes.append({
                        "iteration": i,
                        "payload": mutated_payload.hex(),
                        "error": "Connection Refused / Socket Error"
                    })
                    return crashes # Stop on first crash
                
                elif response:
                    # Analyze HTTP Response Code
                    try:
                        response_str = response.decode('utf-8', errors='ignore')
                        status_line = response_str.split('\r\n')[0]
                        
                        if " 500 " in status_line:
                            logger.info(f"Iteration {i}: HTTP 500 (Rejection) - Payload processed but failed (Good sign).")
                        elif " 403 " in status_line:
                            logger.warning(f"Iteration {i}: HTTP 403 (Block) - WAF detected. Obfuscation needed.")
                        elif " 200 " in status_line:
                            # Check for RCE confirmation in body
                            if "root" in response_str or "uid=" in response_str or "2025" in response_str:
                                logger.critical(f"RCE CONFIRMED! Target returned suspicious data: {response_str[:100]}")
                                crashes.append({
                                    "iteration": i,
                                    "payload": mutated_payload.hex(),
                                    "error": "RCE Confirmed (Suspicious Response)"
                                })
                                return crashes
                    except Exception as e:
                        pass # Not a valid HTTP response, ignore parsing errors
            else:
                # Simulation Mode (Fallback)
                if b"AAAA" in mutated_payload and random.random() < 0.05:
                    logger.warning(f"Simulated Crash detected at iteration {i}!")
                    crashes.append({
                        "iteration": i,
                        "payload": mutated_payload.hex(),
                        "error": "Segmentation Fault (Simulated)"
                    })
                    
            time.sleep(0.1) # Prevent flooding
        
        return crashes

if __name__ == "__main__":
    fuzzer = Fuzzer()
    base = b"User: admin Pass: password"
    print(fuzzer.run_fuzzing_session(base, iterations=50))
