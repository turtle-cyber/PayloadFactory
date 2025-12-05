"""
FeedbackContext - Shared data structure for Fuzzer → RL Agent communication.

This dataclass carries context from the fuzzing phase to the RL Agent,
enabling feedback-driven payload optimization.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class FeedbackContext:
    """Context passed from Fuzzer to RL Agent for informed optimization."""
    
    # Fuzzer findings (crashes, DoS, RCE confirmations)
    crashes: List[Dict[str, Any]] = field(default_factory=list)
    
    # Spider-discovered endpoints
    spider_paths: List[str] = field(default_factory=list)
    
    # Vulnerability type: "web" | "binary" | "unknown"
    vuln_type: str = "unknown"
    
    # Best payload so far (from previous iterations)
    best_payload: bytes = b""
    
    # HTTP response codes seen during fuzzing
    response_codes: List[int] = field(default_factory=list)
    
    # High-latency responses (DoS indicators), in milliseconds
    latency_spikes: List[float] = field(default_factory=list)
    
    # Original exploit code (for context-aware mutations)
    exploit_code: Optional[str] = None
    
    def has_dos_indicators(self) -> bool:
        """Check if feedback suggests DoS potential."""
        return len(self.latency_spikes) > 0 or any(
            "DoS" in c.get("error", "") or "Latency" in c.get("error", "")
            for c in self.crashes
        )
    
    def has_rce_indicators(self) -> bool:
        """Check if feedback suggests RCE success."""
        return any(
            "RCE" in c.get("error", "") or "uid=" in str(c.get("error", ""))
            for c in self.crashes
        )
    
    def has_crash_indicators(self) -> bool:
        """Check if feedback suggests memory corruption crash."""
        return any(
            "Crash" in c.get("error", "") or "Refused" in c.get("error", "")
            for c in self.crashes
        )
    
    def get_successful_payloads(self) -> List[bytes]:
        """Extract payloads that triggered findings."""
        payloads = []
        for crash in self.crashes:
            payload_hex = crash.get("payload", "")
            if payload_hex:
                try:
                    payloads.append(bytes.fromhex(payload_hex))
                except ValueError:
                    pass
        return payloads
    
    @classmethod
    def from_boofuzz_crashes(cls, boofuzz_crashes: List[Dict], spider_paths: List[str] = None) -> "FeedbackContext":
        """
        Create FeedbackContext from Boofuzz crash log.
        
        Args:
            boofuzz_crashes: List of crash dictionaries from BoofuzzEngine
            spider_paths: Spider-discovered endpoints
            
        Returns:
            FeedbackContext instance for RL Agent
        """
        crashes = []
        latency_spikes = []
        response_codes = []
        
        for crash in boofuzz_crashes:
            crashes.append({
                "iteration": crash.get("test_case", crash.get("index", 0)),
                "payload": crash.get("payload", crash.get("data", b"").hex() if isinstance(crash.get("data"), bytes) else ""),
                "error": crash.get("reason", crash.get("type", "Unknown")),
                "metrics": {"time_ms": crash.get("time_ms", 0)}
            })
            if crash.get("time_ms", 0) > 1500:
                latency_spikes.append(crash["time_ms"])
            if crash.get("response_code"):
                response_codes.append(crash["response_code"])
        
        return cls(
            crashes=crashes,
            latency_spikes=latency_spikes,
            response_codes=response_codes,
            spider_paths=spider_paths or [],
            vuln_type="web"
        )

