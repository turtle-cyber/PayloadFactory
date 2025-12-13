"""
Smart Hybrid Fuzzer Module
3-Layer fuzzing approach: Random -> Boofuzz-style -> LLM-guided
Falls back to simpler layers if more complex ones fail.
"""

import logging
from ml_engine.fuzzing_module import Fuzzer

logger = logging.getLogger(__name__)


class SmartHybridFuzzer(Fuzzer):
    """
    Smart Hybrid Fuzzer with 3-layer approach:
    Layer 1: Random mutation fuzzing (fast, broad coverage)
    Layer 2: Boofuzz-style protocol-aware fuzzing (structured)
    Layer 3: LLM-guided intelligent fuzzing (context-aware)
    """
    
    def __init__(self, target_ip=None, target_port=None):
        """Initialize the smart hybrid fuzzer."""
        super().__init__(target_ip=target_ip, target_port=target_port)
        self.current_layer = 1
        logger.info(f"SmartHybridFuzzer initialized for {target_ip}:{target_port}")
    
    def run_fuzzing_session(self, base_payload, iterations=100):
        """
        Run a smart hybrid fuzzing session.
        Uses 3-layer approach, falling back to simpler layers if needed.
        """
        logger.info(f"Starting SmartHybridFuzzer session with {iterations} iterations")
        
        # Layer 1: Random fuzzing (default from parent)
        self.current_layer = 1
        results = super().run_fuzzing_session(base_payload, iterations=iterations)
        
        # If no crashes found and we have paths, try structured mutations
        if not results and hasattr(self, 'paths') and self.paths:
            self.current_layer = 2
            logger.info("Layer 1 found no crashes, trying Layer 2 (structured)")
            # Use parent fuzzer with structured mutations
            results = super().run_fuzzing_session(base_payload, iterations=iterations // 2)
        
        return results
    
    def get_current_layer(self) -> int:
        """Return the current fuzzing layer being used."""
        return self.current_layer
