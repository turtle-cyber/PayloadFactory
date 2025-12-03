import os
import sys
import argparse
import logging
import json
import glob

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "ml_engine")))
from ml_engine.fuzzing_module import Fuzzer
from ml_engine.rl_agent import RLAgent
from ml_engine.logger_config import setup_logger

# Configure logging
logger = setup_logger(__name__, "scan_log.json")

def scan_stage_3(output_dir, remote_host=None, remote_port=None, scan_id=None):
    """
    Stage 3: Fuzzing and RL Optimization of generated exploits.
    """
    logger.info("="*50)
    logger.info("STAGE 3: FUZZING & RL OPTIMIZATION (Process 3)")
    if remote_host:
        logger.info(f"ATTACK MODE ENABLED: Targeting {remote_host}:{remote_port}")
    else:
        logger.info("SIMULATION MODE: Fuzzing locally (no network traffic)")
    logger.info("="*50)

    # Find generated exploits
    exploit_files = glob.glob(os.path.join(output_dir, "exploit_*.py"))
    
    if not exploit_files:
        logger.info("No exploits found to optimize. Skipping Stage 3.")
        return

    logger.info(f"Found {len(exploit_files)} exploits to optimize.")
    
    # Initialize Fuzzer with target if provided
    fuzzer = Fuzzer(target_ip=remote_host, target_port=remote_port)
    rl_agent = RLAgent()
    
    for exploit_file in exploit_files:
        file_name = os.path.basename(exploit_file)
        logger.info(f"Optimizing {file_name}...")
        
        try:
            # Read the exploit code
            with open(exploit_file, 'r', encoding='utf-8') as f:
                exploit_code = f.read()
            
            # Define payload file path
            payload_file = exploit_file.replace("exploit_", "payload_").replace(".py", ".bin")
            payload_file = os.path.join(output_dir, "payloads", os.path.basename(payload_file))

            # 1. Fuzzing Phase (With Feedback Loop)
            max_retries = 2
            crashes = []
            
            for attempt in range(max_retries + 1):
                logger.info(f"  -> Running Fuzzer (Attempt {attempt+1}/{max_retries+1})...")
                
                # Load payload (re-load in case it was regenerated)
                if os.path.exists(payload_file):
                    with open(payload_file, 'rb') as pf:
                        base_payload = pf.read()
                else:
                    base_payload = b"A" * 64
                
                crashes = fuzzer.run_fuzzing_session(base_payload, iterations=20)
                
                if crashes:
                    logger.info(f"  -> Fuzzer found {len(crashes)} crashes! Success.")
                    break # Success!
                
                # If no crashes and we have retries left, REGENERATE
                if attempt < max_retries and remote_host:
                    logger.warning("  -> Fuzzing failed (0 crashes). Initiating Self-Healing...")
                    
                    # Lazy load generator only if needed
                    from ml_engine.exploit_generator import ExploitGenerator, PayloadExtractor
                    # We need a generator instance. In a real app, pass it or singleton.
                    # For now, we instantiate (expensive but functional)
                    # Ideally we should pass the model/tokenizer if possible, but Stage 3 is standalone process usually.
                    # If we want to share model, we'd need to load it here or pass it.
                    # For now, let's assume it loads its own or we skip regeneration if too heavy.
                    # To avoid reloading heavy model, we might skip this if not strictly needed.
                    # But the original code had it.
                    
                    gen = ExploitGenerator() 
                    
                    new_code = gen.regenerate_exploit(exploit_code, "No Crash detected. Payload might be incorrect or offset too small.")
                    
                    # Save new code
                    with open(exploit_file, 'w', encoding='utf-8') as f:
                        f.write(new_code)
                    
                    # Extract new payload
                    extractor = PayloadExtractor()
                    new_payload = extractor.extract(new_code)
                    with open(payload_file, 'wb') as pf:
                        pf.write(new_payload)
                        
                    logger.info("  -> Exploit regenerated and saved. Retrying...")
                    exploit_code = new_code # Update for next loop
            
            # 2. RL Optimization Phase
            logger.info("  -> Running RL Agent...")
            optimized_payload = rl_agent.optimize_exploit(
                base_payload, 
                iterations=20, 
                target_ip=remote_host, 
                target_port=remote_port
            )
            
            # Append optimization results to the exploit file as comments
            with open(exploit_file, 'a', encoding='utf-8') as f:
                f.write("\n\n# --- AUTOMATED OPTIMIZATION RESULTS ---\n")
                if remote_host:
                     f.write(f"# ATTACK REPORT: Target {remote_host}:{remote_port}\n")
                f.write(f"# Fuzzing: Found {len(crashes)} crashes.\n")
                f.write(f"# RL Agent: Optimized payload length to {len(optimized_payload)} bytes.\n")
                f.write(f"# Optimized Payload Snippet: {repr(optimized_payload[:50])}...\n")
                
            logger.info(f"  -> Optimization complete for {file_name}")

        except Exception as e:
            logger.error(f"Error optimizing {file_name}: {e}")

    logger.info("Stage 3 Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    parser.add_argument("--remote-host", help="Target IP")
    parser.add_argument("--remote-port", type=int, help="Target Port")
    parser.add_argument("--scan-id", help="Scan ID for database tracking")
    args = parser.parse_args()
    
    scan_stage_3(args.output_dir, args.remote_host, args.remote_port, args.scan_id)
