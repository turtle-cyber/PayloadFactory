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
from ml_engine.spider_module import WebSpider
from ml_engine.logger_config import setup_logger

# Configure logging
logger = setup_logger(__name__, "scan_log.json")

def scan_stage_3(output_dir, remote_host=None, remote_port=None, scan_id=None, infinite=False, threads=1):
    """
    Stage 3: Fuzzing and RL Optimization of generated exploits.
    """
    logger.info("="*50)
    logger.info("STAGE 3: FUZZING & RL OPTIMIZATION (Process 3)")
    if infinite:
        logger.info("MODE: INFINITE FUZZING (Until Crash)")
    if threads > 1:
        logger.info(f"MODE: PARALLEL FUZZING ({threads} threads)")
    
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
    
    # --- SPIDER MODULE INTEGRATION ---
    discovered_paths = []
    if remote_host and remote_port:
        target_url = f"{remote_host}:{remote_port}"
        logger.info(f"Running Spider on {target_url} to find endpoints...")
        try:
            spider = WebSpider(target_url)
            spider.crawl()
            discovered_paths = spider.get_paths()
            logger.info(f"Spider found {len(discovered_paths)} endpoints: {discovered_paths}")
            
            # Update Fuzzer with discovered paths
            fuzzer.set_paths(discovered_paths)
        except Exception as e:
            logger.warning(f"Spider failed: {e}")
            
    # Initialize generator for lazy loading
    gen = None

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
            # --- INFINITE LOOP WRAPPER ---
            while True:
                # 1. Fuzzing Phase (With Feedback Loop)
                # Keep retries low (5) even in infinite mode so we hit the RL Optimization phase frequently.
                max_retries = 5
                crashes = []
                
                attempt = 0
                while attempt <= max_retries:
                    attempt += 1
                    logger.info(f"  -> Running Fuzzer (Attempt {attempt}/{max_retries})...")
                    
                    # Load payload (re-load in case it was regenerated)
                    if os.path.exists(payload_file):
                        with open(payload_file, 'rb') as pf:
                            base_payload = pf.read()
                    else:
                        base_payload = b"A" * 64
                    
                    if threads > 1:
                        crashes = fuzzer.run_parallel_fuzzing_session(base_payload, iterations=20, threads=threads)
                    else:
                        crashes = fuzzer.run_fuzzing_session(base_payload, iterations=20)
                    
                    if crashes:
                        # Analyze findings to report specific type
                        finding_types = set()
                        for c in crashes:
                            err = c.get("error", "")
                            if "High Latency" in err:
                                finding_types.add("DoS (High Latency)")
                            elif "RCE" in err:
                                finding_types.add("RCE (Confirmed)")
                                # Extract Date if present
                                if "Date:" in err:
                                    date_str = err.split("Date: ")[1].strip(")")
                                    logger.info(f"  -> [!!!] SYSTEM INFILTRATED. Server Time: {date_str}")
                            else:
                                finding_types.add("Crash/Error")
                        
                        types_str = ", ".join(finding_types)
                        logger.info(f"  -> Fuzzer found {len(crashes)} findings! ({types_str})")
                        break # Success!
                    
                    # If no crashes and we have retries left, REGENERATE
                    if attempt < max_retries and remote_host:
                        logger.warning("  -> Fuzzing failed (0 crashes). Initiating Self-Healing...")
                        
                        # INTELLIGENT LOOP: Pick a relevant path if available
                        target_path = None
                        if discovered_paths:
                            import random
                            target_path = random.choice(discovered_paths)
                            logger.info(f"  -> Intelligent Loop: Guiding LLM to target {target_path}")

                        # Lazy load generator only if needed
                        if gen is None:
                            from ml_engine.exploit_generator import ExploitGenerator, PayloadExtractor
                            gen = ExploitGenerator() 
                        
                        # Pass feedback to the generator
                        new_code = gen.regenerate_exploit(
                            exploit_code, 
                            "Fuzzer failed to find any crashes. The payload might be blocked or invalid.",
                            target_path=target_path,
                            feedback="Try to use a different payload structure or target the specific endpoint provided."
                        )
                        
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
                    
                # --- NEW: Inject Optimized Payload into Code ---
                if len(optimized_payload) > 0:
                    logger.info("  -> Injecting optimized payload into exploit script...")
                    # Simple heuristic: Look for 'payloads = [' or 'payload = '
                    # and try to insert the optimized one as the FIRST item.
                    
                    new_exploit_lines = []
                    injected = False
                    
                    with open(exploit_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                    for line in lines:
                        new_exploit_lines.append(line)
                        if not injected and ("payloads = [" in line or "payloads=[" in line):
                            # Inject immediately after list start
                            new_exploit_lines.append(f"    {repr(optimized_payload.decode('utf-8', errors='ignore'))}, # OPTIMIZED BY RL AGENT\n")
                            injected = True
                            
                    if injected:
                        with open(exploit_file, 'w', encoding='utf-8') as f:
                            f.writelines(new_exploit_lines)
                        logger.info("  -> Exploit script updated with optimized payload.")
                    else:
                        # Fallback: If no list found, append a new one at the top or appropriate place
                        logger.warning("  -> Could not find 'payloads = [' list. Appending new list...")
                        
                        # Insert after imports (heuristic: look for 'import ' lines)
                        insert_idx = 0
                        for i, line in enumerate(lines):
                            if line.startswith("import ") or line.startswith("from "):
                                insert_idx = i + 1
                        
                        new_lines = lines[:insert_idx] + [
                            "\n# --- INJECTED BY RL AGENT ---\n",
                            "payloads = [\n",
                            f"    {repr(optimized_payload.decode('utf-8', errors='ignore'))},\n",
                            "]\n"
                        ] + lines[insert_idx:]
                        
                        with open(exploit_file, 'w', encoding='utf-8') as f:
                            f.writelines(new_lines)
                        logger.info("  -> Created new 'payloads' list with optimized payload.")

                logger.info(f"  -> Optimization complete for {file_name}")
                
                if not infinite:
                    break
                else:
                    logger.info("  -> Infinite Mode: Restarting cycle with new optimized payload...")
                    # Update base_payload for next cycle
                    base_payload = optimized_payload
                    # Update payload file
                    with open(payload_file, 'wb') as pf:
                        pf.write(base_payload)

        except Exception as e:
            logger.error(f"Error optimizing {file_name}: {e}")

    logger.info("Stage 3 Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    parser.add_argument("--remote-host", help="Target IP")
    parser.add_argument("--remote-port", type=int, help="Target Port")
    parser.add_argument("--scan-id", help="Scan ID for database tracking")
    parser.add_argument("--infinite", action="store_true", help="Run fuzzing indefinitely until crash")
    parser.add_argument("--threads", type=int, default=1, help="Number of concurrent fuzzing threads")
    args = parser.parse_args()
    
    scan_stage_3(args.output_dir, args.remote_host, args.remote_port, args.scan_id, infinite=args.infinite, threads=args.threads)
