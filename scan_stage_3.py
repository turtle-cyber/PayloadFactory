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
# WebSpider removed - endpoints now come from exploit code or default paths
from ml_engine.logger_config import setup_logger
from ml_engine.feedback_context import FeedbackContext
from ml_engine.exploit_executor import ExploitExecutor, ExploitResult
from ml_engine.db_manager import DatabaseManager

# Initialize DB
db_manager = DatabaseManager()

# Configure logging
logger = setup_logger(__name__, "scan_log.json")

# Global scan_id for logging (set when stage starts)
_current_scan_id = None

def scan_log(message: str, level: str = "info"):
    """
    Log a message to both file and MongoDB for real-time frontend display.
    """
    # Log to file
    if level == "info":
        logger.info(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    else:
        logger.debug(message)
    
    # Save to MongoDB for frontend streaming
    if _current_scan_id:
        try:
            db_manager.save_scan_log(_current_scan_id, message, level)
        except:
            pass  # Don't fail scan if log saving fails

def scan_stage_3(output_dir, remote_host=None, remote_port=None, scan_id=None, infinite=False, threads=1, use_boofuzz=False, tomcat_direct=False, auto_execute=False, smart_fuzz=True):
    """
    Stage 3: Fuzzing and RL Optimization of generated exploits.
    
    Args:
        auto_execute: If True, automatically execute exploits against the target after optimization
        smart_fuzz: If True, use SmartHybridFuzzer (3-layer fuzzing with LLM)
    """
    # Set global scan_id for logging
    global _current_scan_id
    _current_scan_id = scan_id
    
    scan_log("=" * 50)
    scan_log("STAGE 3: FUZZING & RL OPTIMIZATION")
    if infinite:
        scan_log("MODE: INFINITE FUZZING (Until Crash)")
    if threads > 1:
        scan_log(f"MODE: PARALLEL FUZZING ({threads} threads)")
    if tomcat_direct:
        scan_log("MODE: TOMCAT DIRECT ATTACK (CVE-based targeting)")
    if auto_execute:
        scan_log("MODE: AUTO-EXECUTE ENABLED (Exploits will be run against target)")
    if smart_fuzz:
        scan_log("MODE: SMART HYBRID FUZZER (3-Layer: Random + Boofuzz + LLM)")
    
    if remote_host:
        scan_log(f"ATTACK MODE: Targeting {remote_host}:{remote_port}")
    else:
        scan_log("SIMULATION MODE: Fuzzing locally (no network traffic)")
    scan_log("=" * 50)

    # Find generated exploits
    exploit_files = glob.glob(os.path.join(output_dir, "exploit_*.py"))
    
    if not exploit_files:
        scan_log("No exploits found to optimize. Skipping Stage 3.", "warning")
        return

    scan_log(f"Found {len(exploit_files)} exploits to optimize.")
    
    # Initialize Fuzzer - Choose strategy based on flags
    # Priority: smart_fuzz > use_boofuzz > legacy
    if smart_fuzz and remote_host:
        from ml_engine.smart_fuzzer import SmartHybridFuzzer
        fuzzer = SmartHybridFuzzer(target_ip=remote_host, target_port=remote_port)
        scan_log("Using SMART HYBRID FUZZER (Layer 1: Random, Layer 2: Boofuzz, Layer 3: LLM)")
    elif use_boofuzz and remote_host:
        from ml_engine.boofuzz_engine import BoofuzzEngine
        fuzzer = BoofuzzEngine(target_ip=remote_host, target_port=remote_port)
        logger.info("Using BOOFUZZ engine for advanced fuzzing")
    else:
        fuzzer = Fuzzer(target_ip=remote_host, target_port=remote_port)
    rl_agent = RLAgent()
    
    # Initialize ExploitExecutor if auto-execute is enabled
    exploit_executor = None
    if auto_execute and remote_host:
        exploit_executor = ExploitExecutor(timeout=30, use_listener=False)
        scan_log("ExploitExecutor initialized for auto-execution")
    
    # --- TOMCAT DIRECT ATTACK MODE ---
    tomcat_paths = []
    if tomcat_direct and remote_host and remote_port:
        scan_log("="*50)
        scan_log("TOMCAT DIRECT ATTACK PHASE")
        scan_log("="*50)
        try:
            from ml_engine.tomcat_scanner import TomcatScanner
            from ml_engine.tomcat_targets import get_all_attack_paths
            
            # Run Tomcat-specific scan
            scanner = TomcatScanner(remote_host)
            results = scanner.full_scan(remote_port)
            
            # Use Tomcat-specific paths instead of spider
            tomcat_paths = get_all_attack_paths()
            fuzzer.set_paths(tomcat_paths)
            scan_log(f"Loaded {len(tomcat_paths)} Tomcat attack paths")
            
            # If credentials found, log critical
            if results.get("credentials"):
                scan_log(f"CREDENTIALS FOUND: {results['credentials']}", "warning")
            
            # If vulnerabilities found, continue with enhanced fuzzing
            if results.get("vulnerabilities"):
                for vuln in results["vulnerabilities"]:
                    scan_log(f"VULNERABILITY: {vuln}", "warning")
                    
        except Exception as e:
            scan_log(f"Tomcat scanner failed: {e}. Using default paths.", "warning")
            tomcat_direct = False
    
    # --- ENDPOINT DISCOVERY (No Spider - use exploit metadata or defaults) ---
    # Spider removed - endpoints are already embedded in Stage 2 exploit code
    # or we use well-known attack paths based on target type
    discovered_paths = []
    if not tomcat_direct and remote_host and remote_port:
        # Use common web attack paths instead of spidering
        # These are generic paths likely to exist on most web servers
        discovered_paths = [
            "/", "/admin", "/login", "/api", "/manager", "/console",
            "/admin.php", "/index.php", "/upload", "/files",
            "/manager/html", "/manager/text", "/host-manager",
            "/status", "/jmxrmi", "/invoker/JMXInvokerServlet"
        ]
        fuzzer.set_paths(discovered_paths)
        scan_log(f"Using {len(discovered_paths)} default attack paths (Spider removed)")
    elif tomcat_paths:
        discovered_paths = tomcat_paths
            
    # Initialize generator for lazy loading
    gen = None

    for exploit_file in exploit_files:
        file_name = os.path.basename(exploit_file)
        scan_log(f"Optimizing {file_name}...")
        
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
                    scan_log(f"  -> Running Fuzzer (Attempt {attempt}/{max_retries})...")
                    
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
                                    scan_log(f"  -> [!!!] SYSTEM INFILTRATED. Server Time: {date_str}", "warning")
                            else:
                                finding_types.add("Crash/Error")
                        
                        types_str = ", ".join(finding_types)
                        scan_log(f"  -> Fuzzer found {len(crashes)} findings! ({types_str})")
                        break # Success!
                    
                    # If no crashes and we have retries left, REGENERATE
                    if attempt < max_retries and remote_host:
                        scan_log("  -> Fuzzing failed (0 crashes). Initiating Self-Healing...", "warning")
                        
                        # INTELLIGENT LOOP: Pick a relevant path if available
                        target_path = None
                        if discovered_paths:
                            import random
                            target_path = random.choice(discovered_paths)
                            scan_log(f"  -> Intelligent Loop: Guiding LLM to target {target_path}")

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
                        
                        # ============================================================
                        # VALIDATION: Check if LLM output is valid Python before saving
                        # ============================================================
                        is_valid = False
                        try:
                            import ast
                            ast.parse(new_code)
                            is_valid = True
                        except SyntaxError as e:
                            scan_log(f"  -> LLM generated invalid Python! Syntax error: {e}", "warning")
                            scan_log("  -> Keeping original exploit, only mutating payload...", "warning")
                        
                        if is_valid:
                            # Additional sanity check: must contain 'import' and 'target'
                            if 'import' in new_code and ('target' in new_code or 'requests' in new_code or 'remote' in new_code):
                                # Save new code
                                with open(exploit_file, 'w', encoding='utf-8') as f:
                                    f.write(new_code)
                                
                                # Extract new payload
                                extractor = PayloadExtractor()
                                new_payload = extractor.extract(new_code)
                                with open(payload_file, 'wb') as pf:
                                    pf.write(new_payload)
                                    
                                scan_log("  -> Exploit regenerated and saved. Retrying...")
                                exploit_code = new_code # Update for next loop
                            else:
                                scan_log("  -> LLM output missing key elements. Keeping original.", "warning")
                        else:
                            # If LLM failed, just mutate the payload instead
                            scan_log("  -> Mutating existing payload instead of regenerating...")
                            mutated = fuzzer.mutate_payload(base_payload)
                            with open(payload_file, 'wb') as pf:
                                pf.write(mutated)
                
                # 2. Build FeedbackContext for RL Agent
                vuln_type = "binary" if ("pwntools" in exploit_code or "p32" in exploit_code or "p64" in exploit_code) else "web"
                feedback = FeedbackContext(
                    crashes=crashes,
                    spider_paths=discovered_paths,
                    vuln_type=vuln_type,
                    best_payload=base_payload,
                    response_codes=[c.get("metrics", {}).get("response_code", 0) for c in crashes if c.get("metrics")],
                    latency_spikes=[c.get("metrics", {}).get("time_ms", 0) for c in crashes if c.get("metrics", {}).get("time_ms", 0) > 1000],
                    exploit_code=exploit_code
                )
                
                # 3. RL Optimization Phase (with shared Fuzzer and Feedback)
                scan_log("  -> Running RL Agent with feedback context...")
                optimized_payload = rl_agent.optimize_exploit(
                    base_payload, 
                    iterations=20, 
                    target_ip=remote_host, 
                    target_port=remote_port,
                    fuzzer=fuzzer,      # Share fuzzer (keeps spider paths)
                    feedback=feedback   # Pass crash context
                )
                
                # 4. Validation Phase - Test the optimized payload
                validation_status = "UNTESTED"
                validation_latency = 0.0
                if remote_host:
                    scan_log("  -> Validating optimized payload...")
                    validation_result = fuzzer.send_payload(optimized_payload)
                    validation_latency = validation_result.get("time_ms", 0)
                    
                    if validation_result["crash"]:
                        validation_status = "CRASH_CONFIRMED"
                    elif validation_latency > 1500:
                        validation_status = "DOS_CONFIRMED"
                    elif validation_result.get("data"):
                        response_str = validation_result["data"].decode('utf-8', errors='ignore')
                        if "uid=" in response_str or "root" in response_str:
                            validation_status = "RCE_CONFIRMED"
                        else:
                            validation_status = "RESPONSE_OK"
                    else:
                        validation_status = "NO_RESPONSE"
                    
                    scan_log(f"  -> Validation: {validation_status} (Latency: {validation_latency:.1f}ms)")
                
                # Append optimization results to the exploit file as comments
                with open(exploit_file, 'a', encoding='utf-8') as f:
                    f.write("\n\n# --- AUTOMATED OPTIMIZATION RESULTS ---\n")
                    if remote_host:
                         f.write(f"# ATTACK REPORT: Target {remote_host}:{remote_port}\n")
                    f.write(f"# Fuzzing: Found {len(crashes)} crashes.\n")
                    f.write(f"# RL Agent: Optimized payload length to {len(optimized_payload)} bytes.\n")
                    f.write(f"# Validation: {validation_status} (Latency: {validation_latency:.1f}ms)\n")
                    f.write(f"# Optimized Payload Snippet: {repr(optimized_payload[:50])}...\n")
                    
                # --- NEW: Inject Optimized Payload into Code ---
                if len(optimized_payload) > 0:
                    scan_log("  -> Injecting optimized payload into exploit script...")
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
                        scan_log("  -> Exploit script updated with optimized payload.")
                    else:
                        # Fallback: If no list found, append a new one at the top or appropriate place
                        scan_log("  -> Could not find 'payloads = [' list. Appending new list...", "warning")
                        
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
                        scan_log("  -> Created new 'payloads' list with optimized payload.")

                scan_log(f"  -> Optimization complete for {file_name}")
                
                # --- EXPLOIT EXECUTION PHASE ---
                if exploit_executor and remote_host:
                    scan_log("="*50)
                    scan_log("EXPLOIT EXECUTION PHASE")
                    scan_log("="*50)
                    scan_log(f"  -> Executing exploit: {file_name}")
                    
                    exec_result = exploit_executor.execute_exploit(
                        exploit_file, 
                        target_ip=remote_host, 
                        target_port=remote_port
                    )
                    
                    if exec_result.rce_detected:
                        scan_log(f"  -> *** RCE SUCCESSFUL! *** Exploit: {file_name}", "warning")
                        scan_log(f"  -> Output: {exec_result.output[:500] if exec_result.output else 'N/A'}", "warning")
                        # Append RCE confirmation to exploit file
                        with open(exploit_file, 'a', encoding='utf-8') as f:
                            f.write(f"\n# *** RCE CONFIRMED on {remote_host}:{remote_port} ***\n")
                    elif exec_result.dos_detected:
                        scan_log(f"  -> DoS detected: {file_name}", "warning")
                    elif exec_result.success:
                        scan_log(f"  -> Exploit executed successfully: {file_name}")
                        scan_log(f"  -> Output: {exec_result.output[:200] if exec_result.output else 'N/A'}")
                    else:
                        scan_log(f"  -> Exploit execution failed: {exec_result.error[:200] if exec_result.error else 'Unknown error'}", "error")
                
                if not infinite:
                    break
                else:
                    scan_log("  -> Infinite Mode: Restarting cycle with new optimized payload...")
                    # Update base_payload for next cycle
                    base_payload = optimized_payload
                    # Update payload file
                    with open(payload_file, 'wb') as pf:
                        pf.write(base_payload)

        except Exception as e:
            scan_log(f"Error optimizing {file_name}: {e}", "error")

    scan_log("Stage 3 Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    parser.add_argument("--remote-host", help="Target IP")
    parser.add_argument("--remote-port", type=int, help="Target Port")
    parser.add_argument("--scan-id", help="Scan ID for database tracking")
    parser.add_argument("--infinite", action="store_true", help="Run fuzzing indefinitely until crash")
    parser.add_argument("--threads", type=int, default=1, help="Number of concurrent fuzzing threads")
    parser.add_argument("--use-boofuzz", action="store_true", help="Use Boofuzz advanced fuzzer (CVE payloads for Tomcat v8-v11)")
    parser.add_argument("--tomcat-direct", action="store_true", help="Use Tomcat-specific attack targeting (port scan, brute-force, CVE chains)")
    parser.add_argument("--auto-execute", action="store_true", help="Automatically execute exploits against target after optimization")
    parser.add_argument("--smart-fuzz", action="store_true", default=True, help="Use Smart Hybrid Fuzzer (3-Layer: Random + Boofuzz + LLM)")
    parser.add_argument("--no-smart-fuzz", action="store_true", help="Disable Smart Hybrid Fuzzer, use legacy fuzzer")
    args = parser.parse_args()
    
    # Handle --no-smart-fuzz flag
    smart_fuzz = args.smart_fuzz and not args.no_smart_fuzz
    
    scan_stage_3(args.output_dir, args.remote_host, args.remote_port, args.scan_id, infinite=args.infinite, threads=args.threads, use_boofuzz=args.use_boofuzz, tomcat_direct=args.tomcat_direct, auto_execute=args.auto_execute, smart_fuzz=smart_fuzz)

