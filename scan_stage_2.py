import os
import sys
import argparse
import logging
import json
import torch
import gc
from datetime import datetime

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "ml_engine")))
from ml_engine.vuln_scanner import VulnScanner
from ml_engine.exploit_generator import ExploitGenerator
from ml_engine.db_manager import DatabaseManager
from ml_engine.logger_config import setup_logger

# Initialize DB
db_manager = DatabaseManager()

# Configure logging
logger = setup_logger(__name__, "scan_log.json")

def scan_stage_2(target_dir, output_dir, intermediate_file, remote_host=None, remote_port=None, scan_id=None, skip_other_files=False, demo_mode=False):
    """
    Stage 2: LLM Classification, Other Files Scan, Exploit Gen.
    
    Args:
        target_dir: Directory to scan
        output_dir: Directory to save exploits
        intermediate_file: JSON file with Stage 1 findings
        remote_host: Optional target host for exploit scripts
        remote_port: Optional target port for exploit scripts
        scan_id: Optional database scan ID
        skip_other_files: If True, skip scanning additional file types (quick scan mode)
        
    Deep Thinking:
    - skip_other_files defaults to False for backward compatibility
    - When True, we ONLY process Stage 1 findings (no new file discovery)
    - This significantly reduces LLM inference time for MVP
    - Stage 1 findings already contain high-confidence vulnerabilities
    """
    logger.info("="*50)
    logger.info("STAGE 2: LLM ANALYSIS & EXPLOIT GEN (Process 2)")
    logger.info("="*50)

    # Load findings from Stage 1
    all_findings = []
    if os.path.exists(intermediate_file):
        with open(intermediate_file, 'r', encoding='utf-8') as f:
            all_findings = json.load(f)
    
    # Collect other files
    OTHER_EXTENSIONS = {'.py', '.php', '.java', '.js', '.go', '.rb'}

    # DEMO MODE TOGGLE
    # Set to True to enable "Paranoid Mode" for specific targets
    # Now controlled by argument
    
    # CRITICAL TOMCAT TARGETS (Prioritize these for deep analysis)
    TARGET_FILES = set()
    if demo_mode:
        logger.info("DEMO MODE ENABLED: Targeting critical Tomcat components")
        TARGET_FILES = {
            "StandardContext.java", "ContextConfig.java", "JspServlet.java", 
            "DefaultServlet.java", "ManagerBase.java", "StandardManager.java",
            "PersistentManagerBase.java", "FileStore.java", "CGIServlet.java",
            "HostConfig.java", "AprLifecycleListener.java", "AjpProcessor.java"
        }
    # Create set of already processed files to prevent double-scanning
    processed_files = set()
    for finding in all_findings:
        processed_files.add(os.path.abspath(finding['file_path']))
        
    other_files = []
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext.lower() in OTHER_EXTENSIONS:
                full_path = os.path.abspath(os.path.join(root, file))
                if full_path not in processed_files:
                    other_files.append(full_path)

    if not all_findings and not other_files:
        logger.info("Nothing to process in Stage 2.")
        return
    
    # Quick Scan Mode: Skip collecting "other files" if flag is set
    # Deep Thinking:
    # - In quick mode, we trust Stage 1's prioritized findings
    # - Scanning additional .py/.js/.go files is expensive (LLM inference)
    # - For MVP, focusing on Stage 1 findings provides best ROI
    # - EXCEPTION: Always scan TARGET_FILES if found
    if skip_other_files:
        logger.info("="*50)
        logger.info("QUICK SCAN MODE: Skipping general files, but checking for CRITICAL TARGETS")
        
        # Filter other_files to keep ONLY critical targets
        critical_files = [f for f in other_files if os.path.basename(f) in TARGET_FILES]
        
        if critical_files:
            logger.info(f"FOUND {len(critical_files)} CRITICAL TARGETS to scan despite Quick Mode:")
            for cf in critical_files:
                logger.info(f"  - {os.path.basename(cf)}")
            other_files = critical_files
        else:
            logger.info(f"No critical targets found. Will process only {len(all_findings)} Stage 1 findings")
            other_files = []
        logger.info("="*50)

    try:
        # Build target URL for exploit generation
        target_url = None
        if remote_host and remote_port:
            # Construct full URL with protocol
            target_url = f"http://{remote_host}:{remote_port}"
            logger.info(f"Using target URL for exploits: {target_url}")
        
        # Load LLM via VulnScanner
        logger.info("Loading LLM (Hermes 3)...")
        vuln_scanner = VulnScanner(mode="llm")
        
        # Initialize ExploitGenerator sharing the SAME model/tokenizer
        logger.info("Initializing ExploitGenerator with shared model...")
        exploit_gen = ExploitGenerator(
            model=vuln_scanner.llm_model, 
            tokenizer=vuln_scanner.llm_tokenizer,
            default_target=target_url
        )
        
        # Import enhanced modules
        from ml_engine.exploit_context import extract_vulnerability_context
        from ml_engine.exploit_validator import ExploitValidator
        validator = ExploitValidator()
        
        # Prepare output directories
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        payloads_dir = os.path.join(output_dir, "payloads")
        if not os.path.exists(payloads_dir):
            os.makedirs(payloads_dir)

        # Helper function to generate and save exploit
        def process_and_generate(file_path, vulnerabilities, code_content, file_id=None):
            file_name = os.path.basename(file_path)
            processed_locations = set() # Track unique locations to prevent duplicates
            
            for i, vuln in enumerate(vulnerabilities):
                # DEDUPLICATION: Check if we already processed this location/chunk
                vuln_loc = vuln.get('location', '')
                vuln_chunk = vuln.get('vulnerable_chunk', '')
                unique_key = f"{vuln_loc}_{hash(vuln_chunk)}"
                
                if unique_key in processed_locations:
                    logger.info(f"Skipping duplicate vulnerability at {vuln_loc}")
                    continue
                processed_locations.add(unique_key)

                # Classify if not already classified
                if vuln.get('classification') is None:
                    logger.info(f"Classifying vulnerability in {file_name}...")
                    chunk_to_analyze = vuln.get('vulnerable_chunk', code_content)
                    
                    # Check if this is a critical target
                    is_critical = os.path.basename(file_path) in TARGET_FILES
                    if is_critical:
                        logger.info(f"  -> Using PARANOID mode for classification")
                        
                    classification_list = vuln_scanner.classify_vulnerability(chunk_to_analyze, paranoid_mode=is_critical)
                    # Handle list return (take first result or empty dict)
                    classification = classification_list[0] if isinstance(classification_list, list) and classification_list else (classification_list if isinstance(classification_list, dict) else {})
                    
                    vuln['classification'] = classification
                    logger.info(f"  -> CWE: {classification.get('cwe', 'N/A')}")
                    
                    # REAL-TIME SAVE: Persist the classification immediately
                    try:
                        # We need to update the specific finding in the main list
                        # Since 'vulnerabilities' is a reference to the list inside 'all_findings',
                        # modifying 'vuln' (dict) updates the main list.
                        # We just need to dump 'all_findings' to disk.
                        if all_findings:
                            with open(intermediate_file, 'w', encoding='utf-8') as f:
                                json.dump(all_findings, f, indent=4, ensure_ascii=False)
                        
                        # DB SAVE (Update)
                        # We need to save the specific finding.
                        # Extract line number from location string (e.g., "Line 45" or "Token Offset...")
                        line_number = 0
                        loc_str = vuln.get('location', '')
                        if 'Line' in loc_str:
                            try:
                                line_number = int(loc_str.split('Line')[1].strip().split()[0])
                            except: pass
                        
                        # Prepare enhanced finding data
                        vuln_data = {
                            'file_path': file_path,
                            'file_name': file_name,
                            'location': loc_str,
                            'line_number': line_number,
                            'type': classification.get('type', 'Unknown'),
                            'severity': classification.get('severity', 'Unknown'),
                            'cwe_id': classification.get('cwe', 'Unknown'),
                            'owasp_category': classification.get('owasp', 'Unknown'),
                            'details': vuln,
                            'stage': 2
                        }
                        
                        # Save and get finding_id
                        finding_id = db_manager.save_finding(vuln_data, scan_id=scan_id, file_id=file_id)
                        vuln['finding_id'] = finding_id # Store for exploit linkage
                        
                    except Exception as save_err:
                        logger.error(f"Failed to save intermediate findings/db: {save_err}")

                # Check if we should generate exploit
                classification = vuln.get('classification', {})
                cwe = classification.get('cwe', 'Unknown')
                
                # Skip if Safe or Unknown (without strong vuln indicators)
                # STRICTER CHECK: If CWE is Unknown, we only proceed if type is explicitly "Potential Vulnerability"
                # AND the details don't look like a false positive.
                if cwe == 'Safe':
                    logger.info(f"Skipping exploit generation for {file_name} (Classified as Safe)")
                    continue
                
                if cwe == 'Unknown':
                    vuln_type = classification.get('type', '')
                    if 'Potential Vulnerability' not in vuln_type:
                        logger.info(f"Skipping exploit generation for {file_name} (Classified as Unknown/Safe)")
                        continue
                    # Optional: Add more heuristics here if needed
                    
                logger.info(f"Generating exploit for: {file_name} (CWE: {cwe})")
                
                try:
                    # Extract context
                    context = extract_vulnerability_context(file_path, vuln, code_content)
                    
                    # Generate enhanced exploit
                    exploit_result = exploit_gen.generate_exploit_enhanced(
                        context=context,
                        weaponize=True,
                        weaponize_config=None
                    )
                    
                    if exploit_result['success']:
                        exploit_code = exploit_result['script']
                        payload_bytes = exploit_result['payload']
                        metadata = exploit_result['metadata']
                        
                        # Safety check: Ensure exploit code is not empty
                        if not exploit_code.strip():
                            logger.warning(f"Exploit code is empty for {file_name}, skipping...")
                            continue
                        
                        # Validate exploit
                        validation = validator.validate(exploit_code)
                        
                        # NEW: CWE Validation
                        cwe_validation = validator.validate_cwe_match(exploit_code, cwe)
                        if not cwe_validation['valid']:
                             logger.warning(f"CWE Mismatch: {cwe_validation['message']}")
                             # Trigger regeneration
                             failure_reason = f"CWE Mismatch: {cwe_validation['message']}"
                             exploit_code = exploit_gen.regenerate_exploit(exploit_code, failure_reason)
                             # Re-validate
                             validation = validator.validate(exploit_code)
                        
                        if not validation['syntax_valid']:
                            logger.warning(f"Generated exploit has syntax errors: {validation['errors']}")
                            # FIXED Fallback: Use regenerate_exploit to preserve context
                            logger.info("Attempting to regenerate exploit with error feedback...")
                            failure_reason = f"Syntax errors: {validation['errors']}"
                            exploit_code = exploit_gen.regenerate_exploit(exploit_code, failure_reason)
                            validation = validator.validate(exploit_code)
                        
                        # Save exploit script
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        exploit_filename = f"exploit_{file_name}_{i}_{timestamp}.py"
                        exploit_path = os.path.join(output_dir, exploit_filename)
                        
                        with open(exploit_path, 'w', encoding='utf-8') as ef:
                            ef.write(f'"""\nMetadata:\n{json.dumps(metadata, indent=2)}\n"""\n')
                            ef.write(f"# Validation: {validation}\n\n")
                            ef.write(exploit_code)
                        
                        logger.info(f"Exploit saved: {exploit_filename} (Valid: {validation['valid']})")
                        
                        # DB SAVE (Exploit)
                        exploit_data = {
                            'filename': exploit_filename,
                            'target_file': file_name,
                            'finding_id': vuln.get('finding_id'), # Link to specific finding
                            'cwe': cwe,
                            'code': exploit_code,
                            'metadata': metadata,
                            'validation': validation,
                            'path': exploit_path
                        }
                        db_manager.save_exploit(exploit_data, scan_id=scan_id, file_id=file_id)
                        
                        # Save payload
                        payload_filename = f"payload_{file_name}_{i}_{timestamp}.bin"
                        payload_path = os.path.join(payloads_dir, payload_filename)
                        with open(payload_path, 'wb') as pf:
                            pf.write(payload_bytes)
                        logger.info(f"Payload saved: {payload_filename}")
                        
                    else:
                        logger.error(f"Enhanced generation failed, using fallback...")
                        # Fallback logic could be added here if needed
                        
                except Exception as ge:
                    logger.error(f"Failed to generate exploit for {file_name}: {ge}")

        # 1. Process Stage 1 Findings (Interleaved)
        if all_findings:
            logger.info(f"Processing {len(all_findings)} findings from Stage 1...")
            for finding in all_findings:
                file_path = finding['file_path']
                # Retrieve IDs if they exist from Stage 1
                f_scan_id = finding.get('scan_id', scan_id)
                f_file_id = finding.get('file_id')
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()
                    
                    process_and_generate(file_path, finding['vulnerabilities'], code_content, file_id=f_file_id)
                    
                    # Clear GPU cache after processing each Stage 1 finding
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                    
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()

        # 2. Scan & Process Other Files (Interleaved)
        if other_files:
            logger.info(f"Scanning {len(other_files)} other files...")
            for file_path in other_files:
                logger.info(f"Scanning: {os.path.basename(file_path)}")
                
                # Register file in DB
                file_id = None
                if scan_id:
                    try:
                        file_size = os.path.getsize(file_path)
                        file_id = db_manager.add_file(scan_id, file_path, file_size)
                    except Exception as e:
                        logger.error(f"Failed to register file {file_path}: {e}")

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()
                    if not code_content.strip(): continue
                    
                    _, ext = os.path.splitext(file_path)
                    
                    # Check if this is a critical target
                    is_critical = os.path.basename(file_path) in TARGET_FILES
                    if is_critical:
                        logger.info(f"!!! PARANOID MODE ENABLED for {os.path.basename(file_path)} !!!")

                    # Scan with CUDA OOM protection
                    try:
                        vulnerabilities = vuln_scanner.scan_code(code_content, file_extension=ext, file_path=file_path, paranoid_mode=is_critical)
                    except (RuntimeError, torch.cuda.OutOfMemoryError) as cuda_err:
                        if "out of memory" in str(cuda_err).lower():
                            logger.error(f"CUDA OOM while scanning {os.path.basename(file_path)}. Clearing cache...")
                            torch.cuda.empty_cache()
                            gc.collect()
                            # Retry once after clearing
                            try:
                                vulnerabilities = vuln_scanner.scan_code(code_content, file_extension=ext, file_path=file_path)
                            except Exception as retry_err:
                                logger.error(f"Retry failed for {os.path.basename(file_path)}: {retry_err}")
                                continue  # Skip this file
                        else:
                            raise
                    
                    if vulnerabilities:
                        confirmed = [v for v in vulnerabilities if v.get('confidence', 0) > 0.5]
                        if confirmed:
                            logger.warning(f"Vulnerability detected in {os.path.basename(file_path)}")
                            
                            # Save finding to DB first
                            for vuln in confirmed:
                                vuln_data = {
                                    'file_path': file_path,
                                    'file_name': os.path.basename(file_path),
                                    'location': vuln.get('location'),
                                    'details': vuln,
                                    'stage': 2
                                }
                                db_manager.save_finding(vuln_data, scan_id=scan_id, file_id=file_id)

                            # Immediately generate exploit
                            process_and_generate(file_path, confirmed, code_content, file_id=file_id)
                    
                    # Clear GPU cache after each file to prevent accumulation
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                            
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {e}")
                    # Clear cache even on error
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()

        # Cleanup
        del vuln_scanner
        del exploit_gen
        torch.cuda.empty_cache()
        gc.collect()

    except Exception as e:
        logger.error(f"Stage 2 Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Stage 2: LLM analysis and exploit generation"
    )
    parser.add_argument("target_dir", help="Directory to scan")
    parser.add_argument("output_dir", help="Directory to save exploits")
    parser.add_argument("intermediate_file", help="JSON file with Stage 1 findings")
    parser.add_argument("--remote-host", help="Target IP for exploit scripts")
    parser.add_argument("--remote-port", type=int, help="Target port for exploit scripts")
    parser.add_argument("--scan-id", help="Scan ID for database tracking")
    
    # Deep Thinking: Quick scan flag
    # - Allows skipping "other files" scan for faster MVP scanning
    # - Default False maintains backward compatibility
    # - Should be set to True when --quick-scan is used in Stage 1
    parser.add_argument(
        "--skip-other-files",
        action="store_true",
        help="Skip scanning additional file types (.py, .js, .go) in quick scan mode"
    )
    
    parser.add_argument(
        "--demo-mode",
        action="store_true",
        help="Enable Demo Mode (Paranoid scanning for specific targets)"
    )
    
    args = parser.parse_args()
    
    scan_stage_2(
        args.target_dir, 
        args.output_dir, 
        args.intermediate_file, 
        args.remote_host, 
        args.remote_port, 
        args.scan_id,
        skip_other_files=args.skip_other_files,
        demo_mode=args.demo_mode
    )
