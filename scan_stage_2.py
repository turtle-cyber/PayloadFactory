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

# Initialize DB
db_manager = DatabaseManager()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scan_log.txt", mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def scan_stage_2(target_dir, output_dir, intermediate_file, remote_host=None, remote_port=None):
    """
    Stage 2: LLM Classification, Other Files Scan, Exploit Gen.
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
        def process_and_generate(file_path, vulnerabilities, code_content):
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
                    classification = vuln_scanner.classify_vulnerability(chunk_to_analyze)
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
                        db_manager.save_finding({
                            'file_path': file_path,
                            'file_name': file_name,
                            'vulnerabilities': [vuln], # Save just this updated vuln
                            'stage': 2
                        })
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
                        
                        # Validate exploit
                        validation = validator.validate(exploit_code)
                        
                        if not validation['syntax_valid']:
                            logger.warning(f"Generated exploit has syntax errors: {validation['errors']}")
                            # Fallback
                            vuln_desc = f"Vulnerability in {file_name}: {vuln.get('details', 'Unknown issue')}"
                            exploit_code = exploit_gen.generate_exploit(vuln_desc)
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
                        db_manager.save_exploit({
                            'filename': exploit_filename,
                            'target_file': file_name,
                            'cwe': cwe,
                            'code': exploit_code,
                            'metadata': metadata,
                            'validation': validation,
                            'path': exploit_path
                        })
                        
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
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()
                    
                    process_and_generate(file_path, finding['vulnerabilities'], code_content)
                    
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")

        # 2. Scan & Process Other Files (Interleaved)
        if other_files:
            logger.info(f"Scanning {len(other_files)} other files...")
            for file_path in other_files:
                logger.info(f"Scanning: {os.path.basename(file_path)}")
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code_content = f.read()
                    if not code_content.strip(): continue
                    
                    _, ext = os.path.splitext(file_path)
                    vulnerabilities = vuln_scanner.scan_code(code_content, file_extension=ext)
                    
                    if vulnerabilities:
                        confirmed = [v for v in vulnerabilities if v.get('confidence', 0) > 0.5]
                        if confirmed:
                            logger.warning(f"Vulnerability detected in {os.path.basename(file_path)}")
                            # Immediately generate exploit
                            process_and_generate(file_path, confirmed, code_content)
                            
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {e}")

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
    parser = argparse.ArgumentParser()
    parser.add_argument("target_dir")
    parser.add_argument("output_dir")
    parser.add_argument("intermediate_file")
    parser.add_argument("--remote-host", help="Target IP for exploit scripts")
    parser.add_argument("--remote-port", type=int, help="Target port for exploit scripts")
    args = parser.parse_args()
    
    scan_stage_2(args.target_dir, args.output_dir, args.intermediate_file, args.remote_host, args.remote_port)
