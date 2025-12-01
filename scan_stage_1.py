import os
import sys
import argparse
import logging
import json
import torch
import gc

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "ml_engine")))
from ml_engine.vuln_scanner import VulnScanner
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

def scan_stage_1(target_dir, intermediate_file):
    """
    Stage 1: Scan C/C++ files using specialized models.
    Saves findings to intermediate_file.
    """
    logger.info("="*50)
    logger.info("="*50)
    logger.info("STAGE 1: SPECIALIZED MODEL SCANNING (Process 1)")
    logger.info("="*50)

    SUPPORTED_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp', '.cc', '.java', '.jsp', '.php'}
    target_files = []

    # Collect files
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext.lower() in SUPPORTED_EXTENSIONS:
                target_files.append(os.path.join(root, file))

    if not target_files:
        logger.info("No supported files (C/C++, Java, PHP) found. Skipping Stage 1.")
        return

    logger.info(f"Found {len(target_files)} supported files.")
    
    # FILTERING: Exclude test, legacy, and header files to reduce false positives
    filtered_files = []
    # Directories to ignore (case-insensitive)
    ignored_dirs = {'test', 'tests', 'testing', 'mock', 'mocks', 'demo', 'demos', 'example', 'examples', 'sample', 'samples', 'bench', 'benchmark', 'benchmarks', 'legacy'}
    # Filename patterns to ignore
    ignored_file_patterns = ['test', 'mock', 'spec', 'fixture']
    
    for f in target_files:
        # Check full path for ignored directories
        path_parts = f.lower().split(os.sep)
        if any(d in ignored_dirs for d in path_parts):
            # logger.debug(f"Skipping file in ignored directory: {f}")
            continue

        fname = os.path.basename(f).lower()
        
        # Check for headers
        if f.endswith('.h') or f.endswith('.hpp'):
            continue
            
        # Check for test files (e.g., MyClassTest.java, TestUtils.java)
        if fname.endswith('test.java') or fname.startswith('test'):
             # logger.debug(f"Skipping test file: {fname}")
             continue
             
        # Check for other ignored patterns in filename
        if any(pat in fname for pat in ignored_file_patterns):
            # logger.debug(f"Skipping likely non-production file: {fname}")
            continue
            
        filtered_files.append(f)
        
    logger.info(f"Proceeding with {len(filtered_files)} files after filtering (excluded {len(target_files) - len(filtered_files)}).")
    
    all_findings = []
    
    try:
        vuln_scanner = VulnScanner(mode="c_cpp")
        
        for file_path in filtered_files:
            logger.info(f"Scanning: {os.path.basename(file_path)}")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()
                
                if not code_content.strip(): continue

                _, ext = os.path.splitext(file_path)
                vulnerabilities = vuln_scanner.scan_code(code_content, file_extension=ext)
                
                if vulnerabilities:
                    # Filter and store
                    confirmed = [v for v in vulnerabilities if v.get('confidence', 0) > 0.5]
                    if confirmed:
                        logger.info(f"Flagged for analysis: {os.path.basename(file_path)} (Confidence: {confirmed[0]['confidence']:.2f})")
                        all_findings.append({
                            'file_path': file_path,
                            'file_name': os.path.basename(file_path),
                            'vulnerabilities': confirmed
                        })
                        
                        # REAL-TIME SAVING: Update the file immediately
                        try:
                            with open(intermediate_file, 'w', encoding='utf-8') as f:
                                json.dump(all_findings, f, indent=4, ensure_ascii=False)
                            logger.info(f"Saved intermediate findings (Total: {len(all_findings)})")
                            
                            # DB SAVE
                            db_manager.save_finding({
                                'file_path': file_path,
                                'file_name': os.path.basename(file_path),
                                'vulnerabilities': confirmed,
                                'stage': 1
                            })
                        except Exception as save_err:
                            logger.error(f"Failed to save intermediate file/db: {save_err}")

            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
        
        # Final Save (redundant but safe)
        with open(intermediate_file, 'w', encoding='utf-8') as f:
            json.dump(all_findings, f, indent=4, ensure_ascii=False)
            
        logger.info(f"Stage 1 Complete. Saved {len(all_findings)} findings to {intermediate_file}")

    except Exception as e:
        logger.error(f"Stage 1 Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_dir")
    parser.add_argument("intermediate_file")
    args = parser.parse_args()
    
    scan_stage_1(args.target_dir, args.intermediate_file)
