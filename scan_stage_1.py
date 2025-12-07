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
from ml_engine.logger_config import setup_logger
from ml_engine.file_prioritizer import FilePrioritizer
from ml_engine.cve_database import CVEDatabase

# Initialize DB
db_manager = DatabaseManager()

# Configure logging
logger = setup_logger(__name__, "scan_log.json")

def scan_stage_1(target_dir, intermediate_file, scan_id=None, quick_scan=False, max_files=300):
    """
    Stage 1: Scan C/C++ files using specialized models.
    Saves findings to intermediate_file.
    
    Args:
        target_dir: Directory to scan
        intermediate_file: JSON file to save findings
        scan_id: Optional database scan ID
        quick_scan: If True, prioritize files and limit to max_files (MVP mode)
        max_files: Maximum files to scan in quick mode (default: 300)
        
    Deep Thinking:
    - quick_scan defaults to False for backward compatibility
    - When enabled, we apply intelligent prioritization AFTER existing filters
    - This ensures we still skip tests/headers, then prioritize what's left
    - Existing full-scan behavior is completely unchanged
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
        
    logger.info(f"Proceeding with {len(filtered_files)} files after filtering (excluded {len(target_files) - len(filtered_files)})")
    
    # QUICK SCAN MODE: Prioritize files if enabled
    # Deep Thinking:
    # - This is a NEW step that only runs when quick_scan=True
    # - We apply prioritization AFTER existing filters (don't waste compute on test files)
    # - Logging shows both filtered count AND prioritized count for transparency
    # - If quick_scan=False, final_files = filtered_files (no change)
    final_files = filtered_files
    
    if quick_scan:
        logger.info("="*50)
        logger.info("QUICK SCAN MODE ENABLED")
        logger.info(f"Prioritizing files and limiting to top {max_files}...")
        logger.info("="*50)
        
        try:
            prioritizer = FilePrioritizer({"max_files": max_files})
            prioritized = prioritizer.prioritize_files(filtered_files)
            
            # Extract just the file paths (drop scores)
            final_files = [file_path for file_path, score in prioritized]
            
            logger.info(f"Selected {len(final_files)} high-priority files out of {len(filtered_files)} filtered files")
            logger.info(f"Time savings estimate: {len(filtered_files) - len(final_files)} files skipped")
            
            # Show top 10 selected files for transparency
            logger.info("Top 10 prioritized files:")
            for i, (file_path, score) in enumerate(prioritized[:10]):
                logger.info(f"  {i+1}. [{score:.1f}] {os.path.basename(file_path)}")
                
        except Exception as e:
            logger.error(f"File prioritization failed: {e}. Falling back to all filtered files.")
            # Graceful degradation: if prioritizer fails, scan all filtered files
            final_files = filtered_files
    
    all_findings = []

    try:
        vuln_scanner = VulnScanner(mode="c_cpp")
        cve_db = CVEDatabase()  # Initialize CVE database for version-specific detection

        # GLOBAL CVE DETECTION: Check for Tomcat version at scan level (FALLBACK)
        detected_software = None
        detected_version = None

        # Try to detect from target directory structure first
        if os.path.exists(os.path.join(target_dir, "build.properties.default")):
            logger.info("Found build.properties.default in target directory - attempting global version detection")
            try:
                with open(os.path.join(target_dir, "build.properties.default"), 'r', encoding='utf-8') as f:
                    props_content = f.read()

                import re
                major = re.search(r'version\.major=(\d+)', props_content)
                minor = re.search(r'version\.minor=(\d+)', props_content)
                build = re.search(r'version\.build=(\d+)', props_content)

                if major and minor and build:
                    detected_version = f"{major.group(1)}.{minor.group(1)}.{build.group(1)}"
                    detected_software = "apache_tomcat"
                    logger.info(f"Global detection: {detected_software} {detected_version}")
            except Exception as e:
                logger.warning(f"Failed global version detection: {e}")

        for file_path in final_files:  # Changed from filtered_files to final_files
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
                vulnerabilities = vuln_scanner.scan_code(code_content, file_extension=ext)

                # CVE ENRICHMENT: Add version-specific CVEs (Tomcat, etc.)
                vulnerabilities = cve_db.enrich_findings_with_cves(
                    vulnerabilities, code_content, file_path
                )

                if vulnerabilities:
                    # Filter and store
                    confirmed = [v for v in vulnerabilities if v.get('confidence', 0) > 0.5]
                    if confirmed:
                        logger.info(f"Flagged for analysis: {os.path.basename(file_path)} (Confidence: {confirmed[0]['confidence']:.2f})")
                        
                        # Add IDs to finding object for intermediate file consistency
                        finding_entry = {
                            'file_path': file_path,
                            'file_name': os.path.basename(file_path),
                            'vulnerabilities': confirmed,
                            'scan_id': scan_id,
                            'file_id': file_id
                        }
                        all_findings.append(finding_entry)
                        
                        # REAL-TIME SAVING: Update the file immediately
                        try:
                            with open(intermediate_file, 'w', encoding='utf-8') as f:
                                json.dump(all_findings, f, indent=4, ensure_ascii=False)
                            logger.info(f"Saved intermediate findings (Total: {len(all_findings)})")
                            
                            # DB SAVE
                            # We save each vulnerability individually or as a block?
                            # db_manager.save_finding expects a finding dict.
                            # The current structure has 'vulnerabilities': [list].
                            # We should probably iterate and save each vuln if we want granular tracking,
                            # OR save the whole block.
                            # Looking at db_manager.save_finding, it updates based on file_path+location.
                            # So we should iterate.
                            
                            for vuln in confirmed:
                                # Extract line number
                                line_number = 0
                                loc_str = vuln.get('location', '')
                                if 'Line' in loc_str:
                                    try:
                                        line_number = int(loc_str.split('Line')[1].strip().split()[0])
                                    except: pass

                                vuln_data = {
                                    'file_path': file_path,
                                    'file_name': os.path.basename(file_path),
                                    'location': loc_str,
                                    'line_number': vuln.get('line_number', line_number),  # Use scanner's line_number if available
                                    # CRITICAL: Extract CWE/CVE fields to top level for db_manager
                                    'cwe_id': vuln.get('cwe') or vuln.get('cwe_id') or 'Unclassified',
                                    'type': vuln.get('type', 'Potential Vulnerability'),
                                    'severity': vuln.get('severity', 'Medium'),
                                    'owasp_category': vuln.get('owasp') or vuln.get('owasp_category', 'Unknown'),
                                    'details': vuln,  # Keep full vuln as nested details
                                    'stage': 1
                                }
                                # Save and capture ID
                                finding_id = db_manager.save_finding(vuln_data, scan_id=scan_id, file_id=file_id)
                                
                                # Update the finding entry in all_findings with the ID so Stage 2 knows it
                                # We need to find the specific vuln in finding_entry['vulnerabilities'] and add the ID
                                # But finding_entry['vulnerabilities'] is a list of dicts.
                                # 'vuln' is a reference to one of them?
                                # Yes, 'confirmed' is a list of references to dicts in 'vulnerabilities' (which is ref to 'vulnerabilities' list)
                                # So modifying 'vuln' modifies 'finding_entry'
                                vuln['finding_id'] = finding_id
                                vuln['line_number'] = line_number

                        except Exception as save_err:
                            logger.error(f"Failed to save intermediate file/db: {save_err}")

            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
        
        # FALLBACK: If no CVEs detected via per-file scan, inject global CVEs
        total_cves = 0
        cve_list = set()
        for finding in all_findings:
            for vuln in finding.get('vulnerabilities', []):
                cve_id = vuln.get('cve', 'N/A')
                if cve_id != 'N/A' and cve_id.startswith('CVE-'):
                    total_cves += 1
                    cve_list.add(cve_id)

        # If we detected software globally but found no CVEs, force inject them
        # Also inject if version is "unknown" - better to show all possible CVEs than none
        if detected_software and total_cves == 0:
            logger.warning(f"No CVEs detected via per-file scanning. Injecting global CVEs for {detected_software} {detected_version or 'unknown'}...")

            # Get CVEs for detected version
            global_cves = cve_db.get_cves_for_version(detected_software, detected_version)

            if global_cves:
                # Create a synthetic finding entry for the global CVEs
                synthetic_finding = {
                    'file_path': target_dir,
                    'file_name': f'{detected_software}_{detected_version}',
                    'vulnerabilities': [],
                    'scan_id': scan_id,
                    'file_id': None
                }

                for cve in global_cves:
                    cve_finding = {
                        "type": f"Version-Specific Vulnerability: {cve['description']}",
                        "cwe": cve["cwe"],
                        "cve": cve["cve_id"],
                        "severity": cve["severity"],
                        "cvss": cve.get("cvss", 0.0),
                        "confidence": 0.9,  # High confidence for version-based CVE
                        "owasp": cve.get("owasp", "N/A"),
                        "location": f"Global ({detected_software} {detected_version})",
                        "details": f"{cve['description']}. Affected versions: {cve.get('affected_versions', 'See CVE details')}",
                        "exploit_available": cve.get("exploit_available", False),
                        "exploit_notes": cve.get("exploit_notes", ""),
                        "reasoning": f"Detected {detected_software} version {detected_version}. This version is vulnerable to {cve['cve_id']} ({cve['cwe']}). " + cve.get("exploit_notes", "")
                    }
                    synthetic_finding['vulnerabilities'].append(cve_finding)

                    # Save to database
                    if scan_id:
                        vuln_data = {
                            'file_path': target_dir,
                            'file_name': f'{detected_software}_{detected_version}',
                            'location': f"Global ({detected_software} {detected_version})",
                            'line_number': 0,
                            'details': cve_finding,
                            'stage': 1
                        }
                        finding_id = db_manager.save_finding(vuln_data, scan_id=scan_id, file_id=None)
                        cve_finding['finding_id'] = finding_id

                all_findings.append(synthetic_finding)
                logger.info(f"Injected {len(global_cves)} global CVEs into findings")

                # Recount CVEs
                for cve in global_cves:
                    cve_list.add(cve['cve_id'])
                total_cves = len(cve_list)

        # Final Save (redundant but safe)
        with open(intermediate_file, 'w', encoding='utf-8') as f:
            json.dump(all_findings, f, indent=4, ensure_ascii=False)

        logger.info("="*50)
        logger.info(f"Stage 1 Complete. Saved {len(all_findings)} findings to {intermediate_file}")
        if total_cves > 0:
            logger.info(f"🎯 Detected {len(cve_list)} unique CVEs: {', '.join(sorted(cve_list))}")
        else:
            logger.warning("⚠️ No CVEs detected. Consider checking version detection logic.")
        logger.info("="*50)

    except Exception as e:
        logger.error(f"Stage 1 Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Stage 1: Specialized model scanning for C/C++/Java/PHP files"
    )
    parser.add_argument("target_dir", help="Directory to scan")
    parser.add_argument("intermediate_file", help="JSON file to save findings")
    parser.add_argument("--scan-id", help="Scan ID for database tracking")
    
    # Deep Thinking: Quick scan parameters
    # - Flag is optional (default False) for backward compatibility
    # - max_files has sensible default (300) but can be overridden
    # - Designed to be easily called from orchestrator or GUI
    parser.add_argument(
        "--quick-scan", 
        action="store_true",
        help="Enable quick scan mode (prioritize security-critical files for faster MVP scanning)"
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=300,
        help="Maximum files to scan in quick mode (default: 300)"
    )
    
    args = parser.parse_args()
    
    scan_stage_1(
        args.target_dir, 
        args.intermediate_file, 
        scan_id=args.scan_id,
        quick_scan=args.quick_scan,
        max_files=args.max_files
    )
