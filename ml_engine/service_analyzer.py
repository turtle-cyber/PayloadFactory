"""
Service Analyzer Module
Uses LLM (Qwen) to analyze discovered services and provide:
- Exploitation steps
- Source code download links
- CVE details
- Attack vector recommendations
"""

import logging
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ServiceAnalysis:
    """Container for LLM analysis of a service."""
    service_name: str
    version: str
    port: int
    
    # LLM-generated content
    exploitation_steps: List[str]
    source_code_links: List[Dict[str, str]]  # [{"name": "GitHub", "url": "..."}]
    cves: List[Dict[str, str]]  # [{"id": "CVE-...", "description": "..."}]
    attack_vectors: List[str]
    risk_level: str  # "critical", "high", "medium", "low"
    notes: str
    
    # New fields for comprehensive analysis
    vm_setup: Optional[Dict[str, Any]] = None  # {"os": "...", "install_commands": [...]}
    tools_needed: Optional[List[str]] = None  # ["nmap", "metasploit", ...]


class ServiceAnalyzer:
    """
    Analyzes services using LLM to provide exploitation guidance.
    """
    
    # Prompt template for service analysis
    ANALYSIS_PROMPT = """You are a penetration testing expert. Analyze the discovered service and provide ACTIONABLE exploitation guidance.

TARGET:
- Service: {service_name}
- Version: {version}
- Port: {port}
- Banner: {banner}
- Extra Info: {extra_info}

Respond with a valid JSON object containing:

{{
  "exploitation_steps": [
    "Step 1: Check for default credentials (admin:admin, tomcat:tomcat)",
    "Step 2: Use nmap --script http-vuln-* to detect known vulnerabilities",
    "Step 3: If manager app accessible, deploy malicious WAR file",
    "..."
  ],
  "attack_vectors": ["RCE", "Authentication Bypass", "File Upload"],
  "tools_needed": ["nmap", "metasploit", "curl", "gobuster"],
  "source_code_links": [
    {{"name": "Official Repo", "url": "https://github.com/..."}}
  ],
  "vm_setup": {{
    "os": "Ubuntu 22.04",
    "install_commands": ["apt install openjdk-11-jdk", "wget tomcat.tar.gz"]
  }},
  "risk_level": "critical|high|medium|low",
  "notes": "Additional observations about the target"
}}

RULES:
1. Provide REAL, WORKING exploitation steps using actual tools
2. Do NOT invent CVE numbers - leave the "cves" field empty (we add CVEs separately)
3. Be specific to {service_name} version {version}
4. For web services, include paths like /manager, /admin, /console
5. Include Metasploit module names if applicable (e.g., exploit/multi/http/tomcat_mgr_upload)

Output ONLY the JSON object, no explanations."""

    def __init__(self, model_id: str = "hermes", scan_id: str = None):
        """
        Initialize analyzer with specified LLM.

        Args:
            model_id: Model to use ("hermes" for text-only, "qwen" for vision+text)
                      Default is "hermes" as it's more reliable for text-only analysis.
            scan_id: Optional scan ID to query CVEs from database
        """
        self.model_id = model_id
        self.model = None
        self.tokenizer = None
        self.scan_id = scan_id
        self.db_manager = None

        # Initialize database manager if scan_id provided
        if scan_id:
            try:
                from ml_engine.db_manager import DatabaseManager
                self.db_manager = DatabaseManager()
            except Exception as e:
                logger.warning(f"Failed to initialize database manager: {e}")

        self._load_model()
    
    def _get_cves_from_database(self, service_name: str) -> List[Dict[str, str]]:
        """
        Query CVEs from the scan database for this service.

        Args:
            service_name: Name of the service (e.g., "Apache Tomcat")

        Returns:
            List of CVE dicts with id, description, severity
        """
        if not self.db_manager or not self.scan_id:
            return []

        try:
            # Query findings from database that have CVE information
            findings = self.db_manager.get_findings(scan_id=self.scan_id)

            cves = []
            seen_cves = set()

            for finding in findings:
                details = finding.get('details', {})

                # Check for CVE in top-level or nested in details
                cve_id = details.get('cve') or finding.get('cve')
                cwe_id = details.get('cwe') or finding.get('cwe')
                severity = details.get('severity') or finding.get('severity', 'Unknown')
                vuln_type = details.get('type') or finding.get('type', '')

                # Only include if it's an actual CVE (not N/A or Unknown)
                if cve_id and cve_id not in ['N/A', 'Unknown'] and cve_id not in seen_cves:
                    description = details.get('details') or details.get('description', vuln_type)
                    if isinstance(description, str) and len(description) > 200:
                        description = description[:197] + "..."

                    cves.append({
                        "id": cve_id,
                        "description": description or vuln_type,
                        "severity": severity
                    })
                    seen_cves.add(cve_id)

            logger.info(f"Found {len(cves)} CVEs in database for this scan")
            return cves

        except Exception as e:
            logger.error(f"Failed to query CVEs from database: {e}")
            return []

    def _get_known_service_cves(self, service_name: str, version: str = "") -> List[Dict[str, str]]:
        """
        Get known CVEs for common services (standalone, no database required).
        This enables CVE data for blackbox recon without prior whitebox scans.
        
        Args:
            service_name: Service name (e.g., "Apache Tomcat", "nginx")
            version: Optional version string
            
        Returns:
            List of CVE dicts with id, description, severity
        """
        # Normalize service name for matching
        service_lower = service_name.lower()
        
        # Known CVEs for common services
        KNOWN_CVES = {
            "apache tomcat": [
                {"id": "CVE-2024-50379", "description": "TOCTOU Race Condition RCE via partial PUT requests", "severity": "Critical"},
                {"id": "CVE-2024-52318", "description": "XSS in JSP/Tag files due to improper output escaping", "severity": "Medium"},
                {"id": "CVE-2024-52317", "description": "Request/Response mix-up with HTTP/2 causing data leakage", "severity": "High"},
                {"id": "CVE-2024-52316", "description": "Authentication bypass when using Jakarta Authentication", "severity": "Critical"},
                {"id": "CVE-2024-38286", "description": "DoS via TLS handshake abort causing OutOfMemoryError", "severity": "High"},
                {"id": "CVE-2024-34750", "description": "DoS via improper HTTP/2 stream handling", "severity": "High"},
                {"id": "CVE-2024-23672", "description": "DoS via malformed WebSocket frames", "severity": "High"},
                {"id": "CVE-2020-1938", "description": "Ghostcat - AJP File Read/Inclusion vulnerability", "severity": "Critical"},
                {"id": "CVE-2020-9484", "description": "RCE via Session Persistence deserialization", "severity": "Critical"},
                {"id": "CVE-2019-0232", "description": "CGI Servlet RCE on Windows", "severity": "Critical"},
                {"id": "CVE-2017-12617", "description": "Remote code execution via PUT method", "severity": "Critical"},
            ],
            "nginx": [
                {"id": "CVE-2021-23017", "description": "DNS resolver off-by-one heap write", "severity": "High"},
                {"id": "CVE-2019-20372", "description": "HTTP Request Smuggling", "severity": "Medium"},
                {"id": "CVE-2017-7529", "description": "Integer overflow in range filter", "severity": "High"},
            ],
            "apache httpd": [
                {"id": "CVE-2021-41773", "description": "Path traversal and RCE", "severity": "Critical"},
                {"id": "CVE-2021-42013", "description": "Path traversal fix bypass", "severity": "Critical"},
                {"id": "CVE-2021-40438", "description": "SSRF via mod_proxy", "severity": "Critical"},
            ],
            "openssh": [
                {"id": "CVE-2024-6387", "description": "regreSSHion - Remote code execution in sshd", "severity": "Critical"},
                {"id": "CVE-2023-38408", "description": "Remote code execution via ssh-agent", "severity": "Critical"},
            ],
            "mysql": [
                {"id": "CVE-2016-6662", "description": "Remote root code execution", "severity": "Critical"},
                {"id": "CVE-2012-2122", "description": "Authentication bypass", "severity": "Critical"},
            ],
            "redis": [
                {"id": "CVE-2022-0543", "description": "Lua sandbox escape leading to RCE", "severity": "Critical"},
                {"id": "CVE-2015-8080", "description": "Integer overflow in YAML parser", "severity": "High"},
            ],
            "mongodb": [
                {"id": "CVE-2017-2665", "description": "Default configuration allows unauthenticated access", "severity": "Critical"},
            ],
            "smb": [
                {"id": "CVE-2017-0144", "description": "EternalBlue - Remote code execution", "severity": "Critical"},
                {"id": "CVE-2020-0796", "description": "SMBGhost - Remote code execution", "severity": "Critical"},
            ],
        }
        
        # Find matching service
        for key, cves in KNOWN_CVES.items():
            if key in service_lower or service_lower in key:
                logger.info(f"Found {len(cves)} known CVEs for {service_name}")
                return cves
        
        # Check for port-based fallback (e.g., "Service on port 8080" -> likely Tomcat)
        if "8080" in service_name or "tomcat" in service_lower:
            logger.info("Port 8080 detected - returning Tomcat CVEs")
            return KNOWN_CVES.get("apache tomcat", [])
        
        return []

    def _load_model(self):
        """Load the LLM model (supports both standard LLMs and Vision-Language models)."""
        try:
            from ml_engine.model_config import get_model_config
            import torch
            from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
            
            config = get_model_config(self.model_id)
            model_path = config["base_path"]
            adapter_path = config.get("adapter_path_full")
            model_type = config.get("type", "causal_lm")
            
            logger.info(f"Loading {config['name']} for service analysis...")
            
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
            )
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            
            # Use appropriate model class based on type
            if model_type == "vision_lm" or "VL" in config["name"] or "vl" in model_path.lower():
                # Load Qwen2.5-VL with the correct class
                try:
                    from transformers import Qwen2_5_VLForConditionalGeneration
                    logger.info("Using Qwen2_5_VLForConditionalGeneration for VL model...")
                    self.model = Qwen2_5_VLForConditionalGeneration.from_pretrained(
                        model_path,
                        torch_dtype=torch.float16,
                        device_map="auto",
                        trust_remote_code=True
                    )
                except ImportError:
                    # Fallback: try AutoModelForVision2Seq
                    from transformers import AutoModelForVision2Seq
                    logger.info("Using AutoModelForVision2Seq for VL model...")
                    self.model = AutoModelForVision2Seq.from_pretrained(
                        model_path,
                        torch_dtype=torch.float16,
                        device_map="auto",
                        trust_remote_code=True
                    )
            else:
                # Standard causal LM
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    quantization_config=quantization_config,
                    device_map="auto",
                    trust_remote_code=True
                )
            
            # Apply LoRA adapter if available
            if adapter_path:
                import os
                if os.path.exists(adapter_path):
                    logger.info(f"Applying LoRA adapter from {adapter_path}...")
                    from peft import PeftModel
                    self.model = PeftModel.from_pretrained(self.model, adapter_path)
                    logger.info("LoRA adapter loaded.")
            
            logger.info("Service analyzer model loaded successfully.")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def analyze_service(self, service_info: Dict[str, Any]) -> ServiceAnalysis:
        """
        Analyze a single service using LLM.
        
        Args:
            service_info: Dict with service details (port, service, version, banner, etc.)
            
        Returns:
            ServiceAnalysis with LLM-generated guidance
        """
        # Resolve service name - use fallback if unknown
        product = service_info.get("product", "unknown")
        service = service_info.get("service", "unknown")
        port = service_info.get("port", 0)
        
        if product == "unknown" or not product:
            product = self._get_service_name_by_port(port)
        if service == "unknown" or not service:
            service = product
        
        # Build prompt
        prompt = self.ANALYSIS_PROMPT.format(
            service_name=product,
            version=service_info.get("version", "unknown"),
            port=port,
            banner=service_info.get("banner", ""),
            extra_info=service_info.get("extrainfo", "")
        )
        
        # Generate response
        try:
            response = self._generate(prompt)
            analysis = self._parse_response(response, service_info)

            # ENHANCEMENT: Merge CVEs from multiple sources
            # Priority: 1. Database CVEs, 2. Known service CVEs, 3. LLM CVEs
            existing_cve_ids = {cve['id'] for cve in analysis.cves}
            
            # Add database CVEs (most reliable for this specific scan)
            db_cves = self._get_cves_from_database(product)
            for db_cve in db_cves:
                if db_cve['id'] not in existing_cve_ids:
                    analysis.cves.insert(0, db_cve)
                    existing_cve_ids.add(db_cve['id'])
            
            # Add known service CVEs (reliable hardcoded data)
            known_cves = self._get_known_service_cves(product, service_info.get("version", ""))
            for known_cve in known_cves:
                if known_cve['id'] not in existing_cve_ids:
                    analysis.cves.append(known_cve)
                    existing_cve_ids.add(known_cve['id'])
            
            if db_cves or known_cves:
                logger.info(f"Total CVEs: {len(analysis.cves)} (DB: {len(db_cves)}, Known: {len(known_cves)}, LLM: {len(analysis.cves) - len(db_cves) - len(known_cves)})")

            return analysis
        except Exception as e:
            logger.error(f"Failed to analyze service: {e}")
            # Return fallback analysis with known CVEs
            known_cves = self._get_known_service_cves(product, service_info.get("version", ""))
            db_cves = self._get_cves_from_database(product)
            all_cves = db_cves + [c for c in known_cves if c['id'] not in {d['id'] for d in db_cves}]
            
            return ServiceAnalysis(
                service_name=service_info.get("product", service_info.get("service", "Unknown")),
                version=service_info.get("version", "Unknown"),
                port=service_info.get("port", 0),
                exploitation_steps=["Analysis failed - manual review required"],
                source_code_links=[],
                cves=all_cves,  # Include all available CVEs
                attack_vectors=[],
                risk_level="critical" if all_cves else "unknown",
                notes=f"Analysis error: {str(e)}"
            )
    
    def analyze_scan_results(self, scan_results: Dict[str, Any]) -> List[ServiceAnalysis]:
        """
        Analyze all services from a network scan.
        
        Args:
            scan_results: Output from NetworkScanner.scan()
            
        Returns:
            List of ServiceAnalysis for each service
        """
        analyses = []
        
        for service in scan_results.get("services", []):
            logger.info(f"Analyzing service on port {service.get('port')}...")
            analysis = self.analyze_service(service)
            analyses.append(analysis)
        
        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        analyses.sort(key=lambda x: risk_order.get(x.risk_level, 5))
        
        return analyses
    
    def _get_service_name_by_port(self, port: int) -> str:
        """Get a likely service name based on port number."""
        port_map = {
            21: "FTP Server",
            22: "OpenSSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP Web Server",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS Web Server",
            445: "SMB/CIFS",
            3306: "MySQL",
            3389: "Remote Desktop (RDP)",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "Apache Tomcat / HTTP Proxy",
            8443: "HTTPS Alt / Tomcat SSL",
            9090: "Web Admin Console",
            27017: "MongoDB"
        }
        return port_map.get(port, f"Service on port {port}")
    
    def _generate(self, prompt: str, max_new_tokens: int = 2500) -> str:
        """Generate LLM response."""
        import torch
        
        # Format as chat message
        messages = [
            {"role": "system", "content": "You are a penetration testing expert. Always respond with valid JSON only."},
            {"role": "user", "content": prompt}
        ]
        
        # Try to use chat template if available
        try:
            text = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
        except:
            text = f"<|im_start|>system\nYou are a penetration testing expert. Always respond with valid JSON only.<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
        
        inputs = self.tokenizer(text, return_tensors="pt").to(self.model.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=0.7,
                top_p=0.9,
                do_sample=True,
                repetition_penalty=1.1,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        response = self.tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        return response.strip()
    
    def _parse_response(self, response: str, service_info: Dict[str, Any]) -> ServiceAnalysis:
        """Parse LLM response into ServiceAnalysis."""
        # Try to extract JSON from response
        try:
            # Try multiple extraction strategies
            data = None
            import re

            # Strategy 1: Try to parse entire response as JSON (fastest)
            try:
                data = json.loads(response.strip())
            except:
                pass

            # Strategy 2: Look for JSON code block with better regex
            if data is None:
                # Match various code block formats
                json_block = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
                if json_block:
                    try:
                        data = json.loads(json_block.group(1))
                    except:
                        pass

            # Strategy 3: Find matching braces (improved algorithm)
            if data is None and "{" in response:
                start = response.find("{")
                # Count braces to find matching end
                depth = 0
                end = start
                in_string = False
                escape_next = False

                for i, char in enumerate(response[start:], start):
                    if escape_next:
                        escape_next = False
                        continue
                    if char == '\\':
                        escape_next = True
                        continue
                    if char == '"' and not escape_next:
                        in_string = not in_string
                    if not in_string:
                        if char == '{':
                            depth += 1
                        elif char == '}':
                            depth -= 1
                            if depth == 0:
                                end = i + 1
                                break

                if end > start:
                    json_str = response[start:end]
                    # Try parsing as-is first
                    try:
                        data = json.loads(json_str)
                    except:
                        # Clean up common issues and try again
                        json_str = re.sub(r',\s*}', '}', json_str)  # Remove trailing commas in objects
                        json_str = re.sub(r',\s*]', ']', json_str)  # Remove trailing commas in arrays
                        try:
                            data = json.loads(json_str)
                        except:
                            pass

            # Strategy 4: Try finding JSON after common LLM prefixes
            if data is None:
                for prefix in ['here is', 'here\'s', 'response:', 'json:', 'output:']:
                    if prefix in response.lower():
                        idx = response.lower().find(prefix) + len(prefix)
                        rest = response[idx:].strip()
                        if rest.startswith('{'):
                            try:
                                # Find matching closing brace
                                depth = 0
                                end = 0
                                for i, char in enumerate(rest):
                                    if char == '{':
                                        depth += 1
                                    elif char == '}':
                                        depth -= 1
                                        if depth == 0:
                                            end = i + 1
                                            break
                                if end > 0:
                                    data = json.loads(rest[:end])
                                    break
                            except:
                                pass

            if data is None:
                raise ValueError("Could not extract valid JSON from response")
            
            return ServiceAnalysis(
                service_name=service_info.get("product", service_info.get("service", "Unknown")),
                version=service_info.get("version", "Unknown"),
                port=service_info.get("port", 0),
                exploitation_steps=data.get("exploitation_steps", []),
                source_code_links=data.get("source_code_links", []),
                cves=data.get("cves", []),
                attack_vectors=data.get("attack_vectors", []),
                risk_level=data.get("risk_level", "unknown"),
                notes=data.get("notes", ""),
                vm_setup=data.get("vm_setup"),
                tools_needed=data.get("tools_needed", [])
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            # Try to extract useful info from raw response using advanced text parsing
            import re

            exploitation_steps = []
            cves = []
            attack_vectors = []
            tools_needed = []

            lines = response.split('\n')

            # Extract CVEs from text
            cve_pattern = r'(CVE-\d{4}-\d{4,7})\s*[-:]\s*(.+?)(?:\n|$)'
            for match in re.finditer(cve_pattern, response, re.IGNORECASE):
                cve_id = match.group(1).upper()
                description = match.group(2).strip()
                # Clean up common artifacts like parentheses, brackets, etc.
                description = re.sub(r'\s*[\(\[].*?[\)\]].*$', '', description)
                description = re.sub(r'\s*\(.*$', '', description)  # Remove trailing parentheses
                if description:  # Only add if description is not empty
                    cves.append({
                        "id": cve_id,
                        "description": description,
                        "severity": "unknown"
                    })

            # Extract exploitation steps
            for line in lines:
                line = line.strip()
                # Match numbered lists, bullet points, or step indicators
                if re.match(r'^[\d\-\*\•]\s*.+', line) and len(line) > 5:
                    # Skip if it's a CVE line (already extracted)
                    if not re.match(r'CVE-\d{4}-\d{4,7}', line):
                        # Clean up the line
                        clean_line = re.sub(r'^[\d\-\*\•]+\.?\s*', '', line)
                        if clean_line:
                            exploitation_steps.append(clean_line)

            # Extract attack vectors from common keywords
            attack_keywords = [
                'RCE', 'Remote Code Execution', 'SQL Injection', 'XSS', 'Cross-Site Scripting',
                'CSRF', 'Cross Site Request Forgery', 'Path Traversal', 'File Upload',
                'Authentication Bypass', 'Privilege Escalation', 'Buffer Overflow',
                'Deserialization', 'XXE', 'SSRF', 'Command Injection'
            ]
            for keyword in attack_keywords:
                if re.search(rf'\b{re.escape(keyword)}\b', response, re.IGNORECASE):
                    if keyword not in attack_vectors:
                        attack_vectors.append(keyword)

            # Extract tool names
            tool_keywords = ['metasploit', 'nmap', 'burp', 'sqlmap', 'nikto', 'hydra',
                           'john', 'hashcat', 'gobuster', 'dirb', 'wfuzz', 'ffuf']
            for tool in tool_keywords:
                if re.search(rf'\b{tool}\b', response, re.IGNORECASE):
                    if tool.lower() not in [t.lower() for t in tools_needed]:
                        tools_needed.append(tool.lower())

            # Determine risk level based on CVE count and keywords
            risk_level = "unknown"
            critical_keywords = ['critical', 'rce', 'remote code execution', 'unauthenticated']
            if any(keyword in response.lower() for keyword in critical_keywords) or len(cves) >= 5:
                risk_level = "critical"
            elif len(cves) >= 3 or 'high' in response.lower():
                risk_level = "high"
            elif len(cves) >= 1:
                risk_level = "medium"

            return ServiceAnalysis(
                service_name=service_info.get("product", service_info.get("service", "Unknown")),
                version=service_info.get("version", "Unknown"),
                port=service_info.get("port", 0),
                exploitation_steps=exploitation_steps[:15] if exploitation_steps else ["Manual analysis required - see notes for raw LLM output"],
                source_code_links=[],
                cves=cves[:20],  # Limit to top 20 CVEs
                attack_vectors=attack_vectors[:10],
                risk_level=risk_level,
                notes=response[:2000],  # Increased from 500 to 2000 characters
                vm_setup=None,
                tools_needed=tools_needed
            )
    
    def generate_simulation_setup(self, service_info: Dict[str, Any], os_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate a simulation/lab setup guide for testing vulnerabilities on a service.
        
        Args:
            service_info: Dict with service details (port, service, product, version, banner)
            os_info: Optional OS detection info (name, family, vendor)
            
        Returns:
            Dict containing setup instructions, docker commands, VM configs, etc.
        """
        product = service_info.get("product", service_info.get("service", "Unknown"))
        version = service_info.get("version", "latest")
        port = service_info.get("port", 80)
        
        # Normalize service name
        product_lower = product.lower() if product else ""
        
        # Common setup templates for popular services
        SETUP_TEMPLATES = {
            "apache tomcat": {
                "docker_image": f"tomcat:{version if version != 'unknown' else 'latest'}",
                "docker_run": f"docker run -d -p {port}:8080 --name tomcat-lab tomcat:{version if version != 'unknown' else 'latest'}",
                "vulnerable_versions": ["8.5.0-8.5.78", "9.0.0-9.0.62", "10.0.0-10.0.20"],
                "install_commands": [
                    "apt-get update && apt-get install -y openjdk-11-jdk",
                    f"wget https://archive.apache.org/dist/tomcat/tomcat-{version.split('.')[0] if version != 'unknown' else '9'}/v{version}/bin/apache-tomcat-{version}.tar.gz" if version != 'unknown' else "# Download specific version from Apache archives",
                    "tar -xzf apache-tomcat-*.tar.gz -C /opt/",
                    "chmod +x /opt/apache-tomcat-*/bin/*.sh"
                ],
                "config_files": ["/opt/tomcat/conf/server.xml", "/opt/tomcat/conf/tomcat-users.xml"],
                "default_creds": ["tomcat:tomcat", "admin:admin", "manager:manager"],
                "test_paths": ["/manager/html", "/host-manager/html", "/manager/status"],
                "notes": "For CVE testing, use vulnerable Docker images from vulhub/tomcat or specific version archives."
            },
            "nginx": {
                "docker_image": f"nginx:{version if version != 'unknown' else 'latest'}",
                "docker_run": f"docker run -d -p {port}:80 --name nginx-lab nginx:{version if version != 'unknown' else 'latest'}",
                "vulnerable_versions": ["1.16.0-1.16.1", "1.17.0-1.17.6"],
                "install_commands": [
                    "apt-get update && apt-get install -y nginx",
                    "systemctl start nginx"
                ],
                "config_files": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"],
                "test_paths": ["/", "/.git/", "/server-status"],
                "notes": "Configure with misconfigurations for testing: alias traversal, open redirects, etc."
            },
            "apache": {
                "docker_image": f"httpd:{version if version != 'unknown' else 'latest'}",
                "docker_run": f"docker run -d -p {port}:80 --name apache-lab httpd:{version if version != 'unknown' else 'latest'}",
                "vulnerable_versions": ["2.4.49", "2.4.50"],
                "install_commands": [
                    "apt-get update && apt-get install -y apache2",
                    "a2enmod cgi",
                    "systemctl start apache2"
                ],
                "config_files": ["/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/000-default.conf"],
                "test_paths": ["/cgi-bin/", "/server-status", "/icons/"],
                "notes": "For CVE-2021-41773/42013 testing, use specific vulnerable version with mod_cgi enabled."
            },
            "openssh": {
                "docker_image": "linuxserver/openssh-server",
                "docker_run": f"docker run -d -p {port}:22 -e PUID=1000 -e PGID=1000 --name ssh-lab linuxserver/openssh-server",
                "vulnerable_versions": ["8.5p1-9.6p1"],  # regreSSHion
                "install_commands": [
                    "apt-get update && apt-get install -y openssh-server",
                    "systemctl start sshd"
                ],
                "config_files": ["/etc/ssh/sshd_config"],
                "default_creds": ["root:root", "admin:admin"],
                "notes": "For CVE-2024-6387 (regreSSHion) lab, compile specific vulnerable version from source."
            },
            "mysql": {
                "docker_image": f"mysql:{version if version != 'unknown' else '8.0'}",
                "docker_run": f"docker run -d -p {port}:3306 -e MYSQL_ROOT_PASSWORD=root --name mysql-lab mysql:{version if version != 'unknown' else '8.0'}",
                "install_commands": [
                    "apt-get update && apt-get install -y mysql-server",
                    "systemctl start mysql"
                ],
                "config_files": ["/etc/mysql/mysql.conf.d/mysqld.cnf"],
                "default_creds": ["root:root", "root:mysql", "admin:admin"],
                "notes": "For auth bypass testing (CVE-2012-2122), use older MySQL 5.x versions."
            },
            "redis": {
                "docker_image": f"redis:{version if version != 'unknown' else 'latest'}",
                "docker_run": f"docker run -d -p {port}:6379 --name redis-lab redis:{version if version != 'unknown' else 'latest'}",
                "install_commands": [
                    "apt-get update && apt-get install -y redis-server",
                    "# For unauthenticated access: comment out 'bind' and set 'protected-mode no'"
                ],
                "config_files": ["/etc/redis/redis.conf"],
                "notes": "Default Redis has no auth. Enable Lua for CVE-2022-0543 testing."
            }
        }
        
        # Find matching template
        setup = None
        for key, template in SETUP_TEMPLATES.items():
            if key in product_lower or product_lower in key:
                setup = template.copy()
                break
        
        # Generic fallback
        if setup is None:
            setup = {
                "docker_run": f"# No specific Docker image available for {product}",
                "install_commands": [f"# Manual installation required for {product} {version}"],
                "config_files": [],
                "notes": f"Search Docker Hub or official documentation for {product} installation instructions."
            }
        
        # Add common fields
        setup["service_name"] = product
        setup["version"] = version
        setup["port"] = port
        setup["os_recommendation"] = os_info.get("name", "Ubuntu 22.04 LTS") if os_info else "Ubuntu 22.04 LTS"
        
        return setup
    
    def format_simulation_setup(self, setup_data: Dict[str, Any]) -> str:
        """Format simulation setup data for display."""
        lines = [
            "=" * 70,
            f"  LAB SETUP: {setup_data.get('service_name', 'Unknown')} {setup_data.get('version', '')}",
            f"  PORT: {setup_data.get('port', 'N/A')}",
            "=" * 70,
            ""
        ]
        
        # Docker section
        if setup_data.get("docker_run"):
            lines.append("🐳 DOCKER QUICK START:")
            lines.append(f"  {setup_data['docker_run']}")
            lines.append("")
        
        # Installation commands
        if setup_data.get("install_commands"):
            lines.append("📦 MANUAL INSTALLATION:")
            for cmd in setup_data["install_commands"]:
                lines.append(f"  $ {cmd}")
            lines.append("")
        
        # Config files
        if setup_data.get("config_files"):
            lines.append("⚙️ CONFIG FILES:")
            for cfg in setup_data["config_files"]:
                lines.append(f"  • {cfg}")
            lines.append("")
        
        # Default credentials
        if setup_data.get("default_creds"):
            lines.append("🔑 DEFAULT CREDENTIALS TO TRY:")
            for cred in setup_data["default_creds"]:
                lines.append(f"  • {cred}")
            lines.append("")
        
        # Test paths
        if setup_data.get("test_paths"):
            lines.append("🎯 TEST PATHS:")
            for path in setup_data["test_paths"]:
                lines.append(f"  • {path}")
            lines.append("")
        
        # Vulnerable versions
        if setup_data.get("vulnerable_versions"):
            lines.append("⚠️ KNOWN VULNERABLE VERSIONS:")
            lines.append(f"  {', '.join(setup_data['vulnerable_versions'])}")
            lines.append("")
        
        # Notes
        if setup_data.get("notes"):
            lines.append("📝 NOTES:")
            lines.append(f"  {setup_data['notes']}")
        
        return "\n".join(lines)
    
    def format_analysis(self, analysis: ServiceAnalysis) -> str:
        """Format analysis for display."""
        # Color codes for risk levels
        risk_indicators = {
            "critical": "🔴 CRITICAL",
            "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM",
            "low": "🟢 LOW",
            "unknown": "⚪ UNKNOWN"
        }
        risk_display = risk_indicators.get(analysis.risk_level.lower(), "⚪ UNKNOWN")

        lines = [
            f"{'='*70}",
            f"  SERVICE: {analysis.service_name} v{analysis.version}",
            f"  PORT: {analysis.port}",
            f"  RISK LEVEL: {risk_display}",
            f"{'='*70}",
            "",
        ]

        # CVEs section (moved up for importance)
        lines.append("🐛 CVE VULNERABILITIES:")
        if analysis.cves:
            lines.append(f"  Found {len(analysis.cves)} CVE(s):")
            for i, cve in enumerate(analysis.cves, 1):
                cvss = cve.get('cvss', '')
                severity = cve.get('severity', 'unknown')
                cvss_str = f" [CVSS: {cvss}]" if cvss else ""
                severity_badge = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(severity.lower(), '⚪')

                description = cve.get('description', 'No description')
                # Truncate long descriptions
                if len(description) > 80:
                    description = description[:77] + "..."

                lines.append(f"  {i}. {severity_badge} {cve.get('id', 'Unknown')}{cvss_str}")
                lines.append(f"     {description}")
        else:
            lines.append("   No known CVEs found")

        lines.append("")
        lines.append("  EXPLOITATION STEPS:")
        if analysis.exploitation_steps:
            for i, step in enumerate(analysis.exploitation_steps, 1):
                # Wrap long steps
                if len(step) > 75:
                    lines.append(f"  {i}. {step[:72]}...")
                else:
                    lines.append(f"  {i}. {step}")
        else:
            lines.append("   No exploitation steps available")

        lines.append("")
        lines.append(" ATTACK VECTORS:")
        if analysis.attack_vectors:
            # Group similar attacks
            lines.append(f"  {', '.join(analysis.attack_vectors)}")
        else:
            lines.append("  No specific attack vectors identified")

        # Tools section
        if analysis.tools_needed:
            lines.append("")
            lines.append(" REQUIRED TOOLS:")
            lines.append(f"  {', '.join(analysis.tools_needed)}")

        # Source code links
        if analysis.source_code_links:
            lines.append("")
            lines.append(" SOURCE CODE:")
            for link in analysis.source_code_links:
                name = link.get('name', 'Link')
                url = link.get('url', 'N/A')
                # Truncate long URLs
                if len(url) > 60:
                    url = url[:57] + "..."
                lines.append(f"  • {name}: {url}")

        # VM/Lab Setup
        if analysis.vm_setup:
            lines.append("")
            lines.append(" LAB SETUP:")
            vm = analysis.vm_setup
            if vm.get('os'):
                lines.append(f"  OS: {vm.get('os')}")
            if vm.get('install_commands'):
                lines.append("  Install Commands:")
                for cmd in vm.get('install_commands', [])[:5]:  # Limit to 5
                    lines.append(f"    $ {cmd}")
            if vm.get('vulnerable_version_download'):
                lines.append(f"  Vulnerable Version: {vm.get('vulnerable_version_download')}")
            if vm.get('configuration'):
                lines.append(f"  Configuration: {vm.get('configuration')}")

        # Notes at the bottom
        if analysis.notes:
            lines.append("")
            lines.append(" ADDITIONAL NOTES:")
            # Wrap notes at 70 characters
            note_lines = []
            current_line = ""
            for word in analysis.notes.split():
                if len(current_line) + len(word) + 1 <= 70:
                    current_line += (word + " ")
                else:
                    note_lines.append(current_line.strip())
                    current_line = word + " "
            if current_line:
                note_lines.append(current_line.strip())

            for note_line in note_lines[:10]:  # Limit to 10 lines
                lines.append(f"  {note_line}")
            if len(note_lines) > 10:
                lines.append(f"  ... ({len(note_lines) - 10} more lines)")

        return "\n".join(lines)


def analyze_target(ip: str, ports: str = "1-1000", model_id: str = "qwen") -> Dict[str, Any]:
    """
    Convenience function: Scan and analyze a target.
    
    Returns:
        Dict with scan results and analyses
    """
    from ml_engine.network_scanner import NetworkScanner
    
    # Scan
    scanner = NetworkScanner()
    scan_results = scanner.scan_target(ip, ports=[int(p) for p in ports.split(",")] if "," in ports else None)
    
    # Analyze
    analyzer = ServiceAnalyzer(model_id=model_id)
    analyses = analyzer.analyze_scan_results({
        "ip": ip,
        "services": [asdict(s) if hasattr(s, '__dataclass_fields__') else s for s in scan_results.services]
    })
    
    return {
        "scan_results": scan_results,
        "analyses": [asdict(a) for a in analyses]
    }


if __name__ == "__main__":
    import sys
    
    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python service_analyzer.py <IP> [ports]")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_ports = sys.argv[2] if len(sys.argv) > 2 else "80,443,8080"
    
    result = analyze_target(target_ip, target_ports)
    print(json.dumps(result, indent=2, default=str))
