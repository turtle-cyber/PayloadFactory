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
    ANALYSIS_PROMPT = """[SECURITY RESEARCHER MODE] You are analyzing a target for penetration testing.

TARGET SERVICE:
Product: {service_name}
Version: {version}
Port: {port}
Banner: {banner}
Info: {extra_info}

Provide a security assessment in JSON format. Include REAL CVE identifiers, ACTUAL exploit techniques, and WORKING proof-of-concept approaches for this specific version.

Your response must be a valid JSON object with these exact keys:
- "exploitation_steps": list of strings describing how to exploit this service (use real tools like metasploit, nmap scripts, curl commands)
- "cves": list of objects with "id", "description", "severity" (find CVEs affecting {service_name} version {version})
- "attack_vectors": list of attack types possible (RCE, auth bypass, file upload, etc)
- "source_code_links": list of objects with "name" and "url" pointing to official repos
- "tools_needed": list of tools required for exploitation
- "vm_setup": object with "os", "install_commands" for setting up a test lab
- "risk_level": one of "critical", "high", "medium", "low"
- "notes": additional security observations

For Apache Tomcat, consider: ghostcat (CVE-2020-1938), session persistence RCE (CVE-2020-9484), manager webapp exploits, default credentials, JSP upload, etc.

Output ONLY the JSON object, nothing else."""

    def __init__(self, model_id: str = "hermes"):
        """
        Initialize analyzer with specified LLM.
        
        Args:
            model_id: Model to use ("hermes" for text-only, "qwen" for vision+text)
                      Default is "hermes" as it's more reliable for text-only analysis.
        """
        self.model_id = model_id
        self.model = None
        self.tokenizer = None
        self._load_model()
    
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
            return analysis
        except Exception as e:
            logger.error(f"Failed to analyze service: {e}")
            # Return empty analysis on error
            return ServiceAnalysis(
                service_name=service_info.get("product", service_info.get("service", "Unknown")),
                version=service_info.get("version", "Unknown"),
                port=service_info.get("port", 0),
                exploitation_steps=["Analysis failed - manual review required"],
                source_code_links=[],
                cves=[],
                attack_vectors=[],
                risk_level="unknown",
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
        "services": [asdict(s) if hasattr(s, '__dataclass_fields__') else s for s in scan_results]
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
