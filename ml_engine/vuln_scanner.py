from transformers import AutoTokenizer, AutoModelForSequenceClassification, BitsAndBytesConfig, AutoModelForCausalLM
import torch
import torch.nn.functional as F
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnScanner:
    def __init__(self, mode="hybrid", unixcoder_path="microsoft/unixcoder-base", graphcodebert_path="microsoft/graphcodebert-base", model=None, tokenizer=None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Using device: {self.device}")
        self.mode = mode

        # Initialize model placeholders
        self.unix_model = None
        self.graph_model = None
        self.llm_model = model
        self.llm_tokenizer = tokenizer

        # Load models based on mode
        if self.mode in ["hybrid", "c_cpp"]:
            self._load_specialized_models(unixcoder_path, graphcodebert_path)
        
        if self.mode == "llm" and self.llm_model is None:
            self._load_llm()

    def _load_specialized_models(self, unixcoder_path, graphcodebert_path):
        base_model_dir = os.path.join(os.path.dirname(__file__), "saved_models")
        
        # UnixCoder
        unix_path = os.path.join(base_model_dir, "unixcoder")
        if os.path.exists(unix_path) and os.path.exists(os.path.join(unix_path, "config.json")):
            logger.info(f"Found fine-tuned UnixCoder at {unix_path}. Loading...")
            self.unix_tokenizer = AutoTokenizer.from_pretrained(unix_path)
            self.unix_model = AutoModelForSequenceClassification.from_pretrained(unix_path).to(self.device)
        else:
            logger.info(f"Loading UnixCoder base from {unixcoder_path}")
            self.unix_tokenizer = AutoTokenizer.from_pretrained(unixcoder_path)
            self.unix_model = AutoModelForSequenceClassification.from_pretrained(unixcoder_path, num_labels=2).to(self.device)

        # GraphCodeBERT
        graph_path = os.path.join(base_model_dir, "graphcodebert")
        if os.path.exists(graph_path) and os.path.exists(os.path.join(graph_path, "config.json")):
             logger.info(f"Found fine-tuned GraphCodeBERT at {graph_path}. Loading...")
             self.graph_tokenizer = AutoTokenizer.from_pretrained(graph_path)
             self.graph_model = AutoModelForSequenceClassification.from_pretrained(graph_path).to(self.device)
        else:
            logger.info(f"Loading GraphCodeBERT base from {graphcodebert_path}")
            self.graph_tokenizer = AutoTokenizer.from_pretrained(graphcodebert_path)
            self.graph_model = AutoModelForSequenceClassification.from_pretrained(graphcodebert_path, num_labels=2).to(self.device)

    def _load_llm(self):
        # ... (Existing implementation) ...
        model_path = r"E:\GRAND_AI_MODELS\hermes-3-llama-3.1-8b"
        logger.info(f"Loading Hermes 3 for multi-language scanning from {model_path}...")
        
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
        
        self.llm_tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.llm_model = AutoModelForCausalLM.from_pretrained(
            model_path,
            quantization_config=quantization_config,
            device_map="auto"
        )

    def scan_with_llm(self, code_snippet, file_path="", paranoid_mode=False):
        """
        Uses Hermes 3 LLM to scan for vulnerabilities in any language.
        """
        # Framework Detection Check (Skip if not paranoid)
        if not paranoid_mode and self.is_framework_file(file_path, code_snippet):
            logger.info(f"Skipping framework/library file: {file_path}")
            return [{
                "cwe": "Safe",
                "type": "Framework File",
                "severity": "None",
                "details": "Skipped known framework/library file"
            }]

        if not self.llm_model:
            self._load_llm()
        
        # Check GPU memory before inference
        if torch.cuda.is_available():
            try:
                free_memory = torch.cuda.get_device_properties(0).total_memory - torch.cuda.memory_allocated(0)
                if free_memory < 500 * 1024 * 1024:  # Less than 500MB free
                    logger.warning(f"Low GPU memory ({free_memory / 1024**2:.0f}MB free). Clearing cache...")
                    torch.cuda.empty_cache()
            except:
                pass
            
        system_role = "Analyze the following code for security vulnerabilities."
        if paranoid_mode:
            system_role = "You are a PARANOID Security Auditor. Your goal is to find ANY potential vulnerability, no matter how small. Assume all input is malicious. Do not give the benefit of the doubt. Analyze the following code for security vulnerabilities."

        prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
{system_role} 
Provide the output in strict JSON format.

If you find a vulnerability:
{{
    "vulnerable": true,
    "severity": "High/Medium/Low",
    "type": "Vulnerability Name",
    "details": "Brief explanation"
}}

If the code is safe:
{{
    "vulnerable": false,
    "severity": "None",
    "type": "None",
    "details": "Code is safe"
}}

Code:
```
{code_snippet}
```

### Response:
"""
        inputs = self.llm_tokenizer(prompt, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.llm_model.generate(
                **inputs, 
                max_new_tokens= 2048, 
                temperature=0.1,
                do_sample=True
            )
            
        generated_text = self.llm_tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Parse JSON response
        import json
        import re
        
        analysis_text = generated_text
        if "### Response:" in generated_text:
            analysis_text = generated_text.split("### Response:")[-1].strip()
            
        # Try to find JSON block
        try:
            json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                is_vulnerable = data.get("vulnerable", False)
                details = data.get("details", analysis_text)
                severity = data.get("severity", "Unknown")
            else:
                # Fallback to text analysis
                is_vulnerable = "vulnerable" in analysis_text.lower() and "false" not in analysis_text.lower()
                details = analysis_text
                severity = "Unknown"
        except:
             is_vulnerable = "vulnerable" in analysis_text.lower()
             details = analysis_text
             severity = "Unknown"

        confidence = 0.9 if is_vulnerable else 0.1
        
        if is_vulnerable:
            return [{
                "type": "LLM Detected Vulnerability",
                "details": details,
                "severity": severity,
                "confidence": confidence,
                "model": "Hermes 3 8B"
            }]
        
        return []

        return vulnerabilities

    def _remove_comments(self, text):
        """
        Removes C-style comments (// and /* */) from the code.
        """
        import re
        def replacer(match):
            s = match.group(0)
            if s.startswith('/'):
                return " " # replace comment with space
            else:
                return s # return string literal unchanged
        
        # Regex to match comments or string literals (so we don't remove // inside strings)
        pattern = re.compile(
            r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
            re.DOTALL | re.MULTILINE
        )
        return re.sub(pattern, replacer, text)

    def is_framework_file(self, file_path: str, code_content: str = "") -> bool:
        """Detect if file is framework/library implementation"""
        file_path = file_path.lower()
        code_content = code_content.lower()
        
        FRAMEWORK_PATTERNS = [
            "arrayelresolver", "beanelresolver", "jakarta/el",
            "springframework", "apache/commons", "/test/", "/tests/",
            "mock", "stub"
        ]
        
        # Check file path
        if any(pat in file_path for pat in FRAMEWORK_PATTERNS):
            return True
            
        # Check code content for package declarations that indicate framework code
        if "package javax.el" in code_content or "package jakarta.el" in code_content:
            return True
            
        return False

    def scan_specialized(self, code_snippet, language="c_cpp", file_path=""):
        """
        Scans code using specialized UnixCoder and GraphCodeBERT models.
        Supports C/C++, Java, PHP (since models are multi-lingual).
        """
        # Framework Detection Check
        if self.is_framework_file(file_path, code_snippet):
            logger.info(f"Skipping framework/library file: {file_path}")
            return []

        vulnerabilities = []
        
        # Preprocess: Remove comments
        clean_code = self._remove_comments(code_snippet)
        
        if not clean_code.strip():
            return []

        # Tokenize the CLEAN code
        tokens = self.unix_tokenizer.encode(clean_code, add_special_tokens=False)
        total_tokens = len(tokens)
        
        # Sliding window parameters
        window_size = 1024 
        stride = 512
        
        # If file is small, just scan it once
        if total_tokens <= window_size:
            windows = [(0, total_tokens, clean_code)]
        else:
            windows = []
            for i in range(0, total_tokens, stride):
                end = min(i + window_size, total_tokens)
                chunk_tokens = tokens[i:end]
                chunk_text = self.unix_tokenizer.decode(chunk_tokens)
                windows.append((i, end, chunk_text))
                if end == total_tokens:
                    break
        
        logger.info(f"Scanning {len(windows)} windows for file ({language})...")

        # Define Dangerous Functions based on Language
        if language == "java":
            DANGEROUS_FUNCTIONS = [
                "Runtime.exec", "ProcessBuilder", "executeQuery", "eval", "ObjectInputStream",
                "FileInputStream", "Statement", "getRuntime", "loadLibrary"
            ]
        elif language == "php":
            DANGEROUS_FUNCTIONS = [
                "exec", "system", "shell_exec", "eval", "query", "passthru", 
                "popen", "proc_open", "pcntl_exec", "assert", "unserialize"
            ]
        else: # Default C/C++
            DANGEROUS_FUNCTIONS = [
                "strcpy", "strcat", "sprintf", "vsprintf", "gets", "system", "popen",
                "exec", "memcpy", "memset", "malloc", "free", "realloc", "alloca",
                "scanf", "vscanf", "fscanf"
            ]

        for window_idx, (start_idx, end_idx, chunk_text) in enumerate(windows):
            try:
                # --- UnixCoder Analysis ---
                unix_inputs = self.unix_tokenizer(chunk_text, return_tensors="pt", truncation=True, max_length=512).to(self.device)
                with torch.no_grad():
                    unix_outputs = self.unix_model(**unix_inputs)
                    unix_probs = F.softmax(unix_outputs.logits, dim=-1)
                    unix_vuln_score = unix_probs[0][1].item()

                # --- GraphCodeBERT Analysis ---
                graph_inputs = self.graph_tokenizer(chunk_text, return_tensors="pt", truncation=True, max_length=512).to(self.device)
                with torch.no_grad():
                    graph_outputs = self.graph_model(**graph_inputs)
                    graph_probs = F.softmax(graph_outputs.logits, dim=-1)
                    graph_vuln_score = graph_probs[0][1].item()

                avg_score = (unix_vuln_score + graph_vuln_score) / 2
                
                # Heuristic: If score is high but not extreme, require a dangerous keyword
                has_dangerous_func = any(func in chunk_text for func in DANGEROUS_FUNCTIONS)
                
                # Threshold logic
                is_vulnerable = False
                if avg_score > 0.85:
                    is_vulnerable = True
                elif avg_score > 0.60 and has_dangerous_func:
                    is_vulnerable = True
                
                if is_vulnerable: 
                    # DEDUPLICATION: Check if this overlaps with the last finding
                    is_duplicate = False
                    if vulnerabilities:
                        last_vuln = vulnerabilities[-1]
                        last_end = int(last_vuln['location'].split('-')[1])
                        # If current start is within the previous window, it's likely the same issue
                        if start_idx < last_end:
                            # Keep the one with higher confidence
                            if avg_score > last_vuln['confidence']:
                                vulnerabilities.pop() # Remove the weaker duplicate
                            else:
                                is_duplicate = True # Ignore this one

                    if not is_duplicate:
                        vulnerabilities.append({
                            "type": "Potential Vulnerability (ML Detected)",
                            "details": f"Models detected high probability of vulnerability in code segment.\nUnixCoder: {unix_vuln_score:.2f}\nGraphCodeBERT: {graph_vuln_score:.2f}",
                            "confidence": avg_score,
                            "model_consensus": "High" if (unix_vuln_score > 0.8 and graph_vuln_score > 0.8) else "Mixed",
                            "classification": None, 
                            "location": f"Token Offset {start_idx}-{end_idx}",
                            "vulnerable_chunk": chunk_text # Store the text for the LLM
                        })
                
                # MEMORY MANAGEMENT: Clear cache every 10 windows
                if (window_idx + 1) % 10 == 0:
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                        
            except (RuntimeError, torch.cuda.OutOfMemoryError) as e:
                if "out of memory" in str(e).lower():
                    logger.error(f"CUDA OOM at window {window_idx}. Clearing cache and continuing...")
                    torch.cuda.empty_cache()
                    import gc
                    gc.collect()
                    # Skip this window and continue
                    continue
                else:
                    raise
                
        return vulnerabilities

    def classify_vulnerability(self, code_snippet, paranoid_mode=False):
        """
        Asks the LLM to classify the vulnerability in the given snippet.
        """
        if not self.llm_model:
            self._load_llm()
            
        system_role = "You are a Security Analyst."
        if paranoid_mode:
            system_role = "You are a PARANOID Security Auditor. Your goal is to find ANY potential vulnerability, no matter how small. Assume all input is malicious. Do not give the benefit of the doubt."

        prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
{system_role} Analyze the provided code snippet for security vulnerabilities.

**ANALYSIS FRAMEWORK:**
1. **Code Comprehension**: Understand what the code does and where user input enters.
2. **Vulnerability Check**: Check for patterns like SQL Injection, XSS, Command Injection, Path Traversal, etc.
3. **False Positive Check**: Is this test code? Is the input sanitized? Is the dangerous function actually reachable?
4. **Classification**: If vulnerable, identify the specific CWE.
5. **Owasp Check**: Is this a known OWASP Top 10 issue? If so, provide the specific category.
6. **Severity Check**: Assign a severity level based on the vulnerability.
7. **Details Check**: Provide a brief explanation of the vulnerability and how to exploit it.

**OUTPUT FORMAT (JSON ONLY):**
If VULNERABLE:
{{
    "reasoning": "Multi-step analysis: (1) What the code does, (2) Where input enters, (3) Why it's vulnerable, (4) How to exploit",
    "cwe": "CWE-XXX (SPECIFIC, e.g., CWE-917 for EL Injection, NOT CWE-74)",
    "cve": "CVE-YYYY-XXXXX if known, otherwise 'N/A'",
    "owasp": "A##:2021-Category"or any other owasp that matches,
    "severity": "Critical/High/Medium/Low",
    "type": "SPECIFIC Vulnerability Name (e.g., 'EL Injection', 'SQL Injection', NOT 'Injection')",
    "details": "Brief explanation of exploit path and impact (2-3 sentences)"
}}

If SAFE:
{{
    "vulnerable": false,
    "type": "Safe",
    "cwe": "Safe",
    "severity": "None",
    
}}

**CODE TO ANALYZE:**
```
{code_snippet[:20000]}
```

### Response:
"""
        inputs = self.llm_tokenizer(prompt, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.llm_model.generate(
                **inputs, 
                max_new_tokens=2024,  # Increased to accommodate full JSON with CVE/OWASP/Severity
                temperature=0.1,
                do_sample=False
            )
            
        response = self.llm_tokenizer.decode(outputs[0], skip_special_tokens=True)
        if "### Response:" in response:
            response = response.split("### Response:")[-1].strip()
        
        # SANITIZE: Ensure UTF-8 compatibility by replacing problematic characters
        # Replace Windows-1252 smart quotes and other non-UTF-8 chars
        response = response.encode('utf-8', errors='ignore').decode('utf-8')
        response = response.replace('\x91', "'").replace('\x92', "'")  # Smart single quotes
        response = response.replace('\x93', '"').replace('\x94', '"')  # Smart double quotes
        response = response.replace('\x96', '-').replace('\x97', '-')  # Em/en dashes
            
        # DEBUG: Log raw response to understand why it's failing
        logger.info(f"RAW LLM RESPONSE for snippet: {response[:200]}...")
            
        # Basic parsing (LLM might not always output perfect JSON, so we fallback)
        import json
        import re
        
        # Try to find JSON block first
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                
                # ============================================================
                # UNIVERSAL VULNERABILITY DETECTION SYSTEM
                # Post-processing to ensure accurate classification
                # ============================================================
                
                # Define vulnerability patterns with keywords, CWE, and severity
                # Define vulnerability patterns with keywords, CWE, and severity
                # REFINED: Removed generic keywords to prevent false positives
                VULN_PATTERNS = {
                    "EL Injection": {
                        "keywords": ["createValueExpression", "ELProcessor", "ExpressionFactory"],
                        "cwe": "CWE-917",
                        "severity": "High",
                        "owasp": "A03:2021-Injection"
                    },
                    "SQL Injection": {
                        "keywords": ["executeQuery", "executeUpdate", "Statement.execute"],
                        "anti_keywords": ["PreparedStatement", "setString", "setInt"], 
                        "cwe": "CWE-89",
                        "severity": "Critical",
                        "owasp": "A03:2021-Injection"
                    },
                    "XSS": {
                        "keywords": ["innerHTML", "document.write", "response.getWriter().print"],
                        "cwe": "CWE-79",
                        "severity": "High",
                        "owasp": "A03:2021-Injection"
                    },
                    "Path Traversal": {
                        "keywords": ["../../", "..\\", "rootPath", "basePath"], # Stricter keywords
                        "cwe": "CWE-22",
                        "severity": "High",
                        "owasp": "A01:2021-Broken Access Control"
                    },
                    "Deserialization": {
                        "keywords": ["readObject", "XMLDecoder", "unserialize"],
                        "cwe": "CWE-502",
                        "severity": "Critical",
                        "owasp": "A08:2021-Software and Data Integrity Failures"
                    },
                    "Command Injection": {
                        "keywords": ["Runtime.exec", "ProcessBuilder", "shell_exec", "system("],
                        "cwe": "CWE-78",
                        "severity": "Critical",
                        "owasp": "A03:2021-Injection"
                    },
                    "XXE": {
                        "keywords": ["setFeature", "XMLInputFactory", "!ENTITY"],
                        "cwe": "CWE-611",
                        "severity": "High",
                        "owasp": "A05:2021-Security Misconfiguration"
                    },
                    "SSRF": {
                        "keywords": ["openConnection", "HttpClient", "169.254.169.254"],
                        "cwe": "CWE-918",
                        "severity": "High",
                        "owasp": "A10:2021-Server-Side Request Forgery"
                    }
                }
                
                # Check each pattern
                detected_vuln = None
                for vuln_type, pattern in VULN_PATTERNS.items():
                    # Check if all keywords are present
                    keywords_found = any(kw in code_snippet for kw in pattern["keywords"])
                    
                    # Check anti-keywords (for SQL Injection)
                    anti_keywords_found = False
                    if "anti_keywords" in pattern:
                        anti_keywords_found = any(kw in code_snippet for kw in pattern["anti_keywords"])
                    
                    if keywords_found and not anti_keywords_found:
                        # Only override if LLM was unsure or missed it, OR if it's a critical pattern
                        # But if LLM explicitly said "Safe" with reasoning, we should be careful.
                        # For now, we'll treat these as "Strong Indicators" but allow LLM to provide details.
                        detected_vuln = {
                            "type": vuln_type,
                            "cwe": pattern["cwe"],
                            "severity": pattern["severity"],
                            "owasp": pattern["owasp"]
                        }
                        logger.info(f"{vuln_type} keywords detected - potential vulnerability")
                        break
                
                # Logic: 
                # 1. If LLM says Vulnerable, trust LLM (it has reasoning).
                # 2. If LLM says Safe/Unknown BUT we found Strong Keywords, override to Vulnerable (Safety Net).
                # 3. If LLM says Safe and No Keywords, return Safe.
                
                llm_is_vuln = data.get("vulnerable", False) or "vulnerable" in str(data).lower()
                
                if detected_vuln and not llm_is_vuln:
                    logger.info(f"LLM missed {detected_vuln['type']} but keywords found. Overriding.")
                    return [{
                        "cwe": detected_vuln["cwe"],
                        "cve": data.get("cve", "N/A"),
                        "owasp": detected_vuln["owasp"],
                        "severity": detected_vuln["severity"],
                        "type": detected_vuln["type"],
                        "details": f"{detected_vuln['type']} detected via keyword analysis (LLM missed it). Verify manually."
                    }]
                
                # If LLM detected it, ensure classification matches keywords if present
                if llm_is_vuln and detected_vuln:
                     if data.get("cwe") == "Unknown" or data.get("cwe") == "CWE-74":
                         data["cwe"] = detected_vuln["cwe"]
                         data["type"] = detected_vuln["type"]
                
                # Otherwise, return LLM classification
                return [{
                    "cwe": data.get("cwe", "Unknown"),
                    "cve": data.get("cve", "N/A"),
                    "owasp": data.get("owasp", "Unknown"),
                    "severity": data.get("severity", "Unknown"),
                    "type": data.get("type", "Unknown"),
                    "details": data.get("details", response)
                }]
        except:
            pass

        # Fallback for non-JSON output (legacy behavior or hallucination)
        if "Safe" in response and len(response) < 50:
             return [{
                "cwe": "Safe",
                "cve": "N/A",
                "owasp": "None",
                "severity": "None",
                "type": "False Positive"
            }]
            
        # IMPROVED FALLBACK: Try to extract CWE/Type from text using Regex
        cwe_match = re.search(r'(CWE-\d+)', response, re.IGNORECASE)
        cwe_val = cwe_match.group(1).upper() if cwe_match else "Unknown"
        
        # Determine if it's a vulnerability based on keywords
        is_vuln = "safe" not in response.lower() and ("vulnerability" in response.lower() or "cwe" in response.lower())
        
        return [{
            "cwe": cwe_val,
            "cve": "N/A",
            "owasp": "Unknown",
            "severity": "Unknown",
            "type": "Potential Vulnerability" if is_vuln else "Unknown",
            "details": response  # Keep full response for context
        }]

    def scan_code(self, code_snippet, file_extension=None, file_path="", paranoid_mode=False):
        """
        Main dispatch method. Detects language and chooses the best scanner.
        """
        is_c_cpp = False
        
        # 1. Check Extension Hint
        if file_extension:
            if file_extension.lower() in ['.c', '.cpp', '.h', '.hpp', '.cc']:
                is_c_cpp = True
        
        # 2. Fallback to Heuristic if no extension or ambiguous
        if not is_c_cpp:
            is_c_cpp = "#include" in code_snippet or "int main" in code_snippet or "void *" in code_snippet
        
        # Dispatch based on Mode and Language
        if self.mode == "c_cpp":
            # Force C/C++ scanner (user explicitly requested this mode)
            return self.scan_specialized(code_snippet, language="c_cpp", file_path=file_path)
            
        elif self.mode == "llm":
            # Force LLM scanner
            return self.scan_with_llm(code_snippet, file_path=file_path, paranoid_mode=paranoid_mode)
            
        else: # Hybrid Mode
            if is_c_cpp:
                logger.info("Detected C/C++ code. Using specialized models.")
                return self.scan_specialized(code_snippet, language="c_cpp", file_path=file_path)
            elif file_extension and file_extension.lower() in ['.java', '.jsp']:
                logger.info("Detected Java code. Using specialized models.")
                return self.scan_specialized(code_snippet, language="java", file_path=file_path)
            elif file_extension and file_extension.lower() in ['.php']:
                logger.info("Detected PHP code. Using specialized models.")
                return self.scan_specialized(code_snippet, language="php", file_path=file_path)
            else:
                logger.info("Non-specialized code detected. Switching to LLM scanner.")
                return self.scan_with_llm(code_snippet, file_path=file_path, paranoid_mode=paranoid_mode)

if __name__ == "__main__":
    scanner = VulnScanner(mode="llm")
    
    print("\n--- TEST 1: Safe Code (Should be Safe) ---")
    safe_code = """
    public void readFile(String filename) {
        File file = new File("safe_dir/" + filename); // 'File' keyword present but safe usage
        if (!file.getCanonicalPath().startsWith("safe_dir")) return;
        // ...
    }
    """
    result = scanner.scan_code(safe_code, ".java")
    print("RESULT:", result if result else "SAFE (Correct)")

    print("\n--- TEST 2: Command Injection (Should be Vulnerable) ---")
    cmd_code = """
    String cmd = request.getParameter("cmd");
    Runtime.getRuntime().exec(cmd); // Dangerous keyword present
    """
    result = scanner.scan_code(cmd_code, ".java")
    print("RESULT:", result if result else "SAFE (Incorrect)")

    print("\n--- TEST 3: EL Injection (Should be Vulnerable) ---")
    el_code = """
    ExpressionFactory factory = ExpressionFactory.newInstance();
    ValueExpression ve = factory.createValueExpression(context, input, String.class); // Dangerous
    """
    result = scanner.scan_code(el_code, ".java")
    print("RESULT:", result if result else "SAFE (Incorrect)")
