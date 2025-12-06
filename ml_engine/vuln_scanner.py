from transformers import AutoTokenizer, AutoModelForSequenceClassification, BitsAndBytesConfig, AutoModelForCausalLM
import torch
import torch.nn.functional as F
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnScanner:
    def __init__(self, mode="hybrid", unixcoder_path="microsoft/unixcoder-base", graphcodebert_path="microsoft/graphcodebert-base", model=None, tokenizer=None, model_id=None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Using device: {self.device}")
        self.mode = mode
        
        # Model selection
        from ml_engine.model_config import DEFAULT_MODEL
        self.model_id = model_id if model_id else DEFAULT_MODEL

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
        """Load LLM based on model_id from config registry with optional LoRA adapter."""
        from ml_engine.model_config import get_model_config
        import os
        
        config = get_model_config(self.model_id)
        model_path = config["base_path"]
        adapter_path = config.get("adapter_path_full")
        
        logger.info(f"Loading {config['name']} for multi-language scanning from {model_path}...")
        
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
        
        self.llm_tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        self.llm_model = AutoModelForCausalLM.from_pretrained(
            model_path,
            quantization_config=quantization_config,
            device_map="auto",
            trust_remote_code=True
        )
        
        # Apply LoRA adapter if specified
        if adapter_path and os.path.exists(adapter_path):
            logger.info(f"Applying LoRA adapter from {adapter_path}...")
            from peft import PeftModel
            self.llm_model = PeftModel.from_pretrained(self.llm_model, adapter_path)
            logger.info("LoRA adapter loaded successfully.")
        elif adapter_path:
            logger.warning(f"Adapter path specified but not found: {adapter_path}")

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

    def _get_llm_exploit_details(self, code_snippet: str, vuln_type: str) -> str:
        """
        Ask LLM for exploit details ONLY (not for CVE/CWE classification).
        Used when we have a verified pattern match and just want more context.
        """
        if not self.llm_model:
            return None
            
        prompt = f"""Below is an instruction. Write a response that completes the request.

### Instruction:
A {vuln_type} vulnerability was detected in the following code.
Provide a brief 2-3 sentence explanation of:
1. How this vulnerability can be exploited
2. What the impact would be

Code:
```
{code_snippet[:5000]}
```

### Response:
"""
        try:
            inputs = self.llm_tokenizer(prompt, return_tensors="pt").to(self.device)
            with torch.no_grad():
                outputs = self.llm_model.generate(
                    **inputs,
                    max_new_tokens=256,
                    temperature=0.1,
                    do_sample=False
                )
            response = self.llm_tokenizer.decode(outputs[0], skip_special_tokens=True)
            if "### Response:" in response:
                response = response.split("### Response:")[-1].strip()
            return response[:500]  # Limit length
        except Exception as e:
            logger.debug(f"Failed to get LLM details: {e}")
            return None

    def classify_vulnerability(self, code_snippet, paranoid_mode=False):
        """
        Classifies vulnerability using PATTERN-FIRST approach.
        
        1. First, try pattern-based classification (100% accurate CVE/CWE)
        2. If pattern matches, use verified CVE/CWE from database
        3. Only use LLM for generating exploit details/explanation
        4. If no pattern matches, fall back to LLM (but mark as "unverified")
        """
        from ml_engine.cve_database import classify_by_pattern
        
        # =====================================================================
        # STEP 1: Pattern-Based Classification (Preferred - 100% Accurate)
        # =====================================================================
        pattern_result = classify_by_pattern(code_snippet)
        
        if pattern_result:
            logger.info(f"[PATTERN] Verified classification: {pattern_result['type']} ({pattern_result['cwe']})")
            
            # Use verified CVE/CWE from pattern database
            # Optionally ask LLM for exploit details only
            details = f"{pattern_result['type']} detected. {pattern_result.get('exploit_hints', '')}"
            
            # If we want LLM to add more context (optional, can skip for speed)
            if self.llm_model and not paranoid_mode:
                try:
                    llm_details = self._get_llm_exploit_details(code_snippet, pattern_result['type'])
                    if llm_details:
                        details = llm_details
                except:
                    pass  # Use pattern-based details if LLM fails
            
            return [{
                "cwe": pattern_result["cwe"],
                "cve": "N/A",  # We don't guess CVE - only verified from version detection
                "owasp": pattern_result["owasp"],
                "severity": pattern_result["severity"],
                "type": pattern_result["type"],
                "details": details,
                "confidence": "high",
                "source": "pattern_database"
            }]
        
        # =====================================================================
        # STEP 2: No Pattern Match - Use LLM as Fallback (Mark as "unverified")
        # =====================================================================
        logger.info("[PATTERN] No pattern match - falling back to LLM classification")
        
        if not self.llm_model:
            self._load_llm()
            
        system_role = "You are a Security Analyst."
        if paranoid_mode:
            system_role = "You are a PARANOID Security Auditor. Your goal is to find ANY potential vulnerability, no matter how small."

        # Simplified prompt - just ask for vulnerability type and details, NOT CVE
        prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
{system_role} Analyze the provided code snippet for security vulnerabilities.

**OUTPUT FORMAT (JSON ONLY):**
If VULNERABLE:
{{
    "vulnerable": true,
    "type": "Vulnerability Name (e.g., 'EL Injection', 'SQL Injection')",
    "severity": "Critical/High/Medium/Low",
    "details": "Brief explanation of the vulnerability and how to exploit it"
}}

If SAFE:
{{
    "vulnerable": false,
    "type": "Safe"
}}

**CODE TO ANALYZE:**
```
{code_snippet[:15000]}
```

### Response:
"""
        inputs = self.llm_tokenizer(prompt, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.llm_model.generate(
                **inputs, 
                max_new_tokens=1024,  # Reduced since we don't need CVE/OWASP
                temperature=0.1,
                do_sample=False
            )
            
        response = self.llm_tokenizer.decode(outputs[0], skip_special_tokens=True)
        if "### Response:" in response:
            response = response.split("### Response:")[-1].strip()
        
        # SANITIZE: Ensure UTF-8 compatibility
        response = response.encode('utf-8', errors='ignore').decode('utf-8')
        response = response.replace('\x91', "'").replace('\x92', "'")
        response = response.replace('\x93', '"').replace('\x94', '"')
        response = response.replace('\x96', '-').replace('\x97', '-')
            
        logger.info(f"[LLM FALLBACK] Response: {response[:200]}...")
            
        import json
        import re
        
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                
                is_vulnerable = data.get("vulnerable", True)  # Default to vulnerable if not specified
                
                if is_vulnerable and data.get("type", "").lower() != "safe":
                    # LLM detected vulnerability but we don't trust its CVE/CWE
                    # Mark as "unverified" so user knows this is LLM-guessed
                    return [{
                        "cwe": "Unverified",  # Don't trust LLM CVE/CWE guessing
                        "cve": "N/A",
                        "owasp": "Unknown",
                        "severity": data.get("severity", "Medium"),
                        "type": data.get("type", "Potential Vulnerability"),
                        "details": data.get("details", response),
                        "confidence": "low",  # Low confidence for LLM-only classification
                        "source": "llm_fallback"
                    }]
                else:
                    # LLM says safe
                    return [{
                        "cwe": "Safe",
                        "cve": "N/A",
                        "owasp": "None",
                        "severity": "None",
                        "type": "Safe",
                        "confidence": "medium",
                        "source": "llm"
                    }]
        except Exception as e:
            logger.warning(f"Failed to parse LLM response: {e}")

        # Fallback for non-JSON output
        if "Safe" in response and len(response) < 100:
             return [{
                "cwe": "Safe",
                "cve": "N/A",
                "owasp": "None",
                "severity": "None",
                "type": "Safe"
            }]
        
        # Can't determine - mark as potential issue
        return [{
            "cwe": "Unverified",
            "cve": "N/A",
            "owasp": "Unknown",
            "severity": "Unknown",
            "type": "Potential Vulnerability (LLM Unparseable)",
            "details": response[:500],
            "confidence": "low",
            "source": "llm_fallback"
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
