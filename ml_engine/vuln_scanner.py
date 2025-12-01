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

    def scan_with_llm(self, code_snippet):
        """
        Uses Hermes 3 LLM to scan for vulnerabilities in any language.
        """
        if not self.llm_model:
            self._load_llm()
            
        prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
Analyze the following code for security vulnerabilities. 
If you find a vulnerability, explain it and rate the severity (Low/Medium/High/Critical).
If the code is safe, say "No vulnerabilities found."

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
                max_new_tokens=256, 
                temperature=0.1,
                do_sample=True
            )
            
        analysis = self.llm_tokenizer.decode(outputs[0], skip_special_tokens=True)
        if "### Response:" in analysis:
            analysis = analysis.split("### Response:")[-1].strip()
            
        is_vulnerable = "No vulnerabilities found" not in analysis
        confidence = 0.9 if is_vulnerable else 0.1
        
        return [{
            "type": "LLM Detected Vulnerability",
            "details": analysis,
            "confidence": confidence,
            "model": "Hermes 3 8B"
        }]

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

    def scan_specialized(self, code_snippet, language="c_cpp"):
        """
        Scans code using specialized UnixCoder and GraphCodeBERT models.
        Supports C/C++, Java, PHP (since models are multi-lingual).
        """
        vulnerabilities = []
        
        # Preprocess: Remove comments
        clean_code = self._remove_comments(code_snippet)
        
        if not clean_code.strip():
            return []

        # Tokenize the CLEAN code
        tokens = self.unix_tokenizer.encode(clean_code, add_special_tokens=False)
        total_tokens = len(tokens)
        
        # Sliding window parameters
        window_size = 510 
        stride = 256
        
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

        for start_idx, end_idx, chunk_text in windows:
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
                
        return vulnerabilities

    def classify_vulnerability(self, code_snippet):
        """
        Asks the LLM to classify the vulnerability in the given snippet.
        """
        if not self.llm_model:
            self._load_llm()
            
        prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
The following code snippet has been flagged as vulnerable by a static analysis tool. 
Analyze it carefully and provide a comprehensive security assessment.

**OWASP Top 10 2021 Mapping Guide:**
- A01:2021-Broken Access Control: Missing auth checks, path traversal, insecure direct object reference
- A02:2021-Cryptographic Failures: Hardcoded keys, weak crypto, sensitive data exposure
- A03:2021-Injection: SQL/Command/LDAP injection, XSS, template injection
- A04:2021-Insecure Design: Missing security controls, flawed business logic
- A05:2021-Security Misconfiguration: Default configs, verbose errors, unnecessary features
- A06:2021-Vulnerable Components: Outdated libraries, known CVEs
- A07:2021-Authentication Failures: Weak passwords, broken session management
- A08:2021-Software and Data Integrity: Unsigned updates, insecure deserialization
- A09:2021-Logging Failures: Missing audit logs, inadequate monitoring
- A10:2021-SSRF: Server-side request forgery, unvalidated redirects

1. If it contains a security vulnerability, output a JSON object like this:
{{
    "reasoning": "Step-by-step analysis of why this is vulnerable.",
    "cwe": "CWE-ID (e.g., CWE-89)",
    "cve": "CVE-ID if known, otherwise 'N/A'",
    "owasp": "Map CWE to most appropriate OWASP category above, or 'N/A' if none fit",
    "severity": "Critical/High/Medium/Low",
    "type": "Vulnerability Name",
    "details": "Brief explanation of the issue and impact."
}}

2. If it looks like safe code, comments, or a false positive, output a JSON object like this:
{{
    "reasoning": "Analysis of why this code is safe.",
    "cwe": "Safe",
    "cve": "N/A",
    "owasp": "N/A",
    "severity": "None",
    "type": "False Positive",
    "details": "Code appears safe."
}}

Code:
```
{code_snippet[:1024]}
```

### Response:
"""
        inputs = self.llm_tokenizer(prompt, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.llm_model.generate(
                **inputs, 
                max_new_tokens=256,  # Increased to accommodate full JSON with CVE/OWASP/Severity
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
                # Ensure keys exist
                return {
                    "cwe": data.get("cwe", "Unknown"),
                    "cve": data.get("cve", "N/A"),
                    "owasp": data.get("owasp", "Unknown"),
                    "severity": data.get("severity", "Unknown"),
                    "type": data.get("type", "Unknown"),
                    "details": data.get("details", response)
                }
        except:
            pass

        # Fallback for non-JSON output (legacy behavior or hallucination)
        if "Safe" in response and len(response) < 50:
             return {
                "cwe": "Safe",
                "cve": "N/A",
                "owasp": "None",
                "severity": "None",
                "type": "False Positive"
            }
            
        # IMPROVED FALLBACK: Try to extract CWE/Type from text using Regex
        cwe_match = re.search(r'(CWE-\d+)', response, re.IGNORECASE)
        cwe_val = cwe_match.group(1).upper() if cwe_match else "Unknown"
        
        # Determine if it's a vulnerability based on keywords
        is_vuln = "safe" not in response.lower() and ("vulnerability" in response.lower() or "cwe" in response.lower())
        
        return {
            "cwe": cwe_val,
            "cve": "N/A",
            "owasp": "Unknown",
            "severity": "Unknown",
            "type": "Potential Vulnerability" if is_vuln else "Unknown",
            "details": response  # Keep full response for context
        }

    def scan_code(self, code_snippet, file_extension=None):
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
            return self.scan_specialized(code_snippet, language="c_cpp")
            
        elif self.mode == "llm":
            # Force LLM scanner
            return self.scan_with_llm(code_snippet)
            
        else: # Hybrid Mode
            if is_c_cpp:
                logger.info("Detected C/C++ code. Using specialized models.")
                return self.scan_specialized(code_snippet, language="c_cpp")
            elif file_extension and file_extension.lower() in ['.java', '.jsp']:
                logger.info("Detected Java code. Using specialized models.")
                return self.scan_specialized(code_snippet, language="java")
            elif file_extension and file_extension.lower() in ['.php']:
                logger.info("Detected PHP code. Using specialized models.")
                return self.scan_specialized(code_snippet, language="php")
            else:
                logger.info("Non-specialized code detected. Switching to LLM scanner.")
                return self.scan_with_llm(code_snippet)

if __name__ == "__main__":
    scanner = VulnScanner()
    
    # Test C++
    print("Testing C++ Scan:")
    c_code = "void func() { char buf[10]; strcpy(buf, input); }"
    print(scanner.scan_code(c_code))
    
    # Test Python (will trigger LLM load)
    # print("\nTesting Python Scan:")
    # py_code = "import os; os.system(user_input)"
    # print(scanner.scan_code(py_code))
