"""
CVE Database - Maps software versions to known CVEs
Supports version-based vulnerability detection for penetration testing demos
"""
import re
import logging
from packaging import version

logger = logging.getLogger(__name__)

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
                    "exploit_notes": "RCE via race condition when default servlet write enabled on case-insensitive filesystem"
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
                # Return all CVEs if version unknown (conservative approach)
                matching_cves.append(cve)
                continue

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
