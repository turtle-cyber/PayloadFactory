"""
File Prioritizer Module
========================
Intelligently ranks files based on security criticality for optimized scanning.

Design Philosophy:
- Security-critical files should be scanned first (auth, admin, core business logic)
- Test files, examples, and documentation should be deprioritized
- Configurable scoring system allows customization per project
- Fast execution (pre-filtering should add minimal overhead)

Scoring Algorithm:
- Directory importance: 0-30 points
- Filename patterns: 0-25 points
- Content keywords: 0-30 points
- File size penalty: 0-15 points deduction
- Total score: 0-100 range
"""

import os
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)

class FilePrioritizer:
    """
    Intelligent file ranking system for security-focused code scanning.
    
    Deep Thinking Rationale:
    - We need fast pre-filtering (can't read full content of 3000+ files)
    - Directory structure often indicates code purpose (naming conventions)
    - Security keywords in filenames are strong indicators
    - First 1000 chars of file are usually enough for keyword detection
    - Very large files (>50KB) are often generated/vendor code
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize prioritizer with optional configuration.
        
        Args:
            config: Optional configuration dict. If None, uses sensible defaults.
        
        Deep Thinking:
        - Defaults should work for Java/C/C++ enterprise apps (most common)
        - Config allows override for different project structures
        - Validation ensures bad config doesn't crash the system
        """
        self.config = config or self._get_default_config()
        self._validate_config()
        
    def _get_default_config(self) -> Dict:
        """
        Provides sensible default configuration.
        
        Deep Thinking:
        - High-priority dirs: Where security code typically lives
        - Excluded dirs: Test/demo code rarely has exploitable vulns in production
        - Keywords: Functions/classes that handle security boundaries
        - Size threshold: 50KB balances coverage vs likely generated code
        """
        return {
            "max_files": 300,  # Reasonable scan scope for 2-hour target
            
            # Directory scoring (30 points max)
            "high_priority_dirs": [
                "security", "auth", "authentication", "authorization", 
                "admin", "core", "crypto", "cryptography", "session",
                "login", "permission", "access", "policy"
            ],
            "medium_priority_dirs": [
                "api", "servlet", "filter", "controller", "service",
                "handler", "processor", "manager", "util", "utils"
            ],
            "excluded_dirs": [
                "test", "tests", "testing", "mock", "mocks", "demo", 
                "demos", "example", "examples", "sample", "samples",
                "bench", "benchmark", "benchmarks", "legacy", "deprecated",
                "doc", "docs", "documentation", "resources", "build", "dist"
            ],
            
            # Filename pattern scoring (25 points max)
            "high_priority_patterns": [
                "security", "auth", "admin", "login", "session", 
                "credential", "password", "token", "crypto", "encrypt",
                "permission", "access", "policy", "privilege"
            ],
            "excluded_patterns": [
                "test", "mock", "spec", "fixture", "sample", "demo",
                "example", "benchmark"
            ],
            
            # Content keyword scoring (30 points max)
            # Deep Thinking: These are functions/classes that cross security boundaries
            "dangerous_keywords": {
                # Command injection vectors
                "Runtime.exec": 5, "ProcessBuilder": 5, "Runtime.getRuntime": 4,
                "system(": 4, "popen": 4, "exec(": 3,
                
                # SQL injection vectors
                "executeQuery": 4, "createStatement": 4, "executeUpdate": 4,
                "Statement.execute": 4, "query(": 3,
                
                # Deserialization
                "ObjectInputStream": 5, "readObject": 4, "XMLDecoder": 4,
                "deserialize": 4, "unserialize": 4,
                
                # File operations (path traversal)
                "FileInputStream": 3, "FileReader": 3, "getResource": 3,
                
                # Expression language injection
                "ELProcessor": 5, "createValueExpression": 5, "ELResolver": 4,
                "ExpressionFactory": 4, "ValueExpression": 4,
                
                # Authentication/session
                "createSession": 3, "getSession": 2, "authenticate": 3,
                "login": 2, "credential": 3, "password": 2,
                
                # XML processing (XXE)
                "DocumentBuilder": 3, "SAXParser": 3, "XMLReader": 3,
                
                # Network (SSRF)
                "URLConnection": 3, "HttpURLConnection": 3, "openConnection": 3,
                
                # Crypto (weak crypto)
                "MessageDigest": 2, "Cipher": 2, "KeyGenerator": 2
            },
            
            # File size considerations
            "max_file_size_kb": 50,  # Files larger than this get penalized
            "huge_file_threshold_kb": 100,  # Files this large are likely generated
            
            # Content preview for keyword detection
            "preview_bytes": 2000  # Read first 2KB for keyword matching
        }
    
    def _validate_config(self):
        """
        Validates configuration to prevent runtime errors.
        
        Deep Thinking:
        - Bad config can cause silent failures or wrong results
        - Better to fail fast with clear error message
        - Validation overhead is negligible (runs once at init)
        """
        required_keys = [
            "max_files", "high_priority_dirs", "medium_priority_dirs",
            "excluded_dirs", "dangerous_keywords"
        ]
        
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"Missing required config key: {key}")
        
        if self.config["max_files"] <= 0:
            raise ValueError("max_files must be positive")
            
        if not isinstance(self.config["dangerous_keywords"], dict):
            raise ValueError("dangerous_keywords must be a dict mapping keywords to scores")
    
    def prioritize_files(self, file_paths: List[str]) -> List[Tuple[str, float]]:
        """
        Ranks files by security priority and returns top N.
        
        Args:
            file_paths: List of absolute file paths to rank
            
        Returns:
            List of (file_path, score) tuples, sorted by score (highest first),
            limited to max_files from config
            
        Deep Thinking:
        - We iterate once through all files (O(n))
        - Sorting is O(n log n) but n is already filtered to reasonable size
        - Reading file previews is I/O bound but we only read first 2KB
        - Total overhead should be <30 seconds for 3000 files
        """
        logger.info(f"Prioritizing {len(file_paths)} files...")
        
        scored_files = []
        
        for file_path in file_paths:
            try:
                # Skip if in excluded directory (fast path)
                if self._is_excluded_directory(file_path):
                    continue
                
                # Calculate priority score
                score = self._calculate_score(file_path)
                
                # Only include files with non-zero score
                if score > 0:
                    scored_files.append((file_path, score))
                    
            except Exception as e:
                logger.debug(f"Error scoring {file_path}: {e}")
                # Don't let one bad file break the whole process
                continue
        
        # Sort by score (highest first)
        scored_files.sort(key=lambda x: x[1], reverse=True)
        
        # Limit to max_files
        max_files = self.config["max_files"]
        top_files = scored_files[:max_files]
        
        
        logger.info(f"Selected top {len(top_files)} files out of {len(scored_files)} scored files")
        if top_files:  # Only show score range if we have results
            logger.info(f"Score range: {top_files[0][1]:.1f} (highest) to {top_files[-1][1]:.1f} (lowest)")
        
        return top_files
    
    def _is_excluded_directory(self, file_path: str) -> bool:
        """
        Fast check if file is in excluded directory.
        
        Deep Thinking:
        - This is called for EVERY file, so must be fast
        - Case-insensitive matching (Windows/Linux compatibility)
        - Path separator normalization
        """
        path_lower = file_path.lower().replace('\\', '/')
        path_parts = path_lower.split('/')
        
        excluded_dirs = [d.lower() for d in self.config["excluded_dirs"]]
        
        # Check if any path component matches excluded dirs
        return any(part in excluded_dirs for part in path_parts)
    
    def _calculate_score(self, file_path: str) -> float:
        """
        Calculates priority score for a single file.
        
        Returns:
            Score between 0-100 (higher = more important)
            
        Deep Thinking:
        - Scoring is additive: multiple indicators = higher confidence
        - Components are weighted by reliability:
          * Directory structure: 30 points (reliable, fast)
          * Filename patterns: 25 points (good signal, fast)
          * Content keywords: 30 points (best signal, slower)
          * Size penalty: -15 points (large files usually generated)
        - Total max: 85 points (100 - 15 penalty)
        """
        score = 0.0
        
        # Component 1: Directory scoring (0-30 points)
        score += self._score_directory(file_path)
        
        # Component 2: Filename scoring (0-25 points)
        score += self._score_filename(file_path)
        
        # Component 3: Content keyword scoring (0-30 points)
        score += self._score_content(file_path)
        
        # Component 4: Size penalty (0 to -15 points)
        score += self._score_file_size(file_path)
        
        # Ensure non-negative
        return max(0.0, score)
    
    def _score_directory(self, file_path: str) -> float:
        """
        Scores based on directory structure.
        
        Deep Thinking:
        - High-priority dirs get 30 points (strong signal)
        - Medium-priority dirs get 15 points (moderate signal)
        - Default is 5 points (at least it's source code)
        - Multiple matches don't stack (take maximum)
        """
        path_lower = file_path.lower().replace('\\', '/')
        path_parts = path_lower.split('/')
        
        # Check high priority
        high_priority = [d.lower() for d in self.config["high_priority_dirs"]]
        if any(part in high_priority for part in path_parts):
            return 30.0
        
        # Check medium priority
        medium_priority = [d.lower() for d in self.config["medium_priority_dirs"]]
        if any(part in medium_priority for part in path_parts):
            return 15.0
        
        # Default: it's at least source code
        return 5.0
    
    def _score_filename(self, file_path: str) -> float:
        """
        Scores based on filename patterns.
        
        Deep Thinking:
        - Filenames like "AuthenticationFilter.java" are strong signals
        - Multiple pattern matches are additive (up to 25 points max)
        - Case-insensitive matching for robustness
        """
        filename = os.path.basename(file_path).lower()
        score = 0.0
        
        # Check high priority patterns
        high_patterns = [p.lower() for p in self.config["high_priority_patterns"]]
        for pattern in high_patterns:
            if pattern in filename:
                score += 5.0  # Each match adds 5 points
        
        # Check excluded patterns (override to 0)
        excluded_patterns = [p.lower() for p in self.config["excluded_patterns"]]
        for pattern in excluded_patterns:
            if pattern in filename:
                return 0.0  # Explicitly excluded
        
        # Cap at 25 points
        return min(score, 25.0)
    
    def _score_content(self, file_path: str) -> float:
        """
        Scores based on dangerous keywords in file content.
        
        Deep Thinking:
        - Reading full files is expensive (3000+ files × avg 20KB = 60MB+)
        - First 2KB usually contains imports and class declarations
        - Dangerous keywords in imports/early code = high likelihood of usage
        - Multiple keywords are additive (more signals = higher confidence)
        """
        score = 0.0
        
        try:
            # Read preview only (first 2KB)
            preview_size = self.config.get("preview_bytes", 2000)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content_preview = f.read(preview_size)
            
            # Check for dangerous keywords
            for keyword, keyword_score in self.config["dangerous_keywords"].items():
                if keyword in content_preview:
                    score += keyword_score
            
            # Cap at 30 points
            return min(score, 30.0)
            
        except Exception as e:
            logger.debug(f"Error reading {file_path}: {e}")
            return 0.0  # Can't read = skip it
    
    def _score_file_size(self, file_path: str) -> float:
        """
        Applies penalty for very large files.
        
        Deep Thinking:
        - Large files (>50KB) are often:
          * Auto-generated code
          * Vendor libraries (copied into project)
          * Test fixtures with large data
        - Huge files (>100KB) are almost never manually written
        - Penalty is progressive: larger = more penalty
        - Returns negative value (penalty)
        """
        try:
            size_kb = os.path.getsize(file_path) / 1024.0
            
            max_size = self.config.get("max_file_size_kb", 50)
            huge_threshold = self.config.get("huge_file_threshold_kb", 100)
            
            if size_kb > huge_threshold:
                # Huge files: -15 points (strong penalty)
                return -15.0
            elif size_kb > max_size:
                # Large files: -5 to -15 points (progressive penalty)
                excess = size_kb - max_size
                penalty_range = huge_threshold - max_size
                penalty = -5.0 - (excess / penalty_range) * 10.0
                return max(penalty, -15.0)
            else:
                # Normal size: no penalty
                return 0.0
                
        except Exception as e:
            logger.debug(f"Error getting size for {file_path}: {e}")
            return 0.0


if __name__ == "__main__":
    # Quick self-test
    logging.basicConfig(level=logging.INFO)
    
    prioritizer = FilePrioritizer()
    
    # Test files
    test_files = [
        "C:/project/src/main/java/com/example/security/AuthenticationFilter.java",
        "C:/project/src/main/java/com/example/util/StringUtils.java",
        "C:/project/src/test/java/com/example/security/AuthenticationFilterTest.java",
        "C:/project/src/main/java/com/example/admin/UserManager.java",
    ]
    
    results = prioritizer.prioritize_files(test_files)
    
    print("\nPrioritization Results:")
    for path, score in results:
        print(f"{score:5.1f} - {os.path.basename(path)}")
