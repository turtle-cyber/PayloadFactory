import time
import requests
import socket
import platform
import os
import json
import argparse
import threading

# Try to import psutil for resource monitoring
try:
    import psutil
except ImportError:
    psutil = None

# Configuration
DEFAULT_SERVER_URL = "http://localhost:8000/agent/logs"

# System logs
SYSTEM_LOG_FILES = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/dmesg",
    "/var/log/kern.log"
]

# Tomcat-specific logs (covers common installation paths)
TOMCAT_LOG_FILES = [
    # Default Tomcat installation
    "/opt/tomcat/logs/catalina.out",
    "/opt/tomcat/logs/localhost_access_log*.txt",
    "/opt/tomcat/logs/localhost.*.log",
    # Ubuntu/Debian package install
    "/var/log/tomcat*/catalina.out",
    "/var/log/tomcat*/localhost_access_log*.txt",
    # Generic Catalina paths
    "/var/lib/tomcat*/logs/catalina.out",
    # Docker/Custom
    "/logs/catalina.out",
    "/app/logs/catalina.out",
]

# Combine all log files
DEFAULT_LOG_FILES = SYSTEM_LOG_FILES

# ============================================================
# FUZZING-SPECIFIC KEYWORDS (High Priority)
# ============================================================
# These indicate potential vulnerabilities found by fuzzer
FUZZING_KEYWORDS = [
    # Crashes and Memory Issues
    "segfault", "segmentation fault", "core dumped", "sigsegv",
    "sigabrt", "sigill", "sigbus", "sigfpe", "sigtrap",
    "stack overflow", "buffer overflow", "heap overflow",
    "use after free", "double free", "memory leak",
    "out of memory", "oom",

    # Java/Tomcat Specific
    "outofmemoryerror", "stackoverflowerror", "nullpointerexception",
    "illegalargumentexception", "securityexception",
    "java.lang.error", "java.lang.exception",
    "catalina.core", "tomcat",

    # RCE Indicators
    "command execution", "exec", "/bin/", "/usr/bin/",
    "uid=", "gid=", "whoami", "id:",

    # DoS Indicators
    "too many open files", "connection refused", "resource temporarily unavailable",
    "service unavailable", "timeout", "hang", "unresponsive",

    # Path Traversal
    "directory traversal", "../", "..\\", "web-inf", "etc/passwd",

    # Authentication Issues
    "authentication failed", "authorization failed", "access denied",
    "permission denied", "unauthorized",

    # SQL/Command Injection
    "sql syntax", "mysql", "postgresql", "syntax error near",

    # Critical System Events
    "kernel panic", "oops", "bug:", "warn_on"
]

# Generic Error Keywords (Low Priority - Only send if fuzzing keywords not found)
GENERIC_ERRORS = ["error", "fail", "exception", "critical"]

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "os": platform.system(),
        "release": platform.release()
    }

def categorize_log(line, matched_keyword):
    """Categorize log entry for fuzzer"""
    line_lower = line.lower()

    # Crash categories
    if any(k in line_lower for k in ["segfault", "sigsegv", "core dumped", "sigabrt"]):
        return "CRASH"

    # Memory issues
    if any(k in line_lower for k in ["out of memory", "oom", "buffer overflow", "heap overflow", "use after free"]):
        return "MEMORY_ERROR"

    # DoS indicators
    if any(k in line_lower for k in ["timeout", "hang", "too many", "service unavailable", "unresponsive"]):
        return "DOS"

    # RCE indicators
    if any(k in line_lower for k in ["uid=", "gid=", "whoami", "/bin/", "exec"]):
        return "RCE"

    # Path traversal
    if any(k in line_lower for k in ["../", "directory traversal", "web-inf", "etc/passwd"]):
        return "PATH_TRAVERSAL"

    # Authentication bypass
    if any(k in line_lower for k in ["authentication failed", "unauthorized", "access denied"]):
        return "AUTH_BYPASS"

    # Injection
    if any(k in line_lower for k in ["sql syntax", "syntax error"]):
        return "INJECTION"

    # Tomcat/Java specific
    if any(k in line_lower for k in ["tomcat", "catalina", "outofmemoryerror", "nullpointerexception"]):
        return "TOMCAT_ERROR"

    return "GENERIC_ERROR"

def get_resource_usage():
    """Returns CPU and RAM usage."""
    metrics = {"cpu_percent": 0.0, "ram_percent": 0.0}
    if psutil:
        metrics["cpu_percent"] = psutil.cpu_percent(interval=None)
        metrics["ram_percent"] = psutil.virtual_memory().percent
    else:
        # Fallback for Linux without psutil
        try:
            # Load Average (1 min) as proxy for CPU
            with open("/proc/loadavg", "r") as f:
                metrics["cpu_percent"] = float(f.read().split()[0]) * 10 # Rough estimate
            
            # Memory
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                free = int(lines[1].split()[1])
                metrics["ram_percent"] = round(((total - free) / total) * 100, 1)
        except:
            pass
    return metrics

def send_metrics(server_url, interval):
    """Background thread to send system metrics."""
    print(f"[*] Starting resource monitoring (Interval: {interval}s)")
    system_info = get_system_info()
    
    while True:
        try:
            metrics = get_resource_usage()
            payload = {
                "metadata": system_info,
                "type": "metric",
                "content": f"CPU: {metrics['cpu_percent']}% | RAM: {metrics['ram_percent']}%",
                "metrics": metrics,
                "timestamp": time.time()
            }
            requests.post(server_url, json=payload, timeout=2)
        except Exception:
            pass # Fail silently for metrics
        time.sleep(interval)

def monitor_logs(server_url, log_files, verbose=False):
    print(f"[*] Starting Agent on {socket.gethostname()}...")
    print(f"[*] Sending logs to {server_url}")
    print(f"[*] Monitoring {len(log_files)} files. Verbose: {verbose}")
    
    system_info = get_system_info()
    
    # Open all log files
    files = {}
    for log_path in log_files:
        if os.path.exists(log_path):
            try:
                f = open(log_path, 'r', errors='ignore')
                f.seek(0, os.SEEK_END) # Start at end
                files[log_path] = f
                print(f"[+] Monitoring {log_path}")
            except PermissionError:
                print(f"[-] Permission denied: {log_path} (Try running as root)")
        else:
            print(f"[-] File not found: {log_path}")

    if not files:
        print("[!] No log files accessible. Exiting.")
        return

    while True:
        for log_path, f in files.items():
            line = f.readline()
            if line:
                line = line.strip()
                if not line: continue

                # ============================================================
                # SMART FILTERING LOGIC (Prioritized)
                # ============================================================
                line_lower = line.lower()
                priority = "none"
                matched_keyword = None
                should_send = False

                if verbose:
                    # Verbose mode: send everything
                    should_send = True
                    priority = "verbose"
                else:
                    # Priority 1: FUZZING-SPECIFIC keywords (Always send)
                    for keyword in FUZZING_KEYWORDS:
                        if keyword.lower() in line_lower:
                            should_send = True
                            priority = "high"
                            matched_keyword = keyword
                            break

                    # Priority 2: Generic errors (Send only if not too frequent)
                    if not should_send:
                        for keyword in GENERIC_ERRORS:
                            if keyword.lower() in line_lower:
                                # Rate limit generic errors (max 10 per minute)
                                # For now, just send but could add throttling
                                should_send = True
                                priority = "low"
                                matched_keyword = keyword
                                break

                if should_send:
                    # Categorize the log for better fuzzer feedback
                    category = categorize_log(line, matched_keyword)

                    payload = {
                        "metadata": system_info,
                        "type": "log",
                        "log_file": log_path,
                        "content": line,
                        "priority": priority,
                        "category": category,
                        "matched_keyword": matched_keyword,
                        "timestamp": time.time()
                    }
                    try:
                        requests.post(server_url, json=payload, timeout=2)
                        if priority == "high":
                            print(f"[!] {category}: {matched_keyword} -> {line[:70]}...")
                    except Exception as e:
                        print(f"[!] Failed to send log: {e}")
        time.sleep(0.1)

def expand_log_paths(paths):
    """Expand glob patterns in log paths."""
    import glob as glob_module
    expanded = []
    for path in paths:
        if "*" in path:
            matches = glob_module.glob(path)
            expanded.extend(matches)
        else:
            expanded.append(path)
    return list(set(expanded))  # Remove duplicates

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PayloadFactory Linux Agent")
    parser.add_argument("--server", default=DEFAULT_SERVER_URL, help="Server URL (e.g. http://192.168.1.5:8000/agent/logs)")
    parser.add_argument("--files", nargs="+", help="Additional log files to monitor")
    parser.add_argument("--verbose", action="store_true", help="Send ALL logs (disable filtering)")
    parser.add_argument("--interval", type=int, default=5, help="Metric reporting interval (seconds)")
    parser.add_argument("--tomcat", action="store_true", help="Enable Tomcat mode: monitor catalina.out, access logs, etc.")
    
    args = parser.parse_args()
    
    # Ensure endpoint
    url = args.server
    if not url.endswith("/agent/logs"):
        url = url.rstrip("/") + "/agent/logs"
    
    # Build target files list
    target_files = list(SYSTEM_LOG_FILES)
    
    # Add Tomcat logs if --tomcat flag is set
    if args.tomcat:
        print("[*] TOMCAT MODE: Adding Tomcat-specific log files...")
        target_files.extend(TOMCAT_LOG_FILES)
    
    # Add user-specified files
    if args.files:
        target_files.extend(args.files)
    
    # Expand glob patterns (e.g., /var/log/tomcat*/catalina.out)
    target_files = expand_log_paths(target_files)
    
    print(f"[*] Monitoring {len(target_files)} log files:")
    for f in target_files[:10]:  # Show first 10
        print(f"    - {f}")
    if len(target_files) > 10:
        print(f"    ... and {len(target_files) - 10} more")
        
    # Start Metrics Thread
    t = threading.Thread(target=send_metrics, args=(url, args.interval), daemon=True)
    t.start()
        
    try:
        monitor_logs(url, target_files, args.verbose)
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")

