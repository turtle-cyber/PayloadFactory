import time
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
DEFAULT_LOG_FILES = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/dmesg",
    "/var/log/kern.log"
]

# Keywords to filter for (unless verbose)
ERROR_KEYWORDS = ["error", "fail", "panic", "segfault", "exception", "critical", "warning", "denied", "refused"]

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "ip": socket.gethostbyname(socket.gethostname()),
        "os": platform.system(),
        "release": platform.release()
    }

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
                
                # Filtering Logic
                should_send = verbose
                if not should_send:
                    if any(k in line.lower() for k in ERROR_KEYWORDS):
                        should_send = True
                
                if should_send:
                    payload = {
                        "metadata": system_info,
                        "type": "log",
                        "log_file": log_path,
                        "content": line,
                        "timestamp": time.time()
                    }
                    try:
                        requests.post(server_url, json=payload, timeout=2)
                        # print(f"Sent: {line[:50]}...")
                    except Exception as e:
                        print(f"[!] Failed to send log: {e}")
        time.sleep(0.1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PayloadFactory Linux Agent")
    parser.add_argument("--server", default=DEFAULT_SERVER_URL, help="Server URL (e.g. http://192.168.1.5:8000/agent/logs)")
    parser.add_argument("--files", nargs="+", help="Additional log files to monitor")
    parser.add_argument("--verbose", action="store_true", help="Send ALL logs (disable filtering)")
    parser.add_argument("--interval", type=int, default=5, help="Metric reporting interval (seconds)")
    
    args = parser.parse_args()
    
    # Ensure endpoint
    url = args.server
    if not url.endswith("/agent/logs"):
        url = url.rstrip("/") + "/agent/logs"
    
    # Merge default files with user files
    target_files = DEFAULT_LOG_FILES
    if args.files:
        target_files.extend(args.files)
        
    # Start Metrics Thread
    t = threading.Thread(target=send_metrics, args=(url, args.interval), daemon=True)
    t.start()
        
    try:
        monitor_logs(url, target_files, args.verbose)
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")
