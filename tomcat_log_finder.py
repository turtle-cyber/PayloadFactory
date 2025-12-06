#!/usr/bin/env python3
"""
Tomcat Log Finder - Discovers Tomcat installation and log paths dynamically.
Run this on the target Linux system to find Tomcat logs.
"""
import os
import glob
import subprocess
import sys

def find_tomcat_installations():
    """Find all Tomcat installations on the system."""
    installations = []

    # Common Tomcat installation paths
    search_paths = [
        "/opt/tomcat*",
        "/opt/apache-tomcat*",
        "/usr/share/tomcat*",
        "/var/lib/tomcat*",
        "/usr/local/tomcat*",
        "/home/*/tomcat*",
        "/srv/tomcat*",
    ]

    for pattern in search_paths:
        matches = glob.glob(pattern)
        installations.extend(matches)

    # Check running Tomcat processes
    try:
        ps_output = subprocess.check_output(
            ["ps", "aux"],
            universal_newlines=True
        )
        for line in ps_output.split('\n'):
            if 'catalina' in line.lower() or 'tomcat' in line.lower():
                # Extract path from command line
                if '-Dcatalina.home=' in line:
                    start = line.find('-Dcatalina.home=') + len('-Dcatalina.home=')
                    end = line.find(' ', start)
                    path = line[start:end] if end != -1 else line[start:]
                    if path and os.path.isdir(path):
                        installations.append(path)
    except Exception as e:
        print(f"Warning: Could not check running processes: {e}", file=sys.stderr)

    return list(set(installations))

def find_log_files(base_path):
    """Find all Tomcat log files in a given installation."""
    log_files = []

    # Common log subdirectories
    log_dirs = [
        os.path.join(base_path, "logs"),
        os.path.join(base_path, "log"),
    ]

    for log_dir in log_dirs:
        if os.path.isdir(log_dir):
            # Find all log files
            patterns = [
                "catalina.out",
                "catalina.*.log",
                "localhost*.log",
                "localhost_access_log*.txt",
                "host-manager*.log",
                "manager*.log",
            ]

            for pattern in patterns:
                matches = glob.glob(os.path.join(log_dir, pattern))
                log_files.extend(matches)

    return log_files

def check_file_permissions(filepath):
    """Check if we can read the file."""
    try:
        with open(filepath, 'r') as f:
            f.read(1)
        return True
    except PermissionError:
        return False
    except Exception:
        return False

def main():
    print("="*60)
    print("Tomcat Log Finder")
    print("="*60)

    # Find installations
    installations = find_tomcat_installations()

    if not installations:
        print("\n[!] No Tomcat installations found.")
        print("[*] Searched in common paths like /opt/tomcat*, /var/lib/tomcat*, etc.")
        print("[*] If Tomcat is installed in a custom location, please specify it manually.")
        return

    print(f"\n[+] Found {len(installations)} Tomcat installation(s):\n")

    all_logs = []
    for install_path in installations:
        print(f"  📁 {install_path}")
        log_files = find_log_files(install_path)

        if log_files:
            print(f"     Found {len(log_files)} log file(s):")
            for log_file in log_files:
                readable = check_file_permissions(log_file)
                status = "✅ Readable" if readable else "❌ Permission Denied"
                print(f"       - {log_file} [{status}]")
                if readable:
                    all_logs.append(log_file)
        else:
            print(f"     ⚠️  No log files found in standard locations")

    # Generate agent command
    if all_logs:
        print("\n" + "="*60)
        print("Recommended linux_agent.py Command:")
        print("="*60)

        # Option 1: Use --tomcat flag
        print("\nOption 1 (Automatic - uses built-in paths):")
        print(f"  sudo python3 linux_agent.py --server http://YOUR_SERVER_IP:8000 --tomcat")

        # Option 2: Specify exact files
        print("\nOption 2 (Explicit - specify exact log files found):")
        cmd = f"  sudo python3 linux_agent.py --server http://YOUR_SERVER_IP:8000 --files"
        for log in all_logs[:5]:  # Show max 5 files
            cmd += f' "{log}"'
        if len(all_logs) > 5:
            cmd += " ..."
        print(cmd)

        print("\nNote: Run with 'sudo' to access protected log files.")

    else:
        print("\n[!] No readable log files found.")
        print("[*] Try running this script with sudo:")
        print(f"    sudo python3 {sys.argv[0]}")

    print("\n" + "="*60)

if __name__ == "__main__":
    main()
