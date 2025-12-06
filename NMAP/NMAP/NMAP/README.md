# Network Reconnaissance Scanner

A Python-based network scanner that detects services, versions, operating systems, and other details for any IP address, URL, or domain.

## 📦 Available Scanners

This repository contains **two versions**:

1. **[network_scanner.py](network_scanner.py)** - Basic scanner (simple & easy to use)
2. **[advanced_scanner.py](advanced_scanner.py)** - Advanced scanner with stealth & evasion capabilities

## Features

### Basic Scanner (network_scanner.py)
- ✅ Scan IP addresses, URLs, or domain names
- ✅ Detect open ports and running services
- ✅ Identify service versions
- ✅ Operating System detection
- ✅ OS version identification
- ✅ Multiple scan modes (Quick, Default, Aggressive)
- ✅ Clean, formatted output

### Advanced Scanner (advanced_scanner.py)
#### 🥷 Stealth Scanning Techniques
- ✅ **SYN Scan** - Half-open stealth scanning
- ✅ **FIN Scan** - Bypass simple firewalls
- ✅ **NULL Scan** - Advanced IDS evasion
- ✅ **Xmas Scan** - Alternative stealth method
- ✅ **ACK Scan** - Firewall rule mapping

#### 🛡️ Evasion Techniques
- ✅ **Packet Fragmentation** - Bypass packet inspection
- ✅ **Decoy Scanning** - Hide your IP among fake sources
- ✅ **MAC Spoofing** - Change source MAC address
- ✅ **Randomize Host Order** - Prevent pattern detection
- ✅ **Timing Templates (T0-T5)** - Control scan speed for stealth

#### 🚀 Advanced Functionality
- ✅ **Comprehensive Input Validation** - Handles IP, Domain, URL, CIDR
- ✅ **Vulnerability Scanning** - NSE script integration
- ✅ **Export Formats** - JSON, CSV, HTML reports
- ✅ **Logging System** - Track all activities
- ✅ **Verbose Mode** - Detailed debugging
- ✅ **Error Handling** - Robust edge case management

## Prerequisites

### 1. Install Nmap

**Windows:**
- Download from: https://nmap.org/download.html
- Run the installer and follow the prompts
- Add Nmap to your system PATH

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install nmap
```

**macOS:**
```bash
brew install nmap
```

### 2. Python 3.x
Make sure Python 3.6 or higher is installed.

## Installation

1. Install the required Python package:
```bash
pip install -r requirements.txt
```

Or install directly:
```bash
pip install python-nmap
```

## Usage

### Basic Scanner Usage

#### Interactive Mode

Run the script without arguments:
```bash
python network_scanner.py
```

Then enter:
- Target (IP/URL/Domain)
- Scan type preference

#### Command Line Mode

```bash
python network_scanner.py <target> [scan_type]
```

**Examples:**
```bash
# Scan an IP address
python network_scanner.py 192.168.1.1

# Scan a domain
python network_scanner.py example.com

# Scan a URL
python network_scanner.py https://example.com

# Quick scan
python network_scanner.py scanme.nmap.org quick

# Aggressive scan (all ports)
python network_scanner.py 192.168.1.1 aggressive
```

---

### Advanced Scanner Usage

#### Interactive Mode (Recommended)

```bash
python advanced_scanner.py
```

Guides you through:
- Target selection
- Scan mode (Quick/Standard/Aggressive/Stealth/Custom)
- Stealth technique selection
- Evasion options
- Export preferences

#### Command Line Mode

```bash
python advanced_scanner.py -t <target> [options]
```

#### Quick Reference - Command Line Flags

**Stealth Scanning:**
```bash
# SYN Scan (half-open stealth)
python advanced_scanner.py -t target.com --stealth syn

# FIN Scan (bypass firewalls)
python advanced_scanner.py -t target.com --stealth fin

# NULL Scan (IDS evasion)
python advanced_scanner.py -t target.com --stealth null

# Xmas Scan
python advanced_scanner.py -t target.com --stealth xmas

# ACK Scan (firewall mapping)
python advanced_scanner.py -t target.com --stealth ack
```

**Evasion Techniques:**
```bash
# Packet fragmentation
python advanced_scanner.py -t target.com --fragment

# Decoy scanning (hide your IP)
python advanced_scanner.py -t target.com --decoy random

# MAC address spoofing
python advanced_scanner.py -t target.com --spoof-mac 0

# Randomize host order
python advanced_scanner.py -t target.com --randomize

# Timing templates (T0=slowest/stealthiest, T5=fastest)
python advanced_scanner.py -t target.com -T2
```

**Advanced Features:**
```bash
# Vulnerability scanning
python advanced_scanner.py -t target.com --vuln

# Export results to JSON
python advanced_scanner.py -t target.com --export json

# Export results to CSV
python advanced_scanner.py -t target.com --export csv

# Export results to HTML
python advanced_scanner.py -t target.com --export html

# Verbose mode
python advanced_scanner.py -t target.com -v

# Log to file
python advanced_scanner.py -t target.com --log scan.log

# Scan all ports
python advanced_scanner.py -t target.com --all-ports

# Scan specific ports
python advanced_scanner.py -t target.com -p "80,443,8080"

# Quick scan (top 100 ports)
python advanced_scanner.py -t target.com --quick

# Aggressive scan
python advanced_scanner.py -t target.com --aggressive
```

**Combined Examples:**

```bash
# Maximum stealth scan
python advanced_scanner.py -t target.com \
    --stealth fin \
    -T1 \
    --fragment \
    --decoy random \
    --randomize \
    --spoof-mac 0 \
    -v

# Full vulnerability assessment
python advanced_scanner.py -t target.com \
    --aggressive \
    --vuln \
    --export html \
    -v \
    --log vuln_scan.log

# Corporate network scan (CIDR range)
python advanced_scanner.py -t 192.168.1.0/24 \
    --quick \
    --export csv

# Web application scan
python advanced_scanner.py -t webapp.com \
    -p "80,443,8000,8080,8443" \
    --vuln \
    --export html
```

**See All Options:**
```bash
python advanced_scanner.py --help
```

## Scan Types

1. **Default** (Recommended)
   - Scans top 1000 common ports
   - Service version detection
   - OS detection
   - Good balance of speed and detail

2. **Quick**
   - Scans top 100 most common ports
   - Service version detection
   - Fastest option

3. **Aggressive**
   - Scans ALL 65535 ports
   - Service version detection
   - OS detection with scripts
   - Most thorough but SLOW

## Output Information

The scanner provides:
- Host state (up/down)
- Hostnames
- Operating System details with accuracy percentage
- OS type, vendor, and family
- Open ports with protocol (TCP/UDP)
- Service names running on each port
- Service versions and additional info
- System uptime
- TCP sequence analysis

## Example Output

```
============================================================
HOST: 192.168.1.1
============================================================
State: up
Hostnames: router.local

────────────────────────────────────────────────────────────
OS DETECTION:
────────────────────────────────────────────────────────────
  • Linux 4.15 - 5.6 (Accuracy: 95%)
    - Type: general purpose
    - Vendor: Linux
    - OS Family: Linux
    - OS Gen: 5.X

────────────────────────────────────────────────────────────
OPEN PORTS AND SERVICES:
────────────────────────────────────────────────────────────
PORT       STATE      SERVICE              VERSION
---------- ---------- -------------------- ------------------------------
22/tcp     open       ssh                  OpenSSH 8.2p1 Ubuntu
80/tcp     open       http                 Apache httpd 2.4.41
443/tcp    open       ssl/http             Apache httpd 2.4.41

============================================================
SCAN COMPLETE
============================================================
```

## Important Notes

### Administrative Privileges

Some scans (especially OS detection) may require elevated privileges:

**Windows:**
Run Command Prompt or PowerShell as Administrator

**Linux/macOS:**
```bash
sudo python network_scanner.py <target>
```

### Legal Notice

This tool is for authorized security testing, network administration, and educational purposes only. Always ensure you have permission to scan the target network/system. Unauthorized scanning may be illegal in your jurisdiction.

### Firewall Considerations

- Firewalls may block scan attempts
- Some services may not respond to version detection
- Results accuracy depends on target configuration

## Troubleshooting

**Error: "Nmap not found"**
- Ensure Nmap is installed and in your system PATH
- Restart terminal after installation

**Error: "Permission denied"**
- Run with administrator/sudo privileges
- Required for OS detection and some scan types

**No results returned**
- Target may be offline or blocking scans
- Firewall may be filtering packets
- Try different scan types

## Documentation

- **[README.md](README.md)** - This file (quick start guide)
- **[ADVANCED_USAGE_GUIDE.md](ADVANCED_USAGE_GUIDE.md)** - Comprehensive guide with detailed examples, techniques, and best practices

## License

This tool is provided for educational and authorized security testing purposes.

---

## Quick Command Reference

### Basic Commands
```bash
# Basic scan
python network_scanner.py scanme.nmap.org

# Advanced interactive mode
python advanced_scanner.py

# Quick advanced scan
python advanced_scanner.py -t scanme.nmap.org --quick
```

### Stealth Operations
```bash
# Stealth scan with evasion
python advanced_scanner.py -t target.com --stealth syn -T1 --fragment --decoy random

# Ultra-stealth
python advanced_scanner.py -t target.com --stealth fin -T0 --randomize
```

### Vulnerability Assessment
```bash
# Full vulnerability scan with export
python advanced_scanner.py -t target.com --vuln --aggressive --export html -v
```

For detailed documentation, see **[ADVANCED_USAGE_GUIDE.md](ADVANCED_USAGE_GUIDE.md)**
