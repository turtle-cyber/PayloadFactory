# Advanced Network Scanner - Complete Usage Guide

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Stealth Scanning Techniques](#stealth-scanning-techniques)
4. [Evasion Techniques](#evasion-techniques)
5. [Advanced Features](#advanced-features)
6. [Command-Line Examples](#command-line-examples)
7. [Understanding Results](#understanding-results)
8. [Legal & Ethical Considerations](#legal--ethical-considerations)

---

## Installation

### Step 1: Install Nmap

**Windows:**
```bash
# Download from https://nmap.org/download.html
# Install and add to PATH
```

**Linux:**
```bash
sudo apt update
sudo apt install nmap
```

**macOS:**
```bash
brew install nmap
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install python-nmap
```

---

## Quick Start

### Interactive Mode (Recommended for Beginners)

Simply run without arguments:
```bash
python advanced_scanner.py
```

You'll be guided through:
- Target selection
- Scan mode selection
- Advanced options
- Export preferences

### Command-Line Mode

```bash
# Basic scan
python advanced_scanner.py -t scanme.nmap.org

# Stealth scan
python advanced_scanner.py -t 192.168.1.1 --stealth syn -T2

# Aggressive scan with export
python advanced_scanner.py -t example.com --aggressive --export json -v
```

---

## Stealth Scanning Techniques

Stealth scanning helps avoid detection by firewalls and IDS/IPS systems.

### 1. SYN Stealth Scan (Half-Open Scan)
**Most Popular & Effective**

```bash
python advanced_scanner.py -t target.com --stealth syn -T2
```

**How it works:**
- Sends SYN packet
- Receives SYN-ACK (port open) or RST (port closed)
- Never completes TCP handshake
- Doesn't appear in application logs

**Best for:** General stealth scanning, avoiding log detection

---

### 2. FIN Scan
```bash
python advanced_scanner.py -t target.com --stealth fin -T1
```

**How it works:**
- Sends packets with only FIN flag
- Closed ports respond with RST
- Open ports ignore the packet (RFC 793)

**Best for:** Bypassing simple firewalls, Unix/Linux systems

---

### 3. NULL Scan
```bash
python advanced_scanner.py -t target.com --stealth null -T1
```

**How it works:**
- Sends packets with NO flags set
- Similar to FIN scan behavior
- More unusual traffic pattern

**Best for:** Advanced IDS evasion, Unix/Linux targets

---

### 4. Xmas Scan
```bash
python advanced_scanner.py -t target.com --stealth xmas -T1
```

**How it works:**
- Sends packets with FIN, PSH, and URG flags set
- "Lights up like a Christmas tree"
- Similar response patterns to FIN/NULL

**Best for:** Firewall testing, non-Windows targets

---

### 5. ACK Scan
```bash
python advanced_scanner.py -t target.com --stealth ack
```

**How it works:**
- Sends ACK packets
- Doesn't determine open/closed ports
- Maps firewall rulesets

**Best for:** Firewall detection and mapping

---

## Evasion Techniques

### Timing Templates

Control scan speed to avoid detection:

```bash
# T0 - Paranoid (ultra slow, 5 min per port)
python advanced_scanner.py -t target.com -T0

# T1 - Sneaky (slow, IDS evasion)
python advanced_scanner.py -t target.com --stealth syn -T1

# T2 - Polite (slower, less bandwidth)
python advanced_scanner.py -t target.com -T2

# T3 - Normal (default)
python advanced_scanner.py -t target.com -T3

# T4 - Aggressive (faster, recommended)
python advanced_scanner.py -t target.com -T4

# T5 - Insane (extremely fast, may miss results)
python advanced_scanner.py -t target.com -T5
```

**Recommendation:**
- **Stealth operations:** T0 or T1
- **IDS evasion:** T1 or T2
- **Normal scanning:** T3 or T4
- **Quick recon:** T4 or T5

---

### Packet Fragmentation

Split packets into tiny fragments to evade packet inspection:

```bash
python advanced_scanner.py -t target.com --fragment --stealth syn -T2
```

**How it works:**
- Breaks IP packets into small fragments
- Some IDS/IPS can't reassemble fragmented packets
- Bypasses simple packet filters

**Note:** Less effective against modern IDS

---

### Decoy Scanning

Hide your IP among fake source addresses:

```bash
# Random decoys
python advanced_scanner.py -t target.com --decoy random

# Specific decoys (manual)
python advanced_scanner.py -t target.com --decoy "192.168.1.5,192.168.1.6,192.168.1.7,ME"
```

**How it works:**
- Scanner sends packets from multiple IPs
- Target sees scans from many sources
- Your real IP is hidden in the noise

**Best practices:**
- Use IPs that are actually up
- Mix your IP with decoys (ME)
- Don't use more than 10 decoys

---

### MAC Address Spoofing

```bash
# Random vendor MAC
python advanced_scanner.py -t target.com --spoof-mac 0

# Specific vendor (e.g., Cisco)
python advanced_scanner.py -t target.com --spoof-mac Cisco

# Specific MAC address
python advanced_scanner.py -t target.com --spoof-mac 00:11:22:33:44:55
```

**When to use:**
- Local network scanning
- Bypassing MAC filtering
- Blending with network devices

---

### Randomize Host Order

```bash
python advanced_scanner.py -t 192.168.1.0/24 --randomize
```

**Benefits:**
- Prevents sequential scan detection
- Looks less like automated scanning
- Harder to track scan patterns

---

### Combined Evasion Example

Maximum stealth scan:

```bash
python advanced_scanner.py -t target.com \
    --stealth fin \
    -T1 \
    --fragment \
    --decoy random \
    --randomize \
    --spoof-mac 0 \
    -v
```

---

## Advanced Features

### 1. Vulnerability Scanning

```bash
python advanced_scanner.py -t target.com --vuln --export html
```

Runs NSE vulnerability detection scripts:
- CVE detection
- Known exploits
- Misconfiguration checks
- Default credentials

---

### 2. CIDR Range Scanning

```bash
# Scan entire subnet
python advanced_scanner.py -t 192.168.1.0/24

# Scan larger network
python advanced_scanner.py -t 10.0.0.0/16 --quick
```

---

### 3. Custom Port Ranges

```bash
# Specific ports
python advanced_scanner.py -t target.com -p "80,443,8080,8443"

# Port range
python advanced_scanner.py -t target.com -p "1-1000"

# All ports (slow!)
python advanced_scanner.py -t target.com --all-ports
```

---

### 4. Export Results

```bash
# JSON export
python advanced_scanner.py -t target.com --export json

# CSV export (good for spreadsheets)
python advanced_scanner.py -t target.com --export csv

# HTML report (visual)
python advanced_scanner.py -t target.com --export html
```

Files are saved as: `scan_YYYYMMDD_HHMMSS.[format]`

---

### 5. Logging

```bash
python advanced_scanner.py -t target.com --log scan.log -v
```

**Benefits:**
- Track scan history
- Debug issues
- Audit trail
- Verbose output to file

---

## Command-Line Examples

### Scenario 1: Initial Network Reconnaissance

```bash
# Quick discovery scan
python advanced_scanner.py -t 192.168.1.0/24 --quick -v
```

---

### Scenario 2: Detailed Host Analysis

```bash
# Full service and OS detection
python advanced_scanner.py -t 192.168.1.50 --aggressive --export html
```

---

### Scenario 3: Stealth Penetration Test

```bash
# Ultra-stealthy scan
python advanced_scanner.py -t target.com \
    --stealth syn \
    -T1 \
    --fragment \
    --decoy random \
    --randomize \
    -p "21,22,23,25,80,443,3389,8080" \
    --log stealth_scan.log
```

---

### Scenario 4: Vulnerability Assessment

```bash
# Find vulnerabilities and export
python advanced_scanner.py -t target.com \
    --aggressive \
    --vuln \
    --export json \
    -v
```

---

### Scenario 5: Firewall Rule Mapping

```bash
# Detect firewall rules with ACK scan
python advanced_scanner.py -t target.com \
    --stealth ack \
    --all-ports \
    --export csv
```

---

### Scenario 6: Web Application Scan

```bash
# Focus on web ports
python advanced_scanner.py -t webapp.com \
    -p "80,443,8000,8080,8443" \
    --vuln \
    --export html
```

---

## Understanding Results

### Port States

- **open**: Service is accepting connections
- **closed**: Port is accessible but no service listening
- **filtered**: Firewall/filter is blocking probes
- **open|filtered**: Can't determine if open or filtered
- **closed|filtered**: Can't determine if closed or filtered

### OS Detection Accuracy

- **90-100%**: Very likely correct
- **80-89%**: Probably correct
- **70-79%**: Possibly correct
- **<70%**: Low confidence, multiple options

### Service Version Detection

- **Product**: Software name (e.g., Apache)
- **Version**: Version number (e.g., 2.4.41)
- **Extra Info**: Additional details (e.g., Ubuntu, SSL)

---

## Performance Tips

### Fast Scanning
```bash
python advanced_scanner.py -t target.com --quick -T4
```

### Thorough Scanning
```bash
python advanced_scanner.py -t target.com --all-ports -T2 --aggressive
```

### Balanced (Recommended)
```bash
python advanced_scanner.py -t target.com -T3 --export json
```

---

## Troubleshooting

### No Results / All Ports Filtered

**Solutions:**
1. Run with administrator/sudo privileges
2. Try different stealth techniques
3. Use slower timing template (T1 or T2)
4. Check if target is actually up

```bash
# Try this
sudo python advanced_scanner.py -t target.com --stealth syn -T2 -v
```

---

### Permission Denied

**Solution:** Run with elevated privileges

```bash
# Windows: Run as Administrator
# Linux/Mac:
sudo python advanced_scanner.py -t target.com
```

---

### Nmap Not Found

**Solution:** Ensure nmap is in system PATH

```bash
# Test nmap installation
nmap --version

# If not found, reinstall nmap
```

---

### Scan Too Slow

**Solutions:**
1. Use faster timing: `-T4` or `-T5`
2. Reduce port range: `--quick` or `-p "common ports"`
3. Skip OS detection for speed

```bash
python advanced_scanner.py -t target.com --quick -T4
```

---

### Scan Too Noisy (Getting Detected)

**Solutions:**
1. Use slower timing: `-T1` or `-T0`
2. Enable evasion: `--fragment --decoy random`
3. Use stealth scans: `--stealth fin`

```bash
python advanced_scanner.py -t target.com --stealth fin -T1 --fragment --decoy random
```

---

## Legal & Ethical Considerations

### ⚠️ IMPORTANT LEGAL NOTICE

**Only scan systems you own or have explicit written permission to test.**

### Authorized Use Cases

✅ **Legal:**
- Your own systems and networks
- Systems with written authorization
- Penetration testing contracts
- CTF (Capture The Flag) competitions
- Lab environments
- scanme.nmap.org (specifically provided for testing)

❌ **Illegal:**
- Scanning without permission
- Unauthorized penetration testing
- Network reconnaissance for malicious purposes
- Scanning ISP/hosting provider networks

### Best Practices

1. **Get Written Permission**: Always obtain written authorization
2. **Define Scope**: Clearly define what can be scanned
3. **Set Time Windows**: Agree on when scanning can occur
4. **Document Everything**: Keep logs of all activities
5. **Report Findings**: Properly disclose vulnerabilities
6. **Respect Privacy**: Don't access or modify data

### Recommended Test Target

For practice and learning:
```bash
python advanced_scanner.py -t scanme.nmap.org
```

**Note:** scanme.nmap.org is specifically provided by nmap.org for testing purposes.

---

## Privacy & Anonymity

### What This Tool Does NOT Provide

- **NOT anonymous**: Your IP is visible unless you use proxies/VPN
- **NOT untraceable**: Logs can identify you
- **NOT invisible**: Advanced IDS will detect scans

### For True Anonymity

Consider additional layers:
- VPN services
- Tor network (with caution)
- Proxy chains
- Authorized test networks

**Warning:** Attempting to hide illegal activity is itself illegal in many jurisdictions.

---

## Additional Resources

### Learning
- [Nmap Official Documentation](https://nmap.org/book/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

### Practice
- [HackTheBox](https://www.hackthebox.eu/) - Legal hacking practice
- [TryHackMe](https://tryhackme.com/) - Guided learning
- [VulnHub](https://www.vulnhub.com/) - Vulnerable VMs

---

## Support & Contributing

Report issues or contribute at: [Your Repository]

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
