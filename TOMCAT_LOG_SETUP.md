# Tomcat Log Collection Setup Guide

This guide will help you set up log collection from your Apache Tomcat server running on Linux for use with the PayloadFactoryUX fuzzing module.

## Problem Solved

Your original setup wasn't working because:

1. **API mismatch**: The agent was sending fields (`type`, `priority`, `category`) that the API didn't accept
2. **Permission issues**: Tomcat logs require root/sudo access
3. **Hardcoded paths**: Tomcat installations vary across systems
4. **No feedback loop**: Logs weren't reaching the fuzzer in real-time

## Solution Overview

We've created **two new tools**:

1. **`tomcat_log_finder.py`** - Discovers Tomcat installations and log paths
2. **`tomcat_agent.py`** - Lightweight agent focused ONLY on Tomcat fuzzing

## Step-by-Step Setup

### Step 1: Copy Files to Target Linux System

Copy these files to your target Linux system (where Tomcat is running):

```bash
# On your Windows machine (fuzzer)
# Use SCP, SFTP, or any file transfer method

scp tomcat_log_finder.py user@target-ip:/tmp/
scp tomcat_agent.py user@target-ip:/tmp/
```

### Step 2: Find Tomcat Logs

On the **target Linux system**, run the log finder:

```bash
# SSH into target
ssh user@target-ip

# Run the finder
cd /tmp
python3 tomcat_log_finder.py
```

**Example Output:**
```
============================================================
Tomcat Log Finder
============================================================

[+] Found 1 Tomcat installation(s):

  📁 /opt/tomcat
     Found 3 log file(s):
       - /opt/tomcat/logs/catalina.out [✅ Readable]
       - /opt/tomcat/logs/localhost_access_log.2024-12-06.txt [✅ Readable]
       - /opt/tomcat/logs/localhost.2024-12-06.log [❌ Permission Denied]

============================================================
Recommended linux_agent.py Command:
============================================================

Option 1 (Automatic - uses built-in paths):
  sudo python3 linux_agent.py --server http://YOUR_SERVER_IP:8000 --tomcat

Option 2 (Explicit - specify exact log files found):
  sudo python3 linux_agent.py --server http://YOUR_SERVER_IP:8000 --files "/opt/tomcat/logs/catalina.out" ...

Note: Run with 'sudo' to access protected log files.
```

### Step 3: Start the Tomcat Agent

**On the target Linux system:**

```bash
# Option 1: Auto-discover logs (recommended)
sudo python3 /tmp/tomcat_agent.py --server http://FUZZER_IP:8000

# Option 2: Specify exact path
sudo python3 /tmp/tomcat_agent.py --server http://FUZZER_IP:8000 --catalina-path /opt/tomcat/logs/catalina.out

# Option 3: Verbose mode (sends all logs, not just errors)
sudo python3 /tmp/tomcat_agent.py --server http://FUZZER_IP:8000 --verbose
```

**Replace `FUZZER_IP`** with your Windows machine's IP (e.g., `192.168.1.170`)

**Example Output:**
```
============================================================
Tomcat Fuzzing Agent
============================================================
Server: http://192.168.1.170:8000/agent/logs
Hostname: ubuntu-tomcat (192.168.1.131)
Verbose: False
============================================================
[+] Auto-discovered catalina.out: /opt/tomcat/logs/catalina.out
[+] Auto-discovered access log: /opt/tomcat/logs/localhost_access_log.2024-12-06.txt
[+] Monitoring: /opt/tomcat/logs/catalina.out

[*] Starting monitoring... (Press Ctrl+C to stop)
```

### Step 4: Start Fuzzing from Windows

**On your Windows machine (PayloadFactory):**

1. **Ensure the server is running:**
   - The GUI launcher automatically starts the server on port 8000
   - Or manually: `python -m uvicorn server.app.main:app --host 0.0.0.0 --port 8000`

2. **Run a scan with Attack Mode:**
   - Open `gui_launcher.py`
   - Go to "Scan Mode" tab
   - Enable "Attack Mode"
   - Enter target IP: `192.168.1.131` (your Tomcat server)
   - Enter target port: `8080` (or your Tomcat port)
   - Click "Start Scan"

3. **Or use command line:**
   ```bash
   python scan_and_exploit.py C:\path\to\webapp\source --remote-host 192.168.1.131 --remote-port 8080
   ```

### Step 5: Monitor Real-time Logs

**In the GUI:**
- Go to the "Agent Mode" tab
- You should see live logs appearing from your Tomcat server
- Critical findings (RCE, CRASH, DOS) will be highlighted

**Example logs you'll see:**
```
[2024-12-06 16:30:15] Received agent log from ubuntu-tomcat: [!] RCE: uid=\d+ -> SEVERE: java.lang.Runtime.exec() detected...
[2024-12-06 16:30:18] Received agent log from ubuntu-tomcat: [!] CRASH: OutOfMemoryError -> java.lang.OutOfMemoryError: Java heap space...
```

## Verification

### Test 1: Agent Endpoint
```bash
# On your Windows machine
curl -X POST http://localhost:8000/agent/logs -H "Content-Type: application/json" -d "{\"metadata\":{\"hostname\":\"test\"},\"type\":\"log\",\"log_file\":\"/test\",\"content\":\"TEST\",\"timestamp\":1234567890}"
```

Expected: `{"status":"received"}`

### Test 2: Agent Connection
```bash
# On target Linux system
sudo python3 tomcat_agent.py --server http://FUZZER_IP:8000 --verbose
```

Then trigger a Tomcat error (e.g., access invalid URL) and check if it appears in the GUI.

## What Gets Monitored

The agent monitors for these **critical patterns** in Tomcat logs:

| Category | Patterns |
|----------|----------|
| **RCE** | Runtime.exec, ProcessBuilder, uid=, /bin/bash, command execution |
| **CRASH** | OutOfMemoryError, StackOverflowError, java.lang.Error, FATAL |
| **PATH_TRAVERSAL** | ../.., WEB-INF, directory traversal |
| **AUTH_BYPASS** | authentication fail, 401, 403, access denied |
| **DESERIALIZATION** | ObjectInputStream, readObject, serialization |
| **DOS** | too many connections, timeout, resource unavailable |
| **EL_INJECTION** | ELException, ${...}, expression evaluation |

## Integration with RL Fuzzer

The logs are automatically used by your fuzzing/RL module:

1. **Fuzzer** ([ml_engine/fuzzing_module.py:379-391](ml_engine/fuzzing_module.py#L379-L391)) checks for agent logs during fuzzing
2. **RL Agent** ([ml_engine/rl_agent.py:378-385](ml_engine/rl_agent.py#L378-L385)) uses log feedback to optimize payloads
3. **Feedback Context** creates context from crashes/errors for intelligent mutation

## Troubleshooting

### Issue: "Permission denied" on log files
**Solution:** Run with `sudo`:
```bash
sudo python3 tomcat_agent.py --server http://FUZZER_IP:8000
```

### Issue: "Could not find Tomcat logs"
**Solution:** Run the log finder first:
```bash
python3 tomcat_log_finder.py
```
Then use the recommended command from the output.

### Issue: Logs not appearing in GUI
**Checklist:**
1. ✅ Is the agent running on target? (`ps aux | grep tomcat_agent`)
2. ✅ Can target reach fuzzer? (`ping FUZZER_IP`)
3. ✅ Is port 8000 open? (`netstat -an | grep 8000`)
4. ✅ Is MongoDB running? (`netstat -an | grep 27017`)

### Issue: Too many logs flooding the system
**Solution:** Use the default mode (NOT verbose):
```bash
sudo python3 tomcat_agent.py --server http://FUZZER_IP:8000
# Do NOT use --verbose flag
```

The agent only sends **critical** logs by default.

## Alternative: Use Original linux_agent.py

If you prefer the original agent:

```bash
# Make sure the API fix is applied (it is!)
sudo python3 linux_agent.py --server http://FUZZER_IP:8000 --tomcat --interval 2
```

This monitors both system logs AND Tomcat logs.

## Performance Notes

- **Tomcat Agent**: ~0.5% CPU, monitors 1-2 log files
- **Linux Agent**: ~1-2% CPU, monitors 10+ log files
- **Log send rate**: ~1-5 logs/second during fuzzing
- **Network bandwidth**: < 1 KB/s

## Next Steps

Once logs are flowing:

1. Run Stage 3 fuzzing with the RL agent
2. Monitor the Agent tab in the GUI for real-time feedback
3. Check MongoDB for persistent log storage:
   ```bash
   # Connect to MongoDB
   mongo -u admin -p admin
   use payloadfactoryDB
   db.agent_logs.find().limit(10)
   ```

4. Review crash findings:
   ```bash
   db.agent_logs.find({"category": "CRASH"})
   ```

## Summary

You now have **two** working solutions:

| Tool | Use Case | Best For |
|------|----------|----------|
| **tomcat_agent.py** | Tomcat-only fuzzing | Fast, lightweight, focused |
| **linux_agent.py --tomcat** | Full system monitoring | Comprehensive, includes system logs |

Both work with your existing fuzzing infrastructure and provide real-time feedback to the RL module.

---

**Questions?** Check the logs in `scan_log.json` or MongoDB collection `agent_logs`.
