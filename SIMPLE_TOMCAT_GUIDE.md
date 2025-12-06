# Simple Tomcat Log Setup - Step by Step

## What This Does

Your **fuzzer** (Windows machine) needs to know what's happening **inside** your Tomcat server (Linux machine) when you attack it.

Think of it like this:
```
You attack Tomcat → Tomcat crashes → We need to know WHY it crashed
```

The agent sends Tomcat's error logs back to your fuzzer so the RL module can learn.

---

## The Setup (2 Machines)

### **Machine 1: Windows (Your Fuzzer)**
- This is where you're running `gui_launcher.py`
- This is where PayloadFactoryUX is installed
- IP: `192.168.1.170` (example - yours might be different)

### **Machine 2: Linux (Target with Tomcat)**
- This is where Apache Tomcat is running
- This is the server you're attacking
- IP: `192.168.1.131` (example - yours might be different)

---

## Step-by-Step Instructions

### 🔹 STEP 1: Find Your Windows Machine's IP

On your **Windows machine**, open CMD and run:
```cmd
ipconfig
```

Look for "IPv4 Address" - this is your **FUZZER_IP**

Example output:
```
IPv4 Address. . . . . . . . . . . : 192.168.1.170
```

**Write this down:** My FUZZER_IP = `______________`

---

### 🔹 STEP 2: Copy the Agent to Linux

You need to get `tomcat_agent.py` onto your Linux machine.

**Option A: If you have SSH access**
```bash
# On Windows CMD (from PayloadFactoryUX folder)
scp tomcat_agent.py username@192.168.1.131:/home/username/
```
Replace:
- `username` with your Linux username
- `192.168.1.131` with your Linux machine's IP

**Option B: No SSH? Copy manually**
1. Open `tomcat_agent.py` in Notepad
2. Copy all the text
3. On Linux, run: `nano ~/tomcat_agent.py`
4. Paste the text
5. Press Ctrl+X, then Y, then Enter to save

**Option C: Use USB drive**
1. Copy `tomcat_agent.py` to USB
2. Plug USB into Linux machine
3. Copy file from USB: `cp /media/usb/tomcat_agent.py ~/`

---

### 🔹 STEP 3: Run the Agent on Linux

On your **Linux machine** (where Tomcat is running):

```bash
# First, make sure you're in the right directory
cd ~

# Run the agent (replace 192.168.1.170 with YOUR Windows IP)
sudo python3 tomcat_agent.py --server http://192.168.1.170:8000
```

**What you should see:**
```
============================================================
Tomcat Fuzzing Agent
============================================================
Server: http://192.168.1.170:8000/agent/logs
Hostname: ubuntu-server (192.168.1.131)
Verbose: False
============================================================
[+] Auto-discovered catalina.out: /opt/tomcat/logs/catalina.out
[+] Monitoring: /opt/tomcat/logs/catalina.out

[*] Starting monitoring... (Press Ctrl+C to stop)
```

✅ **Leave this running!** Don't close this terminal.

---

### 🔹 STEP 4: Verify Connection

On your **Windows machine**, open a browser and go to:
```
http://localhost:8000/health
```

You should see:
```json
{"status":"healthy"}
```

✅ This means your server is running!

---

### 🔹 STEP 5: Run Your Fuzzing Attack

On your **Windows machine**, open the GUI:

```cmd
python gui_launcher.py
```

**In the GUI:**
1. Go to the **"Scan Mode"** tab
2. Check the box: ☑ **"Enable Attack Mode (Stage 3)"**
3. Enter **Target IP**: `192.168.1.131` (your Linux Tomcat IP)
4. Enter **Port**: `8080` (or whatever port Tomcat uses)
5. Click **"Start Scan"**

---

### 🔹 STEP 6: Watch the Logs

In the GUI, click the **"Agent Mode"** tab.

You should start seeing logs like:
```
[2024-12-06 16:30:15] Received agent log from ubuntu-server: [!] RCE: exec -> java.lang.Runtime.exec() detected
[2024-12-06 16:30:18] Received agent log from ubuntu-server: [!] CRASH: OutOfMemoryError -> Tomcat ran out of memory
```

✅ **This means it's working!**

---

## Visual Diagram

```
┌─────────────────────────────────────────────────────┐
│  WINDOWS MACHINE (192.168.1.170)                   │
│                                                     │
│  ┌──────────────────┐         ┌─────────────────┐  │
│  │  gui_launcher.py │ ◄────── │ Server :8000    │  │
│  │  (You attack)    │         │ (Receives logs) │  │
│  └────────┬─────────┘         └────────▲────────┘  │
│           │                             │          │
│           │ Sends fuzzing               │          │
│           │ payloads                    │          │
└───────────┼─────────────────────────────┼──────────┘
            │                             │
            │                             │ Sends logs
            ▼                             │
┌─────────────────────────────────────────┼──────────┐
│  LINUX MACHINE (192.168.1.131)          │          │
│                                         │          │
│  ┌──────────────────┐    ┌─────────────┴────────┐ │
│  │  Apache Tomcat   │    │  tomcat_agent.py     │ │
│  │  :8080           │───►│  (Monitors logs)     │ │
│  │  (Under attack)  │    │                      │ │
│  └──────────────────┘    └──────────────────────┘ │
│                                                    │
│  Tomcat crashes → Agent sees error → Sends to     │
│  Windows fuzzer → RL learns → Next attack smarter │
└────────────────────────────────────────────────────┘
```

---

## Troubleshooting

### ❌ Problem: "Connection refused" when running agent

**Cause:** Windows firewall is blocking port 8000

**Fix on Windows:**
1. Search "Windows Firewall" in Start menu
2. Click "Advanced settings"
3. Click "Inbound Rules" → "New Rule"
4. Select "Port" → Next
5. Enter "8000" → Next
6. Allow the connection → Next → Finish

**Quick test:**
```bash
# On Linux, test if you can reach Windows
telnet 192.168.1.170 8000
```

If it connects, you'll see: `Connected to 192.168.1.170`

---

### ❌ Problem: "Permission denied" on catalina.out

**Cause:** You're not running as root/sudo

**Fix:**
```bash
# Always use sudo
sudo python3 tomcat_agent.py --server http://192.168.1.170:8000
```

---

### ❌ Problem: "Could not find Tomcat logs"

**Cause:** Tomcat is installed in a non-standard location

**Fix - Find where Tomcat logs are:**
```bash
# Run this to find Tomcat
ps aux | grep tomcat

# Look for something like:
# -Dcatalina.home=/usr/local/tomcat

# Then specify the exact path:
sudo python3 tomcat_agent.py --server http://192.168.1.170:8000 \
  --catalina-path /usr/local/tomcat/logs/catalina.out
```

---

### ❌ Problem: No logs appearing in GUI

**Checklist:**

1. ✅ Is the agent running on Linux?
   ```bash
   # On Linux, check:
   ps aux | grep tomcat_agent
   ```
   Should show the python process running.

2. ✅ Can Linux reach Windows?
   ```bash
   # On Linux:
   ping 192.168.1.170
   ```
   Should get replies.

3. ✅ Is the server running on Windows?
   ```cmd
   # On Windows:
   netstat -an | findstr 8000
   ```
   Should show: `LISTENING` on port 8000

4. ✅ Is MongoDB running?
   ```cmd
   # On Windows:
   netstat -an | findstr 27017
   ```
   Should show connections.

---

## Testing Without Fuzzing

Want to test if logs are flowing **before** running a full attack?

### Test 1: Manual Log Entry

**On Linux:**
```bash
# Trigger a fake Tomcat error
echo "SEVERE: OutOfMemoryError test" >> /opt/tomcat/logs/catalina.out
```

**On Windows GUI:**
- Check the "Agent Mode" tab
- You should see the error appear within 2 seconds

### Test 2: Real Tomcat Error

**On Linux:**
```bash
# Access an invalid URL to trigger a 404
curl http://localhost:8080/this-does-not-exist
```

**On Windows GUI:**
- Check the "Agent Mode" tab
- You should see the 404 error log

---

## What Happens Next?

Once logs are flowing:

1. **Fuzzer sends payload** to Tomcat
2. **Tomcat crashes/errors**
3. **Agent sees error in catalina.out**
4. **Agent sends error to Windows**
5. **RL module learns:** "This payload caused OutOfMemoryError"
6. **Next payload is smarter** based on what worked

This is called **feedback-driven fuzzing** - the fuzzer learns from the target's reactions!

---

## Summary Checklist

- [ ] I found my Windows IP: `______________`
- [ ] I copied `tomcat_agent.py` to Linux
- [ ] I ran the agent with sudo on Linux
- [ ] I see "Monitoring: /opt/tomcat/logs/catalina.out"
- [ ] I can access http://localhost:8000/health on Windows
- [ ] I enabled Attack Mode in the GUI
- [ ] I see logs in the "Agent Mode" tab

✅ **All checked?** You're ready to fuzz Tomcat!

---

## Still Confused?

Show me:
1. The **error message** you're getting
2. The **IP addresses** of both machines
3. The **output** when you run the agent

I'll help you debug it!
