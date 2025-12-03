#!/bin/bash

# PayloadFactoryUX Agent Deployment Script

# Default to User's IP if not provided
SERVER_IP=${1:-"192.168.1.170"}
SERVER_URL="http://$SERVER_IP:8000"

echo "[*] Using Server IP: $SERVER_IP"

echo "[*] Installing dependencies..."

# Try apt first (Debian/Ubuntu/Kali) - Best for system packages
if command -v apt &> /dev/null; then
    echo "[*] Attempting to install python3-requests via apt..."
    sudo apt update && sudo apt install -y python3-requests
else
    # Fallback to pip
    if command -v pip3 &> /dev/null; then
        echo "[*] Attempting to install requests via pip..."
        pip3 install requests --break-system-packages || pip3 install requests
    else
        echo "[!] pip not found. Please install python3-requests manually."
        exit 1
    fi
fi

echo "[*] Starting Agent connecting to $SERVER_URL..."
# Run in background or foreground? Let's run in foreground for now so user sees output
python3 linux_agent.py --server "$SERVER_URL"
