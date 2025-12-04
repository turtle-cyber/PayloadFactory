import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import subprocess
import threading
import os
import sys
import logging
import json
# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "ml_engine")))
from ml_engine.logger_config import setup_logger

# Configure logging (JSON)
logger = setup_logger(__name__, "scan_log.json")

# Configure appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PayloadFactoryApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("PayloadFactoryUX - Testing Console")
        self.geometry("1000x700")

        # Layout configuration
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="PayloadFactoryUX", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.scan_btn = ctk.CTkButton(self.sidebar_frame, text="New Scan", command=self.reset_ui)
        self.scan_btn.grid(row=1, column=0, padx=20, pady=10)
        
        self.open_exploits_btn = ctk.CTkButton(self.sidebar_frame, text="Open Exploits Folder", command=self.open_exploits_folder)
        self.open_exploits_btn.grid(row=2, column=0, padx=20, pady=10)

        # --- Main Area (Tabs) ---
        self.tab_view = ctk.CTkTabview(self, width=800)
        self.tab_view.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.scan_tab = self.tab_view.add("Scan Mode")
        self.agent_tab = self.tab_view.add("Agent Mode")
        
        # --- SCAN TAB CONTENT ---
        self.top_frame = ctk.CTkFrame(self.scan_tab, fg_color="transparent")
        self.top_frame.pack(fill="x", pady=10)
        
        self.folder_label = ctk.CTkLabel(self.top_frame, text="Target Folder:", font=ctk.CTkFont(size=14))
        self.folder_label.pack(side="left", padx=(0, 10))
        
        self.folder_entry = ctk.CTkEntry(self.top_frame, width=400)
        self.folder_entry.pack(side="left", padx=(0, 10))
        
        self.browse_btn = ctk.CTkButton(self.top_frame, text="Browse", width=100, command=self.browse_folder)
        self.browse_btn.pack(side="left")
        
        self.start_btn = ctk.CTkButton(self.top_frame, text="Start Scan", width=100, fg_color="green", hover_color="darkgreen", command=self.start_scan)
        self.start_btn.pack(side="left", padx=10)
        
        # Deep Thinking: Quick scan checkbox placement
        # - Place between folder selection and attack mode (logical flow)
        # - Prominent but not intrusive
        # - Tooltip provides clarity without cluttering UI
        # - Default unchecked for backward compatibility
        self.quick_scan_frame = ctk.CTkFrame(self.scan_tab, fg_color="transparent")
        self.quick_scan_frame.pack(fill="x", pady=10)
        
        self.quick_scan_var = ctk.BooleanVar(value=False)  # Default: full scan
        self.quick_scan_check = ctk.CTkCheckBox(
            self.quick_scan_frame, 
            text="⚡ Quick Scan (MVP Mode - ~2 hours)",
            variable=self.quick_scan_var,
            font=ctk.CTkFont(size=13, weight="bold")
        )
        self.quick_scan_check.pack(side="left", padx=(0, 10))
        
        self.quick_scan_info = ctk.CTkLabel(
            self.quick_scan_frame,
            text="(Scans only top ~300 security-critical files)",
            text_color="gray",
            font=ctk.CTkFont(size=11)
        )
        self.quick_scan_info.pack(side="left")

        # Demo Mode Checkbox
        self.demo_mode_var = ctk.BooleanVar(value=False)
        self.demo_mode_check = ctk.CTkCheckBox(
            self.quick_scan_frame,
            text="🔥 Demo Mode (Paranoid)",
            variable=self.demo_mode_var,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="red", hover_color="darkred"
        )
        self.demo_mode_check.pack(side="left", padx=(20, 10))

        # Attack Mode Options (Inside Scan Tab)
        self.attack_frame = ctk.CTkFrame(self.scan_tab, fg_color="transparent")
        self.attack_frame.pack(fill="x", pady=20)
        
        self.attack_mode_var = ctk.BooleanVar(value=False)
        self.attack_check = ctk.CTkCheckBox(self.attack_frame, text="Enable Attack Mode (Stage 3)", variable=self.attack_mode_var, command=self.toggle_attack_inputs)
        self.attack_check.pack(side="left", padx=(0, 20))
        
        self.ip_label = ctk.CTkLabel(self.attack_frame, text="Target IP:")
        self.ip_label.pack(side="left", padx=(0, 5))
        self.ip_entry = ctk.CTkEntry(self.attack_frame, width=120, placeholder_text="192.168.x.x")
        self.ip_entry.pack(side="left", padx=(0, 15))
        
        self.port_label = ctk.CTkLabel(self.attack_frame, text="Port:")
        self.port_label.pack(side="left", padx=(0, 5))
        self.port_entry = ctk.CTkEntry(self.attack_frame, width=60, placeholder_text="80")
        self.port_entry.pack(side="left")
        
        self.toggle_attack_inputs() # Initialize state

        # --- AGENT TAB CONTENT ---
        self.agent_info = ctk.CTkLabel(self.agent_tab, text="Run the following command on your Linux target:", font=ctk.CTkFont(size=14, weight="bold"))
        self.agent_info.pack(pady=(20, 10))
        
        self.agent_cmd = ctk.CTkEntry(self.agent_tab, width=600)
        self.agent_cmd.insert(0, "python3 linux_agent.py --server http://192.168.1.170:8000")
        self.agent_cmd.pack(pady=5)
        
        self.agent_status = ctk.CTkLabel(self.agent_tab, text="Live Agent Logs:", text_color="gray")
        self.agent_status.pack(pady=(20, 5))
        
        self.agent_log_box = ctk.CTkTextbox(self.agent_tab, width=700, height=300, font=("Consolas", 11))
        self.agent_log_box.pack(pady=10)
        self.agent_log_box.configure(state="disabled")
        
        # Start polling for logs
        self.last_log_pos = 0

        # --- Console Output ---
        self.console_label = ctk.CTkLabel(self, text="Scan Logs & Vulnerability Reports:", font=ctk.CTkFont(size=14, weight="bold"))
        self.console_label.grid(row=0, column=1, padx=20, pady=(120, 0), sticky="w") # Adjusted padding

        self.console_box = ctk.CTkTextbox(self, width=600, font=("Consolas", 12))
        self.console_box.grid(row=1, column=1, padx=20, pady=(10, 20), sticky="nsew")
        self.console_box.configure(state="disabled")

        # --- Exploit List (Right Side - Optional, keeping simple for now) ---

        self.process = None
        self.server_started = False

        # Defer server start and log polling until after UI is fully initialized
        self.after(100, self._post_init_tasks)

    def _post_init_tasks(self):
        """Initialize non-UI tasks after the window is displayed"""
        # Start server in background
        self.start_server()
        # Start log polling
        self.after(2000, self.poll_agent_logs)

    def start_server(self):
        """Start API server in background thread without blocking UI"""
        if self.server_started:
            return

        def run_uvicorn():
            try:
                # Run uvicorn programmatically or via subprocess
                # Redirect stderr to a file to capture startup errors
                with open("server_error.log", "w") as err_file:
                    cmd = [sys.executable, "-m", "uvicorn", "server.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
                    subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW, stderr=err_file, stdout=err_file)
                logger.info("API Server started on port 8000")
                self.server_started = True
            except Exception as e:
                logger.error(f"Failed to start API server: {e}")

        threading.Thread(target=run_uvicorn, daemon=True).start()

    def toggle_attack_inputs(self):
        state = "normal" if self.attack_mode_var.get() else "disabled"
        self.ip_entry.configure(state=state)
        self.port_entry.configure(state=state)

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_entry.delete(0, "end")
            self.folder_entry.insert(0, folder_selected)

    def log(self, message):
        self.console_box.configure(state="normal")
        self.console_box.insert("end", message + "\n")
        self.console_box.see("end")
        self.console_box.configure(state="disabled")

    def start_scan(self):
        target_dir = self.folder_entry.get()
        if not target_dir or not os.path.exists(target_dir):
            self.log("Error: Please select a valid target folder.")
            return

        # Get Attack Args
        remote_host = None
        remote_port = None
        if self.attack_mode_var.get():
            remote_host = self.ip_entry.get().strip()
            remote_port = self.port_entry.get().strip()
            if not remote_host or not remote_port:
                self.log("Error: Attack Mode enabled but IP/Port missing.")
                return

        self.start_btn.configure(state="disabled", text="Scanning...")
        self.log(f"\n--- Starting Scan on: {target_dir} ---\n")
        
        # Deep Thinking: User feedback for scan mode
        # - Clear messaging about what will happen
        # - Sets proper expectations for completion time
        # - Visible in console so user can verify settings
        if self.quick_scan_var.get():
            self.log("--- QUICK SCAN MODE: Prioritizing top ~300 security-critical files ---")
            self.log("--- Estimated time: 1.5-2.5 hours ---\n")
        elif self.demo_mode_var.get():
            self.log("--- DEMO MODE ENABLED: Paranoid scanning for critical targets ---")
        else:
            self.log("--- FULL SCAN: All files will be scanned ---")
            self.log("--- This may take several hours ---\n")
        
        if remote_host:
            self.log(f"--- ATTACK MODE: Targeting {remote_host}:{remote_port} ---\n")

        # Run in a separate thread to keep UI responsive
        threading.Thread(target=self.run_scan_script, args=(target_dir, remote_host, remote_port), daemon=True).start()

    def run_scan_script(self, target_dir, remote_host=None, remote_port=None):
        # Path to python executable and script
        python_exe = sys.executable
        script_path = os.path.join(os.path.dirname(__file__), "scan_and_exploit.py")
        
        cmd = [python_exe, script_path, target_dir]
        
        if remote_host and remote_port:
            cmd.extend(["--remote-host", remote_host, "--remote-port", remote_port])
        
        # Deep Thinking: Flag propagation from GUI
        # - Simple boolean check - either quick or full scan
        # - Could add max_files customization but keeping simple for MVP
        # - Flag is passed to orchestrator which handles stage coordination
        if self.quick_scan_var.get():
            cmd.append("--quick-scan")
            
        if self.demo_mode_var.get():
            cmd.append("--demo-mode")
        
        try:
            # Force UTF-8 encoding for the subprocess output
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"

            # Use Popen to capture output in real-time
            self.process = subprocess.Popen(
                cmd, 
                env=env, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1, 
                encoding='utf-8',
                errors='replace' # Handle invalid chars gracefully
            )

            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.after(0, self.log, line.strip())
            
            self.process.stdout.close()
            return_code = self.process.wait()
            
            self.after(0, self.scan_finished, return_code)

        except Exception as e:
            self.after(0, self.log, f"Error running script: {e}")
            self.after(0, self.scan_finished, -1)

    def scan_finished(self, return_code):
        self.start_btn.configure(state="normal", text="Start Scan")
        if return_code == 0:
            self.log("\n--- Scan Completed Successfully ---")
        else:
            self.log(f"\n--- Scan Failed with Exit Code {return_code} ---")

    def open_exploits_folder(self):
        exploits_dir = os.path.join(os.path.dirname(__file__), "exploits")
        if not os.path.exists(exploits_dir):
            os.makedirs(exploits_dir)
        os.startfile(exploits_dir)

    def reset_ui(self):
        self.console_box.configure(state="normal")
        self.console_box.delete("1.0", "end")
        self.console_box.configure(state="disabled")
        self.folder_entry.delete(0, "end")

    def poll_agent_logs(self):
        """Poll agent logs in a more efficient way"""
        try:
            log_file = "scan_log.json"
            if os.path.exists(log_file):
                file_size = os.path.getsize(log_file)
                # Only read if file has grown since last check
                if file_size > self.last_log_pos:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self.last_log_pos)
                        # Read only up to 100KB at a time to prevent UI lag
                        chunk_size = min(100 * 1024, file_size - self.last_log_pos)
                        if chunk_size > 0:
                            content = f.read(chunk_size)
                            self.last_log_pos = f.tell()

                            # Process lines without blocking
                            lines = content.split('\n')
                            for line in lines[:50]:  # Limit to 50 lines per poll to prevent lag
                                if "Received agent log" in line:
                                    try:
                                        log_entry = json.loads(line)
                                        msg = f"[{log_entry.get('timestamp', 'N/A')}] {log_entry.get('message', line)}"
                                        self.agent_log_box.configure(state="normal")
                                        self.agent_log_box.insert("end", msg + "\n")
                                        self.agent_log_box.see("end")
                                        self.agent_log_box.configure(state="disabled")
                                    except:
                                        pass
        except Exception as e:
            # Silently handle errors to prevent log spam
            pass

        # Continue polling
        self.after(2000, self.poll_agent_logs)

if __name__ == "__main__":
    app = PayloadFactoryApp()
    app.mainloop()
