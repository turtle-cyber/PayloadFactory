import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import subprocess
import threading
import os
import sys

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

        # --- Main Area ---
        self.top_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.top_frame.grid(row=0, column=1, padx=20, pady=20, sticky="ew")
        
        self.folder_label = ctk.CTkLabel(self.top_frame, text="Target Folder:", font=ctk.CTkFont(size=14))
        self.folder_label.pack(side="left", padx=(0, 10))
        
        self.folder_entry = ctk.CTkEntry(self.top_frame, width=400)
        self.folder_entry.pack(side="left", padx=(0, 10))
        
        self.browse_btn = ctk.CTkButton(self.top_frame, text="Browse", width=100, command=self.browse_folder)
        self.browse_btn.pack(side="left")
        
        self.start_btn = ctk.CTkButton(self.top_frame, text="Start Scan", width=100, fg_color="green", hover_color="darkgreen", command=self.start_scan)
        self.start_btn.pack(side="left", padx=10)

        # --- Attack Mode Options ---
        self.attack_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.attack_frame.grid(row=0, column=1, padx=20, pady=(60, 0), sticky="ew") # Below top_frame
        
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

        # --- Console Output ---
        self.console_label = ctk.CTkLabel(self, text="Scan Logs & Vulnerability Reports:", font=ctk.CTkFont(size=14, weight="bold"))
        self.console_label.grid(row=0, column=1, padx=20, pady=(120, 0), sticky="w") # Adjusted padding

        self.console_box = ctk.CTkTextbox(self, width=600, font=("Consolas", 12))
        self.console_box.grid(row=1, column=1, padx=20, pady=(10, 20), sticky="nsew")
        self.console_box.configure(state="disabled")

        # --- Exploit List (Right Side - Optional, keeping simple for now) ---
        
        self.process = None

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

if __name__ == "__main__":
    app = PayloadFactoryApp()
    app.mainloop()
