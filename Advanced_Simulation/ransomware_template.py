"""
Advanced Ransomware Simulation - Professional Edition
Team: DON'T WANNA CRY
Purpose: Security Training & Detection Testing
WARNING: Educational purposes only - Simulates ransomware behavior
"""

import os
import sys
import time
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
import logging
import json
import base64
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import secrets

# ============================================================================
# CONFIGURATION
# ============================================================================

class SimulationConfig:
    """Centralized configuration for ransomware simulation"""
    
    # Target Configuration
    TARGET_DIR = "target_data"
    BACKUP_DIR = ".simulation_backup"
    
    # File Extensions to Target (Realistic)
    TARGET_EXTENSIONS = [
        '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
        '.zip', '.rar', '.7z', '.sql', '.db', '.csv', '.xml', '.json'
    ]
    
    # Ransom Note
    NOTE_FILENAME = "!!!READ_ME_TO_DECRYPT!!!.txt"
    LOCKED_EXTENSION = ".locked"
    
    # Visual Configuration
    BG_COLOR = "#0a0a0a"
    TXT_COLOR = "#00ff41"
    ALERT_COLOR = "#ff0000"
    WARNING_COLOR = "#ffaa00"
    
    # Timing Configuration
    COUNTDOWN_HOURS = 72
    ENCRYPTION_DELAY = 0.3  # Seconds between file operations
    
    # Behavioral Evasion
    MAX_FILES_PER_DIR = 100  # Limit to avoid suspicion
    ENABLE_SANDBOX_DETECTION = True
    ENABLE_VM_DETECTION = True
    
    # Persistence Simulation
    SIMULATE_PERSISTENCE = True
    WALLPAPER_CHANGE = True

# ============================================================================
# ANTI-ANALYSIS & EVASION TECHNIQUES
# ============================================================================

class EvasionTechniques:
    """Advanced evasion and anti-analysis techniques"""
    
    @staticmethod
    def detect_sandbox():
        """Detect common sandbox environments"""
        sandbox_indicators = [
            'C:\\analysis',
            'C:\\sandbox',
            'C:\\malware',
            'C:\\sample'
        ]
        
        for indicator in sandbox_indicators:
            if os.path.exists(indicator):
                return True
        
        # Check for common sandbox usernames
        username = os.environ.get('USERNAME', '').lower()
        sandbox_users = ['sandbox', 'malware', 'virus', 'sample', 'analyst']
        if any(user in username for user in sandbox_users):
            return True
            
        return False
    
    @staticmethod
    def detect_vm():
        """Detect virtual machine environment"""
        vm_indicators = [
            'VBOX',
            'VirtualBox',
            'VMware',
            'QEMU',
            'Xen'
        ]
        
        # Check system manufacturer
        try:
            import platform
            system_info = platform.platform().lower()
            for indicator in vm_indicators:
                if indicator.lower() in system_info:
                    return True
        except:
            pass
            
        return False
    
    @staticmethod
    def check_mouse_movement():
        """Detect automated environments by checking mouse activity"""
        try:
            import win32api
            pos1 = win32api.GetCursorPos()
            time.sleep(2)
            pos2 = win32api.GetCursorPos()
            return pos1 != pos2
        except:
            return True  # Assume real environment if check fails
    
    @staticmethod
    def sleep_evasion():
        """Time-based evasion to avoid automated analysis"""
        start = time.time()
        time.sleep(3)
        elapsed = time.time() - start
        
        # If sleep was accelerated (common in sandboxes), it's likely automated
        return elapsed >= 2.5

# ============================================================================
# ENCRYPTION SIMULATION ENGINE
# ============================================================================

class EncryptionSimulator:
    """Simulates file encryption without actual cryptography"""
    
    def __init__(self, callback=None):
        self.callback = callback
        self.processed_files = []
        self.failed_files = []
        self.session_id = secrets.token_hex(16)
        
    def log(self, message, level="INFO"):
        """Thread-safe logging with callback"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] [{level}] {message}"
        
        if self.callback:
            self.callback(log_msg, level)
        else:
            print(log_msg)
    
    def create_test_environment(self):
        """Create realistic test files for simulation"""
        self.log("Initializing test environment...", "INIT")
        
        if not os.path.exists(SimulationConfig.TARGET_DIR):
            os.makedirs(SimulationConfig.TARGET_DIR)
        
        # Create backup directory
        if not os.path.exists(SimulationConfig.BACKUP_DIR):
            os.makedirs(SimulationConfig.BACKUP_DIR)
        
        # Create diverse test files
        test_files = {
            'financial_report_2024.xlsx': 'Financial Data\n' * 50,
            'project_proposal.docx': 'Important Document\n' * 50,
            'client_database.db': 'Database Records\n' * 50,
            'presentation.pptx': 'Presentation Content\n' * 50,
            'backup_codes.txt': 'Backup Information\n' * 50,
            'family_photos.jpg': 'Photo Data\n' * 50,
            'contracts.pdf': 'Legal Documents\n' * 50,
            'source_code.py': 'print("Important Code")\n' * 50,
        }
        
        for filename, content in test_files.items():
            filepath = os.path.join(SimulationConfig.TARGET_DIR, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        self.log(f"Created {len(test_files)} test files", "OK")
    
    def backup_file(self, filepath):
        """Create backup before 'encryption'"""
        try:
            backup_path = os.path.join(
                SimulationConfig.BACKUP_DIR,
                os.path.basename(filepath)
            )
            
            with open(filepath, 'rb') as src:
                with open(backup_path, 'wb') as dst:
                    dst.write(src.read())
            return True
        except Exception as e:
            self.log(f"Backup failed for {filepath}: {e}", "ERROR")
            return False
    
    def simulate_encryption(self, filepath):
        """Simulate file encryption by renaming"""
        try:
            # Backup original file
            self.backup_file(filepath)
            
            # Simulate encryption by renaming
            locked_path = filepath + SimulationConfig.LOCKED_EXTENSION
            os.rename(filepath, locked_path)
            
            self.processed_files.append(locked_path)
            return True
            
        except Exception as e:
            self.log(f"Failed to process {filepath}: {e}", "ERROR")
            self.failed_files.append(filepath)
            return False
    
    def generate_ransom_note(self):
        """Generate realistic ransom note"""
        note_content = f"""
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ██████╗  ██████╗ ███╗   ██╗████████╗    ██╗    ██╗ █████╗ ███╗   ██╗████████╗ ██████╗██████╗ ██╗   ██╗    ██████╗██████╗ ██╗   ██╗
║   ██╔══██╗██╔═══██╗████╗  ██║╚══██╔══╝    ██║    ██║██╔══██╗████╗  ██║╚══██╔══╝██╔════╝██╔══██╗╚██╗ ██╔╝   ██╔════╝██╔══██╗╚██╗ ██╔╝
║   ██║  ██║██║   ██║██╔██╗ ██║   ██║       ██║ █╗ ██║███████║██╔██╗ ██║   ██║   ██║     ██████╔╝ ╚████╔╝    ██║     ██████╔╝ ╚████╔╝ 
║   ██║  ██║██║   ██║██║╚██╗██║   ██║       ██║███╗██║██╔══██║██║╚██╗██║   ██║   ██║     ██╔══██╗  ╚██╔╝     ██║     ██╔══██╗  ╚██╔╝  
║   ██████╔╝╚██████╔╝██║ ╚████║   ██║       ╚███╔███╔╝██║  ██║██║ ╚████║   ██║   ╚██████╗██║  ██║   ██║      ╚██████╗██║  ██║   ██║   
║   ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝        ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝       ╚═════╝╚═╝  ╚═╝   ╚═╝   
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

⚠️  WHAT HAPPENED TO YOUR FILES? ⚠️

Your important files (documents, photos, databases, etc.) have been encrypted
with military-grade encryption algorithms (RSA-4096 + AES-256).

🔒 YOUR FILES ARE NOW LOCKED:
   • All your documents, photos, databases are encrypted
   • No one can recover your files without our decryption key
   • File recovery tools will NOT work - they will destroy your data
   • This is a SIMULATION for security training purposes

⏰ TIME IS RUNNING OUT:
   • You have 72 HOURS to restore your files
   • After this time, the decryption key will be destroyed
   • Your files will be PERMANENTLY LOST

📋 SIMULATION INFORMATION:
   • Session ID: {self.session_id}
   • Encrypted Files: {len(self.processed_files)}
   • Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
   • Team: DON'T WANNA CRY

🔓 HOW TO RESTORE YOUR FILES:
   1. Click the "UNLOCK / RESTORE SYSTEM" button in the GUI
   2. All files will be automatically restored from backup
   3. This is a controlled simulation - no real harm done

⚠️  WARNING - DO NOT:
   × Do not delete this file
   × Do not rename encrypted files
   × Do not try to decrypt files manually
   × Do not restart your computer (in real attack)

📧 CONTACT (Simulation Only):
   This is a SECURITY TRAINING SIMULATION
   No real encryption has occurred
   All files can be restored safely

═══════════════════════════════════════════════════════════════════════

Remember: This demonstrates why you need:
✓ Regular backups
✓ Updated antivirus
✓ Security awareness training
✓ Network segmentation
✓ Email filtering

Stay safe. Stay secure.

═══════════════════════════════════════════════════════════════════════
"""
        
        note_path = os.path.join(
            SimulationConfig.TARGET_DIR,
            SimulationConfig.NOTE_FILENAME
        )
        
        with open(note_path, 'w', encoding='utf-8') as f:
            f.write(note_content)
        
        self.log(f"Ransom note created: {note_path}", "OK")
    
    def run_simulation(self):
        """Execute the full encryption simulation"""
        self.log("=" * 60, "INIT")
        self.log("RANSOMWARE SIMULATION INITIATED", "INIT")
        self.log("=" * 60, "INIT")
        
        # Create test environment
        self.create_test_environment()
        time.sleep(1)
        
        # Evasion checks
        if SimulationConfig.ENABLE_SANDBOX_DETECTION:
            if EvasionTechniques.detect_sandbox():
                self.log("Sandbox detected - Proceeding with simulation anyway", "WARN")
        
        if SimulationConfig.ENABLE_VM_DETECTION:
            if EvasionTechniques.detect_vm():
                self.log("Virtual Machine detected - Proceeding with simulation", "WARN")
        
        # Start encryption simulation
        self.log("Beginning file encryption simulation...", "PROC")
        time.sleep(0.5)
        
        file_count = 0
        for root, dirs, files in os.walk(SimulationConfig.TARGET_DIR):
            for filename in files:
                # Skip already locked files and ransom notes
                if filename.endswith(SimulationConfig.LOCKED_EXTENSION):
                    continue
                if filename == SimulationConfig.NOTE_FILENAME:
                    continue
                
                filepath = os.path.join(root, filename)
                
                # Check file extension
                _, ext = os.path.splitext(filename)
                if ext.lower() not in SimulationConfig.TARGET_EXTENSIONS:
                    continue
                
                # Simulate encryption
                self.log(f"Encrypting: {filename}", "PROC")
                
                if self.simulate_encryption(filepath):
                    self.log(f"✓ Locked: {filename}", "OK")
                    file_count += 1
                    time.sleep(SimulationConfig.ENCRYPTION_DELAY)
                
                # Limit files per directory
                if file_count >= SimulationConfig.MAX_FILES_PER_DIR:
                    break
        
        # Generate ransom note
        self.generate_ransom_note()
        
        # Summary
        self.log("=" * 60, "DONE")
        self.log(f"SIMULATION COMPLETE", "DONE")
        self.log(f"Files Encrypted: {len(self.processed_files)}", "DONE")
        self.log(f"Files Failed: {len(self.failed_files)}", "DONE")
        self.log("=" * 60, "DONE")

# ============================================================================
# GRAPHICAL USER INTERFACE
# ============================================================================

class RansomwareGUI:
    """Professional ransomware GUI simulation"""
    
    def __init__(self, root):
        self.root = root
        self.encryption_complete = False
        self.countdown_seconds = SimulationConfig.COUNTDOWN_HOURS * 3600
        
        self._setup_window()
        self._create_ui()
        self._start_simulation()
        self._start_countdown()
    
    def _setup_window(self):
        """Configure main window"""
        self.root.title("CRITICAL SECURITY ALERT")
        self.root.configure(bg=SimulationConfig.BG_COLOR)
        
        # Fullscreen and topmost
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        
        # Disable close button
        self.root.protocol("WM_DELETE_WINDOW", self._on_close_attempt)
        
        # Bind escape key for emergency exit (for testing)
        self.root.bind("<Escape>", lambda e: self._emergency_exit())
    
    def _create_ui(self):
        """Create the user interface"""
        
        # Header - Critical Alert
        header_frame = tk.Frame(self.root, bg=SimulationConfig.ALERT_COLOR, height=100)
        header_frame.pack(fill="x", pady=0)
        
        tk.Label(
            header_frame,
            text="⚠️ CRITICAL SYSTEM ALERT ⚠️",
            bg=SimulationConfig.ALERT_COLOR,
            fg="white",
            font=("Impact", 48, "bold")
        ).pack(pady=20)
        
        # Team Banner
        tk.Label(
            self.root,
            text="═══ Team DON'T WANNA CRY ═══",
            bg=SimulationConfig.BG_COLOR,
            fg=SimulationConfig.WARNING_COLOR,
            font=("Courier New", 28, "bold")
        ).pack(pady=15)
        
        # Main Message
        message_frame = tk.Frame(self.root, bg=SimulationConfig.BG_COLOR)
        message_frame.pack(pady=10)
        
        messages = [
            "Your files have been encrypted!",
            "All your important documents, photos, and databases are now locked.",
            "You cannot access them without our decryption key."
        ]
        
        for msg in messages:
            tk.Label(
                message_frame,
                text=msg,
                bg=SimulationConfig.BG_COLOR,
                fg=SimulationConfig.TXT_COLOR,
                font=("Arial", 16)
            ).pack(pady=3)
        
        # Countdown Timer
        timer_frame = tk.Frame(self.root, bg=SimulationConfig.BG_COLOR)
        timer_frame.pack(pady=20)
        
        tk.Label(
            timer_frame,
            text="Time Remaining Until Files Are Lost Forever:",
            bg=SimulationConfig.BG_COLOR,
            fg="white",
            font=("Arial", 14)
        ).pack()
        
        self.timer_label = tk.Label(
            timer_frame,
            text="72:00:00",
            bg=SimulationConfig.BG_COLOR,
            fg=SimulationConfig.ALERT_COLOR,
            font=("DS-Digital", 72, "bold")
        )
        self.timer_label.pack(pady=10)
        
        # Activity Log
        log_frame = tk.Frame(self.root, bg=SimulationConfig.BG_COLOR)
        log_frame.pack(fill="both", expand=True, padx=50, pady=20)
        
        tk.Label(
            log_frame,
            text="═══ ENCRYPTION ACTIVITY LOG ═══",
            bg=SimulationConfig.BG_COLOR,
            fg=SimulationConfig.WARNING_COLOR,
            font=("Courier New", 14, "bold")
        ).pack()
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            bg="#0d0d0d",
            fg=SimulationConfig.TXT_COLOR,
            font=("Consolas", 11),
            height=12,
            insertbackground=SimulationConfig.TXT_COLOR,
            state='disabled'
        )
        self.log_text.pack(fill="both", expand=True, pady=10)
        
        # Restore Button
        button_frame = tk.Frame(self.root, bg=SimulationConfig.BG_COLOR)
        button_frame.pack(pady=30)
        
        self.restore_btn = tk.Button(
            button_frame,
            text="🔓 UNLOCK / RESTORE SYSTEM 🔓",
            font=("Arial", 22, "bold"),
            bg="#ffffff",
            fg=SimulationConfig.ALERT_COLOR,
            activebackground="#ffcccc",
            activeforeground=SimulationConfig.ALERT_COLOR,
            padx=40,
            pady=20,
            command=self._restore_files,
            cursor="hand2"
        )
        self.restore_btn.pack()
        
        # Footer - Awareness Message
        disclaimer_frame = tk.Frame(self.root, bg="#1a0a0a", bd=2, relief="ridge")
        disclaimer_frame.pack(fill="x", side="bottom", pady=0)
        
        tk.Label(
            disclaimer_frame,
            text="💀 IF YOU DON'T WANNA CRY, DON'T LET YOUR GUARD DOWN! 💀",
            bg="#1a0a0a",
            fg="#ff4444",
            font=("Impact", 18)
        ).pack(pady=8)
        
        tk.Label(
            disclaimer_frame,
            text="This could have been real. Your files, your memories, your work — gone in seconds.",
            bg="#1a0a0a",
            fg="#ff9999",
            font=("Arial", 12, "italic")
        ).pack(pady=3)
        
        tk.Label(
            disclaimer_frame,
            text="One wrong click is all it takes. Stay vigilant. Stay protected. Stay safe.",
            bg="#1a0a0a",
            fg="#ffcc00",
            font=("Arial", 11, "bold")
        ).pack(pady=3)
        
        footer_frame = tk.Frame(disclaimer_frame, bg="#0f0505")
        footer_frame.pack(fill="x", pady=5)
        
        tk.Label(
            footer_frame,
            text="💀 RansomRun - Security Awareness Training 💀",
            bg="#0f0505",
            fg="#888888",
            font=("Arial", 10)
        ).pack()
        
        tk.Label(
            footer_frame,
            text="SIMULATION MODE - No actual harm done to your system | Press ESC to exit",
            bg="#0f0505",
            fg="#666666",
            font=("Arial", 9)
        ).pack()
    
    def _add_log(self, message, level="INFO"):
        """Add message to log window"""
        self.log_text.config(state='normal')
        
        # Color coding
        color = SimulationConfig.TXT_COLOR
        if level == "ERROR":
            color = SimulationConfig.ALERT_COLOR
        elif level == "WARN":
            color = SimulationConfig.WARNING_COLOR
        elif level == "OK":
            color = "#00ff00"
        elif level == "DONE":
            color = "#ffaa00"
        
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def _start_simulation(self):
        """Start encryption simulation in background thread"""
        def run():
            simulator = EncryptionSimulator(callback=self._add_log)
            simulator.run_simulation()
            self.encryption_complete = True
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
    
    def _start_countdown(self):
        """Start countdown timer"""
        def update_timer():
            if self.countdown_seconds > 0:
                self.countdown_seconds -= 1
                
                hours = self.countdown_seconds // 3600
                minutes = (self.countdown_seconds % 3600) // 60
                seconds = self.countdown_seconds % 60
                
                time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                self.timer_label.config(text=time_str)
                
                self.root.after(1000, update_timer)
            else:
                self.timer_label.config(text="TIME'S UP!", fg="#ff0000")
        
        update_timer()
    
    def _restore_files(self):
        """Restore all encrypted files"""
        self._add_log("=" * 60, "INIT")
        self._add_log("INITIATING FILE RESTORATION...", "INIT")
        self._add_log("=" * 60, "INIT")
        
        restored_count = 0
        failed_count = 0
        
        # Restore from backup
        if os.path.exists(SimulationConfig.BACKUP_DIR):
            for backup_file in os.listdir(SimulationConfig.BACKUP_DIR):
                backup_path = os.path.join(SimulationConfig.BACKUP_DIR, backup_file)
                original_path = os.path.join(SimulationConfig.TARGET_DIR, backup_file)
                
                try:
                    with open(backup_path, 'rb') as src:
                        with open(original_path, 'wb') as dst:
                            dst.write(src.read())
                    
                    self._add_log(f"✓ Restored: {backup_file}", "OK")
                    restored_count += 1
                except Exception as e:
                    self._add_log(f"✗ Failed: {backup_file}", "ERROR")
                    failed_count += 1
        
        # Remove locked files
        for root, dirs, files in os.walk(SimulationConfig.TARGET_DIR):
            for filename in files:
                if filename.endswith(SimulationConfig.LOCKED_EXTENSION):
                    try:
                        os.remove(os.path.join(root, filename))
                    except:
                        pass
        
        # Remove ransom note
        note_path = os.path.join(SimulationConfig.TARGET_DIR, SimulationConfig.NOTE_FILENAME)
        if os.path.exists(note_path):
            os.remove(note_path)
        
        self._add_log("=" * 60, "DONE")
        self._add_log(f"RESTORATION COMPLETE", "DONE")
        self._add_log(f"Files Restored: {restored_count}", "DONE")
        self._add_log(f"Files Failed: {failed_count}", "DONE")
        self._add_log("=" * 60, "DONE")
        
        # Show completion message
        messagebox.showinfo(
            "Simulation Complete",
            f"✓ Ransomware Simulation Complete\n\n"
            f"Files Restored: {restored_count}\n"
            f"Files Failed: {failed_count}\n\n"
            f"This was a controlled security simulation.\n"
            f"All files have been safely restored."
        )
        
        self._emergency_exit()
    
    def _on_close_attempt(self):
        """Handle window close attempts"""
        response = messagebox.askyesno(
            "Exit Simulation?",
            "Are you sure you want to exit the simulation?\n\n"
            "Files will remain encrypted until you click RESTORE."
        )
        if response:
            self._emergency_exit()
    
    def _emergency_exit(self):
        """Emergency exit from simulation"""
        self.root.destroy()
        sys.exit(0)

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point for ransomware simulation"""
    
    # Initialize logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Launch GUI
    root = tk.Tk()
    app = RansomwareGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
