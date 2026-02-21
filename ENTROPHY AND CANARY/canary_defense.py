import sys
import time
import os
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- CONFIGURATION ---
TARGET_DIR = "target_data"
CANARY_FILES = [
    "passwords.xlsx",
    "financials_2025.pdf",
    "ceo_login.txt"
]
# ---------------------

def plant_canaries():
    """Creates honeypot files in the target directory."""
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        
    print("[*] Planting Canary Files (Honeypots)...")
    for file_name in CANARY_FILES:
        path = os.path.join(TARGET_DIR, file_name)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("CONFIDENTIAL DATA - DO NOT TOUCH\n" * 100)
            # Try to hide it (Windows only)
            try:
                import subprocess
                subprocess.check_call(["attrib", "+h", path])
                print(f" [+] Planted & Hidden: {file_name}")
            except:
                print(f" [+] Planted: {file_name}")

class CanaryHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if filename in CANARY_FILES:
                self.trigger_alert(filename, "MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if filename in CANARY_FILES:
                self.trigger_alert(filename, "DELETED")

    def trigger_alert(self, filename, action):
        print("\n" + "!" * 50)
        print(f"🚨🚨 HIGH FIDELITY ALERT TRIGGERED 🚨🚨")
        print(f"File Touched: {filename}")
        print(f"Action Detected: {action}")
        print(f"Conclusion: RANSOMWARE ACTIVITY DETECTED!")
        print("!" * 50 + "\n")
        # In a real EDR, this would kill the process immediately.

def start_monitoring():
    event_handler = CanaryHandler()
    observer = Observer()
    observer.schedule(event_handler, path=TARGET_DIR, recursive=False)
    
    print(f"[*] Canary Defense Active.")
    print(f"[*] Monitoring {len(CANARY_FILES)} honeypots in '{TARGET_DIR}'...")
    print("[*] Waiting for the attacker...")
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    print("=== BLUE TEAM: CANARY DEFENSE MODULE ===")
    plant_canaries()
    start_monitoring()
