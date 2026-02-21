import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import time
import os
from datetime import datetime

class RansomwarePopup:
    def __init__(self):
        self.root = tk.Tk()
        self.countdown = 72 * 3600
        self.files_encrypted = []
        
        # Window setup - FULLSCREEN
        self.root.title("CRITICAL SECURITY ALERT")
        self.root.configure(bg="#0a0a0a")
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        self.root.bind("<Escape>", lambda e: self.restore_exit())
        
        self.build_ui()
        self.start_timer()
        self.start_encryption()
        self.root.mainloop()
    
    def build_ui(self):
        # RED HEADER
        header = tk.Frame(self.root, bg="#ff0000", height=120)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="⚠️ CRITICAL SYSTEM ALERT ⚠️", bg="#ff0000", fg="white", font=("Impact", 52, "bold")).pack(expand=True)
        
        # TEAM BANNER
        tk.Label(self.root, text="═══ Team DON'T WANNA CRY ═══", bg="#0a0a0a", fg="#ffaa00", font=("Courier New", 32, "bold")).pack(pady=20)
        
        # MESSAGES
        for msg in ["Your files have been encrypted!", "All documents, photos, and databases are now locked.", "You cannot access them without our decryption key."]:
            tk.Label(self.root, text=msg, bg="#0a0a0a", fg="#00ff41", font=("Arial", 18)).pack(pady=5)
        
        # COUNTDOWN
        tk.Label(self.root, text="Time Remaining:", bg="#0a0a0a", fg="white", font=("Arial", 16)).pack(pady=(30,5))
        self.timer_lbl = tk.Label(self.root, text="72:00:00", bg="#0a0a0a", fg="#ff0000", font=("Arial", 80, "bold"))
        self.timer_lbl.pack(pady=10)
        
        # LOG
        tk.Label(self.root, text="═══ ENCRYPTION LOG ═══", bg="#0a0a0a", fg="#ffaa00", font=("Courier New", 16, "bold")).pack(pady=(20,5))
        self.log = scrolledtext.ScrolledText(self.root, bg="#111111", fg="#00ff41", font=("Consolas", 12), height=10, state="disabled")
        self.log.pack(fill="x", padx=100, pady=10)
        
        # UNLOCK BUTTON
        tk.Button(self.root, text="🔓 UNLOCK / RESTORE SYSTEM 🔓", font=("Arial", 26, "bold"), bg="white", fg="red", padx=50, pady=25, command=self.restore_exit, cursor="hand2").pack(pady=40)
    
    def add_log(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log.see("end")
        self.log.config(state="disabled")
    
    def start_timer(self):
        def tick():
            while self.countdown > 0:
                h = self.countdown // 3600
                m = (self.countdown % 3600) // 60
                s = self.countdown % 60
                self.timer_lbl.config(text=f"{h:02d}:{m:02d}:{s:02d}")
                self.countdown -= 1
                time.sleep(1)
        threading.Thread(target=tick, daemon=True).start()
    
    def start_encryption(self):
        def encrypt():
            self.add_log("RANSOMWARE SIMULATION STARTED")
            target = "target_data"
            if not os.path.exists(target):
                os.makedirs(target)
                for i in range(5):
                    with open(f"{target}/doc_{i}.txt", "w") as f:
                        f.write("Test content " * 100)
                self.add_log(f"Created test files in {target}")
            
            time.sleep(1)
            for f in os.listdir(target):
                if not f.endswith(".locked"):
                    src = f"{target}/{f}"
                    dst = f"{src}.locked"
                    try:
                        os.rename(src, dst)
                        self.files_encrypted.append(dst)
                        self.add_log(f"ENCRYPTED: {f}")
                        time.sleep(0.4)
                    except: pass
            
            self.add_log(f"COMPLETE: {len(self.files_encrypted)} files encrypted")
        threading.Thread(target=encrypt, daemon=True).start()
    
    def restore_exit(self):
        for f in self.files_encrypted:
            try:
                os.rename(f, f.replace(".locked", ""))
            except: pass
        messagebox.showinfo("RESTORED", "Files restored. Simulation complete.")
        self.root.destroy()

if __name__ == "__main__":
    RansomwarePopup()
